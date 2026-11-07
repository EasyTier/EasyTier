use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    foundation::time::{Duration, timeout},
    packet::{PacketType, ZCPacket},
    peers::{
        conn::{fec, peer_session::PeerSessionStore},
        context::NetworkIdentity,
        test_support::NoopPeerContext,
    },
    proto::common::{Flags, SecureModeConfig, TunnelInfo},
    tunnel::{
        SinkItem,
        filter::{TunnelFilter, TunnelWithFilter},
        ring::{RingTunnel, create_ring_socket_pair},
    },
};

use super::PeerConn;

#[derive(Default)]
struct DropFirstSource {
    dropped: AtomicBool,
    sources: AtomicUsize,
    repairs: AtomicUsize,
    plain_data: AtomicUsize,
}

impl TunnelFilter for DropFirstSource {
    type FilterOutput = ();

    fn before_send(&self, packet: SinkItem) -> Option<SinkItem> {
        // Observe the independent envelope directly, without asking the
        // production parser to decide what the test should drop or count.
        match packet.tunnel_payload().get(8).copied() {
            Some(0x40) => {
                self.sources.fetch_add(1, Ordering::Relaxed);
                if !self.dropped.swap(true, Ordering::Relaxed) {
                    return None;
                }
            }
            Some(kind) if kind & 0xc0 == 0x80 => {
                self.repairs.fetch_add(1, Ordering::Relaxed);
            }
            Some(kind)
                if [
                    PacketType::Data,
                    PacketType::KcpSrc,
                    PacketType::KcpDst,
                    PacketType::QuicSrc,
                    PacketType::QuicDst,
                ]
                .iter()
                .any(|packet_type| kind == *packet_type as u8) =>
            {
                self.plain_data.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        Some(packet)
    }

    fn filter_output(&self) {}
}

fn flags(enabled: bool) -> Flags {
    Flags {
        enable_udp_fec: enabled,
        mtu: 1300,
        ..Default::default()
    }
}

fn context(peer_key: u8, flags: Flags, noise: bool) -> Arc<NoopPeerContext> {
    let mut context = NoopPeerContext::new(NetworkIdentity {
        network_name: "fec-test".to_owned(),
        network_secret: Some("secret".to_owned()),
        network_secret_digest: None,
    })
    .with_flags(flags);
    if noise {
        let private = StaticSecret::from([peer_key; 32]);
        let public = PublicKey::from(&private);
        context = context.with_secure_mode(SecureModeConfig {
            enabled: true,
            local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
            local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
        });
    }
    Arc::new(context)
}

async fn connect(
    enabled: [bool; 2],
    tunnel_type: &str,
    noise: bool,
) -> (PeerConn, PeerConn, [Arc<DropFirstSource>; 2]) {
    connect_with_flags(enabled.map(flags), tunnel_type, noise).await
}

fn create_connections(
    flags: [Flags; 2],
    tunnel_type: &str,
    noise: bool,
) -> (PeerConn, PeerConn, [Arc<DropFirstSource>; 2]) {
    let (client_socket, server_socket) = create_ring_socket_pair(32);
    let info = TunnelInfo {
        tunnel_type: tunnel_type.to_owned(),
        ..Default::default()
    };
    // The ring keeps this test local; its advertised type exercises PeerConn's
    // transport gate. UDP socket I/O is covered separately.
    let client_tunnel = RingTunnel::new(client_socket, Some(info.clone()));
    let server_tunnel = RingTunnel::new(server_socket, Some(info));
    let filters = [
        Arc::new(DropFirstSource::default()),
        Arc::new(DropFirstSource::default()),
    ];
    let [client_flags, server_flags] = flags;
    let client = PeerConn::new(
        1,
        context(1, client_flags, noise),
        Box::new(TunnelWithFilter::new(client_tunnel, filters[0].clone())),
        Arc::new(PeerSessionStore::new()),
    );
    let server = PeerConn::new(
        2,
        context(2, server_flags, noise),
        Box::new(TunnelWithFilter::new(server_tunnel, filters[1].clone())),
        Arc::new(PeerSessionStore::new()),
    );
    for conn in [&client, &server] {
        assert_eq!(
            conn.local_features()
                .iter()
                .any(|feature| feature == fec::FEATURE),
            tunnel_type == "udp",
        );
    }
    (client, server, filters)
}

async fn handshake(client: &mut PeerConn, server: &mut PeerConn) {
    let (client_result, server_result) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            client.do_handshake_as_client(),
            server.do_handshake_as_server_ext(|_, _| Ok(())),
        )
    })
    .await
    .expect("peer handshake timed out");
    client_result.unwrap();
    server_result.unwrap();
    assert_eq!(client.get_peer_id(), 2);
    assert_eq!(server.get_peer_id(), 1);
}

async fn connect_with_flags(
    flags: [Flags; 2],
    tunnel_type: &str,
    noise: bool,
) -> (PeerConn, PeerConn, [Arc<DropFirstSource>; 2]) {
    let (mut client, mut server, filters) = create_connections(flags, tunnel_type, noise);
    handshake(&mut client, &mut server).await;
    (client, server, filters)
}

async fn exchange_direction(
    sender: &PeerConn,
    receiver: &PeerConn,
    packet_type: PacketType,
    payloads: [&[u8]; 2],
) {
    timeout(Duration::from_secs(5), async {
        for payload in payloads {
            let mut packet = ZCPacket::new_with_payload(payload);
            packet.fill_peer_manager_hdr(
                sender.get_my_peer_id(),
                receiver.get_my_peer_id(),
                packet_type as u8,
            );
            sender.send_msg(packet).await.unwrap();
        }
        let mut received = BTreeSet::new();
        for _ in payloads {
            let packet = receiver
                .recv_next_peer_manager_packet(Some(packet_type))
                .await
                .unwrap();
            let header = packet.peer_manager_header().unwrap();
            assert_eq!(header.from_peer_id.get(), sender.get_my_peer_id());
            assert_eq!(header.to_peer_id.get(), receiver.get_my_peer_id());
            assert_eq!(header.packet_type, packet_type as u8);
            assert!(!header.is_encrypted());
            assert!(received.insert(packet.payload().to_vec()));
        }
        assert_eq!(received, payloads.into_iter().map(<[u8]>::to_vec).collect());
    })
    .await
    .expect("peer data delivery timed out");
}

async fn exchange(client: &PeerConn, server: &PeerConn, packet_type: PacketType) {
    tokio::join!(
        exchange_direction(
            client,
            server,
            packet_type,
            [b"client first", b"client second"]
        ),
        exchange_direction(
            server,
            client,
            packet_type,
            [b"server first", b"server second"]
        ),
    );
}

fn assert_traffic(
    client: &PeerConn,
    server: &PeerConn,
    filters: &[Arc<DropFirstSource>; 2],
    sources: usize,
    plain: usize,
) {
    let dropped = usize::from(sources > 0);
    for (conn, filter) in [(client, &filters[0]), (server, &filters[1])] {
        assert_eq!(filter.dropped.load(Ordering::Relaxed), sources > 0);
        assert_eq!(filter.sources.load(Ordering::Relaxed), sources);
        assert_eq!(filter.plain_data.load(Ordering::Relaxed), plain);
        if sources == 0 {
            assert_eq!(filter.repairs.load(Ordering::Relaxed), 0);
        } else {
            assert!(filter.repairs.load(Ordering::Relaxed) >= 1);
        }
        if let Some(stats) = conn.get_conn_info().fec {
            assert_eq!(stats.tx_sources, sources as u64);
            assert_eq!(stats.rx_sources, (sources - dropped) as u64);
            assert_eq!(stats.recovered, dropped as u64);
            assert_eq!(stats.invalid_packets, 0);
        }
    }
}

async fn assert_recovery(noise: bool) {
    for enabled in [[true, true], [true, false], [false, true]] {
        let (client, server, filters) = connect(enabled, "udp", noise).await;
        for conn in [&client, &server] {
            let info = conn.get_conn_info();
            assert!(info.features.iter().any(|feature| feature == fec::FEATURE));
            assert!(info.fec.unwrap().active);
            assert_eq!(conn.noise_handshake_result.is_some(), noise);
        }
        exchange(&client, &server, PacketType::Data).await;
        assert_traffic(&client, &server, &filters, 2, 0);
    }
}

#[tokio::test]
async fn legacy_handshake_enables_bidirectional_udp_recovery() {
    assert_recovery(false).await;
}

#[tokio::test]
async fn noise_handshake_recovers_and_decrypts_original_payload() {
    assert_recovery(true).await;
}

#[tokio::test]
async fn noise_full_mtu_sources_are_encoded_and_recovered() {
    // Only the requesting endpoint reserves 16 bytes for FEC. Both endpoints
    // reserve the 28-byte AEAD tail. Exercise each full TUN size through the
    // real session filter, including the larger passive endpoint's packets.
    for enabled in [[true, false], [false, true]] {
        let flags = enabled.map(|enabled| Flags {
            mtu: 1380,
            ..flags(enabled)
        });
        let (client, server, filters) = connect_with_flags(flags, "udp", true).await;
        let [client_len, server_len] =
            enabled.map(|enabled| 1380 - 28 - if enabled { 16 } else { 0 });
        let client_payloads = [vec![7; client_len], vec![9; client_len]];
        let server_payloads = [vec![11; server_len], vec![13; server_len]];
        tokio::join!(
            exchange_direction(
                &client,
                &server,
                PacketType::Data,
                [&client_payloads[0], &client_payloads[1]]
            ),
            exchange_direction(
                &server,
                &client,
                PacketType::Data,
                [&server_payloads[0], &server_payloads[1]]
            ),
        );
        assert_traffic(&client, &server, &filters, 2, 0);
    }
}

#[tokio::test]
async fn packets_larger_than_the_local_mtu_remain_protected() {
    let (client, server, filters) = connect([true, false], "udp", true).await;
    // Forwarded input need not obey this endpoint's 1300-byte TUN setting.
    let first = vec![7; 1500];
    let second = vec![9; 1500];
    tokio::join!(
        exchange_direction(&client, &server, PacketType::Data, [&first, &second]),
        exchange_direction(&server, &client, PacketType::Data, [&first, &second]),
    );
    assert_traffic(&client, &server, &filters, 2, 0);
}

#[tokio::test]
async fn disabled_and_non_udp_connections_keep_plain_path() {
    for (enabled, tunnel_type) in [
        ([false, false], "udp"),
        ([true, true], "tcp"),
        ([true, true], "ring"),
    ] {
        let (client, server, filters) = connect(enabled, tunnel_type, false).await;
        assert_eq!(
            client
                .get_conn_info()
                .features
                .iter()
                .any(|feature| feature == fec::FEATURE),
            tunnel_type == "udp",
        );
        assert_eq!(
            server
                .get_conn_info()
                .features
                .iter()
                .any(|feature| feature == fec::FEATURE),
            tunnel_type == "udp",
        );
        exchange(&client, &server, PacketType::Data).await;
        assert_traffic(&client, &server, &filters, 0, 2);
        for conn in [&client, &server] {
            if let Some(stats) = conn.get_conn_info().fec {
                assert!(!stats.active);
            }
        }
    }
}

#[tokio::test]
async fn an_endpoint_without_fec_capability_keeps_both_directions_plain() {
    for noise in [false, true] {
        let (mut client, mut server, filters) =
            create_connections([flags(false), flags(true)], "udp", noise);
        // Simulate an endpoint that does not implement FEC negotiation. Its
        // adapter stays waiting and cannot start encoding either direction.
        client.fec = None;
        assert!(
            !client
                .local_features()
                .iter()
                .any(|feature| feature == fec::FEATURE)
        );
        handshake(&mut client, &mut server).await;
        assert!(
            !server
                .get_conn_info()
                .features
                .iter()
                .any(|feature| feature == fec::FEATURE)
        );
        assert!(!server.get_conn_info().fec.unwrap().active);
        exchange(&client, &server, PacketType::Data).await;
        assert_traffic(&client, &server, &filters, 0, 2);
    }
}

#[tokio::test]
async fn proxy_packet_types_require_an_explicit_flag_from_either_endpoint() {
    for (enabled, kcp, quic) in [
        (true, [false, false], [false, false]),
        (true, [true, false], [false, false]),
        (true, [false, true], [false, false]),
        (true, [false, false], [true, false]),
        (true, [false, false], [false, true]),
        (true, [true, false], [false, true]),
        (false, [true, false], [false, true]),
    ] {
        let flags = [0, 1].map(|side| Flags {
            enable_udp_fec_kcp: kcp[side],
            enable_udp_fec_quic: quic[side],
            ..flags(enabled && side == 0)
        });
        let (client, server, filters) = connect_with_flags(flags, "udp", true).await;
        let mut sources = 0;
        let mut plain = 0;
        for (packet_type, protected) in [
            (PacketType::KcpSrc, enabled && kcp.contains(&true)),
            (PacketType::KcpDst, enabled && kcp.contains(&true)),
            (PacketType::QuicSrc, enabled && quic.contains(&true)),
            (PacketType::QuicDst, enabled && quic.contains(&true)),
        ] {
            let before: [_; 2] =
                std::array::from_fn(|side| filters[side].sources.load(Ordering::Relaxed));
            exchange(&client, &server, packet_type).await;
            for (filter, before) in filters.iter().zip(before) {
                assert_eq!(
                    filter.sources.load(Ordering::Relaxed) - before,
                    if protected { 2 } else { 0 },
                    "{packet_type:?}"
                );
            }
            if protected {
                sources += 2;
            } else {
                plain += 2;
            }
        }
        assert_traffic(&client, &server, &filters, sources, plain);
        for conn in [&client, &server] {
            assert_eq!(conn.get_conn_info().fec.unwrap().active, enabled);
        }
    }
}
