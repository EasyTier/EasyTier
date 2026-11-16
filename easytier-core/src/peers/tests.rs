use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::foundation::time::{Duration, timeout};

use crate::{
    foundation::token_bucket::{ArcByteLimiter, ByteLimiter},
    packet::{PacketType, ZCPacket},
    peers::{
        PeerConnectionOrigin, PeerPacketIngress,
        conn::{
            peer_conn::{PeerConn, PeerConnId},
            peer_map::PeerMap,
            peer_session::{PeerSession, PeerSessionStore},
        },
        context::{NetworkIdentity, PeerContext},
        create_packet_recv_chan,
        error::Error,
        recv_packet_envelope_from_chan,
        test_support::NoopPeerContext,
    },
    tunnel::ring::create_ring_tunnel_pair,
};

struct RejectingRecvLimiter;

impl ByteLimiter for RejectingRecvLimiter {
    fn try_consume(&self, _bytes: u64) -> bool {
        false
    }
}

struct LimitedPeerContext {
    limiter: ArcByteLimiter,
}

impl PeerContext for LimitedPeerContext {
    fn network_identity(&self) -> NetworkIdentity {
        NetworkIdentity::default()
    }

    fn recv_limiter(
        &self,
        _network_name: &str,
        _is_foreign_network: bool,
    ) -> Option<ArcByteLimiter> {
        Some(self.limiter.clone())
    }
}

impl PeerConn {
    #[tracing::instrument]
    async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        self.do_handshake_as_server_ext(|_, _| Ok(())).await
    }
}

fn secure_mode_config(peer_key: u8) -> crate::proto::common::SecureModeConfig {
    let private = StaticSecret::from([peer_key; 32]);
    let public = PublicKey::from(&private);
    crate::proto::common::SecureModeConfig {
        enabled: true,
        local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
        local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
    }
}

#[tokio::test]
async fn peer_conn_handshake_over_memory_tunnel() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert_eq!(client.get_peer_id(), 2);
    assert_eq!(server.get_peer_id(), 1);
    assert_eq!(client.get_conn_info().features, ["liveness-echo-v1"]);
    assert_eq!(server.get_conn_info().features, ["liveness-echo-v1"]);
}

#[tokio::test(start_paused = true)]
async fn peer_conn_pingpong_continues_while_a_secure_relay_batch_drains() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::{SinkExt, StreamExt};

    use crate::tunnel::{Tunnel, TunnelError, wrapper::TunnelWrapper};

    let wrap = |tunnel: Box<dyn Tunnel>, slow: bool, pongs: Arc<AtomicUsize>| {
        let info = tunnel.info();
        let (stream, sink) = tunnel.split();
        let stream = stream.inspect(move |packet| {
            if packet.as_ref().is_ok_and(|packet| {
                packet
                    .peer_manager_header()
                    .is_some_and(|header| header.packet_type == PacketType::Pong as u8)
            }) {
                pongs.fetch_add(1, Ordering::Relaxed);
            }
        });
        let sink = sink.with(move |packet: ZCPacket| async move {
            if slow
                && packet
                    .peer_manager_header()
                    .is_some_and(|header| header.packet_type == PacketType::RpcReq as u8)
            {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            Ok::<_, TunnelError>(packet)
        });
        Box::new(TunnelWrapper::new(stream, sink, info)) as Box<dyn Tunnel>
    };
    let pongs = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        Arc::new(NoopPeerContext::default()),
        wrap(client_tunnel, true, pongs[0].clone()),
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        Arc::new(NoopPeerContext::default()),
        wrap(server_tunnel, false, pongs[1].clone()),
        Arc::new(PeerSessionStore::new()),
    );
    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();
    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    client.start_recv_loop(client_tx).await;
    server.start_recv_loop(server_tx).await;
    client.start_pingpong();
    server.start_pingpong();
    let session = Arc::new(PeerSession::new(
        3,
        [7; 32],
        0,
        0,
        "aes-gcm".to_owned(),
        "aes-gcm".to_owned(),
        None,
    ));
    let endpoint = PeerSession::new(
        1,
        [7; 32],
        0,
        0,
        "aes-gcm".to_owned(),
        "aes-gcm".to_owned(),
        None,
    );
    let destination = 3;
    let packets = (0..207u32)
        .map(|sequence| {
            let mut packet = ZCPacket::new_with_payload(&vec![sequence as u8; 1200]);
            packet.mut_payload()[..4].copy_from_slice(&sequence.to_le_bytes());
            packet.fill_peer_manager_hdr(1, destination, PacketType::RpcReq as u8);
            packet.peer_session = Some(session.clone());
            packet
        })
        .collect();
    client.send_msg(ZCPacket::batch(packets)).await.unwrap();
    timeout(Duration::from_secs(100), async {
        for sequence in 0..207u32 {
            let mut packet = server_rx.recv().await.unwrap();
            assert_eq!(
                packet.peer_manager_header().unwrap().packet_type,
                PacketType::RpcReq as u8
            );
            assert!(packet.peer_manager_header().unwrap().is_encrypted());
            endpoint
                .decrypt_payload(1, destination, &mut packet)
                .unwrap();
            assert_eq!(packet.payload()[..4], sequence.to_le_bytes());
            assert_eq!(packet.payload()[4..], vec![sequence as u8; 1196]);
            if sequence == 100 {
                // Actual native Pongs were received before half of the batch
                // finished; business-packet liveness echoes cannot satisfy this.
                for received in &pongs {
                    assert!(received.load(Ordering::Relaxed) > 0);
                }
            }
            assert!(!client.is_closed());
            assert!(!server.is_closed());
        }
    })
    .await
    .expect("slow RPC batch did not drain while native pingpong was running");
}

#[tokio::test]
async fn peer_conn_handshake_anonymizes_foreign_network_names() {
    for (client_secure, server_secure) in [(false, false), (false, true), (true, true)] {
        for (client_name, expected_reply) in
            [("", "fg-"), ("foreign", "fg-foreign"), ("net", "net")]
        {
            let client_identity = if client_name == "net" {
                NetworkIdentity::new(client_name.to_owned(), "secret".to_owned())
            } else {
                // No name or secret is required to send a valid plaintext request:
                // the client sends a 32-byte all-zero digest without a secret.
                NetworkIdentity::new_credential(client_name.to_owned())
            };
            let mut client_ctx = NoopPeerContext::new(client_identity);
            let mut server_ctx =
                NoopPeerContext::new(NetworkIdentity::new("net".to_owned(), "secret".to_owned()));
            if client_secure {
                client_ctx = client_ctx.with_secure_mode(secure_mode_config(1));
            }
            if server_secure {
                server_ctx = server_ctx.with_secure_mode(secure_mode_config(2));
            }

            let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
            let mut client = PeerConn::new(
                1,
                Arc::new(client_ctx),
                client_tunnel,
                Arc::new(PeerSessionStore::new()),
            );
            let mut server = PeerConn::new(
                2,
                Arc::new(server_ctx),
                server_tunnel,
                Arc::new(PeerSessionStore::new()),
            );
            let (client_ret, server_ret) = timeout(Duration::from_secs(1), async {
                tokio::join!(
                    client.do_handshake_as_client(),
                    server.do_handshake_as_server()
                )
            })
            .await
            .expect("memory tunnel handshake should complete");

            client_ret.unwrap();
            server_ret.unwrap();
            assert_eq!(
                client.get_network_identity().network_name,
                expected_reply,
                "client_name={client_name:?}, client_secure={client_secure}, server_secure={server_secure}",
            );
            assert_eq!(server.get_network_identity().network_name, client_name);
            assert_eq!(
                !client.get_conn_info().noise_remote_static_pubkey.is_empty(),
                client_secure,
            );
        }
    }
}

#[tokio::test]
async fn peer_recv_limit_drops_excess_data_without_blocking_ping() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(LimitedPeerContext {
        limiter: Arc::new(RejectingRecvLimiter),
    });

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    client.start_recv_loop(client_tx).await;
    server.start_recv_loop(server_tx).await;

    let client_rx_packets = client.get_stats().rx_packets;

    let mut data = ZCPacket::new_with_payload(b"over limit");
    data.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client.send_msg(data).await.unwrap();

    let mut ping = ZCPacket::new_with_payload(&[]);
    ping.fill_peer_manager_hdr(1, 2, PacketType::Ping as u8);
    client.send_msg(ping).await.unwrap();

    timeout(Duration::from_secs(1), async {
        while client.get_stats().rx_packets == client_rx_packets {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receive limiting must not block the following pong");

    assert!(
        timeout(Duration::from_millis(50), server_rx.recv())
            .await
            .is_err(),
        "over-limit data packet should be dropped"
    );
}

#[tokio::test]
async fn peer_conn_noise_handshake_advertises_liveness_echo() {
    fn context(peer_key: u8) -> Arc<NoopPeerContext> {
        Arc::new(
            NoopPeerContext::new(NetworkIdentity {
                network_name: "net".to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            })
            .with_secure_mode(secure_mode_config(peer_key)),
        )
    }

    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        context(1),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        context(2),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert_eq!(client.get_conn_info().features, ["liveness-echo-v1"]);
    assert_eq!(server.get_conn_info().features, ["liveness-echo-v1"]);
}

#[tokio::test]
async fn peer_conn_handshake_matches_plaintext_secret_identity() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::new(NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some("secret".to_string()),
        network_secret_digest: None,
    }));
    let server_ctx = Arc::new(NoopPeerContext::new(NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some("secret".to_string()),
        network_secret_digest: None,
    }));

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert!(client.matches_local_network_secret());
    assert!(server.matches_local_network_secret());
}

#[tokio::test]
async fn local_packet_channel_injection_has_no_attached_privilege() {
    let (sender, mut receiver) = create_packet_recv_chan();
    let mut packet = ZCPacket::new_with_payload(b"local");
    packet.fill_peer_manager_hdr(77, 3, PacketType::Data as u8);

    sender.send(packet).await.unwrap();

    let envelope = recv_packet_envelope_from_chan(&mut receiver).await.unwrap();
    let (_, ingress) = envelope.into_parts();
    assert_eq!(ingress, PeerPacketIngress::Local);
    assert!(!ingress.is_attached());
}

#[tokio::test]
async fn peer_map_forwards_packet_over_memory_tunnel() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel,
        peer_session_store.clone(),
    );
    let mut server_conn = PeerConn::new(2, server_ctx.clone(), server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client_conn.do_handshake_as_client(),
        server_conn.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);

    client_map.add_new_peer_conn(client_conn).await.unwrap();
    server_map.add_new_peer_conn(server_conn).await.unwrap();

    let mut packet = ZCPacket::new_with_payload(b"hello");
    packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map.send_msg_directly(packet, 2).await.unwrap();

    let received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.payload(), b"hello");
}

#[tokio::test]
async fn peer_channel_uses_admission_origin_instead_of_packet_header() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel,
        peer_session_store.clone(),
    );
    let mut server_conn = PeerConn::new_with_peer_id_hint_and_origin(
        2,
        server_ctx.clone(),
        server_tunnel,
        None,
        peer_session_store,
        PeerConnectionOrigin::Attached,
    );
    let (client_ret, server_ret) = tokio::join!(
        client_conn.do_handshake_as_client(),
        server_conn.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();
    let server_conn_id = server_conn.get_conn_id();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);
    client_map.add_new_peer_conn(client_conn).await.unwrap();
    server_map.add_new_peer_conn(server_conn).await.unwrap();
    assert!(server_map.has_direct_attached_peer(1));

    let mut packet = ZCPacket::new_with_payload(b"forged source");
    packet.fill_peer_manager_hdr(77, 3, PacketType::Data as u8);
    client_map.send_msg_directly(packet, 2).await.unwrap();

    let envelope = timeout(
        Duration::from_secs(1),
        recv_packet_envelope_from_chan(&mut server_rx),
    )
    .await
    .unwrap()
    .unwrap();
    let (received, ingress) = envelope.into_parts();
    assert_eq!(
        received.peer_manager_header().unwrap().from_peer_id.get(),
        77
    );
    assert_eq!(
        ingress,
        PeerPacketIngress::Peer {
            peer_id: 1,
            conn_id: server_conn_id,
            origin: PeerConnectionOrigin::Attached,
        }
    );
}

#[tokio::test]
async fn peer_map_reselects_cached_connection_after_close() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel_a, server_tunnel_a) = create_ring_tunnel_pair();
    let (client_tunnel_b, server_tunnel_b) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn_a = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel_a,
        peer_session_store.clone(),
    );
    let mut server_conn_a = PeerConn::new(
        2,
        server_ctx.clone(),
        server_tunnel_a,
        peer_session_store.clone(),
    );
    let mut client_conn_b = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel_b,
        peer_session_store.clone(),
    );
    let mut server_conn_b =
        PeerConn::new(2, server_ctx.clone(), server_tunnel_b, peer_session_store);

    let (client_a_ret, server_a_ret, client_b_ret, server_b_ret) = tokio::join!(
        client_conn_a.do_handshake_as_client(),
        server_conn_a.do_handshake_as_server(),
        client_conn_b.do_handshake_as_client(),
        server_conn_b.do_handshake_as_server(),
    );
    client_a_ret.unwrap();
    server_a_ret.unwrap();
    client_b_ret.unwrap();
    server_b_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);

    client_map.add_new_peer_conn(client_conn_a).await.unwrap();
    client_map.add_new_peer_conn(client_conn_b).await.unwrap();
    server_map.add_new_peer_conn(server_conn_a).await.unwrap();
    server_map.add_new_peer_conn(server_conn_b).await.unwrap();

    let mut first_packet = ZCPacket::new_with_payload(b"first");
    first_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map.send_msg_directly(first_packet, 2).await.unwrap();
    let first_received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_received.payload(), b"first");

    let first_conn_id = client_map.get_peer_default_conn_id(2).await.unwrap();
    assert_ne!(first_conn_id, PeerConnId::default());
    client_map.close_peer_conn(2, &first_conn_id).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while client_map.get_peer_default_conn_id(2).await == Some(first_conn_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut second_packet = ZCPacket::new_with_payload(b"second");
    second_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map
        .send_msg_directly(second_packet, 2)
        .await
        .unwrap();
    let second_received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_received.payload(), b"second");
    assert_ne!(
        client_map.get_peer_default_conn_id(2).await,
        Some(first_conn_id)
    );
}
