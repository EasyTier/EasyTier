use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use pnet_packet::{
    MutablePacket,
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket, TcpFlags},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::{
    config::peers::PeerRuntimeSnapshot,
    config::{IpPrefix, NetworkIdentity},
    host::testkit::{TestDns, TestHost, TestUdpSocket},
    peers::{
        PacketRecvChanReceiver, create_packet_recv_chan, peer_manager::PortablePeerManagerConfig,
    },
    tunnel::ring::RingTunnelRegistry,
};

fn test_gateway() -> Arc<GatewayModule<TestHost>> {
    let runtime_config = CoreRuntimeConfigStore::new(
        crate::config::runtime::CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    let host = Arc::new(TestHost::default());
    let (packet_sender, packet_recv) = mpsc::channel(16);
    Arc::new(GatewayModule {
        operation: Mutex::new(()),
        started: AtomicBool::new(false),
        runtime_config,
        peer_manager: Weak::new(),
        transport_proxy: None,
        host: host.clone(),
        socket_context: SocketContext::default(),
        command_runtime: Arc::new(HostSocks5ServerRuntime::new(
            host,
            Arc::new(TestDns),
            SocketContext::default(),
        )),
        events: Arc::new(()),
        tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
        packet_sender,
        packet_recv: Arc::new(Mutex::new(packet_recv)),
        net: Arc::new(Mutex::new(None)),
        entries: Arc::new(Socks5EntryTable::default()),
        udp_client_map: Arc::new(DashMap::new()),
        udp_forward_task: Arc::new(DashMap::new()),
        socks5_enabled: Arc::new(AtomicBool::new(false)),
        data_plane_refs: Arc::new(AtomicUsize::new(0)),
        data_plane_net_ready: tokio::sync::watch::channel(false).0,
        cancel_tokens: Arc::new(DashMap::new()),
        port_forward_list_change_notifier: Arc::new(Notify::new()),
        pipeline_guard: Mutex::new(None),
    })
}

struct DataPlaneEndpoint {
    gateway: Arc<GatewayModule<TestHost>>,
    peer_manager: Arc<PeerManagerCore>,
    _packet_receiver: PacketRecvChanReceiver,
    ip: cidr::Ipv4Inet,
}

fn data_plane_endpoint(host: Arc<TestHost>, ip: cidr::Ipv4Inet) -> DataPlaneEndpoint {
    const NETWORK_NAME: &str = "gateway-data-plane";

    let mut runtime = PeerRuntimeSnapshot::default().runtime;
    runtime.core.node.peer_id = None;
    runtime.core.node.network_name = NETWORK_NAME.to_owned();
    runtime.core.routes.ipv4 = Some(
        IpPrefix::new(IpAddr::V4(ip.address()), ip.network_length())
            .expect("test IPv4 prefix should be valid"),
    );
    runtime.network_identity = NetworkIdentity {
        network_name: NETWORK_NAME.to_owned(),
        network_secret: Some("shared-secret".to_owned()),
        network_secret_digest: None,
    };
    let peer_config = PortablePeerManagerConfig::new(runtime);
    let runtime_config = CoreRuntimeConfigStore::new(
        crate::config::runtime::CoreRuntimeConfig::default(),
        Arc::new(peer_config.snapshot.clone()),
    );
    let (packet_sender, packet_receiver) = create_packet_recv_chan();
    let dns = Arc::new(TestDns);
    let peer_manager = Arc::new(
        PeerManagerCore::new_portable_for_test(peer_config, packet_sender)
            .expect("build portable peer manager"),
    );
    let gateway = GatewayModule::new(
        runtime_config,
        peer_manager.clone(),
        None,
        host,
        dns,
        SocketContext::default(),
        Arc::new(()),
    );

    DataPlaneEndpoint {
        gateway,
        peer_manager,
        _packet_receiver: packet_receiver,
        ip,
    }
}

async fn setup_data_plane_pair() -> (DataPlaneEndpoint, DataPlaneEndpoint) {
    let host = Arc::new(TestHost::default());
    let a = data_plane_endpoint(host.clone(), "10.126.126.1/24".parse().unwrap());
    let b = loop {
        let b = data_plane_endpoint(host.clone(), "10.126.126.2/24".parse().unwrap());
        if b.peer_manager.my_peer_id() != a.peer_manager.my_peer_id() {
            break b;
        }
    };

    let (run_a, run_b) = tokio::join!(a.peer_manager.run(), b.peer_manager.run());
    run_a.unwrap();
    run_b.unwrap();
    let (start_a, start_b) = tokio::join!(a.gateway.start(), b.gateway.start());
    start_a.unwrap();
    start_b.unwrap();

    let registry = Arc::new(RingTunnelRegistry::default());
    let listener_id = uuid::Uuid::new_v4();
    let mut listener = registry.bind(listener_id).unwrap();
    let client_tunnel = registry.connect(listener_id).unwrap().into_tunnel();
    let server_tunnel = listener.accept().await.unwrap().into_tunnel();
    let (client, server) = tokio::join!(
        b.peer_manager.add_client_tunnel(client_tunnel, true),
        a.peer_manager.add_tunnel_as_server(server_tunnel, true),
    );
    client.unwrap();
    server.unwrap();

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if a.peer_manager
                .list_route_snapshots()
                .await
                .iter()
                .any(|route| {
                    route.peer_id == b.peer_manager.my_peer_id()
                        && route.ipv4_addr == Some(b.ip.into())
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Ring peers did not exchange routes");

    (a, b)
}

async fn stop_data_plane_pair(a: &DataPlaneEndpoint, b: &DataPlaneEndpoint) {
    tokio::join!(a.gateway.stop(), b.gateway.stop());
    tokio::join!(
        a.peer_manager.clear_resources(),
        b.peer_manager.clear_resources()
    );
}

fn build_tcp_packet(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    let src_ip = match src.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => panic!("test only supports ipv4"),
    };
    let dst_ip = match dst.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => panic!("test only supports ipv4"),
    };

    {
        let mut ip_packet = MutableIpv4Packet::new(&mut buf).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(src.port());
        tcp_packet.set_destination(dst.port());
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN | TcpFlags::ACK);
        tcp_packet.set_window(65535);
        tcp_packet.set_checksum(tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &src_ip,
            &dst_ip,
        ));

        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
    }

    buf
}

fn build_udp_followup_fragment(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 28];
    {
        let mut ip_packet = MutableIpv4Packet::new(&mut buf).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(28);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_packet.set_fragment_offset(1);
        ip_packet.set_source(src);
        ip_packet.set_destination(dst);
        ip_packet
            .payload_mut()
            .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);

        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
    }

    buf
}

#[tokio::test]
async fn data_plane_tcp_pingpong() {
    let (a, b) = setup_data_plane_pair().await;
    let timeout = Duration::from_secs(10);
    let mut listener = b.gateway.data_plane_tcp_bind(0, timeout).await.unwrap();
    let listen_addr = SocketAddr::new(b.ip.address().into(), listener.local_addr().port());

    let accept = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.flush().await.unwrap();
    });

    let mut client = a
        .gateway
        .data_plane_tcp_connect(listen_addr, timeout)
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    accept.await.unwrap();

    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test]
async fn data_plane_udp_pingpong() {
    let (a, b) = setup_data_plane_pair().await;
    let timeout = Duration::from_secs(10);
    let socket_a = a.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    let socket_b = b.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    let addr_a = SocketAddr::new(a.ip.address().into(), socket_a.local_addr().port());
    let addr_b = SocketAddr::new(b.ip.address().into(), socket_b.local_addr().port());

    socket_b.send_to(b"warmup", addr_a).await.unwrap();
    socket_a.send_to(b"ping", addr_b).await.unwrap();
    let mut buf = [0u8; 16];
    let (len, from) = tokio::time::timeout(timeout, socket_b.recv_from(&mut buf))
        .await
        .expect("receive ping timed out")
        .unwrap();
    assert_eq!(&buf[..len], b"ping");
    assert_eq!(from, addr_a);

    socket_b.send_to(b"pong", addr_a).await.unwrap();
    loop {
        let (len, from) = tokio::time::timeout(timeout, socket_a.recv_from(&mut buf))
            .await
            .expect("receive pong timed out")
            .unwrap();
        if &buf[..len] == b"pong" {
            assert_eq!(from, addr_b);
            break;
        }
    }

    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test]
async fn startup_applies_initial_port_forwards_and_cleans_up_on_failure() {
    let gateway = test_gateway();
    gateway.runtime_config.update_services(|services| {
        services.gateway.port_forwards = vec![PortForwardConfig {
            bind_addr: "127.0.0.1:11010".parse().unwrap(),
            dst_addr: "10.0.0.2:80".parse().unwrap(),
            proto: "tcp".to_owned(),
        }];
    });

    let error = gateway.start().await.unwrap_err();

    assert!(error.to_string().contains("peer manager is gone"));
    assert_eq!(gateway.host.tcp_binds.load(Ordering::Relaxed), 1);
    assert!(gateway.cancel_tokens.is_empty());
    assert!(!gateway.started.load(Ordering::Relaxed));
}

#[tokio::test]
async fn socks5_consumes_modified_data_when_entry_matches() {
    let gateway = test_gateway();

    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
    let entry = Socks5Entry {
        src: local,
        dst: remote,
        kind: TCP_ENTRY,
    };
    gateway.entries.insert(
        entry,
        GatewayEntryData::Tcp {
            _reservation: Arc::new(()),
        },
    );

    for packet_type in [
        PacketType::DataWithKcpSrcModified,
        PacketType::DataWithQuicSrcModified,
    ] {
        let mut packet = ZCPacket::new_with_payload(&build_tcp_packet(remote, local));
        packet.fill_peer_manager_hdr(1, 1, packet_type as u8);

        let result = gateway.try_process_packet_from_peer(packet).await;
        assert!(result.is_none());

        let mut receiver = gateway.packet_recv.lock().await;
        let received = receiver.try_recv().unwrap();
        assert_eq!(
            received.peer_manager_header().unwrap().packet_type,
            packet_type as u8
        );
    }
}

#[tokio::test]
async fn socks5_passes_through_unmatched_or_malformed_modified_data() {
    let gateway = test_gateway();
    gateway.entries.insert(
        Socks5Entry {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22),
            kind: TCP_ENTRY,
        },
        GatewayEntryData::Tcp {
            _reservation: Arc::new(()),
        },
    );

    let unmatched_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40001);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
    let mut unmatched_packet =
        ZCPacket::new_with_payload(&build_tcp_packet(remote, unmatched_local));
    unmatched_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);
    let result = gateway.try_process_packet_from_peer(unmatched_packet).await;
    assert!(result.is_some());

    let mut malformed_packet = ZCPacket::new_with_payload(&[0u8; 8]);
    malformed_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithQuicSrcModified as u8);
    let result = gateway.try_process_packet_from_peer(malformed_packet).await;
    assert!(result.is_some());

    let mut receiver = gateway.packet_recv.lock().await;
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn socks5_passes_through_non_loopback_modified_data_even_when_entry_matches() {
    let gateway = test_gateway();

    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
    let entry = Socks5Entry {
        src: local,
        dst: remote,
        kind: TCP_ENTRY,
    };
    gateway.entries.insert(
        entry,
        GatewayEntryData::Tcp {
            _reservation: Arc::new(()),
        },
    );

    let mut packet = ZCPacket::new_with_payload(&build_tcp_packet(remote, local));
    packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);

    let result = gateway.try_process_packet_from_peer(packet).await;
    assert!(result.is_some());

    let mut receiver = gateway.packet_recv.lock().await;
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn socks5_mirrors_fragmented_udp_when_entry_matches() {
    let gateway = test_gateway();

    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 53);
    gateway.entries.insert(
        Socks5Entry {
            src: local,
            dst: remote,
            kind: UDP_ENTRY,
        },
        GatewayEntryData::Udp((
            Arc::new(GatewayUdpSocket::Host(Arc::new(TestUdpSocket(
                "127.0.0.1:1".parse().unwrap(),
            )))),
            UdpClientKey {
                client_addr: local,
                dst_addr: remote,
            },
        )),
    );
    assert_eq!(gateway.entries.count(), 1);

    let mut packet = ZCPacket::new_with_payload(&build_udp_followup_fragment(
        match remote.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unreachable!(),
        },
        match local.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unreachable!(),
        },
    ));
    packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

    let result = gateway.try_process_packet_from_peer(packet).await;
    assert!(result.is_some());

    let mut receiver = gateway.packet_recv.lock().await;
    let received = receiver.try_recv().unwrap();
    assert_eq!(
        received.peer_manager_header().unwrap().packet_type,
        PacketType::Data as u8
    );
}
