use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::{
    config::peers::PeerRuntimeSnapshot,
    config::{IpPrefix, NetworkIdentity},
    host::{
        packet::{HostPacketReceiver, host_packet_channel},
        testkit::TestHost,
    },
    peers::peer_manager::PortablePeerManagerConfig,
    tunnel::ring::RingTunnelRegistry,
};

fn test_gateway() -> Arc<DataPlaneRuntime<TestHost>> {
    let runtime_config = CoreRuntimeConfigStore::new(
        crate::config::runtime::CoreRuntimeConfig::default(),
        Arc::new(PeerRuntimeSnapshot::default()),
    );
    let host = Arc::new(TestHost::default());
    let (packet_sender, packet_recv) = mpsc::channel(16);
    Arc::new(DataPlaneRuntime {
        operation: Mutex::new(()),
        runtime_started: AtomicBool::new(false),
        runtime_guard: DataPlaneIoGuard::new(),
        runtime_config,
        peer_manager: Weak::new(),
        transport_proxy: None,
        host: host.clone(),
        socket_context: SocketContext::default(),
        runtime_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
        packet_sender,
        packet_recv: Arc::new(Mutex::new(packet_recv)),
        net: Arc::new(Mutex::new(None)),
        entries: Arc::new(FlowTable::default()),
        udp_fragments: Arc::new(std::sync::Mutex::new(UdpFragments::default())),
        data_plane_consumers: Arc::new(DataPlaneConsumers::new()),
        data_plane_net_ready: tokio::sync::watch::channel(false).0,
        pipeline_guard: Mutex::new(None),
    })
}

struct DataPlaneEndpoint {
    gateway: Arc<DataPlaneRuntime<TestHost>>,
    peer_manager: Arc<PeerManagerCore>,
    _packet_receiver: HostPacketReceiver,
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
    let (packet_sender, packet_receiver) = host_packet_channel();
    let peer_manager = Arc::new(
        PeerManagerCore::new_portable_for_test(peer_config, packet_sender)
            .expect("build portable peer manager"),
    );
    let gateway = DataPlaneRuntime::new(
        runtime_config,
        peer_manager.clone(),
        None,
        host,
        SocketContext::default(),
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
    let (start_a, start_b) = tokio::join!(a.gateway.start_runtime(), b.gateway.start_runtime());
    start_a.unwrap();
    start_b.unwrap();

    let registry = Arc::new(RingTunnelRegistry::default());
    let listener_id = uuid::Uuid::new_v4();
    let mut listener = registry.bind(listener_id).unwrap();
    let client_tunnel = registry.connect(listener_id).unwrap().into_tunnel();
    let server_tunnel = listener.accept().await.unwrap().into_tunnel();
    let (client, server) = tokio::join!(
        b.peer_manager.add_client_tunnel(client_tunnel),
        a.peer_manager.add_tunnel_as_server(server_tunnel),
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
    tokio::join!(a.gateway.stop_runtime(), b.gateway.stop_runtime());
    tokio::join!(
        a.peer_manager.clear_resources(),
        b.peer_manager.clear_resources()
    );
}

async fn wait_for_session_completion(
    session: &DataPlaneSession<TestHost>,
) -> DataPlaneCompletionDescriptor {
    tokio::time::timeout(Duration::from_secs(10), session.completion_notified())
        .await
        .expect("data-plane session completion timed out");
    let completions = session.drain_completions(1);
    assert_eq!(completions.len(), 1);
    completions[0]
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
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut buf);
        ip_packet.set_version(4);
        ip_packet.set_header_len(20);
        ip_packet.set_total_len(40);
        ip_packet.set_hop_limit(64);
        ip_packet.set_next_header(IpProtocol::Tcp);
        ip_packet.set_src_addr(src_ip);
        ip_packet.set_dst_addr(dst_ip);

        let mut tcp_packet = TcpPacket::new_unchecked(ip_packet.payload_mut());
        tcp_packet.set_src_port(src.port());
        tcp_packet.set_dst_port(dst.port());
        tcp_packet.set_header_len(20);
        tcp_packet.set_syn(true);
        tcp_packet.set_ack(true);
        tcp_packet.set_window_len(65535);
        tcp_packet.fill_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip));

        ip_packet.fill_checksum();
    }

    buf
}

pub(super) const UDP_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 144, 144, 1);
const UDP_LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(UDP_LOCAL_IP), 40000);
const UDP_REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 53);

pub(super) fn build_udp_fragments() -> [ZCPacket; 2] {
    let src_ip = Ipv4Addr::new(10, 144, 144, 3);
    let dst_ip = UDP_LOCAL_IP;
    let mut udp = [0; 24];
    {
        let mut packet = UdpPacket::new_unchecked(&mut udp[..]);
        packet.set_src_port(UDP_REMOTE.port());
        packet.set_dst_port(UDP_LOCAL.port());
        packet.set_len(24);
        packet.payload_mut().copy_from_slice(b"fragmented-first");
        packet.fill_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip));
    }

    [(&udp[..16], 0, true), (&udp[16..], 16, false)].map(|(payload, offset, more_fragments)| {
        let mut buf = vec![0; 20 + payload.len()];
        let mut ip = Ipv4Packet::new_unchecked(&mut buf);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len((20 + payload.len()) as u16);
        ip.set_ident(42);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(src_ip);
        ip.set_dst_addr(dst_ip);
        ip.set_frag_offset(offset);
        ip.set_more_frags(more_fragments);
        ip.payload_mut().copy_from_slice(payload);
        ip.fill_checksum();
        let mut packet = ZCPacket::new_with_payload(&buf);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let header = packet.mut_peer_manager_header().unwrap();
        header.set_latency_first(true).set_no_proxy(true);
        header.forward_counter = 3;
        packet
    })
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
async fn data_plane_sessions_complete_tcp_operations_end_to_end() {
    let (a, b) = setup_data_plane_pair().await;
    let session_a = DataPlaneSession::new(&a.gateway);
    let session_b = DataPlaneSession::new(&b.gateway);
    session_a.start().unwrap();
    session_b.start().unwrap();

    let bind = session_b
        .submit_tcp_bind(0, Some(Duration::from_secs(10)))
        .unwrap();
    let completion = wait_for_session_completion(&session_b).await;
    assert_eq!(completion.operation_id, bind);
    let (listener, listen_addr) = session_b
        .take_result_with(bind, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpBound {
                listener,
                local_addr,
            }) => Some((*listener, *local_addr)),
            _ => None,
        })
        .unwrap()
        .unwrap();

    let accept = session_b
        .submit_tcp_accept(listener, Some(Duration::from_secs(10)))
        .unwrap();
    let connect = session_a
        .submit_tcp_connect(listen_addr, Some(Duration::from_secs(10)))
        .unwrap();
    let (connect_completion, accept_completion) = tokio::join!(
        wait_for_session_completion(&session_a),
        wait_for_session_completion(&session_b),
    );
    assert_eq!(connect_completion.operation_id, connect);
    assert_eq!(accept_completion.operation_id, accept);
    let client = session_a
        .take_result_with(connect, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpConnected { stream, .. }) => Some(*stream),
            _ => None,
        })
        .unwrap()
        .unwrap();
    let server = session_b
        .take_result_with(accept, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpAccepted { stream, .. }) => Some(*stream),
            _ => None,
        })
        .unwrap()
        .unwrap();

    let read = session_b.submit_tcp_read(server, 16).unwrap();
    let write = session_a
        .submit_tcp_write(client, b"ping".to_vec())
        .unwrap();
    let (write_completion, read_completion) = tokio::join!(
        wait_for_session_completion(&session_a),
        wait_for_session_completion(&session_b),
    );
    assert_eq!(write_completion.operation_id, write);
    assert_eq!(read_completion.operation_id, read);
    let written = session_a
        .take_result_with(write, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpWritten { len }) => Some(*len),
            _ => None,
        })
        .unwrap()
        .unwrap();
    let received = session_b
        .take_result_with(read, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpRead { data, eof }) if !eof => Some(data.clone()),
            _ => None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(written, 4);
    assert_eq!(received, b"ping");

    let eof_read = session_b.submit_tcp_read(server, 16).unwrap();
    let shutdown = session_a.submit_tcp_shutdown_write(client).unwrap();
    let shutdown_completion = wait_for_session_completion(&session_a).await;
    let eof_completion = wait_for_session_completion(&session_b).await;
    assert_eq!(shutdown_completion.operation_id, shutdown);
    assert_eq!(eof_completion.operation_id, eof_read);
    session_a
        .take_result_with(shutdown, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpWriteShutdown) => Some(()),
            _ => None,
        })
        .unwrap()
        .unwrap();
    let eof = session_b
        .take_result_with(eof_read, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpRead { data, eof }) => Some((data.clone(), *eof)),
            _ => None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(eof, (Vec::new(), true));

    let response_read = session_a.submit_tcp_read(client, 16).unwrap();
    let response_write = session_b
        .submit_tcp_write(server, b"pong".to_vec())
        .unwrap();
    let (response_read_completion, response_write_completion) = tokio::join!(
        wait_for_session_completion(&session_a),
        wait_for_session_completion(&session_b),
    );
    assert_eq!(response_read_completion.operation_id, response_read);
    assert_eq!(response_write_completion.operation_id, response_write);
    let response = session_a
        .take_result_with(response_read, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpRead { data, eof }) if !eof => Some(data.clone()),
            _ => None,
        })
        .unwrap()
        .unwrap();
    let response_len = session_b
        .take_result_with(response_write, |outcome| match outcome {
            Ok(DataPlaneOperationResult::TcpWritten { len }) => Some(*len),
            _ => None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(response, b"pong");
    assert_eq!(response_len, 4);

    let blocked_read = session_b.submit_tcp_read(server, 16).unwrap();
    session_b.close_resource(server);
    let close_completion = wait_for_session_completion(&session_b).await;
    assert_eq!(close_completion.operation_id, blocked_read);
    assert_eq!(
        close_completion.status,
        DataPlaneCompletionStatus::Error(DataPlaneErrorKind::HandleClosed)
    );
    let close_error = session_b
        .take_result_with(blocked_read, |outcome| outcome.as_ref().err().copied())
        .unwrap()
        .unwrap();
    assert_eq!(close_error, DataPlaneErrorKind::HandleClosed);

    let stopped_read = session_a.submit_tcp_read(client, 16).unwrap();
    session_a.stop();
    let stop_completion = wait_for_session_completion(&session_a).await;
    assert_eq!(stop_completion.operation_id, stopped_read);
    assert_eq!(
        stop_completion.status,
        DataPlaneCompletionStatus::Error(DataPlaneErrorKind::InstanceStopped)
    );

    session_a.close_resource(client);
    session_b.close_resource(listener);
    session_b.stop();
    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test]
async fn data_plane_sessions_report_udp_truncation() {
    let (a, b) = setup_data_plane_pair().await;
    let session_a = DataPlaneSession::new(&a.gateway);
    let session_b = DataPlaneSession::new(&b.gateway);
    session_a.start().unwrap();
    session_b.start().unwrap();

    let bind_a = session_a.submit_udp_bind(0, None).unwrap();
    let bind_b = session_b.submit_udp_bind(0, None).unwrap();
    let (completion_a, completion_b) = tokio::join!(
        wait_for_session_completion(&session_a),
        wait_for_session_completion(&session_b),
    );
    assert_eq!(completion_a.operation_id, bind_a);
    assert_eq!(completion_b.operation_id, bind_b);
    let (socket_a, addr_a) = session_a
        .take_result_with(bind_a, |outcome| match outcome {
            Ok(DataPlaneOperationResult::UdpBound { socket, local_addr }) => {
                Some((*socket, *local_addr))
            }
            _ => None,
        })
        .unwrap()
        .unwrap();
    let (socket_b, addr_b) = session_b
        .take_result_with(bind_b, |outcome| match outcome {
            Ok(DataPlaneOperationResult::UdpBound { socket, local_addr }) => {
                Some((*socket, *local_addr))
            }
            _ => None,
        })
        .unwrap()
        .unwrap();

    let receive = session_b.submit_udp_receive(socket_b, 2).unwrap();
    let send = session_a
        .submit_udp_send(socket_a, addr_b, b"ping".to_vec())
        .unwrap();
    let (send_completion, receive_completion) = tokio::join!(
        wait_for_session_completion(&session_a),
        wait_for_session_completion(&session_b),
    );
    assert_eq!(send_completion.operation_id, send);
    assert_eq!(receive_completion.operation_id, receive);
    let (data, peer_addr, truncated) = session_b
        .take_result_with(receive, |outcome| match outcome {
            Ok(DataPlaneOperationResult::UdpReceived {
                data,
                peer_addr,
                truncated,
            }) => Some((data.clone(), *peer_addr, *truncated)),
            _ => None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(data, b"pi");
    assert_eq!(peer_addr, addr_a);
    assert!(truncated);

    session_a.close_resource(socket_a);
    session_b.close_resource(socket_b);
    session_a.stop();
    session_b.stop();
    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test]
async fn public_tcp_connect_never_falls_back_to_an_unrelated_host() {
    let host = Arc::new(TestHost::default());
    let endpoint = data_plane_endpoint(host, "10.126.131.1/24".parse().unwrap());
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();

    let error = match endpoint
        .gateway
        .data_plane_tcp_connect("192.0.2.10:443".parse().unwrap(), Duration::from_secs(1))
        .await
    {
        Ok(_) => panic!("public data plane unexpectedly used a Host TCP route"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), DataPlaneErrorKind::NoOverlayRoute);
    assert_eq!(endpoint.gateway.host.tcp_binds.load(Ordering::Relaxed), 0);

    endpoint.gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn listener_and_accepted_stream_own_independent_flow_lifetimes() {
    let (a, b) = setup_data_plane_pair().await;
    let timeout = Duration::from_secs(10);
    let mut listener = b.gateway.data_plane_tcp_bind(0, timeout).await.unwrap();
    let listen_addr = SocketAddr::new(b.ip.address().into(), listener.local_addr().port());

    let (accepted, client) = tokio::join!(
        listener.accept(),
        a.gateway.data_plane_tcp_connect(listen_addr, timeout),
    );
    let (mut server, peer_addr) = accepted.unwrap();
    let mut client = client.unwrap();

    assert_eq!(client.local_addr(), peer_addr);
    assert_eq!(a.gateway.entries.count(), 1);
    assert_eq!(b.gateway.entries.count(), 2);

    drop(listener);
    assert_eq!(b.gateway.entries.count(), 1);

    client.write_all(b"after-listener-drop").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 19];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"after-listener-drop");

    drop(client);
    assert_eq!(a.gateway.entries.count(), 0);
    drop(server);
    assert_eq!(b.gateway.entries.count(), 0);

    stop_data_plane_pair(&a, &b).await;
}

async fn send_udp(sender: &DataPlaneUdpSocket, receiver: &DataPlaneUdpSocket, data: &[u8]) {
    sender.send_to(data, receiver.local_addr()).await.unwrap();
    let mut buf = vec![0; data.len()];
    let (len, from) = tokio::time::timeout(Duration::from_secs(10), receiver.recv_from(&mut buf))
        .await
        .expect("UDP receive timed out")
        .unwrap();
    assert_eq!(&buf[..len], data);
    assert_eq!(from, sender.local_addr());
}

#[tokio::test]
async fn data_plane_udp_pingpong() {
    let (a, b) = setup_data_plane_pair().await;
    let timeout = Duration::from_secs(10);
    let first = a.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    let second = a.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    let receiver = b.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    assert_ne!(first.local_addr(), second.local_addr());
    for sender in [&first, &second] {
        assert_ne!(sender.local_addr().port(), 0);
        assert_eq!(sender.local_addr().ip(), IpAddr::V4(a.ip.address()));
        send_udp(sender, &receiver, b"ping").await;
        send_udp(&receiver, sender, b"pong").await;
    }
    // Sending to different destinations must not create per-remote flows.
    assert_eq!(a.gateway.entries.count(), 2);
    assert_eq!(b.gateway.entries.count(), 1);
    assert_eq!(a.gateway.host.udp_binds.load(Ordering::Relaxed), 0);
    assert_eq!(b.gateway.host.udp_binds.load(Ordering::Relaxed), 0);
    drop((first, second, receiver));
    assert_eq!(a.gateway.entries.count(), 0);
    assert_eq!(b.gateway.entries.count(), 0);
    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test]
async fn data_plane_udp_carries_maximum_ipv4_payload() {
    let (a, b) = setup_data_plane_pair().await;
    let timeout = Duration::from_secs(10);
    let socket_a = a.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    let socket_b = b.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    send_udp(&socket_a, &socket_b, &vec![0x5a; 65_507]).await;
    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test]
async fn udp_fixed_ports_are_owned_by_each_instance_until_socket_drop() {
    let (a, b) = setup_data_plane_pair().await;
    let timeout = Duration::from_secs(10);
    let first = a.gateway.data_plane_udp_bind(48000, timeout).await.unwrap();
    let second = b.gateway.data_plane_udp_bind(48000, timeout).await.unwrap();
    let error = a
        .gateway
        .data_plane_udp_bind(48000, timeout)
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), DataPlaneErrorKind::AddressInUse);
    assert_eq!(a.gateway.entries.count(), 1);
    send_udp(&first, &second, b"same-port").await;
    let addr = first.local_addr();
    drop(first);
    assert_eq!(a.gateway.entries.count(), 0);
    let rebound = a.gateway.data_plane_udp_bind(48000, timeout).await.unwrap();
    assert_eq!(rebound.local_addr(), addr);
    send_udp(&second, &rebound, b"rebound").await;
    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_udp_binds_have_exactly_one_owner() {
    let host = Arc::new(TestHost::default());
    let endpoint = data_plane_endpoint(host, "10.126.132.1/24".parse().unwrap());
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let gateway = endpoint.gateway.clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            gateway
                .data_plane_udp_bind(48000, Duration::from_secs(10))
                .await
        });
    }
    let mut sockets = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(socket) => sockets.push(socket),
            Err(error) => assert_eq!(error.kind(), DataPlaneErrorKind::AddressInUse),
        }
    }
    assert_eq!(sockets.len(), 1);
    assert_eq!(endpoint.gateway.entries.count(), 1);
    assert_eq!(endpoint.gateway.host.udp_binds.load(Ordering::Relaxed), 0);
    drop(sockets);
    assert_eq!(endpoint.gateway.entries.count(), 0);
    endpoint.gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn udp_ephemeral_allocation_advances_past_collisions() {
    let endpoint = data_plane_endpoint(
        Arc::new(TestHost::default()),
        "10.126.132.1/24".parse().unwrap(),
    );
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();
    let gateway = &endpoint.gateway;
    let timeout = Duration::from_secs(10);
    let fixed = gateway.data_plane_udp_bind(11000, timeout).await.unwrap();
    for port in 10001..11000 {
        let addr = SocketAddr::new(endpoint.ip.address().into(), port);
        gateway
            .entries
            .insert(FlowKey::udp_bind(addr), FlowData::Udp);
    }
    let socket = gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    assert_eq!(socket.local_addr().port(), 11001);
    let net = gateway.net.lock().await.as_ref().unwrap().net.clone();
    assert_eq!(net.get_port(), 11002);
    let next = gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    assert_eq!(next.local_addr().port(), 11003);

    let mut slow = net.ephemeral_ports();
    let last = net.ephemeral_ports().nth(10).unwrap();
    slow.nth(2);
    assert_eq!(net.get_port(), last + 1);
    drop((fixed, socket, next));
    gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn udp_ephemeral_bind_wraps_and_reports_exhaustion() {
    let host = Arc::new(TestHost::default());
    let endpoint = data_plane_endpoint(host.clone(), "10.126.132.1/24".parse().unwrap());
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();
    let gateway = &endpoint.gateway;
    let timeout = Duration::from_secs(10);
    let fixed = gateway.data_plane_udp_bind(60001, timeout).await.unwrap();
    // Leave only the port reached after wrapping past the end of the range.
    for port in 10001..60001 {
        let addr = SocketAddr::new(endpoint.ip.address().into(), port);
        gateway
            .entries
            .insert(FlowKey::udp_bind(addr), FlowData::Udp);
    }
    let socket = gateway.data_plane_udp_bind(0, timeout).await.unwrap();
    assert_eq!(socket.local_addr().port(), 10000);
    let error = gateway.data_plane_udp_bind(0, timeout).await.err().unwrap();
    assert_eq!(error.kind(), DataPlaneErrorKind::ResourceLimit);
    assert_eq!(host.udp_binds.load(Ordering::Relaxed), 0);

    drop((fixed, socket));
    gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn final_data_plane_lease_releases_net_and_same_ipv4_reacquires_it() {
    let host = Arc::new(TestHost::default());
    let endpoint = data_plane_endpoint(host, "10.126.127.1/24".parse().unwrap());
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();

    let socket = endpoint
        .gateway
        .data_plane_udp_bind(0, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(endpoint.gateway.net.lock().await.is_some());

    drop(socket);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if endpoint.gateway.net.lock().await.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("final data-plane lease did not release smoltcp net");

    let socket = endpoint
        .gateway
        .data_plane_udp_bind(0, Duration::from_secs(1))
        .await
        .expect("same IPv4 generation should be recreated");
    assert!(endpoint.gateway.net.lock().await.is_some());

    drop(socket);
    endpoint.gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn immediate_consumer_reacquire_never_leases_closing_generation() {
    let host = Arc::new(TestHost::default());
    let endpoint = data_plane_endpoint(host, "10.126.133.1/24".parse().unwrap());
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();
    let destination: SocketAddr = "10.126.133.2:31001".parse().unwrap();

    for _ in 0..20 {
        let socket = endpoint
            .gateway
            .data_plane_udp_bind(0, Duration::from_secs(1))
            .await
            .expect("consumer should acquire the current smoltcp generation");
        socket
            .send_to(b"generation-probe", destination)
            .await
            .expect("new consumer must not inherit a closing generation");
        drop(socket);
        tokio::task::yield_now().await;
    }

    endpoint.gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn tcp_connect_survives_ipv4_generation_replacement() {
    let (a, b) = setup_data_plane_pair().await;
    let _consumer = b.gateway.acquire_consumer_lease().unwrap();

    for ip in ["10.126.127.2", "10.126.126.2"] {
        let ip: IpAddr = ip.parse().unwrap();
        b.gateway.runtime_config.update_peer_with(|peer| {
            peer.runtime.core.routes.ipv4 = Some(IpPrefix::new(ip, 24).unwrap());
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if b.gateway
                    .net
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|plane| IpAddr::V4(plane.ipv4_addr.address()) == ip)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("data-plane IPv4 generation did not update");
    }

    let timeout = Duration::from_secs(10);
    let mut listener = b.gateway.data_plane_tcp_bind(0, timeout).await.unwrap();
    let listen_addr = SocketAddr::new(b.ip.address().into(), listener.local_addr().port());
    let (accepted, client) = tokio::join!(
        listener.accept(),
        a.gateway.data_plane_tcp_connect(listen_addr, timeout),
    );
    let (mut server, _) = accepted.unwrap();
    let mut client = client.unwrap();

    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    stop_data_plane_pair(&a, &b).await;
}

#[tokio::test]
async fn ipv4_change_closes_existing_generation_with_typed_error() {
    let host = Arc::new(TestHost::default());
    let endpoint = data_plane_endpoint(host, "10.126.128.1/24".parse().unwrap());
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();
    let socket = endpoint
        .gateway
        .data_plane_udp_bind(0, Duration::from_secs(1))
        .await
        .unwrap();

    endpoint.gateway.runtime_config.update_peer_with(|peer| {
        peer.runtime.core.routes.ipv4 =
            Some(IpPrefix::new("10.126.129.1".parse().unwrap(), 24).unwrap());
    });

    let mut buf = [0u8; 1];
    let error = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
        .await
        .expect("old generation receive did not wake")
        .unwrap_err();
    let data_plane_error = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<DataPlaneError>())
        .expect("generation close must preserve the typed data-plane error");
    assert_eq!(data_plane_error.kind(), DataPlaneErrorKind::NetworkChanged);

    drop(socket);
    endpoint.gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn readiness_timeout_has_stable_error_kind() {
    let host = Arc::new(TestHost::default());
    let endpoint = data_plane_endpoint(host, "10.126.130.1/24".parse().unwrap());
    endpoint
        .gateway
        .runtime_config
        .update_peer_with(|peer| peer.runtime.core.routes.ipv4 = None);
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();

    let error = match endpoint
        .gateway
        .data_plane_udp_bind(0, Duration::from_millis(1))
        .await
    {
        Ok(_) => panic!("data-plane bind unexpectedly succeeded without an IPv4 address"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), DataPlaneErrorKind::DeadlineExceeded);

    endpoint.gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}

#[tokio::test]
async fn data_plane_consumes_modified_data_when_entry_matches() {
    let gateway = test_gateway();

    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
    let entry = FlowKey {
        src: local,
        dst: remote,
        kind: TCP_ENTRY,
    };
    gateway.entries.insert(
        entry,
        FlowData::Tcp {
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
        assert!(matches!(result, PeerPacketFilterResult::Consumed));

        let mut receiver = gateway.packet_recv.lock().await;
        let received = receiver.try_recv().unwrap();
        assert_eq!(
            received.peer_manager_header().unwrap().packet_type,
            packet_type as u8
        );
    }
}

#[tokio::test]
async fn data_plane_passes_through_unmatched_or_malformed_modified_data() {
    let gateway = test_gateway();
    gateway.entries.insert(
        FlowKey {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22),
            kind: TCP_ENTRY,
        },
        FlowData::Tcp {
            _reservation: Arc::new(()),
        },
    );

    let unmatched_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40001);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
    let mut unmatched_packet =
        ZCPacket::new_with_payload(&build_tcp_packet(remote, unmatched_local));
    unmatched_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);
    let result = gateway.try_process_packet_from_peer(unmatched_packet).await;
    assert!(matches!(result, PeerPacketFilterResult::Pass(_)));

    let mut malformed_packet = ZCPacket::new_with_payload(&[0u8; 8]);
    malformed_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithQuicSrcModified as u8);
    let result = gateway.try_process_packet_from_peer(malformed_packet).await;
    assert!(matches!(result, PeerPacketFilterResult::Pass(_)));

    let mut receiver = gateway.packet_recv.lock().await;
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn data_plane_passes_through_non_loopback_modified_data_when_entry_matches() {
    let gateway = test_gateway();

    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
    let entry = FlowKey {
        src: local,
        dst: remote,
        kind: TCP_ENTRY,
    };
    gateway.entries.insert(
        entry,
        FlowData::Tcp {
            _reservation: Arc::new(()),
        },
    );

    let mut packet = ZCPacket::new_with_payload(&build_tcp_packet(remote, local));
    packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);

    let result = gateway.try_process_packet_from_peer(packet).await;
    assert!(matches!(result, PeerPacketFilterResult::Pass(_)));

    let mut receiver = gateway.packet_recv.lock().await;
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn data_plane_routes_udp_fragments_together() {
    for port in [None, Some(UDP_LOCAL.port() + 1), Some(UDP_LOCAL.port())] {
        for reverse in [false, true] {
            let gateway = test_gateway();
            gateway.runtime_config.update_peer_with(|peer| {
                peer.runtime.core.routes.ipv4 =
                    Some(IpPrefix::new(UDP_LOCAL_IP.into(), 24).unwrap());
            });
            if let Some(port) = port {
                gateway.entries.insert(
                    FlowKey::udp_bind(SocketAddr::new(UDP_LOCAL_IP.into(), port)),
                    FlowData::Udp,
                );
            }
            let mut downstream = Vec::new();
            let mut delivered = Vec::new();
            let mut expected = Vec::new();
            // More than smoltcp's 16 slots, with every tail arriving before any first.
            for index in if reverse { [1, 0] } else { [0, 1] } {
                for id in 0..32 {
                    let mut packet = build_udp_fragments().into_iter().nth(index).unwrap();
                    let mut ip = Ipv4Packet::new_unchecked(packet.mut_payload());
                    ip.set_ident(id);
                    ip.fill_checksum();
                    expected.push(packet.clone().into_bytes());
                    match gateway.try_process_packet_from_peer(packet).await {
                        PeerPacketFilterResult::Consumed => {}
                        PeerPacketFilterResult::Pass(packet) => {
                            downstream.push(packet.into_bytes())
                        }
                        PeerPacketFilterResult::PassBatch(packets) => {
                            downstream.extend(packets.into_iter().map(ZCPacket::into_bytes))
                        }
                    }
                    let mut receiver = gateway.packet_recv.lock().await;
                    while let Ok(packet) = receiver.try_recv() {
                        delivered.push(packet.into_bytes());
                    }
                }
            }
            expected.sort();
            downstream.sort();
            delivered.sort();
            if port == Some(UDP_LOCAL.port()) {
                assert_eq!(delivered, expected);
                assert!(downstream.is_empty());
            } else {
                assert_eq!(downstream, expected);
                assert!(delivered.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn data_plane_only_buffers_eligible_local_udp_fragments() {
    let gateway = test_gateway();
    gateway.runtime_config.update_peer_with(|peer| {
        peer.runtime.core.routes.ipv4 = Some(IpPrefix::new(UDP_LOCAL_IP.into(), 24).unwrap());
    });
    gateway
        .entries
        .insert(FlowKey::udp_bind(UDP_LOCAL), FlowData::Udp);
    for (destination, packet_type, to_peer, buffered) in [
        (UDP_LOCAL_IP, PacketType::Data, 2, true),
        (Ipv4Addr::new(10, 144, 144, 9), PacketType::Data, 2, false),
        (UDP_LOCAL_IP, PacketType::DataWithKcpSrcModified, 1, true),
        (UDP_LOCAL_IP, PacketType::DataWithKcpSrcModified, 2, false),
        (UDP_LOCAL_IP, PacketType::DataWithQuicSrcModified, 1, true),
        (UDP_LOCAL_IP, PacketType::DataWithQuicSrcModified, 2, false),
    ] {
        let [_, mut tail] = build_udp_fragments();
        let mut ip = Ipv4Packet::new_unchecked(tail.mut_payload());
        ip.set_dst_addr(destination);
        ip.fill_checksum();
        tail.fill_peer_manager_hdr(1, to_peer, packet_type as u8);
        let expected = tail.clone().into_bytes();
        let result = gateway.try_process_packet_from_peer(tail).await;
        if buffered {
            assert!(matches!(result, PeerPacketFilterResult::Consumed));
        } else {
            let PeerPacketFilterResult::Pass(packet) = result else {
                panic!("unrelated fragment buffered")
            };
            assert_eq!(packet.into_bytes(), expected);
        }
        assert!(gateway.packet_recv.lock().await.try_recv().is_err());
    }
}

#[tokio::test]
async fn data_plane_udp_receives_fragments_after_unbound_datagrams() {
    let endpoint = data_plane_endpoint(
        Arc::new(TestHost::default()),
        "10.144.144.1/24".parse().unwrap(),
    );
    endpoint.peer_manager.run().await.unwrap();
    endpoint.gateway.start_runtime().await.unwrap();
    let timeout = Duration::from_secs(10);
    let socket = endpoint
        .gateway
        .data_plane_udp_bind(UDP_LOCAL.port(), timeout)
        .await
        .unwrap();
    // Unrelated complete datagrams must never leave orphan tails in smoltcp.
    for id in 0..32 {
        for mut packet in build_udp_fragments() {
            let mut ip = Ipv4Packet::new_unchecked(packet.mut_payload());
            ip.set_ident(id);
            if ip.frag_offset() == 0 {
                let mut udp = UdpPacket::new_unchecked(ip.payload_mut());
                udp.set_dst_port(UDP_LOCAL.port() + 1);
                udp.set_checksum(0);
            }
            ip.fill_checksum();
            assert!(matches!(
                endpoint.gateway.try_process_packet_from_peer(packet).await,
                PeerPacketFilterResult::Pass(_)
            ));
        }
    }
    let [first, tail] = build_udp_fragments();
    for packet in [tail, first] {
        assert!(matches!(
            endpoint.gateway.try_process_packet_from_peer(packet).await,
            PeerPacketFilterResult::Consumed
        ));
    }
    let mut data = [0; 32];
    let (len, from) = tokio::time::timeout(timeout, socket.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data[..len], b"fragmented-first");
    assert_eq!(from, UDP_REMOTE);
    // A datagram larger than either MTU remains a set of original small packets.
    for port in [UDP_LOCAL.port(), UDP_LOCAL.port() + 1] {
        let mut udp = vec![0; 8 + 4096];
        let mut udp_packet = UdpPacket::new_unchecked(&mut udp);
        udp_packet.set_src_port(UDP_REMOTE.port());
        udp_packet.set_dst_port(port);
        udp_packet.set_len(4104);
        udp_packet.payload_mut().fill(0xab);
        udp_packet.fill_checksum(&UDP_REMOTE.ip().into(), &UDP_LOCAL.ip().into());
        let [template, _] = build_udp_fragments();
        let mut fragments = Vec::new();
        for (index, payload) in udp.chunks(1200).enumerate() {
            let mut bytes = template.payload()[..20].to_vec();
            bytes.extend_from_slice(payload);
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
            ip.set_ident(port);
            ip.set_total_len((20 + payload.len()) as u16);
            ip.set_frag_offset((index * 1200) as u16);
            ip.set_more_frags((index + 1) * 1200 < udp.len());
            ip.fill_checksum();
            let mut packet = ZCPacket::new_with_payload(&bytes);
            packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
            fragments.push(packet);
        }
        let mut expected = fragments
            .iter()
            .map(|p| p.clone().into_bytes())
            .collect::<Vec<_>>();
        let mut passed = Vec::new();
        for packet in fragments.into_iter().rev() {
            match endpoint.gateway.try_process_packet_from_peer(packet).await {
                PeerPacketFilterResult::Consumed => {}
                PeerPacketFilterResult::Pass(_) => panic!("tails should wait for the first"),
                PeerPacketFilterResult::PassBatch(packets) => {
                    assert!(packets.iter().all(|packet| packet.payload_len() <= 1280));
                    passed.extend(packets.into_iter().map(ZCPacket::into_bytes));
                }
            }
        }
        if port == UDP_LOCAL.port() {
            assert!(passed.is_empty());
            let mut data = vec![0; 4096];
            let (len, from) = tokio::time::timeout(timeout, socket.recv_from(&mut data))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(len, 4096);
            assert_eq!(data, vec![0xab; 4096]);
            assert_eq!(from, UDP_REMOTE);
        } else {
            expected.sort();
            passed.sort();
            assert_eq!(passed, expected);
        }
    }
    drop(socket);
    endpoint.gateway.stop_runtime().await;
    endpoint.peer_manager.clear_resources().await;
}
