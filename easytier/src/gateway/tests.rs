use std::{sync::Arc, time::Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    common::global_ctx::{NetworkIdentity, tests::get_mock_global_ctx_with_network},
    instance::composition::{
        NativeCoreInstance, runtime_core_instance_adapters, runtime_direct_options,
        runtime_endpoint_discovery_config, runtime_stun_server_config,
    },
    instance::config::runtime_peer_manager_config,
    tunnel::common::tests::wait_for_condition,
};
use easytier_core::{
    instance::{CoreInstanceConfig, PortableCoreInstanceConfig},
    listener::transport::TransportListenerConfig,
    peers::peer_manager::RouteAlgoType,
    socket::tcp::TcpListenOptions,
};

struct Endpoint {
    core: Arc<NativeCoreInstance>,
    _packet_receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ip: cidr::Ipv4Inet,
}

async fn setup_pair() -> (Endpoint, Endpoint) {
    let a_ip: cidr::Ipv4Inet = "10.126.126.1/24".parse().unwrap();
    let b_ip: cidr::Ipv4Inet = "10.126.126.2/24".parse().unwrap();
    let network = || {
        Some(NetworkIdentity::new(
            "gateway-data-plane".to_owned(),
            "shared-secret".to_owned(),
        ))
    };
    let global_a = get_mock_global_ctx_with_network(network());
    let global_b = get_mock_global_ctx_with_network(network());
    global_a.set_ipv4(Some(a_ip));
    global_b.set_ipv4(Some(b_ip));

    let (packet_sink_a, packet_receiver_a) = tokio::sync::mpsc::channel(16);
    let (packet_sink_b, packet_receiver_b) = tokio::sync::mpsc::channel(16);
    let peer_a = runtime_peer_manager_config(&global_a, RouteAlgoType::Ospf);
    let peer_b = runtime_peer_manager_config(&global_b, RouteAlgoType::Ospf);
    let connectivity_a = CoreInstanceConfig {
        initial_peers: Vec::new(),
        listeners: vec![TransportListenerConfig::Tcp {
            url: "tcp://127.0.0.1:0".parse().unwrap(),
            options: TcpListenOptions::manual_connect("127.0.0.1:0".parse().unwrap()),
            must_succeed: true,
        }],
        runtime: Default::default(),
        stun: runtime_stun_server_config(&global_a),
        endpoint_discovery: runtime_endpoint_discovery_config(&global_a),
        manual: Default::default(),
        direct: runtime_direct_options(&global_a, true),
    };
    let connectivity_b = CoreInstanceConfig {
        initial_peers: Vec::new(),
        listeners: Vec::new(),
        runtime: Default::default(),
        stun: runtime_stun_server_config(&global_b),
        endpoint_discovery: runtime_endpoint_discovery_config(&global_b),
        manual: Default::default(),
        direct: runtime_direct_options(&global_b, true),
    };
    let core_a = NativeCoreInstance::new_portable(
        runtime_core_instance_adapters(global_a),
        PortableCoreInstanceConfig {
            peer: peer_a,
            connectivity: connectivity_a,
        },
        Arc::new(packet_sink_a),
    )
    .expect("build first core instance");
    let core_b = NativeCoreInstance::new_portable(
        runtime_core_instance_adapters(global_b),
        PortableCoreInstanceConfig {
            peer: peer_b,
            connectivity: connectivity_b,
        },
        Arc::new(packet_sink_b),
    )
    .expect("build second core instance");
    let core_a = Arc::new(core_a);
    let core_b = Arc::new(core_b);

    let (start_a, start_b) = tokio::join!(core_a.start(), core_b.start());
    start_a.unwrap();
    start_b.unwrap();
    core_a.start_gateway().await.unwrap();
    core_b.start_gateway().await.unwrap();
    assert_ne!(core_a.peer_id(), core_b.peer_id());
    let listener = core_a
        .running_listeners()
        .into_iter()
        .find(|url| url.scheme() == "tcp")
        .expect("second core instance should own a TCP listener");
    core_b.add_connector(listener).unwrap();
    let b_peer_id = core_b.peer_id();
    wait_for_condition(
        || {
            let core_a = core_a.clone();
            async move {
                core_a
                    .route_snapshots()
                    .await
                    .iter()
                    .any(|route| route.peer_id == b_peer_id && route.ipv4_addr == Some(b_ip.into()))
            }
        },
        Duration::from_secs(10),
    )
    .await;

    (
        Endpoint {
            core: core_a,
            _packet_receiver: packet_receiver_a,
            ip: a_ip,
        },
        Endpoint {
            core: core_b,
            _packet_receiver: packet_receiver_b,
            ip: b_ip,
        },
    )
}

#[tokio::test]
async fn data_plane_tcp_pingpong() {
    let (a, b) = setup_pair().await;
    let timeout = Duration::from_secs(10);
    let mut listener = b.core.data_plane_tcp_bind(0, timeout).await.unwrap();
    let listen_addr =
        std::net::SocketAddr::new(b.ip.address().into(), listener.local_addr().port());

    let accept = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.flush().await.unwrap();
    });

    let mut client = a
        .core
        .data_plane_tcp_connect(listen_addr, timeout)
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    accept.await.unwrap();

    a.core.stop().await;
    b.core.stop().await;
}

#[tokio::test]
async fn data_plane_udp_pingpong() {
    let (a, b) = setup_pair().await;
    let timeout = Duration::from_secs(10);
    let socket_a = a.core.data_plane_udp_bind(0, timeout).await.unwrap();
    let socket_b = b.core.data_plane_udp_bind(0, timeout).await.unwrap();
    let addr_a = std::net::SocketAddr::new(a.ip.address().into(), socket_a.local_addr().port());
    let addr_b = std::net::SocketAddr::new(b.ip.address().into(), socket_b.local_addr().port());

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

    a.core.stop().await;
    b.core.stop().await;
}
