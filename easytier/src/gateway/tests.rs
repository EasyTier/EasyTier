use std::{sync::Arc, time::Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    common::global_ctx::tests::get_mock_global_ctx,
    connector::core_instance::{
        RuntimeCoreInstance, build_runtime_core_instance, runtime_instance_config,
    },
    peers::{
        create_packet_recv_chan,
        peer_manager::{PeerManager, RouteAlgoType},
    },
    proto::common::TunnelInfo,
    tunnel::Tunnel,
    tunnel::common::tests::wait_for_condition,
};
use easytier_core::tunnel::ring::{RingTunnel, create_ring_socket_pair};

struct Endpoint {
    _peer: Arc<PeerManager>,
    core: Arc<RuntimeCoreInstance>,
    ip: cidr::Ipv4Inet,
}

fn ring_tunnel_info(local: &str, remote: &str) -> TunnelInfo {
    TunnelInfo {
        tunnel_type: "ring".to_owned(),
        local_addr: Some(local.parse::<url::Url>().unwrap().into()),
        remote_addr: Some(remote.parse::<url::Url>().unwrap().into()),
        resolved_remote_addr: Some(remote.parse::<url::Url>().unwrap().into()),
    }
}

async fn connect_peer_manager(client: Arc<PeerManager>, server: Arc<PeerManager>) {
    let (client_socket, server_socket) = create_ring_socket_pair(1024);
    let client_tunnel: Box<dyn Tunnel> = Box::new(RingTunnel::new(
        client_socket,
        Some(ring_tunnel_info("ring://client", "ring://server")),
    ));
    let server_tunnel: Box<dyn Tunnel> = Box::new(RingTunnel::new(
        server_socket,
        Some(ring_tunnel_info("ring://server", "ring://client")),
    ));
    tokio::spawn(async move {
        client
            .core()
            .add_client_tunnel(client_tunnel, false)
            .await
            .unwrap();
    });
    tokio::spawn(async move {
        server
            .core()
            .add_tunnel_as_server(server_tunnel, true)
            .await
            .unwrap();
    });
}

async fn setup_pair() -> (Endpoint, Endpoint) {
    let create_peer = || {
        let (packet_sender, _packet_receiver) = create_packet_recv_chan();
        Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            get_mock_global_ctx(),
            packet_sender,
        ))
    };
    let a = create_peer();
    let b = create_peer();

    let a_ip: cidr::Ipv4Inet = "10.126.126.1/24".parse().unwrap();
    let b_ip: cidr::Ipv4Inet = "10.126.126.2/24".parse().unwrap();
    a.get_global_ctx().set_ipv4(Some(a_ip));
    b.get_global_ctx().set_ipv4(Some(b_ip));
    a.refresh_runtime_config();
    b.refresh_runtime_config();

    let core_a = Arc::new(
        build_runtime_core_instance(a.get_global_ctx(), a.clone())
            .expect("build first core instance"),
    );
    let core_b = Arc::new(
        build_runtime_core_instance(b.get_global_ctx(), b.clone())
            .expect("build second core instance"),
    );
    for (core, peer) in [(&core_a, &a), (&core_b, &b)] {
        core.update_runtime_config(runtime_instance_config(&peer.get_global_ctx()))
            .await
            .unwrap();
        core.start().await.unwrap();
        core.start_gateway().await.unwrap();
    }

    connect_peer_manager(a.clone(), b.clone()).await;
    wait_for_condition(
        || async {
            a.core()
                .get_route()
                .get_peer_id_by_ipv4(&b_ip.address())
                .await
                .is_some()
        },
        Duration::from_secs(10),
    )
    .await;

    (
        Endpoint {
            _peer: a,
            core: core_a,
            ip: a_ip,
        },
        Endpoint {
            _peer: b,
            core: core_b,
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
