use std::sync::{atomic::AtomicU32, Arc};

use tokio::{net::UdpSocket, task::JoinSet};

use super::*;

use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        netns::{NetNS, ROOT_NETNS_NAME},
    },
    instance::instance::Instance,
    tunnels::{
        common::tests::_tunnel_pingpong_netns,
        ring_tunnel::RingTunnelConnector,
        tcp_tunnel::{TcpTunnelConnector, TcpTunnelListener},
        udp_tunnel::{UdpTunnelConnector, UdpTunnelListener},
    },
};

pub fn prepare_linux_namespaces() {
    del_netns("net_a");
    del_netns("net_b");
    del_netns("net_c");
    del_netns("net_d");

    create_netns("net_a", "10.1.1.1/24");
    create_netns("net_b", "10.1.1.2/24");
    create_netns("net_c", "10.1.2.3/24");
    create_netns("net_d", "10.1.2.4/24");

    prepare_bridge("br_a");
    prepare_bridge("br_b");

    add_ns_to_bridge("br_a", "net_a");
    add_ns_to_bridge("br_a", "net_b");
    add_ns_to_bridge("br_b", "net_c");
    add_ns_to_bridge("br_b", "net_d");
}

pub fn get_inst_config(inst_name: &str, ns: Option<&str>, ipv4: &str) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(ipv4.parse().unwrap());
    config.set_listeners(vec![
        "tcp://0.0.0.0:11010".parse().unwrap(),
        "udp://0.0.0.0:11010".parse().unwrap(),
    ]);
    config
}

pub async fn init_three_node(proto: &str) -> Vec<Instance> {
    log::set_max_level(log::LevelFilter::Info);
    prepare_linux_namespaces();

    let mut inst1 = Instance::new(get_inst_config("inst1", Some("net_a"), "10.144.144.1"));
    let mut inst2 = Instance::new(get_inst_config("inst2", Some("net_b"), "10.144.144.2"));
    let mut inst3 = Instance::new(get_inst_config("inst3", Some("net_c"), "10.144.144.3"));

    inst1.run().await.unwrap();
    inst2.run().await.unwrap();
    inst3.run().await.unwrap();

    if proto == "tcp" {
        inst2
            .get_conn_manager()
            .add_connector(TcpTunnelConnector::new(
                "tcp://10.1.1.1:11010".parse().unwrap(),
            ));
    } else {
        inst2
            .get_conn_manager()
            .add_connector(UdpTunnelConnector::new(
                "udp://10.1.1.1:11010".parse().unwrap(),
            ));
    }

    inst2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", inst3.id()).parse().unwrap(),
        ));

    // wait inst2 have two route.
    let now = std::time::Instant::now();
    loop {
        if inst2.get_peer_manager().list_routes().await.len() == 2 {
            break;
        }
        if now.elapsed().as_secs() > 5 {
            panic!("wait inst2 have two route timeout");
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    vec![inst1, inst2, inst3]
}

#[tokio::test]
#[serial_test::serial]
pub async fn basic_three_node_test_tcp() {
    let insts = init_three_node("tcp").await;

    check_route(
        "10.144.144.2",
        insts[1].peer_id(),
        insts[0].get_peer_manager().list_routes().await,
    );

    check_route(
        "10.144.144.3",
        insts[2].peer_id(),
        insts[0].get_peer_manager().list_routes().await,
    );
}

#[tokio::test]
#[serial_test::serial]
pub async fn basic_three_node_test_udp() {
    let insts = init_three_node("udp").await;

    check_route(
        "10.144.144.2",
        insts[1].peer_id(),
        insts[0].get_peer_manager().list_routes().await,
    );

    check_route(
        "10.144.144.3",
        insts[2].peer_id(),
        insts[0].get_peer_manager().list_routes().await,
    );
}

#[tokio::test]
#[serial_test::serial]
pub async fn tcp_proxy_three_node_test() {
    let insts = init_three_node("tcp").await;

    insts[2]
        .get_global_ctx()
        .add_proxy_cidr("10.1.2.0/24".parse().unwrap())
        .unwrap();
    assert_eq!(insts[2].get_global_ctx().get_proxy_cidrs().len(), 1);

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    // wait updater
    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

    let tcp_listener = TcpTunnelListener::new("tcp://10.1.2.4:22223".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://10.1.2.4:22223".parse().unwrap());

    _tunnel_pingpong_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
    )
    .await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn icmp_proxy_three_node_test() {
    let insts = init_three_node("tcp").await;

    insts[2]
        .get_global_ctx()
        .add_proxy_cidr("10.1.2.0/24".parse().unwrap())
        .unwrap();
    assert_eq!(insts[2].get_global_ctx().get_proxy_cidrs().len(), 1);

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    // wait updater
    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

    // send ping with shell in net_a to net_d
    let _g = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let code = tokio::process::Command::new("ip")
        .args(&[
            "netns", "exec", "net_a", "ping", "-c", "1", "-W", "1", "10.1.2.4",
        ])
        .status()
        .await
        .unwrap();
    assert_eq!(code.code().unwrap(), 0);
}

#[tokio::test]
#[serial_test::serial]
pub async fn proxy_three_node_disconnect_test() {
    let mut inst4 = Instance::new(get_inst_config("inst4", Some("net_d"), "10.144.144.4"));
    inst4
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.2.3:11010".parse().unwrap(),
        ));
    inst4.run().await.unwrap();

    tokio::spawn(async {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
            set_link_status("net_d", false);
            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
            set_link_status("net_d", true);
        }
    });

    // TODO: add some traffic here, also should check route & peer list
    tokio::time::sleep(tokio::time::Duration::from_secs(35)).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn udp_proxy_three_node_test() {
    let insts = init_three_node("tcp").await;

    insts[2]
        .get_global_ctx()
        .add_proxy_cidr("10.1.2.0/24".parse().unwrap())
        .unwrap();
    assert_eq!(insts[2].get_global_ctx().get_proxy_cidrs().len(), 1);

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    // wait updater
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let tcp_listener = UdpTunnelListener::new("udp://10.1.2.4:22233".parse().unwrap());
    let tcp_connector = UdpTunnelConnector::new("udp://10.1.2.4:22233".parse().unwrap());

    _tunnel_pingpong_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
    )
    .await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn udp_broadcast_test() {
    let _insts = init_three_node("tcp").await;

    let udp_broadcast_responder = |net_ns: NetNS, counter: Arc<AtomicU32>| async move {
        let _g = net_ns.guard();
        let socket: UdpSocket = UdpSocket::bind("0.0.0.0:22111").await.unwrap();
        socket.set_broadcast(true).unwrap();

        println!("Awaiting responses..."); // self.recv_buff is a [u8; 8092]
        let mut recv_buff = [0; 8092];
        while let Ok((n, addr)) = socket.recv_from(&mut recv_buff).await {
            println!("{} bytes response from {:?}", n, addr);
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Remaining code not directly relevant to the question
        }
    };

    let mut tasks = JoinSet::new();
    let counter = Arc::new(AtomicU32::new(0));
    tasks.spawn(udp_broadcast_responder(
        NetNS::new(Some("net_b".into())),
        counter.clone(),
    ));
    tasks.spawn(udp_broadcast_responder(
        NetNS::new(Some("net_c".into())),
        counter.clone(),
    ));

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // send broadcast
    let net_ns = NetNS::new(Some("net_a".into()));
    let _g = net_ns.guard();
    let socket: UdpSocket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.set_broadcast(true).unwrap();
    // socket.connect(("10.144.144.255", 22111)).await.unwrap();
    let call: Vec<u8> = vec![1; 1024];
    println!("Sending call, {} bytes", call.len());
    match socket.send_to(&call, "10.144.144.255:22111").await {
        Err(e) => panic!("Error sending call: {:?}", e),
        _ => {}
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);
}
