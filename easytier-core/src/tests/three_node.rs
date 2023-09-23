use super::*;

use crate::{
    common::netns::{NetNS, ROOT_NETNS_NAME},
    instance::instance::{Instance, InstanceConfigWriter},
    tunnels::{
        common::tests::_tunnel_pingpong_netns,
        ring_tunnel::RingTunnelConnector,
        tcp_tunnel::{TcpTunnelConnector, TcpTunnelListener},
        udp_tunnel::UdpTunnelConnector,
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

pub async fn prepare_inst_configs() {
    InstanceConfigWriter::new("inst1")
        .set_ns(Some("net_a".into()))
        .set_addr("10.144.144.1".to_owned());

    InstanceConfigWriter::new("inst2")
        .set_ns(Some("net_b".into()))
        .set_addr("10.144.144.2".to_owned());

    InstanceConfigWriter::new("inst3")
        .set_ns(Some("net_c".into()))
        .set_addr("10.144.144.3".to_owned());
}

pub async fn init_three_node(proto: &str) -> Vec<Instance> {
    log::set_max_level(log::LevelFilter::Info);
    prepare_linux_namespaces();

    prepare_inst_configs().await;

    let mut inst1 = Instance::new("inst1");
    let mut inst2 = Instance::new("inst2");
    let mut inst3 = Instance::new("inst3");

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
        insts[1].id(),
        insts[0].get_peer_manager().list_routes().await,
    );

    check_route(
        "10.144.144.3",
        insts[2].id(),
        insts[0].get_peer_manager().list_routes().await,
    );
}

#[tokio::test]
#[serial_test::serial]
pub async fn basic_three_node_test_udp() {
    let insts = init_three_node("udp").await;

    check_route(
        "10.144.144.2",
        insts[1].id(),
        insts[0].get_peer_manager().list_routes().await,
    );

    check_route(
        "10.144.144.3",
        insts[2].id(),
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
        insts[2].id(),
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
        insts[2].id(),
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
    InstanceConfigWriter::new("inst4")
        .set_ns(Some("net_d".into()))
        .set_addr("10.144.144.4".to_owned());

    let mut inst4 = Instance::new("inst4");
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
