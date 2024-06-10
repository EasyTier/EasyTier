use std::{
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use tokio::{net::UdpSocket, task::JoinSet};

use super::*;

use crate::{
    common::{
        config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
        netns::{NetNS, ROOT_NETNS_NAME},
    },
    instance::instance::Instance,
    tunnel::common::tests::wait_for_condition,
    tunnel::{ring::RingTunnelConnector, tcp::TcpTunnelConnector, udp::UdpTunnelConnector},
};

#[cfg(feature = "wireguard")]
use crate::{
    common::config::VpnPortalConfig,
    tunnel::wireguard::{WgConfig, WgTunnelConnector},
    vpn_portal::wireguard::get_wg_config_for_portal,
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
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_listeners(vec![
        "tcp://0.0.0.0:11010".parse().unwrap(),
        "udp://0.0.0.0:11010".parse().unwrap(),
        "wg://0.0.0.0:11011".parse().unwrap(),
        "ws://0.0.0.0:11011".parse().unwrap(),
        "wss://0.0.0.0:11012".parse().unwrap(),
    ]);
    config
}

pub async fn init_three_node(proto: &str) -> Vec<Instance> {
    init_three_node_ex(proto, |cfg| cfg).await
}

pub async fn init_three_node_ex<F: Fn(TomlConfigLoader) -> TomlConfigLoader>(
    proto: &str,
    cfg_cb: F,
) -> Vec<Instance> {
    log::set_max_level(log::LevelFilter::Info);
    prepare_linux_namespaces();

    let mut inst1 = Instance::new(cfg_cb(get_inst_config(
        "inst1",
        Some("net_a"),
        "10.144.144.1",
    )));
    let mut inst2 = Instance::new(cfg_cb(get_inst_config(
        "inst2",
        Some("net_b"),
        "10.144.144.2",
    )));
    let mut inst3 = Instance::new(cfg_cb(get_inst_config(
        "inst3",
        Some("net_c"),
        "10.144.144.3",
    )));

    inst1.run().await.unwrap();
    inst2.run().await.unwrap();
    inst3.run().await.unwrap();

    if proto == "tcp" {
        inst2
            .get_conn_manager()
            .add_connector(TcpTunnelConnector::new(
                "tcp://10.1.1.1:11010".parse().unwrap(),
            ));
    } else if proto == "udp" {
        inst2
            .get_conn_manager()
            .add_connector(UdpTunnelConnector::new(
                "udp://10.1.1.1:11010".parse().unwrap(),
            ));
    } else if proto == "wg" {
        #[cfg(feature = "wireguard")]
        inst2
            .get_conn_manager()
            .add_connector(WgTunnelConnector::new(
                "wg://10.1.1.1:11011".parse().unwrap(),
                WgConfig::new_from_network_identity(
                    &inst1.get_global_ctx().get_network_identity().network_name,
                    &inst1
                        .get_global_ctx()
                        .get_network_identity()
                        .network_secret
                        .unwrap_or_default(),
                ),
            ));
    } else if proto == "ws" {
        #[cfg(feature = "websocket")]
        inst2
            .get_conn_manager()
            .add_connector(crate::tunnel::websocket::WSTunnelConnector::new(
                "ws://10.1.1.1:11011".parse().unwrap(),
            ));
    } else if proto == "wss" {
        #[cfg(feature = "websocket")]
        inst2
            .get_conn_manager()
            .add_connector(crate::tunnel::websocket::WSTunnelConnector::new(
                "wss://10.1.1.1:11012".parse().unwrap(),
            ));
    }

    inst2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", inst3.id()).parse().unwrap(),
        ));

    // wait inst2 have two route.
    wait_for_condition(
        || async { inst2.get_peer_manager().list_routes().await.len() == 2 },
        Duration::from_secs(5000),
    )
    .await;

    wait_for_condition(
        || async { inst1.get_peer_manager().list_routes().await.len() == 2 },
        Duration::from_secs(5000),
    )
    .await;

    vec![inst1, inst2, inst3]
}

async fn ping_test(from_netns: &str, target_ip: &str, payload_size: Option<usize>) -> bool {
    let _g = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let code = tokio::process::Command::new("ip")
        .args(&[
            "netns",
            "exec",
            from_netns,
            "ping",
            "-c",
            "1",
            "-s",
            payload_size.unwrap_or(56).to_string().as_str(),
            "-W",
            "1",
            target_ip.to_string().as_str(),
        ])
        .status()
        .await
        .unwrap();
    code.code().unwrap() == 0
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn basic_three_node_test(#[values("tcp", "udp", "wg", "ws", "wss")] proto: &str) {
    let insts = init_three_node(proto).await;

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

    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.1", None).await },
        Duration::from_secs(5000),
    )
    .await;
}

async fn subnet_proxy_test_udp() {
    use crate::tunnel::{common::tests::_tunnel_pingpong_netns, udp::UdpTunnelListener};
    use rand::Rng;

    let udp_listener = UdpTunnelListener::new("udp://10.1.2.4:22233".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://10.1.2.4:22233".parse().unwrap());

    // NOTE: this should not excced udp tunnel max buffer size
    let mut buf = vec![0; 20 * 1024];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;

    // no fragment
    let udp_listener = UdpTunnelListener::new("udp://10.1.2.4:22233".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://10.1.2.4:22233".parse().unwrap());

    let mut buf = vec![0; 1 * 1024];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;

    // connect to virtual ip (no tun mode)

    let udp_listener = UdpTunnelListener::new("udp://0.0.0.0:22234".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://10.144.144.3:22234".parse().unwrap());
    // NOTE: this should not excced udp tunnel max buffer size
    let mut buf = vec![0; 20 * 1024];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;

    // no fragment
    let udp_listener = UdpTunnelListener::new("udp://0.0.0.0:22235".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://10.144.144.3:22235".parse().unwrap());

    let mut buf = vec![0; 1 * 1024];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;
}

async fn subnet_proxy_test_tcp() {
    use crate::tunnel::{common::tests::_tunnel_pingpong_netns, tcp::TcpTunnelListener};
    use rand::Rng;

    let tcp_listener = TcpTunnelListener::new("tcp://10.1.2.4:22223".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://10.1.2.4:22223".parse().unwrap());

    let mut buf = vec![0; 32];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;

    // connect to virtual ip (no tun mode)
    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:22223".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://10.144.144.3:22223".parse().unwrap());

    let mut buf = vec![0; 32];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;
}

async fn subnet_proxy_test_icmp() {
    wait_for_condition(
        || async { ping_test("net_a", "10.1.2.4", None).await },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_a", "10.1.2.4", Some(5 * 1024)).await },
        Duration::from_secs(5),
    )
    .await;

    // connect to virtual ip (no tun mode)
    wait_for_condition(
        || async { ping_test("net_a", "10.144.144.3", None).await },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_a", "10.144.144.3", Some(5 * 1024)).await },
        Duration::from_secs(5),
    )
    .await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn subnet_proxy_three_node_test(
    #[values("tcp", "udp", "wg")] proto: &str,
    #[values(true)] no_tun: bool,
) {
    let insts = init_three_node_ex(proto, |cfg| {
        if cfg.get_inst_name() == "inst3" {
            let mut flags = cfg.get_flags();
            flags.no_tun = no_tun;
            cfg.set_flags(flags);
            cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap());
        }
        cfg
    })
    .await;

    assert_eq!(insts[2].get_global_ctx().get_proxy_cidrs().len(), 1);

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    subnet_proxy_test_icmp().await;
    subnet_proxy_test_tcp().await;
    subnet_proxy_test_udp().await;
}

#[cfg(feature = "wireguard")]
#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn proxy_three_node_disconnect_test(#[values("tcp", "wg")] proto: &str) {
    use crate::tunnel::wireguard::{WgConfig, WgTunnelConnector};

    let insts = init_three_node(proto).await;
    let mut inst4 = Instance::new(get_inst_config("inst4", Some("net_d"), "10.144.144.4"));
    if proto == "tcp" {
        inst4
            .get_conn_manager()
            .add_connector(TcpTunnelConnector::new(
                "tcp://10.1.2.3:11010".parse().unwrap(),
            ));
    } else if proto == "wg" {
        inst4
            .get_conn_manager()
            .add_connector(WgTunnelConnector::new(
                "wg://10.1.2.3:11011".parse().unwrap(),
                WgConfig::new_from_network_identity(
                    &inst4.get_global_ctx().get_network_identity().network_name,
                    &inst4
                        .get_global_ctx()
                        .get_network_identity()
                        .network_secret
                        .unwrap_or_default(),
                ),
            ));
    } else {
        unreachable!("not support");
    }
    inst4.run().await.unwrap();

    let task = tokio::spawn(async move {
        for _ in 1..=2 {
            tokio::time::sleep(tokio::time::Duration::from_secs(8)).await;
            // inst4 should be in inst1's route list
            let routes = insts[0].get_peer_manager().list_routes().await;
            assert!(
                routes
                    .iter()
                    .find(|r| r.peer_id == inst4.peer_id())
                    .is_some(),
                "inst4 should be in inst1's route list, {:?}",
                routes
            );

            set_link_status("net_d", false);
            tokio::time::sleep(tokio::time::Duration::from_secs(8)).await;
            let routes = insts[0].get_peer_manager().list_routes().await;
            assert!(
                routes
                    .iter()
                    .find(|r| r.peer_id == inst4.peer_id())
                    .is_none(),
                "inst4 should not be in inst1's route list, {:?}",
                routes
            );
            set_link_status("net_d", true);
        }
    });

    let (ret,) = tokio::join!(task);
    assert!(ret.is_ok());
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

#[tokio::test]
#[serial_test::serial]
pub async fn foreign_network_forward_nic_data() {
    prepare_linux_namespaces();

    let center_node_config = get_inst_config("inst1", Some("net_a"), "10.144.144.1");
    center_node_config
        .set_network_identity(NetworkIdentity::new("center".to_string(), "".to_string()));
    let mut center_inst = Instance::new(center_node_config);

    let mut inst1 = Instance::new(get_inst_config("inst1", Some("net_b"), "10.144.145.1"));
    let mut inst2 = Instance::new(get_inst_config("inst2", Some("net_c"), "10.144.145.2"));

    center_inst.run().await.unwrap();
    inst1.run().await.unwrap();
    inst2.run().await.unwrap();

    assert_ne!(inst1.id(), center_inst.id());
    assert_ne!(inst2.id(), center_inst.id());

    inst1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center_inst.id()).parse().unwrap(),
        ));

    inst2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center_inst.id()).parse().unwrap(),
        ));

    wait_for_condition(
        || async {
            inst1.get_peer_manager().list_routes().await.len() == 1
                && inst2.get_peer_manager().list_routes().await.len() == 1
        },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_b", "10.144.145.2", None).await },
        Duration::from_secs(5),
    )
    .await;
}

use std::{net::SocketAddr, str::FromStr};

use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, WGApi, WireguardInterfaceApi,
};

fn run_wireguard_client(
    endpoint: SocketAddr,
    peer_public_key: Key,
    client_private_key: Key,
    allowed_ips: Vec<String>,
    client_ip: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create new API object for interface
    let ifname: String = if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        "wg0".into()
    } else {
        "utun3".into()
    };
    let wgapi = WGApi::new(ifname.clone(), false)?;

    // create interface
    wgapi.create_interface()?;

    // Peer secret key
    let mut peer = Peer::new(peer_public_key.clone());

    log::info!("endpoint");
    // Peer endpoint and interval
    peer.endpoint = Some(endpoint);
    peer.persistent_keepalive_interval = Some(1);
    for ip in allowed_ips {
        peer.allowed_ips.push(IpAddrMask::from_str(ip.as_str())?);
    }

    // interface configuration
    let interface_config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: client_private_key.to_string(),
        address: client_ip,
        port: 12345,
        peers: vec![peer],
    };

    #[cfg(not(windows))]
    wgapi.configure_interface(&interface_config)?;
    #[cfg(windows)]
    wgapi.configure_interface(&interface_config, &[])?;
    wgapi.configure_peer_routing(&interface_config.peers)?;
    Ok(())
}

#[cfg(feature = "wireguard")]
#[tokio::test]
#[serial_test::serial]
pub async fn wireguard_vpn_portal() {
    let mut insts = init_three_node("tcp").await;
    let net_ns = NetNS::new(Some("net_d".into()));
    let _g = net_ns.guard();
    insts[2]
        .get_global_ctx()
        .config
        .set_vpn_portal_config(VpnPortalConfig {
            wireguard_listen: "0.0.0.0:22121".parse().unwrap(),
            client_cidr: "10.14.14.0/24".parse().unwrap(),
        });
    insts[2].run_vpn_portal().await.unwrap();

    let net_ns = NetNS::new(Some("net_d".into()));
    let _g = net_ns.guard();
    let wg_cfg = get_wg_config_for_portal(&insts[2].get_global_ctx().get_network_identity());
    run_wireguard_client(
        "10.1.2.3:22121".parse().unwrap(),
        Key::try_from(wg_cfg.my_public_key()).unwrap(),
        Key::try_from(wg_cfg.peer_secret_key()).unwrap(),
        vec!["10.14.14.0/24".to_string(), "10.144.144.0/24".to_string()],
        "10.14.14.2".to_string(),
    )
    .unwrap();

    // ping other node in network
    wait_for_condition(
        || async { ping_test("net_d", "10.144.144.1", None).await },
        Duration::from_secs(5),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_d", "10.144.144.2", None).await },
        Duration::from_secs(5),
    )
    .await;

    // ping portal node
    wait_for_condition(
        || async { ping_test("net_d", "10.144.144.3", None).await },
        Duration::from_secs(5),
    )
    .await;
}
