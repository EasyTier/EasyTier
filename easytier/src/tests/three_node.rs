use core::panic;
use std::{
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use rand::Rng;
use tokio::{net::UdpSocket, task::JoinSet};

use super::*;

use crate::{
    common::{
        config::{ConfigLoader, NetworkIdentity, PortForwardConfig, TomlConfigLoader},
        netns::{NetNS, ROOT_NETNS_NAME},
    },
    instance::instance::Instance,
    proto::common::CompressionAlgoPb,
    tunnel::{
        common::tests::wait_for_condition, ring::RingTunnelConnector, tcp::TcpTunnelConnector,
        udp::UdpTunnelConnector,
    },
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
    config.set_socks5_portal(Some("socks5://0.0.0.0:12345".parse().unwrap()));
    config
}

pub async fn init_three_node(proto: &str) -> Vec<Instance> {
    init_three_node_ex(proto, |cfg| cfg, false).await
}

pub async fn init_three_node_ex<F: Fn(TomlConfigLoader) -> TomlConfigLoader>(
    proto: &str,
    cfg_cb: F,
    use_public_server: bool,
) -> Vec<Instance> {
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
        inst1
            .get_conn_manager()
            .add_connector(TcpTunnelConnector::new(
                "tcp://10.1.1.2:11010".parse().unwrap(),
            ));
    } else if proto == "udp" {
        inst1
            .get_conn_manager()
            .add_connector(UdpTunnelConnector::new(
                "udp://10.1.1.2:11010".parse().unwrap(),
            ));
    } else if proto == "wg" {
        #[cfg(feature = "wireguard")]
        inst1
            .get_conn_manager()
            .add_connector(WgTunnelConnector::new(
                "wg://10.1.1.2:11011".parse().unwrap(),
                WgConfig::new_from_network_identity(
                    &inst2.get_global_ctx().get_network_identity().network_name,
                    &inst2
                        .get_global_ctx()
                        .get_network_identity()
                        .network_secret
                        .unwrap_or_default(),
                ),
            ));
    } else if proto == "ws" {
        #[cfg(feature = "websocket")]
        inst1
            .get_conn_manager()
            .add_connector(crate::tunnel::websocket::WSTunnelConnector::new(
                "ws://10.1.1.2:11011".parse().unwrap(),
            ));
    } else if proto == "wss" {
        #[cfg(feature = "websocket")]
        inst1
            .get_conn_manager()
            .add_connector(crate::tunnel::websocket::WSTunnelConnector::new(
                "wss://10.1.1.2:11012".parse().unwrap(),
            ));
    }

    inst3
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", inst2.id()).parse().unwrap(),
        ));

    // wait inst2 have two route.
    wait_for_condition(
        || async {
            if !use_public_server {
                inst2.get_peer_manager().list_routes().await.len() == 2
            } else {
                inst2
                    .get_peer_manager()
                    .get_foreign_network_manager()
                    .list_foreign_networks()
                    .await
                    .foreign_networks
                    .len()
                    == 1
            }
        },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || async {
            let routes = inst1.get_peer_manager().list_routes().await;
            println!("routes: {:?}", routes);
            routes.len() == 2
        },
        Duration::from_secs(5),
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
        "10.144.144.2/24",
        insts[1].peer_id(),
        insts[0].get_peer_manager().list_routes().await,
    );

    check_route(
        "10.144.144.3/24",
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
    let mut buf = vec![0; 7 * 1024];
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
    let mut buf = vec![0; 7 * 1024];
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
    #[values(true, false)] no_tun: bool,
    #[values(true, false)] relay_by_public_server: bool,
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] disable_kcp_input: bool,
    #[values(true, false)] dst_enable_kcp_proxy: bool,
) {
    let insts = init_three_node_ex(
        proto,
        |cfg| {
            if cfg.get_inst_name() == "inst3" {
                let mut flags = cfg.get_flags();
                flags.no_tun = no_tun;
                flags.disable_kcp_input = disable_kcp_input;
                flags.enable_kcp_proxy = dst_enable_kcp_proxy;
                cfg.set_flags(flags);
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap());
            }

            if cfg.get_inst_name() == "inst2" && relay_by_public_server {
                cfg.set_network_identity(NetworkIdentity::new(
                    "public".to_string(),
                    "public".to_string(),
                ));
            }

            if cfg.get_inst_name() == "inst1" && enable_kcp_proxy {
                let mut flags = cfg.get_flags();
                flags.enable_kcp_proxy = true;
                cfg.set_flags(flags);
            }

            cfg
        },
        relay_by_public_server,
    )
    .await;

    assert_eq!(insts[2].get_global_ctx().get_proxy_cidrs().len(), 1);

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3/24",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    subnet_proxy_test_icmp().await;
    subnet_proxy_test_tcp().await;
    subnet_proxy_test_udp().await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn data_compress(
    #[values(true, false)] inst1_compress: bool,
    #[values(true, false)] inst2_compress: bool,
) {
    let _insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst1" && inst1_compress {
                let mut flags = cfg.get_flags();
                flags.data_compress_algo = CompressionAlgoPb::Zstd.into();
                cfg.set_flags(flags);
            }

            if cfg.get_inst_name() == "inst3" && inst2_compress {
                let mut flags = cfg.get_flags();
                flags.data_compress_algo = CompressionAlgoPb::Zstd.into();
                cfg.set_flags(flags);
            }

            cfg
        },
        false,
    )
    .await;

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

#[cfg(feature = "wireguard")]
#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn proxy_three_node_disconnect_test(#[values("tcp", "wg")] proto: &str) {
    use crate::{
        common::scoped_task::ScopedTask,
        tunnel::wireguard::{WgConfig, WgTunnelConnector},
    };

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

    tracing::info!("inst1 peer id: {:?}", insts[0].peer_id());
    tracing::info!("inst2 peer id: {:?}", insts[1].peer_id());
    tracing::info!("inst3 peer id: {:?}", insts[2].peer_id());
    tracing::info!("inst4 peer id: {:?}", inst4.peer_id());

    let task = tokio::spawn(async move {
        for _ in 1..=2 {
            // inst4 should be in inst1's route list
            wait_for_condition(
                || async {
                    insts[0]
                        .get_peer_manager()
                        .list_routes()
                        .await
                        .iter()
                        .find(|r| r.peer_id == inst4.peer_id())
                        .is_some()
                },
                Duration::from_secs(8),
            )
            .await;

            set_link_status("net_d", false);
            let _t = ScopedTask::from(tokio::spawn(async move {
                // do some ping in net_a to trigger net_c pingpong
                loop {
                    ping_test("net_a", "10.144.144.4", Some(1)).await;
                }
            }));
            wait_for_condition(
                || async {
                    let ret = insts[2]
                        .get_peer_manager()
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .iter()
                        .find(|r| **r == inst4.peer_id())
                        .is_none();
                    if !ret {
                        println!(
                            "conn info: {:?}",
                            insts[2]
                                .get_peer_manager()
                                .get_peer_map()
                                .list_peer_conns(inst4.peer_id())
                                .await
                        );
                    }
                    ret
                },
                // 0 down, assume last packet is recv in -0.01
                // [2, 7) send ping
                // [4, 9) ping fail and close connection
                Duration::from_secs(11),
            )
            .await;

            wait_for_condition(
                || async {
                    insts[0]
                        .get_peer_manager()
                        .list_routes()
                        .await
                        .iter()
                        .find(|r| r.peer_id == inst4.peer_id())
                        .is_none()
                },
                Duration::from_secs(7),
            )
            .await;

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
            inst1.get_peer_manager().list_routes().await.len() == 2
                && inst2.get_peer_manager().list_routes().await.len() == 2
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

    tracing::info!("endpoint");
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

#[cfg(feature = "wireguard")]
#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn socks5_vpn_portal(#[values("10.144.144.1", "10.144.144.3")] dst_addr: &str) {
    use rand::Rng as _;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_socks::tcp::socks5::Socks5Stream;

    let _insts = init_three_node("tcp").await;

    let mut buf = vec![0u8; 1024];
    rand::thread_rng().fill(&mut buf[..]);

    let buf_clone = buf.clone();
    let dst_addr_clone = dst_addr.to_owned();
    let task = tokio::spawn(async move {
        let net_ns = if dst_addr_clone == "10.144.144.1" {
            NetNS::new(Some("net_a".into()))
        } else {
            NetNS::new(Some("net_c".into()))
        };
        let _g = net_ns.guard();

        let socket = TcpListener::bind("0.0.0.0:22222").await.unwrap();
        let (mut st, addr) = socket.accept().await.unwrap();

        if dst_addr_clone == "10.144.144.3" {
            assert_eq!(addr.ip().to_string(), "10.144.144.1".to_string());
        } else {
            assert_eq!(addr.ip().to_string(), "127.0.0.1".to_string());
        }

        let rbuf = &mut [0u8; 1024];
        st.read_exact(rbuf).await.unwrap();
        assert_eq!(rbuf, buf_clone.as_slice());
    });

    let net_ns = NetNS::new(Some("net_a".into()));
    let _g = net_ns.guard();

    println!("connect to socks5 portal");
    let stream = TcpStream::connect("127.0.0.1:12345").await.unwrap();
    println!("connect to socks5 portal done");

    stream.set_nodelay(true).unwrap();
    let mut conn = Socks5Stream::connect_with_socket(stream, format!("{}:22222", dst_addr))
        .await
        .unwrap();

    conn.write_all(&buf).await.unwrap();
    drop(conn);

    tokio::join!(task).0.unwrap();
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn manual_reconnector(#[values(true, false)] is_foreign: bool) {
    prepare_linux_namespaces();

    let center_node_config = get_inst_config("inst1", Some("net_a"), "10.144.144.1");
    if is_foreign {
        center_node_config
            .set_network_identity(NetworkIdentity::new("center".to_string(), "".to_string()));
    }
    let mut center_inst = Instance::new(center_node_config);

    let inst1_config = get_inst_config("inst1", Some("net_b"), "10.144.145.1");
    inst1_config.set_listeners(vec![]);
    let mut inst1 = Instance::new(inst1_config);

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

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let peer_map = if !is_foreign {
        inst1.get_peer_manager().get_peer_map()
    } else {
        inst1
            .get_peer_manager()
            .get_foreign_network_client()
            .get_peer_map()
    };

    let conns = peer_map
        .list_peer_conns(center_inst.peer_id())
        .await
        .unwrap();

    assert!(conns.len() >= 1);

    wait_for_condition(
        || async { ping_test("net_b", "10.144.145.2", None).await },
        Duration::from_secs(5),
    )
    .await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn port_forward_test(
    #[values(true, false)] no_tun: bool,
    #[values(64, 1900)] buf_size: u64,
) {
    prepare_linux_namespaces();

    let _insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst1" {
                cfg.set_port_forwards(vec![
                    // test port forward to other virtual node
                    PortForwardConfig {
                        bind_addr: "0.0.0.0:23456".parse().unwrap(),
                        dst_addr: "10.144.144.3:23456".parse().unwrap(),
                        proto: "tcp".to_string(),
                    },
                    // test port forward to subnet proxy
                    PortForwardConfig {
                        bind_addr: "0.0.0.0:23457".parse().unwrap(),
                        dst_addr: "10.1.2.4:23457".parse().unwrap(),
                        proto: "tcp".to_string(),
                    },
                    // test udp port forward to other virtual node
                    PortForwardConfig {
                        bind_addr: "0.0.0.0:23458".parse().unwrap(),
                        dst_addr: "10.144.144.3:23458".parse().unwrap(),
                        proto: "udp".to_string(),
                    },
                    // test udp port forward to subnet proxy
                    PortForwardConfig {
                        bind_addr: "0.0.0.0:23459".parse().unwrap(),
                        dst_addr: "10.1.2.4:23459".parse().unwrap(),
                        proto: "udp".to_string(),
                    },
                ]);
            } else if cfg.get_inst_name() == "inst3" {
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap());
            }
            let mut flags = cfg.get_flags();
            flags.no_tun = no_tun;
            cfg.set_flags(flags);
            cfg
        },
        false,
    )
    .await;

    use crate::tunnel::{
        common::tests::_tunnel_pingpong_netns, tcp::TcpTunnelListener, udp::UdpTunnelConnector,
        udp::UdpTunnelListener,
    };

    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:23456".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://127.0.0.1:23456".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;

    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:23457".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://127.0.0.1:23457".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;

    let udp_listener = UdpTunnelListener::new("udp://0.0.0.0:23458".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://127.0.0.1:23458".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;

    let udp_listener = UdpTunnelListener::new("udp://0.0.0.0:23459".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://127.0.0.1:23459".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
        buf,
    )
    .await;
}
