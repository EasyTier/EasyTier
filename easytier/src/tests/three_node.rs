#![allow(clippy::too_many_arguments)]

use core::panic;
use std::{
    future::Future,
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};

use rand::{Rng, rngs::OsRng};
use tokio::{net::UdpSocket, task::JoinSet};
use x25519_dalek::StaticSecret;

use super::*;

#[cfg(feature = "magic-dns")]
use crate::instance::dns_server::MAGIC_DNS_INSTANCE_ADDR;

// TODO: 需要加一个单测，确保 socks5 + exit node == self || proxy_cidr == 0.0.0.0/0 时，可以实现出口节点的能力。

use crate::{
    common::{
        config::{ConfigLoader, NetworkIdentity, PortForwardConfig, TomlConfigLoader},
        netns::{NetNS, ROOT_NETNS_NAME},
        stats_manager::{LabelSet, LabelType, MetricName},
    },
    instance::instance::Instance,
    proto::{
        api::instance::TcpProxyEntryTransportType,
        common::{CompressionAlgoPb, SecureModeConfig},
    },
    tunnel::{
        common::tests::{
            _tunnel_bench_netns, _tunnel_pingpong_netns_with_timeout, wait_for_condition,
        },
        ring::RingTunnelConnector,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
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
    del_netns("net_e");

    create_netns("net_a", "10.1.1.1/24", "fd11::1/64");
    create_netns("net_b", "10.1.1.2/24", "fd11::2/64");
    create_netns("net_c", "10.1.2.3/24", "fd12::3/64");
    create_netns("net_d", "10.1.2.4/24", "fd12::4/64");
    create_netns("net_e", "10.1.1.3/24", "fd11::3/64");

    prepare_bridge("br_a");
    prepare_bridge("br_b");

    add_ns_to_bridge("br_a", "net_a");
    add_ns_to_bridge("br_a", "net_b");
    add_ns_to_bridge("br_a", "net_e");
    add_ns_to_bridge("br_b", "net_c");
    add_ns_to_bridge("br_b", "net_d");
}

pub fn get_inst_config(
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
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

async fn init_three_node_ex_with_inst3<F: Fn(TomlConfigLoader) -> TomlConfigLoader>(
    proto: &str,
    cfg_cb: F,
    use_public_server: bool,
    inst3_ns: &str,
    inst3_ipv4: &str,
    inst3_ipv6: &str,
) -> Vec<Instance> {
    prepare_linux_namespaces();

    let mut inst1 = Instance::new(cfg_cb(get_inst_config(
        "inst1",
        Some("net_a"),
        "10.144.144.1",
        "fd00::1/64",
    )));
    let mut inst2 = Instance::new(cfg_cb(get_inst_config(
        "inst2",
        Some("net_b"),
        "10.144.144.2",
        "fd00::2/64",
    )));
    let mut inst3 = Instance::new(cfg_cb(get_inst_config(
        "inst3",
        Some(inst3_ns),
        inst3_ipv4,
        inst3_ipv6,
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
            .add_connector(crate::tunnel::websocket::WsTunnelConnector::new(
                "ws://10.1.1.2:11011".parse().unwrap(),
            ));
    } else if proto == "wss" {
        #[cfg(feature = "websocket")]
        inst1
            .get_conn_manager()
            .add_connector(crate::tunnel::websocket::WsTunnelConnector::new(
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

    wait_for_condition(
        || async {
            let routes = inst3.get_peer_manager().list_routes().await;
            println!("routes: {:?}", routes);
            routes.len() == 2
        },
        Duration::from_secs(5),
    )
    .await;

    vec![inst1, inst2, inst3]
}

pub async fn init_three_node_ex<F: Fn(TomlConfigLoader) -> TomlConfigLoader>(
    proto: &str,
    cfg_cb: F,
    use_public_server: bool,
) -> Vec<Instance> {
    init_three_node_ex_with_inst3(
        proto,
        cfg_cb,
        use_public_server,
        "net_c",
        "10.144.144.3",
        "fd00::3/64",
    )
    .await
}

async fn init_lazy_p2p_three_node_ex<F: Fn(TomlConfigLoader) -> TomlConfigLoader>(
    proto: &str,
    cfg_cb: F,
) -> Vec<Instance> {
    init_three_node_ex_with_inst3(proto, cfg_cb, false, "net_e", "10.144.144.3", "fd00::3/64").await
}

pub async fn drop_insts(insts: Vec<Instance>) {
    let mut set = JoinSet::new();
    for mut inst in insts {
        set.spawn(async move {
            inst.clear_resources().await;
            let pm = Arc::downgrade(&inst.get_peer_manager());
            drop(inst);
            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 5 && pm.strong_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            debug_assert_eq!(pm.strong_count(), 0, "PeerManager should be dropped");
        });
    }
    while set.join_next().await.is_some() {}
}

async fn wait_for_tun_ready_event(
    receiver: &mut tokio::sync::broadcast::Receiver<crate::common::global_ctx::GlobalCtxEvent>,
) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let crate::common::global_ctx::GlobalCtxEvent::TunDeviceReady(ifname) =
                receiver.recv().await.unwrap()
            {
                return ifname;
            }
        }
    })
    .await
    .unwrap()
}

async fn assert_no_tun_ready_event(
    receiver: &mut tokio::sync::broadcast::Receiver<crate::common::global_ctx::GlobalCtxEvent>,
    timeout: Duration,
) {
    tokio::time::timeout(timeout, async {
        loop {
            if let crate::common::global_ctx::GlobalCtxEvent::TunDeviceReady(ifname) =
                receiver.recv().await.unwrap()
            {
                panic!("unexpected TunDeviceReady event: {ifname}");
            }
        }
    })
    .await
    .ok();
}

async fn assert_no_tun_fallback_event(
    receiver: &mut tokio::sync::broadcast::Receiver<crate::common::global_ctx::GlobalCtxEvent>,
    timeout: Duration,
) {
    tokio::time::timeout(timeout, async {
        loop {
            if let crate::common::global_ctx::GlobalCtxEvent::TunDeviceFallback(reason) =
                receiver.recv().await.unwrap()
            {
                panic!("unexpected TunDeviceFallback event: {reason}");
            }
        }
    })
    .await
    .ok();
}

async fn wait_for_tun_fallback_event(
    receiver: &mut tokio::sync::broadcast::Receiver<crate::common::global_ctx::GlobalCtxEvent>,
) -> String {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let crate::common::global_ctx::GlobalCtxEvent::TunDeviceFallback(reason) =
                receiver.recv().await.unwrap()
            {
                return reason;
            }
        }
    })
    .await
    .unwrap()
}

async fn wait_for_dhcp_ipv4_changed_event(
    receiver: &mut tokio::sync::broadcast::Receiver<crate::common::global_ctx::GlobalCtxEvent>,
) -> cidr::Ipv4Inet {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let crate::common::global_ctx::GlobalCtxEvent::DhcpIpv4Changed(_, Some(ip)) =
                receiver.recv().await.unwrap()
            {
                return ip;
            }
        }
    })
    .await
    .unwrap()
}

async fn link_exists_in_netns(netns: &str, ifname: &str) -> bool {
    let _g = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let code = tokio::process::Command::new("ip")
        .args(["netns", "exec", netns, "ip", "link", "show", "dev", ifname])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap();
    code.success()
}

fn assert_tcp_proxy_metric_has_protocol(
    inst: &Instance,
    protocol: TcpProxyEntryTransportType,
    min_value: u64,
) {
    let metrics = inst
        .get_global_ctx()
        .stats_manager()
        .get_metrics_by_prefix(&MetricName::TcpProxyConnect.to_string());

    assert!(
        metrics.iter().any(|metric| {
            metric.value >= min_value
                && metric.labels.labels().iter().any(|l| {
                    let t = LabelType::Protocol(protocol.as_str_name().to_string());
                    t.key() == l.key && t.value() == l.value
                })
        }),
        "metrics: {:?}",
        metrics
    );
}

async fn shared_tun_subnet_proxy_transport_test(
    transport: TcpProxyEntryTransportType,
    source_shared: bool,
) {
    prepare_linux_namespaces();

    let center_cfg = get_inst_config("center", Some("net_b"), "10.144.144.100", "fd00::64/64");
    center_cfg.set_listeners(vec![]);
    let mut center = Instance::new(center_cfg);

    let mut shared_events = Vec::new();
    let mut insts = Vec::new();
    let dst_idx;

    if source_shared {
        let source_cfg = get_inst_config("src_shared", Some("net_a"), "10.144.144.1", "fd00::1/64");
        source_cfg.set_listeners(vec![]);
        source_cfg.set_socks5_portal(None);
        let mut source_flags = source_cfg.get_flags();
        source_flags.dev_name = "et_ssrc0".to_string();
        match transport {
            TcpProxyEntryTransportType::Kcp => source_flags.enable_kcp_proxy = true,
            TcpProxyEntryTransportType::Quic => source_flags.enable_quic_proxy = true,
            _ => unreachable!(),
        }
        source_cfg.set_flags(source_flags.clone());
        let source = Instance::new(source_cfg);
        shared_events.push(source.get_global_ctx().subscribe());

        let source_peer = get_inst_config("src_peer", Some("net_a"), "10.144.144.2", "fd00::2/64");
        source_peer.set_listeners(vec![]);
        source_peer.set_socks5_portal(None);
        source_peer.set_flags(source_flags);
        let source_peer = Instance::new(source_peer);
        shared_events.push(source_peer.get_global_ctx().subscribe());

        let dst_cfg = get_inst_config("dst", Some("net_c"), "10.144.144.3", "fd00::3/64");
        dst_cfg.set_listeners(vec![]);
        dst_cfg.set_socks5_portal(None);
        dst_cfg
            .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
            .unwrap();
        let dst = Instance::new(dst_cfg);

        insts.push(source);
        insts.push(source_peer);
        insts.push(dst);
        dst_idx = 2;
    } else {
        let src_cfg = get_inst_config("src", Some("net_a"), "10.144.144.1", "fd00::1/64");
        src_cfg.set_listeners(vec![]);
        src_cfg.set_socks5_portal(None);
        let mut src_flags = src_cfg.get_flags();
        match transport {
            TcpProxyEntryTransportType::Kcp => src_flags.enable_kcp_proxy = true,
            TcpProxyEntryTransportType::Quic => src_flags.enable_quic_proxy = true,
            _ => unreachable!(),
        }
        src_cfg.set_flags(src_flags);
        let src = Instance::new(src_cfg);

        let dst_cfg = get_inst_config("dst_shared", Some("net_c"), "10.144.144.3", "fd00::3/64");
        dst_cfg.set_listeners(vec![]);
        dst_cfg.set_socks5_portal(None);
        dst_cfg
            .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
            .unwrap();
        let mut dst_flags = dst_cfg.get_flags();
        dst_flags.dev_name = "et_sdst0".to_string();
        dst_cfg.set_flags(dst_flags.clone());
        let dst = Instance::new(dst_cfg);
        shared_events.push(dst.get_global_ctx().subscribe());

        let dst_peer = get_inst_config("dst_peer", Some("net_c"), "10.144.144.4", "fd00::4/64");
        dst_peer.set_listeners(vec![]);
        dst_peer.set_socks5_portal(None);
        dst_peer.set_flags(dst_flags);
        let dst_peer = Instance::new(dst_peer);
        shared_events.push(dst_peer.get_global_ctx().subscribe());

        insts.push(src);
        insts.push(dst);
        insts.push(dst_peer);
        dst_idx = 1;
    }

    center.run().await.unwrap();
    for inst in &mut insts {
        inst.run().await.unwrap();
    }

    let ifname = wait_for_tun_ready_event(&mut shared_events[0]).await;
    for receiver in shared_events.iter_mut().skip(1) {
        assert_eq!(ifname, wait_for_tun_ready_event(receiver).await);
    }

    insts[0]
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    insts[dst_idx]
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    wait_for_condition(
        || async {
            insts[0].get_peer_manager().list_routes().await.len() >= 2
                && insts[dst_idx].get_peer_manager().list_routes().await.len() >= 2
        },
        Duration::from_secs(8),
    )
    .await;

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3/24",
        insts[dst_idx].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    subnet_proxy_test_icmp("10.1.2.4", Duration::from_secs(8)).await;
    subnet_proxy_test_tcp("10.1.2.4", "10.1.2.4", Duration::from_secs(8)).await;
    subnet_proxy_test_udp("10.1.2.4", "10.1.2.4", Duration::from_secs(8)).await;

    assert_tcp_proxy_metric_has_protocol(&insts[0], transport, 1);
    for receiver in &mut shared_events {
        assert_no_tun_fallback_event(receiver, Duration::from_secs(2)).await;
    }

    let mut all_insts = vec![center];
    all_insts.extend(insts);
    drop_insts(all_insts).await;
}

async fn ping_test(from_netns: &str, target_ip: &str, payload_size: Option<usize>) -> bool {
    let _g = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let code = tokio::process::Command::new("ip")
        .args([
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
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap();
    code.code().unwrap() == 0
}

async fn ping6_test(from_netns: &str, target_ip: &str, payload_size: Option<usize>) -> bool {
    let _g = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let code = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            from_netns,
            "ping6",
            "-c",
            "1",
            "-s",
            payload_size.unwrap_or(56).to_string().as_str(),
            "-W",
            "1",
            target_ip.to_string().as_str(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap();
    code.code().unwrap() == 0
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn basic_three_node_test(
    #[values("tcp", "udp", "wg", "ws", "wss")] proto: &str,
    #[values(
        ["aes-gcm", "aes-gcm"],
        ["aes-256-gcm", "aes-256-gcm"],
        ["chacha20", "chacha20"],
        ["xor", "xor"],
        ["openssl-chacha20", "openssl-chacha20"],
        ["openssl-aes-gcm", "openssl-aes-gcm"],
        ["openssl-aes-256-gcm", "openssl-aes-256-gcm"],
        ["aes-gcm", "openssl-aes-gcm"],
        ["openssl-aes-gcm", "aes-gcm"],
        ["aes-256-gcm", "openssl-aes-256-gcm"],
        ["openssl-aes-256-gcm", "aes-256-gcm"],
        ["chacha20", "openssl-chacha20"],
        ["openssl-chacha20", "chacha20"],
    )]
    encrypt_algorithm_pair: [&str; 2],
) {
    let insts = init_three_node_ex(
        proto,
        |cfg| {
            let mut flags = cfg.get_flags();
            if cfg.get_inst_name() == "inst0" {
                flags.encryption_algorithm = encrypt_algorithm_pair[0].to_string();
            } else {
                flags.encryption_algorithm = encrypt_algorithm_pair[1].to_string();
            }
            cfg.set_flags(flags);
            cfg
        },
        false,
    )
    .await;

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

    // Test IPv4 connectivity
    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.1", None).await },
        Duration::from_secs(5000),
    )
    .await;

    // Test IPv6 connectivity
    wait_for_condition(
        || async { ping6_test("net_c", "fd00::1", None).await },
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        || async { ping6_test("net_a", "fd00::3", None).await },
        Duration::from_secs(5),
    )
    .await;

    drop_insts(insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn subnet_proxy_loop_prevention_test() {
    // 测试场景：inst1 和 inst2 都代理了 10.1.2.0/24 网段，
    // inst1 发起对 10.1.2.5 的 ping，不应该出现环路
    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst1" {
                // inst1 代理 10.1.2.0/24 网段
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            } else if cfg.get_inst_name() == "inst2" {
                // inst2 也代理相同的 10.1.2.0/24 网段
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            }
            cfg
        },
        false,
    )
    .await;

    // 等待代理路由出现 - inst1 应该看到 inst2 的代理路由
    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.2/24",
        insts[1].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    // 等待代理路由出现 - inst2 应该看到 inst1 的代理路由
    wait_proxy_route_appear(
        &insts[1].get_peer_manager(),
        "10.144.144.1/24",
        insts[0].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    // 从 inst1 (net_a) 发起对 10.1.2.5 的 ping 测试
    // 这应该失败，并且不会产生环路
    let now = std::time::Instant::now();
    while now.elapsed().as_secs() < 10 {
        ping_test("net_a", "10.1.2.5", None).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    println!(
        "inst0 metrics: {:?}",
        insts[0]
            .get_global_ctx()
            .stats_manager()
            .export_prometheus()
    );

    let all_metrics = insts[0].get_global_ctx().stats_manager().get_all_metrics();
    for metric in all_metrics {
        if metric.name == MetricName::TrafficPacketsSelfTx {
            let counter = insts[0]
                .get_global_ctx()
                .stats_manager()
                .get_counter(metric.name, metric.labels.clone());
            assert!(counter.get() < 40);
        }
    }

    drop_insts(insts).await;
}

async fn subnet_proxy_test_udp(listen_ip: &str, target_ip: &str, timeout: Duration) {
    use crate::tunnel::{
        common::tests::_tunnel_pingpong_netns_with_timeout, udp::UdpTunnelListener,
    };
    use rand::Rng;

    let udp_listener =
        UdpTunnelListener::new(format!("udp://{}:22233", listen_ip).parse().unwrap());
    let udp_connector =
        UdpTunnelConnector::new(format!("udp://{}:22233", target_ip).parse().unwrap());

    // NOTE: this should not excced udp tunnel max buffer size
    let mut buf = vec![0; 7 * 1024];
    rand::thread_rng().fill(&mut buf[..]);

    let ns_name = if target_ip == "10.144.144.3" {
        "net_c"
    } else {
        "net_d"
    };

    let result = _tunnel_pingpong_netns_with_timeout(
        udp_listener,
        udp_connector,
        NetNS::new(Some(ns_name.into())),
        NetNS::new(Some("net_a".into())),
        buf,
        timeout,
    )
    .await;
    assert!(result.is_ok(), "{}", result.unwrap_err());

    // no fragment
    let udp_listener =
        UdpTunnelListener::new(format!("udp://{}:22233", listen_ip).parse().unwrap());
    let udp_connector =
        UdpTunnelConnector::new(format!("udp://{}:22233", target_ip).parse().unwrap());

    let mut buf = vec![0; 1024];
    rand::thread_rng().fill(&mut buf[..]);

    let result = _tunnel_pingpong_netns_with_timeout(
        udp_listener,
        udp_connector,
        NetNS::new(Some(ns_name.into())),
        NetNS::new(Some("net_a".into())),
        buf,
        timeout,
    )
    .await;
    assert!(result.is_ok(), "{}", result.unwrap_err());
}

async fn subnet_proxy_test_tcp(listen_ip: &str, connect_ip: &str, timeout: Duration) {
    use crate::tunnel::{
        common::tests::_tunnel_pingpong_netns_with_timeout, tcp::TcpTunnelListener,
    };
    use rand::Rng;

    let tcp_listener = TcpTunnelListener::new(format!("tcp://{listen_ip}:22223").parse().unwrap());
    let tcp_connector =
        TcpTunnelConnector::new(format!("tcp://{}:22223", connect_ip).parse().unwrap());

    let mut buf = vec![0; 32];
    rand::thread_rng().fill(&mut buf[..]);

    let ns_name = if connect_ip == "10.144.144.3" {
        "net_c"
    } else {
        "net_d"
    };

    let result = _tunnel_pingpong_netns_with_timeout(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some(ns_name.into())),
        NetNS::new(Some("net_a".into())),
        buf,
        timeout,
    )
    .await;
    assert!(result.is_ok(), "{}", result.unwrap_err());
}

async fn subnet_proxy_test_icmp(target_ip: &str, timeout: Duration) {
    wait_for_condition(
        || async { ping_test("net_a", target_ip, None).await },
        timeout,
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_a", target_ip, Some(5 * 1024)).await },
        timeout,
    )
    .await;
}

#[tokio::test]
pub async fn quic_proxy() {
    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst3" {
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            } else if cfg.get_inst_name() == "inst1" {
                let mut flags = cfg.get_flags();
                flags.enable_quic_proxy = true;
                cfg.set_flags(flags);
            }
            cfg
        },
        false,
    )
    .await;

    assert_eq!(insts[2].get_global_ctx().config.get_proxy_cidrs().len(), 1);

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3/24",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    let target_ip = "10.1.2.4";

    subnet_proxy_test_icmp(target_ip, Duration::from_secs(5)).await;
    subnet_proxy_test_icmp("10.144.144.3", Duration::from_secs(5)).await;
    subnet_proxy_test_tcp(target_ip, target_ip, Duration::from_secs(5)).await;
    subnet_proxy_test_tcp("0.0.0.0", "10.144.144.3", Duration::from_secs(5)).await;

    let metrics = insts[0]
        .get_global_ctx()
        .stats_manager()
        .get_metrics_by_prefix(&MetricName::TcpProxyConnect.to_string());
    assert_eq!(metrics.len(), 2);
    assert_eq!(1, metrics[0].value);
    assert_eq!(1, metrics[1].value);

    drop_insts(insts).await;
}

#[rstest::rstest]
#[serial_test::serial]
#[tokio::test]
pub async fn subnet_proxy_three_node_test(
    #[values(true, false)] no_tun: bool,
    #[values(true, false)] relay_by_public_server: bool,
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] enable_quic_proxy: bool,
    #[values(true, false)] disable_kcp_input: bool,
    #[values(true, false)] disable_quic_input: bool,
    #[values(true, false)] dst_enable_kcp_proxy: bool,
    #[values(true, false)] dst_enable_quic_proxy: bool,
) {
    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst3" {
                let mut flags = cfg.get_flags();
                flags.no_tun = no_tun;
                flags.disable_kcp_input = disable_kcp_input;
                flags.enable_kcp_proxy = dst_enable_kcp_proxy;
                flags.disable_quic_input = disable_quic_input;
                flags.enable_quic_proxy = dst_enable_quic_proxy;
                cfg.set_flags(flags);
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
                cfg.add_proxy_cidr(
                    "10.1.2.0/24".parse().unwrap(),
                    Some("10.1.3.0/24".parse().unwrap()),
                )
                .unwrap();
            }

            if cfg.get_inst_name() == "inst2" && relay_by_public_server {
                cfg.set_network_identity(NetworkIdentity::new(
                    "public".to_string(),
                    "public".to_string(),
                ));
            }

            if cfg.get_inst_name() == "inst1" {
                let mut flags = cfg.get_flags();
                if enable_kcp_proxy {
                    flags.enable_kcp_proxy = true;
                }
                if enable_quic_proxy {
                    flags.enable_quic_proxy = true;
                }
                cfg.set_flags(flags);
            }

            cfg
        },
        relay_by_public_server,
    )
    .await;

    assert_eq!(insts[2].get_global_ctx().config.get_proxy_cidrs().len(), 2);

    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3/24",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;
    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3/24",
        insts[2].peer_id(),
        "10.1.3.0/24",
    )
    .await;

    for target_ip in ["10.1.3.4", "10.1.2.4", "10.144.144.3"] {
        subnet_proxy_test_icmp(target_ip, Duration::from_secs(5)).await;
        let listen_ip = if target_ip == "10.144.144.3" {
            "0.0.0.0"
        } else {
            "10.1.2.4"
        };
        subnet_proxy_test_tcp(listen_ip, target_ip, Duration::from_secs(5)).await;
        subnet_proxy_test_udp(listen_ip, target_ip, Duration::from_secs(5)).await;
    }
    if enable_quic_proxy && !disable_quic_input {
        let metrics = insts[0]
            .get_global_ctx()
            .stats_manager()
            .get_metrics_by_prefix(&MetricName::TcpProxyConnect.to_string());
        assert_eq!(metrics.len(), 3);
        for metric in metrics {
            assert_eq!(1, metric.value);
            assert!(metric.labels.labels().iter().any(|l| {
                let t =
                    LabelType::Protocol(TcpProxyEntryTransportType::Quic.as_str_name().to_string());
                t.key() == l.key && t.value() == l.value
            }));
        }
    } else if enable_kcp_proxy && !disable_kcp_input {
        let metrics = insts[0]
            .get_global_ctx()
            .stats_manager()
            .get_metrics_by_prefix(&MetricName::TcpProxyConnect.to_string());
        assert_eq!(metrics.len(), 3);
        for metric in metrics {
            assert_eq!(1, metric.value);
            assert!(metric.labels.labels().iter().any(|l| {
                let t =
                    LabelType::Protocol(TcpProxyEntryTransportType::Kcp.as_str_name().to_string());
                t.key() == l.key && t.value() == l.value
            }));
        }
    } else {
        // tcp subnet proxy
        let metrics = insts[2]
            .get_global_ctx()
            .stats_manager()
            .get_metrics_by_prefix(&MetricName::TcpProxyConnect.to_string());
        if no_tun {
            assert_eq!(metrics.len(), 3);
        } else {
            assert_eq!(metrics.len(), 2);
        }
        for metric in metrics {
            assert_eq!(1, metric.value);
            assert!(metric.labels.labels().iter().any(|l| {
                let t =
                    LabelType::Protocol(TcpProxyEntryTransportType::Tcp.as_str_name().to_string());
                t.key() == l.key && t.value() == l.value
            }));
        }
    }

    drop_insts(insts).await;
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

    drop_insts(_insts).await;
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
    let mut inst4 = Instance::new(get_inst_config(
        "inst4",
        Some("net_d"),
        "10.144.144.4",
        "fd00::4/64",
    ));
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
                        .any(|r| r.peer_id == inst4.peer_id())
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
                    !insts[2]
                        .get_peer_manager()
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .iter()
                        .any(|r| *r == inst4.peer_id())
                },
                // 0 down, assume last packet is recv in -0.01
                // [2, 7) send ping
                // [4, 9) ping fail and close connection
                Duration::from_secs(11),
            )
            .await;

            wait_for_condition(
                || async {
                    !insts[0]
                        .get_peer_manager()
                        .list_routes()
                        .await
                        .iter()
                        .any(|r| r.peer_id == inst4.peer_id())
                },
                Duration::from_secs(7),
            )
            .await;

            set_link_status("net_d", true);
        }

        drop_insts(insts).await;
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
    if let Err(e) = socket.send_to(&call, "10.144.144.255:22111").await {
        panic!("Error sending call: {:?}", e)
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);

    drop_insts(_insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn foreign_network_forward_nic_data() {
    prepare_linux_namespaces();

    let center_node_config = get_inst_config("inst1", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_node_config
        .set_network_identity(NetworkIdentity::new("center".to_string(), "".to_string()));
    let mut center_inst = Instance::new(center_node_config);

    let mut inst1 = Instance::new(get_inst_config(
        "inst1",
        Some("net_b"),
        "10.144.145.1",
        "fd00:1::1/64",
    ));
    let mut inst2 = Instance::new(get_inst_config(
        "inst2",
        Some("net_c"),
        "10.144.145.2",
        "fd00:1::2/64",
    ));

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

    drop_insts(vec![center_inst, inst1, inst2]).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_same_namespace_real_tun() {
    prepare_linux_namespaces();

    let center_cfg = get_inst_config("center", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_cfg.set_listeners(vec![]);
    let mut center = Instance::new(center_cfg);

    let shared_cfg_1 = get_inst_config("shared_1", Some("net_b"), "10.144.144.2", "fd00::2/64");
    shared_cfg_1.set_listeners(vec![]);
    shared_cfg_1.set_socks5_portal(None);
    let mut shared_flags = shared_cfg_1.get_flags();
    shared_flags.dev_name = "et_shared0".to_string();
    shared_cfg_1.set_flags(shared_flags.clone());
    let mut shared_1 = Instance::new(shared_cfg_1);

    let shared_cfg_2 = get_inst_config("shared_2", Some("net_b"), "10.144.144.3", "fd00::3/64");
    shared_cfg_2.set_listeners(vec![]);
    shared_cfg_2.set_socks5_portal(None);
    shared_cfg_2.set_flags(shared_flags);
    let mut shared_2 = Instance::new(shared_cfg_2);

    let remote_cfg = get_inst_config("remote", Some("net_c"), "10.144.144.4", "fd00::4/64");
    remote_cfg.set_listeners(vec![]);
    let mut remote = Instance::new(remote_cfg);

    let mut shared_1_events = shared_1.get_global_ctx().subscribe();
    let mut shared_2_events = shared_2.get_global_ctx().subscribe();

    center.run().await.unwrap();
    shared_1.run().await.unwrap();
    shared_2.run().await.unwrap();
    remote.run().await.unwrap();

    let shared_1_tun = wait_for_tun_ready_event(&mut shared_1_events).await;
    let shared_2_tun = wait_for_tun_ready_event(&mut shared_2_events).await;
    assert_eq!(shared_1_tun, shared_2_tun);

    shared_1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    shared_2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    remote
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    wait_for_condition(
        || async {
            shared_1.get_peer_manager().list_routes().await.len() == 3
                && shared_2.get_peer_manager().list_routes().await.len() == 3
                && remote.get_peer_manager().list_routes().await.len() == 3
        },
        Duration::from_secs(8),
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.2", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.3", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_b", "10.144.144.4", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping6_test("net_c", "fd00::2", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping6_test("net_c", "fd00::3", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping6_test("net_b", "fd00::4", None).await },
        Duration::from_secs(8),
    )
    .await;

    drop_insts(vec![center, shared_1, shared_2, remote]).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_dev_name_mismatch_falls_back_to_dedicated_tun() {
    prepare_linux_namespaces();

    let shared_cfg_1 = get_inst_config("shared_1", Some("net_b"), "10.144.144.2", "fd00::2/64");
    shared_cfg_1.set_listeners(vec![]);
    shared_cfg_1.set_socks5_portal(None);
    let mut flags_1 = shared_cfg_1.get_flags();
    flags_1.dev_name = "et_sdm0".to_string();
    shared_cfg_1.set_flags(flags_1);
    let mut shared_1 = Instance::new(shared_cfg_1);

    let shared_cfg_2 = get_inst_config("shared_2", Some("net_b"), "10.144.144.3", "fd00::3/64");
    shared_cfg_2.set_listeners(vec![]);
    shared_cfg_2.set_socks5_portal(None);
    let mut flags_2 = shared_cfg_2.get_flags();
    flags_2.dev_name = "et_sdm1".to_string();
    shared_cfg_2.set_flags(flags_2);
    let mut shared_2 = Instance::new(shared_cfg_2);

    let mut shared_1_events = shared_1.get_global_ctx().subscribe();
    let mut shared_2_events = shared_2.get_global_ctx().subscribe();

    shared_1.run().await.unwrap();
    shared_2.run().await.unwrap();

    let ifname = wait_for_tun_ready_event(&mut shared_1_events).await;
    assert_eq!(ifname, "et_sdm0");

    let reason = wait_for_tun_fallback_event(&mut shared_2_events).await;
    assert!(reason.contains("does not match requested dev_name"));
    wait_for_condition(
        || async { link_exists_in_netns("net_b", "et_sdm1").await },
        Duration::from_secs(8),
    )
    .await;
    assert_no_tun_fallback_event(&mut shared_1_events, Duration::from_secs(2)).await;

    drop_insts(vec![shared_1, shared_2]).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_cleans_up_device_after_last_member_leaves() {
    prepare_linux_namespaces();

    let shared_cfg_1 = get_inst_config("shared_1", Some("net_b"), "10.144.144.2", "fd00::2/64");
    shared_cfg_1.set_listeners(vec![]);
    shared_cfg_1.set_socks5_portal(None);
    let mut shared_flags = shared_cfg_1.get_flags();
    shared_flags.dev_name = "et_shared_gc0".to_string();
    shared_cfg_1.set_flags(shared_flags.clone());
    let mut shared_1 = Instance::new(shared_cfg_1);

    let shared_cfg_2 = get_inst_config("shared_2", Some("net_b"), "10.144.144.3", "fd00::3/64");
    shared_cfg_2.set_listeners(vec![]);
    shared_cfg_2.set_socks5_portal(None);
    shared_cfg_2.set_flags(shared_flags);
    let mut shared_2 = Instance::new(shared_cfg_2);

    let mut shared_1_events = shared_1.get_global_ctx().subscribe();
    let mut shared_2_events = shared_2.get_global_ctx().subscribe();

    shared_1.run().await.unwrap();
    shared_2.run().await.unwrap();

    let ifname = wait_for_tun_ready_event(&mut shared_1_events).await;
    assert_eq!(ifname, wait_for_tun_ready_event(&mut shared_2_events).await);
    assert!(link_exists_in_netns("net_b", &ifname).await);

    shared_1.clear_resources().await;
    drop(shared_1);
    wait_for_condition(
        || async { link_exists_in_netns("net_b", &ifname).await },
        Duration::from_secs(5),
    )
    .await;

    shared_2.clear_resources().await;
    drop(shared_2);
    wait_for_condition(
        || async { !link_exists_in_netns("net_b", &ifname).await },
        Duration::from_secs(8),
    )
    .await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_proxy_cidr_same_namespace_real_tun() {
    prepare_linux_namespaces();

    let center_cfg = get_inst_config("center", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_cfg.set_listeners(vec![]);
    let mut center = Instance::new(center_cfg);

    let shared_cfg_1 = get_inst_config("shared_1", Some("net_c"), "10.144.144.2", "fd00::2/64");
    shared_cfg_1.set_listeners(vec![]);
    shared_cfg_1.set_socks5_portal(None);
    shared_cfg_1
        .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
        .unwrap();
    let mut shared_flags = shared_cfg_1.get_flags();
    shared_flags.dev_name = "et_shp0".to_string();
    shared_cfg_1.set_flags(shared_flags.clone());
    let mut shared_1 = Instance::new(shared_cfg_1);

    let shared_cfg_2 = get_inst_config("shared_2", Some("net_c"), "10.144.144.3", "fd00::3/64");
    shared_cfg_2.set_listeners(vec![]);
    shared_cfg_2.set_socks5_portal(None);
    shared_cfg_2.set_flags(shared_flags);
    let mut shared_2 = Instance::new(shared_cfg_2);

    let remote_cfg = get_inst_config("remote", Some("net_b"), "10.144.144.4", "fd00::4/64");
    remote_cfg.set_listeners(vec![]);
    let mut remote = Instance::new(remote_cfg);

    let mut shared_1_events = shared_1.get_global_ctx().subscribe();
    let mut shared_2_events = shared_2.get_global_ctx().subscribe();

    center.run().await.unwrap();
    shared_1.run().await.unwrap();
    shared_2.run().await.unwrap();
    remote.run().await.unwrap();

    let shared_1_tun = wait_for_tun_ready_event(&mut shared_1_events).await;
    let shared_2_tun = wait_for_tun_ready_event(&mut shared_2_events).await;
    assert_eq!(shared_1_tun, shared_2_tun);

    shared_1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    shared_2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    remote
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    wait_for_condition(
        || async {
            shared_1.get_peer_manager().list_routes().await.len() == 3
                && shared_2.get_peer_manager().list_routes().await.len() == 3
                && remote.get_peer_manager().list_routes().await.len() == 3
        },
        Duration::from_secs(8),
    )
    .await;

    wait_proxy_route_appear(
        &center.get_peer_manager(),
        "10.144.144.2/24",
        shared_1.peer_id(),
        "10.1.2.0/24",
    )
    .await;
    wait_proxy_route_appear(
        &remote.get_peer_manager(),
        "10.144.144.2/24",
        shared_1.peer_id(),
        "10.1.2.0/24",
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_a", "10.1.2.4", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_b", "10.1.2.4", None).await },
        Duration::from_secs(8),
    )
    .await;

    assert_no_tun_fallback_event(&mut shared_1_events, Duration::from_secs(2)).await;
    assert_no_tun_fallback_event(&mut shared_2_events, Duration::from_secs(2)).await;

    drop_insts(vec![center, shared_1, shared_2, remote]).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_dhcp_same_namespace_real_tun() {
    prepare_linux_namespaces();

    let center_cfg = get_inst_config("center", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_cfg.set_listeners(vec![]);
    let mut center = Instance::new(center_cfg);

    let dhcp_cfg_1 = get_inst_config("dhcp_1", Some("net_b"), "10.144.144.2", "fd00::2/64");
    dhcp_cfg_1.set_listeners(vec![]);
    dhcp_cfg_1.set_socks5_portal(None);
    dhcp_cfg_1.set_ipv4(None);
    dhcp_cfg_1.set_dhcp(true);
    let mut dhcp_flags = dhcp_cfg_1.get_flags();
    dhcp_flags.dev_name = "et_shdh0".to_string();
    dhcp_cfg_1.set_flags(dhcp_flags.clone());
    let mut dhcp_1 = Instance::new(dhcp_cfg_1);

    let dhcp_cfg_2 = get_inst_config("dhcp_2", Some("net_b"), "10.144.144.3", "fd00::3/64");
    dhcp_cfg_2.set_listeners(vec![]);
    dhcp_cfg_2.set_socks5_portal(None);
    dhcp_cfg_2.set_ipv4(None);
    dhcp_cfg_2.set_dhcp(true);
    dhcp_cfg_2.set_flags(dhcp_flags);
    let mut dhcp_2 = Instance::new(dhcp_cfg_2);

    let remote_cfg = get_inst_config("remote", Some("net_c"), "10.144.144.4", "fd00::4/64");
    remote_cfg.set_listeners(vec![]);
    let mut remote = Instance::new(remote_cfg);

    let mut dhcp_1_tun_events = dhcp_1.get_global_ctx().subscribe();
    let mut dhcp_2_tun_events = dhcp_2.get_global_ctx().subscribe();
    let mut dhcp_1_dhcp_events = dhcp_1.get_global_ctx().subscribe();
    let mut dhcp_2_dhcp_events = dhcp_2.get_global_ctx().subscribe();

    center.run().await.unwrap();
    dhcp_1.run().await.unwrap();

    dhcp_1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    let dhcp_1_tun = wait_for_tun_ready_event(&mut dhcp_1_tun_events).await;
    let dhcp_1_ip = wait_for_dhcp_ipv4_changed_event(&mut dhcp_1_dhcp_events).await;

    wait_for_condition(
        || async { dhcp_1.get_peer_manager().list_routes().await.len() == 1 },
        Duration::from_secs(8),
    )
    .await;

    dhcp_2.run().await.unwrap();
    remote.run().await.unwrap();

    dhcp_2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    remote
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    let dhcp_2_tun = wait_for_tun_ready_event(&mut dhcp_2_tun_events).await;
    let dhcp_2_ip = wait_for_dhcp_ipv4_changed_event(&mut dhcp_2_dhcp_events).await;

    assert_eq!(dhcp_1_tun, dhcp_2_tun);
    assert_ne!(dhcp_1_ip.address(), dhcp_2_ip.address());
    assert_eq!(dhcp_1_ip.network(), dhcp_2_ip.network());

    wait_for_condition(
        || async {
            dhcp_1.get_peer_manager().list_routes().await.len() == 3
                && dhcp_2.get_peer_manager().list_routes().await.len() == 3
                && remote.get_peer_manager().list_routes().await.len() == 3
        },
        Duration::from_secs(12),
    )
    .await;

    let dhcp_1_ip_str = dhcp_1_ip.address().to_string();
    let dhcp_2_ip_str = dhcp_2_ip.address().to_string();
    wait_for_condition(
        || async { ping_test("net_c", &dhcp_1_ip_str, None).await },
        Duration::from_secs(12),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_c", &dhcp_2_ip_str, None).await },
        Duration::from_secs(12),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_b", "10.144.144.4", None).await },
        Duration::from_secs(12),
    )
    .await;

    assert_no_tun_fallback_event(&mut dhcp_1_tun_events, Duration::from_secs(2)).await;
    assert_no_tun_fallback_event(&mut dhcp_2_tun_events, Duration::from_secs(2)).await;

    drop_insts(vec![center, dhcp_1, dhcp_2, remote]).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_dynamic_proxy_conflict_falls_back() {
    use crate::proto::api::config::{ConfigPatchAction, InstanceConfigPatch, ProxyNetworkPatch};

    prepare_linux_namespaces();

    let center_cfg = get_inst_config("center", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_cfg.set_listeners(vec![]);
    let mut center = Instance::new(center_cfg);

    let shared_cfg_1 = get_inst_config("shared_1", Some("net_c"), "10.144.144.2", "fd00::2/64");
    shared_cfg_1.set_listeners(vec![]);
    shared_cfg_1.set_socks5_portal(None);
    shared_cfg_1
        .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
        .unwrap();
    let mut shared_flags = shared_cfg_1.get_flags();
    shared_flags.dev_name = "et_srf0".to_string();
    shared_cfg_1.set_flags(shared_flags.clone());
    let mut shared_1 = Instance::new(shared_cfg_1);

    let shared_cfg_2 = get_inst_config("shared_2", Some("net_c"), "10.144.144.3", "fd00::3/64");
    shared_cfg_2.set_listeners(vec![]);
    shared_cfg_2.set_socks5_portal(None);
    shared_cfg_2.set_flags(shared_flags);
    let mut shared_2 = Instance::new(shared_cfg_2);

    let remote_cfg = get_inst_config("remote", Some("net_b"), "10.144.144.4", "fd00::4/64");
    remote_cfg.set_listeners(vec![]);
    let mut remote = Instance::new(remote_cfg);

    let mut shared_1_events = shared_1.get_global_ctx().subscribe();
    let mut shared_2_events = shared_2.get_global_ctx().subscribe();

    center.run().await.unwrap();
    shared_1.run().await.unwrap();
    shared_2.run().await.unwrap();
    remote.run().await.unwrap();

    let shared_1_tun = wait_for_tun_ready_event(&mut shared_1_events).await;
    let shared_2_tun = wait_for_tun_ready_event(&mut shared_2_events).await;
    assert_eq!(shared_1_tun, shared_2_tun);

    shared_1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    shared_2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    remote
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    wait_for_condition(
        || async {
            shared_1.get_peer_manager().list_routes().await.len() == 3
                && shared_2.get_peer_manager().list_routes().await.len() == 3
                && remote.get_peer_manager().list_routes().await.len() == 3
        },
        Duration::from_secs(8),
    )
    .await;

    shared_2
        .get_config_patcher()
        .apply_patch(InstanceConfigPatch {
            proxy_networks: vec![ProxyNetworkPatch {
                action: ConfigPatchAction::Add as i32,
                cidr: Some("10.1.2.0/24".parse().unwrap()),
                mapped_cidr: None,
            }],
            ..Default::default()
        })
        .await
        .unwrap();

    let reason = wait_for_tun_fallback_event(&mut shared_2_events).await;
    assert!(reason.contains("route prefix"));
    wait_for_condition(
        || async { ping_test("net_b", "10.1.2.4", None).await },
        Duration::from_secs(10),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_b", "10.144.144.3", None).await },
        Duration::from_secs(10),
    )
    .await;
    assert_no_tun_fallback_event(&mut shared_1_events, Duration::from_secs(2)).await;

    drop_insts(vec![center, shared_1, shared_2, remote]).await;
}

#[cfg(feature = "magic-dns")]
#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_magic_dns_same_namespace_real_tun() {
    prepare_linux_namespaces();

    let center_cfg = get_inst_config("center", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_cfg.set_listeners(vec![]);
    let mut center = Instance::new(center_cfg);

    let shared_cfg_1 = get_inst_config("shared_1", Some("net_b"), "10.144.144.2", "fd00::2/64");
    shared_cfg_1.set_listeners(vec![]);
    shared_cfg_1.set_socks5_portal(None);
    let mut shared_flags = shared_cfg_1.get_flags();
    shared_flags.dev_name = "et_shared_dns0".to_string();
    shared_flags.accept_dns = true;
    shared_cfg_1.set_flags(shared_flags.clone());
    let mut shared_1 = Instance::new(shared_cfg_1);

    let shared_cfg_2 = get_inst_config("shared_2", Some("net_b"), "10.144.144.3", "fd00::3/64");
    shared_cfg_2.set_listeners(vec![]);
    shared_cfg_2.set_socks5_portal(None);
    shared_cfg_2.set_flags(shared_flags);
    let mut shared_2 = Instance::new(shared_cfg_2);

    let remote_cfg = get_inst_config("remote", Some("net_c"), "10.144.144.4", "fd00::4/64");
    remote_cfg.set_listeners(vec![]);
    let mut remote = Instance::new(remote_cfg);

    let mut shared_1_events = shared_1.get_global_ctx().subscribe();
    let mut shared_2_events = shared_2.get_global_ctx().subscribe();

    center.run().await.unwrap();
    shared_1.run().await.unwrap();
    shared_2.run().await.unwrap();
    remote.run().await.unwrap();

    let shared_1_tun = wait_for_tun_ready_event(&mut shared_1_events).await;
    let shared_2_tun = wait_for_tun_ready_event(&mut shared_2_events).await;
    assert_eq!(shared_1_tun, shared_2_tun);

    shared_1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    shared_2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    remote
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    wait_for_condition(
        || async {
            shared_1.get_peer_manager().list_routes().await.len() == 3
                && shared_2.get_peer_manager().list_routes().await.len() == 3
                && remote.get_peer_manager().list_routes().await.len() == 3
        },
        Duration::from_secs(8),
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.2", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.3", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_b", "10.144.144.4", None).await },
        Duration::from_secs(8),
    )
    .await;
    let _ = MAGIC_DNS_INSTANCE_ADDR;

    assert_no_tun_fallback_event(&mut shared_1_events, Duration::from_secs(2)).await;
    assert_no_tun_fallback_event(&mut shared_2_events, Duration::from_secs(2)).await;

    drop_insts(vec![center, shared_1, shared_2, remote]).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_kcp_proxy_with_source_shared_tun() {
    shared_tun_subnet_proxy_transport_test(TcpProxyEntryTransportType::Kcp, true).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_quic_proxy_with_source_shared_tun() {
    shared_tun_subnet_proxy_transport_test(TcpProxyEntryTransportType::Quic, true).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_kcp_proxy_with_destination_shared_tun() {
    shared_tun_subnet_proxy_transport_test(TcpProxyEntryTransportType::Kcp, false).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn shared_tun_quic_proxy_with_destination_shared_tun() {
    shared_tun_subnet_proxy_transport_test(TcpProxyEntryTransportType::Quic, false).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn same_namespace_no_tun_skips_shared_tun_and_keeps_connectivity() {
    prepare_linux_namespaces();

    let center_cfg = get_inst_config("center", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_cfg.set_listeners(vec![]);
    let mut center = Instance::new(center_cfg);

    let no_tun_cfg_1 = get_inst_config("no_tun_1", Some("net_b"), "10.144.144.2", "fd00::2/64");
    no_tun_cfg_1.set_listeners(vec![]);
    no_tun_cfg_1.set_socks5_portal(None);
    let mut no_tun_flags = no_tun_cfg_1.get_flags();
    no_tun_flags.dev_name = "et_shared_disabled0".to_string();
    no_tun_flags.no_tun = true;
    no_tun_cfg_1.set_flags(no_tun_flags.clone());
    let mut no_tun_1 = Instance::new(no_tun_cfg_1);

    let no_tun_cfg_2 = get_inst_config("no_tun_2", Some("net_b"), "10.144.144.3", "fd00::3/64");
    no_tun_cfg_2.set_listeners(vec![]);
    no_tun_cfg_2.set_socks5_portal(None);
    no_tun_cfg_2.set_flags(no_tun_flags);
    let mut no_tun_2 = Instance::new(no_tun_cfg_2);

    let remote_cfg = get_inst_config("remote", Some("net_c"), "10.144.144.4", "fd00::4/64");
    remote_cfg.set_listeners(vec![]);
    let mut remote = Instance::new(remote_cfg);

    let mut no_tun_1_events = no_tun_1.get_global_ctx().subscribe();
    let mut no_tun_2_events = no_tun_2.get_global_ctx().subscribe();

    center.run().await.unwrap();
    no_tun_1.run().await.unwrap();
    no_tun_2.run().await.unwrap();
    remote.run().await.unwrap();

    assert_no_tun_ready_event(&mut no_tun_1_events, Duration::from_secs(2)).await;
    assert_no_tun_ready_event(&mut no_tun_2_events, Duration::from_secs(2)).await;

    no_tun_1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    no_tun_2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));
    remote
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center.id()).parse().unwrap(),
        ));

    wait_for_condition(
        || async {
            no_tun_1.get_peer_manager().list_routes().await.len() == 3
                && no_tun_2.get_peer_manager().list_routes().await.len() == 3
                && remote.get_peer_manager().list_routes().await.len() == 3
        },
        Duration::from_secs(8),
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.2", None).await },
        Duration::from_secs(8),
    )
    .await;
    wait_for_condition(
        || async { ping_test("net_c", "10.144.144.3", None).await },
        Duration::from_secs(8),
    )
    .await;

    drop_insts(vec![center, no_tun_1, no_tun_2, remote]).await;
}

use std::{net::SocketAddr, str::FromStr};

use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer, key::Key, net::IpAddrMask,
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
#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn wireguard_vpn_portal(#[values(true, false)] test_v6: bool) {
    let mut insts = init_three_node("tcp").await;

    if test_v6 {
        ping6_test("net_d", "fd12::3", None).await;
    } else {
        ping_test("net_d", "10.1.2.3", None).await;
    }

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

    let dst_socket_addr = if test_v6 {
        "[fd12::3]:22121".parse().unwrap()
    } else {
        "10.1.2.3:22121".parse().unwrap()
    };

    let net_ns = NetNS::new(Some("net_d".into()));
    let _g = net_ns.guard();
    let wg_cfg = get_wg_config_for_portal(&insts[2].get_global_ctx().get_network_identity());
    run_wireguard_client(
        dst_socket_addr,
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

    drop_insts(insts).await;
}

#[cfg(feature = "wireguard")]
#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn socks5_vpn_portal(
    #[values("10.144.144.1", "10.144.144.3", "10.1.2.4")] dst_addr: &str,
) {
    use rand::Rng as _;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_socks::tcp::socks5::Socks5Stream;

    let _insts = init_three_node_ex(
        "tcp",
        |cfg| {
            if cfg.get_inst_name() == "inst3" {
                // 添加子网代理配置
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            }
            cfg
        },
        false,
    )
    .await;

    let mut buf = vec![0u8; 1024];
    rand::thread_rng().fill(&mut buf[..]);

    let buf_clone = buf.clone();
    let dst_addr_clone = dst_addr.to_owned();
    let task = tokio::spawn(async move {
        let net_ns = if dst_addr_clone == "10.144.144.1" {
            NetNS::new(Some("net_a".into()))
        } else if dst_addr_clone == "10.144.144.3" {
            NetNS::new(Some("net_c".into()))
        } else {
            NetNS::new(Some("net_d".into()))
        };

        let _g = net_ns.guard();

        let socket = TcpListener::bind("0.0.0.0:22222").await.unwrap();
        let (mut st, addr) = socket.accept().await.unwrap();

        if dst_addr_clone == "10.144.144.1" {
            assert_eq!(addr.ip().to_string(), "127.0.0.1".to_string());
        } else if dst_addr_clone == "10.144.144.3" {
            assert_eq!(addr.ip().to_string(), "10.144.144.1".to_string());
        } else {
            assert_eq!(addr.ip().to_string(), "10.1.2.3".to_string());
        }

        let rbuf = &mut [0u8; 1024];
        st.read_exact(rbuf).await.unwrap();
        assert_eq!(rbuf, buf_clone.as_slice());
    });

    let net_ns = if dst_addr == "10.1.2.4" {
        NetNS::new(Some("net_c".into()))
    } else {
        NetNS::new(Some("net_a".into()))
    };
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

    drop_insts(_insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn foreign_network_functional_cluster() {
    crate::set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);
    prepare_linux_namespaces();

    let center_node_config1 = get_inst_config("inst1", Some("net_a"), "10.144.144.1", "fd00::1/64");
    center_node_config1
        .set_network_identity(NetworkIdentity::new("center".to_string(), "".to_string()));
    let mut center_inst1 = Instance::new(center_node_config1);

    let center_node_config2 = get_inst_config("inst2", Some("net_b"), "10.144.144.2", "fd00::2/64");
    center_node_config2
        .set_network_identity(NetworkIdentity::new("center".to_string(), "".to_string()));
    let mut center_inst2 = Instance::new(center_node_config2);

    let inst1_config = get_inst_config("inst1", Some("net_c"), "10.144.145.1", "fd00:2::1/64");
    inst1_config.set_listeners(vec![]);
    let mut inst1 = Instance::new(inst1_config);

    let mut inst2 = Instance::new(get_inst_config(
        "inst2",
        Some("net_d"),
        "10.144.145.2",
        "fd00:2::2/64",
    ));

    center_inst1.run().await.unwrap();
    center_inst2.run().await.unwrap();
    inst1.run().await.unwrap();
    inst2.run().await.unwrap();

    center_inst1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center_inst2.id()).parse().unwrap(),
        ));

    inst1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center_inst1.id()).parse().unwrap(),
        ));

    inst2
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center_inst2.id()).parse().unwrap(),
        ));

    let peer_map_inst1 = inst1.get_peer_manager();
    println!("inst1 peer map: {:?}", peer_map_inst1.list_routes().await);
    drop(peer_map_inst1);

    wait_for_condition(
        || async { ping_test("net_c", "10.144.145.2", None).await },
        Duration::from_secs(5),
    )
    .await;

    // connect to two centers, ping should work
    inst1
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", center_inst2.id()).parse().unwrap(),
        ));
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    wait_for_condition(
        || async { ping_test("net_c", "10.144.145.2", None).await },
        Duration::from_secs(5),
    )
    .await;

    drop_insts(vec![center_inst1, center_inst2, inst1, inst2]).await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn manual_reconnector(#[values(true, false)] is_foreign: bool) {
    prepare_linux_namespaces();

    let center_node_config = get_inst_config("inst1", Some("net_a"), "10.144.144.1", "fd00::1/64");
    if is_foreign {
        center_node_config
            .set_network_identity(NetworkIdentity::new("center".to_string(), "".to_string()));
    }
    let mut center_inst = Instance::new(center_node_config);

    let inst1_config = get_inst_config("inst1", Some("net_b"), "10.144.145.1", "fd00:1::1/64");
    inst1_config.set_listeners(vec![]);
    let mut inst1 = Instance::new(inst1_config);

    let mut inst2 = Instance::new(get_inst_config(
        "inst2",
        Some("net_c"),
        "10.144.145.2",
        "fd00:1::2/64",
    ));

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
    let center_inst_peer_id = if !is_foreign {
        center_inst.peer_id()
    } else {
        center_inst
            .get_peer_manager()
            .get_foreign_network_manager()
            .get_network_peer_id(&inst1.get_global_ctx().get_network_identity().network_name)
            .unwrap()
    };

    let conns = peer_map.list_peer_conns(center_inst_peer_id).await.unwrap();

    assert!(!conns.is_empty());

    wait_for_condition(
        || async { ping_test("net_b", "10.144.145.2", None).await },
        Duration::from_secs(5),
    )
    .await;

    drop(peer_map);
    drop_insts(vec![center_inst, inst1, inst2]).await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn port_forward_test(
    #[values(true, false)] no_tun: bool,
    #[values(64, 1900)] buf_size: u64,
    #[values(true, false)] enable_kcp: bool,
    #[values(true, false)] dst_disable_kcp_input: bool,
    #[values(true, false)] disable_relay_kcp: bool,
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

                let mut flags = cfg.get_flags();
                flags.no_tun = no_tun;
                flags.enable_kcp_proxy = enable_kcp;
                cfg.set_flags(flags);
            } else if cfg.get_inst_name() == "inst3" {
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
                let mut flags = cfg.get_flags();
                flags.disable_kcp_input = dst_disable_kcp_input;
                cfg.set_flags(flags);
            } else if cfg.get_inst_name() == "inst2" {
                let mut flags = cfg.get_flags();
                flags.disable_relay_kcp = disable_relay_kcp;
                cfg.set_flags(flags);
            }

            cfg
        },
        false,
    )
    .await;

    use crate::tunnel::{tcp::TcpTunnelListener, udp::UdpTunnelConnector, udp::UdpTunnelListener};

    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:23456".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://127.0.0.1:23456".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns_with_timeout(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf,
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:23457".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://127.0.0.1:23457".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns_with_timeout(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
        buf,
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    let udp_listener = UdpTunnelListener::new("udp://0.0.0.0:23458".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://127.0.0.1:23458".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns_with_timeout(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf,
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    let udp_listener = UdpTunnelListener::new("udp://0.0.0.0:23459".parse().unwrap());
    let udp_connector = UdpTunnelConnector::new("udp://127.0.0.1:23459".parse().unwrap());

    let mut buf = vec![0; buf_size as usize];
    rand::thread_rng().fill(&mut buf[..]);

    _tunnel_pingpong_netns_with_timeout(
        udp_listener,
        udp_connector,
        NetNS::new(Some("net_d".into())),
        NetNS::new(Some("net_a".into())),
        buf,
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    drop_insts(_insts).await;
}

#[rstest::rstest]
#[serial_test::serial]
#[tokio::test]
pub async fn relay_bps_limit_test(#[values(100, 200, 400, 800)] bps_limit: u64) {
    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst2" {
                cfg.set_network_identity(NetworkIdentity::new(
                    "public".to_string(),
                    "public".to_string(),
                ));
                let mut f = cfg.get_flags();
                f.foreign_relay_bps_limit = bps_limit * 1024;
                cfg.set_flags(f);
            }
            cfg
        },
        true,
    )
    .await;

    // connect to virtual ip (no tun mode)
    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:22223".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://10.144.144.3:22223".parse().unwrap());

    let bps = _tunnel_bench_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
    )
    .await;

    println!("bps: {}", bps);

    let bps = bps as u64 / 1024;
    // allow 50kb jitter
    assert!(
        bps >= bps_limit - 50 && bps <= bps_limit + 50,
        "bps: {}, bps_limit: {}",
        bps,
        bps_limit
    );

    drop_insts(insts).await;
}

#[rstest::rstest]
#[serial_test::serial]
#[tokio::test]
pub async fn instance_recv_bps_limit_test(#[values(100, 800)] bps_limit: u64) {
    let insts = init_three_node_ex(
        "tcp",
        |cfg| {
            if cfg.get_inst_name() == "inst2" {
                let mut f = cfg.get_flags();
                f.instance_recv_bps_limit = bps_limit * 1024;
                cfg.set_flags(f);
            }
            cfg
        },
        false,
    )
    .await;

    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:22223".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://10.144.144.3:22223".parse().unwrap());

    let bps = _tunnel_bench_netns(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
    )
    .await;

    println!("bps: {}", bps);

    let bps = bps as u64 / 1024;
    assert!(
        bps >= bps_limit - 50 && bps <= bps_limit + 50,
        "bps: {}, bps_limit: {}",
        bps,
        bps_limit
    );

    drop_insts(insts).await;
}

async fn assert_try_direct_connect_err<C>(inst: &Instance, connector: C)
where
    C: crate::tunnel::TunnelConnector + std::fmt::Debug,
{
    let ret = tokio::time::timeout(
        Duration::from_millis(100),
        inst.get_peer_manager().try_direct_connect(connector),
    )
    .await;

    assert!(matches!(ret, Err(_) | Ok(Err(_))));
}

use std::fs;
use std::io;

fn print_all_fds() -> io::Result<()> {
    let fd_dir = "/proc/self/fd";

    // 读取 /proc/self/fd 目录中的所有条目
    for entry in fs::read_dir(fd_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let fd_str = file_name.to_string_lossy();

        // 尝试解析为数字（跳过 . 和 ..）
        if let Ok(fd_num) = fd_str.parse::<i32>() {
            // 获取文件描述符指向的文件路径（如果可能）
            let target_path = format!("{}/{}", fd_dir, fd_num);
            match fs::read_link(&target_path) {
                Ok(target) => {
                    println!("FD {}: {}", fd_num, target.to_string_lossy());
                }
                Err(e) => {
                    println!("FD {}: (unreadable: {})", fd_num, e);
                }
            }
        }
    }
    Ok(())
}

#[rstest::rstest]
#[serial_test::serial]
#[tokio::test]
async fn avoid_tunnel_loop_back_to_virtual_network(
    #[values(true, false)] no_tun: bool,
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] enable_quic_proxy: bool,
) {
    if enable_kcp_proxy && enable_quic_proxy {
        return;
    }

    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if matches!(cfg.get_inst_name().as_str(), "inst2" | "inst3") {
                let mut flags = cfg.get_flags();
                flags.no_tun = no_tun;
                cfg.set_flags(flags);
            }

            if cfg.get_inst_name().as_str() == "inst1" {
                let mut flags = cfg.get_flags();
                flags.enable_kcp_proxy = enable_kcp_proxy;
                flags.enable_quic_proxy = enable_quic_proxy;
                cfg.set_flags(flags);
            }

            if cfg.get_inst_name().as_str() == "inst3" {
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            }

            cfg
        },
        false,
    )
    .await;

    assert_try_direct_connect_err(
        &insts[0],
        TcpTunnelConnector::new("tcp://10.144.144.2:11010".parse().unwrap()),
    )
    .await;

    assert_try_direct_connect_err(
        &insts[0],
        UdpTunnelConnector::new("udp://10.144.144.3:11010".parse().unwrap()),
    )
    .await;

    assert_try_direct_connect_err(
        &insts[0],
        TcpTunnelConnector::new("tcp://10.1.2.3:11010".parse().unwrap()),
    )
    .await;

    assert_try_direct_connect_err(
        &insts[0],
        UdpTunnelConnector::new("udp://10.1.2.3:11010".parse().unwrap()),
    )
    .await;

    drop_insts(insts).await;

    let _ = print_all_fds();
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn acl_rule_test_inbound(
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] enable_quic_proxy: bool,
) {
    use crate::tunnel::{
        common::tests::_tunnel_pingpong_netns_with_timeout,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
        udp::{UdpTunnelConnector, UdpTunnelListener},
    };
    use rand::Rng;
    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst1" {
                let mut flags = cfg.get_flags();
                flags.enable_kcp_proxy = enable_kcp_proxy;
                flags.enable_quic_proxy = enable_quic_proxy;
                cfg.set_flags(flags);
            }
            cfg
        },
        false,
    )
    .await;

    // 构造 ACL 配置
    use crate::proto::acl::*;
    let mut acl = Acl::default();
    let mut acl_v1 = AclV1::default();

    let mut chain = Chain {
        name: "test_inbound".to_string(),
        chain_type: ChainType::Inbound as i32,
        enabled: true,
        ..Default::default()
    };

    // 禁止 8080
    let deny_rule = Rule {
        name: "deny_8080".to_string(),
        priority: 200,
        enabled: true,
        action: Action::Drop as i32,
        protocol: Protocol::Any as i32,
        ports: vec!["8080".to_string()],
        ..Default::default()
    };
    chain.rules.push(deny_rule);

    // 允许其他
    let allow_rule = Rule {
        name: "allow_all".to_string(),
        priority: 100,
        enabled: true,
        action: Action::Allow as i32,
        protocol: Protocol::Any as i32,
        stateful: true,
        ..Default::default()
    };
    chain.rules.push(allow_rule);

    // 禁止 src ip 为 10.144.144.2 的流量
    let deny_rule = Rule {
        name: "deny_10.144.144.2".to_string(),
        priority: 200,
        enabled: true,
        action: Action::Drop as i32,
        protocol: Protocol::Any as i32,
        source_ips: vec!["10.144.144.2/32".to_string()],
        ..Default::default()
    };
    chain.rules.push(deny_rule);

    acl_v1.chains.push(chain);
    acl.acl_v1 = Some(acl_v1);

    // convert acl to to toml
    let acl_toml = toml::to_string(&acl).unwrap();
    println!("ACL TOML: {}", acl_toml);

    insts[2]
        .get_global_ctx()
        .get_acl_filter()
        .reload_rules(Some(&acl));

    // TCP 测试部分
    {
        // 2. 在 inst2 上监听 8080 和 8081
        let listener_8080 = TcpTunnelListener::new("tcp://0.0.0.0:8080".parse().unwrap());
        let listener_8081 = TcpTunnelListener::new("tcp://0.0.0.0:8081".parse().unwrap());
        let listener_8082 = TcpTunnelListener::new("tcp://0.0.0.0:8082".parse().unwrap());

        // 3. inst1 作为客户端，尝试连接 inst2 的 8080（应被拒绝）和 8081（应被允许）
        let connector_8080 =
            TcpTunnelConnector::new(format!("tcp://{}:8080", "10.144.144.3").parse().unwrap());
        let connector_8081 =
            TcpTunnelConnector::new(format!("tcp://{}:8081", "10.144.144.3").parse().unwrap());
        let connector_8082 =
            TcpTunnelConnector::new(format!("tcp://{}:8082", "10.144.144.3").parse().unwrap());

        // 4. 构造测试数据
        let mut buf = vec![0; 32];
        rand::thread_rng().fill(&mut buf[..]);

        // 5. 8081 应该可以 pingpong 成功
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8081,
            connector_8081,
            NetNS::new(Some("net_c".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_ok(), "{}", result.unwrap_err());

        // 6. 8080 应该连接失败（被 ACL 拦截）
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8080,
            connector_8080,
            NetNS::new(Some("net_c".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_millis(500),
        )
        .await;

        assert!(result.is_err(), "TCP 连接 8080 应被 ACL 拦截，不能成功");

        // 7. 从 10.144.144.2 连接 8082 应该连接失败（被 ACL 拦截）
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8082,
            connector_8082,
            NetNS::new(Some("net_c".into())),
            NetNS::new(Some("net_b".into())),
            buf.clone(),
            Duration::from_millis(500),
        )
        .await;

        assert!(result.is_err(), "TCP 连接 8082 应被 ACL 拦截，不能成功");

        let stats = insts[2].get_global_ctx().get_acl_filter().get_stats();
        println!("stats: {:?}", stats);
    }

    // UDP 测试部分
    {
        // 1. 在 inst2 上监听 UDP 8080 和 8081
        let listener_8080 = UdpTunnelListener::new("udp://0.0.0.0:8080".parse().unwrap());
        let listener_8081 = UdpTunnelListener::new("udp://0.0.0.0:8081".parse().unwrap());

        // 2. inst1 作为客户端，尝试连接 inst2 的 8080（应被拒绝）和 8081（应被允许）
        let connector_8080 =
            UdpTunnelConnector::new(format!("udp://{}:8080", "10.144.144.3").parse().unwrap());
        let connector_8081 =
            UdpTunnelConnector::new(format!("udp://{}:8081", "10.144.144.3").parse().unwrap());

        // 3. 构造测试数据
        let mut buf = vec![0; 32];
        rand::thread_rng().fill(&mut buf[..]);

        // 4. 8081 应该可以 pingpong 成功
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8081,
            connector_8081,
            NetNS::new(Some("net_c".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_ok(), "{}", result.unwrap_err());

        // 5. 8080 应该连接失败（被 ACL 拦截）
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8080,
            connector_8080,
            NetNS::new(Some("net_c".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_millis(500),
        )
        .await;

        assert!(result.is_err(), "UDP 连接 8080 应被 ACL 拦截，不能成功");

        let stats = insts[2].get_global_ctx().get_acl_filter().get_stats();
        println!("stats: {}", stats);
    }

    // remove acl, 8080 should succ
    insts[2]
        .get_global_ctx()
        .get_acl_filter()
        .reload_rules(None);

    drop_insts(insts).await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn acl_rule_test_subnet_proxy(
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] enable_quic_proxy: bool,
) {
    use crate::tunnel::{
        common::tests::_tunnel_pingpong_netns_with_timeout,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
        udp::{UdpTunnelConnector, UdpTunnelListener},
    };
    use rand::Rng;

    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst1" {
                let mut flags = cfg.get_flags();
                flags.enable_kcp_proxy = enable_kcp_proxy;
                flags.enable_quic_proxy = enable_quic_proxy;
                cfg.set_flags(flags);
            } else if cfg.get_inst_name() == "inst3" {
                // 添加子网代理配置
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            }
            cfg
        },
        false,
    )
    .await;

    // 等待代理路由出现
    wait_proxy_route_appear(
        &insts[0].get_peer_manager(),
        "10.144.144.3/24",
        insts[2].peer_id(),
        "10.1.2.0/24",
    )
    .await;

    // Test IPv4 connectivity
    wait_for_condition(
        || async { ping_test("net_a", "10.1.2.4", None).await },
        Duration::from_secs(5),
    )
    .await;

    // 构造 ACL 配置 - 针对子网代理流量
    use crate::proto::acl::*;
    let mut acl = Acl::default();
    let mut acl_v1 = AclV1::default();

    let mut chain = Chain {
        name: "test_subnet_proxy_inbound".to_string(),
        chain_type: ChainType::Forward as i32,
        enabled: true,
        ..Default::default()
    };

    // 禁止访问子网代理中的 8080 端口
    let deny_rule = Rule {
        name: "deny_subnet_8080".to_string(),
        priority: 200,
        enabled: true,
        action: Action::Drop as i32,
        protocol: Protocol::Any as i32,
        ports: vec!["8080".to_string()],
        destination_ips: vec!["10.1.2.0/24".to_string()],
        ..Default::default()
    };
    chain.rules.push(deny_rule);

    // 禁止来自 inst1 (10.144.144.1) 访问子网代理中的 8081 端口
    let deny_src_rule = Rule {
        name: "deny_inst1_to_subnet_8081".to_string(),
        priority: 200,
        enabled: true,
        action: Action::Drop as i32,
        protocol: Protocol::Any as i32,
        ports: vec!["8081".to_string()],
        source_ips: vec!["10.144.144.1/32".to_string()],
        destination_ips: vec!["10.1.2.0/24".to_string()],
        ..Default::default()
    };
    chain.rules.push(deny_src_rule);

    // 允许其他流量
    let allow_rule = Rule {
        name: "allow_all".to_string(),
        priority: 100,
        enabled: true,
        action: Action::Allow as i32,
        protocol: Protocol::Any as i32,
        stateful: true,
        ..Default::default()
    };
    chain.rules.push(allow_rule);

    acl_v1.chains.push(chain);
    acl.acl_v1 = Some(acl_v1);

    // 在 inst3 上应用 ACL 规则
    insts[2]
        .get_global_ctx()
        .get_acl_filter()
        .reload_rules(Some(&acl));

    // TCP 测试部分 - 测试子网代理的 ACL 规则
    {
        // 在 net_d (10.1.2.4) 上监听多个端口
        let listener_8080 = TcpTunnelListener::new("tcp://0.0.0.0:8080".parse().unwrap());
        let listener_8081 = TcpTunnelListener::new("tcp://0.0.0.0:8081".parse().unwrap());
        let listener_8082 = TcpTunnelListener::new("tcp://0.0.0.0:8082".parse().unwrap());

        // 从 inst1 (net_a) 连接到子网代理
        let connector_8080 = TcpTunnelConnector::new("tcp://10.1.2.4:8080".parse().unwrap());
        let connector_8081 = TcpTunnelConnector::new("tcp://10.1.2.4:8081".parse().unwrap());
        let connector_8082 = TcpTunnelConnector::new("tcp://10.1.2.4:8082".parse().unwrap());

        let mut buf = vec![0; 32];
        rand::thread_rng().fill(&mut buf[..]);

        // 8082 应该可以连接成功（不被 ACL 拦截）
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8082,
            connector_8082,
            NetNS::new(Some("net_d".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_ok(), "{}", result.unwrap_err());

        // 8080 应该连接失败（被 ACL 拦截 - 禁止访问子网代理的 8080）
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8080,
            connector_8080,
            NetNS::new(Some("net_d".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_millis(500),
        )
        .await;

        assert!(
            result.is_err(),
            "TCP 连接子网代理 8080 应被 ACL 拦截，不能成功"
        );

        // 8081 应该连接失败（被 ACL 拦截 - 禁止 inst1 访问子网代理的 8081）
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8081,
            connector_8081,
            NetNS::new(Some("net_d".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_millis(500),
        )
        .await;

        assert!(
            result.is_err(),
            "TCP 连接子网代理 8081 应被 ACL 拦截，不能成功"
        );

        let stats = insts[2].get_global_ctx().get_acl_filter().get_stats();
        println!("ACL stats after TCP tests: {:?}", stats);
    }

    // UDP 测试部分 - 测试子网代理的 ACL 规则
    {
        let listener_8080 = UdpTunnelListener::new("udp://0.0.0.0:8080".parse().unwrap());
        let listener_8082 = UdpTunnelListener::new("udp://0.0.0.0:8082".parse().unwrap());

        let connector_8080 = UdpTunnelConnector::new("udp://10.1.2.4:8080".parse().unwrap());
        let connector_8082 = UdpTunnelConnector::new("udp://10.1.2.4:8082".parse().unwrap());

        let mut buf = vec![0; 32];
        rand::thread_rng().fill(&mut buf[..]);

        // 8082 应该可以连接成功
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8082,
            connector_8082,
            NetNS::new(Some("net_d".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_secs(5),
        )
        .await;
        assert!(result.is_ok(), "{}", result.unwrap_err());

        // 8080 应该连接失败（被 ACL 拦截）
        let result = _tunnel_pingpong_netns_with_timeout(
            listener_8080,
            connector_8080,
            NetNS::new(Some("net_d".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            Duration::from_millis(500),
        )
        .await;

        let stats = insts[2].get_global_ctx().get_acl_filter().get_stats();
        println!("ACL stats after UDP tests: {}", stats);

        assert!(
            result.is_err(),
            "UDP 连接子网代理 8080 应被 ACL 拦截，不能成功"
        );
    }

    // 测试 ICMP 到子网代理（应该被拒绝，因为 Any 协议被拒绝）
    tokio::spawn(wait_for_condition(
        || async { ping_test("net_a", "10.1.2.4", None).await },
        Duration::from_secs(1),
    ))
    .await
    .unwrap_err();

    // 移除 ACL 规则
    insts[2]
        .get_global_ctx()
        .get_acl_filter()
        .reload_rules(None);

    // 验证移除 ACL 后，ICMP 可以正常工作
    wait_for_condition(
        || async { ping_test("net_a", "10.1.2.4", None).await },
        Duration::from_secs(5),
    )
    .await;

    drop_insts(insts).await;
}

async fn assert_panics_ext<F, Fut>(f: F, expect_panic: bool)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future + Send + 'static,
{
    // Run the async function in a separate task so panics surface as JoinError
    let res = tokio::spawn(async move {
        f().await;
    })
    .await;

    if expect_panic {
        assert!(
            res.is_err() && res.as_ref().unwrap_err().is_panic(),
            "Expected function to panic, but it didn't",
        );
    } else {
        assert!(res.is_ok(), "Expected function not to panic, but it did");
    }
}

async fn wait_route_cost(inst: &Instance, peer_id: u32, cost: i32, timeout: Duration) {
    let peer_manager = inst.get_peer_manager();
    wait_for_condition(
        move || {
            let peer_manager = peer_manager.clone();
            async move {
                peer_manager
                    .list_routes()
                    .await
                    .iter()
                    .any(|route| route.peer_id == peer_id && route.cost == cost)
            }
        },
        timeout,
    )
    .await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn p2p_only_test(
    #[values(true, false)] has_p2p_conn: bool,
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] enable_quic_proxy: bool,
) {
    use crate::peers::tests::wait_route_appear_with_cost;

    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            if cfg.get_inst_name() == "inst1" {
                let mut flags = cfg.get_flags();
                flags.enable_kcp_proxy = enable_kcp_proxy;
                flags.enable_quic_proxy = enable_quic_proxy;
                flags.disable_p2p = true;
                flags.p2p_only = true;
                cfg.set_flags(flags);
            } else if cfg.get_inst_name() == "inst3" {
                // 添加子网代理配置
                cfg.add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
                    .unwrap();
            }
            cfg
        },
        false,
    )
    .await;

    if has_p2p_conn {
        insts[2]
            .get_conn_manager()
            .add_connector(RingTunnelConnector::new(
                format!("ring://{}", insts[0].id()).parse().unwrap(),
            ));
        wait_route_appear_with_cost(
            insts[2].get_peer_manager(),
            insts[0].get_peer_manager().my_peer_id(),
            Some(1),
        )
        .await
        .unwrap();
    }

    let target_ip = "10.1.2.4";

    for target_ip in ["10.144.144.3", target_ip] {
        assert_panics_ext(
            || async {
                subnet_proxy_test_icmp(target_ip, Duration::from_millis(100)).await;
            },
            !has_p2p_conn,
        )
        .await;

        let listen_ip = if target_ip == "10.144.144.3" {
            "0.0.0.0"
        } else {
            "10.1.2.4"
        };
        assert_panics_ext(
            || async {
                subnet_proxy_test_tcp(listen_ip, target_ip, Duration::from_millis(100)).await;
            },
            !has_p2p_conn,
        )
        .await;

        assert_panics_ext(
            || async {
                subnet_proxy_test_udp(listen_ip, target_ip, Duration::from_millis(100)).await;
            },
            !has_p2p_conn,
        )
        .await;
    }
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn acl_group_base_test(
    #[values("tcp", "udp")] protocol: &str,
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] enable_quic_proxy: bool,
) {
    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        common::tests::_tunnel_pingpong_netns_with_timeout,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
        udp::{UdpTunnelConnector, UdpTunnelListener},
    };
    use rand::Rng;

    // 构造 ACL 配置，包含组信息
    use crate::proto::acl::*;

    // 设置组信息
    let group_declares = vec![
        GroupIdentity {
            group_name: "admin".to_string(),
            group_secret: "admin-secret".to_string(),
        },
        GroupIdentity {
            group_name: "user".to_string(),
            group_secret: "user-secret".to_string(),
        },
    ];

    let mut chain = Chain {
        name: "group_acl_test".to_string(),
        chain_type: ChainType::Inbound as i32,
        enabled: true,
        default_action: Action::Drop as i32,
        ..Default::default()
    };

    // 规则1: 允许admin组访问所有端口
    let admin_allow_rule = Rule {
        name: "allow_admin_all".to_string(),
        priority: 300,
        enabled: true,
        action: Action::Allow as i32,
        protocol: Protocol::Any as i32,
        source_groups: vec!["admin".to_string()],
        stateful: true,
        ..Default::default()
    };
    chain.rules.push(admin_allow_rule);

    // 规则2: 允许user组访问8080端口
    let user_8080_rule = Rule {
        name: "allow_user_8080".to_string(),
        priority: 200,
        enabled: true,
        action: Action::Allow as i32,
        protocol: Protocol::Any as i32,
        source_groups: vec!["user".to_string()],
        ports: vec!["8080".to_string()],
        stateful: true,
        ..Default::default()
    };
    chain.rules.push(user_8080_rule);

    let acl_admin = Acl {
        acl_v1: Some(AclV1 {
            group: Some(GroupInfo {
                declares: group_declares.clone(),
                members: vec!["admin".to_string()],
            }),
            ..AclV1::default()
        }),
    };

    let acl_user = Acl {
        acl_v1: Some(AclV1 {
            group: Some(GroupInfo {
                declares: group_declares.clone(),
                members: vec!["user".to_string()],
            }),
            ..AclV1::default()
        }),
    };

    let acl_target = Acl {
        acl_v1: Some(AclV1 {
            chains: vec![chain.clone()],
            group: Some(GroupInfo {
                declares: group_declares.clone(),
                members: vec![],
            }),
        }),
    };

    let insts = init_three_node_ex(
        protocol,
        move |cfg| {
            match cfg.get_inst_name().as_str() {
                "inst1" => {
                    cfg.set_acl(Some(acl_admin.clone()));
                }
                "inst2" => {
                    cfg.set_acl(Some(acl_user.clone()));
                }
                "inst3" => {
                    cfg.set_acl(Some(acl_target.clone()));
                }
                _ => {}
            }

            let mut flags = cfg.get_flags();
            flags.enable_kcp_proxy = enable_kcp_proxy;
            flags.enable_quic_proxy = enable_quic_proxy;
            cfg.set_flags(flags);

            cfg
        },
        false,
    )
    .await;

    println!("Testing group-based ACL rules...");

    let make_listener = |port: u16| -> Box<dyn TunnelListener + Send + Sync + 'static> {
        match protocol {
            "tcp" => Box::new(TcpTunnelListener::new(
                format!("tcp://0.0.0.0:{}", port).parse().unwrap(),
            )),
            "udp" => Box::new(UdpTunnelListener::new(
                format!("udp://0.0.0.0:{}", port).parse().unwrap(),
            )),
            _ => panic!("unsupported protocol: {}", protocol),
        }
    };

    let make_connector = |port: u16| -> Box<dyn TunnelConnector + Send + Sync + 'static> {
        match protocol {
            "tcp" => Box::new(TcpTunnelConnector::new(
                format!("tcp://10.144.144.3:{}", port).parse().unwrap(),
            )),
            "udp" => Box::new(UdpTunnelConnector::new(
                format!("udp://10.144.144.3:{}", port).parse().unwrap(),
            )),
            _ => panic!("unsupported protocol: {}", protocol),
        }
    };

    // 构造测试数据
    let mut buf = vec![0; 32];
    rand::thread_rng().fill(&mut buf[..]);

    // 测试1: inst1 (admin组) 访问8080 - 应该成功
    let result = _tunnel_pingpong_netns_with_timeout(
        make_listener(8080),
        make_connector(8080),
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf.clone(),
        std::time::Duration::from_millis(30000),
    )
    .await;
    assert!(
        result.is_ok(),
        "Admin group access to port 8080 should be allowed (protocol={})",
        protocol
    );
    println!(
        "✓ Admin group access to port 8080 succeeded ({})\n",
        protocol
    );

    // 测试2: inst1 (admin组) 访问8081 - 应该成功
    let result = _tunnel_pingpong_netns_with_timeout(
        make_listener(8081),
        make_connector(8081),
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf.clone(),
        std::time::Duration::from_millis(30000),
    )
    .await;
    assert!(
        result.is_ok(),
        "Admin group access to port 8081 should be allowed (protocol={})",
        protocol
    );
    println!(
        "✓ Admin group access to port 8081 succeeded ({})\n",
        protocol
    );

    // 测试3: inst2 (user组) 访问8080 - 应该成功
    let result = _tunnel_pingpong_netns_with_timeout(
        make_listener(8080),
        make_connector(8080),
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_b".into())),
        buf.clone(),
        std::time::Duration::from_millis(30000),
    )
    .await;
    assert!(
        result.is_ok(),
        "User group access to port 8080 should be allowed (protocol={})",
        protocol
    );
    println!(
        "✓ User group access to port 8080 succeeded ({})\n",
        protocol
    );

    // 测试4: inst2 (user组) 访问8081 - 应该失败
    let result = _tunnel_pingpong_netns_with_timeout(
        make_listener(8081),
        make_connector(8081),
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_b".into())),
        buf.clone(),
        std::time::Duration::from_millis(200),
    )
    .await;
    assert!(
        result.is_err(),
        "User group access to port 8081 should be blocked (protocol={})",
        protocol
    );
    println!(
        "✓ User group access to port 8081 blocked as expected ({})\n",
        protocol
    );

    let stats = insts[2].get_global_ctx().get_acl_filter().get_stats();
    println!("ACL stats after group {} tests: {:?}", protocol, stats);

    println!("✓ All group-based ACL tests completed successfully");

    drop_insts(insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn lazy_p2p_builds_direct_connection_on_demand() {
    let insts = init_lazy_p2p_three_node_ex("udp", |cfg| {
        if cfg.get_inst_name() == "inst1" {
            let mut flags = cfg.get_flags();
            flags.lazy_p2p = true;
            cfg.set_flags(flags);
        }
        cfg
    })
    .await;

    let inst3_peer_id = insts[2].peer_id();
    assert!(
        !insts[0]
            .get_peer_manager()
            .get_peer_map()
            .has_peer(inst3_peer_id),
        "inst1 should not proactively connect to inst3 when lazy_p2p is enabled"
    );
    wait_route_cost(&insts[0], inst3_peer_id, 2, Duration::from_secs(5)).await;

    assert!(
        ping_test("net_a", "10.144.144.3", None).await,
        "initial relay traffic should still succeed"
    );

    wait_for_condition(
        || async {
            insts[0]
                .get_peer_manager()
                .get_peer_map()
                .has_peer(inst3_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;
    wait_route_cost(&insts[0], inst3_peer_id, 1, Duration::from_secs(10)).await;

    drop_insts(insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn need_p2p_overrides_lazy_p2p() {
    let insts = init_lazy_p2p_three_node_ex("udp", |cfg| {
        let mut flags = cfg.get_flags();
        if cfg.get_inst_name() == "inst1" {
            flags.lazy_p2p = true;
        }
        if cfg.get_inst_name() == "inst3" {
            flags.need_p2p = true;
        }
        cfg.set_flags(flags);
        cfg
    })
    .await;

    let inst3_peer_id = insts[2].peer_id();
    wait_route_cost(&insts[0], inst3_peer_id, 2, Duration::from_secs(5)).await;
    wait_for_condition(
        || async {
            insts[0]
                .get_peer_manager()
                .get_peer_map()
                .has_peer(inst3_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;
    wait_route_cost(&insts[0], inst3_peer_id, 1, Duration::from_secs(10)).await;

    drop_insts(insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn disable_p2p_still_connects_to_need_p2p_peers() {
    let insts = init_lazy_p2p_three_node_ex("udp", |cfg| {
        let mut flags = cfg.get_flags();
        if cfg.get_inst_name() == "inst1" {
            flags.disable_p2p = true;
        }
        if cfg.get_inst_name() == "inst3" {
            flags.need_p2p = true;
        }
        cfg.set_flags(flags);
        cfg
    })
    .await;

    let inst3_peer_id = insts[2].peer_id();
    wait_route_cost(&insts[0], inst3_peer_id, 2, Duration::from_secs(5)).await;
    wait_for_condition(
        || async {
            insts[0]
                .get_peer_manager()
                .get_peer_map()
                .has_peer(inst3_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;
    wait_route_cost(&insts[0], inst3_peer_id, 1, Duration::from_secs(10)).await;

    drop_insts(insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn ordinary_nodes_do_not_proactively_connect_to_disable_p2p_peers() {
    let insts = init_lazy_p2p_three_node_ex("udp", |cfg| {
        if cfg.get_inst_name() == "inst3" {
            let mut flags = cfg.get_flags();
            flags.disable_p2p = true;
            cfg.set_flags(flags);
        }
        cfg
    })
    .await;

    let inst3_peer_id = insts[2].peer_id();
    wait_route_cost(&insts[0], inst3_peer_id, 2, Duration::from_secs(5)).await;
    assert!(
        ping_test("net_a", "10.144.144.3", None).await,
        "relay traffic to disable-p2p peers should still succeed"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        !insts[0]
            .get_peer_manager()
            .get_peer_map()
            .has_peer(inst3_peer_id),
        "ordinary nodes should not proactively establish p2p with disable-p2p peers"
    );
    wait_route_cost(&insts[0], inst3_peer_id, 2, Duration::from_secs(3)).await;

    drop_insts(insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn lazy_p2p_warms_up_before_p2p_only_send() {
    let insts = init_lazy_p2p_three_node_ex("udp", |cfg| {
        if cfg.get_inst_name() == "inst1" {
            let mut flags = cfg.get_flags();
            flags.lazy_p2p = true;
            flags.p2p_only = true;
            cfg.set_flags(flags);
        }
        cfg
    })
    .await;

    let inst3_peer_id = insts[2].peer_id();
    wait_route_cost(&insts[0], inst3_peer_id, 2, Duration::from_secs(5)).await;
    assert!(
        !ping_test("net_a", "10.144.144.3", None).await,
        "the first send should still fail under p2p_only before direct connectivity exists"
    );

    wait_for_condition(
        || async {
            insts[0]
                .get_peer_manager()
                .get_peer_map()
                .has_peer(inst3_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;
    wait_route_cost(&insts[0], inst3_peer_id, 1, Duration::from_secs(10)).await;

    wait_for_condition(
        || async { ping_test("net_a", "10.144.144.3", None).await },
        Duration::from_secs(6),
    )
    .await;

    drop_insts(insts).await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn acl_group_self_test(
    #[values("tcp", "udp")] protocol: &str,
    #[values(true, false)] enable_kcp_proxy: bool,
    #[values(true, false)] enable_quic_proxy: bool,
) {
    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        common::tests::_tunnel_pingpong_netns_with_timeout,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
        udp::{UdpTunnelConnector, UdpTunnelListener},
    };
    use rand::Rng;

    // 构造 ACL 配置，包含组信息
    use crate::proto::acl::*;

    // 设置组信息
    let group_declares = vec![GroupIdentity {
        group_name: "admin".to_string(),
        group_secret: "admin-secret".to_string(),
    }];

    let mut chain = Chain {
        name: "group_acl_test".to_string(),
        chain_type: ChainType::Inbound as i32,
        enabled: true,
        default_action: Action::Drop as i32,
        ..Default::default()
    };

    // 规则1: 允许admin组访问admin组
    let admin_allow_rule = Rule {
        name: "allow_admin_admin".to_string(),
        priority: 300,
        enabled: true,
        action: Action::Allow as i32,
        protocol: Protocol::Any as i32,
        source_groups: vec!["admin".to_string()],
        destination_groups: vec!["admin".to_string()],
        stateful: true,
        ..Default::default()
    };
    chain.rules.push(admin_allow_rule);

    let acl_admin = Acl {
        acl_v1: Some(AclV1 {
            chains: vec![chain.clone()],
            group: Some(GroupInfo {
                declares: group_declares.clone(),
                members: vec!["admin".to_string()],
            }),
        }),
    };

    let acl_common = Acl {
        acl_v1: Some(AclV1 {
            chains: vec![chain.clone()],
            group: Some(GroupInfo {
                declares: group_declares.clone(),
                members: vec![],
            }),
        }),
    };

    let insts = init_three_node_ex(
        protocol,
        move |cfg| {
            match cfg.get_inst_name().as_str() {
                "inst1" => {
                    cfg.set_acl(Some(acl_admin.clone()));
                }
                "inst2" => {
                    cfg.set_acl(Some(acl_common.clone()));
                }
                "inst3" => {
                    cfg.set_acl(Some(acl_admin.clone()));
                }
                _ => {}
            }

            let mut flags = cfg.get_flags();
            flags.enable_kcp_proxy = enable_kcp_proxy;
            flags.enable_quic_proxy = enable_quic_proxy;
            cfg.set_flags(flags);

            cfg
        },
        false,
    )
    .await;

    println!("Testing group-based ACL rules...");

    let make_listener = |port: u16| -> Box<dyn TunnelListener + Send + Sync + 'static> {
        match protocol {
            "tcp" => Box::new(TcpTunnelListener::new(
                format!("tcp://0.0.0.0:{}", port).parse().unwrap(),
            )),
            "udp" => Box::new(UdpTunnelListener::new(
                format!("udp://0.0.0.0:{}", port).parse().unwrap(),
            )),
            _ => panic!("unsupported protocol: {}", protocol),
        }
    };

    let make_connector = |port: u16| -> Box<dyn TunnelConnector + Send + Sync + 'static> {
        match protocol {
            "tcp" => Box::new(TcpTunnelConnector::new(
                format!("tcp://10.144.144.3:{}", port).parse().unwrap(),
            )),
            "udp" => Box::new(UdpTunnelConnector::new(
                format!("udp://10.144.144.3:{}", port).parse().unwrap(),
            )),
            _ => panic!("unsupported protocol: {}", protocol),
        }
    };

    // 构造测试数据
    let mut buf = vec![0; 32];
    rand::thread_rng().fill(&mut buf[..]);

    // 测试1: inst1 (admin组) 访问inst3 (admin组) - 应该成功
    let result = _tunnel_pingpong_netns_with_timeout(
        make_listener(8080),
        make_connector(8080),
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf.clone(),
        std::time::Duration::from_millis(30000),
    )
    .await;
    assert!(
        result.is_ok(),
        "Admin group access to Admin group should be allowed (protocol={})",
        protocol
    );
    println!(
        "✓ Admin group access to Admin group succeeded ({})\n",
        protocol
    );

    // 测试2: inst2 (无组) 访问inst3 (admin组) - 应该失败
    let result = _tunnel_pingpong_netns_with_timeout(
        make_listener(8080),
        make_connector(8080),
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_b".into())),
        buf.clone(),
        std::time::Duration::from_millis(200),
    )
    .await;
    assert!(
        result.is_err(),
        "None group access to inst3 (admin group) should be blocked (protocol={})",
        protocol
    );
    println!(
        "✓ None group access to inst3 (admin group) blocked as expected ({})\n",
        protocol
    );

    let stats = insts[2].get_global_ctx().get_acl_filter().get_stats();
    println!("ACL stats after group {} tests: {:?}", protocol, stats);

    println!("✓ All group-based ACL tests completed successfully");

    drop_insts(insts).await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn whitelist_test(
    #[values("tcp", "udp")] protocol: &str,
    #[values(true, false)] test_outbound_allow_list: bool,
) {
    let port = 44553;
    let acl_configured_inst = if test_outbound_allow_list {
        "inst1"
    } else {
        "inst3"
    };
    let insts = init_three_node_ex(
        protocol,
        move |cfg| {
            let port = if test_outbound_allow_list { 0 } else { port };
            if cfg.get_inst_name() == acl_configured_inst {
                if protocol == "tcp" {
                    cfg.set_tcp_whitelist(vec![format!("{}", port)]);
                } else if protocol == "udp" {
                    cfg.set_udp_whitelist(vec![format!("{}", port)]);
                }
            }
            cfg
        },
        false,
    )
    .await;

    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        common::tests::_tunnel_pingpong_netns_with_timeout,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
        udp::{UdpTunnelConnector, UdpTunnelListener},
    };
    use rand::Rng;

    let make_listener =
        |protocol: &str, port: u16| -> Box<dyn TunnelListener + Send + Sync + 'static> {
            match protocol {
                "tcp" => Box::new(TcpTunnelListener::new(
                    format!("tcp://0.0.0.0:{}", port).parse().unwrap(),
                )),
                "udp" => Box::new(UdpTunnelListener::new(
                    format!("udp://0.0.0.0:{}", port).parse().unwrap(),
                )),
                _ => panic!("unsupported protocol: {}", protocol),
            }
        };

    let make_connector =
        |protocol: &str, port: u16| -> Box<dyn TunnelConnector + Send + Sync + 'static> {
            match protocol {
                "tcp" => Box::new(TcpTunnelConnector::new(
                    format!("tcp://10.144.144.3:{}", port).parse().unwrap(),
                )),
                "udp" => Box::new(UdpTunnelConnector::new(
                    format!("udp://10.144.144.3:{}", port).parse().unwrap(),
                )),
                _ => panic!("unsupported protocol: {}", protocol),
            }
        };

    let mut buf = vec![0; 32];
    rand::thread_rng().fill(&mut buf[..]);

    for p in &["tcp", "udp"] {
        _tunnel_pingpong_netns_with_timeout(
            make_listener(p, port),
            make_connector(p, port),
            NetNS::new(Some("net_c".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap_or_else(|_| panic!("{} should be allowed", p));
    }

    if test_outbound_allow_list {
        return;
    }

    // test other port
    let other_port = port + 1;
    for p in ["tcp", "udp"] {
        let r = _tunnel_pingpong_netns_with_timeout(
            make_listener(p, other_port),
            make_connector(p, other_port),
            NetNS::new(Some("net_c".into())),
            NetNS::new(Some("net_a".into())),
            buf.clone(),
            std::time::Duration::from_millis(100),
        )
        .await;

        if p != protocol {
            assert!(r.is_ok(), "{} should be allowed", p);
        } else {
            assert!(r.is_err(), "{} should be blocked", p);
        }
    }

    drop_insts(insts).await;
}

#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn config_patch_test() {
    use crate::proto::{
        api::config::{
            ConfigPatchAction, InstanceConfigPatch, PortForwardPatch, ProxyNetworkPatch,
        },
        common::{PortForwardConfigPb, SocketType},
    };
    use crate::tunnel::common::tests::_tunnel_pingpong_netns_with_timeout;

    let insts = init_three_node("udp").await;

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

    // 测试1： 修改hostname、ip、子网代理
    let patch = InstanceConfigPatch {
        hostname: Some("new_inst1".to_string()),
        ipv4: Some("10.144.144.22/24".parse().unwrap()),
        proxy_networks: vec![ProxyNetworkPatch {
            action: ConfigPatchAction::Add as i32,
            cidr: Some("10.144.145.0/24".parse().unwrap()),
            mapped_cidr: None,
        }],
        ..Default::default()
    };
    insts[1]
        .get_config_patcher()
        .apply_patch(patch)
        .await
        .unwrap();
    assert_eq!(insts[1].get_global_ctx().get_hostname(), "new_inst1");
    assert_eq!(
        insts[1].get_global_ctx().get_ipv4().unwrap(),
        "10.144.144.22/24".parse().unwrap()
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    check_route_ex(
        insts[0].get_peer_manager().list_routes().await,
        insts[1].peer_id(),
        |r| {
            assert_eq!(r.hostname, "new_inst1");
            assert_eq!(r.ipv4_addr, Some("10.144.144.22/24".parse().unwrap()));
            assert_eq!(r.proxy_cidrs[0], "10.144.145.0/24");
            true
        },
    );

    // 测试2: 端口转发
    let patch = InstanceConfigPatch {
        port_forwards: vec![PortForwardPatch {
            action: ConfigPatchAction::Add as i32,
            cfg: Some(PortForwardConfigPb {
                bind_addr: Some("0.0.0.0:23458".parse::<SocketAddr>().unwrap().into()),
                dst_addr: Some("10.144.144.3:23457".parse::<SocketAddr>().unwrap().into()),
                socket_type: SocketType::Tcp as i32,
            }),
        }],
        ..Default::default()
    };
    insts[0]
        .get_config_patcher()
        .apply_patch(patch)
        .await
        .unwrap();

    let mut buf = vec![0; 32];
    rand::thread_rng().fill(&mut buf[..]);
    let tcp_listener = TcpTunnelListener::new("tcp://0.0.0.0:23457".parse().unwrap());
    let tcp_connector = TcpTunnelConnector::new("tcp://127.0.0.1:23458".parse().unwrap());
    let result = _tunnel_pingpong_netns_with_timeout(
        tcp_listener,
        tcp_connector,
        NetNS::new(Some("net_c".into())),
        NetNS::new(Some("net_a".into())),
        buf.clone(),
        std::time::Duration::from_millis(30000),
    )
    .await;
    assert!(result.is_ok(), "Port forward pingpong should succeed");

    drop_insts(insts).await;
}

/// Generate SecureModeConfig with specified x25519 private key
pub fn generate_secure_mode_config_with_key(
    private_key: &x25519_dalek::StaticSecret,
) -> SecureModeConfig {
    use base64::{Engine, prelude::BASE64_STANDARD};
    use x25519_dalek::PublicKey;

    let public = PublicKey::from(private_key);

    SecureModeConfig {
        enabled: true,
        local_private_key: Some(BASE64_STANDARD.encode(private_key.as_bytes())),
        local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
    }
}

/// Generate SecureModeConfig with random x25519 keypair
pub fn generate_secure_mode_config() -> SecureModeConfig {
    let private = StaticSecret::random_from_rng(OsRng);
    generate_secure_mode_config_with_key(&private)
}

/// Test relay peer end-to-end encryption with TCP
#[rstest::rstest]
#[tokio::test]
#[serial_test::serial]
pub async fn relay_peer_e2e_encryption(#[values("tcp", "udp")] proto: &str) {
    use crate::peers::route_trait::NextHopPolicy;

    let insts = init_three_node_ex(
        proto,
        |cfg| {
            cfg.set_secure_mode(Some(generate_secure_mode_config()));
            cfg
        },
        false,
    )
    .await;

    let inst1_peer_id = insts[0].peer_id();
    let inst2_peer_id = insts[1].peer_id();
    let inst3_peer_id = insts[2].peer_id();

    println!(
        "Test topology: inst1({}) <-> inst2({}) <-> inst3({})",
        inst1_peer_id, inst2_peer_id, inst3_peer_id
    );

    // Check secure mode is enabled
    let secure_mode_1 = insts[0].get_global_ctx().config.get_secure_mode();
    let secure_mode_2 = insts[1].get_global_ctx().config.get_secure_mode();
    let secure_mode_3 = insts[2].get_global_ctx().config.get_secure_mode();
    println!(
        "Secure mode enabled: inst1={}, inst2={}, inst3={}",
        secure_mode_1.is_some(),
        secure_mode_2.is_some(),
        secure_mode_3.is_some()
    );

    // Wait for routes to be established
    wait_for_condition(
        || async {
            let routes = insts[0].get_peer_manager().list_routes().await;
            routes.len() == 2
        },
        Duration::from_secs(10),
    )
    .await;

    // Verify inst1 sees inst3 via inst2 (non-direct path)
    let next_hop_to_inst3 = insts[0]
        .get_peer_manager()
        .get_peer_map()
        .get_gateway_peer_id(inst3_peer_id, NextHopPolicy::LeastHop)
        .await;
    println!("Next hop from inst1 to inst3: {:?}", next_hop_to_inst3);
    assert_eq!(
        next_hop_to_inst3,
        Some(inst2_peer_id),
        "inst1 should reach inst3 via inst2 (relay)"
    );

    // Verify inst1 has no direct connection to inst3
    assert!(
        !insts[0]
            .get_peer_manager()
            .get_peer_map()
            .has_peer(inst3_peer_id),
        "inst1 should NOT have direct connection to inst3"
    );

    // Check if noise_static_pubkey is available for relay handshake
    let route_info_inst3 = insts[0]
        .get_peer_manager()
        .get_peer_map()
        .get_route_peer_info(inst3_peer_id)
        .await;
    println!(
        "Route info for inst3 on inst1: noise_static_pubkey len = {:?}",
        route_info_inst3
            .as_ref()
            .map(|i| i.noise_static_pubkey.len())
    );

    // Wait until relay route info includes inst3 static pubkey for IK handshake.
    wait_for_condition(
        || async {
            insts[0]
                .get_peer_manager()
                .get_peer_map()
                .get_route_peer_info(inst3_peer_id)
                .await
                .is_some_and(|info| !info.noise_static_pubkey.is_empty())
        },
        Duration::from_secs(10),
    )
    .await;

    // Test basic connectivity through relay
    println!("Starting ping test from net_a to 10.144.144.3...");

    assert!(
        ping_test("net_a", "10.144.144.3", None).await,
        "Ping from net_a to inst3 should succeed"
    );

    // Verify relay sessions are established
    let relay_map_1 = insts[0].get_peer_manager().get_relay_peer_map();
    let relay_map_3 = insts[2].get_peer_manager().get_relay_peer_map();

    println!(
        "Relay states after ping: inst1->inst3: {}, inst3->inst1: {}",
        relay_map_1.has_state(inst3_peer_id),
        relay_map_3.has_state(inst1_peer_id)
    );

    // Test bidirectional connectivity
    assert!(
        ping_test("net_a", "10.144.144.3", None).await,
        "Ping from net_a to inst3 should work"
    );
    assert!(
        ping_test("net_c", "10.144.144.1", None).await,
        "Ping from net_c to inst1 should work"
    );

    println!("Test completed successfully!");
    drop_insts(insts).await;
}

#[tokio::test]
#[serial_test::serial]
pub async fn relay_peer_e2e_encryption_udp() {
    let insts = init_three_node_ex(
        "udp",
        |cfg| {
            cfg.set_secure_mode(Some(generate_secure_mode_config()));
            cfg
        },
        false,
    )
    .await;

    let inst1_id = insts[0].get_global_ctx().get_id().to_string();
    let inst3_id = insts[2].get_global_ctx().get_id().to_string();
    let network_name = insts[0].get_global_ctx().get_network_name();
    let total_labels =
        LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone()));

    wait_for_condition(
        || async {
            let routes = insts[0].get_peer_manager().list_routes().await;
            routes.len() == 2
        },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || async { ping_test("net_a", "10.144.144.3", None).await },
        Duration::from_secs(6),
    )
    .await;

    let tx_labels = LabelSet::new()
        .with_label_type(LabelType::NetworkName(network_name.clone()))
        .with_label_type(LabelType::ToInstanceId(inst3_id.clone()));
    let rx_labels = LabelSet::new()
        .with_label_type(LabelType::NetworkName(network_name.clone()))
        .with_label_type(LabelType::FromInstanceId(inst1_id.clone()));

    wait_for_condition(
        || async {
            insts[0]
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficBytesTx, &tx_labels)
                .is_none()
                && insts[0]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficPacketsTx, &tx_labels)
                    .is_none()
                && insts[0]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficBytesTx, &total_labels)
                    .is_some_and(|metric| metric.value > 0)
                && insts[0]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficPacketsTx, &total_labels)
                    .is_some_and(|metric| metric.value > 0)
                && insts[0]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficBytesTxByInstance, &tx_labels)
                    .is_some_and(|metric| metric.value > 0)
                && insts[0]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficPacketsTxByInstance, &tx_labels)
                    .is_some_and(|metric| metric.value > 0)
        },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || async {
            insts[2]
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficBytesRx, &rx_labels)
                .is_none()
                && insts[2]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficPacketsRx, &rx_labels)
                    .is_none()
                && insts[2]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficBytesRx, &total_labels)
                    .is_some_and(|metric| metric.value > 0)
                && insts[2]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficPacketsRx, &total_labels)
                    .is_some_and(|metric| metric.value > 0)
                && insts[2]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficBytesRxByInstance, &rx_labels)
                    .is_some_and(|metric| metric.value > 0)
                && insts[2]
                    .get_global_ctx()
                    .stats_manager()
                    .get_metric(MetricName::TrafficPacketsRxByInstance, &rx_labels)
                    .is_some_and(|metric| metric.value > 0)
        },
        Duration::from_secs(10),
    )
    .await;

    drop_insts(insts).await;
}

/// Test Relay Peer session cleanup on relay failure - TCP
#[tokio::test]
#[serial_test::serial]
pub async fn relay_peer_session_cleanup() {
    use crate::peers::route_trait::NextHopPolicy;

    let mut insts = init_three_node_ex(
        "tcp",
        |cfg| {
            cfg.set_secure_mode(Some(generate_secure_mode_config()));
            cfg
        },
        false,
    )
    .await;

    let inst2_peer_id = insts[1].peer_id();
    let inst3_peer_id = insts[2].peer_id();
    let relay_map_1 = insts[0].get_peer_manager().get_relay_peer_map();

    wait_for_condition(
        || async { ping_test("net_a", "10.144.144.3", None).await },
        Duration::from_secs(6),
    )
    .await;

    wait_for_condition(
        || async { relay_map_1.has_state(inst3_peer_id) && relay_map_1.has_session(inst3_peer_id) },
        Duration::from_secs(3),
    )
    .await;

    let next_hop = insts[0]
        .get_peer_manager()
        .get_peer_map()
        .get_gateway_peer_id(inst3_peer_id, NextHopPolicy::LeastHop)
        .await;
    assert_eq!(next_hop, Some(inst2_peer_id));

    let mut inst2 = insts.remove(1);
    inst2.clear_resources().await;
    drop(inst2);

    wait_for_condition(
        || async {
            let routes = insts[0].get_peer_manager().list_routes().await;
            !routes.iter().any(|r| r.peer_id == inst3_peer_id)
        },
        Duration::from_secs(6),
    )
    .await;

    relay_map_1.evict_idle_sessions(Duration::from_millis(0));
    assert!(!relay_map_1.has_state(inst3_peer_id));

    insts[0]
        .get_peer_manager()
        .get_peer_session_store()
        .evict_unused_sessions();

    wait_for_condition(
        || async { !relay_map_1.has_session(inst3_peer_id) },
        Duration::from_secs(1),
    )
    .await;

    drop_insts(insts).await;
}
