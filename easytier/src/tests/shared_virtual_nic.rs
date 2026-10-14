use std::{net::Ipv4Addr, process::Command, sync::Arc, time::Duration};

use easytier_core::{config::PeerId, process_runtime::CoreProcessRuntime};

use super::{
    InstanceTestExt as _, create_netns, del_netns, drop_insts, network::TestNetwork, ping_test,
};
use crate::{
    common::{
        config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
        netns::{NetNS, ROOT_NETNS_NAME},
    },
    instance::{
        shared_virtual_nic::{ArcSharedVirtualNicRegistry, SharedIpv4Route},
        test_instance::TestInstance as Instance,
    },
    tunnel::common::tests::wait_for_condition,
};

const PROXY_CIDR: &str = "10.1.2.0/24";
const WAIT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct SharedTestRuntime {
    process: Arc<CoreProcessRuntime>,
    registry: ArcSharedVirtualNicRegistry,
}

impl SharedTestRuntime {
    fn new() -> Self {
        Self {
            process: CoreProcessRuntime::new(),
            registry: Instance::new_shared_virtual_nic_registry(),
        }
    }

    fn instance(&self, config: TomlConfigLoader) -> Instance {
        Instance::new_with_process_runtime_and_shared_virtual_nic_registry(
            config,
            self.process.clone(),
            self.registry.clone(),
        )
    }
}

fn test_config(
    instance_name: &str,
    network_name: &str,
    network_secret: &str,
    netns: Option<&str>,
    dev_name: Option<&str>,
    ipv4: &str,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(instance_name.to_owned());
    config.set_network_identity(NetworkIdentity::new(
        network_name.to_owned(),
        network_secret.to_owned(),
    ));
    config.set_netns(netns.map(str::to_owned));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(None);
    config.set_dhcp(false);
    config.set_listeners(vec![]);
    config.set_socks5_portal(None);

    let mut flags = config.get_flags();
    flags.dev_name = dev_name.unwrap_or_default().to_owned();
    flags.enable_ipv6 = false;
    config.set_flags(flags);
    config
}

fn test_dev_name() -> String {
    format!("st{:08x}", rand::random::<u32>())
}

fn short_name(prefix: &str) -> String {
    format!("{prefix}{:04x}", rand::random::<u16>())
}

struct TestNetnsGuard {
    name: String,
}

impl TestNetnsGuard {
    fn new(name: String, ipv4: &str, ipv6: &str) -> Self {
        let guard = Self { name };
        del_netns(&guard.name);
        create_netns(&guard.name, ipv4, ipv6);
        guard
    }
}

impl Drop for TestNetnsGuard {
    fn drop(&mut self) {
        del_netns(&self.name);
    }
}

struct ProxyLab {
    network: TestNetwork,
}

impl ProxyLab {
    fn new() -> Self {
        let mut network = TestNetwork::new();
        network.create_namespace("source", "10.1.1.1/24", "fd11::1/64");
        network.create_namespace("owner", "10.1.2.3/24", "fd12::3/64");
        network.create_namespace("target", "10.1.2.4/24", "fd12::4/64");
        network.create_bridge("bridge");
        network.add_to_bridge("bridge", "owner");
        network.add_to_bridge("bridge", "target");
        Self { network }
    }
}

async fn wait_tun_ready(instance: &Instance, expected: &str) {
    wait_for_condition(
        || async { instance.get_global_ctx().get_tun_device_name().as_deref() == Some(expected) },
        WAIT,
    )
    .await;
}

fn proxy_route_exists(
    routes: &[easytier_proto::core_peer::peer::Route],
    peer_id: PeerId,
    proxy_cidr: &str,
) -> bool {
    routes
        .iter()
        .any(|route| route.peer_id == peer_id && route.proxy_cidrs.iter().any(|c| c == proxy_cidr))
}

async fn wait_proxy_route(instance: &Instance, peer_id: PeerId, proxy_cidr: &str) {
    wait_for_condition(
        || async {
            proxy_route_exists(
                &instance.get_core_instance().route_snapshots().await,
                peer_id,
                proxy_cidr,
            )
        },
        WAIT,
    )
    .await;
}

async fn wait_proxy_route_absent(instance: &Instance, peer_id: PeerId, proxy_cidr: &str) {
    wait_for_condition(
        || async {
            !proxy_route_exists(
                &instance.get_core_instance().route_snapshots().await,
                peer_id,
                proxy_cidr,
            )
        },
        WAIT,
    )
    .await;
}

fn ipv4_route_exists_in_ns(ns: &str, needle: &str) -> bool {
    let _root = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let output = Command::new("ip")
        .args(["netns", "exec", ns, "ip", "route", "show"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "failed to list IPv4 routes in {ns}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.contains(needle))
}

fn tun_ifindex(ns: &str, dev_name: &str) -> Option<u64> {
    let _root = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let mut command = Command::new("ip");
    if ns != ROOT_NETNS_NAME {
        command.args(["-n", ns]);
    }
    let output = command
        .args(["-j", "link", "show", "dev", dev_name])
        .output()
        .unwrap();
    if !output.status.success() {
        return None;
    }
    let links: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    links[0]["ifindex"].as_u64()
}

#[cfg(feature = "proxy-cidr-monitor")]
async fn patch_proxy_cidr(
    instance: &Instance,
    action: crate::proto::api::config::ConfigPatchAction,
) {
    use crate::proto::api::config::{InstanceConfigPatch, ProxyNetworkPatch};

    instance
        .get_config_patcher()
        .apply_patch(InstanceConfigPatch {
            proxy_networks: vec![ProxyNetworkPatch {
                action: action as i32,
                cidr: Some(PROXY_CIDR.parse().unwrap()),
                mapped_cidr: None,
            }],
            ..Default::default()
        })
        .await
        .unwrap();
}

async fn shared_route_owner_count(
    registry: &ArcSharedVirtualNicRegistry,
    dev_name: &str,
    route: &SharedIpv4Route,
) -> usize {
    let nic = {
        let registry = registry.lock().await;
        registry.get_by_dev_name_for_test(dev_name)
    };
    let Some(nic) = nic else {
        return 0;
    };
    nic.lock().await.ifcfg().owners_of_ipv4_route(route).len()
}

#[tokio::test]
#[serial_test::serial]
async fn failed_claim_update_closes_all_members_and_allows_recreation() {
    use crate::instance::{
        shared_virtual_nic::SharedVirtualNicRegistry, virtual_nic::VirtualNicConfig,
    };
    use tokio::sync::Notify;

    let netns = TestNetnsGuard::new(short_name("svf"), "10.233.1.2/24", "fd43::2/64");
    let dev_name = test_dev_name();
    let config =
        || VirtualNicConfig::new(dev_name.clone(), 1400, NetNS::new(Some(netns.name.clone())));
    let mut registry = SharedVirtualNicRegistry::new();
    let first_closed = Arc::new(Notify::new());
    let second_closed = Arc::new(Notify::new());
    let first_id = uuid::Uuid::new_v4();
    let first = registry.create_member(dev_name.clone(), config(), first_id, first_closed.clone());
    let second = registry.create_member(
        dev_name.clone(),
        config(),
        uuid::Uuid::new_v4(),
        second_closed.clone(),
    );
    let first_tunnel = first.create_dev().await.unwrap();
    let second_tunnel = second.create_dev().await.unwrap();
    first.link_up().await.unwrap();
    first
        .add_ip("10.233.97.1".parse().unwrap(), 24)
        .await
        .unwrap();
    second
        .add_ip("10.233.98.1".parse().unwrap(), 24)
        .await
        .unwrap();
    let destination = "10.233.90.0".parse().unwrap();
    first.add_route(destination, 24).await.unwrap();
    assert!(ipv4_route_exists_in_ns(&netns.name, "10.233.90.0/24"));

    // An externally configured, better source makes the address add fail only
    // after the existing route has been removed to update its preferred source.
    let output = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns.name,
            "ip",
            "addr",
            "add",
            "10.233.96.1/24",
            "dev",
            &dev_name,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let err = first
        .add_ip("10.233.96.1".parse().unwrap(), 24)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        crate::common::error::Error::IOError(err)
            if err.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert!(!first.shared_nic().lock().await.is_valid());
    tokio::time::timeout(WAIT, first_closed.notified())
        .await
        .unwrap();
    tokio::time::timeout(WAIT, second_closed.notified())
        .await
        .unwrap();
    assert!(registry.get(&dev_name, &config()).is_none());
    assert!(first.add_route(destination, 24).await.is_err());

    let replacement = registry.create_member(
        dev_name.clone(),
        config(),
        first_id,
        Arc::new(Notify::new()),
    );
    let replacement_tunnel = replacement.create_dev().await.unwrap();
    replacement.link_up().await.unwrap();
    replacement
        .add_ip("10.233.97.1".parse().unwrap(), 24)
        .await
        .unwrap();
    replacement.add_route(destination, 24).await.unwrap();
    assert!(ipv4_route_exists_in_ns(
        &netns.name,
        &format!("10.233.90.0/24 dev {dev_name} proto static src 10.233.97.1")
    ));

    drop((first_tunnel, second_tunnel, replacement_tunnel));
    drop((first, second, replacement));
    wait_for_condition(
        || async { !ipv4_route_exists_in_ns(&netns.name, "10.233.90.0/24") },
        WAIT,
    )
    .await;
}

#[cfg(feature = "management-rpc")]
#[tokio::test]
#[serial_test::serial]
async fn shared_tun_survives_creator_executor_shutdown() {
    use crate::instance::factory::native_instance_manager_with_runtime;
    use easytier_core::instance::manager::ConfigFileControl;

    let local_ns = TestNetnsGuard::new(short_name("sve"), "10.234.1.2/24", "fd44::2/64");
    let peer_ns = TestNetnsGuard::new(short_name("svp"), "10.234.2.2/24", "fd45::2/64");
    let dev_name = test_dev_name();
    let peer_dev = test_dev_name();
    let manager = native_instance_manager_with_runtime(tokio::runtime::Handle::current());
    let mut ids = Vec::new();
    for (name, network, ns, dev, ip, multi_thread) in [
        (
            "creator",
            "first",
            &local_ns.name,
            &dev_name,
            "10.244.1.1/24",
            false,
        ),
        (
            "survivor",
            "second",
            &local_ns.name,
            &dev_name,
            "10.244.2.1/24",
            true,
        ),
        (
            "peer",
            "second",
            &peer_ns.name,
            &peer_dev,
            "10.244.2.2/24",
            false,
        ),
    ] {
        let config = test_config(name, network, "secret", Some(ns), Some(dev), ip);
        let mut flags = config.get_flags();
        flags.multi_thread = multi_thread;
        flags.multi_thread_count = 2;
        flags.disable_upnp = true;
        flags.disable_p2p = true;
        flags.disable_tcp_hole_punching = true;
        flags.disable_udp_hole_punching = true;
        config.set_flags(flags);
        config.set_stun_servers(Some(Vec::new()));
        config.set_stun_servers_v6(Some(Vec::new()));
        config.set_tcp_stun_servers(Some(Vec::new()));
        let id = manager
            .run_network_instance(config, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
        ids.push(id);
        // Make the first instance the actual creator, not merely the first to start.
        wait_for_condition(|| async { tun_ifindex(ns, dev).is_some() }, WAIT).await;
        wait_for_condition(|| async { manager.instance(id).unwrap().is_ready() }, WAIT).await;
    }
    let creator_runtime = manager.data_plane_runtime_handle(&ids[0]).unwrap();
    let creator_task = creator_runtime.spawn(std::future::pending::<()>());
    let survivor = manager.instance(ids[1]).unwrap();
    let peer = manager.instance(ids[2]).unwrap();
    peer.add_connector(format!("ring://{}", ids[1]).parse().unwrap())
        .unwrap();
    wait_for_condition(
        || async {
            survivor.connected_peers().await.contains(&peer.peer_id())
                && peer.connected_peers().await.contains(&survivor.peer_id())
                && ipv4_route_exists_in_ns(&local_ns.name, "10.244.2.0/24")
                && ipv4_route_exists_in_ns(&peer_ns.name, "10.244.2.0/24")
        },
        WAIT,
    )
    .await;

    let bind = |ns: &str, address: &str| {
        let socket =
            NetNS::new(Some(ns.to_owned())).run(|| std::net::UdpSocket::bind(address).unwrap());
        socket.set_nonblocking(true).unwrap();
        tokio::net::UdpSocket::from_std(socket).unwrap()
    };
    let client = bind(&local_ns.name, "10.244.2.1:0");
    let server = bind(&peer_ns.name, "10.244.2.2:0");
    client.connect(server.local_addr().unwrap()).await.unwrap();
    let original_index = tun_ifindex(&local_ns.name, &dev_name).unwrap();
    let mut creator_task = Some(creator_task);
    for (pass, message) in [b"before shutdown".as_slice(), b"after shutdown".as_slice()]
        .into_iter()
        .enumerate()
    {
        if pass == 1 {
            manager
                .delete_network_instances(vec![ids[0]])
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(WAIT, creator_task.take().unwrap())
                    .await
                    .unwrap()
                    .unwrap_err()
                    .is_cancelled()
            );
            assert_eq!(tun_ifindex(&local_ns.name, &dev_name), Some(original_index));
        }
        tokio::time::timeout(WAIT, async {
            client.send(message).await.unwrap();
            let mut buf = [0; 64];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], message);
            assert_eq!(from, client.local_addr().unwrap());
            server.send_to(&buf[..len], from).await.unwrap();
            let len = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], message);
        })
        .await
        .expect("the existing UDP socket must work across creator shutdown");
    }
    assert_eq!(tun_ifindex(&local_ns.name, &dev_name), Some(original_index));
    drop((client, server, survivor, peer));
    manager
        .delete_network_instances(ids[1..].to_vec())
        .await
        .unwrap();
    wait_for_condition(
        || async {
            tun_ifindex(&local_ns.name, &dev_name).is_none()
                && tun_ifindex(&peer_ns.name, &peer_dev).is_none()
        },
        WAIT,
    )
    .await;
}

#[test]
#[serial_test::serial]
fn shared_tun_claim_cleanup_outlives_member_runtime() {
    use crate::instance::{
        shared_virtual_nic::SharedVirtualNicRegistry, virtual_nic::VirtualNicConfig,
    };
    use tokio::{runtime::Builder, sync::Notify};

    let netns = TestNetnsGuard::new(short_name("svc"), "10.235.1.2/24", "fd46::2/64");
    let dev_name = test_dev_name();
    let config =
        || VirtualNicConfig::new(dev_name.clone(), 1400, NetNS::new(Some(netns.name.clone())));
    let mut registry = SharedVirtualNicRegistry::new();
    let first = registry.create_member(
        dev_name.clone(),
        config(),
        uuid::Uuid::new_v4(),
        Arc::new(Notify::new()),
    );
    let second = registry.create_member(
        dev_name.clone(),
        config(),
        uuid::Uuid::new_v4(),
        Arc::new(Notify::new()),
    );
    let member_runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let observer_runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let first_tunnel = member_runtime.block_on(async {
        let tunnel = first.create_dev().await.unwrap();
        first.link_up().await.unwrap();
        first
            .add_ip("10.245.1.1".parse().unwrap(), 24)
            .await
            .unwrap();
        first
            .add_route("10.245.90.0".parse().unwrap(), 24)
            .await
            .unwrap();
        tunnel
    });
    let second_tunnel = observer_runtime.block_on(async {
        let tunnel = second.create_dev().await.unwrap();
        second
            .add_ip("10.245.2.1".parse().unwrap(), 24)
            .await
            .unwrap();
        tunnel
    });
    assert!(ipv4_route_exists_in_ns(&netns.name, "10.245.90.0/24"));
    let original_index = tun_ifindex(&netns.name, &dev_name).unwrap();
    let shared_nic = first.shared_nic();
    let guard = observer_runtime.block_on(shared_nic.lock());
    member_runtime.block_on(async {
        drop((first_tunnel, first));
        // Claim removal cannot acquire the lock until after this runtime exits.
        tokio::task::yield_now().await;
    });
    drop(member_runtime);
    drop(guard);

    observer_runtime.block_on(async {
        wait_for_condition(
            || async { !ipv4_route_exists_in_ns(&netns.name, "10.245.90.0/24") },
            WAIT,
        )
        .await;
        assert_eq!(tun_ifindex(&netns.name, &dev_name), Some(original_index));
        // Reusing the departed member's address also proves its claims were released.
        second
            .add_ip("10.245.1.1".parse().unwrap(), 24)
            .await
            .unwrap();
    });
    // The final registration can be dropped without any entered Tokio runtime.
    drop((second_tunnel, second));
    observer_runtime.block_on(wait_for_condition(
        || async { tun_ifindex(&netns.name, &dev_name).is_none() },
        WAIT,
    ));
}

#[rstest::rstest]
#[case::static_ipv4(false)]
#[case::with_dhcpv6(true)]
#[tokio::test]
#[serial_test::serial]
async fn same_namespace_members_share_tun_across_independent_networks(#[case] dhcpv6: bool) {
    let dev_name = test_dev_name();
    let first_peer_ns = TestNetnsGuard::new(short_name("sva"), "10.231.1.2/24", "fd31::2/64");
    let second_peer_ns = TestNetnsGuard::new(short_name("svb"), "10.231.2.2/24", "fd32::2/64");
    let runtime = SharedTestRuntime::new();

    let first_config = test_config(
        "shared_tun_first",
        "shared_tun_network_a",
        "shared_tun_secret_a",
        None,
        Some(&dev_name),
        "10.144.250.1/24",
    );
    if dhcpv6 {
        first_config.set_dhcpv6_config(easytier_core::config::DhcpConfig::Cidr(
            "fd42:a::/64".parse().unwrap(),
        ));
    }
    let mut first = runtime.instance(first_config);
    let second_config = test_config(
        "shared_tun_second",
        "shared_tun_network_b",
        "shared_tun_secret_b",
        None,
        Some(&dev_name),
        "10.144.251.1/24",
    );
    if dhcpv6 {
        second_config.set_dhcpv6_config(easytier_core::config::DhcpConfig::Cidr(
            "fd42:b::/64".parse().unwrap(),
        ));
    }
    let mut second = runtime.instance(second_config);
    let first_peer_config = test_config(
        "shared_tun_first_peer",
        "shared_tun_network_a",
        "shared_tun_secret_a",
        Some(&first_peer_ns.name),
        None,
        "10.144.250.2/24",
    );
    if dhcpv6 {
        first_peer_config.set_ipv6(Some("fd42:a::2/64".parse().unwrap()));
    }
    let mut first_peer = runtime.instance(first_peer_config);
    let second_peer_config = test_config(
        "shared_tun_second_peer",
        "shared_tun_network_b",
        "shared_tun_secret_b",
        Some(&second_peer_ns.name),
        None,
        "10.144.251.2/24",
    );
    if dhcpv6 {
        second_peer_config.set_ipv6(Some("fd42:b::2/64".parse().unwrap()));
    }
    let mut second_peer = runtime.instance(second_peer_config);

    first.run().await.unwrap();
    second.run().await.unwrap();
    first_peer.run().await.unwrap();
    second_peer.run().await.unwrap();

    wait_tun_ready(&first, &dev_name).await;
    wait_tun_ready(&second, &dev_name).await;
    assert_eq!(
        first.get_global_ctx().get_tun_device_name(),
        second.get_global_ctx().get_tun_device_name()
    );

    first_peer.add_connector_url(first.ring_listener_url());
    second_peer.add_connector_url(second.ring_listener_url());

    wait_for_condition(
        || async {
            first
                .get_core_instance()
                .route_snapshots()
                .await
                .iter()
                .any(|route| route.peer_id == first_peer.peer_id())
                && second
                    .get_core_instance()
                    .route_snapshots()
                    .await
                    .iter()
                    .any(|route| route.peer_id == second_peer.peer_id())
        },
        WAIT,
    )
    .await;
    wait_for_condition(
        || async { ping_test(&first_peer_ns.name, "10.144.250.1", None).await },
        WAIT,
    )
    .await;
    wait_for_condition(
        || async { ping_test(&second_peer_ns.name, "10.144.251.1", None).await },
        WAIT,
    )
    .await;

    if dhcpv6 {
        for (instance, ns) in [
            (&first, &first_peer_ns.name),
            (&second, &second_peer_ns.name),
        ] {
            wait_for_condition(
                || async { instance.get_global_ctx().get_ipv6().is_some() },
                WAIT,
            )
            .await;
            let address = instance
                .get_global_ctx()
                .get_ipv6()
                .unwrap()
                .address()
                .to_string();
            wait_for_condition(|| async { ping_test(ns, &address, None).await }, WAIT).await;
        }
        // Removing one DHCP member must leave the other member's addresses
        // and the physical TUN intact.
        let original_index = tun_ifindex(ROOT_NETNS_NAME, &dev_name);
        assert!(original_index.is_some());
        drop_insts(vec![first]).await;
        assert_eq!(tun_ifindex(ROOT_NETNS_NAME, &dev_name), original_index);
        let address = second
            .get_global_ctx()
            .get_ipv6()
            .unwrap()
            .address()
            .to_string();
        wait_for_condition(
            || async { ping_test(&second_peer_ns.name, &address, None).await },
            WAIT,
        )
        .await;
        drop_insts(vec![second, first_peer, second_peer]).await;
    } else {
        drop_insts(vec![first, second, first_peer, second_peer]).await;
    }
}

#[cfg(feature = "proxy-cidr-monitor")]
#[tokio::test]
#[serial_test::serial]
async fn runtime_proxy_patch_adds_and_removes_os_route() {
    use crate::proto::api::config::ConfigPatchAction;

    let lab = ProxyLab::new();
    let source_dev = test_dev_name();
    let destination_dev = test_dev_name();
    let runtime = SharedTestRuntime::new();
    let mut source = runtime.instance(test_config(
        "shared_patch_source",
        "shared_patch_network",
        "shared_patch_secret",
        Some(lab.network.namespace("source")),
        Some(&source_dev),
        "10.144.244.1/24",
    ));
    let mut destination = runtime.instance(test_config(
        "shared_patch_destination",
        "shared_patch_network",
        "shared_patch_secret",
        Some(lab.network.namespace("owner")),
        Some(&destination_dev),
        "10.144.244.2/24",
    ));

    source.run().await.unwrap();
    destination.run().await.unwrap();
    wait_tun_ready(&source, &source_dev).await;
    wait_tun_ready(&destination, &destination_dev).await;
    destination.add_connector_url(source.ring_listener_url());
    wait_for_condition(
        || async {
            source
                .get_core_instance()
                .route_snapshots()
                .await
                .iter()
                .any(|route| route.peer_id == destination.peer_id())
        },
        WAIT,
    )
    .await;
    assert!(!ipv4_route_exists_in_ns(
        lab.network.namespace("source"),
        &format!("{PROXY_CIDR} dev {source_dev}")
    ));

    patch_proxy_cidr(&destination, ConfigPatchAction::Add).await;
    wait_proxy_route(&source, destination.peer_id(), PROXY_CIDR).await;
    wait_for_condition(
        || async {
            ipv4_route_exists_in_ns(
                lab.network.namespace("source"),
                &format!("{PROXY_CIDR} dev {source_dev}"),
            )
        },
        WAIT,
    )
    .await;

    patch_proxy_cidr(&destination, ConfigPatchAction::Remove).await;
    wait_proxy_route_absent(&source, destination.peer_id(), PROXY_CIDR).await;
    wait_for_condition(
        || async {
            !ipv4_route_exists_in_ns(
                lab.network.namespace("source"),
                &format!("{PROXY_CIDR} dev {source_dev}"),
            )
        },
        WAIT,
    )
    .await;

    drop_insts(vec![source, destination]).await;
}

#[cfg(feature = "magic-dns")]
async fn wait_shared_magic_dns_record(
    ns: &str,
    domain: &str,
    expected_source: &str,
    expected_ip: &str,
) {
    use hickory_proto::{
        op::{Message, MessageType, Query, ResponseCode},
        rr::{RData, RecordType},
    };

    use crate::instance::dns_server::MAGIC_DNS_FAKE_IP;

    let expected_source = expected_source.parse::<Ipv4Addr>().unwrap();
    let expected_ip = expected_ip.parse::<Ipv4Addr>().unwrap();
    let mut query = Message::new();
    query
        .set_id(rand::random())
        .add_query(Query::query(domain.parse().unwrap(), RecordType::A));
    let payload = query.to_vec().unwrap();
    wait_for_condition(
        || async {
            // Let the kernel select the source from the shared route, rather
            // than binding to the server and hiding a client-owned route.
            let Ok(socket) = NetNS::new(Some(ns.to_owned())).run(|| {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
                socket.connect((MAGIC_DNS_FAKE_IP, 53))?;
                socket.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(socket)
            }) else {
                return false;
            };
            let source = socket.local_addr().unwrap().ip();
            if socket.send(&payload).await.is_err() {
                return false;
            }
            let mut buffer = [0; 512];
            let Ok(Ok(len)) =
                tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buffer)).await
            else {
                return false;
            };
            let response = Message::from_vec(&buffer[..len]).unwrap();
            source == std::net::IpAddr::V4(expected_source)
                && response.id() == query.id()
                && response.message_type() == MessageType::Response
                && response.response_code() == ResponseCode::NoError
                && response.answers().len() == 1
                && matches!(response.answers()[0].data(), RData::A(ip) if ip.0 == expected_ip)
        },
        WAIT,
    )
    .await;
}

#[cfg(feature = "magic-dns")]
#[tokio::test]
#[serial_test::serial]
async fn magic_dns_route_follows_serving_member_and_takeover() {
    use crate::instance::dns_server::MAGIC_DNS_FAKE_IP;

    let netns = TestNetnsGuard::new(short_name("svd"), "10.232.1.2/24", "fd42::2/64");
    let dev_name = test_dev_name();
    let runtime = SharedTestRuntime::new();
    let first_config = test_config(
        "shared_dns_first",
        "shared_dns_network",
        "shared_dns_secret",
        Some(&netns.name),
        Some(&dev_name),
        "10.144.243.1/24",
    );
    // The first runner wins the singleton, but the client sorts first when
    // shared route source hints are chosen by UUID.
    first_config.set_id(uuid::Uuid::from_u128(2));
    first_config.set_hostname(Some("shared-dns-first".to_owned()));
    let mut flags = first_config.get_flags();
    flags.accept_dns = true;
    first_config.set_flags(flags.clone());
    let second_config = test_config(
        "shared_dns_second",
        "shared_dns_network",
        "shared_dns_secret",
        Some(&netns.name),
        Some(&dev_name),
        "10.144.242.2/24",
    );
    second_config.set_id(uuid::Uuid::from_u128(1));
    second_config.set_hostname(Some("shared-dns-second".to_owned()));
    second_config.set_flags(flags);
    let mut first = runtime.instance(first_config);
    let mut second = runtime.instance(second_config);

    first.run().await.unwrap();
    wait_tun_ready(&first, &dev_name).await;
    wait_shared_magic_dns_record(
        &netns.name,
        "shared-dns-first.et.net.",
        "10.144.243.1",
        "10.144.243.1",
    )
    .await;

    second.run().await.unwrap();
    wait_tun_ready(&second, &dev_name).await;
    // Resolving the second member also waits for its client to connect and
    // publish, ensuring its failed server election has already completed.
    wait_shared_magic_dns_record(
        &netns.name,
        "shared-dns-second.et.net.",
        "10.144.243.1",
        "10.144.242.2",
    )
    .await;
    let route = SharedIpv4Route::new(MAGIC_DNS_FAKE_IP.parse::<Ipv4Addr>().unwrap(), 32, None);
    assert_eq!(
        shared_route_owner_count(&runtime.registry, &dev_name, &route).await,
        1
    );

    drop_insts(vec![first]).await;
    wait_shared_magic_dns_record(
        &netns.name,
        "shared-dns-second.et.net.",
        "10.144.242.2",
        "10.144.242.2",
    )
    .await;
    assert_eq!(
        shared_route_owner_count(&runtime.registry, &dev_name, &route).await,
        1
    );

    // Keep the TUN alive after the final DNS runner stops so device teardown
    // cannot hide a leaked fake-IP route.
    let mut observer = runtime.instance(test_config(
        "shared_dns_observer",
        "shared_dns_network",
        "shared_dns_secret",
        Some(&netns.name),
        Some(&dev_name),
        "10.144.244.3/24",
    ));
    observer.run().await.unwrap();
    wait_tun_ready(&observer, &dev_name).await;

    drop_insts(vec![second]).await;
    wait_for_condition(
        || async {
            shared_route_owner_count(&runtime.registry, &dev_name, &route).await == 0
                && !ipv4_route_exists_in_ns(
                    &netns.name,
                    &format!("{MAGIC_DNS_FAKE_IP} dev {dev_name}"),
                )
        },
        WAIT,
    )
    .await;
    drop_insts(vec![observer]).await;
}
