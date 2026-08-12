use std::{net::Ipv4Addr, process::Command, sync::Arc, time::Duration};

use easytier_core::{config::PeerId, process_runtime::CoreProcessRuntime};

use super::{
    InstanceTestExt as _, add_ns_to_bridge, create_netns, del_netns, drop_insts, ping_test,
    prepare_bridge,
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
const PROXY_TARGET: &str = "10.1.2.4";
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
    source_ns: String,
    owner_ns: String,
    target_ns: String,
    bridge: String,
}

impl ProxyLab {
    fn new() -> Self {
        let suffix = format!("{:04x}", rand::random::<u16>());
        let lab = Self {
            source_ns: format!("svs{suffix}"),
            owner_ns: format!("svo{suffix}"),
            target_ns: format!("svt{suffix}"),
            bridge: format!("svb{suffix}"),
        };
        lab.cleanup();

        create_netns(&lab.source_ns, "10.1.1.1/24", "fd11::1/64");
        create_netns(&lab.owner_ns, "10.1.2.3/24", "fd12::3/64");
        create_netns(&lab.target_ns, "10.1.2.4/24", "fd12::4/64");
        prepare_bridge(&lab.bridge);
        add_ns_to_bridge(&lab.bridge, &lab.owner_ns);
        add_ns_to_bridge(&lab.bridge, &lab.target_ns);
        lab
    }

    fn cleanup(&self) {
        del_netns(&self.source_ns);
        del_netns(&self.owner_ns);
        del_netns(&self.target_ns);
        let _ = Command::new("ip")
            .args(["link", "del", &self.bridge])
            .output();
    }
}

impl Drop for ProxyLab {
    fn drop(&mut self) {
        self.cleanup();
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
    nic.lock()
        .await
        .ifcfg()
        .snapshot()
        .ipv4_routes
        .get(route)
        .map_or(0, |owners| owners.len())
}

#[tokio::test]
#[serial_test::serial]
async fn same_namespace_members_share_tun_across_independent_networks() {
    let dev_name = test_dev_name();
    let first_peer_ns = TestNetnsGuard::new(short_name("sva"), "10.231.1.2/24", "fd31::2/64");
    let second_peer_ns = TestNetnsGuard::new(short_name("svb"), "10.231.2.2/24", "fd32::2/64");
    let runtime = SharedTestRuntime::new();

    let mut first = runtime.instance(test_config(
        "shared_tun_first",
        "shared_tun_network_a",
        "shared_tun_secret_a",
        None,
        Some(&dev_name),
        "10.144.250.1/24",
    ));
    let mut second = runtime.instance(test_config(
        "shared_tun_second",
        "shared_tun_network_b",
        "shared_tun_secret_b",
        None,
        Some(&dev_name),
        "10.144.251.1/24",
    ));
    let mut first_peer = runtime.instance(test_config(
        "shared_tun_first_peer",
        "shared_tun_network_a",
        "shared_tun_secret_a",
        Some(&first_peer_ns.name),
        None,
        "10.144.250.2/24",
    ));
    let mut second_peer = runtime.instance(test_config(
        "shared_tun_second_peer",
        "shared_tun_network_b",
        "shared_tun_secret_b",
        Some(&second_peer_ns.name),
        None,
        "10.144.251.2/24",
    ));

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

    drop_insts(vec![first, second, first_peer, second_peer]).await;
}

#[cfg(feature = "proxy-cidr-monitor")]
#[tokio::test]
#[serial_test::serial]
async fn duplicate_proxy_cidr_survives_one_shared_owner_departure() {
    let lab = ProxyLab::new();
    let source_dev = test_dev_name();
    let owner_dev = test_dev_name();
    let runtime = SharedTestRuntime::new();

    let mut source = runtime.instance(test_config(
        "shared_proxy_source",
        "shared_proxy_network",
        "shared_proxy_secret",
        Some(&lab.source_ns),
        Some(&source_dev),
        "10.144.245.1/24",
    ));
    let primary_config = test_config(
        "shared_proxy_primary",
        "shared_proxy_network",
        "shared_proxy_secret",
        Some(&lab.owner_ns),
        Some(&owner_dev),
        "10.144.245.2/24",
    );
    primary_config
        .add_proxy_cidr(PROXY_CIDR.parse().unwrap(), None)
        .unwrap();
    let backup_config = test_config(
        "shared_proxy_backup",
        "shared_proxy_network",
        "shared_proxy_secret",
        Some(&lab.owner_ns),
        Some(&owner_dev),
        "10.144.245.3/24",
    );
    backup_config
        .add_proxy_cidr(PROXY_CIDR.parse().unwrap(), None)
        .unwrap();
    let mut primary = runtime.instance(primary_config);
    let mut backup = runtime.instance(backup_config);

    source.run().await.unwrap();
    primary.run().await.unwrap();
    backup.run().await.unwrap();
    wait_tun_ready(&source, &source_dev).await;
    wait_tun_ready(&primary, &owner_dev).await;
    wait_tun_ready(&backup, &owner_dev).await;

    primary.add_connector_url(source.ring_listener_url());
    backup.add_connector_url(source.ring_listener_url());
    wait_proxy_route(&source, primary.peer_id(), PROXY_CIDR).await;
    wait_proxy_route(&source, backup.peer_id(), PROXY_CIDR).await;
    wait_for_condition(
        || async {
            ipv4_route_exists_in_ns(&lab.source_ns, &format!("{PROXY_CIDR} dev {source_dev}"))
                && ping_test(&lab.source_ns, PROXY_TARGET, None).await
        },
        WAIT,
    )
    .await;

    let primary_id = primary.peer_id();
    drop_insts(vec![primary]).await;
    wait_proxy_route_absent(&source, primary_id, PROXY_CIDR).await;
    wait_proxy_route(&source, backup.peer_id(), PROXY_CIDR).await;
    wait_for_condition(
        || async {
            ipv4_route_exists_in_ns(&lab.source_ns, &format!("{PROXY_CIDR} dev {source_dev}"))
                && ping_test(&lab.source_ns, PROXY_TARGET, None).await
        },
        WAIT,
    )
    .await;

    drop_insts(vec![source, backup]).await;
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
        Some(&lab.source_ns),
        Some(&source_dev),
        "10.144.244.1/24",
    ));
    let mut destination = runtime.instance(test_config(
        "shared_patch_destination",
        "shared_patch_network",
        "shared_patch_secret",
        Some(&lab.owner_ns),
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
        &lab.source_ns,
        &format!("{PROXY_CIDR} dev {source_dev}")
    ));

    patch_proxy_cidr(&destination, ConfigPatchAction::Add).await;
    wait_proxy_route(&source, destination.peer_id(), PROXY_CIDR).await;
    wait_for_condition(
        || async {
            ipv4_route_exists_in_ns(&lab.source_ns, &format!("{PROXY_CIDR} dev {source_dev}"))
        },
        WAIT,
    )
    .await;

    patch_proxy_cidr(&destination, ConfigPatchAction::Remove).await;
    wait_proxy_route_absent(&source, destination.peer_id(), PROXY_CIDR).await;
    wait_for_condition(
        || async {
            !ipv4_route_exists_in_ns(&lab.source_ns, &format!("{PROXY_CIDR} dev {source_dev}"))
        },
        WAIT,
    )
    .await;

    drop_insts(vec![source, destination]).await;
}

#[cfg(feature = "magic-dns")]
#[tokio::test]
#[serial_test::serial]
async fn magic_dns_route_lives_until_last_shared_owner_leaves() {
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
    let mut flags = first_config.get_flags();
    flags.accept_dns = true;
    first_config.set_flags(flags.clone());
    let second_config = test_config(
        "shared_dns_second",
        "shared_dns_network",
        "shared_dns_secret",
        Some(&netns.name),
        Some(&dev_name),
        "10.144.243.2/24",
    );
    second_config.set_flags(flags);
    let mut first = runtime.instance(first_config);
    let mut second = runtime.instance(second_config);

    first.run().await.unwrap();
    second.run().await.unwrap();
    wait_tun_ready(&first, &dev_name).await;
    wait_tun_ready(&second, &dev_name).await;

    let route = SharedIpv4Route::new(MAGIC_DNS_FAKE_IP.parse::<Ipv4Addr>().unwrap(), 32, None);
    wait_for_condition(
        || async { shared_route_owner_count(&runtime.registry, &dev_name, &route).await == 2 },
        WAIT,
    )
    .await;
    assert!(ipv4_route_exists_in_ns(
        &netns.name,
        &format!("{MAGIC_DNS_FAKE_IP} dev {dev_name}")
    ));

    drop_insts(vec![first]).await;
    wait_for_condition(
        || async {
            shared_route_owner_count(&runtime.registry, &dev_name, &route).await == 1
                && ipv4_route_exists_in_ns(
                    &netns.name,
                    &format!("{MAGIC_DNS_FAKE_IP} dev {dev_name}"),
                )
        },
        WAIT,
    )
    .await;

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
}
