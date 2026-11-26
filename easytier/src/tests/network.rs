use crate::common::netns::{NetNS, ROOT_NETNS_NAME};

use super::{add_ns_to_bridge, create_netns, del_netns, get_guest_veth_name, run_network_command};

/// Owns one test's host links and namespaces. Keep this alive until its
/// instances and background tasks have stopped, including on setup failures.
pub(super) struct TestNetwork {
    directory: tempfile::TempDir,
    namespaces: Vec<(&'static str, String)>,
    links: Vec<(&'static str, String)>,
}

impl TestNetwork {
    pub(super) fn new() -> Self {
        Self {
            directory: tempfile::Builder::new()
                .prefix("et")
                .rand_bytes(4)
                .tempdir()
                .unwrap(),
            namespaces: Vec::new(),
            links: Vec::new(),
        }
    }

    fn prefix(&self) -> &str {
        self.directory.path().file_name().unwrap().to_str().unwrap()
    }

    pub(super) fn namespace(&self, name: &str) -> &str {
        &self
            .namespaces
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap()
            .1
    }

    pub(super) fn link(&self, name: &str) -> &str {
        &self.links.iter().find(|(key, _)| *key == name).unwrap().1
    }

    fn add_namespace(&mut self, name: &'static str) {
        // veth_<namespace>_h must fit Linux's 15-byte interface name limit.
        let actual = format!("{}{:02x}", self.prefix(), self.namespaces.len());
        assert!(actual.len() <= 8);
        assert!(!self.namespaces.iter().any(|(key, _)| *key == name));
        self.namespaces.push((name, actual));
    }

    pub(super) fn create_namespace(&mut self, name: &'static str, ipv4: &str, ipv6: &str) {
        self.add_namespace(name);
        create_netns(self.namespace(name), ipv4, ipv6);
    }

    pub(super) fn create_empty_namespace(&mut self, name: &'static str) {
        self.add_namespace(name);
        let actual = self.namespace(name);
        run_network_command("ip", &["netns", "add", actual]);
        run_network_command(
            "ip",
            &["netns", "exec", actual, "ip", "link", "set", "lo", "up"],
        );
    }

    pub(super) fn add_link(&mut self, name: &'static str) {
        let actual = format!("{}l{:02x}", self.prefix(), self.links.len());
        assert!(!self.links.iter().any(|(key, _)| *key == name));
        self.links.push((name, actual));
    }

    pub(super) fn create_bridge(&mut self, name: &'static str) {
        self.add_link(name);
        run_network_command("brctl", &["addbr", self.link(name)]);
        run_network_command("ip", &["link", "set", self.link(name), "up"]);
    }

    pub(super) fn add_to_bridge(&self, bridge: &str, namespace: &str) {
        add_ns_to_bridge(self.link(bridge), self.namespace(namespace));
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        let _guard = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
        for (_, namespace) in &self.namespaces {
            del_netns(namespace);
        }
        for (_, link) in self.links.iter().rev() {
            let _ = std::process::Command::new("ip")
                .args(["link", "del", link])
                .output();
        }
    }
}

#[test]
fn nested_namespace_guard_restores_current_thread() {
    let mut network = TestNetwork::new();
    network.create_empty_namespace("net_a");
    network.create_empty_namespace("net_b");
    let net_a = NetNS::new(Some(network.namespace("net_a").into()));
    let net_b = NetNS::new(Some(network.namespace("net_b").into()));
    let current = || std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    let original = current();

    net_a.run(|| {
        let expected = current();
        assert_ne!(expected, original);
        net_b.run(|| assert_ne!(current(), expected));
        assert_eq!(current(), expected);
    });
    assert_eq!(current(), original);
}

#[tokio::test]
async fn async_namespace_restores_between_polls() {
    let mut network = TestNetwork::new();
    network.create_empty_namespace("net_a");
    network.create_empty_namespace("net_b");
    let net_a = NetNS::new(Some(network.namespace("net_a").into()));
    let net_b = NetNS::new(Some(network.namespace("net_b").into()));
    let current = || std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    let original = current();
    let expected = net_a.run(current);

    let mut future = Box::pin(net_a.run_async(|| async {
        assert_eq!(current(), expected);
        tokio::task::yield_now().await;
        assert_eq!(current(), expected);
    }));
    assert!(futures::poll!(future.as_mut()).is_pending());
    assert_eq!(current(), original);
    net_b.run(|| assert_ne!(current(), expected));
    future.await;
    assert_eq!(current(), original);

    let dropped_in = std::cell::RefCell::new(None);
    let mut cancelled = Box::pin(net_a.run_async(|| async {
        let _cleanup = guarden::guard::ContextGuard::new((), |_| {
            *dropped_in.borrow_mut() = Some(current());
        });
        std::future::pending::<()>().await;
    }));
    assert!(futures::poll!(cancelled.as_mut()).is_pending());
    assert_eq!(current(), original);
    drop(cancelled);
    assert_eq!(current(), original);
    assert_eq!(*dropped_in.borrow(), Some(expected));
}

#[cfg(all(feature = "linux-netlink", feature = "tun"))]
#[tokio::test]
async fn filtered_enumeration_excludes_target_namespace_tun_without_sysfs_remount() {
    use crate::common::network::{collect_interfaces, collect_local_ip_addrs};
    use std::net::Ipv4Addr;

    let mut network = TestNetwork::new();
    let veth_ip = "10.0.1.1";
    let tap_ip = "10.0.2.1";
    network.create_namespace("target", &format!("{veth_ip}/24"), "fd00:1::1/64");
    network.add_link("tap");

    let target_ns = network.namespace("target");
    let net_ns = NetNS::new(Some(target_ns.to_owned()));
    let tap_name = network.link("tap").to_string();

    let mut config = tun::Configuration::default();
    config.layer(tun::Layer::L2);
    config.tun_name(&tap_name);
    config.address(tap_ip);
    config.netmask("255.255.255.0");
    config.up();

    // Create the TAP device inside the target network namespace while keeping
    // /sys mounted from the host namespace. Keeping the descriptor open preserves
    // carrier (IFF_LOWER_UP) so the link passes all interface filters except
    // for TUN/TAP detection.
    let _tap = net_ns.run(|| tun::create(&config).unwrap());

    let guest_veth = get_guest_veth_name(target_ns);

    let unfiltered = collect_interfaces(net_ns.clone(), false).await;
    assert!(
        unfiltered.iter().any(|iface| iface.name == tap_name),
        "unfiltered enumeration should include tap link {tap_name}: {unfiltered:?}"
    );
    assert!(
        unfiltered.iter().any(|iface| iface.name == guest_veth),
        "unfiltered enumeration should include non-TUN veth link {guest_veth}: {unfiltered:?}"
    );

    let filtered = collect_interfaces(net_ns.clone(), true).await;
    assert!(
        !filtered.iter().any(|iface| iface.name == tap_name),
        "filtered enumeration should exclude tap link {tap_name}: {filtered:?}"
    );
    assert!(
        filtered.iter().any(|iface| iface.name == guest_veth),
        "filtered enumeration should retain non-TUN veth link {guest_veth}: {filtered:?}"
    );

    let addrs = collect_local_ip_addrs(net_ns).await;
    let veth_v4: Ipv4Addr = veth_ip.parse().unwrap();
    let tap_v4: Ipv4Addr = tap_ip.parse().unwrap();
    assert!(
        addrs.interface_ipv4s.contains(&veth_v4.into()),
        "collected local IP addresses should include veth IPv4 {veth_ip}: {addrs:?}"
    );
    assert!(
        !addrs.interface_ipv4s.contains(&tap_v4.into()),
        "collected local IP addresses should exclude tap IPv4 {tap_ip}: {addrs:?}"
    );
}
