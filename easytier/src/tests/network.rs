use crate::common::netns::{NetNS, ROOT_NETNS_NAME};

use super::{add_ns_to_bridge, create_netns, del_netns, run_network_command};

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
