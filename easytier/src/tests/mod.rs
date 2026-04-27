#[cfg(target_os = "linux")]
mod three_node;

mod ipv6_test;

#[cfg(target_os = "linux")]
mod credential_tests;

#[cfg(target_os = "linux")]
mod upnp_test;

use crate::common::PeerId;
use crate::peers::peer_manager::PeerManager;

pub fn set_env_var<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(key: K, value: V) {
    unsafe { std::env::set_var(key, value) }
}

pub fn remove_env_var<K: AsRef<std::ffi::OsStr>>(key: K) {
    unsafe { std::env::remove_var(key) }
}

pub fn get_guest_veth_name(net_ns: &str) -> &str {
    Box::leak(format!("veth_{}_g", net_ns).into_boxed_str())
}

pub fn get_host_veth_name(net_ns: &str) -> &str {
    Box::leak(format!("veth_{}_h", net_ns).into_boxed_str())
}

pub fn del_netns(name: &str) {
    // del veth host
    let _ = std::process::Command::new("ip")
        .args(["link", "del", get_host_veth_name(name)])
        .output();

    let _ = std::process::Command::new("ip")
        .args(["netns", "del", name])
        .output();
}

pub fn create_netns(name: &str, ipv4: &str, ipv6: &str) {
    // create netns
    let _ = std::process::Command::new("ip")
        .args(["netns", "add", name])
        .output()
        .unwrap();

    // set lo up
    let _ = std::process::Command::new("ip")
        .args(["netns", "exec", name, "ip", "link", "set", "lo", "up"])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args([
            "link",
            "add",
            get_host_veth_name(name),
            "type",
            "veth",
            "peer",
            "name",
            get_guest_veth_name(name),
        ])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args(["link", "set", get_guest_veth_name(name), "netns", name])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            name,
            "ip",
            "link",
            "set",
            get_guest_veth_name(name),
            "up",
        ])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args(["link", "set", get_host_veth_name(name), "up"])
        .output()
        .unwrap();

    for ip in [ipv4, ipv6] {
        let _ = std::process::Command::new("ip")
            .args([
                "netns",
                "exec",
                name,
                "ip",
                "addr",
                "add",
                ip,
                "dev",
                get_guest_veth_name(name),
            ])
            .output()
            .unwrap();
    }
}

pub struct TestNetnsGuard {
    name: String,
    host_ipv4: Option<String>,
}

impl TestNetnsGuard {
    fn run_ip(args: &[&str]) {
        let status = std::process::Command::new("ip")
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "ip command failed: {:?}", args);
    }

    pub fn new(name: &str, guest_ipv4: &str, guest_ipv6: &str) -> Self {
        del_netns(name);
        create_netns(name, guest_ipv4, guest_ipv6);
        Self {
            name: name.to_string(),
            host_ipv4: None,
        }
    }

    pub fn set_host_ipv4(&mut self, host_ipv4: &str) {
        Self::run_ip(&[
            "addr",
            "add",
            host_ipv4,
            "dev",
            get_host_veth_name(&self.name),
        ]);
        self.host_ipv4 = Some(host_ipv4.to_string());
    }
}

impl Drop for TestNetnsGuard {
    fn drop(&mut self) {
        if let Some(host_ipv4) = self.host_ipv4.as_deref() {
            let _ = std::process::Command::new("ip")
                .args([
                    "addr",
                    "del",
                    host_ipv4,
                    "dev",
                    get_host_veth_name(&self.name),
                ])
                .status();
        }
        del_netns(&self.name);
    }
}

pub fn prepare_bridge(name: &str) {
    // del bridge with brctl
    let _ = std::process::Command::new("brctl")
        .args(["delbr", name])
        .output();

    // create new br
    let _ = std::process::Command::new("brctl")
        .args(["addbr", name])
        .output();
}

pub fn add_ns_to_bridge(br_name: &str, ns_name: &str) {
    // use brctl to add ns to bridge
    let _ = std::process::Command::new("brctl")
        .args(["addif", br_name, get_host_veth_name(ns_name)])
        .output()
        .unwrap();

    // set bridge up
    let _ = std::process::Command::new("ip")
        .args(["link", "set", br_name, "up"])
        .output()
        .unwrap();
}

fn check_route(ipv4: &str, dst_peer_id: PeerId, routes: Vec<crate::proto::api::instance::Route>) {
    let mut found = false;
    for r in routes.iter() {
        if r.ipv4_addr == Some(ipv4.parse().unwrap()) {
            found = true;
            assert_eq!(r.peer_id, dst_peer_id, "{:?}", routes);
        }
    }
    assert!(
        found,
        "routes: {:?}, dst_peer_id: {}, ipv4: {}",
        routes, dst_peer_id, ipv4
    );
}

fn check_route_ex(
    routes: Vec<crate::proto::api::instance::Route>,
    peer_id: PeerId,
    checker: impl Fn(&crate::proto::api::instance::Route) -> bool,
) {
    let mut found = false;
    for r in routes.iter() {
        if r.peer_id == peer_id {
            found = true;
            assert!(checker(r), "{:?}", routes);
        }
    }
    assert!(found, "routes: {:?}, dst_peer_id: {}", routes, peer_id);
}

async fn wait_proxy_route_appear(
    mgr: &std::sync::Arc<PeerManager>,
    ipv4: &str,
    dst_peer_id: PeerId,
    proxy_cidr: &str,
) {
    let now = std::time::Instant::now();
    loop {
        for r in mgr.list_routes().await.iter() {
            if r.proxy_cidrs.contains(&proxy_cidr.to_owned()) {
                assert_eq!(r.peer_id, dst_peer_id);
                assert_eq!(r.ipv4_addr, Some(ipv4.parse().unwrap()));
                return;
            }
        }
        if now.elapsed().as_secs() > 5 {
            panic!("wait proxy route appear timeout");
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

fn set_link_status(net_ns: &str, up: bool) {
    let ret = std::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            net_ns,
            "ip",
            "link",
            "set",
            get_guest_veth_name(net_ns),
            if up { "up" } else { "down" },
        ])
        .output()
        .unwrap();
    tracing::info!("set link status: {:?}, net_ns: {}, up: {}", ret, net_ns, up);
}

pub async fn drop_insts(insts: Vec<crate::instance::instance::Instance>) {
    let mut set = tokio::task::JoinSet::new();
    for mut inst in insts {
        set.spawn(async move {
            inst.clear_resources().await;
            let pm = std::sync::Arc::downgrade(&inst.get_peer_manager());
            drop(inst);
            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 5 && pm.strong_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert_eq!(pm.strong_count(), 0, "PeerManager should be dropped");
        });
    }
    while set.join_next().await.is_some() {}
}

pub async fn ping_test(from_netns: &str, target_ip: &str, payload_size: Option<usize>) -> bool {
    use crate::common::netns::{NetNS, ROOT_NETNS_NAME};
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
