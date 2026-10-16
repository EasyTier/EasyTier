#[cfg(target_os = "linux")]
mod three_node;

#[cfg(target_os = "linux")]
mod network;

#[cfg(all(target_os = "linux", feature = "tun"))]
mod shared_virtual_nic;

mod ipv6_test;

#[cfg(target_os = "linux")]
mod credential_tests;

#[cfg(target_os = "linux")]
#[cfg(feature = "upnp")]
mod upnp_test;

use crate::instance::test_instance::TestInstance as Instance;
use easytier_core::config::PeerId;

trait InstanceTestExt {
    fn add_connector_url(&self, url: url::Url);

    fn peer_id(&self) -> PeerId;

    fn ring_listener_url(&self) -> url::Url;
}

impl InstanceTestExt for Instance {
    fn add_connector_url(&self, url: url::Url) {
        self.get_core_instance()
            .add_connector(url)
            .expect("test connector URL should be supported");
    }

    fn peer_id(&self) -> PeerId {
        self.get_core_instance().peer_id()
    }

    fn ring_listener_url(&self) -> url::Url {
        self.get_core_instance()
            .running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "ring")
            .expect("test instance has no running Ring listener")
    }
}

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

fn run_network_command(program: &str, args: &[&str]) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {:?} failed ({}): stdout={}, stderr={}",
        program,
        args,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn create_netns(name: &str, ipv4: &str, ipv6: &str) {
    // create netns
    run_network_command("ip", &["netns", "add", name]);

    // set lo up
    run_network_command(
        "ip",
        &["netns", "exec", name, "ip", "link", "set", "lo", "up"],
    );

    run_network_command(
        "ip",
        &[
            "link",
            "add",
            get_host_veth_name(name),
            "type",
            "veth",
            "peer",
            "name",
            get_guest_veth_name(name),
        ],
    );

    run_network_command(
        "ip",
        &["link", "set", get_guest_veth_name(name), "netns", name],
    );

    run_network_command(
        "ip",
        &[
            "netns",
            "exec",
            name,
            "ip",
            "link",
            "set",
            get_guest_veth_name(name),
            "up",
        ],
    );

    run_network_command("ip", &["link", "set", get_host_veth_name(name), "up"]);

    for ip in [ipv4, ipv6] {
        run_network_command(
            "ip",
            &[
                "netns",
                "exec",
                name,
                "ip",
                "addr",
                "add",
                ip,
                "dev",
                get_guest_veth_name(name),
            ],
        );
    }
}

pub fn add_ns_to_bridge(br_name: &str, ns_name: &str) {
    // use brctl to add ns to bridge
    run_network_command("brctl", &["addif", br_name, get_host_veth_name(ns_name)]);

    // set bridge up
    run_network_command("ip", &["link", "set", br_name, "up"]);
}

fn check_route(
    ipv4: &str,
    dst_peer_id: PeerId,
    routes: Vec<easytier_proto::core_peer::peer::Route>,
) {
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
    routes: Vec<easytier_proto::core_peer::peer::Route>,
    peer_id: PeerId,
    checker: impl Fn(&easytier_proto::core_peer::peer::Route) -> bool,
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
    core: &std::sync::Arc<crate::instance::composition::NativeCoreInstance>,
    ipv4: &str,
    dst_peer_id: PeerId,
    proxy_cidr: &str,
) {
    let now = std::time::Instant::now();
    loop {
        for r in core.route_snapshots().await.iter() {
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

pub async fn drop_insts(insts: Vec<Instance>) {
    let mut set = tokio::task::JoinSet::new();
    for mut inst in insts {
        set.spawn(async move {
            inst.clear_resources().await;
            let core = std::sync::Arc::downgrade(&inst.get_core_instance());
            drop(inst);
            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 5 && core.strong_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert_eq!(core.strong_count(), 0, "CoreInstance should be dropped");
        });
    }
    while set.join_next().await.is_some() {}
}

pub async fn ping_test(from_netns: &str, target_ip: &str, payload_size: Option<usize>) -> bool {
    use crate::common::netns::{NetNS, ROOT_NETNS_NAME};
    let namespace = NetNS::new(Some(ROOT_NETNS_NAME.to_owned()));
    let mut child = namespace
        .run(|| {
            tokio::process::Command::new("ip")
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
                .spawn()
        })
        .unwrap()
        .unwrap();
    let code = child.wait().await.unwrap();
    code.code().unwrap() == 0
}
