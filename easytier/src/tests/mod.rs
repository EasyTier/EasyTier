#[cfg(target_os = "linux")]
mod three_node;

use crate::common::PeerId;
use crate::peers::peer_manager::PeerManager;

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

pub fn create_netns(name: &str, ipv4: &str) {
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

    let _ = std::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            name,
            "ip",
            "addr",
            "add",
            ipv4,
            "dev",
            get_guest_veth_name(name),
        ])
        .output()
        .unwrap();
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

pub fn enable_log() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::TRACE.into())
        .from_env()
        .unwrap()
        .add_directive("tarpc=error".parse().unwrap());
    tracing_subscriber::fmt::fmt()
        .pretty()
        .with_env_filter(filter)
        .init();
}

fn check_route(ipv4: &str, dst_peer_id: PeerId, routes: Vec<crate::proto::cli::Route>) {
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

async fn wait_proxy_route_appear(
    mgr: &std::sync::Arc<PeerManager>,
    ipv4: &str,
    dst_peer_id: PeerId,
    proxy_cidr: &str,
) {
    let now = std::time::Instant::now();
    loop {
        for r in mgr.list_routes().await.iter() {
            let r = r;
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
