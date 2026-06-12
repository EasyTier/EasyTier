use easytier::proto::{api, common};
use napi_derive_ohos::napi;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Mutex;
use url::Url;

static ATTACHED_TUN_INSTANCE_IDS: once_cell::sync::Lazy<Mutex<HashSet<String>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashSet::new()));

pub fn mark_tun_attached(instance_id: &str) {
    if let Ok(mut guard) = ATTACHED_TUN_INSTANCE_IDS.lock() {
        guard.insert(instance_id.to_string());
    }
}

pub fn clear_tun_attached(instance_id: &str) {
    if let Ok(mut guard) = ATTACHED_TUN_INSTANCE_IDS.lock() {
        guard.remove(instance_id);
    }
}

pub fn is_tun_attached(instance_id: &str) -> bool {
    ATTACHED_TUN_INSTANCE_IDS
        .lock()
        .map(|guard| guard.contains(instance_id))
        .unwrap_or(false)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct PeerConnStats {
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_packets: i64,
    pub tx_packets: i64,
    pub latency_us: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct PeerConnInfo {
    pub conn_id: String,
    pub my_peer_id: i64,
    pub peer_id: i64,
    pub features: Vec<String>,
    pub tunnel_type: Option<String>,
    pub local_addr: Option<String>,
    pub remote_addr: Option<String>,
    pub resolved_remote_addr: Option<String>,
    pub stats: Option<PeerConnStats>,
    pub loss_rate: Option<f64>,
    pub is_client: bool,
    pub network_name: Option<String>,
    pub is_closed: bool,
    pub secure_auth_level: Option<i32>,
    pub peer_identity_type: Option<i32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct PeerInfo {
    pub peer_id: i64,
    pub default_conn_id: Option<String>,
    pub directly_connected_conns: Vec<String>,
    pub conns: Vec<PeerConnInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct RouteView {
    pub peer_id: i64,
    pub hostname: Option<String>,
    pub ipv4: Option<String>,
    pub ipv4_cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
    pub proxy_cidrs: Vec<String>,
    pub next_hop_peer_id: Option<i64>,
    pub cost: Option<i32>,
    pub path_latency: Option<i64>,
    pub udp_nat_type: Option<i32>,
    pub tcp_nat_type: Option<i32>,
    pub inst_id: Option<String>,
    pub version: Option<String>,
    pub is_public_server: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct MyNodeInfo {
    pub virtual_ipv4: Option<String>,
    pub virtual_ipv4_cidr: Option<String>,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub peer_id: Option<i64>,
    pub listeners: Vec<String>,
    pub vpn_portal_cfg: Option<String>,
    pub udp_nat_type: Option<i32>,
    pub tcp_nat_type: Option<i32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct RuntimeInstanceState {
    pub config_id: String,
    pub instance_id: String,
    pub display_name: String,
    pub running: bool,
    pub tun_required: bool,
    pub tun_attached: bool,
    pub magic_dns_enabled: bool,
    pub need_exit_node: bool,
    pub error_message: Option<String>,
    pub my_node_info: Option<MyNodeInfo>,
    pub events: Vec<String>,
    pub routes: Vec<RouteView>,
    pub peers: Vec<PeerInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct TunAggregateState {
    pub active: bool,
    pub attached_instance_ids: Vec<String>,
    pub aggregated_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub need_rebuild: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct RuntimeAggregateState {
    pub instances: Vec<RuntimeInstanceState>,
    pub tun: TunAggregateState,
    pub running_instance_count: i32,
}

fn stringify_ipv4_inet(value: Option<common::Ipv4Inet>) -> Option<String> {
    value.map(|v| v.to_string())
}

fn stringify_ipv6_inet(value: Option<common::Ipv6Inet>) -> Option<String> {
    value.map(|v| v.to_string())
}

fn stringify_url(value: Option<common::Url>) -> Option<String> {
    value.map(|v| v.to_string())
}

fn stringify_uuid(value: Option<common::Uuid>) -> Option<String> {
    value.map(|v| v.to_string())
}

fn non_empty_string(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn config_virtual_ipv4_cidr(config: &api::manage::NetworkConfig) -> Option<String> {
    non_empty_string(config.virtual_ipv4.clone())
        .map(|ipv4| format!("{}/{}", ipv4, config.network_length.unwrap_or(24)))
}

fn config_endpoint_urls(config: &api::manage::NetworkConfig) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    if let Some(url) = non_empty_string(config.public_server_url.clone())
        && seen.insert(url.clone())
    {
        urls.push(url);
    }
    for raw in &config.peer_urls {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = trimmed.to_string();
        if seen.insert(value.clone()) {
            urls.push(value);
        }
    }
    urls
}

fn endpoint_url(url: &str) -> Option<Url> {
    Url::parse(url).ok()
}

fn endpoint_scheme(url: &str) -> Option<String> {
    endpoint_url(url)
        .map(|parsed| parsed.scheme().to_string())
        .or_else(|| {
            let scheme = url.split("://").next().unwrap_or("").trim();
            (!scheme.is_empty()).then_some(scheme.to_string())
        })
}

fn endpoint_label(url: &str) -> String {
    if let Some(parsed) = endpoint_url(url)
        && let Some(host) = parsed.host_str()
    {
        return format!("[Config] {}", host);
    }
    format!("[Config] {}", url)
}

fn endpoint_remote_display(url: &str) -> String {
    if let Some(parsed) = endpoint_url(url)
        && let Some(host) = parsed.host_str()
    {
        return parsed
            .port()
            .map(|port| format!("{}:{}", host, port))
            .unwrap_or_else(|| host.to_string());
    }
    url.to_string()
}

fn configured_peer_id(index: usize) -> i64 {
    9_000_000 + index as i64
}

fn configured_route_views(endpoints: &[String], public_server_url: Option<&str>) -> Vec<RouteView> {
    endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| RouteView {
            peer_id: configured_peer_id(index),
            hostname: Some(endpoint_label(endpoint)),
            ipv4: Some(endpoint_remote_display(endpoint)),
            ipv4_cidr: None,
            ipv6_cidr: None,
            proxy_cidrs: Vec::new(),
            next_hop_peer_id: None,
            cost: Some(0),
            path_latency: None,
            udp_nat_type: None,
            tcp_nat_type: None,
            inst_id: None,
            version: None,
            is_public_server: public_server_url.map(|url| url == endpoint),
        })
        .collect()
}

fn configured_peer_views(endpoints: &[String]) -> Vec<PeerInfo> {
    endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| {
            let conn_id = format!("configured-peer-{}", index);
            PeerInfo {
                peer_id: configured_peer_id(index),
                default_conn_id: Some(conn_id.clone()),
                directly_connected_conns: vec![conn_id.clone()],
                conns: vec![PeerConnInfo {
                    conn_id,
                    my_peer_id: 0,
                    peer_id: configured_peer_id(index),
                    features: Vec::new(),
                    tunnel_type: endpoint_scheme(endpoint),
                    local_addr: None,
                    remote_addr: Some(endpoint.clone()),
                    resolved_remote_addr: Some(endpoint_remote_display(endpoint)),
                    stats: None,
                    loss_rate: None,
                    is_client: true,
                    network_name: None,
                    is_closed: false,
                    secure_auth_level: None,
                    peer_identity_type: None,
                }],
            }
        })
        .collect()
}

fn optional_u32_to_i64(value: Option<u32>) -> Option<i64> {
    value.map(|v| v as i64)
}

fn optional_i32_to_i64(value: Option<i32>) -> Option<i64> {
    value.map(|v| v as i64)
}

fn route_to_view(route: api::instance::Route) -> RouteView {
    let stun = route.stun_info;
    let feature_flag = route.feature_flag;
    RouteView {
        peer_id: route.peer_id as i64,
        hostname: (!route.hostname.is_empty()).then_some(route.hostname),
        ipv4: route
            .ipv4_addr
            .as_ref()
            .and_then(|inet| inet.address.as_ref())
            .map(|addr| addr.to_string()),
        ipv4_cidr: stringify_ipv4_inet(route.ipv4_addr),
        ipv6_cidr: stringify_ipv6_inet(route.ipv6_addr),
        proxy_cidrs: route.proxy_cidrs,
        next_hop_peer_id: optional_u32_to_i64(route.next_hop_peer_id_latency_first)
            .or_else(|| Some(route.next_hop_peer_id as i64)),
        cost: Some(route.cost),
        path_latency: optional_i32_to_i64(route.path_latency_latency_first)
            .or_else(|| Some(route.path_latency as i64)),
        udp_nat_type: stun.as_ref().map(|info| info.udp_nat_type),
        tcp_nat_type: stun.as_ref().map(|info| info.tcp_nat_type),
        inst_id: (!route.inst_id.is_empty()).then_some(route.inst_id),
        version: (!route.version.is_empty()).then_some(route.version),
        is_public_server: feature_flag.map(|flag| flag.is_public_server),
    }
}

pub(crate) fn peer_conn_to_view(conn: api::instance::PeerConnInfo) -> PeerConnInfo {
    let stats = conn.stats.map(|stats| PeerConnStats {
        rx_bytes: stats.rx_bytes as i64,
        tx_bytes: stats.tx_bytes as i64,
        rx_packets: stats.rx_packets as i64,
        tx_packets: stats.tx_packets as i64,
        latency_us: stats.latency_us as i64,
    });

    PeerConnInfo {
        conn_id: conn.conn_id,
        my_peer_id: conn.my_peer_id as i64,
        peer_id: conn.peer_id as i64,
        features: conn.features,
        tunnel_type: conn.tunnel.as_ref().map(|t| t.tunnel_type.clone()),
        local_addr: conn
            .tunnel
            .as_ref()
            .and_then(|t| stringify_url(t.local_addr.clone())),
        remote_addr: conn
            .tunnel
            .as_ref()
            .and_then(|t| stringify_url(t.remote_addr.clone())),
        resolved_remote_addr: conn
            .tunnel
            .as_ref()
            .and_then(|t| stringify_url(t.resolved_remote_addr.clone())),
        stats,
        loss_rate: Some(conn.loss_rate as f64),
        is_client: conn.is_client,
        network_name: (!conn.network_name.is_empty()).then_some(conn.network_name),
        is_closed: conn.is_closed,
        secure_auth_level: Some(conn.secure_auth_level),
        peer_identity_type: Some(conn.peer_identity_type),
    }
}

fn peer_to_view(peer: api::instance::PeerInfo) -> PeerInfo {
    PeerInfo {
        peer_id: peer.peer_id as i64,
        default_conn_id: stringify_uuid(peer.default_conn_id),
        directly_connected_conns: peer
            .directly_connected_conns
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
        conns: peer.conns.into_iter().map(peer_conn_to_view).collect(),
    }
}

fn my_node_info_to_view(info: api::manage::MyNodeInfo) -> MyNodeInfo {
    MyNodeInfo {
        virtual_ipv4: info
            .virtual_ipv4
            .as_ref()
            .and_then(|inet| inet.address.as_ref())
            .map(|addr| addr.to_string()),
        virtual_ipv4_cidr: stringify_ipv4_inet(info.virtual_ipv4),
        hostname: (!info.hostname.is_empty()).then_some(info.hostname),
        version: (!info.version.is_empty()).then_some(info.version),
        peer_id: Some(info.peer_id as i64),
        listeners: info
            .listeners
            .into_iter()
            .map(|url| url.to_string())
            .collect(),
        vpn_portal_cfg: info.vpn_portal_cfg,
        udp_nat_type: info.stun_info.as_ref().map(|stun| stun.udp_nat_type),
        tcp_nat_type: info.stun_info.as_ref().map(|stun| stun.tcp_nat_type),
    }
}

pub fn runtime_instance_from_running_info(
    config_id: String,
    display_name: String,
    magic_dns_enabled: bool,
    need_exit_node: bool,
    info: api::manage::NetworkInstanceRunningInfo,
) -> RuntimeInstanceState {
    let tun_attached = info.running && is_tun_attached(&config_id);
    let tun_required = info.running && (info.dev_name != "no_tun" || tun_attached);

    RuntimeInstanceState {
        config_id: config_id.clone(),
        instance_id: config_id,
        display_name,
        running: info.running,
        tun_required,
        tun_attached,
        magic_dns_enabled,
        need_exit_node,
        error_message: info.error_msg,
        my_node_info: info.my_node_info.map(my_node_info_to_view),
        events: info.events,
        routes: info.routes.into_iter().map(route_to_view).collect(),
        peers: info.peers.into_iter().map(peer_to_view).collect(),
    }
}

pub fn runtime_instance_from_config_snapshot(
    config_id: String,
    display_name: String,
    config: api::manage::NetworkConfig,
    running: bool,
) -> RuntimeInstanceState {
    let tun_attached = running && is_tun_attached(&config_id);
    let tun_required =
        running && (config.dev_name.as_deref().unwrap_or("") != "no_tun" || tun_attached);
    let endpoint_urls = config_endpoint_urls(&config);
    let public_server_url = non_empty_string(config.public_server_url.clone());
    let my_node_info = MyNodeInfo {
        virtual_ipv4: non_empty_string(config.virtual_ipv4.clone()),
        virtual_ipv4_cidr: config_virtual_ipv4_cidr(&config),
        hostname: non_empty_string(config.hostname.clone()),
        version: None,
        peer_id: None,
        listeners: config.listener_urls.clone(),
        vpn_portal_cfg: None,
        udp_nat_type: None,
        tcp_nat_type: None,
    };

    RuntimeInstanceState {
        config_id: config_id.clone(),
        instance_id: config_id,
        display_name,
        running,
        tun_required,
        tun_attached,
        magic_dns_enabled: config.enable_magic_dns.unwrap_or(false),
        need_exit_node: !config.exit_nodes.is_empty(),
        error_message: None,
        my_node_info: Some(my_node_info),
        events: Vec::new(),
        routes: configured_route_views(&endpoint_urls, public_server_url.as_deref()),
        peers: configured_peer_views(&endpoint_urls),
    }
}
