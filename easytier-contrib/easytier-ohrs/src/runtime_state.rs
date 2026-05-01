use easytier::proto::{api, common};
use napi_derive_ohos::napi;

#[napi(object)]
pub struct PeerConnStats {
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_packets: i64,
    pub tx_packets: i64,
    pub latency_us: i64,
}

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

#[napi(object)]
pub struct PeerInfo {
    pub peer_id: i64,
    pub default_conn_id: Option<String>,
    pub directly_connected_conns: Vec<String>,
    pub conns: Vec<PeerConnInfo>,
}

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

#[napi(object)]
pub struct RuntimeInstanceState {
    pub config_id: String,
    pub instance_id: String,
    pub display_name: String,
    pub running: bool,
    pub tun_required: bool,
    pub tun_attached: bool,
    pub error_message: Option<String>,
    pub my_node_info: Option<MyNodeInfo>,
    pub events: Vec<String>,
    pub routes: Vec<RouteView>,
    pub peers: Vec<PeerInfo>,
}

#[napi(object)]
pub struct TunAggregateState {
    pub active: bool,
    pub attached_instance_ids: Vec<String>,
    pub aggregated_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub need_rebuild: bool,
}

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
        cost: route.cost_latency_first.or(Some(route.cost)),
        path_latency: optional_i32_to_i64(route.path_latency_latency_first)
            .or_else(|| Some(route.path_latency as i64)),
        udp_nat_type: stun.as_ref().map(|info| info.udp_nat_type),
        tcp_nat_type: stun.as_ref().map(|info| info.tcp_nat_type),
        inst_id: (!route.inst_id.is_empty()).then_some(route.inst_id),
        version: (!route.version.is_empty()).then_some(route.version),
        is_public_server: feature_flag.map(|flag| flag.is_public_server),
    }
}

fn peer_conn_to_view(conn: api::instance::PeerConnInfo) -> PeerConnInfo {
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
        local_addr: conn.tunnel.as_ref().and_then(|t| stringify_url(t.local_addr.clone())),
        remote_addr: conn.tunnel.as_ref().and_then(|t| stringify_url(t.remote_addr.clone())),
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
        listeners: info.listeners.into_iter().map(|url| url.to_string()).collect(),
        vpn_portal_cfg: info.vpn_portal_cfg,
        udp_nat_type: info.stun_info.as_ref().map(|stun| stun.udp_nat_type),
        tcp_nat_type: info.stun_info.as_ref().map(|stun| stun.tcp_nat_type),
    }
}

pub fn runtime_instance_from_running_info(
    config_id: String,
    display_name: String,
    info: api::manage::NetworkInstanceRunningInfo,
) -> RuntimeInstanceState {
    let tun_required = info.dev_name != "no_tun" && info.running;
    let tun_attached = tun_required && !info.dev_name.is_empty();

    RuntimeInstanceState {
        config_id: config_id.clone(),
        instance_id: config_id,
        display_name,
        running: info.running,
        tun_required,
        tun_attached,
        error_message: info.error_msg,
        my_node_info: info.my_node_info.map(my_node_info_to_view),
        events: info.events,
        routes: info.routes.into_iter().map(route_to_view).collect(),
        peers: info.peers.into_iter().map(peer_to_view).collect(),
    }
}
