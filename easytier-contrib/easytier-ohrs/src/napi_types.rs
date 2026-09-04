#![allow(dead_code)]

use easytier_ohos_core::runtime::state::runtime_state as kernel_types;
use easytier_ohos_features::config::services::schema_service as feature_schema;
use easytier_ohos_features::config::types::stored_config as feature_types;
use napi_derive_ohos::napi;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct SocketProtectionRequest {
    pub request_id: String,
    pub socket_fd: i32,
    pub purpose: String,
}

impl From<easytier_ohos_core::socket_protection::SocketProtectionRequest>
    for SocketProtectionRequest
{
    fn from(value: easytier_ohos_core::socket_protection::SocketProtectionRequest) -> Self {
        Self {
            request_id: value.request_id.to_string(),
            socket_fd: value.socket_fd,
            purpose: value.purpose,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct StoredConfigMeta {
    pub config_id: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
    pub favorite: bool,
    pub temporary: bool,
}

impl From<feature_types::StoredConfigMeta> for StoredConfigMeta {
    fn from(value: feature_types::StoredConfigMeta) -> Self {
        Self {
            config_id: value.config_id,
            display_name: value.display_name,
            created_at: value.created_at,
            updated_at: value.updated_at,
            favorite: value.favorite,
            temporary: value.temporary,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct StoredConfigRecord {
    pub meta: StoredConfigMeta,
    pub config_json: String,
}

impl From<feature_types::StoredConfigRecord> for StoredConfigRecord {
    fn from(value: feature_types::StoredConfigRecord) -> Self {
        Self {
            meta: value.meta.into(),
            config_json: value.config_json,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct StoredConfigList {
    pub configs: Vec<StoredConfigMeta>,
}

impl From<feature_types::StoredConfigList> for StoredConfigList {
    fn from(value: feature_types::StoredConfigList) -> Self {
        Self {
            configs: value.configs.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct ExportTomlResult {
    pub toml_text: String,
}

impl From<feature_types::ExportTomlResult> for ExportTomlResult {
    fn from(value: feature_types::ExportTomlResult) -> Self {
        Self {
            toml_text: value.toml_text,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct SharedConfigLinkPayload {
    pub config_json: String,
    pub display_name: Option<String>,
    pub only_start: bool,
}

impl From<feature_types::SharedConfigLinkPayload> for SharedConfigLinkPayload {
    fn from(value: feature_types::SharedConfigLinkPayload) -> Self {
        Self {
            config_json: value.config_json,
            display_name: value.display_name,
            only_start: value.only_start,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct LocalSocketSyncMessage {
    pub message_type: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

impl From<feature_types::KeyValuePair> for KeyValuePair {
    fn from(value: feature_types::KeyValuePair) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct SnapshotImportResult {
    pub ok: bool,
    pub error_code: String,
    pub error_message: String,
    pub snapshot_invalid: bool,
}

impl From<feature_types::SnapshotImportResult> for SnapshotImportResult {
    fn from(value: feature_types::SnapshotImportResult) -> Self {
        Self {
            ok: value.ok,
            error_code: value.error_code,
            error_message: value.error_message,
            snapshot_invalid: value.snapshot_invalid,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct FieldOption {
    pub label: String,
    pub value: String,
}

impl From<feature_schema::FieldOption> for FieldOption {
    fn from(value: feature_schema::FieldOption) -> Self {
        Self {
            label: value.label,
            value: value.value,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct ValidationRule {
    pub rule_type: String,
    pub arg: String,
    pub message: String,
}

impl From<feature_schema::ValidationRule> for ValidationRule {
    fn from(value: feature_schema::ValidationRule) -> Self {
        Self {
            rule_type: value.rule_type,
            arg: value.arg,
            message: value.message,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct NetworkConfigSchema {
    pub node_kind: String,
    pub name: String,
    pub field_number: i32,
    pub type_name: Option<String>,
    pub semantic_type: Option<String>,
    pub value_kind: String,
    pub is_list: bool,
    pub required: bool,
    pub default_value_text: Option<String>,
    pub enum_options: Vec<FieldOption>,
    pub validations: Vec<ValidationRule>,
    pub children: Vec<NetworkConfigSchema>,
    pub definitions: Vec<NetworkConfigSchema>,
}

impl From<feature_schema::NetworkConfigSchema> for NetworkConfigSchema {
    fn from(value: feature_schema::NetworkConfigSchema) -> Self {
        Self {
            node_kind: value.node_kind,
            name: value.name,
            field_number: value.field_number,
            type_name: value.type_name,
            semantic_type: value.semantic_type,
            value_kind: value.value_kind,
            is_list: value.is_list,
            required: value.required,
            default_value_text: value.default_value_text,
            enum_options: value.enum_options.into_iter().map(Into::into).collect(),
            validations: value.validations.into_iter().map(Into::into).collect(),
            children: value.children.into_iter().map(Into::into).collect(),
            definitions: value.definitions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct ConfigFieldMapping {
    pub field_name: String,
    pub field_number: i32,
}

impl From<feature_schema::ConfigFieldMapping> for ConfigFieldMapping {
    fn from(value: feature_schema::ConfigFieldMapping) -> Self {
        Self {
            field_name: value.field_name,
            field_number: value.field_number,
        }
    }
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

impl From<kernel_types::PeerConnStats> for PeerConnStats {
    fn from(value: kernel_types::PeerConnStats) -> Self {
        Self {
            rx_bytes: value.rx_bytes,
            tx_bytes: value.tx_bytes,
            rx_packets: value.rx_packets,
            tx_packets: value.tx_packets,
            latency_us: value.latency_us,
        }
    }
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

impl From<kernel_types::PeerConnInfo> for PeerConnInfo {
    fn from(value: kernel_types::PeerConnInfo) -> Self {
        Self {
            conn_id: value.conn_id,
            my_peer_id: value.my_peer_id,
            peer_id: value.peer_id,
            features: value.features,
            tunnel_type: value.tunnel_type,
            local_addr: value.local_addr,
            remote_addr: value.remote_addr,
            resolved_remote_addr: value.resolved_remote_addr,
            stats: value.stats.map(Into::into),
            loss_rate: value.loss_rate,
            is_client: value.is_client,
            network_name: value.network_name,
            is_closed: value.is_closed,
            secure_auth_level: value.secure_auth_level,
            peer_identity_type: value.peer_identity_type,
        }
    }
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

impl From<kernel_types::PeerInfo> for PeerInfo {
    fn from(value: kernel_types::PeerInfo) -> Self {
        Self {
            peer_id: value.peer_id,
            default_conn_id: value.default_conn_id,
            directly_connected_conns: value.directly_connected_conns,
            conns: value.conns.into_iter().map(Into::into).collect(),
        }
    }
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

impl From<kernel_types::RouteView> for RouteView {
    fn from(value: kernel_types::RouteView) -> Self {
        Self {
            peer_id: value.peer_id,
            hostname: value.hostname,
            ipv4: value.ipv4,
            ipv4_cidr: value.ipv4_cidr,
            ipv6_cidr: value.ipv6_cidr,
            proxy_cidrs: value.proxy_cidrs,
            next_hop_peer_id: value.next_hop_peer_id,
            cost: value.cost,
            path_latency: value.path_latency,
            udp_nat_type: value.udp_nat_type,
            tcp_nat_type: value.tcp_nat_type,
            inst_id: value.inst_id,
            version: value.version,
            is_public_server: value.is_public_server,
        }
    }
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

impl From<kernel_types::MyNodeInfo> for MyNodeInfo {
    fn from(value: kernel_types::MyNodeInfo) -> Self {
        Self {
            virtual_ipv4: value.virtual_ipv4,
            virtual_ipv4_cidr: value.virtual_ipv4_cidr,
            hostname: value.hostname,
            version: value.version,
            peer_id: value.peer_id,
            listeners: value.listeners,
            vpn_portal_cfg: value.vpn_portal_cfg,
            udp_nat_type: value.udp_nat_type,
            tcp_nat_type: value.tcp_nat_type,
        }
    }
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

impl From<kernel_types::RuntimeInstanceState> for RuntimeInstanceState {
    fn from(value: kernel_types::RuntimeInstanceState) -> Self {
        Self {
            config_id: value.config_id,
            instance_id: value.instance_id,
            display_name: value.display_name,
            running: value.running,
            tun_required: value.tun_required,
            tun_attached: value.tun_attached,
            magic_dns_enabled: value.magic_dns_enabled,
            need_exit_node: value.need_exit_node,
            error_message: value.error_message,
            my_node_info: value.my_node_info.map(Into::into),
            events: value.events,
            routes: value.routes.into_iter().map(Into::into).collect(),
            peers: value.peers.into_iter().map(Into::into).collect(),
        }
    }
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

impl From<kernel_types::TunAggregateState> for TunAggregateState {
    fn from(value: kernel_types::TunAggregateState) -> Self {
        Self {
            active: value.active,
            attached_instance_ids: value.attached_instance_ids,
            aggregated_routes: value.aggregated_routes,
            dns_servers: value.dns_servers,
            need_rebuild: value.need_rebuild,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct RuntimeAggregateState {
    pub instances: Vec<RuntimeInstanceState>,
    pub tun: TunAggregateState,
    pub running_instance_count: i32,
}

impl From<kernel_types::RuntimeAggregateState> for RuntimeAggregateState {
    fn from(value: kernel_types::RuntimeAggregateState) -> Self {
        Self {
            instances: value.instances.into_iter().map(Into::into).collect(),
            tun: value.tun.into(),
            running_instance_count: value.running_instance_count,
        }
    }
}
