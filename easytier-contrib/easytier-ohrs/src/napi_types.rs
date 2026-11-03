#![allow(dead_code)]

use easytier_ohos_core::runtime::state::runtime_state as kernel_types;
use easytier_ohos_features::config::services::schema_service as feature_schema;
use easytier_ohos_features::config::types::stored_config as feature_types;
use easytier_proto::CollectionExt;
use napi_derive_ohos::napi;
use refield::Refield;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Refield)]
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
        SocketProtectionRequest! {
            request_id: value.request_id.to_string(),
            ..value
        }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
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
        StoredConfigMeta! { ..value }
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

#[derive(Debug, Clone, Serialize, Refield)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct StoredConfigList {
    pub configs: Vec<StoredConfigMeta>,
}

impl From<feature_types::StoredConfigList> for StoredConfigList {
    fn from(value: feature_types::StoredConfigList) -> Self {
        StoredConfigList! {
            configs: value.configs.convert(),
            ..value
        }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct ExportTomlResult {
    pub toml_text: String,
}

impl From<feature_types::ExportTomlResult> for ExportTomlResult {
    fn from(value: feature_types::ExportTomlResult) -> Self {
        ExportTomlResult! { ..value }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct SharedConfigLinkPayload {
    pub config_json: String,
    pub display_name: Option<String>,
    pub only_start: bool,
}

impl From<feature_types::SharedConfigLinkPayload> for SharedConfigLinkPayload {
    fn from(value: feature_types::SharedConfigLinkPayload) -> Self {
        SharedConfigLinkPayload! { ..value }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct LocalSocketSyncMessage {
    pub message_type: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, Serialize, Refield)]
#[napi(object)]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

impl From<feature_types::KeyValuePair> for KeyValuePair {
    fn from(value: feature_types::KeyValuePair) -> Self {
        KeyValuePair! { ..value }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
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
        SnapshotImportResult! { ..value }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
#[napi(object)]
pub struct FieldOption {
    pub label: String,
    pub value: String,
}

impl From<feature_schema::FieldOption> for FieldOption {
    fn from(value: feature_schema::FieldOption) -> Self {
        FieldOption! { ..value }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
#[napi(object)]
pub struct ValidationRule {
    pub rule_type: String,
    pub arg: String,
    pub message: String,
}

impl From<feature_schema::ValidationRule> for ValidationRule {
    fn from(value: feature_schema::ValidationRule) -> Self {
        ValidationRule! { ..value }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
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
        NetworkConfigSchema! {
            enum_options: value.enum_options.convert(),
            validations: value.validations.convert(),
            children: value.children.convert(),
            definitions: value.definitions.convert(),
            ..value
        }
    }
}

#[derive(Debug, Clone, Serialize, Refield)]
#[napi(object)]
pub struct ConfigFieldMapping {
    pub field_name: String,
    pub field_number: i32,
}

impl From<feature_schema::ConfigFieldMapping> for ConfigFieldMapping {
    fn from(value: feature_schema::ConfigFieldMapping) -> Self {
        ConfigFieldMapping! { ..value }
    }
}

#[derive(Serialize, Refield)]
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
        PeerConnStats! { ..value }
    }
}

#[derive(Serialize, Refield)]
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
        PeerConnInfo! {
            stats: value.stats.map(Into::into),
            ..value
        }
    }
}

#[derive(Serialize, Refield)]
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
        PeerInfo! {
            conns: value.conns.convert(),
            ..value
        }
    }
}

#[derive(Serialize, Refield)]
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
        RouteView! { ..value }
    }
}

#[derive(Serialize, Refield)]
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
        MyNodeInfo! { ..value }
    }
}

#[derive(Serialize, Refield)]
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
        RuntimeInstanceState! {
            my_node_info: value.my_node_info.map(Into::into),
            routes: value.routes.convert(),
            peers: value.peers.convert(),
            ..value
        }
    }
}

#[derive(Serialize, Refield)]
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
        TunAggregateState! { ..value }
    }
}

#[derive(Serialize, Refield)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct RuntimeAggregateState {
    pub instances: Vec<RuntimeInstanceState>,
    pub tun: TunAggregateState,
    pub running_instance_count: i32,
}

impl From<kernel_types::RuntimeAggregateState> for RuntimeAggregateState {
    fn from(value: kernel_types::RuntimeAggregateState) -> Self {
        RuntimeAggregateState! {
            instances: value.instances.convert(),
            tun: value.tun.into(),
            ..value
        }
    }
}
