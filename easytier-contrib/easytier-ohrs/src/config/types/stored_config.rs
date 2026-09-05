use napi_derive_ohos::napi;
use serde::Serialize;

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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct StoredConfigRecord {
    pub meta: StoredConfigMeta,
    pub config_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct StoredConfigList {
    pub configs: Vec<StoredConfigMeta>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct ExportTomlResult {
    pub toml_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct SharedConfigLinkPayload {
    pub config_json: String,
    pub display_name: Option<String>,
    pub only_start: bool,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[napi(object)]
pub struct SnapshotImportResult {
    pub ok: bool,
    pub error_code: String,
    pub error_message: String,
    pub snapshot_invalid: bool,
}
