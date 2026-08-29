use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
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
pub struct StoredConfigRecord {
    pub meta: StoredConfigMeta,
    pub config_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredConfigList {
    pub configs: Vec<StoredConfigMeta>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportTomlResult {
    pub toml_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedConfigLinkPayload {
    pub config_json: String,
    pub display_name: Option<String>,
    pub only_start: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotImportResult {
    pub ok: bool,
    pub error_code: String,
    pub error_message: String,
    pub snapshot_invalid: bool,
}
