#![allow(dead_code)]

#[cfg(not(test))]
use napi_derive_ohos::napi;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(test), napi(object))]
pub struct SharedConfigLinkPayload {
    pub config_json: String,
    pub display_name: Option<String>,
    pub only_start: bool,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(not(test), napi(object))]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(not(test), napi(object))]
pub struct ConfigFieldMapping {
    pub field_name: String,
    pub field_number: i32,
}
