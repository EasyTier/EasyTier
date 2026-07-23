use easytier::proto::api::manage::NetworkConfig;
use easytier::common::config::NetworkConfigExt;
use serde_json::{Map, Value};
use uuid::Uuid;

pub(super) fn validate_config_id(config_id: &str) -> Result<(), String> {
    if config_id.is_empty() {
        return Err("config_id is required".to_string());
    }
    Uuid::parse_str(config_id)
        .map(|_| ())
        .map_err(|e| format!("invalid config_id {}: {}", config_id, e))
}

pub(super) fn is_valid_config_id(config_id: &str) -> bool {
    validate_config_id(config_id).is_ok()
}

pub(super) fn normalize_config_id(
    mut config: NetworkConfig,
    requested_id: String,
) -> Result<NetworkConfig, String> {
    validate_config_id(&requested_id)?;
    config.instance_id = Some(requested_id);
    Ok(config)
}

pub(super) fn validate_config_json(
    config_json: &str,
    config_id: String,
) -> Result<NetworkConfig, String> {
    let config = serde_json::from_str::<NetworkConfig>(config_json)
        .map_err(|e| format!("parse config json failed: {}", e))?;
    let config = normalize_config_id(config, config_id)?;
    config
        .gen_config()
        .map_err(|e| format!("generate toml failed: {}", e))?;
    Ok(config)
}

pub(super) fn config_to_top_level_map(config: &NetworkConfig) -> Option<Map<String, Value>> {
    serde_json::to_value(config).ok()?.as_object().cloned()
}
