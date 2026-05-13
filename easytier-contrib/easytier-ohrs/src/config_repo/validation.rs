use easytier::proto::api::manage::NetworkConfig;
use serde_json::{Map, Value};

pub(super) fn normalize_config_id(
    mut config: NetworkConfig,
    requested_id: String,
) -> Result<NetworkConfig, String> {
    if requested_id.is_empty() {
        return Err("config_id is required".to_string());
    }
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
