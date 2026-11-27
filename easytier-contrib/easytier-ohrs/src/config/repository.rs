use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::proto::api::manage::NetworkConfig;
use easytier::proto::common::CompressionAlgoPb;
use easytier_core::config::api_input::NetworkConfigExt;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

static RUNTIME_CONFIG_SNAPSHOTS: Lazy<Mutex<HashMap<String, RuntimeConfigSnapshot>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
pub struct RuntimeConfigSnapshot {
    pub display_name: String,
    pub config: NetworkConfig,
}

pub fn validate_config_id(config_id: &str) -> Result<(), String> {
    if config_id.is_empty() {
        return Err("config_id is required".to_string());
    }
    Uuid::parse_str(config_id)
        .map(|_| ())
        .map_err(|e| format!("invalid config_id {config_id}: {e}"))
}

pub fn cache_runtime_config_snapshot(
    config_id: String,
    display_name: String,
    config: NetworkConfig,
) {
    if let Ok(mut guard) = RUNTIME_CONFIG_SNAPSHOTS.lock() {
        guard.insert(
            config_id,
            RuntimeConfigSnapshot {
                display_name,
                config,
            },
        );
    }
}

pub fn clear_runtime_config_snapshot(config_id: &str) {
    if let Ok(mut guard) = RUNTIME_CONFIG_SNAPSHOTS.lock() {
        guard.remove(config_id);
    }
}

pub fn clear_all_runtime_config_snapshots() {
    if let Ok(mut guard) = RUNTIME_CONFIG_SNAPSHOTS.lock() {
        guard.clear();
    }
}

pub fn get_runtime_config_snapshot(config_id: &str) -> Option<RuntimeConfigSnapshot> {
    RUNTIME_CONFIG_SNAPSHOTS
        .lock()
        .ok()
        .and_then(|guard| guard.get(config_id).cloned())
}

pub fn get_default_config_json() -> Option<String> {
    let mut config = NetworkConfig::new_from_config(TomlConfigLoader::default()).ok()?;
    config.data_compress_algo = Some(CompressionAlgoPb::None as i32);
    serde_json::to_string(&config).ok()
}

pub fn normalize_config_json(config_json: &str, config_id: Option<&str>) -> Result<String, String> {
    let mut config = serde_json::from_str::<NetworkConfig>(config_json)
        .map_err(|e| format!("parse config json failed: {e}"))?;
    if let Some(id) = config_id.filter(|value| !value.trim().is_empty()) {
        validate_config_id(id)?;
        config.instance_id = Some(id.to_string());
    } else if let Some(existing_id) = config.instance_id.as_deref()
        && !existing_id.trim().is_empty()
    {
        validate_config_id(existing_id)?;
    }
    config
        .gen_config()
        .map_err(|e| format!("generate config failed: {e}"))?;
    serde_json::to_string(&config).map_err(|e| format!("serialize config failed: {e}"))
}

pub fn convert_network_config_to_toml(config_json: &str) -> Result<String, String> {
    let config = serde_json::from_str::<NetworkConfig>(config_json)
        .map_err(|e| format!("parse config json failed: {e}"))?;
    let toml = config
        .gen_config()
        .map_err(|e| format!("generate toml failed: {e}"))?;
    Ok(toml.dump())
}

pub fn convert_toml_to_network_config(toml_text: &str) -> Result<String, String> {
    let loader =
        TomlConfigLoader::new_from_str(toml_text).map_err(|e| format!("parse toml failed: {e}"))?;
    let config = NetworkConfig::new_from_config(loader)
        .map_err(|e| format!("convert toml to network config failed: {e}"))?;
    serde_json::to_string(&config).map_err(|e| format!("serialize network config failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_normalize_and_toml_roundtrip() {
        const CONFIG_ID: &str = "00000000-0000-0000-0000-000000000001";
        let raw = get_default_config_json().expect("default config json");
        let normalized = normalize_config_json(&raw, Some(CONFIG_ID)).expect("normalize config");
        assert!(normalized.contains(CONFIG_ID));

        let toml = convert_network_config_to_toml(&normalized).expect("export toml");
        assert!(toml.contains("instance_id"));

        let back = convert_toml_to_network_config(&toml).expect("import toml");
        let parsed: NetworkConfig = serde_json::from_str(&back).expect("parse back");
        assert_eq!(parsed.instance_id.as_deref(), Some(CONFIG_ID));
    }
}
