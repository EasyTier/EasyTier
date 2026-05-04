use crate::config::types::stored_config::{ExportTomlResult, StoredConfigRecord};
use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::proto::api::manage::NetworkConfig;

pub(super) fn export_config_toml_from_record(record: &StoredConfigRecord) -> Option<ExportTomlResult> {
    let config = serde_json::from_str::<NetworkConfig>(&record.config_json).ok()?;
    let toml = config.gen_config().ok()?;
    Some(ExportTomlResult { toml_text: toml.dump() })
}

pub(super) fn import_toml_to_record(
    toml_text: String,
    display_name: Option<String>,
    save_config_record: impl Fn(String, String, String) -> Option<StoredConfigRecord>,
) -> Option<StoredConfigRecord> {
    let config = NetworkConfig::new_from_config(TomlConfigLoader::new_from_str(&toml_text).ok()?).ok()?;

    let config_id = config.instance_id.clone()?;
    let name_from_toml = toml_text
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("instance_name") {
                return None;
            }
            trimmed
                .split_once('=')
                .map(|(_, value)| value.trim().trim_matches('"').trim_matches('\'').to_string())
        })
        .filter(|name| !name.is_empty());

    let final_name = display_name
        .filter(|name| !name.is_empty())
        .or(name_from_toml)
        .unwrap_or_else(|| config_id.clone());

    let config_json = serde_json::to_string(&config).ok()?;
    save_config_record(config_id, final_name, config_json)
}
