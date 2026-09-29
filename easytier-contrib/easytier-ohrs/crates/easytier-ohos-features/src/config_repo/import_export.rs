use crate::config::types::stored_config::{ExportTomlResult, StoredConfigRecord};
use easytier::common::config::{
    NetworkConfigExt, network_config_from_raw, parse_instance_config, serialize_raw_to_toml,
};
use easytier::proto::api::manage::NetworkConfig;

pub(super) fn export_config_toml_from_record(
    record: &StoredConfigRecord,
) -> Option<ExportTomlResult> {
    let config = serde_json::from_str::<NetworkConfig>(&record.config_json).ok()?;
    let instance_config = config.gen_config().ok()?;
    let toml_text = serialize_raw_to_toml(instance_config.raw()).ok()?;
    Some(ExportTomlResult {
        toml_text,
    })
}

pub(super) fn import_toml_to_record(
    toml_text: String,
    display_name: Option<String>,
    save_config_record: impl Fn(String, String, String) -> Option<StoredConfigRecord>,
) -> Option<StoredConfigRecord> {
    let instance_config = parse_instance_config("import", &toml_text).ok()?;
    let config = network_config_from_raw(instance_config.raw());

    let config_id = config.instance_id.clone()?;
    let name_from_toml = toml_text
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("instance_name") {
                return None;
            }
            trimmed.split_once('=').map(|(_, value)| {
                value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string()
            })
        })
        .filter(|name| !name.is_empty());

    let final_name = display_name
        .filter(|name| !name.is_empty())
        .or(name_from_toml)
        .unwrap_or_else(|| config_id.clone());

    let config_json = serde_json::to_string(&config).ok()?;
    save_config_record(config_id, final_name, config_json)
}
