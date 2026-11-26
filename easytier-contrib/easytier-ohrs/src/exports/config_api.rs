use crate::config;

pub(crate) fn get_default_config() -> Option<String> {
    config::repository::get_default_config_json()
}

pub(crate) fn normalize_network_config(
    config_json: &str,
    config_id: Option<&str>,
) -> Result<String, String> {
    config::repository::normalize_config_json(config_json, config_id)
}

pub(crate) fn convert_toml_to_network_config(toml_text: &str) -> Result<String, String> {
    config::repository::convert_toml_to_network_config(toml_text)
}

pub(crate) fn convert_network_config_to_toml(config_json: &str) -> Result<String, String> {
    config::repository::convert_network_config_to_toml(config_json)
}
