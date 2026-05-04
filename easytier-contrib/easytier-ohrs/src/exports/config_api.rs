use crate::config;

pub(crate) fn init_config_store(root_dir: String) -> bool {
    config::repository::init_config_store(root_dir)
}

pub(crate) fn list_configs() -> String {
    config::repository::list_config_meta_json()
}

pub(crate) fn save_config(config_id: String, display_name: String, config_json: String) -> bool {
    config::repository::save_config_record(config_id, display_name, config_json).is_some()
}

pub(crate) fn create_config(config_id: String, display_name: String) -> bool {
    config::repository::create_config_record(config_id, display_name).is_some()
}

pub(crate) fn delete_stored_config_meta(config_id: String) -> bool {
    config::repository::delete_config_record(&config_id)
}

pub(crate) fn get_config(config_id: String) -> Option<String> {
    config::repository::load_config_json(&config_id)
}

pub(crate) fn get_default_config() -> Option<String> {
    config::repository::get_default_config_json()
}

pub(crate) fn get_config_field(config_id: String, field: String) -> Option<String> {
    config::repository::get_config_field_value(&config_id, &field)
}

pub(crate) fn set_config_field(config_id: String, field: String, json_value: String) -> bool {
    config::repository::set_config_field_value(&config_id, &field, &json_value)
}

pub(crate) fn import_toml(toml_text: String, display_name: Option<String>) -> Option<String> {
    config::repository::import_toml_config(toml_text, display_name).map(|record| record.meta.config_id)
}

pub(crate) fn export_toml(config_id: String) -> Option<String> {
    config::repository::export_config_toml(&config_id).map(|ret| ret.toml_text)
}
