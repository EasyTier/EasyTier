mod config_meta;
mod config_repo;
mod native_log;
mod runtime_state;
mod schema_service;
mod stored_config;

use config_meta::get_config_display_name;
use config_repo::{
    create_config_record, delete_config_record, export_config_toml, get_config_field_value,
    get_default_config_json, import_toml_config, init_config_store as init_repo_store,
    list_config_meta_json, save_config_record, set_config_field_value, start_kernel_with_config_id,
};
use runtime_state::{RuntimeAggregateState, TunAggregateState, runtime_instance_from_running_info};
use schema_service::{
    ConfigFieldMapping, NetworkConfigSchema,
    get_network_config_field_mappings as build_network_config_field_mappings,
    get_network_config_schema as build_network_config_schema,
};
use easytier::common::config::{ConfigFileControl, ConfigLoader, TomlConfigLoader};
use easytier::common::constants::EASYTIER_VERSION;
use easytier::instance_manager::NetworkInstanceManager;
use easytier::proto::api::manage::NetworkConfig;
use napi_derive_ohos::napi;
use ohos_hilog_binding::{hilog_debug, hilog_error};
use std::format;
use uuid::Uuid;

static INSTANCE_MANAGER: once_cell::sync::Lazy<NetworkInstanceManager> =
    once_cell::sync::Lazy::new(NetworkInstanceManager::new);

pub(crate) fn build_default_network_config_json() -> Result<String, String> {
    let config = NetworkConfig::new_from_config(TomlConfigLoader::default())
        .map_err(|e| format!("default_network_config failed {}", e))?;
    serde_json::to_string(&config).map_err(|e| format!("default_network_config failed {}", e))
}

pub(crate) fn run_network_instance_from_json(cfg_json: &str) -> bool {
    let cfg = match serde_json::from_str::<NetworkConfig>(cfg_json) {
        Ok(cfg) => match cfg.gen_config() {
            Ok(toml) => toml,
            Err(e) => {
                hilog_error!("[Rust] parse config failed {}", e);
                return false;
            }
        },
        Err(e) => {
            hilog_error!("[Rust] parse config failed {}", e);
            return false;
        }
    };

    if !INSTANCE_MANAGER.list_network_instance_ids().is_empty() {
        hilog_error!("[Rust] there is a running instance!");
        return false;
    }

    let inst_id = cfg.get_id();
    if INSTANCE_MANAGER.list_network_instance_ids().contains(&inst_id) {
        hilog_error!("[Rust] instance {} already exists", inst_id);
        return false;
    }

    match INSTANCE_MANAGER.run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG) {
        Ok(_) => true,
        Err(err) => {
            hilog_error!("[Rust] start_kernel failed for {}: {}", inst_id, err);
            false
        }
    }
}

fn parse_instance_uuid(config_id: &str) -> Option<Uuid> {
    match Uuid::parse_str(config_id) {
        Ok(uuid) => Some(uuid),
        Err(err) => {
            hilog_error!("[Rust] invalid config_id {}: {}", config_id, err);
            None
        }
    }
}

#[napi]
pub fn init_config_store(root_dir: String) -> bool {
    init_repo_store(root_dir)
}

#[napi]
pub fn list_configs() -> String {
    list_config_meta_json()
}

#[napi]
pub fn get_config_display_name_by_id(config_id: String) -> Option<String> {
    get_config_display_name(&config_id)
}

#[napi]
pub fn save_config(config_id: String, display_name: String, config_json: String) -> bool {
    save_config_record(config_id, display_name, config_json).is_some()
}

#[napi]
pub fn create_config(config_id: String, display_name: String) -> bool {
    create_config_record(config_id, display_name).is_some()
}

#[napi]
pub fn rename_stored_config(config_id: String, display_name: String) -> bool {
    config_meta::set_config_display_name(config_id, display_name).is_some()
}

#[napi]
pub fn delete_stored_config_meta(config_id: String) -> bool {
    delete_config_record(&config_id)
}

#[napi]
pub fn get_config(config_id: String) -> Option<String> {
    config_repo::load_config_json(&config_id)
}

#[napi]
pub fn get_default_config() -> Option<String> {
    get_default_config_json()
}

#[napi]
pub fn get_config_field(config_id: String, field: String) -> Option<String> {
    get_config_field_value(&config_id, &field)
}

#[napi]
pub fn set_config_field(config_id: String, field: String, json_value: String) -> bool {
    set_config_field_value(&config_id, &field, &json_value)
}

#[napi]
pub fn import_toml(toml_text: String, display_name: Option<String>) -> Option<String> {
    import_toml_config(toml_text, display_name).map(|record| record.meta.config_id)
}

#[napi]
pub fn export_toml(config_id: String) -> Option<String> {
    export_config_toml(&config_id).map(|ret| ret.toml_text)
}

#[napi]
pub fn start_kernel(config_id: String) -> bool {
    start_kernel_with_config_id(&config_id)
}

#[napi]
pub fn stop_kernel(config_id: String) -> bool {
    let Some(instance_id) = parse_instance_uuid(&config_id) else {
        return false;
    };

    INSTANCE_MANAGER
        .delete_network_instance(vec![instance_id])
        .map(|_| true)
        .unwrap_or_else(|err| {
            hilog_error!("[Rust] stop_kernel failed {}: {}", config_id, err);
            false
        })
}

#[napi]
pub fn set_tun_fd(config_id: String, fd: i32) -> bool {
    let Some(instance_id) = parse_instance_uuid(&config_id) else {
        return false;
    };

    INSTANCE_MANAGER
        .set_tun_fd(&instance_id, fd)
        .map(|_| true)
        .unwrap_or_else(|err| {
            hilog_error!("[Rust] set_tun_fd failed {}: {}", config_id, err);
            false
        })
}

#[napi]
pub fn get_network_config_schema() -> NetworkConfigSchema {
    build_network_config_schema()
}

#[napi]
pub fn get_network_config_field_mappings() -> Vec<ConfigFieldMapping> {
    build_network_config_field_mappings()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_plain_object_schema_contains_core_networkconfig_metadata() {
        let schema = get_network_config_schema();
        assert_eq!(schema.schema_name, "NetworkConfig");
        assert_eq!(schema.root.field_name, "NetworkConfig");
        assert!(schema
            .root
            .children
            .iter()
            .any(|field| field.field_name == "network_name"));
        let secure_mode = schema
            .root
            .children
            .iter()
            .find(|field| field.field_name == "secure_mode")
            .expect("secure_mode field");
        assert!(secure_mode
            .children
            .iter()
            .any(|field| field.field_name == "enabled"));
    }
}

#[napi]
pub fn get_runtime_snapshot() -> RuntimeAggregateState {
    let infos = match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(err) => {
            hilog_error!("[Rust] collect network infos failed {}", err);
            return RuntimeAggregateState {
                instances: vec![],
                tun: TunAggregateState {
                    active: false,
                    attached_instance_ids: vec![],
                    aggregated_routes: vec![],
                    dns_servers: vec![],
                    need_rebuild: false,
                },
                running_instance_count: 0,
            };
        }
    };

    let mut instances = Vec::with_capacity(infos.len());
    for (instance_uuid, info) in infos {
        let config_id = instance_uuid.to_string();
        let display_name = get_config_display_name(&config_id).unwrap_or_else(|| config_id.clone());
        instances.push(runtime_instance_from_running_info(config_id, display_name, info));
    }

    instances.sort_by(|a, b| a.display_name.cmp(&b.display_name).then_with(|| a.instance_id.cmp(&b.instance_id)));
    let attached_instance_ids = instances
        .iter()
        .filter(|instance| instance.tun_attached)
        .map(|instance| instance.instance_id.clone())
        .collect::<Vec<_>>();
    let aggregated_routes = instances
        .iter()
        .flat_map(|instance| instance.routes.iter().filter_map(|route| route.ipv4_cidr.clone().or(route.ipv6_cidr.clone())))
        .collect::<Vec<_>>();
    let running_instance_count = instances.iter().filter(|instance| instance.running).count() as i32;
    let tun_active = !attached_instance_ids.is_empty();

    RuntimeAggregateState {
        instances,
        tun: TunAggregateState {
            active: tun_active,
            attached_instance_ids,
            aggregated_routes,
            dns_servers: vec![],
            need_rebuild: false,
        },
        running_instance_count,
    }
}
