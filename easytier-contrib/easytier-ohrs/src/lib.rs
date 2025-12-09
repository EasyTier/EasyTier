mod native_log;

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

#[napi(object)]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

#[napi]
pub fn easytier_version() -> String {
    EASYTIER_VERSION.to_string()
}

#[napi]
pub fn set_tun_fd(inst_id: String, fd: i32) -> bool {
    match Uuid::try_parse(&inst_id) {
        Ok(uuid) => match INSTANCE_MANAGER.set_tun_fd(&uuid, fd) {
            Ok(_) => {
                hilog_debug!("[Rust] set tun fd {} to {}.", fd, inst_id);
                true
            }
            Err(e) => {
                hilog_error!("[Rust] cant set tun fd {} to {}. {}", fd, inst_id, e);
                false
            }
        },
        Err(e) => {
            hilog_error!("[Rust] cant covert {} to uuid. {}", inst_id, e);
            false
        }
    }
}

#[napi]
pub fn default_network_config() -> String {
    match NetworkConfig::new_from_config(TomlConfigLoader::default()) {
        Ok(result) => serde_json::to_string(&result).unwrap_or_else(|e| format!("ERROR {}", e)),
        Err(e) => {
            hilog_error!("[Rust] default_network_config failed {}", e);
            format!("ERROR {}", e)
        }
    }
}

#[napi]
pub fn convert_toml_to_network_config(cfg_str: String) -> String {
    match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(cfg) => match NetworkConfig::new_from_config(cfg) {
            Ok(result) => serde_json::to_string(&result).unwrap_or_else(|e| format!("ERROR {}", e)),
            Err(e) => {
                hilog_error!("[Rust] convert_toml_to_network_config failed {}", e);
                format!("ERROR {}", e)
            }
        },
        Err(e) => {
            hilog_error!("[Rust] convert_toml_to_network_config failed {}", e);
            format!("ERROR {}", e)
        }
    }
}

#[napi]
pub fn parse_network_config(cfg_json: String) -> bool {
    match serde_json::from_str::<NetworkConfig>(&cfg_json) {
        Ok(cfg) => match cfg.gen_config() {
            Ok(toml) => {
                hilog_debug!("[Rust] Convert to Toml {}", toml.dump());
                true
            }
            Err(e) => {
                hilog_error!("[Rust] parse config failed {}", e);
                false
            }
        },
        Err(e) => {
            hilog_error!("[Rust] parse config failed {}", e);
            false
        }
    }
}

#[napi]
pub fn run_network_instance(cfg_json: String) -> bool {
    let cfg = match serde_json::from_str::<NetworkConfig>(&cfg_json) {
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

    if INSTANCE_MANAGER.list_network_instance_ids().len() > 0 {
        hilog_error!("[Rust] there is a running instance!");
        return false;
    }

    let inst_id = cfg.get_id();
    if INSTANCE_MANAGER
        .list_network_instance_ids()
        .contains(&inst_id)
    {
        return false;
    }
    INSTANCE_MANAGER
        .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();
    true
}

#[napi]
pub fn stop_network_instance(inst_names: Vec<String>) {
    INSTANCE_MANAGER
        .delete_network_instance(
            inst_names
                .into_iter()
                .filter_map(|s| Uuid::parse_str(&s).ok())
                .collect(),
        )
        .unwrap();
    hilog_debug!("[Rust] stop_network_instance");
}

#[napi]
pub fn collect_network_infos() -> Vec<KeyValuePair> {
    let mut result = Vec::new();
    match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(map) => {
            for (uuid, info) in map.iter() {
                // convert value to json string
                let value = match serde_json::to_string(&info) {
                    Ok(value) => value,
                    Err(e) => {
                        hilog_error!("[Rust] failed to serialize instance {} info: {}", uuid, e);
                        continue;
                    }
                };
                result.push(KeyValuePair {
                    key: uuid.clone().to_string(),
                    value: value.clone(),
                });
            }
        }
        Err(_) => {}
    }
    result
}

#[napi]
pub fn collect_running_network() -> Vec<String> {
    INSTANCE_MANAGER
        .list_network_instance_ids()
        .clone()
        .into_iter()
        .map(|id| id.to_string())
        .collect()
}

#[napi]
pub fn is_running_network(inst_id: String) -> bool {
    match Uuid::try_parse(&inst_id) {
        Ok(uuid) => INSTANCE_MANAGER.list_network_instance_ids().contains(&uuid),
        Err(e) => {
            hilog_error!("[Rust] cant covert {} to uuid. {}", inst_id, e);
            false
        }
    }
}
