mod native_log;

use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::instance_manager::NetworkInstanceManager;
use easytier::launcher::ConfigSource;
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
pub fn set_tun_fd(
    inst_id: String,
    fd: i32,
) -> bool {
    match Uuid::try_parse(&inst_id) {
        Ok(uuid) => {
            match INSTANCE_MANAGER.set_tun_fd(&uuid, fd) {
                Ok(_) => {
                    hilog_debug!("[Rust] set tun fd {} to {}.", fd, inst_id);
                    true
                }
                Err(e) => {
                    hilog_error!("[Rust] cant set tun fd {} to {}. {}", fd, inst_id, e);
                    false
                }
            }
        }
        Err(e) => {
            hilog_error!("[Rust] cant covert {} to uuid. {}", inst_id, e);
            false
        }
    }
}

#[napi]
pub fn parse_config(cfg_str: String) -> bool {
    match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(_) => {
            true
        }
        Err(e) => {
            hilog_error!("[Rust] parse config failed {}", e);
            false
        }
    }
}

#[napi]
pub fn run_network_instance(cfg_str: String) -> bool {
    let cfg = match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(cfg) => cfg,
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
        .run_network_instance(cfg, ConfigSource::FFI)
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
    match INSTANCE_MANAGER.collect_network_infos() {
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
        Ok(uuid) => {
            INSTANCE_MANAGER
                    .list_network_instance_ids()
                    .contains(&uuid)
        }
        Err(e) => {
            hilog_error!("[Rust] cant covert {} to uuid. {}", inst_id, e);
            false
        }
    }
    
}
