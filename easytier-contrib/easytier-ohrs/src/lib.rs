mod native_log;

use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::instance_manager::NetworkInstanceManager;
use easytier::launcher::{ConfigSource, SOCKET_CREATE_CALLBACK};
use lazy_static::lazy_static;
use napi_derive_ohos::napi;
use napi_ohos::bindgen_prelude::*;
use napi_ohos::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use ohos_hilog_binding::{hilog_debug, hilog_error, hilog_warn};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, atomic};
use std::time::Duration;
use std::{format, thread};
use uuid::Uuid;

static INSTANCE_MANAGER: once_cell::sync::Lazy<NetworkInstanceManager> =
    once_cell::sync::Lazy::new(NetworkInstanceManager::new);

static TUN_FD: atomic::AtomicI32 = atomic::AtomicI32::new(-1);

lazy_static! {
    static ref PROTECT_FN: Mutex<Option<ThreadsafeFunction<u32, Promise<()>>>> = Mutex::new(None);
    static ref DNS_FN: Mutex<Option<ThreadsafeFunction<u32, Promise<()>>>> = Mutex::new(None);
    static ref SOCKET_SET: Mutex<HashSet<i32>> = Mutex::new(HashSet::new());
}

pub fn protect_socket(fd: i32, socket_addr: &SocketAddr) -> bool {
    if SOCKET_SET.lock().unwrap().contains(&fd) {
        hilog_debug!("[Rust] fd {} has been protected", fd);
        return true;
    }
    let guard = PROTECT_FN.lock().unwrap();
    match &*guard {
        Some(tsfn) => {
            tsfn.call(Ok(fd as u32), ThreadsafeFunctionCallMode::Blocking);
            thread::sleep(Duration::from_millis(10));
            hilog_debug!("[Rust] successful protect fd {} to {}", fd, socket_addr);
            SOCKET_SET.lock().unwrap().insert(fd);
            true
        }
        None => {
            hilog_error!("[Rust] protect_function is 404");
            false
        }
    }
}

#[napi]
pub fn init_protect_fn(func: ThreadsafeFunction<u32, Promise<()>>) {
    hilog_debug!("[Rust] init_protect_fn");
    let mut guard = PROTECT_FN.lock().unwrap();
    *guard = Some(func);
    let mut guard = SOCKET_CREATE_CALLBACK.lock().unwrap();
    *guard = Some(protect_socket);
}

#[napi(object)]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

#[napi]
pub fn set_global_tun(fd: i32) {
    hilog_debug!("[Rust] init global tun {}", fd);
    TUN_FD.store(fd, Ordering::SeqCst);
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
    let uuid = INSTANCE_MANAGER
        .run_network_instance(cfg, ConfigSource::FFI)
        .unwrap();
    let fd = TUN_FD.load(Ordering::SeqCst);
    if fd > 0 {
        match INSTANCE_MANAGER.set_tun_fd(&uuid, fd) {
            Ok(_) => {
                hilog_debug!("[Rust] set global tun:{} to {}", fd, inst_id);
            }
            Err(e) => {
                hilog_error!("[Rust] set global tun:{} to {} failed {}", fd, inst_id, e);
            }
        }
        hilog_debug!("[Rust] run_network_instance {}", inst_id);
    } else {
        hilog_warn!("[Rust] global tun is {}", fd);
    }
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
    if INSTANCE_MANAGER.list_network_instance_ids().is_empty() {
        SOCKET_SET.lock().unwrap().clear()
    }
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
