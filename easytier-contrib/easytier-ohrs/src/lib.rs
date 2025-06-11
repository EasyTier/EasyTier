mod native_log;

use dashmap::DashMap;
use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::launcher::{NetworkInstance, SOCKET_CREATE_CALLBACK};
use lazy_static::lazy_static;
use napi_derive_ohos::napi;
use napi_ohos::bindgen_prelude::*;
use napi_ohos::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use ohos_hilog_binding::{hilog_info, hilog_warn};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{atomic, Mutex};
use std::time::Duration;
use std::{format, thread};

static INSTANCE_MAP: once_cell::sync::Lazy<DashMap<String, NetworkInstance>> =
    once_cell::sync::Lazy::new(DashMap::new);

static ERROR_MSG: once_cell::sync::Lazy<Mutex<String>> =
    once_cell::sync::Lazy::new(|| Mutex::new(String::new()));

static TUN_FD: atomic::AtomicI32 = atomic::AtomicI32::new(-1);

lazy_static! {
    static ref PROTECT_FN: Mutex<Option<ThreadsafeFunction<u32, Promise<()>>>> = Mutex::new(None);
    static ref DNS_FN: Mutex<Option<ThreadsafeFunction<u32, Promise<()>>>> = Mutex::new(None);
    static ref SOCKET_SET: Mutex<HashSet<i32>> = Mutex::new(HashSet::new());
}

pub fn protect_socket(fd: i32, socket_addr: &SocketAddr) -> bool {
    if SOCKET_SET.lock().unwrap().contains(&fd) {
        hilog_info!("[Rust] fd {} has been protected", fd);
        return true;
    }
    let guard = PROTECT_FN.lock().unwrap();
    match &*guard {
        Some(tsfn) => {
            tsfn.call(Ok(fd as u32), ThreadsafeFunctionCallMode::Blocking);
            thread::sleep(Duration::from_millis(10));
            hilog_info!("[Rust] successful protect fd {} to {}", fd, socket_addr);
            SOCKET_SET.lock().unwrap().insert(fd);
            true
        },
        None => {
            hilog_warn!("[Rust] protect_function is 404");
            false
        },
    }
}

#[napi]
pub async fn init_protect_fn(func: ThreadsafeFunction<u32, Promise<()>>) {
    hilog_info!("[Rust] init_protect_fn");
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
    hilog_info!("[Rust] init global tun {}", fd);
    TUN_FD.store(fd, Ordering::SeqCst);
}

#[napi]
pub fn get_error_msg() -> String {
    let msg_buf = ERROR_MSG.lock().unwrap().clone();
    String::from(msg_buf)
}

#[napi]
pub fn parse_config(cfg_str: String) -> bool {
    if let Err(e) = TomlConfigLoader::new_from_str(&cfg_str) {
        set_error_msg(format!("failed to parse config: {:?}", e));
        return false;
    }
    true
}

#[napi]
pub fn run_network_instance(cfg_str: String) -> bool {
    let cfg = match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            set_error_msg(format!("failed to parse config: {}", e));
            return false;
        }
    };

    let inst_name = cfg.get_inst_name();
    if INSTANCE_MAP.contains_key(&inst_name) {
        set_error_msg(String::from("instance already exists"));
        return false;
    }

    let mut instance = NetworkInstance::new(cfg);
    let fd = TUN_FD.load(Ordering::SeqCst);
    if fd > 0 {
        hilog_info!("[Rust] set global tun:{} to {}", fd, inst_name);
        instance.set_tun_fd(fd);
    }else {
        hilog_warn!("[Rust] global tun is {}", fd);
    }
    if let Err(e) = instance.start().map_err(|e| e.to_string()) {
        set_error_msg(format!("failed to start instance: {}", e));
        return false;
    }
    let fd = TUN_FD.load(Ordering::SeqCst);
    if fd > 0 {
        hilog_info!("[Rust] set global tun:{} to {}", fd, inst_name);
        instance.set_tun_fd(fd);
    }else {
        hilog_warn!("[Rust] global tun is {}", fd);
    }
    hilog_info!("[Rust] run_network_instance {}", inst_name);
    INSTANCE_MAP.insert(inst_name, instance);
    true
}

#[napi]
pub fn retain_network_instance(
    inst_names: Vec<String>
) {
    hilog_info!("[Rust] retain_network_instance {:?}", inst_names);
    if inst_names.len() == 0 {
        INSTANCE_MAP.clear();
        return;
    }
    let _ = INSTANCE_MAP.retain(|k, _| inst_names.contains(k));
    if INSTANCE_MAP.is_empty() {
        SOCKET_SET.lock().unwrap().clear()
    }
}

#[napi]
pub fn stop_network_instance(
    inst_names: Vec<String>
) {
    hilog_info!("[Rust] stop_network_instance {:?}", inst_names);
    if inst_names.len() == 0 {
        return;
    }
    let _ = INSTANCE_MAP.retain(|k, _| !inst_names.contains(k));
    if INSTANCE_MAP.is_empty() {
        SOCKET_SET.lock().unwrap().clear()
    }
}

#[napi]
pub fn destroy_all_network_instance() -> bool {
    hilog_info!("[Rust] destroy_all_network_instance");
    INSTANCE_MAP.clear();
    SOCKET_SET.lock().unwrap().clear();
    true
}

#[napi]
pub fn collect_network_infos(max_length: i32) -> Vec<KeyValuePair> {
    let mut result = Vec::new();
    if max_length == 0 {
        return result;
    }
    let mut index = 0;
    for instance in INSTANCE_MAP.iter() {
        if index >= max_length {
            break;
        }
        let key = instance.key();
        let Some(value) = instance.get_running_info() else {
            continue;
        };
        // convert value to json string
        let value = match serde_json::to_string(&value) {
            Ok(value) => value,
            Err(e) => {
                set_error_msg(format!("failed to serialize instance info: {}", e));
                return result;
            }
        };
        result.push(
            KeyValuePair {
                key: key.clone(),
                value: value.clone(),
            }
        );
        index += 1;
    }
    result
}

#[napi]
pub fn reflash() {
    hilog_warn!("aa")
}

fn set_error_msg(msg: String) {
    let mut msg_buf = ERROR_MSG.lock().unwrap();
    *msg_buf = msg;
}
