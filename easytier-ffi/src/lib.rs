use std::sync::Mutex;

use dashmap::DashMap;
use easytier::{
    common::config::{ConfigLoader as _, TomlConfigLoader},
    launcher::NetworkInstance,
};

static INSTANCE_MAP: once_cell::sync::Lazy<DashMap<String, NetworkInstance>> =
    once_cell::sync::Lazy::new(DashMap::new);

static ERROR_MSG: Mutex<[u8; 256]> = Mutex::new([0; 256]);

#[repr(C)]
pub struct KeyValuePair {
    pub key: *const std::ffi::c_char,
    pub value: *const std::ffi::c_char,
}

fn set_error_msg(msg: &str) {
    let bytes = msg.as_bytes();
    let mut msg_buf = ERROR_MSG.lock().unwrap();
    let len = bytes.len().min(msg_buf.len());
    msg_buf[..len].copy_from_slice(bytes);
    msg_buf[len] = 0; // null-terminate
}

#[no_mangle]
pub extern "C" fn free_string(s: *const std::ffi::c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = std::ffi::CString::from_raw(s as *mut std::ffi::c_char);
    }
}

#[no_mangle]
pub extern "C" fn parse_config(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        std::ffi::CStr::from_ptr(cfg_str)
            .to_string_lossy()
            .into_owned()
    };

    if let Err(e) = TomlConfigLoader::new_from_str(&cfg_str) {
        set_error_msg(&format!("failed to parse config: {}", e));
        return -1;
    }

    0
}

#[no_mangle]
pub extern "C" fn run_network_instance(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        std::ffi::CStr::from_ptr(cfg_str)
            .to_string_lossy()
            .into_owned()
    };
    let cfg = match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            set_error_msg(&format!("failed to parse config: {}", e));
            return -1;
        }
    };

    let inst_name = cfg.get_inst_name();

    if INSTANCE_MAP.contains_key(&inst_name) {
        set_error_msg("instance already exists");
        return -1;
    }

    let mut instance = NetworkInstance::new(cfg);
    if let Err(e) = instance.start().map_err(|e| e.to_string()) {
        set_error_msg(&format!("failed to start instance: {}", e));
        return -1;
    }

    INSTANCE_MAP.insert(inst_name, instance);

    0
}

#[no_mangle]
pub extern "C" fn retain_network_instance(
    inst_names: *const *const std::ffi::c_char,
    length: usize,
) -> std::ffi::c_int {
    let inst_names = unsafe {
        assert!(!inst_names.is_null());
        std::slice::from_raw_parts(inst_names, length)
            .iter()
            .map(|&name| {
                assert!(!name.is_null());
                std::ffi::CStr::from_ptr(name)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>()
    };

    let _ = INSTANCE_MAP.retain(|k, _| inst_names.contains(k));

    0
}

#[no_mangle]
pub extern "C" fn collect_network_infos(
    infos: *mut KeyValuePair,
    max_length: usize,
) -> std::ffi::c_int {
    let infos = unsafe {
        assert!(!infos.is_null());
        std::slice::from_raw_parts_mut(infos, max_length)
    };

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
                set_error_msg(&format!("failed to serialize instance info: {}", e));
                return -1;
            }
        };

        infos[index] = KeyValuePair {
            key: std::ffi::CString::new(key.clone()).unwrap().into_raw(),
            value: std::ffi::CString::new(value).unwrap().into_raw(),
        };
        index += 1;
    }

    index as std::ffi::c_int
}
