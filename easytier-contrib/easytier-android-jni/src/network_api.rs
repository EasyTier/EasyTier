use std::{ffi::CStr, ptr};

use easytier::proto::api::manage::{NetworkInstanceRunningInfo, NetworkInstanceRunningInfoMap};
use easytier_ffi::{
    KeyValuePair, collect_network_infos, free_string, list_instance, parse_config,
    retain_network_instance, run_network_instance, set_tun_fd,
};
use jni::JNIEnv;
use jni::objects::{JClass, JObjectArray, JString};
use jni::sys::{jint, jstring};

use crate::{
    error::{get_last_error, throw_exception},
    strings::jstring_to_cstring,
};

pub(crate) fn set_tun_fd_jni(
    mut env: JNIEnv,
    _class: JClass,
    inst_name: JString,
    fd: jint,
) -> jint {
    let inst_name_cstr = match jstring_to_cstring(&mut env, &inst_name) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid instance name: {}", e));
            return -1;
        }
    };
    unsafe {
        let result = set_tun_fd(inst_name_cstr.as_ptr(), fd);
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

pub(crate) fn parse_config_jni(mut env: JNIEnv, _class: JClass, config: JString) -> jint {
    let config_cstr = match jstring_to_cstring(&mut env, &config) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid config string: {}", e));
            return -1;
        }
    };
    unsafe {
        let result = parse_config(config_cstr.as_ptr());
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

pub(crate) fn run_network_instance_jni(mut env: JNIEnv, _class: JClass, config: JString) -> jint {
    let config_cstr = match jstring_to_cstring(&mut env, &config) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid config string: {}", e));
            return -1;
        }
    };
    unsafe {
        let result = run_network_instance(config_cstr.as_ptr());
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

pub(crate) fn retain_network_instance_jni(
    mut env: JNIEnv,
    _class: JClass,
    instance_names: JObjectArray,
) -> jint {
    if instance_names.is_null() {
        return retain_all(&mut env);
    }

    let array_length = match env.get_array_length(&instance_names) {
        Ok(len) => len as usize,
        Err(e) => {
            throw_exception(&mut env, &format!("Failed to get array length: {:?}", e));
            return -1;
        }
    };

    if array_length == 0 {
        return retain_all(&mut env);
    }

    let mut c_strings = Vec::with_capacity(array_length);
    let mut c_string_ptrs = Vec::with_capacity(array_length);

    for i in 0..array_length {
        let java_string = match env.get_object_array_element(&instance_names, i as i32) {
            Ok(obj) => obj,
            Err(e) => {
                throw_exception(
                    &mut env,
                    &format!("Failed to get array element {}: {:?}", i, e),
                );
                return -1;
            }
        };

        if java_string.is_null() {
            throw_exception(
                &mut env,
                &format!("Invalid instance name at index {}: null", i),
            );
            return -1;
        }

        let jstring = JString::from(java_string);
        let c_string = match jstring_to_cstring(&mut env, &jstring) {
            Ok(cstr) => cstr,
            Err(e) => {
                throw_exception(
                    &mut env,
                    &format!("Invalid instance name at index {}: {}", i, e),
                );
                return -1;
            }
        };

        c_string_ptrs.push(c_string.as_ptr());
        c_strings.push(c_string);
    }

    unsafe {
        let result = retain_network_instance(c_string_ptrs.as_ptr(), c_string_ptrs.len());
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

fn retain_all(env: &mut JNIEnv) -> jint {
    unsafe {
        let result = retain_network_instance(ptr::null(), 0);
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(env, &error);
        }
        result
    }
}

pub(crate) fn collect_network_infos_jni(
    mut env: JNIEnv,
    _class: JClass,
    max_length: jint,
) -> jstring {
    let max_length = max_length.max(0) as usize;
    let mut infos = vec![
        KeyValuePair {
            key: ptr::null(),
            value: ptr::null(),
        };
        max_length
    ];

    unsafe {
        let count = collect_network_infos(infos.as_mut_ptr(), max_length);
        if count < 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
            return ptr::null_mut();
        }

        let mut ret = NetworkInstanceRunningInfoMap::default();
        for info in infos.iter().take(count as usize) {
            let key_ptr = info.key;
            let val_ptr = info.value;
            if key_ptr.is_null() || val_ptr.is_null() {
                break;
            }

            let key = CStr::from_ptr(key_ptr).to_string_lossy().into_owned();
            let val = CStr::from_ptr(val_ptr).to_string_lossy().into_owned();
            free_string(key_ptr);
            free_string(val_ptr);
            let value = match serde_json::from_str::<NetworkInstanceRunningInfo>(&val) {
                Ok(v) => v,
                Err(_) => {
                    throw_exception(&mut env, "Failed to parse JSON");
                    continue;
                }
            };
            ret.map.insert(key, value);
        }

        let json_str = serde_json::to_string(&ret).unwrap_or_else(|_| "{}".to_string());
        match env.new_string(&json_str) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => {
                throw_exception(&mut env, "Failed to create JSON string");
                ptr::null_mut()
            }
        }
    }
}

pub(crate) fn list_instances_jni(mut env: JNIEnv, _class: JClass, max_length: jint) -> jstring {
    let max_length = max_length.max(0) as usize;
    let mut infos = vec![
        KeyValuePair {
            key: ptr::null(),
            value: ptr::null(),
        };
        max_length
    ];

    unsafe {
        let count = list_instance(infos.as_mut_ptr(), max_length);
        if count < 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
            return ptr::null_mut();
        }

        let mut ret = serde_json::Map::new();
        for info in infos.iter().take(count as usize) {
            let key_ptr = info.key;
            let val_ptr = info.value;
            if key_ptr.is_null() || val_ptr.is_null() {
                break;
            }

            let key = CStr::from_ptr(key_ptr).to_string_lossy().into_owned();
            let val = CStr::from_ptr(val_ptr).to_string_lossy().into_owned();
            free_string(key_ptr);
            free_string(val_ptr);
            ret.insert(key, serde_json::Value::String(val));
        }

        let json_str = serde_json::Value::Object(ret).to_string();
        match env.new_string(&json_str) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => {
                throw_exception(&mut env, "Failed to create instance list JSON string");
                ptr::null_mut()
            }
        }
    }
}
