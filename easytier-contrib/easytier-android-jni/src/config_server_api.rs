use std::ptr;

use easytier_ffi::{
    in_config_server_callback, is_config_server_client_connected, start_config_server_client,
    stop_config_server_client,
};
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint};

use crate::{
    callback, error,
    strings::{jstring_to_cstring, optional_jstring_to_cstring},
};

pub(crate) fn start_config_server_client_jni(
    env: &mut JNIEnv,
    config_server_url: JString,
    hostname: JString,
    machine_id: JString,
    secure_mode: jboolean,
    callback_obj: JObject,
) -> jint {
    if in_config_server_callback() {
        error::throw_exception(
            env,
            "Cannot start config server client from config server callback",
        );
        return -1;
    }

    let config_server_url = match jstring_to_cstring(env, &config_server_url) {
        Ok(cstr) => cstr,
        Err(e) => {
            error::throw_exception(env, &format!("Invalid config server URL: {}", e));
            return -1;
        }
    };
    let hostname = match optional_jstring_to_cstring(env, &hostname) {
        Ok(cstr) => cstr,
        Err(e) => {
            error::throw_exception(env, &format!("Invalid hostname: {}", e));
            return -1;
        }
    };
    let machine_id = match jstring_to_cstring(env, &machine_id) {
        Ok(cstr) => cstr,
        Err(e) => {
            error::throw_exception(env, &format!("Invalid machine ID: {}", e));
            return -1;
        }
    };

    let callback_ref = if callback_obj.is_null() {
        None
    } else {
        match callback::new_callback(env, &callback_obj) {
            Ok(state) => Some(state),
            Err(e) => {
                error::throw_exception(env, &e);
                return -1;
            }
        }
    };

    let mut callback_guard = match callback::lock_callback_storage() {
        Ok(guard) => guard,
        Err(e) => {
            error::throw_exception(env, &e);
            return -1;
        }
    };
    if callback_guard.is_none() {
        error::clear_callback_error();
    }

    let callback_fn = callback::callback_fn(&callback_ref);
    let user_data = callback::user_data(&callback_ref);
    let result = unsafe {
        start_config_server_client(
            config_server_url.as_ptr(),
            hostname
                .as_ref()
                .map(|value| value.as_ptr())
                .unwrap_or(ptr::null()),
            machine_id.as_ptr(),
            secure_mode == JNI_TRUE,
            callback_fn,
            user_data,
        )
    };
    if result != 0 {
        if let Some(error_msg) = error::get_last_error() {
            error::throw_exception(env, &error_msg);
        }
        return result;
    }

    *callback_guard = callback_ref;
    result
}

pub(crate) fn stop_config_server_client_jni(mut env: JNIEnv, _class: JClass) -> jint {
    if in_config_server_callback() {
        let result = stop_config_server_client();
        if result != 0
            && let Some(error_msg) = error::get_last_error()
        {
            error::throw_exception(&mut env, &error_msg);
        }
        return result;
    }

    let mut callback_guard = match callback::lock_callback_storage() {
        Ok(guard) => guard,
        Err(e) => {
            error::throw_exception(&mut env, &e);
            return -1;
        }
    };

    let result = stop_config_server_client();
    if result != 0 {
        if let Some(error_msg) = error::get_last_error() {
            error::throw_exception(&mut env, &error_msg);
        }
        return result;
    }

    *callback_guard = None;
    result
}

pub(crate) fn is_config_server_client_connected_jni(_env: JNIEnv, _class: JClass) -> jboolean {
    if is_config_server_client_connected() != 0 {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}
