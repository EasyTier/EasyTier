use std::{
    ffi::{CStr, c_char},
    ptr,
};

use easytier_ffi::{call_json_rpc, free_string};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;

use crate::{
    error::{get_last_error, throw_exception},
    strings::{jstring_to_cstring, optional_jstring_to_cstring},
};

pub(crate) fn call_json_rpc_jni(
    mut env: JNIEnv,
    _class: JClass,
    service_name: JString,
    method_name: JString,
    domain_name: JString,
    payload_json: JString,
) -> jstring {
    let service_name_cstr = match jstring_to_cstring(&mut env, &service_name) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid service name: {}", e));
            return ptr::null_mut();
        }
    };
    let method_name_cstr = match jstring_to_cstring(&mut env, &method_name) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid method name: {}", e));
            return ptr::null_mut();
        }
    };
    let domain_name_cstr = match optional_jstring_to_cstring(&mut env, &domain_name) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid domain name: {}", e));
            return ptr::null_mut();
        }
    };
    let payload_json_cstr = match jstring_to_cstring(&mut env, &payload_json) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid payload JSON: {}", e));
            return ptr::null_mut();
        }
    };

    let domain_name_ptr = domain_name_cstr
        .as_ref()
        .map_or(ptr::null(), |cstr| cstr.as_ptr());
    let mut response_ptr: *const c_char = ptr::null();
    let result = unsafe {
        call_json_rpc(
            service_name_cstr.as_ptr(),
            method_name_cstr.as_ptr(),
            domain_name_ptr,
            payload_json_cstr.as_ptr(),
            &mut response_ptr,
        )
    };

    if result != 0 {
        if let Some(error) = get_last_error() {
            throw_exception(&mut env, &error);
        }
        return ptr::null_mut();
    }

    if response_ptr.is_null() {
        throw_exception(&mut env, "JSON RPC returned a null response");
        return ptr::null_mut();
    }

    let response = unsafe { CStr::from_ptr(response_ptr) }
        .to_string_lossy()
        .into_owned();
    free_string(response_ptr);

    match env.new_string(&response) {
        Ok(jstr) => jstr.into_raw(),
        Err(_) => {
            throw_exception(&mut env, "Failed to create JSON RPC response string");
            ptr::null_mut()
        }
    }
}
