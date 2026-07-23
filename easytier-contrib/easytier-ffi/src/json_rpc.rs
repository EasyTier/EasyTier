use std::{
    ffi::{CString, c_char, c_int},
    sync::Arc,
};

use crate::{
    config_server::in_config_server_callback,
    error::set_error_msg,
    state::ffi_context,
    strings::{c_str_to_string, optional_c_str_to_string},
};

/// # Safety
/// See `crate::call_json_rpc`.
pub(crate) unsafe fn call_json_rpc(
    service_name: *const c_char,
    method_name: *const c_char,
    domain_name: *const c_char,
    payload_json: *const c_char,
    out_response_json: *mut *const c_char,
) -> c_int {
    if out_response_json.is_null() {
        set_error_msg("out_response_json is null");
        return -1;
    }
    unsafe {
        *out_response_json = std::ptr::null();
    }

    if in_config_server_callback() {
        set_error_msg("cannot call JSON RPC from config server callback");
        return -1;
    }

    let service_name = match unsafe { c_str_to_string(service_name, "service_name") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let method_name = match unsafe { c_str_to_string(method_name, "method_name") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let domain_name = match unsafe { optional_c_str_to_string(domain_name, "domain_name") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let payload_json = match unsafe { c_str_to_string(payload_json, "payload_json") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let payload = match serde_json::from_str::<serde_json::Value>(&payload_json) {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&format!("failed to parse payload_json: {}", err));
            return -1;
        }
    };

    let response =
        match ffi_context()
            .runtime
            .block_on(easytier_core::management::call_management_json_rpc(
                &ffi_context().manager.manager(),
                Arc::new(easytier::rpc_service::logger::NativeLoggerControl),
                &service_name,
                &method_name,
                domain_name.as_deref(),
                payload,
            )) {
            Ok(value) => value,
            Err(err) => {
                set_error_msg(&format!("RPC Error: {}", err));
                return -1;
            }
        };
    let response_json = match serde_json::to_string(&response) {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&format!("failed to serialize RPC response: {}", err));
            return -1;
        }
    };
    let response_json = match CString::new(response_json) {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&format!("failed to allocate RPC response: {}", err));
            return -1;
        }
    };

    unsafe {
        *out_response_json = response_json.into_raw();
    }
    0
}
