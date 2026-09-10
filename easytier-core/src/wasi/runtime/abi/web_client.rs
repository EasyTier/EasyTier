use crate::{
    foundation::time::{clear_domain, enter_domain},
    wasi::{
        schema::WasiWebClientCreateConfig,
        web_client::{WEB_CLIENT_DOMAIN, WasiWebClientRuntime},
    },
};

use super::{
    ASYNC_ERROR, CONTEXT, INVALID_INPUT, INVALID_STATE, MAX_CREATE_CONFIG_LEN, read_guest_buffer,
    set_abi_error,
};

fn with_web_client(operation: impl FnOnce(&WasiWebClientRuntime) -> i32) -> i32 {
    CONTEXT.with(|context| {
        let web_client = context.web_client.borrow();
        match web_client.as_ref() {
            Some(web_client) => operation(web_client),
            None => {
                set_abi_error("WebClient is not running");
                INVALID_STATE
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_web_client_create(config_pointer: u32, config_length: u32) -> i32 {
    let encoded = match read_guest_buffer(config_pointer, config_length, MAX_CREATE_CONFIG_LEN) {
        Ok(encoded) => encoded,
        Err(error) => {
            set_abi_error(error);
            return INVALID_INPUT;
        }
    };
    let config: WasiWebClientCreateConfig = match serde_json::from_slice(&encoded) {
        Ok(config) => config,
        Err(error) => {
            set_abi_error(error);
            return INVALID_INPUT;
        }
    };
    if let Err(error) = config.validate() {
        set_abi_error(error);
        return INVALID_INPUT;
    }
    let process_runtime = CONTEXT.with(|context| {
        if context.web_client.borrow().is_some() {
            return None;
        }
        Some(context.factory.process_runtime.clone())
    });
    let Some(process_runtime) = process_runtime else {
        set_abi_error("WebClient is already running");
        return INVALID_STATE;
    };
    let web_client = match WasiWebClientRuntime::new(config, process_runtime) {
        Ok(web_client) => web_client,
        Err(error) => {
            set_abi_error(error);
            return ASYNC_ERROR;
        }
    };
    CONTEXT.with(|context| {
        *context.web_client.borrow_mut() = Some(web_client);
    });
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_web_client_drive() -> i32 {
    with_web_client(|web_client| {
        web_client.drive();
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_web_client_notify_completions() -> i32 {
    with_web_client(|web_client| {
        web_client.notify_host_completions();
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_web_client_next_deadline_millis() -> i64 {
    let mut result = i64::from(INVALID_STATE);
    let status = with_web_client(|web_client| {
        result = web_client
            .next_wait_millis()
            .map(|millis| i64::try_from(millis).unwrap_or(i64::MAX))
            .unwrap_or(i64::MAX);
        0
    });
    if status == 0 {
        result
    } else {
        i64::from(status)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_web_client_is_connected() -> i32 {
    with_web_client(|web_client| i32::from(web_client.is_connected()))
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_web_client_drop() -> i32 {
    let web_client = CONTEXT.with(|context| context.web_client.borrow_mut().take());
    let Some(web_client) = web_client else {
        set_abi_error("WebClient is not running");
        return INVALID_STATE;
    };
    {
        let _domain = enter_domain(WEB_CLIENT_DOMAIN);
        drop(web_client);
    }
    clear_domain(WEB_CLIENT_DOMAIN);
    0
}
