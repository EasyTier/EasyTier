use std::{ffi::CString, fs::File, sync::{Arc, Mutex}};

use easytier::{
    common::{config::{ConfigFileControl, TomlConfigLoader}, global_ctx::GlobalCtxEvent},
    launcher::NetworkInstance,
};
use once_cell::sync::Lazy;
use tracing_oslog::OsLogger;
use tracing_subscriber::layer::SubscriberExt as _;

static INSTANCE: Lazy<Arc<Mutex<Option<NetworkInstance>>>> = Lazy::new(|| Arc::new(Mutex::new(None)));

/// # Safety
/// Initialize logger
#[no_mangle]
pub extern "C" fn init_logger(
    path: *const std::ffi::c_char,
    level: *const std::ffi::c_char,
    err_msg: *mut *const std::ffi::c_char,
) -> std::ffi::c_int {
    let path = unsafe {
        std::ffi::CStr::from_ptr(path)
            .to_string_lossy()
            .into_owned()
    };
    let level = unsafe {
        std::ffi::CStr::from_ptr(level)
            .to_string_lossy()
            .into_owned()
    };

    let impl_func = || {
        let file = File::create(path).map_err(|e| e.to_string())?;
        let collector = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(level))
            .with(tracing_subscriber::fmt::layer().with_writer(file).with_ansi(false))
            .with(OsLogger::new("site.yinmo.easytier.tunnel", "rust"));
        tracing::subscriber::set_global_default(collector).map_err(|e| e.to_string())
    };

    match impl_func() {
        Ok(_) => 0,
        Err(e) => {
            if !err_msg.is_null() {
                if let Ok(cstr) = CString::new(e) {
                    unsafe { *err_msg = cstr.into_raw(); }
                };
            }
            -1
        }
    }
}

/// # Safety
/// Set the tun fd
#[no_mangle]
pub extern "C" fn set_tun_fd(
    fd: std::ffi::c_int,
    err_msg: *mut *const std::ffi::c_char,
) -> std::ffi::c_int {
    let impl_func = || -> Result<(), String> {
        let mut inst = INSTANCE.lock().map_err(|e| e.to_string())?;
        let inst = inst.as_mut().ok_or("no running instance".to_string())?;
        inst.set_tun_fd(fd);
        Ok(())
    };

    match impl_func() {
        Ok(_) => 0,
        Err(e) => {
            if !err_msg.is_null() {
                if let Ok(cstr) = CString::new(e) {
                    unsafe { *err_msg = cstr.into_raw(); }
                };
            }
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *const std::ffi::c_char) {
    if s.is_null() { return; }
    unsafe {
        let _ = std::ffi::CString::from_raw(s as *mut std::ffi::c_char);
    }
}

/// # Safety
/// Run the network instance
#[no_mangle]
pub extern "C" fn run_network_instance(
    cfg_str: *const std::ffi::c_char,
    err_msg: *mut *const std::ffi::c_char,
) -> std::ffi::c_int {
    let impl_func = || {
        if cfg_str.is_null() {
            return Err("cfg_str is nullptr".to_string());
        }
        let cfg_str = unsafe {
            std::ffi::CStr::from_ptr(cfg_str)
                .to_string_lossy()
                .into_owned()
        };
        let cfg = TomlConfigLoader::new_from_str(&cfg_str).map_err(|e| e.to_string())?;
        let mut inst = INSTANCE.lock().map_err(|e| e.to_string())?;
        let mut new_inst = NetworkInstance::new(cfg, ConfigFileControl::STATIC_CONFIG);
        new_inst.start().map_err(|e| e.to_string())?;
        *inst = Some(new_inst);
        Ok(())
    };

    match impl_func() {
        Ok(_) => 0,
        Err(e) => {
            if !err_msg.is_null() {
                if let Ok(cstr) = CString::new(e) {
                    unsafe { *err_msg = cstr.into_raw(); }
                };
            }
            -1
        }
    }
}

/// # Safety
/// Retain the network instance
#[no_mangle]
pub extern "C" fn stop_network_instance() -> std::ffi::c_int {
    match INSTANCE.lock() {
        Ok(mut inst) => {
            inst.as_mut()
                .and_then(|inst| inst.get_stop_notifier())
                .map(|stop| stop.notify_waiters());
            *inst = None;
            0
        },
        Err(_) => -1,
    }
}

/// # Safety
/// Register stop callback
#[no_mangle]
pub extern "C" fn register_stop_callback(
    callback: Option<extern "C" fn()>,
    err_msg: *mut *const std::ffi::c_char,
) -> std::ffi::c_int {
    let impl_func = || -> Result<(), String> {
        let callback = callback.ok_or("callback is null".to_string())?;
        let inst = INSTANCE.lock().map_err(|e| e.to_string())?;
        let inst = inst.as_ref().ok_or("no running instance".to_string())?;
        let stop = inst.get_stop_notifier().ok_or("no stop notifier".to_string())?;
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new();
            if let Ok(runtime) = runtime {
                runtime.block_on(stop.notified());
                callback();
            }
        });
        Ok(())
    };

    match impl_func() {
        Ok(_) => 0,
        Err(e) => {
            if !err_msg.is_null() {
                if let Ok(cstr) = CString::new(e) {
                    unsafe { *err_msg = cstr.into_raw(); }
                };
            }
            -1
        }
    }
}

/// # Safety
/// Register running info callback
#[no_mangle]
pub extern "C" fn register_running_info_callback(
    callback: Option<extern "C" fn()>,
    err_msg: *mut *const std::ffi::c_char,
) -> std::ffi::c_int {
    let impl_func = || -> Result<(), String> {
        let callback = callback.ok_or("callback is null".to_string())?;
        let inst = INSTANCE.lock().map_err(|e| e.to_string())?;
        let inst = inst.as_ref().ok_or("no running instance".to_string())?;
        let mut ev = inst
            .subscribe_event()
            .ok_or("no event subscriber".to_string())?;
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new();
            if let Ok(runtime) = runtime {
                runtime.block_on(async move {
                    loop {
                        match ev.recv().await {
                            Ok(event) => match event {
                                GlobalCtxEvent::DhcpIpv4Changed(_, _)
                                | GlobalCtxEvent::ProxyCidrsUpdated(_, _)
                                | GlobalCtxEvent::ConfigPatched(_) => {
                                    callback();
                                }
                                _ => {}
                            },
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                break;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                continue;
                            }
                        }
                    }
                });
            }
        });
        Ok(())
    };

    match impl_func() {
        Ok(_) => 0,
        Err(e) => {
            if !err_msg.is_null() {
                if let Ok(cstr) = CString::new(e) {
                    unsafe { *err_msg = cstr.into_raw(); }
                };
            }
            -1
        }
    }
}

/// # Safety
/// Get running info
#[no_mangle]
pub extern "C" fn get_running_info(
    json: *mut *const std::ffi::c_char,
    err_msg: *mut *const std::ffi::c_char,
) -> std::ffi::c_int {
    let impl_func = || -> Result<(), String> {
        if json.is_null() {
            return Err("json is a nullptr".to_string());
        }
        let inst = INSTANCE.lock().map_err(|e| e.to_string())?;
        let inst = inst.as_ref().ok_or("no running instance".to_string())?;
        let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let info = runtime.block_on(inst.get_running_info()).map_err(|e| e.to_string())?;
        let info = serde_json::to_string(&info).map_err(|e| e.to_string())?;
        let cstr = CString::new(info).map_err(|e| e.to_string())?;
        unsafe {
            *json = cstr.into_raw()
        }
        Ok(())
    };

    match impl_func() {
        Ok(_) => 0,
        Err(e) => {
            if !err_msg.is_null() {
                if let Ok(cstr) = CString::new(e) {
                    unsafe { *err_msg = cstr.into_raw(); }
                };
            }
            -1
        }
    }
}

/// # Safety
/// Get latest error message
#[no_mangle]
pub extern "C" fn get_latest_error_msg(
    msg: *mut *const std::ffi::c_char,
    err_msg: *mut *const std::ffi::c_char,
) -> std::ffi::c_int {
    let impl_func = || -> Result<(), String> {
        if msg.is_null() {
            return Err("msg is a nullptr".to_string());
        }
        let inst = INSTANCE.lock().map_err(|e| e.to_string())?;
        let inst = inst.as_ref().ok_or("no running instance".to_string())?;
        let latest = inst.get_latest_error_msg();
        if let Some(latest) = latest {
            let cstr = CString::new(latest).map_err(|e| e.to_string())?;
            unsafe { *msg = cstr.into_raw(); }
        } else {
            unsafe { *msg = std::ptr::null(); }
        }
        Ok(())
    };

    match impl_func() {
        Ok(_) => 0,
        Err(e) => {
            if !err_msg.is_null() {
                if let Ok(cstr) = CString::new(e) {
                    unsafe { *err_msg = cstr.into_raw(); }
                };
            }
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_network_instance() {
        let cfg_str = r#"
            inst_name = "test"
            network = "test_network"
        "#;
        let cstr = std::ffi::CString::new(cfg_str).unwrap();
        assert_eq!(run_network_instance(cstr.as_ptr(), 0 as *mut *const std::ffi::c_char), 0);
    }
}
