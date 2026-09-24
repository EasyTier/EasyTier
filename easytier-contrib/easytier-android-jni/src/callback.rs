use std::{
    ffi::{CStr, c_char, c_void},
    sync::{Arc, Mutex, MutexGuard},
};

use easytier_ffi::ConfigServerEventCallback;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JObject, JValue};
use once_cell::sync::Lazy;

use crate::error;

pub(crate) struct JniConfigServerCallback {
    java_vm: jni::JavaVM,
    callback: GlobalRef,
}

static CONFIG_SERVER_CALLBACK: Lazy<Mutex<Option<Arc<JniConfigServerCallback>>>> =
    Lazy::new(|| Mutex::new(None));

pub(crate) fn lock_callback_storage()
-> Result<MutexGuard<'static, Option<Arc<JniConfigServerCallback>>>, String> {
    CONFIG_SERVER_CALLBACK
        .lock()
        .map_err(|e| format!("Failed to lock config server callback: {}", e))
}

pub(crate) fn new_callback(
    env: &mut JNIEnv,
    callback: &JObject,
) -> Result<Arc<JniConfigServerCallback>, String> {
    let java_vm = env
        .get_java_vm()
        .map_err(|e| format!("Failed to get JavaVM: {:?}", e))?;
    let callback = env
        .new_global_ref(callback)
        .map_err(|e| format!("Failed to create callback global ref: {:?}", e))?;
    Ok(Arc::new(JniConfigServerCallback { java_vm, callback }))
}

pub(crate) fn callback_fn(
    callback: &Option<Arc<JniConfigServerCallback>>,
) -> ConfigServerEventCallback {
    callback
        .as_ref()
        .map(|_| config_server_event_callback as unsafe extern "C" fn(*const c_char, *mut c_void))
}

pub(crate) fn user_data(callback: &Option<Arc<JniConfigServerCallback>>) -> *mut c_void {
    callback
        .as_ref()
        .map(|callback| Arc::as_ptr(callback) as *mut c_void)
        .unwrap_or(std::ptr::null_mut())
}

impl JniConfigServerCallback {
    fn clear_pending_exception(
        env: &mut JNIEnv,
        context: &str,
        error: &dyn std::fmt::Debug,
    ) -> String {
        match env.exception_check() {
            Ok(true) => {
                if let Err(clear_err) = env.exception_clear() {
                    return format!(
                        "{}: {:?}; failed to clear pending Java exception: {:?}",
                        context, error, clear_err
                    );
                }
            }
            Ok(false) => {}
            Err(check_err) => {
                return format!(
                    "{}: {:?}; failed to check pending Java exception: {:?}",
                    context, error, check_err
                );
            }
        }

        format!("{}: {:?}", context, error)
    }

    fn on_event(&self, event_json: *const c_char) -> Result<(), String> {
        let event_json = unsafe { CStr::from_ptr(event_json) }
            .to_str()
            .map_err(|e| format!("Invalid config server event JSON: {:?}", e))?;
        let mut env = self
            .java_vm
            .attach_current_thread()
            .map_err(|e| format!("Failed to attach callback thread: {:?}", e))?;
        let event_json = env.new_string(event_json).map_err(|e| {
            Self::clear_pending_exception(&mut env, "Failed to create event string", &e)
        })?;

        if let Err(e) = env.call_method(
            self.callback.as_obj(),
            "onEvent",
            "(Ljava/lang/String;)V",
            &[JValue::from(&event_json)],
        ) {
            return Err(Self::clear_pending_exception(
                &mut env,
                "Failed to call config server callback",
                &e,
            ));
        }
        Ok(())
    }
}

unsafe extern "C" fn config_server_event_callback(
    event_json: *const c_char,
    user_data: *mut c_void,
) {
    if event_json.is_null() || user_data.is_null() {
        return;
    }

    let callback = unsafe { &*(user_data as *const JniConfigServerCallback) };

    if let Err(error) = callback.on_event(event_json) {
        error::set_callback_error(error);
    }
}
