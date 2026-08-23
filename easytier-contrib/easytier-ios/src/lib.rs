//! iOS-facing C ABI for EasyTier.
//!
//! This crate is the iOS counterpart of `easytier-android-jni`: it wraps the
//! easytier-ffi C ABI for instance management and reuses the same
//! platform-agnostic loopback TCP forwarder (data-plane session + operation
//! dispatch, no TUN involved). It builds as a static library for the Apple
//! toolchain; `easytier-ios.h` declares the callable surface.
//!
//! All exported functions are panic-safe: panics are caught at the FFI
//! boundary and reported through `easytier_ios_last_error`.

mod error;
mod forwarder;
mod strings;

use std::{
    ffi::{CStr, c_char, c_int},
    net::{Ipv4Addr, SocketAddrV4},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::Mutex,
};

use once_cell::sync::Lazy;

use forwarder::TcpForwarder;
use strings::cstring_for;

/// Live forwarders keyed by their bound loopback port.
static FORWARDERS: Lazy<Mutex<std::collections::HashMap<u16, TcpForwarder>>> =
    Lazy::new(Default::default);

fn forwarders() -> std::sync::MutexGuard<'static, std::collections::HashMap<u16, TcpForwarder>> {
    FORWARDERS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

/// Run `body` catching any panic; panics are recorded in the last-error
/// buffer so they never unwind across the FFI boundary.
fn guarded<R>(default: R, body: impl FnOnce() -> R) -> R {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(result) => result,
        Err(_) => {
            error::set_error("internal panic in easytier-ios");
            default
        }
    }
}

/// Read a required non-null C string argument.
///
/// # Safety
/// When non-null, `value` must point to a NUL-terminated string.
unsafe fn cstr_arg<'a>(value: *const c_char, what: &str) -> Result<&'a str, String> {
    if value.is_null() {
        return Err(format!("{what} must not be null"));
    }
    // SAFETY: caller guarantees `value` is NUL-terminated.
    let text = unsafe { CStr::from_ptr(value) };
    text.to_str()
        .map_err(|_| format!("{what} is not valid UTF-8"))
}

/// Start one EasyTier network instance from a TOML config string.
///
/// Returns 0 on success, -1 on failure (see `easytier_ios_last_error`).
///
/// # Safety
/// `toml` must be a non-null pointer to a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn easytier_ios_run_instance(toml: *const c_char) -> c_int {
    unsafe {
        guarded(-1, || {
            error::clear_error();
            let toml = match cstr_arg(toml, "config string") {
                Ok(toml) => toml,
                Err(message) => {
                    error::set_error(&message);
                    return -1;
                }
            };
            easytier_ffi::run_network_instance(toml.as_ptr() as *const c_char)
        })
    }
}

/// Keep the named instances and stop all others.
///
/// `names_json` is a JSON array of instance name strings; null, empty or `[]`
/// stops every running instance. Returns 0 on success, -1 on failure.
///
/// # Safety
/// `names_json` may be null; when non-null it must point to a NUL-terminated
/// UTF-8 string containing a JSON array of strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn easytier_ios_retain_instances(names_json: *const c_char) -> c_int {
    unsafe {
        guarded(-1, || {
            error::clear_error();
            let names: Vec<String> = if names_json.is_null() {
                Vec::new()
            } else {
                let text = match cstr_arg(names_json, "instance names JSON") {
                    Ok(text) => text,
                    Err(message) => {
                        error::set_error(&message);
                        return -1;
                    }
                };
                if text.trim().is_empty() {
                    Vec::new()
                } else {
                    match serde_json::from_str(text) {
                        Ok(names) => names,
                        Err(parse_error) => {
                            error::set_error(&format!(
                                "invalid instance names JSON: {parse_error}"
                            ));
                            return -1;
                        }
                    }
                }
            };
            let c_names: Vec<std::ffi::CString> = match names
                .iter()
                .map(|name| cstring_for(name, "instance name"))
                .collect::<std::io::Result<Vec<_>>>()
            {
                Ok(c_names) => c_names,
                Err(invalid) => {
                    error::set_error(&invalid.to_string());
                    return -1;
                }
            };
            let pointers: Vec<*const c_char> =
                c_names.iter().map(|name| name.as_ptr()).collect();
            easytier_ffi::retain_network_instance(pointers.as_ptr(), pointers.len())
        })
    }
}

/// Collect running instance information as a JSON object mapping each
/// instance name to its running info JSON.
///
/// Returns a newly allocated string the caller must release with
/// `easytier_ios_free_string`, or null on failure (see
/// `easytier_ios_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn easytier_ios_collect_network_infos(max_length: c_int) -> *mut c_char {
    guarded(ptr::null_mut(), || {
        error::clear_error();
        let max_length = max_length.max(0) as usize;
        let mut infos = vec![
            easytier_ffi::KeyValuePair {
                key: ptr::null(),
                value: ptr::null(),
            };
            max_length
        ];
        // SAFETY: `infos` is writable storage for `max_length` entries; every
        // returned key/value string is released below with
        // `easytier_ffi::free_string`.
        let count = unsafe { easytier_ffi::collect_network_infos(infos.as_mut_ptr(), max_length) };
        if count < 0 {
            return ptr::null_mut();
        }
        let mut map = serde_json::Map::new();
        for info in infos.iter().take(count as usize) {
            if info.key.is_null() || info.value.is_null() {
                break;
            }
            // SAFETY: non-null entries are NUL-terminated strings allocated by
            // easytier-ffi, each released exactly once after copying.
            let (key, value) = unsafe {
                let key = CStr::from_ptr(info.key).to_string_lossy().into_owned();
                let value = CStr::from_ptr(info.value).to_string_lossy().into_owned();
                easytier_ffi::free_string(info.key);
                easytier_ffi::free_string(info.value);
                (key, value)
            };
            let value = serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value));
            map.insert(key, value);
        }
        let json = serde_json::Value::Object(map).to_string();
        match std::ffi::CString::new(json) {
            Ok(json) => json.into_raw(),
            Err(_) => {
                error::set_error("network info JSON contains a null byte");
                ptr::null_mut()
            }
        }
    })
}

/// Start a loopback TCP forwarder: listen on `127.0.0.1:listen_port`
/// (0 = auto-assign) and relay every accepted connection to
/// `target_ip:target_port` through the data plane of the instance named
/// `inst_name`.
///
/// Returns the bound local port on success, -1 on failure (see
/// `easytier_ios_last_error`).
///
/// # Safety
/// `inst_name` and `target_ip` must be non-null pointers to NUL-terminated
/// UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn easytier_ios_start_tcp_forwarder(
    inst_name: *const c_char,
    target_ip: *const c_char,
    target_port: u16,
    listen_port: u16,
) -> c_int {
    unsafe {
        guarded(-1, || {
            error::clear_error();
            let instance = match cstr_arg(inst_name, "instance name") {
                Ok(instance) => instance.to_owned(),
                Err(message) => {
                    error::set_error(&message);
                    return -1;
                }
            };
            let target_ip = match cstr_arg(target_ip, "target IP") {
                Ok(target_ip) => target_ip,
                Err(message) => {
                    error::set_error(&message);
                    return -1;
                }
            };
            let target_ip: Ipv4Addr = match target_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    error::set_error(&format!("invalid IPv4 target address: \"{target_ip}\""));
                    return -1;
                }
            };
            let target = SocketAddrV4::new(target_ip, target_port);
            let forwarder = match TcpForwarder::start(instance, target, listen_port) {
                Ok(forwarder) => forwarder,
                Err(start_error) => {
                    error::set_error(&format!("failed to start TCP forwarder: {start_error}"));
                    return -1;
                }
            };
            let local_port = forwarder.local_port;
            forwarders().insert(local_port, forwarder);
            c_int::from(local_port)
        })
    }
}

/// Stop the TCP forwarder bound to `local_port`.
///
/// Returns 0 on success, -1 when no forwarder is registered on that port.
#[unsafe(no_mangle)]
pub extern "C" fn easytier_ios_stop_tcp_forwarder(local_port: c_int) -> c_int {
    guarded(-1, || {
        error::clear_error();
        if !(0..=u16::MAX as c_int).contains(&local_port) {
            error::set_error(&format!("invalid local port: {local_port}"));
            return -1;
        }
        let forwarder = forwarders().remove(&(local_port as u16));
        match forwarder {
            Some(forwarder) => match forwarder.stop() {
                Ok(()) => 0,
                Err(stop_error) => {
                    error::set_error(&format!("failed to stop TCP forwarder: {stop_error}"));
                    -1
                }
            },
            None => {
                error::set_error(&format!(
                    "no TCP forwarder registered on local port {local_port}"
                ));
                -1
            }
        }
    })
}

/// Return the last error message on this thread, or null when there is none.
///
/// Combines forwarder-side errors recorded by this library with the
/// easytier-ffi last FFI error. The returned string is newly allocated and
/// must be released with `easytier_ios_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn easytier_ios_last_error() -> *mut c_char {
    guarded(ptr::null_mut(), error::last_error_raw)
}

/// Release a string returned by `easytier_ios_collect_network_infos` or
/// `easytier_ios_last_error`. Passing null is a no-op.
///
/// # Safety
/// `s` must be null or a string previously returned by this library, not yet
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn easytier_ios_free_string(s: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !s.is_null() {
            // SAFETY: caller guarantees `s` came from this library.
            drop(unsafe { std::ffi::CString::from_raw(s) });
        }
    }));
}

#[cfg(test)]
mod tests {
    //! Host-target smoke tests for the C ABI surface. They exercise the
    //! wrapper logic (argument validation, error propagation, the forwarder
    //! registry and string ownership) against a real `no_tun` instance; no
    //! peer connectivity is required.

    use super::*;
    use std::{
        ffi::{CStr, CString},
        sync::{Mutex, MutexGuard},
        time::{Duration, Instant},
    };

    /// Tests share the process-wide easytier-ffi state and the forwarder
    /// registry; run them serially.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn acquire() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn unique_instance(tag: &str) -> String {
        format!("ios-{tag}-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
    }

    fn minimal_config(instance: &str) -> CString {
        CString::new(format!(
            "instance_name = \"{instance}\"\n\
             instance_id = \"{}\"\n\
             ipv4 = \"10.126.126.1\"\n\
             listeners = []\n\
             flags.no_tun = true\n",
            uuid::Uuid::new_v4()
        ))
        .unwrap()
    }

    fn retain_all() {
        let empty = CString::new("[]").unwrap();
        // SAFETY: `empty` is a valid NUL-terminated string.
        assert_eq!(unsafe { easytier_ios_retain_instances(empty.as_ptr()) }, 0);
    }

    struct InstanceGuard;

    impl InstanceGuard {
        fn run(instance: &str) -> Self {
            let config = minimal_config(instance);
            // SAFETY: `config` is a valid NUL-terminated string.
            let result = unsafe { easytier_ios_run_instance(config.as_ptr()) };
            assert_eq!(result, 0, "run_instance failed: {:?}", take_last_error());
            Self
        }
    }

    impl Drop for InstanceGuard {
        fn drop(&mut self) {
            retain_all();
        }
    }

    fn take_last_error() -> Option<String> {
        let error_ptr = easytier_ios_last_error();
        if error_ptr.is_null() {
            return None;
        }
        // SAFETY: `error_ptr` was returned by `easytier_ios_last_error` and is
        // freed exactly once below.
        let message = unsafe { CStr::from_ptr(error_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { easytier_ios_free_string(error_ptr) };
        Some(message)
    }

    fn collect_infos_json() -> String {
        let json_ptr = easytier_ios_collect_network_infos(32);
        assert!(!json_ptr.is_null(), "collect failed: {:?}", take_last_error());
        // SAFETY: `json_ptr` was returned by `easytier_ios_collect_network_infos`
        // and is freed exactly once below.
        let json = unsafe { CStr::from_ptr(json_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { easytier_ios_free_string(json_ptr) };
        json
    }

    #[test]
    fn run_collect_retain_roundtrip() {
        let _guard = acquire();
        let instance = unique_instance("smoke");
        let _instance = InstanceGuard::run(&instance);

        let json = collect_infos_json();
        let infos: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&json).expect("collect_network_infos must return a JSON object");
        assert!(
            infos.contains_key(&instance),
            "instance {instance} missing from collected infos: {json}"
        );

        retain_all();
        let infos = collect_infos_json();
        assert!(
            !infos.contains(&instance),
            "instance {instance} still listed after retain([]): {infos}"
        );
    }

    #[test]
    fn retain_instances_rejects_invalid_json() {
        let _guard = acquire();
        let garbage = CString::new("not json").unwrap();
        // SAFETY: `garbage` is a valid NUL-terminated string.
        let result = unsafe { easytier_ios_retain_instances(garbage.as_ptr()) };
        assert_eq!(result, -1);
        let message = take_last_error().expect("last error must be set");
        assert!(
            message.contains("invalid instance names JSON"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn start_forwarder_fails_for_unknown_instance() {
        let _guard = acquire();
        let instance = unique_instance("missing");
        let name = CString::new(instance.as_str()).unwrap();
        let target = CString::new("10.126.126.99").unwrap();
        // SAFETY: both pointers are valid NUL-terminated strings.
        let result =
            unsafe { easytier_ios_start_tcp_forwarder(name.as_ptr(), target.as_ptr(), 22, 0) };
        assert_eq!(result, -1);
        let message = take_last_error().expect("last error must be set");
        assert!(
            message.contains(&instance),
            "error must mention the instance: {message}"
        );
    }

    #[test]
    fn forwarder_registry_start_and_stop() {
        let _guard = acquire();
        let instance = unique_instance("fwd");
        let _instance = InstanceGuard::run(&instance);
        let name = CString::new(instance.as_str()).unwrap();
        let target = CString::new("10.126.126.99").unwrap();

        // The data-plane runtime comes up asynchronously after
        // `run_network_instance`; retry until the native session is available.
        let deadline = Instant::now() + Duration::from_secs(10);
        let port = loop {
            // SAFETY: both pointers are valid NUL-terminated strings.
            let result =
                unsafe { easytier_ios_start_tcp_forwarder(name.as_ptr(), target.as_ptr(), 22, 0) };
            if result > 0 {
                break result;
            }
            assert!(
                Instant::now() < deadline,
                "start_tcp_forwarder never succeeded: {:?}",
                take_last_error()
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(forwarders().contains_key(&(port as u16)));

        assert_eq!(easytier_ios_stop_tcp_forwarder(port), 0);
        assert!(!forwarders().contains_key(&(port as u16)));
        // Stopping again must fail with a recorded error.
        assert_eq!(easytier_ios_stop_tcp_forwarder(port), -1);
        let message = take_last_error().expect("last error must be set");
        assert!(
            message.contains(&port.to_string()),
            "error must mention the port: {message}"
        );
    }
}
