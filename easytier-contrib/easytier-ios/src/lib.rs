//! iOS-facing C ABI for EasyTier.
//!
//! This crate is the iOS counterpart of `easytier-android-jni`: a thin
//! wrapper over the easytier-ffi C ABI (instance management + the generic
//! `call_json_rpc` management bridge) for apps that embed EasyTier without
//! a TUN device or NEPacketTunnel. Loopback port forwarding into the
//! virtual network is configured through `api.config.ConfigRpcService/PatchConfig`
//! port-forward patches; there is no forwarder in this crate. It builds as
//! a static library for the Apple toolchain; `easytier-ios.h` declares the
//! callable surface.
//!
//! All exported functions are panic-safe: panics are caught at the FFI
//! boundary and reported through `easytier_ios_last_error`.

mod error;
mod strings;

use std::{
    ffi::{CStr, c_char, c_int},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

use strings::cstring_for;

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
            let pointers: Vec<*const c_char> = c_names.iter().map(|name| name.as_ptr()).collect();
            easytier_ffi::retain_network_instance(pointers.as_ptr(), pointers.len())
        })
    }
}

/// Stop exactly one named instance without affecting other instances.
///
/// Unknown names are ignored. Returns 0 on success, -1 on failure.
///
/// # Safety
/// `instance_name` must be a non-null pointer to a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn easytier_ios_delete_instance(instance_name: *const c_char) -> c_int {
    unsafe {
        guarded(-1, || {
            error::clear_error();
            if let Err(message) = cstr_arg(instance_name, "instance name") {
                error::set_error(&message);
                return -1;
            }
            let instance_names = [instance_name];
            easytier_ffi::delete_network_instance(instance_names.as_ptr(), instance_names.len())
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

/// Call an exposed EasyTier management RPC method using protobuf JSON.
///
/// Thin wrapper over easytier-ffi's `call_json_rpc` with a null domain (the
/// generic management registry). `payload_json` must contain the protobuf
/// JSON request, including any `instance` selector required by the target
/// RPC. Port forwarding into the virtual network is driven through this
/// bridge with `api.config.ConfigRpcService/PatchConfig` port-forward patches.
///
/// Returns a newly allocated JSON response string the caller must release
/// with `easytier_ios_free_string`, or null on failure (see
/// `easytier_ios_last_error`).
///
/// # Safety
/// `service_name`, `method_name` and `payload_json` must be non-null
/// pointers to NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn easytier_ios_call_json_rpc(
    service_name: *const c_char,
    method_name: *const c_char,
    payload_json: *const c_char,
) -> *mut c_char {
    unsafe {
        guarded(ptr::null_mut(), || {
            error::clear_error();
            if let Err(message) = cstr_arg(service_name, "service name") {
                error::set_error(&message);
                return ptr::null_mut();
            }
            if let Err(message) = cstr_arg(method_name, "method name") {
                error::set_error(&message);
                return ptr::null_mut();
            }
            let payload = match cstr_arg(payload_json, "payload JSON") {
                Ok(payload) => payload,
                Err(message) => {
                    error::set_error(&message);
                    return ptr::null_mut();
                }
            };
            let mut out: *const c_char = ptr::null();
            let rc = easytier_ffi::call_json_rpc(
                service_name,
                method_name,
                ptr::null(),
                payload.as_ptr() as *const c_char,
                &mut out,
            );
            if rc != 0 {
                // easytier-ffi already recorded the failure in its own
                // last-error buffer.
                return ptr::null_mut();
            }
            out as *mut c_char
        })
    }
}

/// Return the last error message on this thread, or null when there is none.
///
/// Combines wrapper-side errors recorded by this library with the
/// easytier-ffi last FFI error. The returned string is newly allocated and
/// must be released with `easytier_ios_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn easytier_ios_last_error() -> *mut c_char {
    guarded(ptr::null_mut(), error::last_error_raw)
}

/// Release a string returned by `easytier_ios_collect_network_infos`,
/// `easytier_ios_call_json_rpc` or `easytier_ios_last_error`. Passing null
/// is a no-op.
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
    //! wrapper logic (argument validation, error propagation, string
    //! ownership) plus the full port-forward patch path against real `no_tun`
    //! instances; two of them link instances over the process-wide ring
    //! registry (through the always-on `ring://<instance-id>` listener and a
    //! TOML ring connector) to verify a patched TCP port forward end to end.

    use super::*;
    use std::{
        ffi::{CStr, CString},
        io::{Read, Write},
        net::TcpStream,
        sync::{
            Arc, Mutex, MutexGuard,
            atomic::{AtomicBool, Ordering},
        },
    };

    /// Tests share the process-wide easytier-ffi state; run them serially.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn init_logs() {
        use std::sync::Once;
        static LOG_INIT: Once = Once::new();
        LOG_INIT.call_once(|| {
            let filter = tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG")
                    .unwrap_or_else(|_| "easytier_core=debug,easytier=debug,info".to_owned()),
            );
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();
        });
    }

    fn acquire() -> MutexGuard<'static, ()> {
        init_logs();
        TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn unique_instance(tag: &str) -> String {
        format!(
            "ios-{tag}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )
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
        assert!(
            !json_ptr.is_null(),
            "collect failed: {:?}",
            take_last_error()
        );
        // SAFETY: `json_ptr` was returned by
        // `easytier_ios_collect_network_infos` and is freed exactly once below.
        let json = unsafe { CStr::from_ptr(json_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { easytier_ios_free_string(json_ptr) };
        json
    }

    /// Call a management RPC through the wrapper and return the response JSON.
    fn call_json_rpc(service: &str, method: &str, payload: &serde_json::Value) -> String {
        let service_c = CString::new(service).unwrap();
        let method_c = CString::new(method).unwrap();
        let payload_c = CString::new(payload.to_string()).unwrap();
        // SAFETY: all three pointers are valid NUL-terminated strings.
        let response_ptr = unsafe {
            easytier_ios_call_json_rpc(service_c.as_ptr(), method_c.as_ptr(), payload_c.as_ptr())
        };
        assert!(
            !response_ptr.is_null(),
            "{service}/{method} failed: {:?}",
            take_last_error()
        );
        // SAFETY: `response_ptr` was returned by `easytier_ios_call_json_rpc`
        // and is freed exactly once below.
        let response = unsafe { CStr::from_ptr(response_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { easytier_ios_free_string(response_ptr) };
        response
    }

    /// The port-forward patch JSON used by the app: one ADD/REMOVE entry over
    /// `api.config.ConfigRpcService/PatchConfig`, IPv4 addresses encoded as
    /// network-order u32.
    fn port_forward_patch(instance: &str, action: &str, bind_port: u16) -> serde_json::Value {
        serde_json::json!({
            "patch": {
                "port_forwards": [{
                    "action": action,
                    "cfg": {
                        "bind_addr": {"ipv4": {"addr": 0x7F000001}, "port": bind_port},
                        "dst_addr": {"ipv4": {"addr": 0x0A7E7E63}, "port": 80},
                        "socket_type": "TCP",
                    },
                }],
            },
            "instance": {"instance_selector": {"name": instance}},
        })
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
    fn delete_instance_stops_only_the_named_instance() {
        let _guard = acquire();
        let deleted = unique_instance("delete");
        let retained = unique_instance("retain");
        let _deleted_instance = InstanceGuard::run(&deleted);
        let _retained_instance = InstanceGuard::run(&retained);

        let deleted_name = CString::new(deleted.clone()).unwrap();
        // SAFETY: `deleted_name` is a valid NUL-terminated string.
        assert_eq!(
            unsafe { easytier_ios_delete_instance(deleted_name.as_ptr()) },
            0,
            "delete failed: {:?}",
            take_last_error()
        );

        let infos = collect_infos_json();
        assert!(
            !infos.contains(&deleted),
            "deleted instance remains: {infos}"
        );
        assert!(
            infos.contains(&retained),
            "unrelated instance stopped: {infos}"
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
    fn call_json_rpc_rejects_null_payload() {
        let _guard = acquire();
        let service = CString::new("api.config.ConfigRpcService").unwrap();
        let method = CString::new("PatchConfig").unwrap();
        // SAFETY: service/method are valid; payload null must be rejected.
        let response =
            unsafe { easytier_ios_call_json_rpc(service.as_ptr(), method.as_ptr(), ptr::null()) };
        assert!(response.is_null());
        let message = take_last_error().expect("last error must be set");
        assert!(
            message.contains("payload JSON"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn call_json_rpc_rejects_null_service_and_method() {
        let _guard = acquire();
        let service = CString::new("api.config.ConfigRpcService").unwrap();
        let method = CString::new("PatchConfig").unwrap();
        let payload = CString::new("{}").unwrap();

        // SAFETY: method and payload are valid; service null must be rejected.
        let response =
            unsafe { easytier_ios_call_json_rpc(ptr::null(), method.as_ptr(), payload.as_ptr()) };
        assert!(response.is_null());
        let message = take_last_error().expect("last error must be set");
        assert!(
            message.contains("service name"),
            "unexpected error: {message}"
        );

        // SAFETY: service and payload are valid; method null must be rejected.
        let response =
            unsafe { easytier_ios_call_json_rpc(service.as_ptr(), ptr::null(), payload.as_ptr()) };
        assert!(response.is_null());
        let message = take_last_error().expect("last error must be set");
        assert!(
            message.contains("method name"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn port_forward_patch_roundtrip() {
        let _guard = acquire();
        let instance = unique_instance("patch");
        let _instance = InstanceGuard::run(&instance);

        // ADD a loopback TCP forward to an unreachable virtual target; the
        // patch itself only installs the listener and must succeed.
        call_json_rpc(
            "api.config.ConfigRpcService",
            "PatchConfig",
            &port_forward_patch(&instance, "ADD", 18787),
        );

        // The forward is now visible in the instance config dump.
        let config = call_json_rpc(
            "api.config.ConfigRpcService",
            "GetConfig",
            &serde_json::json!({
                "instance": {"instance_selector": {"name": instance}},
            }),
        );
        assert!(
            config.contains("18787"),
            "patched forward missing from config dump: {config}"
        );

        // REMOVE matches the whole PortForwardConfig entry (patch_vec uses
        // PartialEq), so the dst fields must repeat the ADD values.
        call_json_rpc(
            "api.config.ConfigRpcService",
            "PatchConfig",
            &port_forward_patch(&instance, "REMOVE", 18787),
        );
        let config = call_json_rpc(
            "api.config.ConfigRpcService",
            "GetConfig",
            &serde_json::json!({
                "instance": {"instance_selector": {"name": instance}},
            }),
        );
        assert!(
            !config.contains("18787"),
            "removed forward still in config dump: {config}"
        );
    }

    /// Ownership of an easytier-ffi allocated string: freed exactly once on
    /// drop, in a thread that itself calls back into easytier-ffi so the
    /// easytier-ffi free runs on a thread the runtime has seen.
    struct FfiString(*const c_char);

    impl Drop for FfiString {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // `self.0` was allocated by easytier-ffi and is freed exactly
                // once here.
                easytier_ffi::free_string(self.0);
            }
        }
    }

    /// Wait for the next data-plane completion on `session`.
    fn next_completion(
        session: u64,
        timeout: std::time::Duration,
    ) -> easytier_ffi::DataPlaneCompletion {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let ready = easytier_ffi::data_plane_completion_wait(session, 1_000);
            assert!(ready >= 0, "completion wait failed: {ready}");
            if ready == 1 {
                let mut completions = [easytier_ffi::DataPlaneCompletion::default(); 1];
                // SAFETY: `completions` is writable storage for one value.
                let drained = unsafe {
                    easytier_ffi::data_plane_completion_drain(session, completions.as_mut_ptr(), 1)
                };
                assert!(drained >= 0, "completion drain failed: {drained}");
                if drained == 1 {
                    return completions[0];
                }
            }
            assert!(std::time::Instant::now() < deadline, "completion timed out");
        }
    }

    /// Run a data-plane echo server on `instance`: bind `port` on the
    /// instance's virtual stack, then loop accepting a stream, reading one
    /// payload and replying verbatim, until `stop` is set. Holds the
    /// instance's single native data-plane session for its lifetime.
    fn data_plane_echo_server(instance: &str, port: u16, stop: Arc<AtomicBool>) {
        let instance = CString::new(instance).unwrap();
        let mut session = 0u64;
        // SAFETY: `instance` is a valid NUL-terminated string and `session`
        // points to writable storage for one `u64`.
        let result =
            unsafe { easytier_ffi::data_plane_session_open(instance.as_ptr(), &mut session) };
        assert_eq!(result, 0, "session open failed: {result}");
        let session = session;

        // The data-plane runtime starts after the instance; retry the bind
        // until it is up.
        let mut bind_operation = 0u64;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            // SAFETY: `bind_operation` points to writable storage for one `u64`.
            let result = unsafe {
                easytier_ffi::data_plane_tcp_bind_submit(session, port, 15_000, &mut bind_operation)
            };
            if result == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "bind submit failed: {:?}",
                take_last_error()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let bind_completion = next_completion(session, std::time::Duration::from_secs(15));
        assert_eq!(bind_completion.operation_id, bind_operation);
        assert_eq!(
            bind_completion.status, 0,
            "bind failed: status={} kind={}",
            bind_completion.status, bind_completion.operation_kind
        );
        let mut listener = 0u64;
        let mut local = easytier_ffi::DataPlaneSocketAddr::default();
        // SAFETY: outputs reference writable, non-overlapping storage.
        let result = unsafe {
            easytier_ffi::data_plane_tcp_bind_result_take(
                session,
                bind_operation,
                &mut listener,
                &mut local,
            )
        };
        assert_eq!(result, 0, "bind result take failed: {result}");

        while !stop.load(Ordering::Acquire) {
            let mut accept_operation = 0u64;
            // SAFETY: `accept_operation` points to writable storage for one `u64`.
            let result = unsafe {
                easytier_ffi::data_plane_tcp_accept_submit(
                    session,
                    listener,
                    5_000,
                    &mut accept_operation,
                )
            };
            assert_eq!(result, 0, "accept submit failed: {result}");
            let accept_completion = next_completion(session, std::time::Duration::from_secs(10));
            assert_eq!(accept_completion.operation_id, accept_operation);
            if accept_completion.status != 0 {
                // Accept timed out or the listener was closed; re-check stop
                // and either loop for the next connection or exit.
                easytier_ffi::data_plane_operation_free(session, accept_operation);
                if stop.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
            let mut stream = 0u64;
            let mut peer = easytier_ffi::DataPlaneSocketAddr::default();
            // SAFETY: outputs reference writable, non-overlapping storage.
            let result = unsafe {
                easytier_ffi::data_plane_tcp_accept_result_take(
                    session,
                    accept_operation,
                    &mut stream,
                    &mut local,
                    &mut peer,
                )
            };
            assert_eq!(result, 0, "accept result take failed: {result}");

            let mut read_operation = 0u64;
            // SAFETY: `read_operation` points to writable storage for one `u64`.
            let result = unsafe {
                easytier_ffi::data_plane_tcp_read_submit(session, stream, 4096, &mut read_operation)
            };
            assert_eq!(result, 0, "read submit failed: {result}");
            let read_completion = next_completion(session, std::time::Duration::from_secs(15));
            assert_eq!(read_completion.operation_id, read_operation);
            assert_eq!(
                read_completion.status, 0,
                "read failed: {}",
                read_completion.status
            );
            let mut data = [0u8; 4096];
            let mut len = 0u32;
            let mut eof = false;
            // SAFETY: `data` is writable for its length and the scalar outputs
            // reference writable, non-overlapping storage.
            let result = unsafe {
                easytier_ffi::data_plane_tcp_read_result_take(
                    session,
                    read_operation,
                    data.as_mut_ptr(),
                    data.len() as u32,
                    &mut len,
                    &mut eof,
                )
            };
            assert_eq!(result, 0, "read result take failed: {result}");
            assert!(!eof, "unexpected eof before payload");

            // Echo the received payload back verbatim.
            let payload = &data[..len as usize];
            let mut write_operation = 0u64;
            // SAFETY: the ABI copies `payload` before returning.
            let result = unsafe {
                easytier_ffi::data_plane_tcp_write_submit(
                    session,
                    stream,
                    payload.as_ptr(),
                    payload.len() as u32,
                    &mut write_operation,
                )
            };
            assert_eq!(result, 0, "write submit failed: {result}");
            let write_completion = next_completion(session, std::time::Duration::from_secs(15));
            assert_eq!(write_completion.operation_id, write_operation);
            assert_eq!(
                write_completion.status, 0,
                "write failed: {}",
                write_completion.status
            );

            // `stream` was accepted above and is closed exactly once.
            easytier_ffi::data_plane_resource_close(session, stream);
        }

        // `listener` and `session` were opened above and are closed exactly
        // once here.
        easytier_ffi::data_plane_resource_close(session, listener);
        easytier_ffi::data_plane_session_close(session);
    }

    #[test]
    fn ring_connector_pair_sees_peer() {
        let _guard = acquire();
        let server = unique_instance("srv");
        let client = unique_instance("cli");
        let server_id = uuid::Uuid::new_v4();
        let client_id = uuid::Uuid::new_v4();

        let server_config = CString::new(format!(
            "instance_name = \"{server}\"\n\
             instance_id = \"{server_id}\"\n\
             ipv4 = \"10.126.126.99\"\n\
             listeners = []\n\
             flags.no_tun = true\n"
        ))
        .unwrap();
        // SAFETY: `server_config` is a valid NUL-terminated string.
        assert_eq!(
            unsafe { easytier_ios_run_instance(server_config.as_ptr()) },
            0,
            "run server failed: {:?}",
            take_last_error()
        );
        let _cleanup = InstanceGuard;

        let client_config = CString::new(format!(
            "instance_name = \"{client}\"\n\
             instance_id = \"{client_id}\"\n\
             ipv4 = \"10.126.126.100\"\n\
             listeners = []\n\
             flags.no_tun = true\n\
             [[peer]]\n\
             uri = \"ring://{server_id}\"\n",
        ))
        .unwrap();
        // SAFETY: `client_config` is a valid NUL-terminated string.
        assert_eq!(
            unsafe { easytier_ios_run_instance(client_config.as_ptr()) },
            0,
            "run client failed: {:?}",
            take_last_error()
        );

        // Peer setup over the ring registry is asynchronous; wait until the
        // client reports a connected route to the server instance before
        // relying on overlay connectivity.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let peers = call_json_rpc(
                "api.instance.PeerManageRpcService",
                "ListPeer",
                &serde_json::json!({
                    "instance": {"instance_selector": {"name": client}},
                }),
            );
            eprintln!("[dbg] ListPeer raw: {peers}");
            let peers: serde_json::Value = serde_json::from_str(&peers).unwrap();
            let connected = peers["peer_infos"]
                .as_array()
                .map(|infos| {
                    infos.iter().any(|info| {
                        info["directly_connected_conns"]
                            .as_array()
                            .is_some_and(|conns| !conns.is_empty())
                    })
                })
                .unwrap_or(false);
            if connected {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client never connected to server: {peers}"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    /// End to end: two instances linked over the ring registry, a TCP echo
    /// listener on the far end's virtual IP, and a patched loopback port
    /// forward on the near end carrying a full byte round trip.
    #[test]
    fn port_forward_echo_roundtrip_over_ring() {
        let _guard = acquire();
        let server = unique_instance("srv");
        let client = unique_instance("cli");
        let server_id = uuid::Uuid::new_v4();
        let client_id = uuid::Uuid::new_v4();
        let server_ipv4 = "10.126.126.99";

        let server_config = CString::new(format!(
            "instance_name = \"{server}\"\n\
             instance_id = \"{server_id}\"\n\
             ipv4 = \"{server_ipv4}\"\n\
             listeners = []\n\
             flags.no_tun = true\n"
        ))
        .unwrap();
        // SAFETY: `server_config` is a valid NUL-terminated string.
        assert_eq!(
            unsafe { easytier_ios_run_instance(server_config.as_ptr()) },
            0,
            "run server failed: {:?}",
            take_last_error()
        );
        let _cleanup = InstanceGuard;

        let client_config = CString::new(format!(
            "instance_name = \"{client}\"\n\
             instance_id = \"{client_id}\"\n\
             ipv4 = \"10.126.126.100\"\n\
             listeners = []\n\
             flags.no_tun = true\n\
             [[peer]]\n\
             uri = \"ring://{server_id}\"\n"
        ))
        .unwrap();
        // SAFETY: `client_config` is a valid NUL-terminated string.
        assert_eq!(
            unsafe { easytier_ios_run_instance(client_config.as_ptr()) },
            0,
            "run client failed: {:?}",
            take_last_error()
        );

        // Peer setup over the ring registry is asynchronous; wait until the
        // client reports a connected route to the server instance before
        // relying on overlay connectivity.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let peers = call_json_rpc(
                "api.instance.PeerManageRpcService",
                "ListPeer",
                &serde_json::json!({
                    "instance": {"instance_selector": {"name": client}},
                }),
            );
            let peers: serde_json::Value = serde_json::from_str(&peers).unwrap();
            let connected = peers["peer_infos"]
                .as_array()
                .map(|infos| {
                    infos.iter().any(|info| {
                        info["directly_connected_conns"]
                            .as_array()
                            .is_some_and(|conns| !conns.is_empty())
                    })
                })
                .unwrap_or(false);
            if connected {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client never connected to server: {peers}"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // The forward target must be a TCP listener on the server instance's
        // virtual IP. In `no_tun` mode the kernel has no such address, so the
        // server side opens one through its own data plane: an
        // easytier-ffi data-plane session bound on the virtual stack, with a
        // blocking accept/read/write echo loop.
        let echo_port: u16 = 23456;
        let echo_stop = Arc::new(AtomicBool::new(false));
        let echo = std::thread::spawn({
            let echo_stop = echo_stop.clone();
            let server = server.clone();
            move || data_plane_echo_server(&server, echo_port, echo_stop)
        });

        // Patch in the loopback forward on the client instance. Peer setup is
        // asynchronous; the patch itself installs the listener regardless, so
        // retry only while the RPC itself fails (e.g. instance not ready).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let bind_port = 18788;
        let patch = serde_json::json!({
            "patch": {
                "port_forwards": [{
                    "action": "ADD",
                    "cfg": {
                        "bind_addr": {"ipv4": {"addr": 0x7F000001}, "port": bind_port},
                        "dst_addr": {"ipv4": {"addr": 0x0A7E7E63}, "port": echo_port},
                        "socket_type": "TCP",
                    },
                }],
            },
            "instance": {"instance_selector": {"name": client}},
        });
        loop {
            let service = CString::new("api.config.ConfigRpcService").unwrap();
            let method = CString::new("PatchConfig").unwrap();
            let payload = CString::new(patch.to_string()).unwrap();
            let mut out: *const c_char = ptr::null();
            // SAFETY: all pointers are valid NUL-terminated strings; `out` is
            // owned by easytier-ffi and released by the FfiString guard below.
            let rc = unsafe {
                easytier_ffi::call_json_rpc(
                    service.as_ptr(),
                    method.as_ptr(),
                    ptr::null(),
                    payload.as_ptr(),
                    &mut out,
                )
            };
            let _response = FfiString(out);
            if rc == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "patch_config never succeeded: {:?}",
                take_last_error()
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Dial the patched loopback forward until the data-plane path to the
        // server virtual IP comes up, then verify an echo round trip.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", bind_port)) {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                if stream.write_all(b"ping").is_ok() {
                    let mut buf = [0u8; 4];
                    if stream.read_exact(&mut buf).is_ok() && &buf == b"ping" {
                        break;
                    }
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no echo through patched port forward"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        echo_stop.store(true, Ordering::Release);
        echo.join().expect("echo server thread panicked");
    }
}
