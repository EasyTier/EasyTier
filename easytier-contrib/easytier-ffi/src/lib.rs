use std::cell::RefCell;

#[cfg(feature = "ffi-dataplane")]
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
#[cfg(feature = "ffi-dataplane")]
use easytier::launcher::{DataPlaneRef, EasyTierTcpStream, EasyTierUdpSocket};
use easytier::{
    common::config::{ConfigFileControl, ConfigLoader as _, TomlConfigLoader},
    instance_manager::NetworkInstanceManager,
};
#[cfg(feature = "ffi-dataplane")]
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
#[cfg(feature = "ffi-dataplane")]
use tokio_util::sync::CancellationToken;

static INSTANCE_NAME_ID_MAP: once_cell::sync::Lazy<DashMap<String, uuid::Uuid>> =
    once_cell::sync::Lazy::new(DashMap::new);
static INSTANCE_MANAGER: once_cell::sync::Lazy<NetworkInstanceManager> =
    once_cell::sync::Lazy::new(NetworkInstanceManager::new);

thread_local! {
    // # Thread Safety
    // set_error_msg and get_error_msg must be called on the same thread to
    // get correct error. And since `Handle::block_on` polls the top-level
    // future on the calling thread, set_error_msg always runs on the same
    // thread as the corresponding get_error_msg.
    static ERROR_MSG: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}
#[cfg(feature = "ffi-dataplane")]
static NEXT_DATA_PLANE_HANDLE: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "ffi-dataplane")]
static DATA_PLANE_HANDLES: once_cell::sync::Lazy<DashMap<u64, DataPlaneHandle>> =
    once_cell::sync::Lazy::new(DashMap::new);

#[cfg(feature = "ffi-dataplane")]
struct DataPlaneHandle {
    instance_id: uuid::Uuid,
    runtime: tokio::runtime::Handle,
    // Cancelled by close() to wake any in-flight op on this handle.
    close_token: CancellationToken,
    resource: DataPlaneResource,
}

#[cfg(feature = "ffi-dataplane")]
struct TcpHalves {
    // Split the TCP stream into read/write halves to allow concurrent reads and writes.
    read: tokio::sync::Mutex<ReadHalf<EasyTierTcpStream>>,
    write: tokio::sync::Mutex<WriteHalf<EasyTierTcpStream>>,
    // A trigger that notifies the smoltcp net to check whether it can be torn down when dropped.
    _data_plane_ref: DataPlaneRef,
    // Holds the Socks5AutoConnector (which holds the smoltcp route entry) to keep the route alive 
    // for the lifetime of the TCP stream. Otherwise,the route could be invalidated immediately.
    _route_guard: Box<dyn std::any::Any + Send + Sync>,
}

#[cfg(feature = "ffi-dataplane")]
enum DataPlaneResource {
    Tcp(Arc<TcpHalves>),
    Udp(Arc<EasyTierUdpSocket>),
}

#[repr(C)]
pub struct KeyValuePair {
    pub key: *const std::ffi::c_char,
    pub value: *const std::ffi::c_char,
}

fn set_error_msg(msg: &str) {
    ERROR_MSG.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        buf.extend_from_slice(msg.as_bytes());
    });
}

// Several helper functions for FFI data plane operations to facilitate logic reuse.

#[cfg(feature = "ffi-dataplane")]
fn next_handle() -> u64 {
    NEXT_DATA_PLANE_HANDLE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "ffi-dataplane")]
fn timeout_duration(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms)
}

#[cfg(feature = "ffi-dataplane")]
unsafe fn cstr_to_string(ptr: *const std::ffi::c_char, name: &str) -> Option<String> {
    if ptr.is_null() {
        set_error_msg(&format!("{} is null", name));
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(feature = "ffi-dataplane")]
fn get_instance_id(inst_name: &str) -> Option<uuid::Uuid> {
    INSTANCE_NAME_ID_MAP.get(inst_name).map(|id| *id.value())
}

#[cfg(feature = "ffi-dataplane")]
fn parse_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(e) => {
            set_error_msg(&format!("failed to parse ip address: {}", e));
            return None;
        }
    };
    Some(SocketAddr::new(ip, port))
}

/// Encode an IP address for FFI return. Returns `*mut c_char` to match
/// `CString::into_raw`; caller releases it via `free_string`.
#[cfg(feature = "ffi-dataplane")]
fn into_ffi_ip_cstring(ip: IpAddr) -> Option<*mut std::ffi::c_char> {
    match std::ffi::CString::new(ip.to_string()) {
        Ok(s) => Some(s.into_raw()),
        Err(e) => {
            set_error_msg(&format!("failed to encode ip: {}", e));
            None
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
fn get_runtime_handle(inst_id: &uuid::Uuid) -> Option<tokio::runtime::Handle> {
    let Some(rt) = INSTANCE_MANAGER.data_plane_runtime_handle(inst_id) else {
        set_error_msg("instance runtime is not ready");
        return None;
    };
    Some(rt)
}

#[cfg(feature = "ffi-dataplane")]
fn get_tcp_stream(
    handle: u64,
) -> Option<(Arc<TcpHalves>, tokio::runtime::Handle, CancellationToken)> {
    let Some(h) = DATA_PLANE_HANDLES.get(&handle) else {
        set_error_msg("tcp stream handle not found");
        return None;
    };
    match &h.resource {
        DataPlaneResource::Tcp(halves) => {
            Some((halves.clone(), h.runtime.clone(), h.close_token.clone()))
        }
        DataPlaneResource::Udp(_) => {
            set_error_msg("handle is not a tcp stream");
            None
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
fn get_udp_socket(
    handle: u64,
) -> Option<(Arc<EasyTierUdpSocket>, tokio::runtime::Handle, CancellationToken)> {
    let Some(h) = DATA_PLANE_HANDLES.get(&handle) else {
        set_error_msg("udp socket handle not found");
        return None;
    };
    match &h.resource {
        DataPlaneResource::Udp(socket) => {
            Some((socket.clone(), h.runtime.clone(), h.close_token.clone()))
        }
        DataPlaneResource::Tcp(_) => {
            set_error_msg("handle is not a udp socket");
            None
        }
    }
}

/// Run an IO op on the resource's owning runtime, supporting
/// timeout and cancellation.
#[cfg(feature = "ffi-dataplane")]
async fn run_with_cancel<T, F>(
    close_token: &CancellationToken,
    timeout_ms: u64,
    error_prefix: &str,
    op: F,
) -> Option<Result<T, std::io::Error>>
where
    F: Future<Output = Result<T, std::io::Error>>,
{
    tokio::select! {
        biased;
        _ = close_token.cancelled() => {
            set_error_msg(&format!("{}: handle closed", error_prefix));
            None
        }
        res = tokio::time::timeout(timeout_duration(timeout_ms), op) => match res {
            Ok(r) => Some(r),
            Err(_) => {
                set_error_msg(&format!("{} timed out", error_prefix));
                None
            }
        }
    }
}

/// # Safety
/// Set the tun fd
#[unsafe(no_mangle)]
pub unsafe extern "C" fn set_tun_fd(
    inst_name: *const std::ffi::c_char,
    fd: std::ffi::c_int,
) -> std::ffi::c_int {
    let inst_name = unsafe {
        assert!(!inst_name.is_null());
        std::ffi::CStr::from_ptr(inst_name)
            .to_string_lossy()
            .into_owned()
    };
    if !INSTANCE_NAME_ID_MAP.contains_key(&inst_name) {
        return -1;
    }

    let inst_id = *INSTANCE_NAME_ID_MAP
        .get(&inst_name)
        .as_ref()
        .unwrap()
        .value();

    match INSTANCE_MANAGER.set_tun_fd(&inst_id, fd) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// Get the last error message produced on the calling thread. The returned
/// pointer (if non-null) must be released via `free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_error_msg(out: *mut *const std::ffi::c_char) {
    let cstr = ERROR_MSG.with(|cell| {
        let buf = cell.borrow();
        if buf.is_empty() {
            None
        } else {
            std::ffi::CString::new(&buf[..]).ok()
        }
    });
    unsafe {
        *out = match cstr {
            Some(s) => s.into_raw() as *const std::ffi::c_char,
            None => std::ptr::null(),
        };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *const std::ffi::c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = std::ffi::CString::from_raw(s as *mut std::ffi::c_char);
    }
}

/// # Safety
/// Parse the config
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parse_config(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        std::ffi::CStr::from_ptr(cfg_str)
            .to_string_lossy()
            .into_owned()
    };

    if let Err(e) = TomlConfigLoader::new_from_str(&cfg_str) {
        set_error_msg(&format!("failed to parse config: {:?}", e));
        return -1;
    }

    0
}

/// # Safety
/// Run the network instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn run_network_instance(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
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

    if INSTANCE_NAME_ID_MAP.contains_key(&inst_name) {
        set_error_msg("instance already exists");
        return -1;
    }

    let instance_id =
        match INSTANCE_MANAGER.run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG) {
            Ok(id) => id,
            Err(e) => {
                set_error_msg(&format!("failed to start instance: {}", e));
                return -1;
            }
        };

    INSTANCE_NAME_ID_MAP.insert(inst_name, instance_id);

    0
}

/// # Safety
/// Retain the network instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn retain_network_instance(
    inst_names: *const *const std::ffi::c_char,
    length: usize,
) -> std::ffi::c_int {
    if length == 0 {
        if let Err(e) = INSTANCE_MANAGER.retain_network_instance(Vec::new()) {
            set_error_msg(&format!("failed to retain instances: {}", e));
            return -1;
        }
        INSTANCE_NAME_ID_MAP.clear();
        #[cfg(feature = "ffi-dataplane")]
        DATA_PLANE_HANDLES.clear();
        return 0;
    }

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

    let inst_ids: Vec<uuid::Uuid> = inst_names
        .iter()
        .filter_map(|name| INSTANCE_NAME_ID_MAP.get(name).map(|id| *id))
        .collect();

    if let Err(e) = INSTANCE_MANAGER.retain_network_instance(inst_ids.clone()) {
        set_error_msg(&format!("failed to retain instances: {}", e));
        return -1;
    }

    INSTANCE_NAME_ID_MAP.retain(|k, _| inst_names.contains(k));

    // FIXME: `DATA_PLANE_HANDLES.retain()` could trigger drop and cleanup of TCP halves, 
    // but `retain_network_instance()` has shutdown the server.
    // Maybe move this line before `retain_network_instance` to allow graceful close of TCP (TCP FIN)?
    #[cfg(feature = "ffi-dataplane")]
    DATA_PLANE_HANDLES.retain(|_, handle| inst_ids.contains(&handle.instance_id));

    0
}

/// # Safety
/// Collect the network infos
#[unsafe(no_mangle)]
pub unsafe extern "C" fn collect_network_infos(
    infos: *mut KeyValuePair,
    max_length: usize,
) -> std::ffi::c_int {
    if max_length == 0 {
        return 0;
    }

    let infos = unsafe {
        assert!(!infos.is_null());
        std::slice::from_raw_parts_mut(infos, max_length)
    };

    let collected_infos = match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(e) => {
            set_error_msg(&format!("failed to collect network infos: {}", e));
            return -1;
        }
    };

    let mut index = 0;
    for (instance_id, value) in collected_infos.iter() {
        if index >= max_length {
            break;
        }
        let Some(key) = INSTANCE_MANAGER.get_instance_name(instance_id) else {
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
            key: std::ffi::CString::new(key).unwrap().into_raw(),
            value: std::ffi::CString::new(value).unwrap().into_raw(),
        };
        index += 1;
    }

    index as std::ffi::c_int
}

/// # Safety
/// Open a TCP stream through an EasyTier instance data plane. Returns 0 on
/// failure. On success, writes the local socket address chosen for this
/// connection into `out_local_ip` (a heap-allocated C string the caller must
/// release via `free_string`) and `out_local_port`. Both out pointers must be
/// non-null.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_tcp_connect(
    inst_name: *const std::ffi::c_char,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    if out_local_ip.is_null() || out_local_port.is_null() {
        set_error_msg("output pointer is null");
        return 0;
    }
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(dst_ip) = (unsafe { cstr_to_string(dst_ip, "dst_ip") }) else {
        return 0;
    };
    let Some(inst_id) = get_instance_id(&inst_name) else {
        set_error_msg("instance not found");
        return 0;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port as u16) else {
        return 0;
    };
    let Some(runtime) = get_runtime_handle(&inst_id) else {
        return 0;
    };

    let timeout = timeout_duration(timeout_ms);
    let result = runtime.block_on(INSTANCE_MANAGER.data_plane_tcp_connect(
        &inst_id, dst_addr, timeout,
    ));
    match result {
        Ok((stream, local_addr, data_plane_ref, route_guard)) => {
            let Some(local_ip) = into_ffi_ip_cstring(local_addr.ip()) else {
                return 0;
            };
            let (rd, wr) = tokio::io::split(stream);
            let handle = next_handle();
            DATA_PLANE_HANDLES.insert(
                handle,
                DataPlaneHandle {
                    instance_id: inst_id,
                    runtime,
                    close_token: CancellationToken::new(),
                    resource: DataPlaneResource::Tcp(Arc::new(TcpHalves {
                        read: tokio::sync::Mutex::new(rd),
                        write: tokio::sync::Mutex::new(wr),
                        _data_plane_ref: data_plane_ref,
                        _route_guard: route_guard,
                    })),
                },
            );
            unsafe {
                *out_local_ip = local_ip as *const std::ffi::c_char;
                *out_local_port = local_addr.port();
            }
            handle
        }
        Err(e) => {
            set_error_msg(&format!("failed to connect tcp data plane: {}", e));
            0
        }
    }
}

/// # Safety
/// Read from a TCP data-plane stream.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_tcp_read(
    handle: u64,
    buf: *mut std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> std::ffi::c_int {
    if buf.is_null() {
        set_error_msg("buf is null");
        return -1;
    }
    let Some((halves, runtime, close_token)) = get_tcp_stream(handle) else {
        return -1;
    };
    // Safety: caller-owned buffer outlives this blocking call.
    let buf = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    runtime.block_on(async move {
        let mut rd = halves.read.lock().await;
        match run_with_cancel(
            &close_token,
            timeout_ms,
            "failed to read tcp data plane",
            rd.read(buf),
        )
        .await
        {
            Some(Ok(n)) => n as std::ffi::c_int,
            Some(Err(e)) => {
                set_error_msg(&format!("failed to read tcp data plane: {}", e));
                -1
            }
            None => -1,
        }
    })
}

/// # Safety
/// Write to a TCP data-plane stream.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_tcp_write(
    handle: u64,
    buf: *const std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> std::ffi::c_int {
    if buf.is_null() {
        set_error_msg("buf is null");
        return -1;
    }
    let Some((halves, runtime, close_token)) = get_tcp_stream(handle) else {
        return -1;
    };
    let total = len as usize;
    // Safety: caller-owned buffer outlives this blocking call.
    let buf = unsafe { std::slice::from_raw_parts(buf, total) };
    runtime.block_on(async move {
        let mut wr = halves.write.lock().await;
        // Use `write_all` to honor `net.Conn::Write` semantics on the Go side
        // (must write everything or return an error); single `write()` can
        // silently short-write and corrupt streams that the caller assumes are
        // fully written.
        match run_with_cancel(
            &close_token,
            timeout_ms,
            "failed to write tcp data plane",
            wr.write_all(buf),
        )
        .await
        {
            Some(Ok(())) => total as std::ffi::c_int,
            Some(Err(e)) => {
                set_error_msg(&format!("failed to write tcp data plane: {}", e));
                -1
            }
            None => -1,
        }
    })
}

#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub extern "C" fn data_plane_tcp_close(handle: u64) -> std::ffi::c_int {
    let Some((_, h)) =
        DATA_PLANE_HANDLES.remove_if(&handle, |_, e| matches!(e.resource, DataPlaneResource::Tcp(_)))
    else {
        set_error_msg(if DATA_PLANE_HANDLES.contains_key(&handle) {
            "handle is not a tcp stream"
        } else {
            "tcp stream handle not found"
        });
        return -1;
    };
    h.close_token.cancel();
    if let DataPlaneResource::Tcp(halves) = h.resource {
        // Best-effort half-close; if write half is in use, the in-flight call
        // observes the cancel token and releases the lock shortly after.
        h.runtime.spawn(async move {
            if let Ok(mut wr) = halves.write.try_lock() {
                let _ = wr.shutdown().await;
            }
        });
    }
    0
}

/// # Safety
/// Bind a UDP socket through an EasyTier instance data plane. Returns 0 on
/// failure. The local address actually bound (which may differ from the
/// requested port when `local_port == 0`) is written into `out_local_ip` /
/// `out_local_port`; the caller must release `*out_local_ip` via `free_string`.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_udp_bind(
    inst_name: *const std::ffi::c_char,
    local_port: std::ffi::c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    if out_local_ip.is_null() || out_local_port.is_null() {
        set_error_msg("output pointer is null");
        return 0;
    }
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(inst_id) = get_instance_id(&inst_name) else {
        set_error_msg("instance not found");
        return 0;
    };
    let Some(runtime) = get_runtime_handle(&inst_id) else {
        return 0;
    };

    let timeout = timeout_duration(timeout_ms);
    let result = runtime.block_on(INSTANCE_MANAGER.data_plane_udp_bind(
        &inst_id,
        local_port as u16,
        timeout,
    ));
    match result {
        Ok((socket, local_addr)) => {
            let Some(local_ip) = into_ffi_ip_cstring(local_addr.ip()) else {
                return 0;
            };
            let handle = next_handle();
            DATA_PLANE_HANDLES.insert(
                handle,
                DataPlaneHandle {
                    instance_id: inst_id,
                    runtime,
                    close_token: CancellationToken::new(),
                    resource: DataPlaneResource::Udp(Arc::new(socket)),
                },
            );
            unsafe {
                *out_local_ip = local_ip as *const std::ffi::c_char;
                *out_local_port = local_addr.port();
            }
            handle
        }
        Err(e) => {
            set_error_msg(&format!("failed to bind udp data plane: {}", e));
            0
        }
    }
}

/// # Safety
/// Send a datagram through a UDP data-plane socket.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_udp_send_to(
    handle: u64,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    buf: *const std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> std::ffi::c_int {
    if buf.is_null() {
        set_error_msg("buf is null");
        return -1;
    }
    let Some(dst_ip) = (unsafe { cstr_to_string(dst_ip, "dst_ip") }) else {
        return -1;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port as u16) else {
        return -1;
    };
    let Some((socket, runtime, close_token)) = get_udp_socket(handle) else {
        return -1;
    };
    let total = len as usize;
    // Safety: caller-owned buffer outlives this blocking call.
    let buf = unsafe { std::slice::from_raw_parts(buf, total) };
    runtime.block_on(async move {
        match run_with_cancel(
            &close_token,
            timeout_ms,
            "failed to send udp data plane",
            socket.send_to(buf, dst_addr),
        )
        .await
        {
            Some(Ok(n)) => n as std::ffi::c_int,
            Some(Err(e)) => {
                set_error_msg(&format!("failed to send udp data plane: {}", e));
                -1
            }
            None => -1,
        }
    })
}

/// # Safety
/// Receive a datagram from a UDP data-plane socket.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_udp_recv_from(
    handle: u64,
    buf: *mut std::ffi::c_uchar,
    len: u32,
    out_ip: *mut *const std::ffi::c_char,
    out_port: *mut std::ffi::c_ushort,
    timeout_ms: u64,
) -> std::ffi::c_int {
    if buf.is_null() || out_ip.is_null() || out_port.is_null() {
        set_error_msg("output pointer is null");
        return -1;
    }
    let Some((socket, runtime, close_token)) = get_udp_socket(handle) else {
        return -1;
    };
    let total = len as usize;
    // Safety: caller-owned buffer outlives this blocking call.
    let buf = unsafe { std::slice::from_raw_parts_mut(buf, total) };
    let ret = runtime.block_on(run_with_cancel(
        &close_token,
        timeout_ms,
        "udp data plane receive",
        socket.recv_from(buf),
    ));

    match ret {
        Some(Ok((n, addr))) => {
            // The returned ip pointer must be released by the caller via
            // `free_string` (which calls `CString::from_raw`, matching
            // `CString::into_raw` here).
            let Some(ip_cstr) = into_ffi_ip_cstring(addr.ip()) else {
                return -1;
            };
            unsafe {
                *out_ip = ip_cstr as *const std::ffi::c_char;
                *out_port = addr.port() as std::ffi::c_ushort;
            }
            n as std::ffi::c_int
        }
        Some(Err(e)) => {
            set_error_msg(&format!("failed to receive udp data plane: {}", e));
            -1
        }
        None => -1,
    }
}

#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub extern "C" fn data_plane_udp_close(handle: u64) -> std::ffi::c_int {
    let Some((_, h)) =
        DATA_PLANE_HANDLES.remove_if(&handle, |_, e| matches!(e.resource, DataPlaneResource::Udp(_)))
    else {
        set_error_msg(if DATA_PLANE_HANDLES.contains_key(&handle) {
            "handle is not a udp socket"
        } else {
            "udp socket handle not found"
        });
        return -1;
    };
    h.close_token.cancel();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let cfg_str = r#"
            inst_name = "test"
            network = "test_network"
        "#;
        let cstr = std::ffi::CString::new(cfg_str).unwrap();
        unsafe {
            assert_eq!(parse_config(cstr.as_ptr()), 0);
        }
    }

    #[test]
    fn test_run_network_instance() {
        let cfg_str = r#"
            inst_name = "test"
            network = "test_network"
        "#;
        let cstr = std::ffi::CString::new(cfg_str).unwrap();
        unsafe {
            assert_eq!(run_network_instance(cstr.as_ptr()), 0);
        }
    }
}
