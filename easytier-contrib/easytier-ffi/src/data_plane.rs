#[cfg(feature = "ffi-dataplane")]
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[cfg(feature = "ffi-dataplane")]
use dashmap::DashMap;
#[cfg(feature = "ffi-dataplane")]
use easytier_core::gateway::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};
#[cfg(feature = "ffi-dataplane")]
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
#[cfg(feature = "ffi-dataplane")]
use tokio_util::sync::CancellationToken;
#[cfg(feature = "ffi-dataplane")]
use uuid::Uuid;

#[cfg(feature = "ffi-dataplane")]
use crate::{
    config_server::{in_config_server_callback, is_config_server_active_or_stopping},
    error::{free_string, set_error_msg},
    state::{ffi_context, resolve_instance_id_by_name},
};

#[cfg(feature = "ffi-dataplane")]
static NEXT_DATA_PLANE_HANDLE: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "ffi-dataplane")]
static DATA_PLANE_HANDLES: once_cell::sync::Lazy<DashMap<u64, DataPlaneHandle>> =
    once_cell::sync::Lazy::new(DashMap::new);
#[cfg(feature = "ffi-dataplane")]
static DATA_PLANE_USAGE_LOCK: once_cell::sync::Lazy<RwLock<()>> =
    once_cell::sync::Lazy::new(|| RwLock::new(()));

#[cfg(feature = "ffi-dataplane")]
pub(crate) struct DataPlaneHandle {
    pub(crate) instance_id: uuid::Uuid,
    pub(crate) runtime: tokio::runtime::Handle,
    // Cancelled by close() to wake any in-flight op on this handle.
    pub(crate) close_token: CancellationToken,
    pub(crate) resource: DataPlaneResource,
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) struct TcpHalves {
    pub(crate) read: tokio::sync::Mutex<ReadHalf<DataPlaneTcpStream>>,
    pub(crate) write: tokio::sync::Mutex<WriteHalf<DataPlaneTcpStream>>,
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) enum DataPlaneResource {
    Tcp(Arc<TcpHalves>),
    TcpListener(Arc<tokio::sync::Mutex<DataPlaneTcpListener>>),
    Udp(Arc<DataPlaneUdpSocket>),
}

// Several helper functions for FFI data plane operations to facilitate logic reuse.

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn next_handle() -> u64 {
    NEXT_DATA_PLANE_HANDLE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn timeout_duration(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn cstr_to_string(ptr: *const std::ffi::c_char, name: &str) -> Option<String> {
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
pub(crate) fn get_instance_id(inst_name: &str) -> Option<uuid::Uuid> {
    match resolve_instance_id_by_name(inst_name) {
        Ok(Some(instance_id)) => Some(instance_id),
        Ok(None) => {
            set_error_msg("instance not found");
            None
        }
        Err(error) => {
            set_error_msg(&error.to_string());
            None
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn parse_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
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
pub(crate) fn into_ffi_ip_cstring(ip: IpAddr) -> Option<*mut std::ffi::c_char> {
    match std::ffi::CString::new(ip.to_string()) {
        Ok(s) => Some(s.into_raw()),
        Err(e) => {
            set_error_msg(&format!("failed to encode ip: {}", e));
            None
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn get_runtime_handle(
    inst_id: &uuid::Uuid,
    deadline: std::time::Instant,
) -> Option<tokio::runtime::Handle> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let Some(rt) = ffi_context()
        .manager
        .data_plane_wait_runtime_handle(inst_id, remaining)
    else {
        set_error_msg("instance runtime is not ready");
        return None;
    };
    Some(rt)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn insert_tcp_stream_handle(
    instance_id: uuid::Uuid,
    runtime: tokio::runtime::Handle,
    stream: DataPlaneTcpStream,
) -> u64 {
    let (rd, wr) = tokio::io::split(stream);
    let handle = next_handle();
    DATA_PLANE_HANDLES.insert(
        handle,
        DataPlaneHandle {
            instance_id,
            runtime,
            close_token: CancellationToken::new(),
            resource: DataPlaneResource::Tcp(Arc::new(TcpHalves {
                read: tokio::sync::Mutex::new(rd),
                write: tokio::sync::Mutex::new(wr),
            })),
        },
    );
    handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn insert_tcp_listener_handle(
    instance_id: uuid::Uuid,
    runtime: tokio::runtime::Handle,
    listener: DataPlaneTcpListener,
) -> u64 {
    let handle = next_handle();
    DATA_PLANE_HANDLES.insert(
        handle,
        DataPlaneHandle {
            instance_id,
            runtime,
            close_token: CancellationToken::new(),
            resource: DataPlaneResource::TcpListener(Arc::new(tokio::sync::Mutex::new(listener))),
        },
    );
    handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn insert_udp_socket_handle(
    instance_id: uuid::Uuid,
    runtime: tokio::runtime::Handle,
    socket: DataPlaneUdpSocket,
) -> u64 {
    let handle = next_handle();
    DATA_PLANE_HANDLES.insert(
        handle,
        DataPlaneHandle {
            instance_id,
            runtime,
            close_token: CancellationToken::new(),
            resource: DataPlaneResource::Udp(Arc::new(socket)),
        },
    );
    handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn get_tcp_stream(
    handle: u64,
) -> Option<(Arc<TcpHalves>, tokio::runtime::Handle, CancellationToken)> {
    get_tcp_stream_with_instance(handle)
        .map(|(halves, runtime, close_token, _)| (halves, runtime, close_token))
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn get_tcp_stream_with_instance(
    handle: u64,
) -> Option<(
    Arc<TcpHalves>,
    tokio::runtime::Handle,
    CancellationToken,
    uuid::Uuid,
)> {
    let Some(h) = DATA_PLANE_HANDLES.get(&handle) else {
        set_error_msg("tcp stream handle not found");
        return None;
    };
    match &h.resource {
        DataPlaneResource::Tcp(halves) => Some((
            halves.clone(),
            h.runtime.clone(),
            h.close_token.clone(),
            h.instance_id,
        )),
        DataPlaneResource::TcpListener(_) | DataPlaneResource::Udp(_) => {
            set_error_msg("handle is not a tcp stream");
            None
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn get_tcp_listener(
    handle: u64,
) -> Option<(
    Arc<tokio::sync::Mutex<DataPlaneTcpListener>>,
    tokio::runtime::Handle,
    CancellationToken,
    uuid::Uuid,
)> {
    let Some(h) = DATA_PLANE_HANDLES.get(&handle) else {
        set_error_msg("tcp listener handle not found");
        return None;
    };
    match &h.resource {
        DataPlaneResource::TcpListener(listener) => Some((
            listener.clone(),
            h.runtime.clone(),
            h.close_token.clone(),
            h.instance_id,
        )),
        DataPlaneResource::Tcp(_) | DataPlaneResource::Udp(_) => {
            set_error_msg("handle is not a tcp listener");
            None
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn get_udp_socket(
    handle: u64,
) -> Option<(
    Arc<DataPlaneUdpSocket>,
    tokio::runtime::Handle,
    CancellationToken,
)> {
    get_udp_socket_with_instance(handle)
        .map(|(socket, runtime, close_token, _)| (socket, runtime, close_token))
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn get_udp_socket_with_instance(
    handle: u64,
) -> Option<(
    Arc<DataPlaneUdpSocket>,
    tokio::runtime::Handle,
    CancellationToken,
    uuid::Uuid,
)> {
    let Some(h) = DATA_PLANE_HANDLES.get(&handle) else {
        set_error_msg("udp socket handle not found");
        return None;
    };
    match &h.resource {
        DataPlaneResource::Udp(socket) => Some((
            socket.clone(),
            h.runtime.clone(),
            h.close_token.clone(),
            h.instance_id,
        )),
        DataPlaneResource::Tcp(_) | DataPlaneResource::TcpListener(_) => {
            set_error_msg("handle is not a udp socket");
            None
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn remove_data_plane_handles_by_instance_ids(ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }

    let _data_plane_usage_guard = DATA_PLANE_USAGE_LOCK
        .write()
        .unwrap_or_else(|err| err.into_inner());

    DATA_PLANE_HANDLES.retain(|_, handle| {
        if ids.contains(&handle.instance_id) {
            handle.close_token.cancel();
            false
        } else {
            true
        }
    });
    crate::data_plane_async::remove_ops_by_instance_ids(ids);
}

#[cfg(not(feature = "ffi-dataplane"))]
pub(crate) fn remove_data_plane_handles_by_instance_ids(_ids: &[uuid::Uuid]) {}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_rejected() -> bool {
    if in_config_server_callback() {
        set_error_msg("cannot use data plane from config server callback");
        true
    } else if is_config_server_active_or_stopping() {
        set_error_msg("cannot use data plane while config server client is active");
        true
    } else {
        false
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn enter_data_plane_operation() -> Option<std::sync::RwLockReadGuard<'static, ()>> {
    if data_plane_rejected() {
        return None;
    }

    let guard = match DATA_PLANE_USAGE_LOCK.read() {
        Ok(guard) => guard,
        Err(err) => {
            set_error_msg(&format!("failed to lock data plane usage: {}", err));
            return None;
        }
    };
    if data_plane_rejected() {
        return None;
    }
    Some(guard)
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

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn lock_for_config_server_start()
-> Result<std::sync::RwLockWriteGuard<'static, ()>, String> {
    let guard = DATA_PLANE_USAGE_LOCK
        .write()
        .map_err(|err| format!("failed to lock data plane usage: {}", err))?;
    if !DATA_PLANE_HANDLES.is_empty() || crate::data_plane_async::has_live_ops() {
        return Err("cannot start config server client while data plane is in use".to_string());
    }
    Ok(guard)
}
/// # Safety
/// Open a TCP stream through an EasyTier instance data plane. Returns 0 on
/// failure. On success, writes the local socket address chosen for this
/// connection into `out_local_ip` (a heap-allocated C string the caller must
/// release via `free_string`) and `out_local_port`. Both out pointers must be
/// non-null.
#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_connect(
    inst_name: *const std::ffi::c_char,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
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
        return 0;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port) else {
        return 0;
    };
    let deadline = std::time::Instant::now() + timeout_duration(timeout_ms);
    let Some(runtime) = get_runtime_handle(&inst_id, deadline) else {
        return 0;
    };

    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let result = runtime.block_on(
        ffi_context()
            .manager
            .data_plane_tcp_connect(&inst_id, dst_addr, remaining),
    );
    match result {
        Ok(stream) => {
            let local_addr = stream.local_addr();
            let Some(local_ip) = into_ffi_ip_cstring(local_addr.ip()) else {
                return 0;
            };
            let handle = insert_tcp_stream_handle(inst_id, runtime, stream);
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
/// Bind a TCP listener through an EasyTier instance data plane. Returns 0 on
/// failure. The local address actually bound is written into `out_local_ip` /
/// `out_local_port`; the caller must release `*out_local_ip` via `free_string`.
#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_bind(
    inst_name: *const std::ffi::c_char,
    local_port: std::ffi::c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    if out_local_ip.is_null() || out_local_port.is_null() {
        set_error_msg("output pointer is null");
        return 0;
    }
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(inst_id) = get_instance_id(&inst_name) else {
        return 0;
    };
    let deadline = std::time::Instant::now() + timeout_duration(timeout_ms);
    let Some(runtime) = get_runtime_handle(&inst_id, deadline) else {
        return 0;
    };

    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let result = runtime.block_on(
        ffi_context()
            .manager
            .data_plane_tcp_bind(&inst_id, local_port, remaining),
    );
    match result {
        Ok(listener) => {
            let local_addr = listener.local_addr();
            let Some(local_ip) = into_ffi_ip_cstring(local_addr.ip()) else {
                return 0;
            };
            let handle = insert_tcp_listener_handle(inst_id, runtime, listener);
            unsafe {
                *out_local_ip = local_ip as *const std::ffi::c_char;
                *out_local_port = local_addr.port();
            }
            handle
        }
        Err(e) => {
            set_error_msg(&format!("failed to bind tcp data plane: {}", e));
            0
        }
    }
}

/// # Safety
/// Accept one connection from a TCP data-plane listener. Returns a TCP stream
/// handle, or 0 on failure. Local and peer addresses are written into out
/// parameters; returned IP strings must be released via `free_string`.
#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_accept(
    handle: u64,
    timeout_ms: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
    out_peer_ip: *mut *const std::ffi::c_char,
    out_peer_port: *mut std::ffi::c_ushort,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    if out_local_ip.is_null()
        || out_local_port.is_null()
        || out_peer_ip.is_null()
        || out_peer_port.is_null()
    {
        set_error_msg("output pointer is null");
        return 0;
    }
    let Some((listener, runtime, close_token, instance_id)) = get_tcp_listener(handle) else {
        return 0;
    };

    let ret = runtime.block_on(async move {
        let mut listener = listener.lock().await;
        run_with_cancel(
            &close_token,
            timeout_ms,
            "tcp data plane accept",
            listener.accept(),
        )
        .await
    });

    match ret {
        Some(Ok((stream, peer_addr))) => {
            let local_addr = stream.local_addr();
            let Some(local_ip) = into_ffi_ip_cstring(local_addr.ip()) else {
                return 0;
            };
            let Some(peer_ip) = into_ffi_ip_cstring(peer_addr.ip()) else {
                free_string(local_ip);
                return 0;
            };
            let stream_handle = insert_tcp_stream_handle(instance_id, runtime, stream);
            unsafe {
                *out_local_ip = local_ip as *const std::ffi::c_char;
                *out_local_port = local_addr.port();
                *out_peer_ip = peer_ip as *const std::ffi::c_char;
                *out_peer_port = peer_addr.port();
            }
            stream_handle
        }
        Some(Err(e)) => {
            set_error_msg(&format!("failed to accept tcp data plane: {}", e));
            0
        }
        None => 0,
    }
}

/// # Safety
/// Read from a TCP data-plane stream.
#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_read(
    handle: u64,
    buf: *mut std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> std::ffi::c_int {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return -1,
    };
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
pub(crate) unsafe fn data_plane_tcp_write(
    handle: u64,
    buf: *const std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> std::ffi::c_int {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return -1,
    };
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
pub(crate) fn data_plane_tcp_close(handle: u64) -> std::ffi::c_int {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return -1,
    };
    crate::data_plane_async::cancel_ops_for_handle(handle);
    let Some((_, h)) = DATA_PLANE_HANDLES.remove_if(&handle, |_, e| {
        matches!(e.resource, DataPlaneResource::Tcp(_))
    }) else {
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

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_tcp_listener_close(handle: u64) -> std::ffi::c_int {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return -1,
    };
    crate::data_plane_async::cancel_ops_for_handle(handle);
    let Some((_, h)) = DATA_PLANE_HANDLES.remove_if(&handle, |_, e| {
        matches!(e.resource, DataPlaneResource::TcpListener(_))
    }) else {
        set_error_msg(if DATA_PLANE_HANDLES.contains_key(&handle) {
            "handle is not a tcp listener"
        } else {
            "tcp listener handle not found"
        });
        return -1;
    };
    h.close_token.cancel();
    0
}

/// # Safety
/// Bind a UDP socket through an EasyTier instance data plane. Returns 0 on
/// failure. The local address actually bound (which may differ from the
/// requested port when `local_port == 0`) is written into `out_local_ip` /
/// `out_local_port`; the caller must release `*out_local_ip` via `free_string`.
#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_udp_bind(
    inst_name: *const std::ffi::c_char,
    local_port: std::ffi::c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    if out_local_ip.is_null() || out_local_port.is_null() {
        set_error_msg("output pointer is null");
        return 0;
    }
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(inst_id) = get_instance_id(&inst_name) else {
        return 0;
    };
    let deadline = std::time::Instant::now() + timeout_duration(timeout_ms);
    let Some(runtime) = get_runtime_handle(&inst_id, deadline) else {
        return 0;
    };

    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let result = runtime.block_on(
        ffi_context()
            .manager
            .data_plane_udp_bind(&inst_id, local_port, remaining),
    );
    match result {
        Ok(socket) => {
            let local_addr = socket.local_addr();
            let Some(local_ip) = into_ffi_ip_cstring(local_addr.ip()) else {
                return 0;
            };
            let handle = insert_udp_socket_handle(inst_id, runtime, socket);
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
pub(crate) unsafe fn data_plane_udp_send_to(
    handle: u64,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    buf: *const std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> std::ffi::c_int {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return -1,
    };
    if buf.is_null() {
        set_error_msg("buf is null");
        return -1;
    }
    let Some(dst_ip) = (unsafe { cstr_to_string(dst_ip, "dst_ip") }) else {
        return -1;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port) else {
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
pub(crate) unsafe fn data_plane_udp_recv_from(
    handle: u64,
    buf: *mut std::ffi::c_uchar,
    len: u32,
    out_ip: *mut *const std::ffi::c_char,
    out_port: *mut std::ffi::c_ushort,
    timeout_ms: u64,
) -> std::ffi::c_int {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return -1,
    };
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
pub(crate) fn data_plane_udp_close(handle: u64) -> std::ffi::c_int {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return -1,
    };
    crate::data_plane_async::cancel_ops_for_handle(handle);
    let Some((_, h)) = DATA_PLANE_HANDLES.remove_if(&handle, |_, e| {
        matches!(e.resource, DataPlaneResource::Udp(_))
    }) else {
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

#[cfg(all(test, feature = "ffi-dataplane"))]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn config_server_start_waits_for_data_plane_operation() {
        let read_guard = DATA_PLANE_USAGE_LOCK.read().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _write_guard = lock_for_config_server_start().unwrap();
            done_tx.send(()).unwrap();
        });

        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(read_guard);
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        waiter.join().unwrap();
    }

    #[test]
    fn instance_cleanup_waits_for_data_plane_operation() {
        let read_guard = DATA_PLANE_USAGE_LOCK.read().unwrap();
        let instance_id = Uuid::new_v4();
        let (done_tx, done_rx) = mpsc::channel();
        let cleaner = std::thread::spawn(move || {
            remove_data_plane_handles_by_instance_ids(&[instance_id]);
            done_tx.send(()).unwrap();
        });

        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(read_guard);
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cleaner.join().unwrap();
    }
}
