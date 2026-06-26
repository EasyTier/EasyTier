#[cfg(feature = "ffi-dataplane")]
use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(feature = "ffi-dataplane")]
use dashmap::DashMap;
#[cfg(feature = "ffi-dataplane")]
use easytier::launcher::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};
#[cfg(feature = "ffi-dataplane")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "ffi-dataplane")]
use tokio_util::sync::CancellationToken;
#[cfg(feature = "ffi-dataplane")]
use uuid::Uuid;

#[cfg(feature = "ffi-dataplane")]
use crate::{
    data_plane::{
        TcpHalves, cstr_to_string, enter_data_plane_operation, get_instance_id, get_tcp_listener,
        get_tcp_stream_with_instance, get_udp_socket_with_instance, insert_tcp_listener_handle,
        insert_tcp_stream_handle, insert_udp_socket_handle, into_ffi_ip_cstring, parse_socket_addr,
        timeout_duration,
    },
    error::{free_string, set_error_msg},
    state::{ASYNC_RUNTIME, INSTANCE_MANAGER},
};

#[cfg(feature = "ffi-dataplane")]
pub(crate) const DATA_PLANE_OP_PENDING: std::ffi::c_int = 0;
#[cfg(feature = "ffi-dataplane")]
pub(crate) const DATA_PLANE_OP_READY: std::ffi::c_int = 1;
#[cfg(feature = "ffi-dataplane")]
pub(crate) const DATA_PLANE_OP_FAILED: std::ffi::c_int = -1;
#[cfg(feature = "ffi-dataplane")]
pub(crate) const DATA_PLANE_OP_INVALID: std::ffi::c_int = -2;

#[cfg(feature = "ffi-dataplane")]
static NEXT_DATA_PLANE_OP: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "ffi-dataplane")]
static DATA_PLANE_OPS: once_cell::sync::Lazy<DashMap<u64, Arc<DataPlaneAsyncOp>>> =
    once_cell::sync::Lazy::new(DashMap::new);

#[cfg(feature = "ffi-dataplane")]
const MAX_ASYNC_READ_LEN: u32 = 16 * 1024 * 1024;
#[cfg(feature = "ffi-dataplane")]
const MAX_ASYNC_WRITE_LEN: u32 = std::ffi::c_int::MAX as u32;

#[cfg(feature = "ffi-dataplane")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataPlaneAsyncOpKind {
    TcpConnect,
    TcpBind,
    TcpAccept,
    TcpRead,
    TcpWrite,
    UdpBind,
    UdpSendTo,
    UdpRecvFrom,
}

#[cfg(feature = "ffi-dataplane")]
struct DataPlaneAsyncOp {
    kind: DataPlaneAsyncOpKind,
    instance_id: Option<Uuid>,
    target_handle: Option<u64>,
    cancel_token: CancellationToken,
    state: Mutex<DataPlaneAsyncOpState>,
    ready: Condvar,
}

#[cfg(feature = "ffi-dataplane")]
enum DataPlaneAsyncOpState {
    Pending,
    Ready(Box<DataPlaneAsyncOpResult>),
    Failed(String),
    Consumed,
}

#[cfg(feature = "ffi-dataplane")]
enum DataPlaneAsyncOpResult {
    TcpConnect {
        instance_id: Uuid,
        runtime: tokio::runtime::Handle,
        stream: DataPlaneTcpStream,
        local_addr: SocketAddr,
    },
    TcpBind {
        instance_id: Uuid,
        runtime: tokio::runtime::Handle,
        listener: DataPlaneTcpListener,
        local_addr: SocketAddr,
    },
    TcpAccept {
        instance_id: Uuid,
        runtime: tokio::runtime::Handle,
        stream: DataPlaneTcpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    },
    TcpRead {
        data: Vec<u8>,
    },
    TcpWrite {
        written: usize,
    },
    UdpBind {
        instance_id: Uuid,
        runtime: tokio::runtime::Handle,
        socket: DataPlaneUdpSocket,
        local_addr: SocketAddr,
    },
    UdpSendTo {
        sent: usize,
    },
    UdpRecvFrom {
        data: Vec<u8>,
        peer_addr: SocketAddr,
    },
}

#[cfg(feature = "ffi-dataplane")]
fn next_op_handle() -> u64 {
    NEXT_DATA_PLANE_OP.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "ffi-dataplane")]
fn new_op(
    kind: DataPlaneAsyncOpKind,
    instance_id: Option<Uuid>,
    target_handle: Option<u64>,
) -> (u64, Arc<DataPlaneAsyncOp>) {
    let handle = next_op_handle();
    let op = Arc::new(DataPlaneAsyncOp {
        kind,
        instance_id,
        target_handle,
        cancel_token: CancellationToken::new(),
        state: Mutex::new(DataPlaneAsyncOpState::Pending),
        ready: Condvar::new(),
    });
    DATA_PLANE_OPS.insert(handle, op.clone());
    (handle, op)
}

#[cfg(feature = "ffi-dataplane")]
fn complete_op(op: &DataPlaneAsyncOp, result: Result<DataPlaneAsyncOpResult, String>) {
    let Ok(mut state) = op.state.lock() else {
        return;
    };
    if !matches!(*state, DataPlaneAsyncOpState::Pending) {
        return;
    }
    *state = match result {
        Ok(result) => DataPlaneAsyncOpState::Ready(Box::new(result)),
        Err(err) => DataPlaneAsyncOpState::Failed(err),
    };
    op.ready.notify_all();
}

#[cfg(feature = "ffi-dataplane")]
fn cancel_pending_op(op: &DataPlaneAsyncOp, reason: &str) {
    op.cancel_token.cancel();
    let Ok(mut state) = op.state.lock() else {
        return;
    };
    if matches!(*state, DataPlaneAsyncOpState::Pending) {
        *state = DataPlaneAsyncOpState::Failed(reason.to_string());
        op.ready.notify_all();
    }
}

#[cfg(feature = "ffi-dataplane")]
fn validate_max_len(max_len: u32) -> bool {
    if max_len > MAX_ASYNC_READ_LEN {
        set_error_msg(&format!(
            "max_len exceeds async data plane limit of {} bytes",
            MAX_ASYNC_READ_LEN
        ));
        false
    } else {
        true
    }
}

#[cfg(feature = "ffi-dataplane")]
fn validate_write_len(len: u32) -> bool {
    if len > MAX_ASYNC_WRITE_LEN {
        set_error_msg(&format!(
            "len exceeds async data plane write limit of {} bytes",
            MAX_ASYNC_WRITE_LEN
        ));
        false
    } else {
        true
    }
}

#[cfg(feature = "ffi-dataplane")]
fn usize_to_c_int(value: usize, name: &str) -> Option<std::ffi::c_int> {
    if value > std::ffi::c_int::MAX as usize {
        set_error_msg(&format!(
            "{} exceeds c_int limit of {}",
            name,
            std::ffi::c_int::MAX
        ));
        None
    } else {
        Some(value as std::ffi::c_int)
    }
}

#[cfg(feature = "ffi-dataplane")]
fn spawn_instance_runtime_op<Fut, F>(
    op: Arc<DataPlaneAsyncOp>,
    instance_id: Uuid,
    timeout_ms: u64,
    build: F,
) where
    Fut: Future<Output = Result<DataPlaneAsyncOpResult, String>> + Send + 'static,
    F: FnOnce(tokio::runtime::Handle, Duration) -> Fut + Send + 'static,
{
    let deadline = Instant::now() + timeout_duration(timeout_ms);
    ASYNC_RUNTIME.spawn_blocking(move || {
        let runtime = loop {
            if op.cancel_token.is_cancelled() {
                complete_op(&op, Err("data plane async op canceled".to_string()));
                return;
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait_for = remaining.min(Duration::from_millis(50));
            if let Some(runtime) =
                INSTANCE_MANAGER.data_plane_wait_runtime_handle(&instance_id, wait_for)
            {
                break runtime;
            }
            if remaining.is_zero() || Instant::now() >= deadline {
                complete_op(&op, Err("instance runtime is not ready".to_string()));
                return;
            }
        };
        if op.cancel_token.is_cancelled() {
            complete_op(&op, Err("data plane async op canceled".to_string()));
            return;
        }

        let runtime_for_task = runtime.clone();
        let op_for_complete = op.clone();
        runtime.spawn(async move {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let result = build(runtime_for_task, remaining).await;
            complete_op(&op_for_complete, result);
        });
    });
}

#[cfg(feature = "ffi-dataplane")]
fn state_status(state: &DataPlaneAsyncOpState) -> std::ffi::c_int {
    match state {
        DataPlaneAsyncOpState::Pending => DATA_PLANE_OP_PENDING,
        DataPlaneAsyncOpState::Ready(_) => DATA_PLANE_OP_READY,
        DataPlaneAsyncOpState::Failed(_) => DATA_PLANE_OP_FAILED,
        DataPlaneAsyncOpState::Consumed => DATA_PLANE_OP_INVALID,
    }
}

#[cfg(feature = "ffi-dataplane")]
fn take_completed_op(
    handle: u64,
    expected: DataPlaneAsyncOpKind,
) -> Option<DataPlaneAsyncOpResult> {
    let Some((_, op)) = DATA_PLANE_OPS.remove_if(&handle, |_, op| {
        if op.kind != expected {
            return false;
        }
        let Ok(state) = op.state.lock() else {
            return false;
        };
        match &*state {
            DataPlaneAsyncOpState::Ready(_) | DataPlaneAsyncOpState::Failed(_) => true,
            DataPlaneAsyncOpState::Pending | DataPlaneAsyncOpState::Consumed => false,
        }
    }) else {
        let Some(op) = DATA_PLANE_OPS.get(&handle).map(|op| op.clone()) else {
            set_error_msg("data plane async op not found");
            return None;
        };
        if op.kind != expected {
            set_error_msg("data plane async op type mismatch");
            return None;
        }
        let Ok(state) = op.state.lock() else {
            set_error_msg("failed to lock data plane async op");
            return None;
        };
        match &*state {
            DataPlaneAsyncOpState::Pending => {
                set_error_msg("data plane async op is still pending");
                return None;
            }
            DataPlaneAsyncOpState::Consumed => {
                set_error_msg("data plane async op already consumed");
                return None;
            }
            DataPlaneAsyncOpState::Ready(_) | DataPlaneAsyncOpState::Failed(_) => {
                set_error_msg("data plane async op was consumed concurrently");
            }
        }
        return None;
    };

    let completed = {
        let Ok(mut state) = op.state.lock() else {
            set_error_msg("failed to lock data plane async op");
            return None;
        };
        std::mem::replace(&mut *state, DataPlaneAsyncOpState::Consumed)
    };

    match completed {
        DataPlaneAsyncOpState::Ready(result) => Some(*result),
        DataPlaneAsyncOpState::Failed(err) => {
            set_error_msg(&err);
            None
        }
        DataPlaneAsyncOpState::Pending | DataPlaneAsyncOpState::Consumed => None,
    }
}

#[cfg(feature = "ffi-dataplane")]
async fn run_with_cancel<T, E, F>(
    cancel_token: &CancellationToken,
    error_prefix: &str,
    op: F,
) -> Result<T, String>
where
    E: std::fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancel_token.cancelled() => Err(format!("{}: operation canceled", error_prefix)),
        res = op => res.map_err(|err| format!("{}: {}", error_prefix, err)),
    }
}

#[cfg(feature = "ffi-dataplane")]
async fn run_io_with_cancel<T, F>(
    cancel_token: &CancellationToken,
    close_token: &CancellationToken,
    timeout_ms: u64,
    error_prefix: &str,
    op: F,
) -> Result<T, String>
where
    F: Future<Output = Result<T, std::io::Error>>,
{
    tokio::select! {
        biased;
        _ = cancel_token.cancelled() => Err(format!("{}: operation canceled", error_prefix)),
        _ = close_token.cancelled() => Err(format!("{}: handle closed", error_prefix)),
        res = tokio::time::timeout(timeout_duration(timeout_ms), op) => match res {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(format!("{}: {}", error_prefix, err)),
            Err(_) => Err(format!("{} timed out", error_prefix)),
        },
    }
}

#[cfg(feature = "ffi-dataplane")]
fn leak_bytes(data: Vec<u8>) -> (*const std::ffi::c_uchar, u32) {
    if data.is_empty() {
        return (std::ptr::null(), 0);
    }
    let len = data.len() as u32;
    let boxed = data.into_boxed_slice();
    (Box::into_raw(boxed) as *const std::ffi::c_uchar, len)
}

#[cfg(feature = "ffi-dataplane")]
unsafe fn write_addr(
    addr: SocketAddr,
    out_ip: *mut *const std::ffi::c_char,
    out_port: *mut std::ffi::c_ushort,
) -> Option<*mut std::ffi::c_char> {
    let ip = into_ffi_ip_cstring(addr.ip())?;
    unsafe {
        *out_ip = ip as *const std::ffi::c_char;
        *out_port = addr.port();
    }
    Some(ip)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn has_live_ops() -> bool {
    !DATA_PLANE_OPS.is_empty()
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn cancel_ops_for_handle(handle: u64) {
    let ops = DATA_PLANE_OPS
        .iter()
        .filter(|entry| entry.target_handle == Some(handle))
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    for op in ops {
        cancel_pending_op(
            &op,
            "data plane async op canceled because handle was closed",
        );
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn remove_ops_by_instance_ids(ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }

    let op_handles = DATA_PLANE_OPS
        .iter()
        .filter(|entry| entry.instance_id.is_some_and(|id| ids.contains(&id)))
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    for handle in op_handles {
        if let Some((_, op)) = DATA_PLANE_OPS.remove(&handle) {
            op.cancel_token.cancel();
            if let Ok(mut state) = op.state.lock() {
                *state = DataPlaneAsyncOpState::Consumed;
                op.ready.notify_all();
            }
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_async_op_status(handle: u64) -> std::ffi::c_int {
    let Some(op) = DATA_PLANE_OPS.get(&handle).map(|op| op.clone()) else {
        return DATA_PLANE_OP_INVALID;
    };
    let Ok(state) = op.state.lock() else {
        return DATA_PLANE_OP_FAILED;
    };
    state_status(&state)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_async_op_wait(handle: u64, timeout_ms: u64) -> std::ffi::c_int {
    let Some(op) = DATA_PLANE_OPS.get(&handle).map(|op| op.clone()) else {
        return DATA_PLANE_OP_INVALID;
    };
    let Ok(mut state) = op.state.lock() else {
        return DATA_PLANE_OP_FAILED;
    };
    if matches!(*state, DataPlaneAsyncOpState::Pending) && timeout_ms > 0 {
        let timeout = Duration::from_millis(timeout_ms);
        let Ok((next_state, _)) = op.ready.wait_timeout_while(state, timeout, |state| {
            matches!(state, DataPlaneAsyncOpState::Pending)
        }) else {
            return DATA_PLANE_OP_FAILED;
        };
        state = next_state;
    }
    state_status(&state)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_async_op_cancel(handle: u64) -> std::ffi::c_int {
    let Some(op) = DATA_PLANE_OPS.get(&handle).map(|op| op.clone()) else {
        return DATA_PLANE_OP_INVALID;
    };
    cancel_pending_op(&op, "data plane async op canceled");
    0
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_async_op_free(handle: u64) -> std::ffi::c_int {
    let Some((_, op)) = DATA_PLANE_OPS.remove(&handle) else {
        return DATA_PLANE_OP_INVALID;
    };
    op.cancel_token.cancel();
    if let Ok(mut state) = op.state.lock() {
        *state = DataPlaneAsyncOpState::Consumed;
        op.ready.notify_all();
    }
    0
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_free_bytes(ptr: *const std::ffi::c_uchar, len: u32) {
    if ptr.is_null() {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(ptr as *mut std::ffi::c_uchar, len as usize);
    unsafe {
        drop(Box::from_raw(slice));
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_connect_start(
    inst_name: *const std::ffi::c_char,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    timeout_ms: u64,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(dst_ip) = (unsafe { cstr_to_string(dst_ip, "dst_ip") }) else {
        return 0;
    };
    let Some(instance_id) = get_instance_id(&inst_name) else {
        set_error_msg("instance not found");
        return 0;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port) else {
        return 0;
    };

    let (handle, op) = new_op(DataPlaneAsyncOpKind::TcpConnect, Some(instance_id), None);
    let op_for_task = op.clone();
    spawn_instance_runtime_op(
        op,
        instance_id,
        timeout_ms,
        move |runtime_for_result, remaining| async move {
            run_with_cancel(
                &op_for_task.cancel_token,
                "failed to connect tcp data plane",
                INSTANCE_MANAGER.data_plane_tcp_connect(&instance_id, dst_addr, remaining),
            )
            .await
            .map(|stream| {
                let local_addr = stream.local_addr();
                DataPlaneAsyncOpResult::TcpConnect {
                    instance_id,
                    runtime: runtime_for_result,
                    stream,
                    local_addr,
                }
            })
        },
    );
    handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_connect_finish(
    op_handle: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    if out_local_ip.is_null() || out_local_port.is_null() {
        set_error_msg("output pointer is null");
        return 0;
    }
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::TcpConnect) else {
        return 0;
    };
    let DataPlaneAsyncOpResult::TcpConnect {
        instance_id,
        runtime,
        stream,
        local_addr,
    } = result
    else {
        set_error_msg("data plane async op result type mismatch");
        return 0;
    };
    let Some(_ip) = (unsafe { write_addr(local_addr, out_local_ip, out_local_port) }) else {
        return 0;
    };
    insert_tcp_stream_handle(instance_id, runtime, stream)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_bind_start(
    inst_name: *const std::ffi::c_char,
    local_port: std::ffi::c_ushort,
    timeout_ms: u64,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(instance_id) = get_instance_id(&inst_name) else {
        set_error_msg("instance not found");
        return 0;
    };

    let (handle, op) = new_op(DataPlaneAsyncOpKind::TcpBind, Some(instance_id), None);
    let op_for_task = op.clone();
    spawn_instance_runtime_op(
        op,
        instance_id,
        timeout_ms,
        move |runtime_for_result, remaining| async move {
            run_with_cancel(
                &op_for_task.cancel_token,
                "failed to bind tcp data plane",
                INSTANCE_MANAGER.data_plane_tcp_bind(&instance_id, local_port, remaining),
            )
            .await
            .map(|listener| {
                let local_addr = listener.local_addr();
                DataPlaneAsyncOpResult::TcpBind {
                    instance_id,
                    runtime: runtime_for_result,
                    listener,
                    local_addr,
                }
            })
        },
    );
    handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_bind_finish(
    op_handle: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    if out_local_ip.is_null() || out_local_port.is_null() {
        set_error_msg("output pointer is null");
        return 0;
    }
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::TcpBind) else {
        return 0;
    };
    let DataPlaneAsyncOpResult::TcpBind {
        instance_id,
        runtime,
        listener,
        local_addr,
    } = result
    else {
        set_error_msg("data plane async op result type mismatch");
        return 0;
    };
    let Some(_ip) = (unsafe { write_addr(local_addr, out_local_ip, out_local_port) }) else {
        return 0;
    };
    insert_tcp_listener_handle(instance_id, runtime, listener)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_accept_start(handle: u64, timeout_ms: u64) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some((listener, runtime, close_token, instance_id)) = get_tcp_listener(handle) else {
        return 0;
    };

    let (op_handle, op) = new_op(
        DataPlaneAsyncOpKind::TcpAccept,
        Some(instance_id),
        Some(handle),
    );
    let runtime_for_result = runtime.clone();
    runtime.spawn(async move {
        let result = async {
            let mut listener = listener.lock().await;
            let (stream, peer_addr) = run_io_with_cancel(
                &op.cancel_token,
                &close_token,
                timeout_ms,
                "tcp data plane accept",
                listener.accept(),
            )
            .await?;
            let local_addr = stream.local_addr();
            Ok(DataPlaneAsyncOpResult::TcpAccept {
                instance_id,
                runtime: runtime_for_result,
                stream,
                local_addr,
                peer_addr,
            })
        }
        .await;
        complete_op(&op, result);
    });
    op_handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_accept_finish(
    op_handle: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
    out_peer_ip: *mut *const std::ffi::c_char,
    out_peer_port: *mut std::ffi::c_ushort,
) -> u64 {
    if out_local_ip.is_null()
        || out_local_port.is_null()
        || out_peer_ip.is_null()
        || out_peer_port.is_null()
    {
        set_error_msg("output pointer is null");
        return 0;
    }
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::TcpAccept) else {
        return 0;
    };
    let DataPlaneAsyncOpResult::TcpAccept {
        instance_id,
        runtime,
        stream,
        local_addr,
        peer_addr,
    } = result
    else {
        set_error_msg("data plane async op result type mismatch");
        return 0;
    };
    let Some(local_ip) = (unsafe { write_addr(local_addr, out_local_ip, out_local_port) }) else {
        return 0;
    };
    if (unsafe { write_addr(peer_addr, out_peer_ip, out_peer_port) }).is_none() {
        free_string(local_ip);
        return 0;
    }
    insert_tcp_stream_handle(instance_id, runtime, stream)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_read_start(handle: u64, max_len: u32, timeout_ms: u64) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    if !validate_max_len(max_len) {
        return 0;
    }
    let Some((halves, runtime, close_token, instance_id)) = get_tcp_stream_with_instance(handle)
    else {
        return 0;
    };
    let (op_handle, op) = new_op(
        DataPlaneAsyncOpKind::TcpRead,
        Some(instance_id),
        Some(handle),
    );
    runtime.spawn(async move {
        let result = read_tcp(halves, op.clone(), close_token, max_len, timeout_ms).await;
        complete_op(&op, result);
    });
    op_handle
}

#[cfg(feature = "ffi-dataplane")]
async fn read_tcp(
    halves: Arc<TcpHalves>,
    op: Arc<DataPlaneAsyncOp>,
    close_token: CancellationToken,
    max_len: u32,
    timeout_ms: u64,
) -> Result<DataPlaneAsyncOpResult, String> {
    let mut buf = vec![0; max_len as usize];
    let mut rd = halves.read.lock().await;
    let n = run_io_with_cancel(
        &op.cancel_token,
        &close_token,
        timeout_ms,
        "failed to read tcp data plane",
        rd.read(&mut buf),
    )
    .await?;
    buf.truncate(n);
    Ok(DataPlaneAsyncOpResult::TcpRead { data: buf })
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_read_finish(
    op_handle: u64,
    out_buf: *mut *const std::ffi::c_uchar,
    out_len: *mut u32,
) -> std::ffi::c_int {
    if out_buf.is_null() || out_len.is_null() {
        set_error_msg("output pointer is null");
        return -1;
    }
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::TcpRead) else {
        return -1;
    };
    let DataPlaneAsyncOpResult::TcpRead { data } = result else {
        set_error_msg("data plane async op result type mismatch");
        return -1;
    };
    let (ptr, len) = leak_bytes(data);
    unsafe {
        *out_buf = ptr;
        *out_len = len;
    }
    len as std::ffi::c_int
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_tcp_write_start(
    handle: u64,
    buf: *const std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    if len > 0 && buf.is_null() {
        set_error_msg("buf is null");
        return 0;
    }
    if !validate_write_len(len) {
        return 0;
    }
    let Some((halves, runtime, close_token, instance_id)) = get_tcp_stream_with_instance(handle)
    else {
        return 0;
    };
    let data = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buf, len as usize) }.to_vec()
    };
    let (op_handle, op) = new_op(
        DataPlaneAsyncOpKind::TcpWrite,
        Some(instance_id),
        Some(handle),
    );
    runtime.spawn(async move {
        let result = write_tcp(halves, op.clone(), close_token, data, timeout_ms).await;
        complete_op(&op, result);
    });
    op_handle
}

#[cfg(feature = "ffi-dataplane")]
async fn write_tcp(
    halves: Arc<TcpHalves>,
    op: Arc<DataPlaneAsyncOp>,
    close_token: CancellationToken,
    data: Vec<u8>,
    timeout_ms: u64,
) -> Result<DataPlaneAsyncOpResult, String> {
    let written = data.len();
    let mut wr = halves.write.lock().await;
    run_io_with_cancel(
        &op.cancel_token,
        &close_token,
        timeout_ms,
        "failed to write tcp data plane",
        wr.write_all(&data),
    )
    .await?;
    Ok(DataPlaneAsyncOpResult::TcpWrite { written })
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_tcp_write_finish(op_handle: u64) -> std::ffi::c_int {
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::TcpWrite) else {
        return -1;
    };
    let DataPlaneAsyncOpResult::TcpWrite { written } = result else {
        set_error_msg("data plane async op result type mismatch");
        return -1;
    };
    usize_to_c_int(written, "tcp write byte count").unwrap_or(-1)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_udp_bind_start(
    inst_name: *const std::ffi::c_char,
    local_port: std::ffi::c_ushort,
    timeout_ms: u64,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(instance_id) = get_instance_id(&inst_name) else {
        set_error_msg("instance not found");
        return 0;
    };

    let (handle, op) = new_op(DataPlaneAsyncOpKind::UdpBind, Some(instance_id), None);
    let op_for_task = op.clone();
    spawn_instance_runtime_op(
        op,
        instance_id,
        timeout_ms,
        move |runtime_for_result, remaining| async move {
            run_with_cancel(
                &op_for_task.cancel_token,
                "failed to bind udp data plane",
                INSTANCE_MANAGER.data_plane_udp_bind(&instance_id, local_port, remaining),
            )
            .await
            .map(|socket| {
                let local_addr = socket.local_addr();
                DataPlaneAsyncOpResult::UdpBind {
                    instance_id,
                    runtime: runtime_for_result,
                    socket,
                    local_addr,
                }
            })
        },
    );
    handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_udp_bind_finish(
    op_handle: u64,
    out_local_ip: *mut *const std::ffi::c_char,
    out_local_port: *mut std::ffi::c_ushort,
) -> u64 {
    if out_local_ip.is_null() || out_local_port.is_null() {
        set_error_msg("output pointer is null");
        return 0;
    }
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::UdpBind) else {
        return 0;
    };
    let DataPlaneAsyncOpResult::UdpBind {
        instance_id,
        runtime,
        socket,
        local_addr,
    } = result
    else {
        set_error_msg("data plane async op result type mismatch");
        return 0;
    };
    let Some(_ip) = (unsafe { write_addr(local_addr, out_local_ip, out_local_port) }) else {
        return 0;
    };
    insert_udp_socket_handle(instance_id, runtime, socket)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_udp_send_to_start(
    handle: u64,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    buf: *const std::ffi::c_uchar,
    len: u32,
    timeout_ms: u64,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    if len > 0 && buf.is_null() {
        set_error_msg("buf is null");
        return 0;
    }
    if !validate_write_len(len) {
        return 0;
    }
    let Some(dst_ip) = (unsafe { cstr_to_string(dst_ip, "dst_ip") }) else {
        return 0;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port) else {
        return 0;
    };
    let Some((socket, runtime, close_token, instance_id)) = get_udp_socket_with_instance(handle)
    else {
        return 0;
    };
    let data = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buf, len as usize) }.to_vec()
    };

    let (op_handle, op) = new_op(
        DataPlaneAsyncOpKind::UdpSendTo,
        Some(instance_id),
        Some(handle),
    );
    runtime.spawn(async move {
        let result = run_io_with_cancel(
            &op.cancel_token,
            &close_token,
            timeout_ms,
            "failed to send udp data plane",
            socket.send_to(&data, dst_addr),
        )
        .await
        .map(|sent| DataPlaneAsyncOpResult::UdpSendTo { sent });
        complete_op(&op, result);
    });
    op_handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn data_plane_udp_send_to_finish(op_handle: u64) -> std::ffi::c_int {
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::UdpSendTo) else {
        return -1;
    };
    let DataPlaneAsyncOpResult::UdpSendTo { sent } = result else {
        set_error_msg("data plane async op result type mismatch");
        return -1;
    };
    usize_to_c_int(sent, "udp send byte count").unwrap_or(-1)
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_udp_recv_from_start(
    handle: u64,
    max_len: u32,
    timeout_ms: u64,
) -> u64 {
    let _data_plane_usage_guard = match enter_data_plane_operation() {
        Some(guard) => guard,
        None => return 0,
    };
    if !validate_max_len(max_len) {
        return 0;
    }
    let Some((socket, runtime, close_token, instance_id)) = get_udp_socket_with_instance(handle)
    else {
        return 0;
    };
    let (op_handle, op) = new_op(
        DataPlaneAsyncOpKind::UdpRecvFrom,
        Some(instance_id),
        Some(handle),
    );
    runtime.spawn(async move {
        let mut buf = vec![0; max_len as usize];
        let result = run_io_with_cancel(
            &op.cancel_token,
            &close_token,
            timeout_ms,
            "udp data plane receive",
            socket.recv_from(&mut buf),
        )
        .await
        .map(|(n, peer_addr)| {
            buf.truncate(n);
            DataPlaneAsyncOpResult::UdpRecvFrom {
                data: buf,
                peer_addr,
            }
        });
        complete_op(&op, result);
    });
    op_handle
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) unsafe fn data_plane_udp_recv_from_finish(
    op_handle: u64,
    out_buf: *mut *const std::ffi::c_uchar,
    out_len: *mut u32,
    out_ip: *mut *const std::ffi::c_char,
    out_port: *mut std::ffi::c_ushort,
) -> std::ffi::c_int {
    if out_buf.is_null() || out_len.is_null() || out_ip.is_null() || out_port.is_null() {
        set_error_msg("output pointer is null");
        return -1;
    }
    let Some(result) = take_completed_op(op_handle, DataPlaneAsyncOpKind::UdpRecvFrom) else {
        return -1;
    };
    let DataPlaneAsyncOpResult::UdpRecvFrom { data, peer_addr } = result else {
        set_error_msg("data plane async op result type mismatch");
        return -1;
    };
    let Some(_ip) = (unsafe { write_addr(peer_addr, out_ip, out_port) }) else {
        return -1;
    };
    let (ptr, len) = leak_bytes(data);
    unsafe {
        *out_buf = ptr;
        *out_len = len;
    }
    len as std::ffi::c_int
}

#[cfg(all(test, feature = "ffi-dataplane"))]
mod tests {
    use super::*;

    #[test]
    fn cancel_marks_pending_op_failed_and_consumable() {
        let (handle, _op) = new_op(DataPlaneAsyncOpKind::TcpRead, None, None);

        assert_eq!(data_plane_async_op_status(handle), DATA_PLANE_OP_PENDING);
        assert_eq!(data_plane_async_op_cancel(handle), 0);
        assert_eq!(data_plane_async_op_wait(handle, 0), DATA_PLANE_OP_FAILED);
        assert!(take_completed_op(handle, DataPlaneAsyncOpKind::TcpRead).is_none());
        assert_eq!(data_plane_async_op_status(handle), DATA_PLANE_OP_INVALID);
    }

    #[test]
    fn max_len_limit_rejects_oversized_async_reads() {
        assert!(validate_max_len(MAX_ASYNC_READ_LEN));
        assert!(!validate_max_len(MAX_ASYNC_READ_LEN + 1));
    }

    #[test]
    fn write_len_limit_rejects_values_that_c_int_cannot_return() {
        assert!(validate_write_len(MAX_ASYNC_WRITE_LEN));
        assert!(!validate_write_len(MAX_ASYNC_WRITE_LEN + 1));
    }

    #[test]
    fn finish_return_count_must_fit_c_int() {
        assert_eq!(usize_to_c_int(123, "test byte count"), Some(123));
        assert!(usize_to_c_int(std::ffi::c_int::MAX as usize + 1, "test byte count").is_none());
    }

    #[test]
    fn free_consumes_ready_op_before_finish_can_take_it() {
        let (handle, op) = new_op(DataPlaneAsyncOpKind::TcpRead, None, None);
        complete_op(&op, Ok(DataPlaneAsyncOpResult::TcpRead { data: vec![1] }));

        assert_eq!(data_plane_async_op_free(handle), 0);
        assert!(take_completed_op(handle, DataPlaneAsyncOpKind::TcpRead).is_none());
        assert_eq!(data_plane_async_op_status(handle), DATA_PLANE_OP_INVALID);
    }
}
