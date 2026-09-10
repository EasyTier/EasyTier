use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use easytier::instance::host::NativeInstanceHost;
use easytier_core::gateway::{
    DataPlaneCompletionDescriptor, DataPlaneError, DataPlaneErrorKind, DataPlaneOperationId,
    DataPlaneOperationKind, DataPlaneOperationResult, DataPlaneResourceId, DataPlaneSession,
};
use uuid::Uuid;

use crate::{
    config_server::{in_config_server_callback, is_config_server_active_or_stopping},
    state::{ffi_context, resolve_instance_id_by_name},
};

type CoreDataPlaneSession = DataPlaneSession<NativeInstanceHost>;

static NEXT_SESSION_HANDLE: AtomicU64 = AtomicU64::new(1);
static SESSIONS: once_cell::sync::Lazy<Mutex<HashMap<u64, Arc<NativeDataPlaneSession>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));
static DATA_PLANE_USAGE_LOCK: once_cell::sync::Lazy<RwLock<()>> =
    once_cell::sync::Lazy::new(|| RwLock::new(()));

#[derive(Debug)]
pub(super) struct NativeDataPlaneError {
    pub(super) kind: DataPlaneErrorKind,
    pub(super) message: String,
}

impl NativeDataPlaneError {
    fn new(kind: DataPlaneErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(DataPlaneErrorKind::Io, message)
    }

    fn closed(message: impl Into<String>) -> Self {
        Self::new(DataPlaneErrorKind::HandleClosed, message)
    }
}

impl From<DataPlaneError> for NativeDataPlaneError {
    fn from(error: DataPlaneError) -> Self {
        Self::new(error.kind(), error.message())
    }
}

pub(super) type NativeDataPlaneResult<T> = Result<T, NativeDataPlaneError>;

pub(super) struct TcpConnectResult {
    pub(super) stream: u64,
    pub(super) local_addr: SocketAddr,
    pub(super) peer_addr: SocketAddr,
}

pub(super) struct TcpBindResult {
    pub(super) listener: u64,
    pub(super) local_addr: SocketAddr,
}

pub(super) struct TcpAcceptResult {
    pub(super) stream: u64,
    pub(super) local_addr: SocketAddr,
    pub(super) peer_addr: SocketAddr,
}

pub(super) struct TcpReadResult {
    pub(super) len: usize,
    pub(super) eof: bool,
}

pub(super) struct UdpBindResult {
    pub(super) socket: u64,
    pub(super) local_addr: SocketAddr,
}

pub(super) struct UdpReceiveResult {
    pub(super) len: usize,
    pub(super) peer_addr: SocketAddr,
    pub(super) truncated: bool,
}

struct NativeDataPlaneSession {
    instance_id: Uuid,
    runtime: tokio::runtime::Handle,
    core: Arc<CoreDataPlaneSession>,
    submit_gate: Mutex<()>,
    closed: AtomicBool,
}

impl NativeDataPlaneSession {
    fn close(&self) {
        let _gate = self
            .submit_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.core.discard_all();
    }

    fn call<T>(
        &self,
        call: impl FnOnce(&Arc<CoreDataPlaneSession>) -> Result<T, DataPlaneError>,
    ) -> NativeDataPlaneResult<T> {
        let _gate = self
            .submit_gate
            .lock()
            .map_err(|error| NativeDataPlaneError::invalid(error.to_string()))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(NativeDataPlaneError::closed(
                "native data-plane session is closed",
            ));
        }
        let _runtime = self.runtime.enter();
        call(&self.core).map_err(Into::into)
    }

    fn submit(
        &self,
        submit: impl FnOnce(&Arc<CoreDataPlaneSession>) -> Result<DataPlaneOperationId, DataPlaneError>,
    ) -> NativeDataPlaneResult<u64> {
        self.call(submit).map(DataPlaneOperationId::get)
    }
}

fn sessions()
-> NativeDataPlaneResult<std::sync::MutexGuard<'static, HashMap<u64, Arc<NativeDataPlaneSession>>>>
{
    SESSIONS
        .lock()
        .map_err(|error| NativeDataPlaneError::invalid(error.to_string()))
}

fn get_session(handle: u64) -> NativeDataPlaneResult<Arc<NativeDataPlaneSession>> {
    if handle == 0 {
        return Err(NativeDataPlaneError::closed(
            "native data-plane session handle is invalid",
        ));
    }
    let session = sessions()?
        .get(&handle)
        .cloned()
        .ok_or_else(|| NativeDataPlaneError::closed("native data-plane session is closed"))?;
    if session.closed.load(Ordering::Acquire) {
        return Err(NativeDataPlaneError::closed(
            "native data-plane session is closed",
        ));
    }
    Ok(session)
}

fn next_session_handle(
    sessions: &HashMap<u64, Arc<NativeDataPlaneSession>>,
) -> NativeDataPlaneResult<u64> {
    for _ in 0..sessions.len().saturating_add(2) {
        let handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::Relaxed);
        if handle != 0 && !sessions.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(NativeDataPlaneError::new(
        DataPlaneErrorKind::ResourceLimit,
        "native data-plane session handle space is exhausted",
    ))
}

fn reject_data_plane_use() -> NativeDataPlaneResult<()> {
    if in_config_server_callback() {
        Err(NativeDataPlaneError::invalid(
            "cannot use data plane from config server callback",
        ))
    } else if is_config_server_active_or_stopping() {
        Err(NativeDataPlaneError::invalid(
            "cannot use data plane while config server client is active",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn open(inst_name: &str) -> NativeDataPlaneResult<u64> {
    reject_data_plane_use()?;
    let _usage = DATA_PLANE_USAGE_LOCK
        .read()
        .map_err(|error| NativeDataPlaneError::invalid(error.to_string()))?;
    reject_data_plane_use()?;

    let instance_id = resolve_instance_id_by_name(inst_name)
        .map_err(NativeDataPlaneError::invalid)?
        .ok_or_else(|| NativeDataPlaneError::closed("instance not found"))?;
    let manager = &ffi_context().manager;
    let core = manager.data_plane_session(&instance_id).ok_or_else(|| {
        NativeDataPlaneError::closed("instance data-plane session is unavailable")
    })?;
    let runtime = manager
        .data_plane_runtime_handle(&instance_id)
        .ok_or_else(|| NativeDataPlaneError::closed("instance runtime is unavailable"))?;

    let mut sessions = sessions()?;
    if sessions
        .values()
        .any(|session| session.instance_id == instance_id)
    {
        return Err(NativeDataPlaneError::new(
            DataPlaneErrorKind::ResourceLimit,
            "instance already has an open native data-plane session",
        ));
    }
    let handle = next_session_handle(&sessions)?;
    sessions.insert(
        handle,
        Arc::new(NativeDataPlaneSession {
            instance_id,
            runtime,
            core,
            submit_gate: Mutex::new(()),
            closed: AtomicBool::new(false),
        }),
    );
    Ok(handle)
}

pub(super) fn close(handle: u64) -> NativeDataPlaneResult<()> {
    let _usage = DATA_PLANE_USAGE_LOCK
        .read()
        .map_err(|error| NativeDataPlaneError::invalid(error.to_string()))?;
    let mut sessions = sessions()?;
    let session = sessions
        .remove(&handle)
        .ok_or_else(|| NativeDataPlaneError::closed("native data-plane session is closed"))?;
    // Keep the registry locked until the shared core namespace is empty. An
    // open for the same instance must not publish a replacement session before
    // this old wrapper finishes discarding its operations and resources.
    session.close();
    Ok(())
}

fn timeout(timeout_ms: u64) -> Option<Duration> {
    (timeout_ms != u64::MAX).then(|| Duration::from_millis(timeout_ms))
}

fn operation_id(raw: u64) -> NativeDataPlaneResult<DataPlaneOperationId> {
    DataPlaneOperationId::from_raw(raw)
        .ok_or_else(|| NativeDataPlaneError::closed("data-plane operation handle is invalid"))
}

fn resource_id(raw: u64) -> NativeDataPlaneResult<DataPlaneResourceId> {
    DataPlaneResourceId::from_raw(raw)
        .ok_or_else(|| NativeDataPlaneError::closed("data-plane resource handle is invalid"))
}

pub(super) fn submit_tcp_connect(
    session: u64,
    peer_addr: SocketAddr,
    timeout_ms: u64,
) -> NativeDataPlaneResult<u64> {
    get_session(session)?.submit(|core| core.submit_tcp_connect(peer_addr, timeout(timeout_ms)))
}

pub(super) fn submit_tcp_bind(
    session: u64,
    local_port: u16,
    timeout_ms: u64,
) -> NativeDataPlaneResult<u64> {
    get_session(session)?.submit(|core| core.submit_tcp_bind(local_port, timeout(timeout_ms)))
}

pub(super) fn submit_tcp_accept(
    session: u64,
    listener: u64,
    timeout_ms: u64,
) -> NativeDataPlaneResult<u64> {
    let listener = resource_id(listener)?;
    get_session(session)?.submit(|core| core.submit_tcp_accept(listener, timeout(timeout_ms)))
}

pub(super) fn submit_tcp_read(
    session: u64,
    stream: u64,
    max_len: u32,
) -> NativeDataPlaneResult<u64> {
    let stream = resource_id(stream)?;
    get_session(session)?.submit(|core| core.submit_tcp_read(stream, max_len as usize))
}

pub(super) fn submit_tcp_write(
    session: u64,
    stream: u64,
    data: Vec<u8>,
) -> NativeDataPlaneResult<u64> {
    let stream = resource_id(stream)?;
    get_session(session)?.submit(|core| core.submit_tcp_write(stream, data))
}

pub(super) fn submit_udp_bind(
    session: u64,
    local_port: u16,
    timeout_ms: u64,
) -> NativeDataPlaneResult<u64> {
    get_session(session)?.submit(|core| core.submit_udp_bind(local_port, timeout(timeout_ms)))
}

pub(super) fn submit_udp_receive(
    session: u64,
    socket: u64,
    max_len: u32,
) -> NativeDataPlaneResult<u64> {
    let socket = resource_id(socket)?;
    get_session(session)?.submit(|core| core.submit_udp_receive(socket, max_len as usize))
}

pub(super) fn submit_udp_send(
    session: u64,
    socket: u64,
    peer_addr: SocketAddr,
    data: Vec<u8>,
) -> NativeDataPlaneResult<u64> {
    let socket = resource_id(socket)?;
    get_session(session)?.submit(|core| core.submit_udp_send(socket, peer_addr, data))
}

pub(super) fn set_resource_deadline(
    session: u64,
    resource: u64,
    read: bool,
    write: bool,
    timeout_ms: u64,
) -> NativeDataPlaneResult<()> {
    let resource = resource_id(resource)?;
    get_session(session)?
        .call(|core| core.set_resource_deadline(resource, read, write, timeout(timeout_ms)))
}

pub(super) fn cancel_operation(session: u64, operation: u64) -> NativeDataPlaneResult<()> {
    let operation = operation_id(operation)?;
    get_session(session)?.core.cancel_operation(operation);
    Ok(())
}

pub(super) fn free_operation(session: u64, operation: u64) -> NativeDataPlaneResult<()> {
    let operation = operation_id(operation)?;
    get_session(session)?.core.free_operation(operation);
    Ok(())
}

pub(super) fn close_resource(session: u64, resource: u64) -> NativeDataPlaneResult<()> {
    let resource = resource_id(resource)?;
    get_session(session)?.core.close_resource(resource);
    Ok(())
}

pub(super) fn completion_wait(session: u64, timeout_ms: u64) -> NativeDataPlaneResult<bool> {
    let session = get_session(session)?;
    let ready = session.core.completion_wait(timeout(timeout_ms));
    Ok(ready && !session.closed.load(Ordering::Acquire))
}

pub(super) fn drain_completions(
    session: u64,
    max_count: usize,
) -> NativeDataPlaneResult<Vec<DataPlaneCompletionDescriptor>> {
    Ok(get_session(session)?.core.drain_completions(max_count))
}

pub(super) fn result_size(session: u64, operation: u64) -> NativeDataPlaneResult<usize> {
    let operation = operation_id(operation)?;
    get_session(session)?
        .core
        .result_payload_bytes(operation)
        .map_err(Into::into)
}

fn take_result<T>(
    session: u64,
    operation: u64,
    expected: DataPlaneOperationKind,
    take: impl FnOnce(&DataPlaneOperationResult) -> Option<T>,
) -> NativeDataPlaneResult<T> {
    let operation = operation_id(operation)?;
    let session = get_session(session)?;
    let actual = session.core.operation_kind(operation)?;
    if actual != expected {
        return Err(NativeDataPlaneError::invalid(format!(
            "operation kind mismatch: expected {expected:?}, got {actual:?}"
        )));
    }
    let result = session.core.take_result_with(operation, |outcome| {
        Some(match outcome {
            Ok(result) => take(result).ok_or_else(|| {
                NativeDataPlaneError::invalid("data-plane result variant does not match operation")
            }),
            Err(kind) => Err(NativeDataPlaneError::new(
                *kind,
                format!("data-plane operation failed with {kind:?}"),
            )),
        })
    })?;
    result
        .ok_or_else(|| NativeDataPlaneError::invalid("data-plane result could not be consumed"))?
}

pub(super) fn take_tcp_connect(
    session: u64,
    operation: u64,
) -> NativeDataPlaneResult<TcpConnectResult> {
    take_result(
        session,
        operation,
        DataPlaneOperationKind::TcpConnect,
        |result| match result {
            DataPlaneOperationResult::TcpConnected {
                stream,
                local_addr,
                peer_addr,
            } => Some(TcpConnectResult {
                stream: stream.get(),
                local_addr: *local_addr,
                peer_addr: *peer_addr,
            }),
            _ => None,
        },
    )
}

pub(super) fn take_tcp_bind(session: u64, operation: u64) -> NativeDataPlaneResult<TcpBindResult> {
    take_result(
        session,
        operation,
        DataPlaneOperationKind::TcpBind,
        |result| match result {
            DataPlaneOperationResult::TcpBound {
                listener,
                local_addr,
            } => Some(TcpBindResult {
                listener: listener.get(),
                local_addr: *local_addr,
            }),
            _ => None,
        },
    )
}

pub(super) fn take_tcp_accept(
    session: u64,
    operation: u64,
) -> NativeDataPlaneResult<TcpAcceptResult> {
    take_result(
        session,
        operation,
        DataPlaneOperationKind::TcpAccept,
        |result| match result {
            DataPlaneOperationResult::TcpAccepted {
                stream,
                local_addr,
                peer_addr,
            } => Some(TcpAcceptResult {
                stream: stream.get(),
                local_addr: *local_addr,
                peer_addr: *peer_addr,
            }),
            _ => None,
        },
    )
}

pub(super) fn take_tcp_read(
    session: u64,
    operation: u64,
    output: &mut [u8],
) -> NativeDataPlaneResult<TcpReadResult> {
    let required = result_size(session, operation)?;
    if output.len() < required {
        return Err(NativeDataPlaneError::new(
            DataPlaneErrorKind::BufferTooSmall,
            format!(
                "TCP read result requires {required} bytes, buffer has {}",
                output.len()
            ),
        ));
    }
    take_result(
        session,
        operation,
        DataPlaneOperationKind::TcpRead,
        |result| match result {
            DataPlaneOperationResult::TcpRead { data, eof } => {
                output[..data.len()].copy_from_slice(data);
                Some(TcpReadResult {
                    len: data.len(),
                    eof: *eof,
                })
            }
            _ => None,
        },
    )
}

pub(super) fn take_tcp_write(session: u64, operation: u64) -> NativeDataPlaneResult<usize> {
    take_result(
        session,
        operation,
        DataPlaneOperationKind::TcpWrite,
        |result| match result {
            DataPlaneOperationResult::TcpWritten { len } => Some(*len),
            _ => None,
        },
    )
}

pub(super) fn take_udp_bind(session: u64, operation: u64) -> NativeDataPlaneResult<UdpBindResult> {
    take_result(
        session,
        operation,
        DataPlaneOperationKind::UdpBind,
        |result| match result {
            DataPlaneOperationResult::UdpBound { socket, local_addr } => Some(UdpBindResult {
                socket: socket.get(),
                local_addr: *local_addr,
            }),
            _ => None,
        },
    )
}

pub(super) fn take_udp_receive(
    session: u64,
    operation: u64,
    output: &mut [u8],
) -> NativeDataPlaneResult<UdpReceiveResult> {
    let required = result_size(session, operation)?;
    if output.len() < required {
        return Err(NativeDataPlaneError::new(
            DataPlaneErrorKind::BufferTooSmall,
            format!(
                "UDP receive result requires {required} bytes, buffer has {}",
                output.len()
            ),
        ));
    }
    take_result(
        session,
        operation,
        DataPlaneOperationKind::UdpReceive,
        |result| match result {
            DataPlaneOperationResult::UdpReceived {
                data,
                peer_addr,
                truncated,
            } => {
                output[..data.len()].copy_from_slice(data);
                Some(UdpReceiveResult {
                    len: data.len(),
                    peer_addr: *peer_addr,
                    truncated: *truncated,
                })
            }
            _ => None,
        },
    )
}

pub(super) fn take_udp_send(session: u64, operation: u64) -> NativeDataPlaneResult<usize> {
    take_result(
        session,
        operation,
        DataPlaneOperationKind::UdpSend,
        |result| match result {
            DataPlaneOperationResult::UdpSent { len } => Some(*len),
            _ => None,
        },
    )
}

pub(crate) fn remove_data_plane_sessions_by_instance_ids(ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }
    let _usage = DATA_PLANE_USAGE_LOCK
        .write()
        .unwrap_or_else(|error| error.into_inner());
    let removed = {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|error| error.into_inner());
        let handles = sessions
            .iter()
            .filter_map(|(handle, session)| ids.contains(&session.instance_id).then_some(*handle))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| sessions.remove(&handle))
            .collect::<Vec<_>>()
    };
    for session in removed {
        session.close();
    }
}

pub(crate) fn lock_for_config_server_start()
-> Result<std::sync::RwLockWriteGuard<'static, ()>, String> {
    let guard = DATA_PLANE_USAGE_LOCK
        .write()
        .map_err(|error| format!("failed to lock data plane usage: {error}"))?;
    if !SESSIONS
        .lock()
        .map_err(|error| format!("failed to lock data-plane sessions: {error}"))?
        .is_empty()
    {
        return Err("cannot start config server client while data plane is in use".to_string());
    }
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use super::*;

    #[test]
    fn config_server_start_waits_for_session_open_or_close() {
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
}
