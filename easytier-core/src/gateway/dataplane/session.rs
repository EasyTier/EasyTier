//! Instance-scoped data-plane resources, operations, and completion delivery.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    net::SocketAddr,
    sync::{Arc, Condvar, Mutex, MutexGuard, Weak},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex as AsyncMutex,
};
use tokio_util::sync::CancellationToken;

use crate::socket::{
    tcp::{VirtualTcpListenerFactory, VirtualTcpSocketFactory},
    udp::VirtualUdpSocketFactory,
};

use super::{
    DataPlaneConsumerLease, DataPlaneDeadline, DataPlaneError, DataPlaneErrorKind, DataPlaneResult,
    DataPlaneRuntime, DataPlaneTcpConnectOptions, DataPlaneTcpListener, DataPlaneTcpStream,
    DataPlaneUdpSocket,
    operation::{
        DataPlaneCompletionDescriptor, DataPlaneCompletionStatus, DataPlaneOperationId,
        DataPlaneOperationKind, DataPlaneOperationOutcome, DataPlaneOperationResult,
        DataPlaneResourceId,
    },
};

const DEFAULT_MAX_RESOURCES: usize = 4_096;
const DEFAULT_MAX_OPERATIONS: usize = 4_096;
const DEFAULT_MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_READ_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPlaneSessionLimits {
    pub max_resources: usize,
    pub max_operations: usize,
    pub max_result_bytes: usize,
    pub max_read_size: usize,
}

impl Default for DataPlaneSessionLimits {
    fn default() -> Self {
        Self {
            max_resources: DEFAULT_MAX_RESOURCES,
            max_operations: DEFAULT_MAX_OPERATIONS,
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
            max_read_size: DEFAULT_MAX_READ_SIZE,
        }
    }
}

struct TcpResource {
    read: AsyncMutex<ReadHalf<DataPlaneTcpStream>>,
    write: AsyncMutex<WriteHalf<DataPlaneTcpStream>>,
}

struct UdpResource {
    socket: Arc<DataPlaneUdpSocket>,
    read: AsyncMutex<()>,
    write: AsyncMutex<()>,
}

#[derive(Clone)]
enum ResourceIo {
    Tcp(Arc<TcpResource>),
    TcpListener(Arc<AsyncMutex<DataPlaneTcpListener>>),
    Udp(Arc<UdpResource>),
}

struct ResourceEntry {
    io: ResourceIo,
    pending_operations: HashSet<DataPlaneOperationId>,
}

enum OperationSlotState {
    Pending,
    Queued(DataPlaneOperationOutcome),
    Drained(DataPlaneOperationOutcome),
    Discarding,
}

struct OperationSlot {
    kind: DataPlaneOperationKind,
    target: Option<DataPlaneResourceId>,
    cancel: CancellationToken,
    reserved_result_bytes: usize,
    reserves_resource: bool,
    state: OperationSlotState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionLifecycle {
    Created,
    Running,
    Stopped,
}

struct SessionState {
    lifecycle: SessionLifecycle,
    next_operation_id: u64,
    next_resource_id: u64,
    resources: HashMap<DataPlaneResourceId, ResourceEntry>,
    operations: HashMap<DataPlaneOperationId, OperationSlot>,
    completions: VecDeque<DataPlaneCompletionDescriptor>,
    reserved_resources: usize,
    retained_result_bytes: usize,
    wake_generation: u64,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            lifecycle: SessionLifecycle::Created,
            next_operation_id: 1,
            next_resource_id: 1,
            resources: HashMap::new(),
            operations: HashMap::new(),
            completions: VecDeque::new(),
            reserved_resources: 0,
            retained_result_bytes: 0,
            wake_generation: 0,
        }
    }
}

enum PendingOperationResult {
    TcpConnected {
        stream: DataPlaneTcpStream,
        peer_addr: SocketAddr,
    },
    TcpBound(DataPlaneTcpListener),
    TcpAccepted {
        stream: DataPlaneTcpStream,
        peer_addr: SocketAddr,
    },
    TcpRead {
        data: Vec<u8>,
        eof: bool,
    },
    TcpWritten(usize),
    UdpBound(DataPlaneUdpSocket),
    UdpReceived {
        data: Vec<u8>,
        peer_addr: SocketAddr,
        truncated: bool,
    },
    UdpSent(usize),
}

pub struct DataPlaneSession<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    runtime: Weak<DataPlaneRuntime<H>>,
    consumer_lease: Mutex<Option<DataPlaneConsumerLease>>,
    limits: DataPlaneSessionLimits,
    state: Mutex<SessionState>,
    completion_condvar: Condvar,
    completion_notify: tokio::sync::Notify,
}

impl<H> DataPlaneSession<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub(crate) fn new(runtime: &Arc<DataPlaneRuntime<H>>) -> Arc<Self> {
        Self::with_runtime(Arc::downgrade(runtime), DataPlaneSessionLimits::default())
    }

    fn with_runtime(
        runtime: Weak<DataPlaneRuntime<H>>,
        limits: DataPlaneSessionLimits,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            consumer_lease: Mutex::new(None),
            limits,
            state: Mutex::new(SessionState::default()),
            completion_condvar: Condvar::new(),
            completion_notify: tokio::sync::Notify::new(),
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn error(kind: DataPlaneErrorKind, message: &'static str) -> DataPlaneError {
        DataPlaneError::new(kind, message)
    }

    fn ensure_executor() -> DataPlaneResult<()> {
        tokio::runtime::Handle::try_current()
            .map(|_| ())
            .map_err(|_| {
                Self::error(
                    DataPlaneErrorKind::PathNotReady,
                    "data-plane operations require an active Tokio runtime",
                )
            })
    }

    fn runtime(&self) -> DataPlaneResult<Arc<DataPlaneRuntime<H>>> {
        let runtime = self.runtime.upgrade().ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::InstanceStopped,
                "data-plane runtime is no longer available",
            )
        })?;
        let mut lease = self
            .consumer_lease
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if lease.is_none() {
            lease.replace(runtime.acquire_consumer_lease()?);
        }
        Ok(runtime)
    }

    pub(crate) fn start(&self) -> DataPlaneResult<()> {
        let mut state = self.lock_state();
        match state.lifecycle {
            SessionLifecycle::Created => {
                state.lifecycle = SessionLifecycle::Running;
                Ok(())
            }
            SessionLifecycle::Running => Ok(()),
            SessionLifecycle::Stopped => Err(Self::error(
                DataPlaneErrorKind::InstanceStopped,
                "data-plane session is stopped",
            )),
        }
    }

    pub fn limits(&self) -> DataPlaneSessionLimits {
        self.limits
    }

    fn next_operation_id(state: &mut SessionState) -> DataPlaneResult<DataPlaneOperationId> {
        let id = DataPlaneOperationId::from_raw(state.next_operation_id).ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "data-plane operation ID space is exhausted",
            )
        })?;
        state.next_operation_id = state.next_operation_id.checked_add(1).ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "data-plane operation ID space is exhausted",
            )
        })?;
        Ok(id)
    }

    fn next_resource_id(state: &mut SessionState) -> DataPlaneResult<DataPlaneResourceId> {
        let id = DataPlaneResourceId::from_raw(state.next_resource_id).ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "data-plane resource ID space is exhausted",
            )
        })?;
        state.next_resource_id = state.next_resource_id.checked_add(1).ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "data-plane resource ID space is exhausted",
            )
        })?;
        Ok(id)
    }

    fn admit_locked(
        &self,
        state: &mut SessionState,
        kind: DataPlaneOperationKind,
        target: Option<DataPlaneResourceId>,
        reserved_result_bytes: usize,
        reserves_resource: bool,
    ) -> DataPlaneResult<(DataPlaneOperationId, CancellationToken)> {
        if state.lifecycle != SessionLifecycle::Running {
            return Err(Self::error(
                DataPlaneErrorKind::InstanceStopped,
                "data-plane session is not running",
            ));
        }
        if state.operations.len() >= self.limits.max_operations {
            return Err(Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "too many outstanding data-plane operations",
            ));
        }
        let retained_result_bytes = state
            .retained_result_bytes
            .checked_add(reserved_result_bytes)
            .ok_or_else(|| {
                Self::error(
                    DataPlaneErrorKind::ResourceLimit,
                    "data-plane result-byte accounting overflow",
                )
            })?;
        if retained_result_bytes > self.limits.max_result_bytes {
            return Err(Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "data-plane retained-result limit reached",
            ));
        }
        if reserves_resource {
            let resource_usage = state
                .resources
                .len()
                .checked_add(state.reserved_resources)
                .ok_or_else(|| {
                    Self::error(
                        DataPlaneErrorKind::ResourceLimit,
                        "data-plane resource accounting overflow",
                    )
                })?;
            if resource_usage >= self.limits.max_resources {
                return Err(Self::error(
                    DataPlaneErrorKind::ResourceLimit,
                    "too many open data-plane resources",
                ));
            }
        }

        let operation_id = Self::next_operation_id(state)?;
        let cancel = CancellationToken::new();
        state.retained_result_bytes = retained_result_bytes;
        if reserves_resource {
            state.reserved_resources += 1;
        }
        state.operations.insert(
            operation_id,
            OperationSlot {
                kind,
                target,
                cancel: cancel.clone(),
                reserved_result_bytes,
                reserves_resource,
                state: OperationSlotState::Pending,
            },
        );
        if let Some(resource_id) = target {
            state
                .resources
                .get_mut(&resource_id)
                .expect("target resource was validated before admission")
                .pending_operations
                .insert(operation_id);
        }
        Ok((operation_id, cancel))
    }

    fn require_read_size(&self, max_len: usize) -> DataPlaneResult<()> {
        if max_len > self.limits.max_read_size {
            return Err(Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "data-plane read allocation exceeds the per-operation limit",
            ));
        }
        Ok(())
    }

    fn resource_io(
        state: &SessionState,
        resource_id: DataPlaneResourceId,
    ) -> DataPlaneResult<ResourceIo> {
        state
            .resources
            .get(&resource_id)
            .map(|resource| resource.io.clone())
            .ok_or_else(|| {
                Self::error(
                    DataPlaneErrorKind::HandleClosed,
                    "data-plane resource is closed",
                )
            })
    }

    fn require_tcp(
        state: &SessionState,
        resource_id: DataPlaneResourceId,
    ) -> DataPlaneResult<Arc<TcpResource>> {
        match Self::resource_io(state, resource_id)? {
            ResourceIo::Tcp(resource) => Ok(resource),
            ResourceIo::TcpListener(_) | ResourceIo::Udp(_) => Err(Self::error(
                DataPlaneErrorKind::HandleClosed,
                "data-plane resource is not a TCP stream",
            )),
        }
    }

    fn require_tcp_listener(
        state: &SessionState,
        resource_id: DataPlaneResourceId,
    ) -> DataPlaneResult<Arc<AsyncMutex<DataPlaneTcpListener>>> {
        match Self::resource_io(state, resource_id)? {
            ResourceIo::TcpListener(resource) => Ok(resource),
            ResourceIo::Tcp(_) | ResourceIo::Udp(_) => Err(Self::error(
                DataPlaneErrorKind::HandleClosed,
                "data-plane resource is not a TCP listener",
            )),
        }
    }

    fn require_udp(
        state: &SessionState,
        resource_id: DataPlaneResourceId,
    ) -> DataPlaneResult<Arc<UdpResource>> {
        match Self::resource_io(state, resource_id)? {
            ResourceIo::Udp(resource) => Ok(resource),
            ResourceIo::Tcp(_) | ResourceIo::TcpListener(_) => Err(Self::error(
                DataPlaneErrorKind::HandleClosed,
                "data-plane resource is not a UDP socket",
            )),
        }
    }

    async fn run_operation<T, E>(
        cancel: CancellationToken,
        deadline: DataPlaneDeadline,
        future: impl Future<Output = Result<T, E>>,
    ) -> DataPlaneResult<T>
    where
        E: Into<DataPlaneError>,
    {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Self::error(
                DataPlaneErrorKind::Cancelled,
                "data-plane operation cancelled",
            )),
            result = deadline.run(future) => result,
        }
    }

    fn spawn_operation(
        self: &Arc<Self>,
        operation_id: DataPlaneOperationId,
        future: impl Future<Output = DataPlaneResult<PendingOperationResult>> + Send + 'static,
    ) {
        let session = Arc::downgrade(self);
        tokio::spawn(async move {
            let result = future.await;
            if let Some(session) = session.upgrade() {
                session.complete_operation(operation_id, result);
            }
        });
    }

    pub fn submit_tcp_connect(
        self: &Arc<Self>,
        peer_addr: SocketAddr,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let runtime = self.runtime()?;
        let (operation_id, cancel) = {
            let mut state = self.lock_state();
            self.admit_locked(
                &mut state,
                DataPlaneOperationKind::TcpConnect,
                None,
                0,
                true,
            )?
        };
        self.spawn_operation(operation_id, async move {
            let options = DataPlaneTcpConnectOptions::public_with_deadline(deadline);
            let stream =
                Self::run_operation(cancel, deadline, runtime.connect_tcp(peer_addr, options))
                    .await?;
            Ok(PendingOperationResult::TcpConnected { stream, peer_addr })
        });
        Ok(operation_id)
    }

    pub fn submit_tcp_bind(
        self: &Arc<Self>,
        local_port: u16,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let runtime = self.runtime()?;
        let (operation_id, cancel) = {
            let mut state = self.lock_state();
            self.admit_locked(&mut state, DataPlaneOperationKind::TcpBind, None, 0, true)?
        };
        self.spawn_operation(operation_id, async move {
            let listener = Self::run_operation(
                cancel,
                deadline,
                runtime.data_plane_tcp_bind_with_deadline(local_port, deadline),
            )
            .await?;
            Ok(PendingOperationResult::TcpBound(listener))
        });
        Ok(operation_id)
    }

    pub fn submit_tcp_accept(
        self: &Arc<Self>,
        listener_id: DataPlaneResourceId,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let (listener, operation_id, cancel) = {
            let mut state = self.lock_state();
            let listener = Self::require_tcp_listener(&state, listener_id)?;
            let (operation_id, cancel) = self.admit_locked(
                &mut state,
                DataPlaneOperationKind::TcpAccept,
                Some(listener_id),
                0,
                true,
            )?;
            (listener, operation_id, cancel)
        };
        self.spawn_operation(operation_id, async move {
            let (stream, peer_addr) = Self::run_operation(cancel, deadline, async move {
                listener.lock().await.accept().await
            })
            .await?;
            Ok(PendingOperationResult::TcpAccepted { stream, peer_addr })
        });
        Ok(operation_id)
    }

    pub fn submit_tcp_read(
        self: &Arc<Self>,
        stream_id: DataPlaneResourceId,
        max_len: usize,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        self.require_read_size(max_len)?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let (stream, operation_id, cancel) = {
            let mut state = self.lock_state();
            let stream = Self::require_tcp(&state, stream_id)?;
            let (operation_id, cancel) = self.admit_locked(
                &mut state,
                DataPlaneOperationKind::TcpRead,
                Some(stream_id),
                max_len,
                false,
            )?;
            (stream, operation_id, cancel)
        };
        if max_len == 0 {
            self.complete_operation(
                operation_id,
                Ok(PendingOperationResult::TcpRead {
                    data: Vec::new(),
                    eof: false,
                }),
            );
            return Ok(operation_id);
        }
        self.spawn_operation(operation_id, async move {
            let (data, eof) = Self::run_operation(cancel, deadline, async move {
                let mut data = vec![0u8; max_len];
                let len = stream.read.lock().await.read(&mut data).await?;
                data.truncate(len);
                Ok::<_, std::io::Error>((data, len == 0))
            })
            .await?;
            Ok(PendingOperationResult::TcpRead { data, eof })
        });
        Ok(operation_id)
    }

    pub fn submit_tcp_write(
        self: &Arc<Self>,
        stream_id: DataPlaneResourceId,
        data: Vec<u8>,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let (stream, operation_id, cancel) = {
            let mut state = self.lock_state();
            let stream = Self::require_tcp(&state, stream_id)?;
            let (operation_id, cancel) = self.admit_locked(
                &mut state,
                DataPlaneOperationKind::TcpWrite,
                Some(stream_id),
                0,
                false,
            )?;
            (stream, operation_id, cancel)
        };
        self.spawn_operation(operation_id, async move {
            let len = Self::run_operation(cancel, deadline, async move {
                stream.write.lock().await.write(&data).await
            })
            .await?;
            Ok(PendingOperationResult::TcpWritten(len))
        });
        Ok(operation_id)
    }

    pub fn submit_udp_bind(
        self: &Arc<Self>,
        local_port: u16,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let runtime = self.runtime()?;
        let (operation_id, cancel) = {
            let mut state = self.lock_state();
            self.admit_locked(&mut state, DataPlaneOperationKind::UdpBind, None, 0, true)?
        };
        self.spawn_operation(operation_id, async move {
            let socket = Self::run_operation(
                cancel,
                deadline,
                runtime.data_plane_udp_bind_with_deadline(local_port, deadline),
            )
            .await?;
            Ok(PendingOperationResult::UdpBound(socket))
        });
        Ok(operation_id)
    }

    pub fn submit_udp_receive(
        self: &Arc<Self>,
        socket_id: DataPlaneResourceId,
        max_len: usize,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        self.require_read_size(max_len)?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let (socket, operation_id, cancel) = {
            let mut state = self.lock_state();
            let socket = Self::require_udp(&state, socket_id)?;
            let (operation_id, cancel) = self.admit_locked(
                &mut state,
                DataPlaneOperationKind::UdpReceive,
                Some(socket_id),
                max_len,
                false,
            )?;
            (socket, operation_id, cancel)
        };
        self.spawn_operation(operation_id, async move {
            let (data, peer_addr, truncated) = Self::run_operation(cancel, deadline, async move {
                let _read = socket.read.lock().await;
                socket.socket.recv_from_limited(max_len).await
            })
            .await?;
            Ok(PendingOperationResult::UdpReceived {
                data,
                peer_addr,
                truncated,
            })
        });
        Ok(operation_id)
    }

    pub fn submit_udp_send(
        self: &Arc<Self>,
        socket_id: DataPlaneResourceId,
        peer_addr: SocketAddr,
        data: Vec<u8>,
        timeout: Option<Duration>,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        Self::ensure_executor()?;
        let deadline = DataPlaneDeadline::from_optional_timeout(timeout);
        let (socket, operation_id, cancel) = {
            let mut state = self.lock_state();
            let socket = Self::require_udp(&state, socket_id)?;
            let (operation_id, cancel) = self.admit_locked(
                &mut state,
                DataPlaneOperationKind::UdpSend,
                Some(socket_id),
                0,
                false,
            )?;
            (socket, operation_id, cancel)
        };
        self.spawn_operation(operation_id, async move {
            let len = Self::run_operation(cancel, deadline, async move {
                let _write = socket.write.lock().await;
                socket.socket.send_to(&data, peer_addr).await
            })
            .await?;
            Ok(PendingOperationResult::UdpSent(len))
        });
        Ok(operation_id)
    }

    fn unlink_target_locked(
        state: &mut SessionState,
        operation_id: DataPlaneOperationId,
        target: Option<DataPlaneResourceId>,
    ) {
        if let Some(resource_id) = target
            && let Some(resource) = state.resources.get_mut(&resource_id)
        {
            resource.pending_operations.remove(&operation_id);
        }
    }

    fn release_result_reservation_locked(state: &mut SessionState, slot: &mut OperationSlot) {
        state.retained_result_bytes = state
            .retained_result_bytes
            .saturating_sub(slot.reserved_result_bytes);
        slot.reserved_result_bytes = 0;
    }

    fn release_resource_reservation_locked(state: &mut SessionState, slot: &mut OperationSlot) {
        if slot.reserves_resource {
            state.reserved_resources = state.reserved_resources.saturating_sub(1);
            slot.reserves_resource = false;
        }
    }

    fn insert_tcp_resource_locked(
        state: &mut SessionState,
        stream: DataPlaneTcpStream,
    ) -> DataPlaneResult<DataPlaneResourceId> {
        let resource_id = Self::next_resource_id(state)?;
        let (read, write) = tokio::io::split(stream);
        state.resources.insert(
            resource_id,
            ResourceEntry {
                io: ResourceIo::Tcp(Arc::new(TcpResource {
                    read: AsyncMutex::new(read),
                    write: AsyncMutex::new(write),
                })),
                pending_operations: HashSet::new(),
            },
        );
        Ok(resource_id)
    }

    fn insert_listener_resource_locked(
        state: &mut SessionState,
        listener: DataPlaneTcpListener,
    ) -> DataPlaneResult<DataPlaneResourceId> {
        let resource_id = Self::next_resource_id(state)?;
        state.resources.insert(
            resource_id,
            ResourceEntry {
                io: ResourceIo::TcpListener(Arc::new(AsyncMutex::new(listener))),
                pending_operations: HashSet::new(),
            },
        );
        Ok(resource_id)
    }

    fn insert_udp_resource_locked(
        state: &mut SessionState,
        socket: DataPlaneUdpSocket,
    ) -> DataPlaneResult<DataPlaneResourceId> {
        let resource_id = Self::next_resource_id(state)?;
        state.resources.insert(
            resource_id,
            ResourceEntry {
                io: ResourceIo::Udp(Arc::new(UdpResource {
                    socket: Arc::new(socket),
                    read: AsyncMutex::new(()),
                    write: AsyncMutex::new(()),
                })),
                pending_operations: HashSet::new(),
            },
        );
        Ok(resource_id)
    }

    fn finalize_success_locked(
        state: &mut SessionState,
        slot: &mut OperationSlot,
        result: PendingOperationResult,
    ) -> DataPlaneResult<DataPlaneOperationResult> {
        let result = match result {
            PendingOperationResult::TcpConnected { stream, peer_addr } => {
                let local_addr = stream.local_addr();
                let stream = Self::insert_tcp_resource_locked(state, stream)?;
                DataPlaneOperationResult::TcpConnected {
                    stream,
                    local_addr,
                    peer_addr,
                }
            }
            PendingOperationResult::TcpBound(listener) => {
                let local_addr = listener.local_addr();
                let listener = Self::insert_listener_resource_locked(state, listener)?;
                DataPlaneOperationResult::TcpBound {
                    listener,
                    local_addr,
                }
            }
            PendingOperationResult::TcpAccepted { stream, peer_addr } => {
                let local_addr = stream.local_addr();
                let stream = Self::insert_tcp_resource_locked(state, stream)?;
                DataPlaneOperationResult::TcpAccepted {
                    stream,
                    local_addr,
                    peer_addr,
                }
            }
            PendingOperationResult::TcpRead { data, eof } => {
                DataPlaneOperationResult::TcpRead { data, eof }
            }
            PendingOperationResult::TcpWritten(len) => DataPlaneOperationResult::TcpWritten { len },
            PendingOperationResult::UdpBound(socket) => {
                let local_addr = socket.local_addr();
                let socket = Self::insert_udp_resource_locked(state, socket)?;
                DataPlaneOperationResult::UdpBound { socket, local_addr }
            }
            PendingOperationResult::UdpReceived {
                data,
                peer_addr,
                truncated,
            } => DataPlaneOperationResult::UdpReceived {
                data,
                peer_addr,
                truncated,
            },
            PendingOperationResult::UdpSent(len) => DataPlaneOperationResult::UdpSent { len },
        };

        let retained_bytes = result.retained_bytes();
        if retained_bytes > slot.reserved_result_bytes {
            return Err(Self::error(
                DataPlaneErrorKind::ResourceLimit,
                "data-plane operation exceeded its reserved result bytes",
            ));
        }
        state.retained_result_bytes -= slot.reserved_result_bytes - retained_bytes;
        slot.reserved_result_bytes = retained_bytes;
        Self::release_resource_reservation_locked(state, slot);
        Ok(result)
    }

    fn enqueue_outcome_locked(
        state: &mut SessionState,
        operation_id: DataPlaneOperationId,
        slot: &mut OperationSlot,
        outcome: DataPlaneOperationOutcome,
    ) -> bool {
        let status = match &outcome {
            Ok(_) => DataPlaneCompletionStatus::Success,
            Err(kind) => DataPlaneCompletionStatus::Error(*kind),
        };
        let notify = state.completions.is_empty();
        state.completions.push_back(DataPlaneCompletionDescriptor {
            operation_id,
            kind: slot.kind,
            status,
        });
        slot.state = OperationSlotState::Queued(outcome);
        notify
    }

    fn complete_operation(
        &self,
        operation_id: DataPlaneOperationId,
        result: DataPlaneResult<PendingOperationResult>,
    ) {
        let mut state = self.lock_state();
        let Some(mut slot) = state.operations.remove(&operation_id) else {
            return;
        };
        let slot_state = std::mem::replace(&mut slot.state, OperationSlotState::Discarding);
        let notify = match slot_state {
            OperationSlotState::Pending => {
                Self::unlink_target_locked(&mut state, operation_id, slot.target);
                let outcome = match result {
                    Ok(result) => {
                        match Self::finalize_success_locked(&mut state, &mut slot, result) {
                            Ok(result) => Ok(result),
                            Err(error) => {
                                Self::release_result_reservation_locked(&mut state, &mut slot);
                                Self::release_resource_reservation_locked(&mut state, &mut slot);
                                Err(error.kind())
                            }
                        }
                    }
                    Err(error) => {
                        tracing::debug!(
                            ?operation_id,
                            kind = ?slot.kind,
                            error = %error,
                            "data-plane operation failed"
                        );
                        Self::release_result_reservation_locked(&mut state, &mut slot);
                        Self::release_resource_reservation_locked(&mut state, &mut slot);
                        Err(error.kind())
                    }
                };
                let notify =
                    Self::enqueue_outcome_locked(&mut state, operation_id, &mut slot, outcome);
                state.operations.insert(operation_id, slot);
                notify
            }
            OperationSlotState::Discarding => false,
            other @ (OperationSlotState::Queued(_) | OperationSlotState::Drained(_)) => {
                slot.state = other;
                state.operations.insert(operation_id, slot);
                false
            }
        };
        drop(state);
        if notify {
            self.notify_completion();
        }
    }

    fn queue_error_locked(
        state: &mut SessionState,
        operation_id: DataPlaneOperationId,
        kind: DataPlaneErrorKind,
    ) -> bool {
        let Some(mut slot) = state.operations.remove(&operation_id) else {
            return false;
        };
        if !matches!(slot.state, OperationSlotState::Pending) {
            state.operations.insert(operation_id, slot);
            return false;
        }
        slot.cancel.cancel();
        Self::unlink_target_locked(state, operation_id, slot.target);
        Self::release_result_reservation_locked(state, &mut slot);
        Self::release_resource_reservation_locked(state, &mut slot);
        let notify = Self::enqueue_outcome_locked(state, operation_id, &mut slot, Err(kind));
        state.operations.insert(operation_id, slot);
        notify
    }

    fn close_resource_locked(
        state: &mut SessionState,
        resource_id: DataPlaneResourceId,
        pending_kind: DataPlaneErrorKind,
    ) -> bool {
        let Some(resource) = state.resources.remove(&resource_id) else {
            return false;
        };
        resource
            .pending_operations
            .into_iter()
            .fold(false, |notify, operation_id| {
                Self::queue_error_locked(state, operation_id, pending_kind) || notify
            })
    }

    fn discard_outcome_locked(
        state: &mut SessionState,
        outcome: DataPlaneOperationOutcome,
    ) -> bool {
        match outcome {
            Ok(result) => result.created_resource().is_some_and(|resource_id| {
                Self::close_resource_locked(state, resource_id, DataPlaneErrorKind::HandleClosed)
            }),
            Err(_) => false,
        }
    }

    fn notify_completion(&self) {
        self.completion_condvar.notify_all();
        self.completion_notify.notify_one();
    }

    pub fn cancel_operation(&self, operation_id: DataPlaneOperationId) {
        let mut state = self.lock_state();
        let notify =
            Self::queue_error_locked(&mut state, operation_id, DataPlaneErrorKind::Cancelled);
        drop(state);
        if notify {
            self.notify_completion();
        }
    }

    pub fn free_operation(&self, operation_id: DataPlaneOperationId) {
        let mut state = self.lock_state();
        let Some(mut slot) = state.operations.remove(&operation_id) else {
            return;
        };
        let slot_state = std::mem::replace(&mut slot.state, OperationSlotState::Discarding);
        let notify = match slot_state {
            OperationSlotState::Pending => {
                slot.cancel.cancel();
                Self::unlink_target_locked(&mut state, operation_id, slot.target);
                Self::release_result_reservation_locked(&mut state, &mut slot);
                Self::release_resource_reservation_locked(&mut state, &mut slot);
                slot.state = OperationSlotState::Discarding;
                state.operations.insert(operation_id, slot);
                false
            }
            OperationSlotState::Queued(outcome) => {
                state
                    .completions
                    .retain(|completion| completion.operation_id != operation_id);
                Self::release_result_reservation_locked(&mut state, &mut slot);
                Self::discard_outcome_locked(&mut state, outcome)
            }
            OperationSlotState::Drained(outcome) => {
                Self::release_result_reservation_locked(&mut state, &mut slot);
                Self::discard_outcome_locked(&mut state, outcome)
            }
            OperationSlotState::Discarding => {
                slot.state = OperationSlotState::Discarding;
                state.operations.insert(operation_id, slot);
                false
            }
        };
        drop(state);
        if notify {
            self.notify_completion();
        }
    }

    pub fn close_resource(&self, resource_id: DataPlaneResourceId) {
        let mut state = self.lock_state();
        let notify =
            Self::close_resource_locked(&mut state, resource_id, DataPlaneErrorKind::HandleClosed);
        drop(state);
        if notify {
            self.notify_completion();
        }
    }

    pub fn drain_completions(&self, max_count: usize) -> Vec<DataPlaneCompletionDescriptor> {
        let mut state = self.lock_state();
        let mut completions = Vec::with_capacity(max_count.min(state.completions.len()));
        while completions.len() < max_count {
            let Some(completion) = state.completions.pop_front() else {
                break;
            };
            let Some(slot) = state.operations.get_mut(&completion.operation_id) else {
                continue;
            };
            let old_state = std::mem::replace(&mut slot.state, OperationSlotState::Discarding);
            match old_state {
                OperationSlotState::Queued(outcome) => {
                    slot.state = OperationSlotState::Drained(outcome);
                    completions.push(completion);
                }
                other => {
                    slot.state = other;
                }
            }
        }
        completions
    }

    pub fn has_completions(&self) -> bool {
        !self.lock_state().completions.is_empty()
    }

    pub fn completion_wait(&self, timeout: Option<Duration>) -> bool {
        self.completion_wait_after_ready(timeout, || {})
    }

    fn completion_wait_after_ready(&self, timeout: Option<Duration>, ready: impl FnOnce()) -> bool {
        let state = self.lock_state();
        if !state.completions.is_empty() {
            return true;
        }
        if state.lifecycle == SessionLifecycle::Stopped {
            return false;
        }
        let wake_generation = state.wake_generation;
        ready();

        let state = match timeout {
            Some(timeout) => {
                self.completion_condvar
                    .wait_timeout_while(state, timeout, |state| {
                        state.completions.is_empty()
                            && state.lifecycle != SessionLifecycle::Stopped
                            && state.wake_generation == wake_generation
                    })
                    .unwrap_or_else(|error| error.into_inner())
                    .0
            }
            None => self
                .completion_condvar
                .wait_while(state, |state| {
                    state.completions.is_empty()
                        && state.lifecycle != SessionLifecycle::Stopped
                        && state.wake_generation == wake_generation
                })
                .unwrap_or_else(|error| error.into_inner()),
        };
        !state.completions.is_empty()
    }

    pub fn discard_all(&self) {
        let mut state = self.lock_state();
        for slot in state.operations.values() {
            slot.cancel.cancel();
        }
        state.operations.clear();
        state.completions.clear();
        state.resources.clear();
        state.reserved_resources = 0;
        state.retained_result_bytes = 0;
        state.wake_generation = state.wake_generation.wrapping_add(1);
        drop(state);
        self.completion_condvar.notify_all();
        self.completion_notify.notify_one();
    }

    pub async fn completion_notified(&self) {
        loop {
            if self.has_completions() {
                return;
            }
            {
                let state = self.lock_state();
                if state.lifecycle == SessionLifecycle::Stopped {
                    return;
                }
            }
            self.completion_notify.notified().await;
        }
    }

    pub fn result_retained_bytes(
        &self,
        operation_id: DataPlaneOperationId,
    ) -> DataPlaneResult<usize> {
        let state = self.lock_state();
        let slot = state.operations.get(&operation_id).ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::HandleClosed,
                "data-plane operation result is unavailable",
            )
        })?;
        match slot.state {
            OperationSlotState::Drained(_) => Ok(slot.reserved_result_bytes),
            OperationSlotState::Pending
            | OperationSlotState::Queued(_)
            | OperationSlotState::Discarding => Err(Self::error(
                DataPlaneErrorKind::PathNotReady,
                "data-plane operation result has not been drained",
            )),
        }
    }

    pub fn result_payload_bytes(
        &self,
        operation_id: DataPlaneOperationId,
    ) -> DataPlaneResult<usize> {
        let state = self.lock_state();
        let slot = state.operations.get(&operation_id).ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::HandleClosed,
                "data-plane operation result is unavailable",
            )
        })?;
        match &slot.state {
            OperationSlotState::Drained(Ok(result)) => Ok(result.payload_bytes()),
            OperationSlotState::Drained(Err(_)) => Ok(0),
            OperationSlotState::Pending
            | OperationSlotState::Queued(_)
            | OperationSlotState::Discarding => Err(Self::error(
                DataPlaneErrorKind::PathNotReady,
                "data-plane operation result has not been drained",
            )),
        }
    }

    pub fn operation_kind(
        &self,
        operation_id: DataPlaneOperationId,
    ) -> DataPlaneResult<DataPlaneOperationKind> {
        let state = self.lock_state();
        let slot = state.operations.get(&operation_id).ok_or_else(|| {
            Self::error(
                DataPlaneErrorKind::HandleClosed,
                "data-plane operation result is unavailable",
            )
        })?;
        match slot.state {
            OperationSlotState::Drained(_) => Ok(slot.kind),
            OperationSlotState::Pending
            | OperationSlotState::Queued(_)
            | OperationSlotState::Discarding => Err(Self::error(
                DataPlaneErrorKind::PathNotReady,
                "data-plane operation result has not been drained",
            )),
        }
    }

    pub fn take_result_with<R>(
        &self,
        operation_id: DataPlaneOperationId,
        take: impl FnOnce(&DataPlaneOperationOutcome) -> Option<R>,
    ) -> DataPlaneResult<Option<R>> {
        let mut state = self.lock_state();
        let Some(mut slot) = state.operations.remove(&operation_id) else {
            return Err(Self::error(
                DataPlaneErrorKind::HandleClosed,
                "data-plane operation result is unavailable",
            ));
        };
        let slot_state = std::mem::replace(&mut slot.state, OperationSlotState::Discarding);
        let outcome = match slot_state {
            OperationSlotState::Drained(outcome) => outcome,
            other => {
                slot.state = other;
                state.operations.insert(operation_id, slot);
                return Err(Self::error(
                    DataPlaneErrorKind::PathNotReady,
                    "data-plane operation result has not been drained",
                ));
            }
        };
        let Some(result) = take(&outcome) else {
            slot.state = OperationSlotState::Drained(outcome);
            state.operations.insert(operation_id, slot);
            return Ok(None);
        };
        Self::release_result_reservation_locked(&mut state, &mut slot);
        Ok(Some(result))
    }

    pub(crate) fn stop(&self) {
        let mut state = self.lock_state();
        if state.lifecycle == SessionLifecycle::Stopped {
            return;
        }
        state.lifecycle = SessionLifecycle::Stopped;
        state.wake_generation = state.wake_generation.wrapping_add(1);
        let pending = state
            .operations
            .iter()
            .filter_map(|(operation_id, slot)| {
                matches!(slot.state, OperationSlotState::Pending).then_some(*operation_id)
            })
            .collect::<Vec<_>>();
        let mut notify = false;
        for operation_id in pending {
            notify |= Self::queue_error_locked(
                &mut state,
                operation_id,
                DataPlaneErrorKind::InstanceStopped,
            );
        }
        state.resources.clear();
        drop(state);
        self.consumer_lease
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        self.completion_condvar.notify_all();
        self.completion_notify.notify_one();
        if notify {
            tracing::trace!("data-plane session queued stop completions");
        }
    }

    #[cfg(test)]
    fn admit_test_operation(
        &self,
        kind: DataPlaneOperationKind,
        reserved_result_bytes: usize,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        let mut state = self.lock_state();
        self.admit_locked(&mut state, kind, None, reserved_result_bytes, false)
            .map(|(operation_id, _)| operation_id)
    }

    #[cfg(test)]
    fn admit_test_resource_operation(
        &self,
        kind: DataPlaneOperationKind,
    ) -> DataPlaneResult<DataPlaneOperationId> {
        let mut state = self.lock_state();
        self.admit_locked(&mut state, kind, None, 0, true)
            .map(|(operation_id, _)| operation_id)
    }

    #[cfg(test)]
    fn complete_test_operation(
        &self,
        operation_id: DataPlaneOperationId,
        result: DataPlaneResult<PendingOperationResult>,
    ) {
        self.complete_operation(operation_id, result);
    }
}

impl<H> Drop for DataPlaneSession<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for slot in state.operations.values() {
            slot.cancel.cancel();
        }
        state.resources.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use crate::host::testkit::TestHost;

    use super::*;

    fn session_with_limits(limits: DataPlaneSessionLimits) -> Arc<DataPlaneSession<TestHost>> {
        let session = DataPlaneSession::with_runtime(Weak::new(), limits);
        session.start().unwrap();
        session
    }

    fn session() -> Arc<DataPlaneSession<TestHost>> {
        session_with_limits(DataPlaneSessionLimits::default())
    }

    fn successful_write(len: usize) -> DataPlaneResult<PendingOperationResult> {
        Ok(PendingOperationResult::TcpWritten(len))
    }

    #[test]
    fn completion_is_drained_once_and_result_is_taken_once() {
        let session = session();
        let operation_id = session
            .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
            .unwrap();
        session.complete_test_operation(operation_id, successful_write(7));

        let completions = session.drain_completions(8);
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].operation_id, operation_id);
        assert_eq!(completions[0].status, DataPlaneCompletionStatus::Success);
        assert!(session.drain_completions(8).is_empty());

        let preserved = session
            .take_result_with(operation_id, |_| None::<usize>)
            .unwrap();
        assert_eq!(preserved, None);
        let len = session
            .take_result_with(operation_id, |outcome| match outcome {
                Ok(DataPlaneOperationResult::TcpWritten { len }) => Some(*len),
                _ => None,
            })
            .unwrap();
        assert_eq!(len, Some(7));
        assert_eq!(
            session
                .take_result_with(operation_id, |_| Some(()))
                .unwrap_err()
                .kind(),
            DataPlaneErrorKind::HandleClosed
        );
    }

    #[test]
    fn free_pending_discards_the_late_completion() {
        let session = session();
        let operation_id = session
            .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
            .unwrap();

        session.free_operation(operation_id);
        session.complete_test_operation(operation_id, successful_write(3));

        assert!(session.drain_completions(8).is_empty());
        assert_eq!(session.lock_state().operations.len(), 0);
    }

    #[test]
    fn free_queued_removes_its_completion_descriptor() {
        let session = session();
        let operation_id = session
            .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
            .unwrap();
        session.complete_test_operation(operation_id, successful_write(3));

        session.free_operation(operation_id);

        assert!(session.drain_completions(8).is_empty());
        assert_eq!(session.lock_state().operations.len(), 0);
    }

    #[test]
    fn cancel_and_complete_race_has_one_terminal_outcome() {
        for _ in 0..128 {
            let session = session();
            let operation_id = session
                .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
                .unwrap();
            let barrier = Arc::new(Barrier::new(3));

            let cancel_session = session.clone();
            let cancel_barrier = barrier.clone();
            let cancel = thread::spawn(move || {
                cancel_barrier.wait();
                cancel_session.cancel_operation(operation_id);
            });
            let complete_session = session.clone();
            let complete_barrier = barrier.clone();
            let complete = thread::spawn(move || {
                complete_barrier.wait();
                complete_session.complete_test_operation(operation_id, successful_write(9));
            });
            barrier.wait();
            cancel.join().unwrap();
            complete.join().unwrap();

            let completions = session.drain_completions(8);
            assert_eq!(completions.len(), 1);
            assert!(matches!(
                completions[0].status,
                DataPlaneCompletionStatus::Success
                    | DataPlaneCompletionStatus::Error(DataPlaneErrorKind::Cancelled)
            ));
        }
    }

    #[test]
    fn blocking_wait_observes_completion_before_and_after_wait_starts() {
        let session = session();
        let first = session
            .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
            .unwrap();
        session.complete_test_operation(first, successful_write(1));
        assert!(session.completion_wait(Some(Duration::ZERO)));
        session.drain_completions(1);

        let second = session
            .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
            .unwrap();
        let waiter = {
            let session = session.clone();
            thread::spawn(move || session.completion_wait(Some(Duration::from_secs(1))))
        };
        thread::yield_now();
        session.complete_test_operation(second, successful_write(2));
        assert!(waiter.join().unwrap());
    }

    #[test]
    fn stop_wakes_waiters_and_preserves_terminal_completion() {
        let session = session();
        let operation_id = session
            .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
            .unwrap();
        let waiter = {
            let session = session.clone();
            thread::spawn(move || session.completion_wait(None))
        };

        session.stop();

        assert!(waiter.join().unwrap());
        let completion = session.drain_completions(1).pop().unwrap();
        assert_eq!(completion.operation_id, operation_id);
        assert_eq!(
            completion.status,
            DataPlaneCompletionStatus::Error(DataPlaneErrorKind::InstanceStopped)
        );
    }

    #[test]
    fn discard_all_wakes_waiters_without_a_completion() {
        let session = session();
        let barrier = Arc::new(Barrier::new(2));
        let waiter = {
            let session = session.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                session.completion_wait_after_ready(None, || {
                    barrier.wait();
                })
            })
        };
        barrier.wait();

        session.discard_all();

        assert!(!waiter.join().unwrap());
        assert!(session.drain_completions(1).is_empty());
    }

    #[test]
    fn admission_enforces_operation_and_result_limits() {
        let session = session_with_limits(DataPlaneSessionLimits {
            max_resources: 1,
            max_operations: 1,
            max_result_bytes: 4,
            max_read_size: 4,
        });
        session
            .admit_test_operation(DataPlaneOperationKind::TcpRead, 4)
            .unwrap();

        assert_eq!(
            session
                .admit_test_operation(DataPlaneOperationKind::TcpWrite, 0)
                .unwrap_err()
                .kind(),
            DataPlaneErrorKind::ResourceLimit
        );
        assert_eq!(
            session.require_read_size(5).unwrap_err().kind(),
            DataPlaneErrorKind::ResourceLimit
        );
    }

    #[test]
    fn terminal_errors_release_result_and_resource_reservations() {
        let session = session_with_limits(DataPlaneSessionLimits {
            max_resources: 1,
            max_operations: 4,
            max_result_bytes: 4,
            max_read_size: 4,
        });
        let read = session
            .admit_test_operation(DataPlaneOperationKind::TcpRead, 4)
            .unwrap();
        let resource = session
            .admit_test_resource_operation(DataPlaneOperationKind::TcpConnect)
            .unwrap();

        assert_eq!(
            session
                .admit_test_operation(DataPlaneOperationKind::TcpRead, 1)
                .unwrap_err()
                .kind(),
            DataPlaneErrorKind::ResourceLimit
        );
        assert_eq!(
            session
                .admit_test_resource_operation(DataPlaneOperationKind::TcpBind)
                .unwrap_err()
                .kind(),
            DataPlaneErrorKind::ResourceLimit
        );

        session.cancel_operation(read);
        session.complete_test_operation(
            resource,
            Err(DataPlaneError::new(
                DataPlaneErrorKind::Io,
                "synthetic failure",
            )),
        );

        session
            .admit_test_operation(DataPlaneOperationKind::TcpRead, 4)
            .unwrap();
        session
            .admit_test_resource_operation(DataPlaneOperationKind::TcpBind)
            .unwrap();
    }

    #[test]
    fn short_read_accounts_for_retained_vector_capacity() {
        let session = session_with_limits(DataPlaneSessionLimits {
            max_resources: 1,
            max_operations: 2,
            max_result_bytes: 4,
            max_read_size: 4,
        });
        let operation_id = session
            .admit_test_operation(DataPlaneOperationKind::TcpRead, 4)
            .unwrap();
        let mut data = Vec::with_capacity(4);
        data.push(7);

        session.complete_test_operation(
            operation_id,
            Ok(PendingOperationResult::TcpRead { data, eof: false }),
        );

        assert_eq!(session.lock_state().retained_result_bytes, 4);
        session.drain_completions(1);
        assert_eq!(session.result_retained_bytes(operation_id).unwrap(), 4);
        assert_eq!(session.result_payload_bytes(operation_id).unwrap(), 1);
        session
            .take_result_with(operation_id, |_| Some(()))
            .unwrap();
        assert_eq!(session.lock_state().retained_result_bytes, 0);
    }

    #[tokio::test]
    async fn spawned_operation_does_not_keep_session_alive() {
        let session = session();
        let (operation_id, cancel) = {
            let mut state = session.lock_state();
            session
                .admit_locked(&mut state, DataPlaneOperationKind::TcpWrite, None, 0, false)
                .unwrap()
        };
        let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
        session.spawn_operation(operation_id, async move {
            cancel.cancelled().await;
            let _ = cancelled_tx.send(());
            Err(DataPlaneError::new(
                DataPlaneErrorKind::Cancelled,
                "synthetic cancellation",
            ))
        });
        let weak = Arc::downgrade(&session);

        drop(session);

        tokio::time::timeout(Duration::from_secs(1), cancelled_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn deadline_elapsed_before_polling_is_expired() {
        let deadline = DataPlaneDeadline::from_timeout(Duration::from_millis(1));
        thread::sleep(Duration::from_millis(5));

        assert_eq!(
            deadline
                .run(async { Ok::<_, DataPlaneError>(()) })
                .await
                .unwrap_err()
                .kind(),
            DataPlaneErrorKind::DeadlineExceeded
        );
    }
}
