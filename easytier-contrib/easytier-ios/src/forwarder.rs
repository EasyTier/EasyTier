//! Local TCP forwarder over the EasyTier data-plane FFI.
//!
//! A `TcpForwarder` listens on `127.0.0.1:<local_port>` and relays every
//! accepted connection to a fixed virtual-network `target` through the
//! data-plane C ABI exported by `easytier-ffi`. It is the transport layer used
//! by apps that embed EasyTier without a TUN/VpnService: local clients simply
//! dial a loopback port.
//!
//! ## Session concurrency model (verified against easytier-ffi)
//!
//! `easytier-ffi/src/data_plane/session.rs::open` rejects a second native
//! session for the same instance with `ResourceLimit` ("instance already has an
//! open native data-plane session"), and `DATA_PLANE_ABI.md` states "One native
//! session may be open for an EasyTier instance at a time". Per-connection
//! sessions are therefore impossible.
//!
//! Accordingly, one forwarder owns exactly one session for its instance and
//! multiplexes all connections over it: a single event loop drives
//! `data_plane_completion_wait` / `data_plane_completion_drain` and dispatches
//! completions by `operation_id`. The core session
//! (`easytier-core/src/gateway/dataplane/session.rs`) admits concurrent
//! operations per stream — reads and writes use independent deadline and
//! cancellation plumbing — and the default limits (4096 resources, 4096
//! outstanding operations, 64 MiB retained results) leave ample headroom. A JNI
//! layer may run several forwarders as long as they use distinct instances;
//! starting a second forwarder on the same instance fails with `ResourceLimit`.
//!
//! Every inbound connection is served by a pair of blocking std::threads that
//! exchange chunks with the event loop through `std::sync::mpsc` channels.
//! Local reads stay in 64 KiB chunks and the event loop keeps exactly one
//! remote read per connection outstanding, so each connection retains at most
//! one read payload and one pending write in the session. No tokio runtime is
//! involved in the forwarding path.

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use easytier_ffi::{
    DataPlaneCompletion, DataPlaneSocketAddr, data_plane_completion_drain,
    data_plane_completion_wait, data_plane_operation_free, data_plane_resource_close,
    data_plane_session_close, data_plane_session_open, data_plane_tcp_connect_result_take,
    data_plane_tcp_connect_submit, data_plane_tcp_read_result_take, data_plane_tcp_read_submit,
    data_plane_tcp_write_result_take, data_plane_tcp_write_submit,
};

use crate::strings::cstring_for;

/// Operation kinds from the data-plane ABI.
const OP_TCP_CONNECT: u16 = 1;
const OP_TCP_READ: u16 = 4;
const OP_TCP_WRITE: u16 = 5;

/// `data_plane_tcp_read_submit` chunk size.
const READ_CHUNK: u32 = 64 * 1024;

/// Timeout for the data-plane TCP connect towards the forward target.
const CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Maximum time `stop()` waits for one worker thread to exit.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Safety net per blocking local write. When it fires, the local socket write
/// fails and the connection is torn down; a broken remote side unblocks the
/// writer earlier via the `Broken` flag.
const LOCAL_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

fn failed(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn spawn_failed(error: io::Error) -> io::Error {
    failed(format!("failed to spawn forwarder thread: {error}"))
}

fn broken_pipe(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message.into())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

/// Observed by both local worker threads of a connection: the remote side is
/// torn down (or the forwarder is stopping) and the workers must exit.
#[derive(Clone)]
struct Broken(Arc<AtomicBool>);

impl Broken {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn break_it(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_broken(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Command issued by connection threads towards the event loop.
enum Command {
    /// Inbound data to forward; the reply carries the completed write result.
    Write {
        connection: u64,
        data: Vec<u8>,
        reply: mpsc::Sender<io::Result<()>>,
    },
    /// One local worker exited; the stream is released once both are done.
    ConnectionDone { connection: u64 },
}

/// Result of a completed remote read, handed to the owning local writer
/// through its per-connection channel.
struct ReadOutcome {
    data: Vec<u8>,
    eof: bool,
}

/// Per-connection channel state shared between the acceptor, the event loop
/// and `stop`. `read_taken` is the acknowledgement the writer sends after
/// taking a result; the event loop waits on it before submitting the next
/// remote read for the connection. `socket` lets `stop` shut the local socket
/// down so a blocked reader/writer wakes immediately.
struct ConnectionHandles {
    broken: Broken,
    read_results: mpsc::Sender<ReadOutcome>,
    read_taken: Mutex<Option<mpsc::Receiver<()>>>,
    socket: TcpStream,
}

impl ConnectionHandles {
    fn pair(
        broken: Broken,
        socket: TcpStream,
    ) -> (Arc<Self>, mpsc::Receiver<ReadOutcome>, mpsc::Sender<()>) {
        let (results_tx, results_rx) = mpsc::channel();
        let (taken_tx, taken_rx) = mpsc::channel();
        (
            Arc::new(Self {
                broken,
                read_results: results_tx,
                read_taken: Mutex::new(Some(taken_rx)),
                socket,
            }),
            results_rx,
            taken_tx,
        )
    }
}

/// A registered connect attempt: the event loop resolves the attempt id to the
/// per-connection reply channel once the FFI-assigned operation id arrives.
struct ConnectAttempt {
    reply: mpsc::Sender<io::Result<u64>>,
    operation: Option<u64>,
}

/// Connect attempts, keyed by attempt id (== connection id).
type PendingConnects = Arc<Mutex<HashMap<u64, ConnectAttempt>>>;

struct SharedSession {
    handle: u64,
    connects: PendingConnects,
    /// FFI operation id -> attempt id, for connect completions.
    connect_ops: Arc<Mutex<HashMap<u64, u64>>>,
}

impl SharedSession {
    fn open(instance_name: &str) -> io::Result<Arc<Self>> {
        let name = cstring_for(instance_name, "instance name")?;
        let mut handle = 0u64;
        // SAFETY: `name` is a valid NUL-terminated string and `handle` points
        // to writable storage for one `u64`.
        let result = unsafe { data_plane_session_open(name.as_ptr(), &mut handle) };
        if result != 0 || handle == 0 {
            return Err(failed(format!(
                "failed to open data-plane session for instance \"{instance_name}\" (code {result})"
            )));
        }
        Ok(Arc::new(Self {
            handle,
            connects: PendingConnects::default(),
            connect_ops: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    fn submit_connect(&self, attempt: u64, target: SocketAddrV4) -> io::Result<u64> {
        let mut address = [0u8; 16];
        address[..4].copy_from_slice(&target.ip().octets());
        let peer = DataPlaneSocketAddr {
            family: 4,
            port: target.port(),
            address,
        };
        let mut operation = 0u64;
        // Hold `connect_ops` across the FFI submit and the registration: the
        // session may complete the connect as soon as the submit returns, and
        // `complete_connect` resolves completions under this same lock, so the
        // operation -> attempt mapping is always registered before the
        // completion can be dispatched.
        let mut connect_ops = lock(&self.connect_ops);
        // SAFETY: `peer` is a plain value and `operation` points to writable
        // storage for one `u64`.
        let result = unsafe {
            data_plane_tcp_connect_submit(self.handle, peer, CONNECT_TIMEOUT_MS, &mut operation)
        };
        if result != 0 {
            lock(&self.connects).remove(&attempt);
            return Err(failed(format!(
                "data-plane TCP connect submit failed (code {result})"
            )));
        }
        // The completion arrives keyed by the FFI operation id, which the
        // session allocates independently of our attempt/connection ids.
        if let Some(entry) = lock(&self.connects).get_mut(&attempt) {
            entry.operation = Some(operation);
        }
        connect_ops.insert(operation, attempt);
        Ok(operation)
    }

    /// Idempotent close; safe to call from `stop` while the event loop blocks
    /// in `completion_wait`, which then wakes up with no completions.
    fn close(&self) {
        data_plane_session_close(self.handle);
    }
}

impl Drop for SharedSession {
    fn drop(&mut self) {
        data_plane_session_close(self.handle);
    }
}

struct ConnectionState {
    handles: Arc<ConnectionHandles>,
    /// Stream handle; set to 0 after `data_plane_resource_close`.
    stream: u64,
    /// Number of submitted-but-undrained operations referencing `stream`.
    in_flight: u16,
    /// Local workers that have not exited yet.
    live_workers: u8,
    /// Expected length and reply for the outstanding inbound write.
    write_reply: Option<(u32, mpsc::Sender<io::Result<()>>)>,
    /// A remote read is outstanding.
    read_pending: bool,
}

impl ConnectionState {
    fn new(handles: Arc<ConnectionHandles>, stream: u64) -> Self {
        Self {
            handles,
            stream,
            in_flight: 0,
            live_workers: 2,
            write_reply: None,
            read_pending: false,
        }
    }
}

/// All live connections (pending and established), shared with `stop` so it
/// can wake blocked workers without waiting for the event loop.
type LiveConnections = Arc<Mutex<HashMap<u64, Arc<ConnectionHandles>>>>;

enum Wait {
    Ready,
    TimedOut,
    Closed,
}

/// Blocking event loop driving one shared data-plane session.
struct EventLoop {
    session: Arc<SharedSession>,
    commands: mpsc::Receiver<Command>,
    stopped: Arc<AtomicBool>,
    connections: HashMap<u64, ConnectionState>,
    /// operation_id -> connection for in-flight reads and writes.
    operations: HashMap<u64, u64>,
    /// Connections whose connect completion has not arrived yet.
    pending_handles: Arc<Mutex<HashMap<u64, Arc<ConnectionHandles>>>>,
    /// Receives connection ids whose writer acknowledged a read result.
    pump_commands: mpsc::Receiver<u64>,
    /// Live connections shared with `stop` for worker wakeup.
    live: LiveConnections,
}

impl EventLoop {
    fn run(mut self) {
        while !self.stopped.load(Ordering::Acquire) {
            // Apply all queued commands before blocking again so a wait never
            // parks while work is already available. The wait below uses a
            // short (5ms) timeout because the data-plane ABI has no self-wakeup
            // for newly queued write/read commands; this bounds the added
            // latency of an idle connection's first local→remote write.
            while let Ok(command) = self.commands.try_recv() {
                self.handle_command(command);
            }
            while let Ok(connection) = self.pump_commands.try_recv() {
                self.submit_read(connection);
            }
            match self.wait() {
                Wait::Ready => self.drain(),
                Wait::TimedOut => continue,
                Wait::Closed => break,
            }
        }
        self.fail_all();
    }

    fn wait(&self) -> Wait {
        if self.stopped.load(Ordering::Acquire) {
            return Wait::TimedOut;
        }
        let result = data_plane_completion_wait(self.session.handle, 5);
        match result {
            1 => Wait::Ready,
            0 => Wait::TimedOut,
            _ => {
                Wait::Closed
            }
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Write {
                connection,
                data,
                reply,
            } => self.submit_write(connection, data, reply),
            Command::ConnectionDone { connection } => {
                if let Some(state) = self.connections.get_mut(&connection) {
                    state.live_workers = state.live_workers.saturating_sub(1);
                    if state.live_workers == 0 {
                        state.handles.broken.break_it();
                    }
                }
                self.maybe_remove(connection);
            }
        }
    }

    fn submit_read(&mut self, connection: u64) {
        let Some(state) = self.connections.get(&connection) else {
            return;
        };
        if state.stream == 0 || state.read_pending || state.handles.broken.is_broken() {
            return;
        }
        let stream = state.stream;
        let mut operation = 0u64;
        // SAFETY: `operation` points to writable storage for one `u64`.
        let result = unsafe {
            data_plane_tcp_read_submit(self.session.handle, stream, READ_CHUNK, &mut operation)
        };
        if result != 0 {
            self.fail_stream(
                connection,
                &format!("data-plane read submit failed (code {result})"),
            );
            return;
        }
        let state = self
            .connections
            .get_mut(&connection)
            .expect("connection state checked above");
        state.in_flight += 1;
        state.read_pending = true;
        self.operations.insert(operation, connection);
    }

    fn submit_write(&mut self, connection: u64, data: Vec<u8>, reply: mpsc::Sender<io::Result<()>>) {
        let Some(state) = self.connections.get(&connection) else {
            let _ = reply.send(Err(broken_pipe("tcp forwarder connection is closed")));
            return;
        };
        if state.handles.broken.is_broken() || state.stream == 0 {
            let _ = reply.send(Err(broken_pipe("remote stream is closed")));
            return;
        }
        let stream = state.stream;
        let data_len = data.len() as u32;
        let mut operation = 0u64;
        // SAFETY: the ABI copies `data` before returning and `operation`
        // points to writable storage for one `u64`.
        let result = unsafe {
            data_plane_tcp_write_submit(
                self.session.handle,
                stream,
                data.as_ptr(),
                data_len,
                &mut operation,
            )
        };
        if result != 0 {
            let error = failed(format!("data-plane write submit failed (code {result})"));
            self.fail_stream(connection, &error.to_string());
            let _ = reply.send(Err(error));
            return;
        }
        let state = self
            .connections
            .get_mut(&connection)
            .expect("connection state checked above");
        state.in_flight += 1;
        state.write_reply = Some((data_len, reply));
        self.operations.insert(operation, connection);
    }

    fn drain(&mut self) {
        let mut completions = [DataPlaneCompletion::default(); 64];
        // SAFETY: `completions` is writable storage for 64 descriptors.
        let count = unsafe {
            data_plane_completion_drain(
                self.session.handle,
                completions.as_mut_ptr(),
                completions.len() as u32,
            )
        };
        if count < 0 {
            self.fail_all();
            return;
        }
        for completion in completions.iter().take(count as usize) {
            self.dispatch(completion);
        }
    }

    fn dispatch(&mut self, completion: &DataPlaneCompletion) {
        match completion.operation_kind {
            OP_TCP_CONNECT => self.complete_connect(completion),
            OP_TCP_READ | OP_TCP_WRITE => {
                let Some(connection) = self.operations.remove(&completion.operation_id) else {
                    // Cancelled or superseded operation; release its result.
                    data_plane_operation_free(self.session.handle, completion.operation_id);
                    return;
                };
                if completion.operation_kind == OP_TCP_READ {
                    self.complete_read(connection, completion);
                } else {
                    self.complete_write(connection, completion);
                }
            }
            _ => {
                data_plane_operation_free(self.session.handle, completion.operation_id);
            }
        }
    }

    fn complete_connect(&mut self, completion: &DataPlaneCompletion) {
        let operation = completion.operation_id;
        // Resolve the FFI operation id back to the attempt/connection id used
        // when the attempt was registered.
        let Some(connection) = lock(&self.session.connect_ops).remove(&operation) else {
            data_plane_operation_free(self.session.handle, operation);
            return;
        };
        let attempt = lock(&self.session.connects).remove(&connection);
        let Some(attempt) = attempt else {
            data_plane_operation_free(self.session.handle, operation);
            return;
        };
        let reply = attempt.reply;
        let Some(handles) = lock(&self.pending_handles).remove(&connection) else {
            // The acceptor was stopped mid-connect; release the operation.
            data_plane_operation_free(self.session.handle, operation);
            return;
        };
        if completion.status != 0 {
            data_plane_operation_free(self.session.handle, operation);
            handles.broken.break_it();
            let _ = reply.send(Err(failed(format!(
                "data-plane connect failed (status {})",
                completion.status
            ))));
            return;
        }
        let mut stream = 0u64;
        let mut local_addr = DataPlaneSocketAddr::default();
        let mut peer_addr = DataPlaneSocketAddr::default();
        // SAFETY: all output pointers reference writable storage of their
        // respective types and do not overlap.
        let result = unsafe {
            data_plane_tcp_connect_result_take(
                self.session.handle,
                operation,
                &mut stream,
                &mut local_addr,
                &mut peer_addr,
            )
        };
        if result != 0 || stream == 0 {
            handles.broken.break_it();
            let _ = reply.send(Err(failed(format!(
                "data-plane connect result take failed (code {result})"
            ))));
            return;
        }
        lock(&self.live).insert(connection, handles.clone());
        self.connections
            .insert(connection, ConnectionState::new(handles, stream));
        let _ = reply.send(Ok(stream));
        // Kick the remote-to-local pump.
        self.submit_read(connection);
    }

    fn complete_read(&mut self, connection: u64, completion: &DataPlaneCompletion) {
        if let Some(state) = self.connections.get_mut(&connection) {
            state.in_flight = state.in_flight.saturating_sub(1);
            state.read_pending = false;
        }
        if completion.status != 0 {
            data_plane_operation_free(self.session.handle, completion.operation_id);
            self.fail_stream(
                connection,
                &format!("data-plane read failed (status {})", completion.status),
            );
            self.maybe_remove(connection);
            return;
        }
        let mut buffer = vec![0u8; READ_CHUNK as usize];
        let mut len = 0u32;
        let mut eof = false;
        // SAFETY: `buffer` is writable for `READ_CHUNK` bytes and the scalar
        // outputs reference writable, non-overlapping storage. The buffer
        // always satisfies the maximum read size submitted for this session.
        let result = unsafe {
            data_plane_tcp_read_result_take(
                self.session.handle,
                completion.operation_id,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut len,
                &mut eof,
            )
        };
        if result != 0 {
            self.fail_stream(
                connection,
                &format!("data-plane read result take failed (code {result})"),
            );
            self.maybe_remove(connection);
            return;
        }
        buffer.truncate(len as usize);
        let Some(state) = self.connections.get(&connection) else {
            return;
        };
        // Hand the payload to the owning local writer. The writer acknowledges
        // the take through `read_taken`, which the loop waits on before
        // submitting the next read for this connection.
        if state
            .handles
            .read_results
            .send(ReadOutcome { data: buffer, eof })
            .is_err()
        {
            self.fail_stream(connection, "tcp forwarder read result channel closed");
        }
        self.maybe_remove(connection);
    }

    fn complete_write(&mut self, connection: u64, completion: &DataPlaneCompletion) {
        let mut written = 0u32;
        let mut result = if completion.status != 0 {
            data_plane_operation_free(self.session.handle, completion.operation_id);
            Err(failed(format!(
                "data-plane write failed (status {})",
                completion.status
            )))
        } else {
            // SAFETY: `written` points to writable storage for one `u32`.
            let result = unsafe {
                data_plane_tcp_write_result_take(
                    self.session.handle,
                    completion.operation_id,
                    &mut written,
                )
            };
            if result != 0 {
                Err(failed(format!(
                    "data-plane write result take failed (code {result})"
                )))
            } else {
                Ok(())
            }
        };
        let reply = self.connections.get_mut(&connection).and_then(|state| {
            state.in_flight = state.in_flight.saturating_sub(1);
            state.write_reply.take()
        });
        if result.is_ok()
            && let Some((expected, _)) = &reply
            && written != *expected
        {
            result = Err(failed(format!(
                "data-plane write completed after {written} of {expected} bytes"
            )));
        }
        if result.is_err() {
            // Reuse `fail_stream` so a writer blocked on the read-result
            // channel is woken with an EOF sentinel, not just flagged broken.
            self.fail_stream(connection, "data-plane write failed");
        }
        if let Some((_, reply)) = reply {
            let _ = reply.send(result);
        }
        self.maybe_remove(connection);
    }

    /// Release a connection once both workers exited and no operation still
    /// references its stream.
    fn maybe_remove(&mut self, connection: u64) {
        let (close_stream, remove) = match self.connections.get(&connection) {
            Some(state) if state.live_workers == 0 && state.in_flight == 0 => {
                (state.stream != 0, true)
            }
            _ => (false, false),
        };
        if !remove {
            return;
        }
        let state = self.connections.remove(&connection).expect("checked above");
        lock(&self.live).remove(&connection);
        if close_stream {
            data_plane_resource_close(self.session.handle, state.stream);
        }
    }

    /// Mark the remote side of `connection` as torn down and release its
    /// stream as soon as no in-flight operation references it.
    fn fail_stream(&mut self, connection: u64, reason: &str) {
        let write_reply = self.connections.get_mut(&connection).and_then(|state| {
            state.handles.broken.break_it();
            // Wake a writer blocked on the read-result channel.
            let _ = state.handles.read_results.send(ReadOutcome {
                data: Vec::new(),
                eof: true,
            });
            if state.stream != 0 && state.in_flight == 0 {
                let stream = state.stream;
                state.stream = 0;
                data_plane_resource_close(self.session.handle, stream);
            }
            state.write_reply.take()
        });
        if let Some((_, reply)) = write_reply {
            let _ = reply.send(Err(broken_pipe(reason)));
        }
    }

    /// Tear down every tracked connection and fail pending connects; used when
    /// the session dies or the forwarder stops.
    fn fail_all(&mut self) {
        for (_, attempt) in lock(&self.session.connects).drain() {
            let _ = attempt.reply.send(Err(failed("data-plane session closed")));
        }
        lock(&self.session.connect_ops).clear();
        for (_, handles) in lock(&self.pending_handles).drain() {
            handles.broken.break_it();
        }
        lock(&self.live).clear();
        let connections = std::mem::take(&mut self.connections);
        for (_, mut state) in connections {
            state.handles.broken.break_it();
            // Wake a writer blocked on the read-result channel.
            let _ = state.handles.read_results.send(ReadOutcome {
                data: Vec::new(),
                eof: true,
            });
            if state.stream != 0 {
                data_plane_resource_close(self.session.handle, state.stream);
            }
            if let Some((_, reply)) = state.write_reply.take() {
                let _ = reply.send(Err(broken_pipe("data-plane session is closed")));
            }
        }
        self.operations.clear();
    }
}

/// Shared state handed to the accept loop.
struct Acceptor {
    target: SocketAddrV4,
    session: Arc<SharedSession>,
    commands: mpsc::Sender<Command>,
    /// Connections accepted but whose connect completion has not arrived yet;
    /// moved into the event loop's connection table on connect success.
    pending_handles: Arc<Mutex<HashMap<u64, Arc<ConnectionHandles>>>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    next_connection: Arc<AtomicU64>,
    pump_requests: mpsc::Sender<u64>,
    stop: Arc<AtomicBool>,
}

/// A loopback TCP port forwarder bound to one EasyTier instance and target.
///
/// `start` spawns all threads; dropping the value (or calling `stop`) closes
/// the listener, the data-plane session and joins the threads.
pub struct TcpForwarder {
    /// Actual bound loopback port.
    pub local_port: u16,
    instance_name: String,
    target: SocketAddrV4,
    stop: Arc<AtomicBool>,
    session: Arc<SharedSession>,
    /// Kept so the event loop's command channel stays alive while stopping.
    #[allow(dead_code)]
    commands: mpsc::Sender<Command>,
    pending_handles: Arc<Mutex<HashMap<u64, Arc<ConnectionHandles>>>>,
    live: LiveConnections,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Kept so pump threads can always reach the event loop; dropped on `stop`.
    #[allow(dead_code)]
    pump_requests: mpsc::Sender<u64>,
    event_loop: Mutex<Option<JoinHandle<()>>>,
    acceptor: Mutex<Option<JoinHandle<()>>>,
    stopped: Mutex<bool>,
}

impl TcpForwarder {
    /// Start forwarding `127.0.0.1:listen_port` (0 = auto-assign) to `target`
    /// through the data plane of the EasyTier instance named `instance_name`.
    ///
    /// Succeeds without any peer connectivity; connect failures surface per
    /// connection. Fails when the instance has no free native data-plane
    /// session (one per instance, shared by all connections of a forwarder).
    pub fn start(
        instance_name: String,
        target: SocketAddrV4,
        listen_port: u16,
    ) -> io::Result<Self> {
        let session = SharedSession::open(&instance_name)?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, listen_port))?;
        let local_addr = listener.local_addr()?;
        let local_port = match local_addr {
            std::net::SocketAddr::V4(addr) => addr.port(),
            std::net::SocketAddr::V6(_) => unreachable!("bound an IPv4 listener"),
        };
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let (command_tx, command_rx) = mpsc::channel::<Command>();
        let (pump_tx, pump_rx) = mpsc::channel::<u64>();
        let pending_handles: Arc<Mutex<HashMap<u64, Arc<ConnectionHandles>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let live: LiveConnections = Arc::new(Mutex::new(HashMap::new()));
        let workers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));

        let event_loop = std::thread::Builder::new()
            .name(format!("tcp-fwd-loop-{local_port}"))
            .spawn({
                let session = session.clone();
                let stop = stop.clone();
                let pending_handles = pending_handles.clone();
                let live = live.clone();
                move || {
                    EventLoop {
                        session,
                        commands: command_rx,
                        stopped: stop,
                        connections: HashMap::new(),
                        operations: HashMap::new(),
                        pending_handles,
                        pump_commands: pump_rx,
                        live,
                    }
                    .run();
                }
            })
            .map_err(spawn_failed)?;

        let acceptor = std::thread::Builder::new()
            .name(format!("tcp-fwd-accept-{local_port}"))
            .spawn({
                let acceptor = Acceptor {
                    target,
                    session: session.clone(),
                    commands: command_tx.clone(),
                    pending_handles: pending_handles.clone(),
                    workers: workers.clone(),
                    next_connection: Arc::new(AtomicU64::new(1)),
                    pump_requests: pump_tx.clone(),
                    stop: stop.clone(),
                };
                move || accept_loop(listener, acceptor)
            });
        let acceptor = match acceptor {
            Ok(acceptor) => acceptor,
            Err(error) => {
                stop.store(true, Ordering::Release);
                session.close();
                let _ = event_loop.join();
                return Err(spawn_failed(error));
            }
        };

        Ok(Self {
            local_port,
            instance_name,
            target,
            stop,
            session,
            commands: command_tx,
            pending_handles,
            live,
            workers,
            pump_requests: pump_tx,
            event_loop: Mutex::new(Some(event_loop)),
            acceptor: Mutex::new(Some(acceptor)),
            stopped: Mutex::new(false),
        })
    }

    /// Instance this forwarder is bound to.
    #[allow(dead_code)]
    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }

    /// Virtual-network target of every forwarded connection.
    #[allow(dead_code)]
    pub fn target(&self) -> SocketAddrV4 {
        self.target
    }

    /// Stop the forwarder: close the listener and session, then join threads.
    pub fn stop(&self) -> io::Result<()> {
        {
            let mut stopped = lock(&self.stopped);
            if *stopped {
                return Ok(());
            }
            *stopped = true;
        }
        self.stop.store(true, Ordering::Release);
        // Break every connection, wake a blocked writer with an EOF sentinel,
        // and shut the local socket down so a blocked reader exits too.
        for (_, handles) in lock(&self.pending_handles).iter() {
            handles.broken.break_it();
            let _ = handles.read_results.send(ReadOutcome {
                data: Vec::new(),
                eof: true,
            });
            let _ = handles.socket.shutdown(Shutdown::Both);
        }
        for (_, handles) in lock(&self.live).iter() {
            handles.broken.break_it();
            let _ = handles.read_results.send(ReadOutcome {
                data: Vec::new(),
                eof: true,
            });
            let _ = handles.socket.shutdown(Shutdown::Both);
        }
        // Unblock the nonblocking accept loop immediately.
        let _ = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.local_port));
        // Unblock the event loop: closing the session wakes a pending
        // `completion_wait` and makes every subsequent FFI call fail, so the
        // loop unwinds and tears the connections down. `close` is idempotent
        // across the `SharedSession` drop.
        self.session.close();

        let deadline = Instant::now() + STOP_TIMEOUT;
        let join = |handle: &Mutex<Option<JoinHandle<()>>>| -> io::Result<()> {
            let handle = lock(handle).take();
            if let Some(handle) = handle {
                if handle.is_finished() {
                    return handle.join().map_err(|_| failed("forwarder thread panicked"));
                }
                while !handle.is_finished() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if handle.is_finished() {
                    handle.join().map_err(|_| failed("forwarder thread panicked"))?;
                }
            }
            Ok(())
        };
        let accept_result = join(&self.acceptor);
        let loop_result = join(&self.event_loop);
        // The event loop is gone, so no completion is ever dispatched again.
        // A connection whose spawn raced `stop` may have registered its
        // connect attempt after the loop's final `fail_all`; fail such
        // attempts here so readers blocked in `await_connect` can exit.
        for (_, attempt) in lock(&self.session.connects).drain() {
            let _ = attempt.reply.send(Err(failed("tcp forwarder stopped")));
        }
        lock(&self.session.connect_ops).clear();
        for (_, handles) in lock(&self.pending_handles).drain() {
            handles.broken.break_it();
            let _ = handles.read_results.send(ReadOutcome {
                data: Vec::new(),
                eof: true,
            });
            let _ = handles.socket.shutdown(Shutdown::Both);
        }
        let workers: Vec<_> = lock(&self.workers).drain(..).collect();
        // A worker may outlive the teardown (e.g. its connect attempt raced
        // `stop`); bound the wait like the acceptor/event-loop joins instead
        // of blocking forever. A worker still alive at the deadline is
        // detached by dropping its join handle.
        let deadline = Instant::now() + STOP_TIMEOUT;
        for handle in workers {
            while !handle.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
        accept_result.and(loop_result)
    }
}

impl Drop for TcpForwarder {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

impl std::fmt::Debug for TcpForwarder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpForwarder")
            .field("local_port", &self.local_port)
            .field("instance_name", &self.instance_name)
            .field("target", &self.target)
            .finish()
    }
}

fn accept_loop(listener: TcpListener, acceptor: Acceptor) {
    while !acceptor.stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((socket, _)) => {
                if acceptor.stop.load(Ordering::Acquire) {
                    return;
                }
                if let Err(error) = spawn_connection(socket, &acceptor) {
                    log::warn!("tcp forwarder failed to spawn connection: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                if acceptor.stop.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Spawn the per-connection reader/writer/pump threads and submit the
/// data-plane connect. The workers wait for the connect outcome before
/// touching streams.
fn spawn_connection(socket: TcpStream, acceptor: &Acceptor) -> io::Result<()> {
    socket.set_nodelay(true).ok();
    let connection = acceptor.next_connection.fetch_add(1, Ordering::Relaxed);
    let broken = Broken::new();
    let handle_socket = socket
        .try_clone()
        .map_err(|error| failed(format!("failed to clone connection socket: {error}")))?;
    let (handles, results_rx, taken_tx) = ConnectionHandles::pair(broken.clone(), handle_socket);
    let (connect_tx, connect_rx) = mpsc::channel();

    let reader_socket = socket
        .try_clone()
        .map_err(|error| failed(format!("failed to clone connection socket: {error}")))?;
    // Wake the reader periodically so it observes a broken remote side even
    // while the local client stays silent; the data-plane ABI has no half-close
    // for the write direction, so this is how teardown reaches a blocked read.
    reader_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let reader = std::thread::Builder::new()
        .name(format!("tcp-fwd-reader-{connection}"))
        .spawn({
            let commands = acceptor.commands.clone();
            let broken = broken.clone();
            move || reader_loop(connection, reader_socket, broken, commands, connect_rx)
        })
        .map_err(spawn_failed)?;
    lock(&acceptor.workers).push(reader);
    let writer = std::thread::Builder::new()
        .name(format!("tcp-fwd-writer-{connection}"))
        .spawn({
            let commands = acceptor.commands.clone();
            move || writer_loop(connection, socket, broken, commands, results_rx, taken_tx)
        })
        .map_err(|error| {
            stop_connection_workers(&handles);
            spawn_failed(error)
        })?;
    lock(&acceptor.workers).push(writer);
    let pump = std::thread::Builder::new()
        .name(format!("tcp-fwd-pump-{connection}"))
        .spawn({
            let pump_requests = acceptor.pump_requests.clone();
            let handles = handles.clone();
            move || pump_loop(connection, handles, pump_requests)
        })
        .map_err(|error| {
            stop_connection_workers(&handles);
            spawn_failed(error)
        })?;
    lock(&acceptor.workers).push(pump);

    lock(&acceptor.session.connects).insert(
        connection,
        ConnectAttempt {
            reply: connect_tx,
            operation: None,
        },
    );
    lock(&acceptor.pending_handles).insert(connection, handles.clone());
    if let Err(error) = acceptor.session.submit_connect(connection, acceptor.target) {
        lock(&acceptor.pending_handles).remove(&connection);
        stop_connection_workers(&handles);
        return Err(error);
    }
    Ok(())
}

fn stop_connection_workers(handles: &ConnectionHandles) {
    handles.broken.break_it();
    let _ = handles.read_results.send(ReadOutcome {
        data: Vec::new(),
        eof: true,
    });
    let _ = handles.socket.shutdown(Shutdown::Both);
}

/// Per-connection read pump: waits for the writer to acknowledge the previous
/// read result, then asks the event loop to submit the next remote read.
/// Blocks without touching the session, so it cannot stall other connections.
fn pump_loop(
    connection: u64,
    handles: Arc<ConnectionHandles>,
    pump_requests: mpsc::Sender<u64>,
) {
    loop {
        if handles.broken.is_broken() {
            return;
        }
        // Poll with a short sleep instead of a blocking recv: the event loop
        // only consults the receiver through short try_recv bursts, and a
        // blocking recv here would hold the mutex forever once no result is
        // pending, deadlocking `stop`.
        let acknowledged = {
            let taken = lock(&handles.read_taken);
            match taken.as_ref() {
                Some(taken) => taken.try_recv().is_ok(),
                None => return,
            }
        };
        if !acknowledged {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        if handles.broken.is_broken() {
            return;
        }
        if pump_requests.send(connection).is_err() {
            return;
        }
    }
}

/// Wait for the connect completion; returns the remote stream handle.
fn await_connect(reply: &mpsc::Receiver<io::Result<u64>>) -> Option<u64> {
    match reply.recv() {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(error)) => {
            log::debug!("tcp forwarder connect failed: {error}");
            None
        }
        Err(_) => None,
    }
}

/// Local -> remote copy loop.
fn reader_loop(
    connection: u64,
    mut socket: TcpStream,
    broken: Broken,
    commands: mpsc::Sender<Command>,
    connect_reply: mpsc::Receiver<io::Result<u64>>,
) {
    if await_connect(&connect_reply).is_none() {
        let _ = socket.shutdown(Shutdown::Both);
        let _ = commands.send(Command::ConnectionDone { connection });
        return;
    }
    let mut buffer = [0u8; 16 * 1024];
    loop {
        if broken.is_broken() {
            break;
        }
        match socket.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => {
                let (reply_tx, reply_rx) = mpsc::channel();
                if commands
                    .send(Command::Write {
                        connection,
                        data: buffer[..len].to_vec(),
                        reply: reply_tx,
                    })
                    .is_err()
                {
                    break;
                }
                match reply_rx.recv() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        log::debug!("tcp forwarder write failed: {error}");
                        break;
                    }
                    Err(_) => break,
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                // Read-timeout tick: re-check the broken flag.
                continue;
            }
            Err(_) => break,
        }
    }
    // No more local data; the writer keeps delivering remote data until EOF.
    let _ = socket.shutdown(Shutdown::Read);
    let _ = commands.send(Command::ConnectionDone { connection });
}

/// Remote -> local copy loop. Blocks on the per-connection read-result
/// channel; after writing each payload to the local socket it acknowledges the
/// take so the event loop submits the next remote read for this connection.
fn writer_loop(
    connection: u64,
    mut socket: TcpStream,
    broken: Broken,
    commands: mpsc::Sender<Command>,
    read_rx: mpsc::Receiver<ReadOutcome>,
    taken_tx: mpsc::Sender<()>,
) {
    socket.set_write_timeout(Some(LOCAL_WRITE_TIMEOUT)).ok();
    loop {
        if broken.is_broken() {
            break;
        }
        let outcome = match read_rx.recv() {
            Ok(outcome) => outcome,
            Err(_) => break,
        };
        if !outcome.data.is_empty() && socket.write_all(&outcome.data).is_err() {
            break;
        }
        let _ = taken_tx.send(());
        if outcome.eof {
            let _ = socket.shutdown(Shutdown::Write);
            break;
        }
    }
    let _ = commands.send(Command::ConnectionDone { connection });
}

#[cfg(test)]
mod tests;
