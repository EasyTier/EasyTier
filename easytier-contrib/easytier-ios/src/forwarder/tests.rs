//! Host-target tests for `TcpForwarder`.
//!
//! The first three tests need no overlay connectivity. `forward_echo_roundtrip`
//! links two real FFI instances over the process-wide ring registry (through
//! the always-on `ring://<instance-id>` listener and a TOML ring connector)
//! and verifies a full byte round trip through the forwarder and the data
//! plane.

use std::{
    ffi::CString,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use easytier_ffi::{
    DataPlaneSocketAddr, data_plane_completion_wait, data_plane_operation_free,
    data_plane_resource_close, data_plane_session_close, data_plane_session_open,
    data_plane_tcp_accept_result_take, data_plane_tcp_accept_submit,
    data_plane_tcp_bind_result_take, data_plane_tcp_bind_submit, data_plane_tcp_read_result_take,
    data_plane_tcp_read_submit, data_plane_tcp_write_result_take, data_plane_tcp_write_submit,
};

use super::*;

/// Names of instances started by the current test, stopped on guard drop.
static INSTANCES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn unique_instance(tag: &str) -> String {
    format!("fwd-{tag}-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
}

fn run_instance(config: &str, register_as: &str) {
    let config = CString::new(config).unwrap();
    // SAFETY: `config` is a valid NUL-terminated string.
    let result = unsafe { easytier_ffi::run_network_instance(config.as_ptr()) };
    if result != 0 {
        let message = crate::error::get_last_error().unwrap_or_default();
        panic!("run_network_instance failed: {result}: {message}");
    }
    lock(&INSTANCES).push(register_as.to_string());
}

/// Open a forwarder session once the instance's data-plane session is
/// available; `run_network_instance` returns before `instance.start()` finishes
/// bringing the data plane up.
fn start_forwarder(
    instance: &str,
    target: SocketAddrV4,
    listen_port: u16,
) -> io::Result<TcpForwarder> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpForwarder::start(instance.to_string(), target, listen_port) {
            Ok(forwarder) => {
                return Ok(forwarder);
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn start_instance(instance: &str, ipv4: &str) {
    run_instance(
        &format!(
            "instance_name = \"{instance}\"\n\
             instance_id = \"{}\"\n\
             ipv4 = \"{ipv4}\"\n\
             listeners = []\n\
             flags.no_tun = true\n",
            uuid::Uuid::new_v4()
        ),
        instance,
    );
}

fn stop_all_instances() {
    let names = std::mem::take(&mut *lock(&INSTANCES));
    if names.is_empty() {
        return;
    }
    let cstrings: Vec<CString> = names
        .iter()
        .map(|name| CString::new(name.as_str()).unwrap())
        .collect();
    let pointers: Vec<*const std::ffi::c_char> =
        cstrings.iter().map(|name| name.as_ptr()).collect();
    // SAFETY: `pointers` references `cstrings`, all valid NUL-terminated
    // strings, for the duration of the call.
    unsafe { easytier_ffi::delete_network_instance(pointers.as_ptr(), pointers.len()) };
}

struct TestGuard(std::sync::MutexGuard<'static, ()>);

/// Tests share one process-wide FFI context and per-instance native sessions;
/// run them serially to avoid cross-test session/instance interference.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn acquire() -> TestGuard {
    let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    TestGuard(guard)
}

impl Drop for TestGuard {
    fn drop(&mut self) {
        stop_all_instances();
    }
}

/// Probe `data_plane_session_open` until the instance's data-plane runtime is
/// running, i.e. a submitted operation would not fail with InstanceStopped.
fn wait_data_plane_running(instance: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !session_openable(instance) {
        assert!(Instant::now() < deadline, "data-plane runtime never started for {instance}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn session_openable(instance: &str) -> bool {
    let name = CString::new(instance).unwrap();
    let mut session = 0u64;
    // SAFETY: `name` is a valid NUL-terminated string and `session` points to
    // writable storage for one `u64`.
    let result = unsafe { data_plane_session_open(name.as_ptr(), &mut session) };
    if result == 0 && session != 0 {
        data_plane_session_close(session);
        return true;
    }
    false
}

fn open_session(instance: &str) -> u64 {
    let name = CString::new(instance).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut session = 0u64;
        // SAFETY: `name` is a valid NUL-terminated string and `session` points
        // to writable storage for one `u64`.
        let result = unsafe { data_plane_session_open(name.as_ptr(), &mut session) };
        if result == 0 && session != 0 {
            return session;
        }
        // The instance's data-plane session comes up asynchronously after
        // `run_network_instance` returns.
        assert!(Instant::now() < deadline, "data_plane_session_open timed out: {result}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_completion(session: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if data_plane_completion_wait(session, 100) == 1 {
            return;
        }
        assert!(Instant::now() < deadline, "data-plane completion timed out");
    }
}

/// Wait for the next completion and drain it, returning its descriptor.
fn next_completion(session: u64, timeout: Duration) -> easytier_ffi::DataPlaneCompletion {
    wait_completion(session, timeout);
    let mut completions = [easytier_ffi::DataPlaneCompletion::default(); 8];
    // SAFETY: `completions` is writable storage for 8 descriptors.
    let count = unsafe {
        easytier_ffi::data_plane_completion_drain(
            session,
            completions.as_mut_ptr(),
            completions.len() as u32,
        )
    };
    assert!(count > 0, "completion drain returned {count}");
    completions[0]
}

#[test]
fn start_fails_for_unknown_instance_and_sets_error() {
    let _guard = acquire();
    let instance = unique_instance("missing");
    let error = TcpForwarder::start(
        instance.clone(),
        SocketAddrV4::new(Ipv4Addr::new(10, 126, 126, 99), 22),
        0,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains(&instance),
        "unexpected error: {error}"
    );
    let message = crate::error::get_last_error().expect("FFI error must be recorded");
    assert!(
        message.contains("instance not found"),
        "unexpected FFI error: {message}"
    );
}

#[test]
fn unreachable_target_fails_connect_not_start() {
    let _guard = acquire();
    let instance = unique_instance("unreachable");
    start_instance(&instance, "10.126.126.1");
    let forwarder = start_forwarder(
        &instance,
        SocketAddrV4::new(Ipv4Addr::new(10, 126, 126, 99), 22),
        0,
    )
    .expect("forwarder start must not require overlay connectivity");
    let port = forwarder.local_port;
    assert_ne!(port, 0);

    let mut socket = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .expect("loopback connect must succeed");
    socket
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut buffer = [0u8; 1];
    let started = Instant::now();
    let outcome = socket.read(&mut buffer);
    match outcome {
        Ok(0) => {}
        Err(error) => assert!(
            error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::TimedOut
                || error.kind() == io::ErrorKind::ConnectionReset,
            "unexpected read error: {error:?}"
        ),
        Ok(_) => panic!("unexpected payload from unreachable target"),
    }
    assert!(
        started.elapsed() <= Duration::from_secs(20),
        "connect failure must surface within the data-plane timeout"
    );

    forwarder.stop().expect("stop must succeed");
}

#[test]
fn stop_releases_session_and_is_idempotent() {
    let _guard = acquire();
    let instance = unique_instance("stop");
    start_instance(&instance, "10.126.126.1");
    let forwarder = start_forwarder(
        &instance,
        SocketAddrV4::new(Ipv4Addr::new(10, 126, 126, 99), 22),
        0,
    )
    .unwrap();
    let port = forwarder.local_port;
    forwarder.stop().unwrap();
    forwarder.stop().unwrap();
    assert!(
        TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).is_err(),
        "listener must be closed after stop"
    );
    // The shared per-instance session must be reusable after stop.
    let session = open_session(&instance);
    data_plane_session_close(session);
}

#[test]
fn forward_echo_roundtrip() {
    let _guard = acquire();
    let instance_a = unique_instance("echo-a");
    let instance_b = unique_instance("echo-b");
    let id_b = uuid::Uuid::new_v4();
    run_instance(
        &format!(
            "instance_name = \"{instance_b}\"\n\
             instance_id = \"{id_b}\"\n\
             ipv4 = \"10.126.126.2\"\n\
             listeners = []\n\
             flags.no_tun = true\n"
        ),
        &instance_b,
    );
    run_instance(
        &format!(
            "instance_name = \"{instance_a}\"\n\
             instance_id = \"{id_a}\"\n\
             ipv4 = \"10.126.126.1\"\n\
             listeners = []\n\
             flags.no_tun = true\n\
             [[peer]]\n\
             uri = \"ring://{id_b}\"\n",
            id_a = uuid::Uuid::new_v4(),
        ),
        &instance_a,
    );

    let echo_port = 15871u16;
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo = std::thread::spawn({
        let echo_stop = echo_stop.clone();
        let instance_b = instance_b.clone();
        move || echo_server(&instance_b, echo_port, echo_stop)
    });

    // The data-plane runtime comes up asynchronously after
    // `run_network_instance`. The echo server holds instance B's single native
    // session, so only probe A here; B's readiness is implied by the echo
    // server passing its own bind. Give the ring link and routes a moment to
    // settle before forwarding.
    wait_data_plane_running(&instance_a);
    std::thread::sleep(Duration::from_millis(500));

    let forwarder = start_forwarder(
        &instance_a,
        SocketAddrV4::new(Ipv4Addr::new(10, 126, 126, 2), echo_port),
        0,
    )
    .unwrap();
    // Run several sequential connections: the FFI allocates operation ids from
    // a monotonically increasing broker namespace independent of the
    // forwarder's connection counter, so the second connection onwards only
    // succeeds if connect completions are dispatched by operation id.
    for round in 0..3 {
        let mut socket =
            TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, forwarder.local_port))
                .expect("loopback connect failed");
        socket
            .set_read_timeout(Some(Duration::from_secs(25)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let request = format!("ping{round}").into_bytes();
        socket.write_all(&request).unwrap();
        let mut buffer = vec![0u8; request.len()];
        socket.read_exact(&mut buffer).expect("echo read failed");
        assert_eq!(buffer, request, "round {round} payload mismatch");
        drop(socket);
    }

    forwarder.stop().unwrap();
    echo_stop.store(true, Ordering::Release);
    echo.join().expect("echo server thread panicked");
}

/// Run a data-plane echo server on `instance`: bind `port`, then loop accepting
/// a stream, reading one payload and replying "pong", until `stop` is set.
fn echo_server(instance: &str, port: u16, stop: Arc<AtomicBool>) {
    let session = open_session(instance);

    let mut bind_operation = 0u64;
    // The data-plane runtime starts after the instance; retry the bind until
    // it is up.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        // SAFETY: `bind_operation` points to writable storage for one `u64`.
        let result =
            unsafe { data_plane_tcp_bind_submit(session, port, 15_000, &mut bind_operation) };
        if result == 0 {
            break;
        }
        let message = crate::error::get_last_error().unwrap_or_default();
        if Instant::now() >= deadline {
            panic!("bind submit failed: {result}: {message}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let bind_completion = next_completion(session, Duration::from_secs(15));
    assert_eq!(bind_completion.operation_id, bind_operation);
    assert_eq!(bind_completion.status, 0, "bind failed: {}", bind_completion.status);
    let mut listener = 0u64;
    let mut local = DataPlaneSocketAddr::default();
    // SAFETY: outputs reference writable, non-overlapping storage.
    let result = unsafe {
        data_plane_tcp_bind_result_take(session, bind_operation, &mut listener, &mut local)
    };
    if result != 0 {
        let message = crate::error::get_last_error().unwrap_or_default();
        panic!("bind result take failed: {result}: {message}");
    }

    while !stop.load(Ordering::Acquire) {
        let mut accept_operation = 0u64;
        // SAFETY: `accept_operation` points to writable storage for one `u64`.
        let result = unsafe {
            data_plane_tcp_accept_submit(session, listener, 5_000, &mut accept_operation)
        };
        assert_eq!(result, 0, "accept submit failed: {result}");
        let accept_completion = next_completion(session, Duration::from_secs(10));
        assert_eq!(accept_completion.operation_id, accept_operation);
        if accept_completion.status != 0 {
            // Accept timed out or the listener was closed; re-check stop and
            // either loop for the next connection or exit.
            data_plane_operation_free(session, accept_operation);
            if stop.load(Ordering::Acquire) {
                break;
            }
            continue;
        }
        let mut stream = 0u64;
        let mut peer = DataPlaneSocketAddr::default();
        // SAFETY: outputs reference writable, non-overlapping storage.
        let result = unsafe {
            data_plane_tcp_accept_result_take(
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
        let result =
            unsafe { data_plane_tcp_read_submit(session, stream, 4096, &mut read_operation) };
        assert_eq!(result, 0, "read submit failed: {result}");
        let read_completion = next_completion(session, Duration::from_secs(15));
        assert_eq!(read_completion.operation_id, read_operation);
        assert_eq!(read_completion.status, 0, "read failed: {}", read_completion.status);
        let mut data = [0u8; 4096];
        let mut len = 0u32;
        let mut eof = false;
        // SAFETY: `data` is writable for its length and the scalar outputs
        // reference writable, non-overlapping storage.
        let result = unsafe {
            data_plane_tcp_read_result_take(
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
        let payload = data[..len as usize].to_vec();
        let mut write_operation = 0u64;
        // SAFETY: the ABI copies `payload` before returning.
        let result = unsafe {
            data_plane_tcp_write_submit(
                session,
                stream,
                payload.as_ptr(),
                payload.len() as u32,
                &mut write_operation,
            )
        };
        assert_eq!(result, 0, "write submit failed: {result}");
        let write_completion = next_completion(session, Duration::from_secs(15));
        assert_eq!(write_completion.operation_id, write_operation);
        assert_eq!(
            write_completion.status, 0,
            "write failed: {}",
            write_completion.status
        );
        let mut written = 0u32;
        // SAFETY: `written` points to writable storage for one `u32`.
        let result =
            unsafe { data_plane_tcp_write_result_take(session, write_operation, &mut written) };
        assert_eq!(result, 0, "write result take failed: {result}");
        assert_eq!(written as usize, payload.len());
        data_plane_resource_close(session, stream);
    }
    data_plane_resource_close(session, listener);
    data_plane_session_close(session);
}

#[test]
fn two_instances_both_start_data_plane() {
    let _guard = acquire();
    let a = unique_instance("two-a");
    let b = unique_instance("two-b");
    run_instance(&format!("instance_name = \"{a}\"\ninstance_id = \"{}\"\nipv4 = \"10.126.126.1\"\nlisteners = []\nflags.no_tun = true\n", uuid::Uuid::new_v4()), &a);
    run_instance(&format!("instance_name = \"{b}\"\ninstance_id = \"{}\"\nipv4 = \"10.126.126.2\"\nlisteners = []\nflags.no_tun = true\n", uuid::Uuid::new_v4()), &b);
    wait_data_plane_running(&a);
    wait_data_plane_running(&b);
}

/// Regression: a read completing with an error after both workers exited must
/// release the connection (the error path used to skip `maybe_remove`, leaking
/// the connection state until `stop`).
#[test]
fn failed_read_completion_releases_finished_connection() {
    let _guard = acquire();
    let instance = unique_instance("readfail");
    start_instance(&instance, "10.126.126.1");
    wait_data_plane_running(&instance);
    let session = SharedSession::open(&instance).unwrap();
    let (_command_tx, commands) = mpsc::channel();
    let (_pump_tx, pump_commands) = mpsc::channel();
    let live: LiveConnections = LiveConnections::default();
    let mut event_loop = EventLoop {
        session: session.clone(),
        commands,
        stopped: Arc::new(AtomicBool::new(false)),
        connections: HashMap::new(),
        operations: HashMap::new(),
        pending_handles: Arc::new(Mutex::new(HashMap::new())),
        pump_commands,
        live: live.clone(),
    };
    // The leak scenario: both workers already exited while a remote read was
    // still in flight, then the read completes with an error. The operation
    // and stream ids below are bogus; the FFI treats freeing/closing unknown
    // ids as a no-op.
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (handles, _results, _taken) = ConnectionHandles::pair(Broken::new(), socket);
    let mut state = ConnectionState::new(handles.clone(), 4242);
    state.in_flight = 1;
    state.live_workers = 0;
    state.read_pending = true;
    event_loop.connections.insert(7, state);
    lock(&live).insert(7, handles);

    let completion = DataPlaneCompletion {
        operation_id: 999,
        operation_kind: OP_TCP_READ,
        status: 1,
    };
    event_loop.complete_read(7, &completion);

    assert!(
        !event_loop.connections.contains_key(&7),
        "failed read completion must release the finished connection"
    );
    assert!(lock(&live).is_empty(), "live connection entry leaked");
}

/// Regression: `submit_connect` must register the operation -> attempt mapping
/// while holding `connect_ops`, so the event loop (which resolves connect
/// completions under the same lock) can never dispatch a completion before the
/// mapping exists. The race window itself is a thread interleaving that cannot
/// be forced deterministically; this test pins the fix's observable property:
/// no FFI connect is submitted while `connect_ops` is held by someone else.
#[test]
fn connect_submit_waits_for_connect_ops_lock() {
    let _guard = acquire();
    let instance = unique_instance("connreg");
    start_instance(&instance, "10.126.126.1");
    wait_data_plane_running(&instance);
    let session = SharedSession::open(&instance).unwrap();
    let (reply, _reply_rx) = mpsc::channel();
    lock(&session.connects).insert(
        7,
        ConnectAttempt {
            reply,
            operation: None,
        },
    );

    let connect_ops = lock(&session.connect_ops);
    let worker = std::thread::spawn({
        let session = session.clone();
        move || session.submit_connect(7, SocketAddrV4::new(Ipv4Addr::new(10, 126, 126, 99), 22))
    });
    // The FFI submit itself must not have happened while the lock is held, so
    // the attempt still has no operation id assigned.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        lock(&session.connects).get(&7).unwrap().operation.is_none(),
        "connect submit proceeded while connect_ops was locked"
    );
    drop(connect_ops);

    let operation = worker.join().unwrap().expect("connect submit failed");
    assert_eq!(lock(&session.connect_ops).get(&operation), Some(&7));
    assert_eq!(
        lock(&session.connects).get(&7).unwrap().operation,
        Some(operation)
    );
}

/// Regression: a connect attempt registered after the event loop's final
/// `fail_all` (the acceptor/spawn racing `stop`) would never get a completion
/// dispatched. `stop` must fail such stranded attempts so a reader blocked in
/// `await_connect` exits instead of hanging forever.
#[test]
fn stop_fails_connect_registered_after_event_loop_exit() {
    let _guard = acquire();
    let instance = unique_instance("stoprace");
    start_instance(&instance, "10.126.126.1");
    let forwarder = start_forwarder(
        &instance,
        SocketAddrV4::new(Ipv4Addr::new(10, 126, 126, 99), 22),
        0,
    )
    .unwrap();
    // Force the event loop out before `stop`: closing the session fails the
    // completion wait, so the loop breaks and runs its final `fail_all`.
    forwarder.session.close();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let exited = lock(&forwarder.event_loop)
            .as_ref()
            .map(|handle| handle.is_finished())
            .unwrap_or(true);
        if exited {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "event loop did not exit on session close"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Register an attempt now: no event loop remains to dispatch its
    // completion, exactly like the spawn/stop race.
    let (reply, reply_rx) = mpsc::channel();
    lock(&forwarder.session.connects).insert(
        77,
        ConnectAttempt {
            reply,
            operation: None,
        },
    );
    let reader = std::thread::spawn(move || await_connect(&reply_rx));

    forwarder.stop().expect("stop must succeed");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !reader.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        reader.is_finished(),
        "reader stayed blocked in await_connect after stop"
    );
    assert_eq!(reader.join().unwrap(), None);
}

/// Regression: `stop` must not hang forever joining a worker that survived
/// the teardown; after `STOP_TIMEOUT` it detaches the worker and returns.
#[test]
fn stop_detaches_unresponsive_worker_after_deadline() {
    let _guard = acquire();
    let instance = unique_instance("stuck");
    start_instance(&instance, "10.126.126.1");
    let forwarder = start_forwarder(
        &instance,
        SocketAddrV4::new(Ipv4Addr::new(10, 126, 126, 99), 22),
        0,
    )
    .unwrap();
    lock(&forwarder.workers).push(std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(3600));
    }));

    let started = Instant::now();
    forwarder.stop().expect("stop must succeed");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= STOP_TIMEOUT,
        "stop returned before the worker deadline: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "stop hung on the unresponsive worker: {elapsed:?}"
    );
}
