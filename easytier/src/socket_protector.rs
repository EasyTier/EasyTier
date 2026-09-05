use std::{io, sync::Arc};

use async_trait::async_trait;
use easytier_core::socket::{
    tcp::{TcpListenPurpose, TcpSocketPurpose},
    udp::UdpSocketPurpose,
};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

/// Describes why the native runtime created an operating-system socket.
///
/// Diagnostic labels for the native adapter, not the portable policy API.
/// Whether protection is requested is carried by core's socket bind options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocketPurpose {
    TcpConnect(TcpSocketPurpose),
    TcpListen(TcpListenPurpose),
    TcpAccepted(TcpListenPurpose),
    UdpBind(UdpSocketPurpose),
    DnsTcp,
    DnsUdp,
    RouteProbe,
    UpnpRouteProbe,
}

/// Native-only platform callback used by socket creation when `need_protect`
/// is set. The future must resolve only after protection is actually applied;
/// emitting an event without awaiting its acknowledgement is not sufficient.
/// Errors fail creation before bind/connect/listen or exposing an accepted child.
///
/// WASI embedders implement the same contract inside their existing host socket
/// creation operations, using core's encoded bind options, not this raw-FD API.
#[async_trait]
pub trait NativeSocketProtector: Send + Sync + 'static {
    async fn protect(&self, socket_handle: u64, purpose: NativeSocketPurpose) -> io::Result<()>;
}

static NATIVE_SOCKET_PROTECTOR: std::sync::LazyLock<
    std::sync::RwLock<Option<Arc<dyn NativeSocketProtector>>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

/// Installs or removes the process-wide native socket protection capability.
///
/// Instance-specific routing policy still travels in socket options; this hook
/// only exposes a platform service such as Android/iOS/HarmonyOS VPN bypass.
pub fn set_native_socket_protector(protector: Option<Arc<dyn NativeSocketProtector>>) {
    let mut guard = NATIVE_SOCKET_PROTECTOR
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = protector;
}

fn native_socket_protector() -> Option<Arc<dyn NativeSocketProtector>> {
    #[cfg(all(test, unix))]
    if let Ok(protector) = TEST_SOCKET_PROTECTOR.try_with(Arc::clone) {
        return Some(protector);
    }
    NATIVE_SOCKET_PROTECTOR
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

// Isolate factory ordering tests from other tests' sockets in the same process.
#[cfg(all(test, unix))]
tokio::task_local! {
    static TEST_SOCKET_PROTECTOR: Arc<dyn NativeSocketProtector>;
}

pub(crate) fn native_socket_protection_available() -> bool {
    native_socket_protector().is_some()
}

#[cfg(unix)]
pub(crate) async fn protect_native_socket<S>(
    socket: &S,
    purpose: NativeSocketPurpose,
) -> io::Result<()>
where
    S: AsRawFd + ?Sized,
{
    let Some(protector) = native_socket_protector() else {
        return Ok(());
    };
    let fd = socket.as_raw_fd();
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native socket has an invalid file descriptor",
        ));
    }
    protector.protect(fd as u64, purpose).await
}

#[cfg(windows)]
pub(crate) async fn protect_native_socket<S>(
    socket: &S,
    purpose: NativeSocketPurpose,
) -> io::Result<()>
where
    S: AsRawSocket + ?Sized,
{
    let Some(protector) = native_socket_protector() else {
        return Ok(());
    };
    protector
        .protect(socket.as_raw_socket() as u64, purpose)
        .await
}

#[cfg(not(any(unix, windows)))]
pub(crate) async fn protect_native_socket<S>(
    _socket: &S,
    _purpose: NativeSocketPurpose,
) -> io::Result<()>
where
    S: ?Sized,
{
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use easytier_core::socket::{
        tcp::{TcpBindOptions, TcpConnectOptions, TcpListenOptions, VirtualTcpListener},
        udp::UdpBindOptions,
    };
    use std::{
        os::fd::BorrowedFd,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::sync::Semaphore;

    struct GateProtector {
        calls: AtomicUsize,
        gate: Semaphore,
        fail: bool,
    }

    impl GateProtector {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                gate: Semaphore::new(0),
                fail,
            })
        }
    }

    #[async_trait]
    impl NativeSocketProtector for GateProtector {
        async fn protect(&self, handle: u64, purpose: NativeSocketPurpose) -> io::Result<()> {
            // The caller keeps the socket alive while this borrowed callback runs.
            let fd = unsafe { BorrowedFd::borrow_raw(i32::try_from(handle).unwrap()) };
            let socket = socket2::SockRef::from(&fd);
            if !matches!(purpose, NativeSocketPurpose::TcpAccepted(_)) {
                assert_eq!(socket.local_addr()?.as_socket().unwrap().port(), 0);
                assert!(
                    socket.peer_addr().is_err(),
                    "connect must wait for protect completion"
                );
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test protection failure",
                ));
            }
            self.gate.acquire().await.unwrap().forget();
            Ok(())
        }
    }

    #[tokio::test]
    async fn tcp_connect_waits_for_protection_ack() {
        let protector = GateProtector::new(false);
        TEST_SOCKET_PROTECTOR
            .scope(protector.clone(), async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let options = TcpConnectOptions::direct_connect(listener.local_addr().unwrap());
                let connect = crate::socket::tcp::connect_tcp(options);
                tokio::pin!(connect);
                assert!(futures::poll!(&mut connect).is_pending());
                assert_eq!(protector.calls.load(Ordering::SeqCst), 1);
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), listener.accept())
                        .await
                        .is_err()
                );
                protector.gate.add_permits(1);
                let _client = connect.await.unwrap();
                listener.accept().await.unwrap();
            })
            .await;
    }

    #[tokio::test]
    async fn protection_failure_blocks_creation_and_explicit_false_bypasses_callback() {
        let protector = GateProtector::new(true);
        TEST_SOCKET_PROTECTOR
            .scope(protector.clone(), async {
                let local = "127.0.0.1:0".parse().unwrap();
                let bind = TcpBindOptions::default()
                    .with_local_addr(Some(local))
                    .with_need_protect(true);
                assert!(
                    crate::socket::tcp::create_tcp_socket(
                        local,
                        &bind,
                        NativeSocketPurpose::DnsTcp
                    )
                    .await
                    .is_err()
                );
                assert!(
                    crate::socket::tcp::bind_tcp_listener(TcpListenOptions::direct_connect(local))
                        .await
                        .is_err()
                );
                let udp = UdpBindOptions::direct_connect().with_local_addr(Some(local));
                assert!(
                    crate::socket::udp::create_udp_socket(&udp, NativeSocketPurpose::DnsUdp)
                        .await
                        .is_err()
                );
                assert_eq!(protector.calls.load(Ordering::SeqCst), 3);

                let listener =
                    crate::socket::tcp::bind_tcp_listener(TcpListenOptions::port_forward(local))
                        .await
                        .unwrap();
                let connect = TcpConnectOptions::direct_connect(listener.local_addr().unwrap())
                    .with_bind(TcpBindOptions::default().with_need_protect(false));
                let _client = crate::socket::tcp::connect_tcp(connect).await.unwrap();
                listener.accept().await.unwrap();
                let udp = udp.with_need_protect(false);
                crate::socket::udp::create_udp_socket(&udp, NativeSocketPurpose::DnsUdp)
                    .await
                    .unwrap();
                assert_eq!(protector.calls.load(Ordering::SeqCst), 3);
            })
            .await;
    }

    #[tokio::test]
    async fn accepted_child_waits_for_inherited_protection() {
        let protector = GateProtector::new(false);
        TEST_SOCKET_PROTECTOR
            .scope(protector.clone(), async {
                protector.gate.add_permits(1);
                let listener = crate::socket::tcp::bind_tcp_listener(
                    TcpListenOptions::direct_connect("127.0.0.1:0".parse().unwrap()),
                )
                .await
                .unwrap();
                let _client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let accept = listener.accept();
                tokio::pin!(accept);
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), &mut accept)
                        .await
                        .is_err()
                );
                assert_eq!(protector.calls.load(Ordering::SeqCst), 2);
                protector.gate.add_permits(1);
                accept.await.unwrap();
            })
            .await;
    }
}
