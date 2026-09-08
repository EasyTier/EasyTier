use std::{
    io,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

/// Native-only platform callback used by socket creation when `need_protect`
/// is set. The future must resolve only after protection is actually applied;
/// emitting an event without awaiting its acknowledgement is not sufficient.
/// Errors fail creation before bind/connect/listen or exposing an accepted child.
///
/// WASI embedders implement the same contract inside their existing host socket
/// creation operations, using core's encoded bind options, not this raw-FD API.
#[async_trait]
pub trait NativeSocketProtector: Send + Sync + 'static {
    async fn protect(&self, socket_handle: u64) -> io::Result<()>;
}

static NATIVE_SOCKET_PROTECTOR: RwLock<Option<Arc<dyn NativeSocketProtector>>> = RwLock::new(None);

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

// socket2 owns the platform-specific handle; SockRef adapts Tokio sockets here.
pub(crate) async fn protect_native_socket(
    socket: &socket2::Socket,
    need_protect: bool,
) -> io::Result<()> {
    if !need_protect {
        return Ok(());
    }
    let Some(protector) = native_socket_protector() else {
        return Ok(());
    };
    #[cfg(unix)]
    let handle = u64::try_from(socket.as_raw_fd())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;
    #[cfg(windows)]
    let handle = socket.as_raw_socket() as u64;
    protector.protect(handle).await
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use easytier_core::socket::{
        SocketListener,
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
        expect_unbound: bool,
    }

    impl GateProtector {
        fn new(fail: bool, expect_unbound: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                gate: Semaphore::new(0),
                fail,
                expect_unbound,
            })
        }
    }

    #[async_trait]
    impl NativeSocketProtector for GateProtector {
        async fn protect(&self, handle: u64) -> io::Result<()> {
            // The caller keeps the socket alive while this borrowed callback runs.
            let fd = unsafe { BorrowedFd::borrow_raw(i32::try_from(handle).unwrap()) };
            let socket = socket2::SockRef::from(&fd);
            if self.expect_unbound || self.calls.load(Ordering::SeqCst) == 0 {
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
        let protector = GateProtector::new(false, true);
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
        let protector = GateProtector::new(true, true);
        TEST_SOCKET_PROTECTOR
            .scope(protector.clone(), async {
                let local = "127.0.0.1:0".parse().unwrap();
                let bind = TcpBindOptions::default().with_local_addr(Some(local));
                assert!(
                    crate::socket::tcp::create_tcp_socket(local, &bind)
                        .await
                        .is_err()
                );
                assert!(
                    crate::socket::tcp::bind_tcp_listener(TcpListenOptions::direct_connect(local))
                        .await
                        .is_err()
                );
                let udp = UdpBindOptions::direct_connect().with_local_addr(Some(local));
                assert!(crate::socket::udp::create_udp_socket(&udp).await.is_err());
                assert_eq!(protector.calls.load(Ordering::SeqCst), 3);

                for options in [
                    TcpListenOptions::proxy_nat(local),
                    TcpListenOptions::socks5(local),
                    TcpListenOptions::port_forward(local),
                    TcpListenOptions::port_lease(local),
                ] {
                    let listener = crate::socket::tcp::bind_tcp_listener(options)
                        .await
                        .unwrap();
                    let connect = TcpConnectOptions::direct_connect(listener.local_addr().unwrap())
                        .with_bind(TcpBindOptions::default().with_need_protect(false));
                    let _client = crate::socket::tcp::connect_tcp(connect).await.unwrap();
                    listener.accept().await.unwrap();
                }
                let udp = udp.with_need_protect(false);
                crate::socket::udp::create_udp_socket(&udp).await.unwrap();
                let mut rpc = crate::proto::rpc::standalone::runtime_rpc_listener(local);
                rpc.listen().await.unwrap();
                let rpc_addr = rpc.local_url().socket_addrs(|| None).unwrap()[0];
                let _client = tokio::net::TcpStream::connect(rpc_addr).await.unwrap();
                rpc.accept().await.unwrap();
                assert_eq!(protector.calls.load(Ordering::SeqCst), 3);
            })
            .await;
    }

    #[tokio::test]
    async fn accepted_child_waits_for_inherited_protection() {
        let protector = GateProtector::new(false, false);
        TEST_SOCKET_PROTECTOR
            .scope(protector.clone(), async {
                let bind = crate::socket::tcp::bind_tcp_listener(TcpListenOptions::direct_connect(
                    "127.0.0.1:0".parse().unwrap(),
                ));
                tokio::pin!(bind);
                assert!(futures::poll!(&mut bind).is_pending());
                assert_eq!(protector.calls.load(Ordering::SeqCst), 1);
                protector.gate.add_permits(1);
                let listener = bind.await.unwrap();
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
