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
/// Platform integrations can use the purpose to protect only transport and
/// egress sockets while leaving local proxy listeners attached to a VPN/TUN.
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

/// Optional platform hook invoked after a socket is created but before it is
/// used for external traffic.
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
    NATIVE_SOCKET_PROTECTOR
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
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
