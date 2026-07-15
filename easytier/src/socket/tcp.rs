use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use easytier_core::{
    socket::tcp::{
        TcpBindOptions, TcpConnectOptions, TcpListenOptions, TcpListenPurpose, TcpSocketPurpose,
        VirtualTcpListener, VirtualTcpSocket,
    },
    tunnel::TunnelError,
};
use socket2::{SockRef, TcpKeepalive};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream},
};

use crate::{
    common::netns::NetNS,
    tunnel::common::{BindDev, apply_socket_mark, bind},
};

enum RuntimeTcpSocketInner {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(feature = "faketcp")]
    FakeTcp(crate::tunnel::fake_tcp::FakeTcpSocket),
}

pub struct RuntimeTcpSocket {
    inner: RuntimeTcpSocketInner,
}

impl RuntimeTcpSocket {
    pub(crate) fn new(stream: TcpStream) -> Self {
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(?error, "set_nodelay failed for tcp stream");
        }
        Self {
            inner: RuntimeTcpSocketInner::Tcp(stream),
        }
    }

    #[cfg(unix)]
    pub(crate) fn from_unix(stream: UnixStream) -> Self {
        Self {
            inner: RuntimeTcpSocketInner::Unix(stream),
        }
    }

    #[cfg(feature = "faketcp")]
    pub(crate) fn from_fake_tcp(socket: crate::tunnel::fake_tcp::FakeTcpSocket) -> Self {
        Self {
            inner: RuntimeTcpSocketInner::FakeTcp(socket),
        }
    }
}

impl AsyncRead for RuntimeTcpSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => Pin::new(socket).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RuntimeTcpSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => Pin::new(socket).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => Pin::new(socket).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => Pin::new(socket).poll_shutdown(cx),
        }
    }
}

impl VirtualTcpSocket for RuntimeTcpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => stream.local_addr(),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix stream has no IP local address",
            )),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => socket.local_addr(),
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        match &self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => stream.peer_addr(),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix stream has no IP peer address",
            )),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => socket.peer_addr(),
        }
    }

    fn transport_label(&self) -> Option<&str> {
        match &self.inner {
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => socket.transport_label(),
            RuntimeTcpSocketInner::Tcp(_) => None,
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(_) => None,
        }
    }
}

#[derive(Debug)]
pub struct RuntimeTcpListener {
    listener: TcpListener,
    purpose: TcpListenPurpose,
}

impl RuntimeTcpListener {
    pub(crate) fn new(listener: TcpListener, purpose: TcpListenPurpose) -> Self {
        Self { listener, purpose }
    }
}

#[async_trait::async_trait]
impl VirtualTcpListener for RuntimeTcpListener {
    type Socket = RuntimeTcpSocket;

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        if self.purpose == TcpListenPurpose::ProxyNat {
            prepare_proxy_tcp_socket(&stream)?;
        }
        Ok((RuntimeTcpSocket::new(stream), addr))
    }
}

fn unspecified_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
    match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0]), 0),
    }
}

fn bind_dev_from_options(options: &TcpBindOptions, local_addr_was_defaulted: bool) -> BindDev {
    options
        .bind_device
        .clone()
        .map(BindDev::from)
        .unwrap_or_else(|| {
            if local_addr_was_defaulted {
                BindDev::Disabled
            } else {
                BindDev::Auto
            }
        })
}

fn bind_tcp_socket(
    remote_addr: SocketAddr,
    bind_options: TcpBindOptions,
) -> Result<TcpSocket, TunnelError> {
    let (bind_addr, local_addr_was_defaulted) = match bind_options.local_addr {
        Some(addr) => (addr, false),
        None => (unspecified_bind_addr(remote_addr), true),
    };
    let bind_dev = bind_dev_from_options(&bind_options, local_addr_was_defaulted);

    bind::<TcpSocket>()
        .addr(bind_addr)
        .dev(bind_dev)
        .net_ns(NetNS::from_socket_context(&bind_options.context))
        .only_v6(bind_options.only_v6)
        .reuse_addr(native_reuse_addr(&bind_options))
        .reuse_port(bind_options.reuse_port)
        .maybe_socket_mark(bind_options.context.socket_mark)
        .call()
}

fn create_tcp_socket(
    remote_addr: SocketAddr,
    bind_options: &TcpBindOptions,
) -> Result<TcpSocket, TunnelError> {
    // A network namespace is a thread property, but the socket retains its
    // namespace after creation. Never keep the guard across connect().await.
    NetNS::from_socket_context(&bind_options.context).run(|| {
        let socket = if remote_addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        apply_socket_mark(
            &socket2::SockRef::from(&socket),
            bind_options.context.socket_mark,
        )?;
        Ok(socket)
    })
}

fn must_bind_before_connect(bind_options: &TcpBindOptions) -> bool {
    bind_options.local_addr.is_some()
        || bind_options.bind_device.is_some()
        || bind_options.reuse_port
        || bind_options.only_v6
        || bind_options
            .reuse_addr
            .is_some_and(|reuse_addr| reuse_addr != native_reuse_addr_default())
}

fn native_reuse_addr_default() -> bool {
    !cfg!(target_os = "windows")
}

fn native_reuse_addr(bind_options: &TcpBindOptions) -> bool {
    bind_options
        .reuse_addr
        .unwrap_or_else(native_reuse_addr_default)
}

pub(crate) fn bind_tcp_listener(
    options: TcpListenOptions,
) -> Result<RuntimeTcpListener, TunnelError> {
    let purpose = options.purpose;
    let bind_options = options.bind;
    let net_ns = NetNS::from_socket_context(&bind_options.context);
    let addr = bind_options.local_addr.ok_or_else(|| {
        TunnelError::InvalidAddr("tcp listener requires a local bind address".to_owned())
    })?;
    let bind_dev = if bind_options.bind_device.is_none() && purpose == TcpListenPurpose::PortLease {
        BindDev::Disabled
    } else {
        bind_dev_from_options(&bind_options, false)
    };
    let listener = bind::<TcpListener>()
        .addr(addr)
        .dev(bind_dev)
        .maybe_net_ns(Some(net_ns))
        .only_v6(bind_options.only_v6)
        .reuse_addr(native_reuse_addr(&bind_options))
        .reuse_port(bind_options.reuse_port)
        .maybe_socket_mark(bind_options.context.socket_mark)
        .call()?;
    Ok(RuntimeTcpListener::new(listener, purpose))
}

pub(crate) async fn connect_tcp(
    options: TcpConnectOptions,
) -> Result<RuntimeTcpSocket, TunnelError> {
    let remote_addr = options.remote_addr;
    let purpose = options.purpose;
    let bind_options = options.bind;

    if !must_bind_before_connect(&bind_options) {
        let socket = create_tcp_socket(remote_addr, &bind_options)?;
        let stream = socket.connect(remote_addr).await?;
        prepare_connected_tcp_socket(&stream, purpose)?;
        return Ok(RuntimeTcpSocket::new(stream));
    }

    let socket = bind_tcp_socket(remote_addr, bind_options)?;
    let stream = socket.connect(remote_addr).await?;
    prepare_connected_tcp_socket(&stream, purpose)?;
    Ok(RuntimeTcpSocket::new(stream))
}

fn prepare_connected_tcp_socket(stream: &TcpStream, purpose: TcpSocketPurpose) -> io::Result<()> {
    match purpose {
        TcpSocketPurpose::ProxyNat => prepare_proxy_tcp_socket(stream),
        TcpSocketPurpose::StunProbe => SockRef::from(stream).set_linger(Some(Duration::ZERO)),
        _ => Ok(()),
    }
}

pub(crate) fn prepare_proxy_tcp_socket(stream: &TcpStream) -> io::Result<()> {
    const TCP_KEEPALIVE_TIME: std::time::Duration = std::time::Duration::from_secs(5);
    const TCP_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
    const TCP_KEEPALIVE_RETRIES: u32 = 2;

    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);

    #[cfg(not(target_os = "windows"))]
    let keepalive = keepalive.with_retries(TCP_KEEPALIVE_RETRIES);

    let socket = SockRef::from(stream);
    socket.set_tcp_keepalive(&keepalive)?;
    if let Err(error) = socket.set_nodelay(true) {
        tracing::warn!(?error, "set_nodelay failed, ignore it");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_connect_binds_when_socket_option_requires_pre_connect_setup() {
        assert!(must_bind_before_connect(
            &TcpBindOptions::default().with_only_v6(true)
        ));
        assert!(must_bind_before_connect(
            &TcpBindOptions::default().with_bind_device(Some("eth0".to_owned()))
        ));
        assert!(!must_bind_before_connect(&TcpBindOptions::default()));
        assert!(!must_bind_before_connect(
            &TcpBindOptions::default().with_reuse_addr(native_reuse_addr_default())
        ));
        assert!(must_bind_before_connect(
            &TcpBindOptions::default().with_reuse_addr(!native_reuse_addr_default())
        ));
        assert_eq!(
            native_reuse_addr(&TcpBindOptions::default()),
            native_reuse_addr_default()
        );
    }
}
