use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use easytier_core::socket::tcp::{
    TcpBindOptions, TcpConnectOptions, TcpListenOptions, VirtualTcpListener,
    VirtualTcpListenerFactory, VirtualTcpSocket,
};
use easytier_core::tunnel::ring::{RingByteStream, RingTunnelSocket};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream},
};

use crate::{
    common::netns::NetNS,
    tunnel::{
        TunnelError,
        common::{BindDev, apply_socket_mark, bind},
    },
};

enum RuntimeTcpSocketInner {
    Tcp(TcpStream),
    Ring(RingByteStream),
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(feature = "faketcp")]
    FakeTcp(crate::tunnel::fake_tcp::FakeTcpSocket),
}

pub(crate) struct RuntimeTcpSocket {
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

    pub(crate) fn from_ring(socket: Arc<RingTunnelSocket>) -> io::Result<Self> {
        Ok(Self {
            inner: RuntimeTcpSocketInner::Ring(RingByteStream::new(socket)?),
        })
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

    #[cfg(feature = "faketcp")]
    pub(crate) fn into_fake_tcp(
        self,
    ) -> Result<crate::tunnel::fake_tcp::FakeTcpSocket, TunnelError> {
        match self.inner {
            RuntimeTcpSocketInner::FakeTcp(socket) => Ok(socket),
            RuntimeTcpSocketInner::Tcp(_) | RuntimeTcpSocketInner::Ring(_) => {
                Err(TunnelError::InternalError(
                    "FakeTCP upgrader received an ordinary TCP socket".to_owned(),
                ))
            }
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(_) => Err(TunnelError::InternalError(
                "FakeTCP upgrader received a Unix stream".to_owned(),
            )),
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
            RuntimeTcpSocketInner::Ring(stream) => Pin::new(stream).poll_read(cx, buf),
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
            RuntimeTcpSocketInner::Ring(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => Pin::new(socket).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            RuntimeTcpSocketInner::Ring(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => Pin::new(socket).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            RuntimeTcpSocketInner::Ring(stream) => Pin::new(stream).poll_shutdown(cx),
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
            RuntimeTcpSocketInner::Ring(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ring stream has no IP local address",
            )),
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
            RuntimeTcpSocketInner::Ring(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ring stream has no IP peer address",
            )),
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix stream has no IP peer address",
            )),
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => socket.peer_addr(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeTcpListener {
    listener: TcpListener,
}

impl RuntimeTcpListener {
    pub(crate) fn new(listener: TcpListener) -> Self {
        Self { listener }
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
        Ok((RuntimeTcpSocket::new(stream), addr))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeTcpListenerFactory {
    net_ns: NetNS,
}

impl RuntimeTcpListenerFactory {
    pub(crate) fn new(net_ns: NetNS) -> Self {
        Self { net_ns }
    }
}

#[async_trait::async_trait]
impl VirtualTcpListenerFactory for RuntimeTcpListenerFactory {
    type Listener = RuntimeTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        Ok(Arc::new(bind_tcp_listener_with_netns(
            options,
            Some(self.net_ns.clone()),
        )?))
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
        .only_v6(bind_options.only_v6)
        .reuse_addr(bind_options.reuse_addr)
        .reuse_port(bind_options.reuse_port)
        .maybe_socket_mark(bind_options.socket_mark)
        .call()
}

fn must_bind_before_connect(bind_options: &TcpBindOptions) -> bool {
    bind_options.local_addr.is_some()
        || bind_options.bind_device.is_some()
        || bind_options.reuse_port
        || bind_options.only_v6
        || bind_options.reuse_addr != !cfg!(target_os = "windows")
}

pub(crate) fn bind_tcp_listener(
    options: TcpListenOptions,
) -> Result<RuntimeTcpListener, TunnelError> {
    bind_tcp_listener_with_netns(options, None)
}

fn bind_tcp_listener_with_netns(
    options: TcpListenOptions,
    net_ns: Option<NetNS>,
) -> Result<RuntimeTcpListener, TunnelError> {
    let bind_options = options.bind;
    let addr = bind_options.local_addr.ok_or_else(|| {
        TunnelError::InvalidAddr("tcp listener requires a local bind address".to_owned())
    })?;
    let bind_dev = bind_dev_from_options(&bind_options, false);
    let listener = bind::<TcpListener>()
        .addr(addr)
        .dev(bind_dev)
        .maybe_net_ns(net_ns)
        .only_v6(bind_options.only_v6)
        .reuse_addr(bind_options.reuse_addr)
        .reuse_port(bind_options.reuse_port)
        .maybe_socket_mark(bind_options.socket_mark)
        .call()?;
    Ok(RuntimeTcpListener::new(listener))
}

pub(crate) async fn connect_tcp(
    options: TcpConnectOptions,
) -> Result<RuntimeTcpSocket, TunnelError> {
    let remote_addr = options.remote_addr;
    let bind_options = options.bind;

    if !must_bind_before_connect(&bind_options) {
        let stream = if bind_options.socket_mark.is_some() {
            let socket = if remote_addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            apply_socket_mark(&socket2::SockRef::from(&socket), bind_options.socket_mark)?;
            socket.connect(remote_addr).await?
        } else {
            TcpStream::connect(remote_addr).await?
        };
        return Ok(RuntimeTcpSocket::new(stream));
    }

    let socket = bind_tcp_socket(remote_addr, bind_options)?;
    let stream = socket.connect(remote_addr).await?;
    Ok(RuntimeTcpSocket::new(stream))
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
    }
}
