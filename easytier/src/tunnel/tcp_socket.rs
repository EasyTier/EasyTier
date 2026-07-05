use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use easytier_core::socket::tcp::{
    TcpBindOptions, TcpConnectOptions, TcpListenOptions, VirtualTcpListener, VirtualTcpSocket,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream},
};

use crate::tunnel::{
    TunnelError,
    common::{BindDev, apply_socket_mark, bind},
};

#[derive(Debug)]
pub(crate) struct RuntimeTcpSocket {
    stream: TcpStream,
}

impl RuntimeTcpSocket {
    pub(crate) fn new(stream: TcpStream) -> Self {
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(?error, "set_nodelay failed for tcp stream");
        }
        Self { stream }
    }
}

impl AsyncRead for RuntimeTcpSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for RuntimeTcpSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl VirtualTcpSocket for RuntimeTcpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
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
    let bind_options = options.bind;
    let addr = bind_options.local_addr.ok_or_else(|| {
        TunnelError::InvalidAddr("tcp listener requires a local bind address".to_owned())
    })?;
    let bind_dev = bind_dev_from_options(&bind_options, false);
    let listener = bind::<TcpListener>()
        .addr(addr)
        .dev(bind_dev)
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
