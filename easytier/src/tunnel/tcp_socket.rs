use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use easytier_core::socket::{
    SocketContext,
    dial::{BindEndpoint, SocketAttempt},
    tcp::{VirtualTcpListener, VirtualTcpSocket},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream},
};

use crate::{
    common::netns::NetNS,
    tunnel::{
        TunnelError,
        common::{BindDev, bind},
    },
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

fn netns_from_context(context: &SocketContext) -> Option<NetNS> {
    context
        .netns
        .as_ref()
        .map(|netns| NetNS::new(Some(netns.token().to_owned())))
}

pub(crate) fn bind_tcp_listener(
    addr: SocketAddr,
    context: &SocketContext,
) -> Result<RuntimeTcpListener, TunnelError> {
    let listener = bind::<TcpListener>()
        .addr(addr)
        .only_v6(true)
        .maybe_socket_mark(context.socket_mark)
        .maybe_net_ns(netns_from_context(context))
        .call()?;
    Ok(RuntimeTcpListener::new(listener))
}

pub(crate) async fn connect_tcp_attempt(
    attempt: SocketAttempt,
) -> Result<RuntimeTcpSocket, TunnelError> {
    let remote_addr = attempt.remote_addr;
    let socket = match attempt.bind {
        BindEndpoint::Default => {
            let socket = if remote_addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            crate::tunnel::common::apply_socket_mark(
                &socket2::SockRef::from(&socket),
                attempt.context.socket_mark,
            )?;
            socket
        }
        BindEndpoint::Addr(addr) => bind::<TcpSocket>()
            .addr(addr)
            .only_v6(true)
            .maybe_socket_mark(attempt.context.socket_mark)
            .maybe_net_ns(netns_from_context(&attempt.context))
            .call()?,
        BindEndpoint::Device(device) => bind::<TcpSocket>()
            .addr(unspecified_bind_addr(remote_addr))
            .dev(device)
            .only_v6(true)
            .maybe_socket_mark(attempt.context.socket_mark)
            .maybe_net_ns(netns_from_context(&attempt.context))
            .call()?,
        BindEndpoint::AddrOnDevice { addr, device } => bind::<TcpSocket>()
            .addr(addr)
            .dev(BindDev::Custom(device))
            .only_v6(true)
            .maybe_socket_mark(attempt.context.socket_mark)
            .maybe_net_ns(netns_from_context(&attempt.context))
            .call()?,
    };
    let stream = socket.connect(remote_addr).await?;
    Ok(RuntimeTcpSocket::new(stream))
}
