use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use easytier_core::{
    socket::tcp::{
        TcpConnectOptions, TcpListenOptions, TcpListenPurpose, TcpSocketPurpose,
        VirtualTcpListener, VirtualTcpSocket, VirtualTcpSplit,
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

use crate::socket_protector::protect_native_socket;

enum RuntimeTcpSocketInner {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(feature = "faketcp")]
    FakeTcp(crate::socket::fake_tcp::FakeTcpSocket),
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
    pub(crate) fn from_fake_tcp(socket: crate::socket::fake_tcp::FakeTcpSocket) -> Self {
        Self {
            inner: RuntimeTcpSocketInner::FakeTcp(socket),
        }
    }
}

#[cfg(unix)]
pub(crate) fn url_from_unix_socket_addr(addr: tokio::net::unix::SocketAddr) -> Option<url::Url> {
    addr.as_pathname()
        .and_then(|path| path.to_str())
        .and_then(|path| format!("unix://{path}").parse().ok())
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
    fn into_split(self) -> VirtualTcpSplit {
        match self.inner {
            RuntimeTcpSocketInner::Tcp(stream) => {
                let (reader, writer) = stream.into_split();
                (Box::new(reader), Box::new(writer))
            }
            #[cfg(unix)]
            RuntimeTcpSocketInner::Unix(stream) => {
                let (reader, writer) = stream.into_split();
                (Box::new(reader), Box::new(writer))
            }
            #[cfg(feature = "faketcp")]
            RuntimeTcpSocketInner::FakeTcp(socket) => {
                let (reader, writer) = tokio::io::split(socket);
                (Box::new(reader), Box::new(writer))
            }
        }
    }

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
    need_protect: bool,
}

#[async_trait::async_trait]
impl VirtualTcpListener for RuntimeTcpListener {
    type Socket = RuntimeTcpSocket;

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        protect_native_socket(&SockRef::from(&stream), self.need_protect).await?;
        if self.purpose == TcpListenPurpose::ProxyNat {
            prepare_proxy_tcp_socket(&stream)?;
        }
        Ok((RuntimeTcpSocket::new(stream), addr))
    }
}

pub(crate) async fn bind_tcp_listener(
    options: TcpListenOptions,
) -> Result<RuntimeTcpListener, TunnelError> {
    let purpose = options.purpose;
    let mut bind_options = options.bind;
    if bind_options.local_addr.is_none() {
        return Err(TunnelError::InvalidAddr(
            "tcp listener requires a local bind address".to_owned(),
        ));
    }
    if bind_options.bind_device.is_none() && purpose == TcpListenPurpose::PortLease {
        bind_options.bind_device = Some(String::new());
    }
    let need_protect = bind_options.need_protect;
    let listener = crate::socket::bind::<TcpListener>(bind_options).await?;
    Ok(RuntimeTcpListener {
        listener,
        purpose,
        need_protect,
    })
}

pub(crate) async fn connect_tcp(
    options: TcpConnectOptions,
) -> Result<RuntimeTcpSocket, TunnelError> {
    let remote_addr = options.remote_addr;
    let purpose = options.purpose;
    let mut bind_options = options.bind;
    bind_options.context.ip_version = if remote_addr.is_ipv6() {
        easytier_core::socket::IpVersion::V6
    } else {
        easytier_core::socket::IpVersion::V4
    };

    let socket = crate::socket::bind::<TcpSocket>(bind_options).await?;
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
    #[cfg(not(target_os = "windows"))]
    const TCP_KEEPALIVE_RETRIES: u32 = 2;

    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);

    #[cfg(not(target_os = "windows"))]
    let keepalive = keepalive.with_retries(TCP_KEEPALIVE_RETRIES);

    let socket = SockRef::from(stream);
    socket.set_tcp_keepalive(&keepalive)?;
    if let Err(error) = socket.set_tcp_nodelay(true) {
        tracing::warn!(?error, "set_nodelay failed, ignore it");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[tokio::test]
    async fn connect_tcp_selects_remote_family_without_a_local_bind_address() {
        for ip in ["127.0.0.1", "::1"] {
            let listener = TcpListener::bind((ip, 0)).await.unwrap();
            let remote_addr = listener.local_addr().unwrap();
            let socket = connect_tcp(TcpConnectOptions::direct_connect(remote_addr))
                .await
                .unwrap();
            let (_, local_addr) = listener.accept().await.unwrap();
            assert_eq!(socket.peer_addr().unwrap(), remote_addr);
            assert_eq!(socket.local_addr().unwrap(), local_addr);
            assert_eq!(local_addr.is_ipv6(), remote_addr.is_ipv6());
        }
    }

    #[tokio::test]
    async fn runtime_tcp_owned_split_preserves_full_duplex_and_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let client = client.unwrap();
        let (mut server, _) = accepted.unwrap();
        let (mut reader, mut writer) = RuntimeTcpSocket::new(client).into_split();

        writer.write_all(b"client-to-server").await.unwrap();
        let mut from_client = [0; 16];
        server.read_exact(&mut from_client).await.unwrap();
        assert_eq!(&from_client, b"client-to-server");

        server.write_all(b"server-to-client").await.unwrap();
        let mut from_server = [0; 16];
        reader.read_exact(&mut from_server).await.unwrap();
        assert_eq!(&from_server, b"server-to-client");

        writer.shutdown().await.unwrap();
        let mut after_shutdown = [0; 1];
        assert_eq!(server.read(&mut after_shutdown).await.unwrap(), 0);
    }
}
