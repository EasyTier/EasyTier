use std::{fmt, io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::socket::{IpVersion, SocketContext, SocketListener};

/// A core-visible TCP stream endpoint.
///
/// Implementations are runtime adapters over concrete TCP stream types. This
/// trait deliberately stays below tunnel framing: it only exposes stream I/O and
/// socket addresses.
pub trait VirtualTcpSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// Optional host transport label retained in tunnel management metadata.
    fn transport_label(&self) -> Option<&str> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSocketPurpose {
    DirectConnect,
    FakeTcp,
    HolePunch,
    ManualConnect,
    ProxyNat,
    StunProbe,
    Socks5,
    PortForward,
    DataPlane,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpBindOptions {
    #[serde(default)]
    pub context: SocketContext,
    pub local_addr: Option<SocketAddr>,
    pub bind_device: Option<String>,
    /// `None` delegates the platform default to the host socket adapter.
    pub reuse_addr: Option<bool>,
    pub reuse_port: bool,
    pub only_v6: bool,
}

impl TcpBindOptions {
    pub fn new() -> Self {
        Self {
            context: SocketContext::default(),
            local_addr: None,
            bind_device: None,
            reuse_addr: None,
            reuse_port: false,
            only_v6: false,
        }
    }

    pub fn with_local_addr(mut self, local_addr: Option<SocketAddr>) -> Self {
        self.local_addr = local_addr;
        self
    }

    pub fn with_socket_mark(mut self, socket_mark: Option<u32>) -> Self {
        self.context.socket_mark = socket_mark;
        self
    }

    pub fn with_context(mut self, context: SocketContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_ip_version(mut self, ip_version: IpVersion) -> Self {
        self.context.ip_version = ip_version;
        self
    }

    pub fn with_bind_device(mut self, bind_device: Option<String>) -> Self {
        self.bind_device = bind_device;
        self
    }

    pub fn with_reuse_addr(mut self, reuse_addr: bool) -> Self {
        self.reuse_addr = Some(reuse_addr);
        self
    }

    pub fn with_reuse_port(mut self, reuse_port: bool) -> Self {
        self.reuse_port = reuse_port;
        self
    }

    pub fn with_only_v6(mut self, only_v6: bool) -> Self {
        self.only_v6 = only_v6;
        self
    }
}

impl Default for TcpBindOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectOptions {
    pub remote_addr: SocketAddr,
    pub bind: TcpBindOptions,
    pub purpose: TcpSocketPurpose,
}

impl TcpConnectOptions {
    pub fn direct_connect(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default(),
            purpose: TcpSocketPurpose::DirectConnect,
        }
    }

    pub fn with_purpose(mut self, purpose: TcpSocketPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn hole_punch(remote_addr: SocketAddr, local_addr: Option<SocketAddr>) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default().with_local_addr(local_addr),
            purpose: TcpSocketPurpose::HolePunch,
        }
    }

    pub fn manual_connect(remote_addr: SocketAddr, local_addr: Option<SocketAddr>) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default().with_local_addr(local_addr),
            purpose: TcpSocketPurpose::ManualConnect,
        }
    }

    pub fn proxy_nat(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default(),
            purpose: TcpSocketPurpose::ProxyNat,
        }
    }

    pub fn stun_probe(remote_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpSocketPurpose::StunProbe,
        }
    }

    pub fn socks5(remote_addr: SocketAddr) -> Self {
        Self::direct_connect(remote_addr).with_purpose(TcpSocketPurpose::Socks5)
    }

    pub fn port_forward(remote_addr: SocketAddr) -> Self {
        Self::direct_connect(remote_addr).with_purpose(TcpSocketPurpose::PortForward)
    }

    pub fn data_plane(remote_addr: SocketAddr) -> Self {
        Self::direct_connect(remote_addr).with_purpose(TcpSocketPurpose::DataPlane)
    }

    pub fn with_bind(mut self, bind: TcpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[async_trait]
pub trait VirtualTcpSocketFactory: Send + Sync + 'static {
    type Socket: VirtualTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket>;
}

#[async_trait]
pub trait VirtualTcpListener: Send + Sync + 'static {
    type Socket: VirtualTcpSocket;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpListenPurpose {
    DirectConnect,
    HolePunch,
    ManualConnect,
    ProxyNat,
    Socks5,
    PortForward,
    PortLease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpListenOptions {
    pub bind: TcpBindOptions,
    pub purpose: TcpListenPurpose,
}

impl TcpListenOptions {
    pub fn direct_connect(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::DirectConnect,
        }
    }

    pub fn hole_punch(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::HolePunch,
        }
    }

    pub fn manual_connect(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::ManualConnect,
        }
    }

    pub fn proxy_nat(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::ProxyNat,
        }
    }

    pub fn socks5(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::Socks5,
        }
    }

    pub fn port_forward(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::PortForward,
        }
    }

    pub fn port_lease(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::PortLease,
        }
    }

    pub fn with_bind(mut self, bind: TcpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[async_trait]
pub trait VirtualTcpListenerFactory: Send + Sync + 'static {
    type Listener: VirtualTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>>;
}

type AcceptedTcpSocket<F> =
    <<F as VirtualTcpListenerFactory>::Listener as VirtualTcpListener>::Socket;

pub struct TcpSocketListener<F>
where
    F: VirtualTcpListenerFactory,
{
    url: url::Url,
    options: TcpListenOptions,
    factory: Arc<F>,
    listener: Option<Arc<F::Listener>>,
}

impl<F> TcpSocketListener<F>
where
    F: VirtualTcpListenerFactory,
{
    pub fn new_with_options(url: url::Url, options: TcpListenOptions, factory: Arc<F>) -> Self {
        Self {
            url,
            options,
            factory,
            listener: None,
        }
    }

    fn listener(&self) -> anyhow::Result<Arc<F::Listener>> {
        self.listener
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tcp socket listener is not started"))
    }
}

impl<F> fmt::Debug for TcpSocketListener<F>
where
    F: VirtualTcpListenerFactory,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpSocketListener")
            .field("url", &self.url)
            .field("options", &self.options)
            .field("listening", &self.listener.is_some())
            .finish()
    }
}

#[async_trait]
impl<F> SocketListener for TcpSocketListener<F>
where
    F: VirtualTcpListenerFactory,
{
    type Accepted = AcceptedTcpSocket<F>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.listener.is_some() {
            return Ok(());
        }

        let listener = self.factory.bind_tcp(self.options.clone()).await?;
        let local_addr = listener.local_addr()?;
        self.url
            .set_port(Some(local_addr.port()))
            .map_err(|_| anyhow::anyhow!("failed to update tcp listener port for {}", self.url))?;
        self.listener = Some(listener);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        loop {
            let listener = self.listener()?;
            match listener.accept().await {
                Ok((socket, _)) => return Ok(socket),
                Err(error) if is_retryable_tcp_accept_error(&error) => {
                    tracing::warn!(?error, "tcp accept failed with retryable error");
                }
                Err(error) => {
                    tracing::warn!(?error, "tcp accept failed");
                    return Err(error.into());
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
    }
}

fn is_retryable_tcp_accept_error(error: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        error.kind(),
        NotConnected | ConnectionAborted | ConnectionRefused | ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };

    use tokio::io::{DuplexStream, ReadBuf};

    use super::*;

    struct MockTcpSocket {
        stream: DuplexStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }

    impl MockTcpSocket {
        fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
            let (stream, _) = tokio::io::duplex(64);
            Self {
                stream,
                local_addr,
                peer_addr,
            }
        }
    }

    impl AsyncRead for MockTcpSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockTcpSocket {
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

    impl VirtualTcpSocket for MockTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }
    }

    struct MockTcpListener {
        local_addr: SocketAddr,
        accepts: Mutex<VecDeque<io::Result<MockTcpSocket>>>,
    }

    impl MockTcpListener {
        fn new(local_addr: SocketAddr, accepts: Vec<io::Result<MockTcpSocket>>) -> Self {
            Self {
                local_addr,
                accepts: Mutex::new(accepts.into()),
            }
        }
    }

    #[async_trait::async_trait]
    impl VirtualTcpListener for MockTcpListener {
        type Socket = MockTcpSocket;

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
            let result = self.accepts.lock().unwrap().pop_front();
            match result {
                Some(Ok(socket)) => {
                    let peer_addr = socket.peer_addr()?;
                    Ok((socket, peer_addr))
                }
                Some(Err(error)) => Err(error),
                None => std::future::pending().await,
            }
        }
    }

    struct MockTcpListenerFactory {
        listener: Arc<MockTcpListener>,
        binds: Mutex<Vec<TcpListenOptions>>,
    }

    impl MockTcpListenerFactory {
        fn new(listener: Arc<MockTcpListener>) -> Self {
            Self {
                listener,
                binds: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl VirtualTcpListenerFactory for MockTcpListenerFactory {
        type Listener = MockTcpListener;

        async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
            self.binds.lock().unwrap().push(options);
            Ok(self.listener.clone())
        }
    }

    #[test]
    fn tcp_connect_options_preserve_socket_purpose() {
        let remote_addr = SocketAddr::from(([127, 0, 0, 1], 11010));
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));

        assert_eq!(
            TcpConnectOptions::direct_connect(remote_addr),
            TcpConnectOptions {
                remote_addr,
                bind: TcpBindOptions::default(),
                purpose: TcpSocketPurpose::DirectConnect,
            }
        );
        assert_eq!(
            TcpConnectOptions::hole_punch(remote_addr, Some(local_addr)),
            TcpConnectOptions {
                remote_addr,
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpSocketPurpose::HolePunch,
            }
        );
        assert_eq!(
            TcpConnectOptions::manual_connect(remote_addr, Some(local_addr)),
            TcpConnectOptions {
                remote_addr,
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpSocketPurpose::ManualConnect,
            }
        );
        assert_eq!(
            TcpConnectOptions::proxy_nat(remote_addr),
            TcpConnectOptions {
                remote_addr,
                bind: TcpBindOptions::default(),
                purpose: TcpSocketPurpose::ProxyNat,
            }
        );
        assert_eq!(
            TcpConnectOptions::stun_probe(remote_addr, local_addr),
            TcpConnectOptions {
                remote_addr,
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpSocketPurpose::StunProbe,
            }
        );
        assert_eq!(
            TcpConnectOptions::socks5(remote_addr).purpose,
            TcpSocketPurpose::Socks5
        );
        assert_eq!(
            TcpConnectOptions::port_forward(remote_addr).purpose,
            TcpSocketPurpose::PortForward
        );
        assert_eq!(
            TcpConnectOptions::data_plane(remote_addr).purpose,
            TcpSocketPurpose::DataPlane
        );
    }

    #[test]
    fn tcp_listen_options_preserve_socket_purpose() {
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 11010));

        assert_eq!(
            TcpListenOptions::socks5(local_addr).purpose,
            TcpListenPurpose::Socks5
        );
        assert_eq!(
            TcpListenOptions::port_forward(local_addr).purpose,
            TcpListenPurpose::PortForward
        );
        assert_eq!(
            TcpListenOptions::port_lease(local_addr).purpose,
            TcpListenPurpose::PortLease
        );

        assert_eq!(
            TcpListenOptions::direct_connect(local_addr),
            TcpListenOptions {
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpListenPurpose::DirectConnect,
            }
        );
        assert_eq!(
            TcpListenOptions::hole_punch(local_addr),
            TcpListenOptions {
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpListenPurpose::HolePunch,
            }
        );
        assert_eq!(
            TcpListenOptions::manual_connect(local_addr),
            TcpListenOptions {
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpListenPurpose::ManualConnect,
            }
        );
        assert_eq!(
            TcpListenOptions::proxy_nat(local_addr),
            TcpListenOptions {
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpListenPurpose::ProxyNat,
            }
        );
    }

    #[test]
    fn tcp_bind_options_preserve_socket_configuration() {
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let options = TcpBindOptions::default()
            .with_local_addr(Some(local_addr))
            .with_socket_mark(Some(7))
            .with_bind_device(Some("eth0".to_owned()))
            .with_reuse_addr(true)
            .with_reuse_port(true)
            .with_only_v6(true);

        assert_eq!(
            options,
            TcpBindOptions {
                context: SocketContext::default().with_socket_mark(Some(7)),
                local_addr: Some(local_addr),
                bind_device: Some("eth0".to_owned()),
                reuse_addr: Some(true),
                reuse_port: true,
                only_v6: true,
            }
        );
    }

    #[test]
    fn tcp_bind_default_delegates_reuse_addr_policy_to_host() {
        assert_eq!(TcpBindOptions::default().reuse_addr, None);
    }

    #[tokio::test]
    async fn tcp_socket_listener_binds_and_accepts_socket() {
        let requested_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let bound_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let options = TcpListenOptions::direct_connect(requested_addr);
        let listener = Arc::new(MockTcpListener::new(
            bound_addr,
            vec![Ok(MockTcpSocket::new(bound_addr, peer_addr))],
        ));
        let factory = Arc::new(MockTcpListenerFactory::new(listener));
        let mut socket_listener = TcpSocketListener::new_with_options(
            "tcp://127.0.0.1:0".parse().unwrap(),
            options.clone(),
            factory.clone(),
        );

        socket_listener.listen().await.unwrap();
        let accepted = socket_listener.accept().await.unwrap();

        assert_eq!(socket_listener.local_url().port(), Some(bound_addr.port()));
        assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
        assert_eq!(factory.binds.lock().unwrap().as_slice(), &[options]);
    }

    #[tokio::test]
    async fn tcp_socket_listener_retries_retryable_accept_error() {
        let requested_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let bound_addr = SocketAddr::from(([127, 0, 0, 1], 12010));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12011));
        let listener = Arc::new(MockTcpListener::new(
            bound_addr,
            vec![
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
                Ok(MockTcpSocket::new(bound_addr, peer_addr)),
            ],
        ));
        let factory = Arc::new(MockTcpListenerFactory::new(listener));
        let mut socket_listener = TcpSocketListener::new_with_options(
            "tcp://127.0.0.1:0".parse().unwrap(),
            TcpListenOptions::direct_connect(requested_addr),
            factory,
        );

        socket_listener.listen().await.unwrap();
        let accepted = socket_listener.accept().await.unwrap();

        assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
    }
}
