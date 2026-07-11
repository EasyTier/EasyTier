use std::{
    fmt,
    marker::PhantomData,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use url::Url;

use crate::{
    connectivity::protocol::{
        ServerProtocolAdmissionController, ServerProtocolUpgrade, ServerProtocolUpgrader, raw,
    },
    listener::{
        AcceptedSocketHandler, ListenerConnectionCounter, ListenerEventSink, ListenerManager,
        SocketListener,
    },
    peers::peer_manager::PeerManagerCore,
    socket::{
        tcp::{TcpListenOptions, TcpSocketListener, VirtualTcpListener, VirtualTcpListenerFactory},
        udp::{
            UdpSession, UdpSessionAcceptKind, UdpSessionControlHandler, UdpSessionListenRequest,
            UdpSessionSocket, UdpSessionSocketListener, VirtualUdpSocketFactory,
        },
    },
};

pub type HostAcceptedTcpSocket<H> =
    <<H as VirtualTcpListenerFactory>::Listener as VirtualTcpListener>::Socket;

/// The transport boundary of a core listener.
///
/// Socket creation and binding belong to the host factory. Protocol handling
/// consumes this value and may turn it into one or more EasyTier tunnels.
pub enum AcceptedTransport<TcpSocket> {
    Tcp {
        socket: TcpSocket,
        local_url: Url,
    },
    Udp {
        session: UdpSession,
        local_url: Url,
        admission: Option<crate::connectivity::protocol::ServerProtocolAdmission>,
    },
    ByteStream {
        socket: TcpSocket,
        local_url: Url,
        remote_url: Option<Url>,
    },
}

impl<TcpSocket> AcceptedTransport<TcpSocket> {
    pub fn local_url(&self) -> &Url {
        match self {
            Self::Tcp { local_url, .. }
            | Self::Udp { local_url, .. }
            | Self::ByteStream { local_url, .. } => local_url,
        }
    }
}

pub struct RawAcceptedTransportHandler {
    peer_manager: Weak<PeerManagerCore>,
}

#[async_trait]
pub trait AcceptedTunnelHandler: Send + Sync + 'static {
    async fn handle_tunnel(&self, tunnel: Box<dyn crate::tunnel::Tunnel>) -> anyhow::Result<()>;
}

#[async_trait]
impl AcceptedTunnelHandler for PeerManagerCore {
    async fn handle_tunnel(&self, tunnel: Box<dyn crate::tunnel::Tunnel>) -> anyhow::Result<()> {
        self.add_tunnel_as_server(tunnel, true).await?;
        Ok(())
    }
}

/// Upgrades accepted sockets or sessions in core before peer admission.
pub struct ProtocolAcceptedTransportHandler<TcpSocket, H> {
    tunnel_handler: Weak<H>,
    protocol: Arc<dyn ServerProtocolUpgrader<TcpSocket>>,
}

impl<TcpSocket, H> ProtocolAcceptedTransportHandler<TcpSocket, H> {
    pub fn new(
        tunnel_handler: &Arc<H>,
        protocol: Arc<dyn ServerProtocolUpgrader<TcpSocket>>,
    ) -> Self {
        Self {
            tunnel_handler: Arc::downgrade(tunnel_handler),
            protocol,
        }
    }
}

impl<TcpSocket, H> ProtocolAcceptedTransportHandler<TcpSocket, H>
where
    H: AcceptedTunnelHandler,
{
    async fn handle_tunnel(&self, tunnel: Box<dyn crate::tunnel::Tunnel>) -> anyhow::Result<()> {
        self.tunnel_handler
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("accepted tunnel handler is gone"))?
            .handle_tunnel(tunnel)
            .await
    }

    async fn handle_upgrade(&self, upgrade: ServerProtocolUpgrade) -> anyhow::Result<()> {
        match upgrade {
            ServerProtocolUpgrade::Tunnel(tunnel) => self.handle_tunnel(tunnel).await,
            ServerProtocolUpgrade::Acceptor(mut acceptor) => loop {
                let tunnel = acceptor.accept().await?;
                let _ = self.handle_tunnel(tunnel).await;
            },
        }
    }
}

#[async_trait]
impl<TcpSocket, H> AcceptedSocketHandler<AcceptedTransport<TcpSocket>>
    for ProtocolAcceptedTransportHandler<TcpSocket, H>
where
    TcpSocket: crate::socket::tcp::VirtualTcpSocket,
    H: AcceptedTunnelHandler,
{
    async fn handle_accepted_socket(
        &self,
        accepted: AcceptedTransport<TcpSocket>,
    ) -> anyhow::Result<()> {
        let upgrade = match accepted {
            AcceptedTransport::Tcp { socket, local_url } => {
                self.protocol.upgrade_tcp(socket, local_url).await?
            }
            AcceptedTransport::Udp {
                session,
                local_url,
                admission,
            } => {
                self.protocol
                    .upgrade_udp(session, local_url, admission)
                    .await?
            }
            AcceptedTransport::ByteStream {
                socket,
                local_url,
                remote_url,
            } => {
                self.protocol
                    .upgrade_byte_stream(socket, local_url, remote_url)
                    .await?
            }
        };
        self.handle_upgrade(upgrade).await
    }
}

impl RawAcceptedTransportHandler {
    pub fn new(peer_manager: &Arc<PeerManagerCore>) -> Self {
        Self {
            peer_manager: Arc::downgrade(peer_manager),
        }
    }
}

#[async_trait]
impl<TcpSocket> AcceptedSocketHandler<AcceptedTransport<TcpSocket>> for RawAcceptedTransportHandler
where
    TcpSocket: crate::socket::tcp::VirtualTcpSocket,
{
    async fn handle_accepted_socket(
        &self,
        accepted: AcceptedTransport<TcpSocket>,
    ) -> anyhow::Result<()> {
        let peer_manager = self
            .peer_manager
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("peer manager is gone"))?;
        let tunnel = match accepted {
            AcceptedTransport::Tcp { socket, local_url } => {
                if local_url.scheme() != "tcp" {
                    anyhow::bail!("unsupported raw TCP listener protocol: {local_url}");
                }
                raw::upgrade_accepted_tcp_with_local_url(socket, local_url)?
            }
            AcceptedTransport::Udp {
                session, local_url, ..
            } => {
                if local_url.scheme() != "udp" {
                    anyhow::bail!("unsupported raw UDP listener protocol: {local_url}");
                }
                raw::upgrade_accepted_udp(session)?
            }
            AcceptedTransport::ByteStream {
                socket,
                local_url,
                remote_url,
            } => raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?,
        };
        peer_manager.add_tunnel_as_server(tunnel, true).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum TransportListenerConfig {
    Tcp {
        url: Url,
        options: TcpListenOptions,
        must_succeed: bool,
    },
    Udp {
        url: Url,
        request: UdpSessionListenRequest,
        accept_kind: UdpSessionAcceptKind,
        must_succeed: bool,
    },
}

impl TransportListenerConfig {
    pub fn must_succeed(&self) -> bool {
        match self {
            Self::Tcp { must_succeed, .. } | Self::Udp { must_succeed, .. } => *must_succeed,
        }
    }

    pub fn url(&self) -> &Url {
        match self {
            Self::Tcp { url, .. } | Self::Udp { url, .. } => url,
        }
    }

    pub fn supports_raw_handler(&self) -> bool {
        matches!(self, Self::Tcp { url, .. } if url.scheme() == "tcp")
            || matches!(
                self,
                Self::Udp {
                    url,
                    accept_kind: UdpSessionAcceptKind::EasyTierMux,
                    ..
                } if url.scheme() == "udp"
            )
    }
}

struct TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    inner: TcpSocketListener<H>,
}

impl<H> TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    fn new(url: Url, options: TcpListenOptions, host: Arc<H>) -> Self {
        Self {
            inner: TcpSocketListener::new_with_options(url, options, host),
        }
    }
}

impl<H> fmt::Debug for TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpTransportListener")
            .field("inner", &self.inner)
            .finish()
    }
}

#[async_trait]
impl<H> SocketListener for TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    type Accepted = AcceptedTransport<HostAcceptedTcpSocket<H>>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let socket = self.inner.accept().await?;
        Ok(AcceptedTransport::Tcp {
            socket,
            local_url: self.inner.local_url(),
        })
    }

    fn local_url(&self) -> Url {
        self.inner.local_url()
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner.connection_counter()
    }
}

struct UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
{
    inner: UdpSessionSocketListener<H, H>,
    protocol_admission: Option<ServerProtocolAdmissionController>,
    tcp_socket: PhantomData<fn() -> TcpSocket>,
}

const QUIC_MAX_ACTIVE_UDP_SESSIONS: usize = 1024;
const QUIC_MAX_IN_FLIGHT_HANDSHAKES: usize = 128;

impl<H, TcpSocket> UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
{
    fn new(
        url: Url,
        request: UdpSessionListenRequest,
        accept_kind: UdpSessionAcceptKind,
        host: Arc<H>,
    ) -> Self {
        let protocol_admission = matches!(
            accept_kind,
            UdpSessionAcceptKind::Classified(crate::socket::udp::UdpSessionProtocol::Quic)
        )
        .then(|| {
            ServerProtocolAdmissionController::new(
                QUIC_MAX_ACTIVE_UDP_SESSIONS,
                QUIC_MAX_IN_FLIGHT_HANDSHAKES,
            )
        });
        Self {
            inner: UdpSessionSocketListener::new_with_request(
                url,
                request,
                accept_kind,
                host.clone(),
                host,
            ),
            protocol_admission,
            tcp_socket: PhantomData,
        }
    }
}

impl<H, TcpSocket> fmt::Debug for UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpTransportListener")
            .field("inner", &self.inner)
            .finish()
    }
}

#[async_trait]
impl<H, TcpSocket> SocketListener for UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
    TcpSocket: Send + 'static,
{
    type Accepted = AcceptedTransport<TcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        loop {
            let session = self.inner.accept().await?;
            let admission = match &self.protocol_admission {
                Some(controller) => match controller.try_admit() {
                    Some(admission) => Some(admission),
                    None => {
                        tracing::debug!(
                            peer_addr = ?session.peer_addr(),
                            "drop UDP session after protocol admission limit"
                        );
                        continue;
                    }
                },
                None => None,
            };
            return Ok(AcceptedTransport::Udp {
                session,
                local_url: self.inner.local_url(),
                admission,
            });
        }
    }

    fn local_url(&self) -> Url {
        self.inner.local_url()
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner.connection_counter()
    }
}

struct ErasedAcceptedTransportHandler<TcpSocket> {
    inner: Arc<dyn AcceptedSocketHandler<AcceptedTransport<TcpSocket>>>,
}

#[async_trait]
impl<TcpSocket> AcceptedSocketHandler<AcceptedTransport<TcpSocket>>
    for ErasedAcceptedTransportHandler<TcpSocket>
where
    TcpSocket: Send + 'static,
{
    async fn handle_accepted_socket(
        &self,
        accepted: AcceptedTransport<TcpSocket>,
    ) -> anyhow::Result<()> {
        self.inner.handle_accepted_socket(accepted).await
    }
}

type HostTransportListenerManager<H> = ListenerManager<
    AcceptedTransport<HostAcceptedTcpSocket<H>>,
    ErasedAcceptedTransportHandler<HostAcceptedTcpSocket<H>>,
>;

/// Owns TCP and UDP transport listeners built entirely from host factories.
pub struct TransportListenerService<H>
where
    H: VirtualTcpListenerFactory
        + VirtualUdpSocketFactory
        + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    manager: HostTransportListenerManager<H>,
}

impl<H> TransportListenerService<H>
where
    H: VirtualTcpListenerFactory
        + VirtualUdpSocketFactory
        + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    pub fn new(
        host: Arc<H>,
        configs: Vec<TransportListenerConfig>,
        handler: Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
    ) -> Self {
        Self::build(host, configs, handler, None)
    }

    pub fn new_with_events(
        host: Arc<H>,
        configs: Vec<TransportListenerConfig>,
        handler: Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
        events: Arc<dyn ListenerEventSink>,
    ) -> Self {
        Self::build(host, configs, handler, Some(events))
    }

    fn build(
        host: Arc<H>,
        configs: Vec<TransportListenerConfig>,
        handler: Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
        events: Option<Arc<dyn ListenerEventSink>>,
    ) -> Self {
        let handler = Arc::new(ErasedAcceptedTransportHandler { inner: handler });
        let mut manager = match events {
            Some(events) => ListenerManager::new_with_events(handler, events),
            None => ListenerManager::new(handler),
        };

        for config in configs {
            let must_succeed = config.must_succeed();
            match config {
                TransportListenerConfig::Tcp { url, options, .. } => {
                    let host = host.clone();
                    manager.add_listener(
                        move || {
                            Box::new(TcpTransportListener::new(
                                url.clone(),
                                options.clone(),
                                host.clone(),
                            ))
                        },
                        must_succeed,
                    );
                }
                TransportListenerConfig::Udp {
                    url,
                    request,
                    accept_kind,
                    ..
                } => {
                    let host = host.clone();
                    manager.add_listener(
                        move || {
                            Box::new(UdpTransportListener::new(
                                url.clone(),
                                request.clone(),
                                accept_kind,
                                host.clone(),
                            ))
                        },
                        must_succeed,
                    );
                }
            }
        }

        Self { manager }
    }

    pub fn listener_count(&self) -> usize {
        self.manager.listener_count()
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        self.manager.run().await
    }

    pub async fn stop(&self) {
        self.manager.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::SocketAddr,
        pin::Pin,
        sync::{
            Arc, Mutex as StdMutex,
            atomic::{AtomicU16, AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::{
        io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
        sync::{Mutex, Notify, mpsc},
    };

    use super::*;
    use crate::{
        connectivity::protocol::{CoreServerProtocolUpgrader, ServerTunnelAcceptor},
        socket::{
            tcp::{VirtualTcpListener, VirtualTcpSocket},
            udp::{
                UdpBindOptions, UdpSessionKind, UdpSessionProtocol, UdpSessionSocket,
                VirtualUdpSocket, new_syn_packet,
            },
        },
    };

    struct MockTcpSocket {
        stream: DuplexStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
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
        accepted_tx: mpsc::UnboundedSender<MockTcpSocket>,
        accepted_rx: Mutex<mpsc::UnboundedReceiver<MockTcpSocket>>,
    }

    impl MockTcpListener {
        fn new(local_addr: SocketAddr) -> Self {
            let (accepted_tx, accepted_rx) = mpsc::unbounded_channel();
            Self {
                local_addr,
                accepted_tx,
                accepted_rx: Mutex::new(accepted_rx),
            }
        }

        fn accept_from(&self, peer_addr: SocketAddr) {
            let (stream, _remote) = tokio::io::duplex(64);
            self.accepted_tx
                .send(MockTcpSocket {
                    stream,
                    local_addr: self.local_addr,
                    peer_addr,
                })
                .unwrap();
        }
    }

    #[async_trait]
    impl VirtualTcpListener for MockTcpListener {
        type Socket = MockTcpSocket;

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
            let socket =
                self.accepted_rx.lock().await.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "accept queue closed")
                })?;
            let peer_addr = socket.peer_addr;
            Ok((socket, peer_addr))
        }
    }

    struct MockUdpSocket {
        local_addr: SocketAddr,
        incoming: StdMutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        incoming_notify: Notify,
    }

    impl MockUdpSocket {
        fn new(local_addr: SocketAddr) -> Self {
            Self {
                local_addr,
                incoming: StdMutex::new(VecDeque::new()),
                incoming_notify: Notify::new(),
            }
        }

        fn receive_from(&self, data: Vec<u8>, peer_addr: SocketAddr) {
            self.incoming.lock().unwrap().push_back((data, peer_addr));
            self.incoming_notify.notify_one();
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for MockUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            loop {
                if let Some((data, peer_addr)) = self.incoming.lock().unwrap().pop_front() {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    return Ok((len, peer_addr));
                }
                self.incoming_notify.notified().await;
            }
        }
    }

    struct MockHost {
        next_tcp_port: AtomicU16,
        next_udp_port: AtomicU16,
        tcp_listeners: StdMutex<Vec<Arc<MockTcpListener>>>,
        udp_sockets: StdMutex<Vec<Arc<MockUdpSocket>>>,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                next_tcp_port: AtomicU16::new(21000),
                next_udp_port: AtomicU16::new(22000),
                tcp_listeners: StdMutex::new(Vec::new()),
                udp_sockets: StdMutex::new(Vec::new()),
            }
        }

        fn tcp_listener(&self, index: usize) -> Arc<MockTcpListener> {
            self.tcp_listeners.lock().unwrap()[index].clone()
        }

        fn udp_socket(&self, index: usize) -> Arc<MockUdpSocket> {
            self.udp_sockets.lock().unwrap()[index].clone()
        }
    }

    fn assigned_addr(requested: Option<SocketAddr>, next_port: &AtomicU16) -> SocketAddr {
        let mut addr = requested.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        if addr.port() == 0 {
            addr.set_port(next_port.fetch_add(1, Ordering::Relaxed));
        }
        addr
    }

    #[async_trait]
    impl VirtualTcpListenerFactory for MockHost {
        type Listener = MockTcpListener;

        async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
            let local_addr = assigned_addr(options.bind.local_addr, &self.next_tcp_port);
            let listener = Arc::new(MockTcpListener::new(local_addr));
            self.tcp_listeners.lock().unwrap().push(listener.clone());
            Ok(listener)
        }
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for MockHost {
        type Socket = MockUdpSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            let local_addr = assigned_addr(options.local_addr, &self.next_udp_port);
            let socket = Arc::new(MockUdpSocket::new(local_addr));
            self.udp_sockets.lock().unwrap().push(socket.clone());
            Ok(socket)
        }
    }

    #[async_trait]
    impl UdpSessionControlHandler<MockUdpSocket> for MockHost {}

    #[derive(Debug, PartialEq, Eq)]
    enum AcceptedEvent {
        Tcp { port: u16 },
        Udp { port: u16, kind: UdpSessionKind },
    }

    struct ActiveHandlerGuard(Arc<AtomicUsize>);

    impl ActiveHandlerGuard {
        fn new(active: Arc<AtomicUsize>) -> Self {
            active.fetch_add(1, Ordering::Relaxed);
            Self(active)
        }
    }

    impl Drop for ActiveHandlerGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }

    struct RecordingHandler {
        events: mpsc::UnboundedSender<AcceptedEvent>,
        blocked: Arc<Notify>,
        active: Arc<AtomicUsize>,
    }

    struct QueueTunnelAcceptor {
        tunnels: VecDeque<Box<dyn crate::tunnel::Tunnel>>,
    }

    #[async_trait]
    impl ServerTunnelAcceptor for QueueTunnelAcceptor {
        async fn accept(&mut self) -> anyhow::Result<Box<dyn crate::tunnel::Tunnel>> {
            self.tunnels
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("server tunnel acceptor finished"))
        }
    }

    struct RecordingServerProtocolUpgrader {
        tcp_calls: AtomicUsize,
        udp_calls: AtomicUsize,
    }

    impl RecordingServerProtocolUpgrader {
        fn new() -> Self {
            Self {
                tcp_calls: AtomicUsize::new(0),
                udp_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ServerProtocolUpgrader<MockTcpSocket> for RecordingServerProtocolUpgrader {
        fn supports_scheme(&self, scheme: &str) -> bool {
            matches!(scheme, "tcp" | "udp")
        }

        async fn upgrade_tcp(
            &self,
            socket: MockTcpSocket,
            _local_url: Url,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            self.tcp_calls.fetch_add(1, Ordering::Relaxed);
            let first = raw::upgrade_accepted_tcp(socket)?;
            let (stream, _remote) = tokio::io::duplex(64);
            let second = raw::upgrade_accepted_tcp(MockTcpSocket {
                stream,
                local_addr: "127.0.0.1:21001".parse().unwrap(),
                peer_addr: "127.0.0.1:31001".parse().unwrap(),
            })?;
            Ok(ServerProtocolUpgrade::Acceptor(Box::new(
                QueueTunnelAcceptor {
                    tunnels: VecDeque::from([first, second]),
                },
            )))
        }

        async fn upgrade_udp(
            &self,
            session: UdpSession,
            _local_url: Url,
            _admission: Option<crate::connectivity::protocol::ServerProtocolAdmission>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            self.udp_calls.fetch_add(1, Ordering::Relaxed);
            Ok(ServerProtocolUpgrade::Tunnel(raw::upgrade_accepted_udp(
                session,
            )?))
        }

        async fn upgrade_byte_stream(
            &self,
            socket: MockTcpSocket,
            local_url: Url,
            remote_url: Option<Url>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            Ok(ServerProtocolUpgrade::Tunnel(
                raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?,
            ))
        }
    }

    struct RecordingTunnelHandler {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl AcceptedTunnelHandler for RecordingTunnelHandler {
        async fn handle_tunnel(
            &self,
            _tunnel: Box<dyn crate::tunnel::Tunnel>,
        ) -> anyhow::Result<()> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            if call == 0 {
                anyhow::bail!("first admission rejected");
            }
            Ok(())
        }
    }

    #[async_trait]
    impl AcceptedSocketHandler<AcceptedTransport<MockTcpSocket>> for RecordingHandler {
        async fn handle_accepted_socket(
            &self,
            accepted: AcceptedTransport<MockTcpSocket>,
        ) -> anyhow::Result<()> {
            let _active = ActiveHandlerGuard::new(self.active.clone());
            match accepted {
                AcceptedTransport::Tcp { socket, local_url } => {
                    self.events.send(AcceptedEvent::Tcp {
                        port: local_url.port().unwrap(),
                    })?;
                    self.blocked.notified().await;
                    drop(socket);
                }
                AcceptedTransport::Udp {
                    session, local_url, ..
                } => {
                    self.events.send(AcceptedEvent::Udp {
                        port: local_url.port().unwrap(),
                        kind: session.kind(),
                    })?;
                    self.blocked.notified().await;
                    drop(session);
                }
                AcceptedTransport::ByteStream {
                    socket, local_url, ..
                } => {
                    self.events.send(AcceptedEvent::Tcp {
                        port: local_url.port().unwrap_or_default(),
                    })?;
                    self.blocked.notified().await;
                    drop(socket);
                }
            }
            Ok(())
        }
    }

    fn wireguard_packet() -> Vec<u8> {
        let mut packet = vec![0; 32];
        packet[..4].copy_from_slice(&4u32.to_le_bytes());
        packet
    }

    fn quic_initial_packet(dcid: u8) -> Vec<u8> {
        let mut packet = vec![0; 1200];
        packet[0] = 0xc0;
        packet[4] = 1;
        packet[5] = 1;
        packet[6] = dcid;
        packet[7] = 0;
        packet[8] = 0;
        packet[9] = 1;
        packet
    }

    #[tokio::test]
    async fn quic_admission_happens_before_transport_is_returned() -> anyhow::Result<()> {
        let host = Arc::new(MockHost::new());
        let mut listener = UdpTransportListener::<MockHost, MockTcpSocket>::new(
            "quic://127.0.0.1:0".parse()?,
            UdpSessionListenRequest::new(UdpBindOptions::port_bound_listener(
                "127.0.0.1:0".parse()?,
            )),
            UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
            host.clone(),
        );
        listener.protocol_admission = Some(ServerProtocolAdmissionController::new(1, 1));
        listener.listen().await?;
        let socket = host.udp_socket(0);

        socket.receive_from(quic_initial_packet(1), "127.0.0.1:32001".parse()?);
        let first = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await??;
        assert!(matches!(
            &first,
            AcceptedTransport::Udp {
                admission: Some(_),
                ..
            }
        ));

        socket.receive_from(quic_initial_packet(2), "127.0.0.1:32002".parse()?);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );

        drop(first);
        socket.receive_from(quic_initial_packet(3), "127.0.0.1:32003".parse()?);
        let third = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await??;
        assert!(matches!(
            third,
            AcceptedTransport::Udp {
                admission: Some(_),
                ..
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn protocol_handler_consumes_multi_tunnel_acceptors_and_udp_upgrades()
    -> anyhow::Result<()> {
        let tunnel_handler = Arc::new(RecordingTunnelHandler {
            calls: AtomicUsize::new(0),
        });
        let protocol = Arc::new(RecordingServerProtocolUpgrader::new());
        let handler = ProtocolAcceptedTransportHandler::new(&tunnel_handler, protocol.clone());

        let (stream, _remote) = tokio::io::duplex(64);
        let tcp_result = handler
            .handle_accepted_socket(AcceptedTransport::Tcp {
                socket: MockTcpSocket {
                    stream,
                    local_addr: "127.0.0.1:21000".parse().unwrap(),
                    peer_addr: "127.0.0.1:31000".parse().unwrap(),
                },
                local_url: "tcp://127.0.0.1:21000".parse().unwrap(),
            })
            .await
            .unwrap_err();
        assert_eq!(tcp_result.to_string(), "server tunnel acceptor finished");
        assert_eq!(protocol.tcp_calls.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_handler.calls.load(Ordering::Relaxed), 2);

        let udp_socket = Arc::new(MockUdpSocket::new("127.0.0.1:22000".parse().unwrap()));
        let udp_session = UdpSession::identity_standalone(
            udp_socket,
            "127.0.0.1:32000".parse().unwrap(),
            UdpSessionKind::EasyTierMux,
        )?;
        handler
            .handle_accepted_socket(AcceptedTransport::Udp {
                session: udp_session,
                local_url: "udp://127.0.0.1:22000".parse().unwrap(),
                admission: None,
            })
            .await?;
        assert_eq!(protocol.udp_calls.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_handler.calls.load(Ordering::Relaxed), 3);

        Ok::<(), anyhow::Error>(())
    }

    #[tokio::test]
    async fn core_builtin_server_upgrades_raw_udp_and_byte_streams() -> anyhow::Result<()> {
        let tunnel_handler = Arc::new(RecordingTunnelHandler {
            calls: AtomicUsize::new(0),
        });
        let protocol = Arc::new(CoreServerProtocolUpgrader::new(Default::default()));
        let handler = ProtocolAcceptedTransportHandler::new(&tunnel_handler, protocol);

        let udp_socket = Arc::new(MockUdpSocket::new("127.0.0.1:22000".parse()?));
        let udp_session = UdpSession::identity_standalone(
            udp_socket,
            "127.0.0.1:32000".parse()?,
            UdpSessionKind::EasyTierMux,
        )?;
        let admission_error = handler
            .handle_accepted_socket(AcceptedTransport::Udp {
                session: udp_session,
                local_url: "udp://127.0.0.1:22000".parse()?,
                admission: None,
            })
            .await
            .unwrap_err();
        assert_eq!(admission_error.to_string(), "first admission rejected");

        let (stream, _remote) = tokio::io::duplex(64);
        handler
            .handle_accepted_socket(AcceptedTransport::ByteStream {
                socket: MockTcpSocket {
                    stream,
                    local_addr: "127.0.0.1:21000".parse()?,
                    peer_addr: "127.0.0.1:31000".parse()?,
                },
                local_url: "ring://local".parse()?,
                remote_url: Some("ring://remote".parse()?),
            })
            .await?;
        assert_eq!(tunnel_handler.calls.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[tokio::test]
    async fn service_preserves_transport_boundary_and_stops_blocked_handlers() {
        let host = Arc::new(MockHost::new());
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let active = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(RecordingHandler {
            events: event_tx,
            blocked: Arc::new(Notify::new()),
            active: active.clone(),
        });
        let service = TransportListenerService::new(
            host.clone(),
            vec![
                TransportListenerConfig::Tcp {
                    url: "tcp://127.0.0.1:0".parse().unwrap(),
                    options: TcpListenOptions::manual_connect("127.0.0.1:0".parse().unwrap()),
                    must_succeed: true,
                },
                TransportListenerConfig::Udp {
                    url: "udp://127.0.0.1:0".parse().unwrap(),
                    request: UdpSessionListenRequest::new(UdpBindOptions::port_bound_listener(
                        "127.0.0.1:0".parse().unwrap(),
                    )),
                    accept_kind: UdpSessionAcceptKind::EasyTierMux,
                    must_succeed: true,
                },
                TransportListenerConfig::Udp {
                    url: "wg://127.0.0.1:0".parse().unwrap(),
                    request: UdpSessionListenRequest::new(UdpBindOptions::port_bound_listener(
                        "127.0.0.1:0".parse().unwrap(),
                    )),
                    accept_kind: UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
                    must_succeed: true,
                },
            ],
            handler,
        );

        service.start().await.unwrap();
        host.tcp_listener(0)
            .accept_from("127.0.0.1:31000".parse().unwrap());
        host.udp_socket(0).receive_from(
            new_syn_packet(1, 2).into_bytes().to_vec(),
            "127.0.0.1:32000".parse().unwrap(),
        );
        host.udp_socket(1)
            .receive_from(wireguard_packet(), "127.0.0.1:32001".parse().unwrap());

        let mut events = Vec::new();
        for _ in 0..3 {
            events.push(
                tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
                    .await
                    .expect("accepted transport was not handled")
                    .expect("accepted transport event channel closed"),
            );
        }
        assert!(events.contains(&AcceptedEvent::Tcp { port: 21000 }));
        assert!(events.contains(&AcceptedEvent::Udp {
            port: 22000,
            kind: UdpSessionKind::EasyTierMux,
        }));
        assert!(events.contains(&AcceptedEvent::Udp {
            port: 22001,
            kind: UdpSessionKind::WireGuard,
        }));
        assert_eq!(active.load(Ordering::Relaxed), 3);

        tokio::time::timeout(Duration::from_secs(1), service.stop())
            .await
            .expect("transport listener service did not stop");
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }
}
