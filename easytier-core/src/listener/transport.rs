use std::{
    fmt,
    marker::PhantomData,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use url::Url;

use crate::{
    connectivity::protocol::raw,
    listener::{
        AcceptedSocketHandler, ListenerConnectionCounter, ListenerEventSink, ListenerManager,
        SocketListener,
    },
    peers::peer_manager::PeerManagerCore,
    socket::{
        tcp::{TcpListenOptions, TcpSocketListener, VirtualTcpListener, VirtualTcpListenerFactory},
        udp::{
            UdpSession, UdpSessionAcceptKind, UdpSessionControlHandler, UdpSessionListenRequest,
            UdpSessionSocketListener, VirtualUdpSocketFactory,
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
    Tcp { socket: TcpSocket, local_url: Url },
    Udp { session: UdpSession, local_url: Url },
}

impl<TcpSocket> AcceptedTransport<TcpSocket> {
    pub fn local_url(&self) -> &Url {
        match self {
            Self::Tcp { local_url, .. } | Self::Udp { local_url, .. } => local_url,
        }
    }
}

pub struct RawAcceptedTransportHandler {
    peer_manager: Weak<PeerManagerCore>,
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
            AcceptedTransport::Udp { session, local_url } => {
                if local_url.scheme() != "udp" {
                    anyhow::bail!("unsupported raw UDP listener protocol: {local_url}");
                }
                raw::upgrade_accepted_udp(session)?
            }
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
    tcp_socket: PhantomData<fn() -> TcpSocket>,
}

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
        Self {
            inner: UdpSessionSocketListener::new_with_request(
                url,
                request,
                accept_kind,
                host.clone(),
                host,
            ),
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
        let session = self.inner.accept().await?;
        Ok(AcceptedTransport::Udp {
            session,
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
    use crate::socket::{
        tcp::{VirtualTcpListener, VirtualTcpSocket},
        udp::{
            UdpBindOptions, UdpSessionKind, UdpSessionProtocol, UdpSessionSocket, VirtualUdpSocket,
            new_syn_packet,
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
                AcceptedTransport::Udp { session, local_url } => {
                    self.events.send(AcceptedEvent::Udp {
                        port: local_url.port().unwrap(),
                        kind: session.kind(),
                    })?;
                    self.blocked.notified().await;
                    drop(session);
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
