use std::{fmt, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use rand::seq::SliceRandom as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

use crate::{
    connectivity::{
        manual::resolve_url_addrs,
        protocol::{
            ServerProtocolAdmissionController, ServerProtocolUpgrade, ServerProtocolUpgrader, raw,
        },
    },
    host::dns::DnsResolver,
    listener::{
        AcceptedSocketHandler, ListenerEvent, ListenerEventSink, ListenerFactory, ListenerManager,
        plan::ListenerPlanFailure,
    },
    socket::{
        IpVersion, ListenerConnectionCounter, SocketContext, SocketListener,
        tcp::{TcpListenOptions, TcpSocketListener, VirtualTcpListener, VirtualTcpListenerFactory},
        udp::{
            UdpSession, UdpSessionAcceptKind, UdpSessionListenRequest, UdpSessionSocket,
            UdpSessionSocketListener, VirtualUdpSocketFactory,
        },
    },
    tunnel::{Tunnel, ring::RingTunnelRegistry},
};

pub type HostAcceptedTcpSocket<H> =
    <<H as VirtualTcpListenerFactory>::Listener as VirtualTcpListener>::Socket;

/// The transport boundary of a core listener.
///
/// Socket creation and binding belong to the host factory. Protocol handling
/// consumes this value and may turn it into one or more EasyTier tunnels.
pub enum AcceptedTransport<TcpSocket> {
    Tunnel {
        tunnel: Box<dyn Tunnel>,
        local_url: Url,
    },
    Tcp {
        socket: TcpSocket,
        local_url: Url,
        upgrade_permit: Option<OwnedSemaphorePermit>,
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
            Self::Tunnel { local_url, .. }
            | Self::Tcp { local_url, .. }
            | Self::Udp { local_url, .. }
            | Self::ByteStream { local_url, .. } => local_url,
        }
    }
}

#[async_trait]
pub trait AcceptedTunnelHandler: Send + Sync + 'static {
    async fn handle_tunnel(&self, tunnel: Box<dyn crate::tunnel::Tunnel>) -> anyhow::Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptedTunnelEvent {
    Accepted {
        local_url: String,
        remote_url: String,
    },
    AdmissionFailed {
        local_url: String,
        remote_url: String,
        error: String,
    },
}

pub trait AcceptedTunnelEventSink: Send + Sync + 'static {
    fn emit(&self, event: AcceptedTunnelEvent);
}

impl AcceptedTunnelEventSink for () {
    fn emit(&self, _event: AcceptedTunnelEvent) {}
}

/// Upgrades accepted sockets or sessions in core before peer admission.
pub struct ProtocolAcceptedTransportHandler<TcpSocket, H> {
    tunnel_handler: Arc<H>,
    protocol: Arc<dyn ServerProtocolUpgrader<TcpSocket>>,
}

impl<TcpSocket, H> ProtocolAcceptedTransportHandler<TcpSocket, H> {
    pub fn new(
        tunnel_handler: &Arc<H>,
        protocol: Arc<dyn ServerProtocolUpgrader<TcpSocket>>,
    ) -> Self {
        Self {
            tunnel_handler: tunnel_handler.clone(),
            protocol,
        }
    }
}

impl<TcpSocket, H> ProtocolAcceptedTransportHandler<TcpSocket, H>
where
    H: AcceptedTunnelHandler,
{
    async fn handle_tunnel(&self, tunnel: Box<dyn crate::tunnel::Tunnel>) -> anyhow::Result<()> {
        self.tunnel_handler.handle_tunnel(tunnel).await
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
        let (upgrade, tcp_upgrade_permit) = match accepted {
            AcceptedTransport::Tunnel { tunnel, .. } => {
                return self.handle_tunnel(tunnel).await;
            }
            AcceptedTransport::Tcp {
                socket,
                local_url,
                upgrade_permit,
            } => (
                self.protocol.upgrade_tcp(socket, local_url).await?,
                upgrade_permit,
            ),
            AcceptedTransport::Udp {
                session,
                local_url,
                admission,
            } => (
                self.protocol
                    .upgrade_udp(session, local_url, admission)
                    .await?,
                None,
            ),
            AcceptedTransport::ByteStream {
                socket,
                local_url,
                remote_url,
            } if local_url.scheme() == "unix" => {
                let tunnel = raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?;
                return self.handle_tunnel(tunnel).await;
            }
            AcceptedTransport::ByteStream {
                socket,
                local_url,
                remote_url,
            } => (
                self.protocol
                    .upgrade_byte_stream(socket, local_url, remote_url)
                    .await?,
                None,
            ),
        };
        drop(tcp_upgrade_permit);
        self.handle_upgrade(upgrade).await
    }
}

#[derive(Debug, Clone)]
pub(crate) enum TransportListenerConfig {
    Ring {
        url: Url,
        must_succeed: bool,
    },
    Tcp {
        url: Url,
        options: TcpListenOptions,
        max_pending_upgrades: Option<std::num::NonZeroUsize>,
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
    pub(crate) fn must_succeed(&self) -> bool {
        match self {
            Self::Ring { must_succeed, .. }
            | Self::Tcp { must_succeed, .. }
            | Self::Udp { must_succeed, .. } => *must_succeed,
        }
    }

    pub(crate) fn url(&self) -> &Url {
        match self {
            Self::Ring { url, .. } | Self::Tcp { url, .. } | Self::Udp { url, .. } => url,
        }
    }

    pub(crate) fn supports_raw_handler(&self) -> bool {
        matches!(self, Self::Ring { url, .. } if url.scheme() == "ring")
            || matches!(self, Self::Tcp { url, .. } if url.scheme() == "tcp")
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

struct RingTransportListener<TcpSocket> {
    url: Url,
    registry: Arc<RingTunnelRegistry>,
    inner: Option<crate::tunnel::ring::RingTunnelSocketListener>,
    tcp_socket: PhantomData<fn() -> TcpSocket>,
}

impl<TcpSocket> RingTransportListener<TcpSocket> {
    fn new(url: Url, registry: Arc<RingTunnelRegistry>) -> Self {
        Self {
            url,
            registry,
            inner: None,
            tcp_socket: PhantomData,
        }
    }
}

impl<TcpSocket> fmt::Debug for RingTransportListener<TcpSocket> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RingTransportListener")
            .field("url", &self.url)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[async_trait]
impl<TcpSocket> SocketListener for RingTransportListener<TcpSocket>
where
    TcpSocket: Send + 'static,
{
    type Accepted = AcceptedTransport<TcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_none() {
            if self.url.scheme() != "ring" {
                anyhow::bail!("Ring listener requires ring URL: {}", self.url);
            }
            let local_id = self
                .url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("ring listener URL has no peer id: {}", self.url))?
                .parse()?;
            self.inner = Some(self.registry.bind(local_id)?);
        }
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let accepted = self
            .inner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Ring transport listener is not started"))?
            .accept()
            .await?;
        Ok(AcceptedTransport::Tunnel {
            tunnel: accepted.into_tunnel(),
            local_url: self.url.clone(),
        })
    }

    fn local_url(&self) -> Url {
        self.url.clone()
    }
}

struct TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    url: Url,
    options: TcpListenOptions,
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    upgrade_slots: Option<Arc<Semaphore>>,
    inner: Option<TcpSocketListener<H>>,
}

impl<H> TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    fn new(
        url: Url,
        options: TcpListenOptions,
        max_pending_upgrades: Option<std::num::NonZeroUsize>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
    ) -> Self {
        let upgrade_slots = max_pending_upgrades.map(|limit| Arc::new(Semaphore::new(limit.get())));
        Self {
            url,
            options,
            host,
            dns,
            upgrade_slots,
            inner: None,
        }
    }

    fn inner(&mut self) -> anyhow::Result<&mut TcpSocketListener<H>> {
        self.inner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("TCP transport listener is not started"))
    }
}

impl<H> fmt::Debug for TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpTransportListener")
            .field("url", &self.url)
            .field("listening", &self.inner.is_some())
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
        if self.inner.is_some() {
            return Ok(());
        }
        let mut options = self.options.clone();
        if options.bind.local_addr.is_none() {
            options.bind.local_addr = Some(
                resolve_listener_addr(&self.url, options.bind.context.clone(), self.dns.as_ref())
                    .await?,
            );
        }
        if let Some(local_addr) = options.bind.local_addr {
            options.bind.context.ip_version = if local_addr.is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            options.bind.only_v6 = local_addr.is_ipv6();
        }
        let mut inner =
            TcpSocketListener::new_with_options(self.url.clone(), options, self.host.clone());
        inner.listen().await?;
        self.inner = Some(inner);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let upgrade_permit = match &self.upgrade_slots {
            Some(slots) => Some(slots.clone().acquire_owned().await?),
            None => None,
        };
        let local_url = self.local_url();
        let socket = self.inner()?.accept().await?;
        Ok(AcceptedTransport::Tcp {
            socket,
            local_url,
            upgrade_permit,
        })
    }

    fn local_url(&self) -> Url {
        self.inner
            .as_ref()
            .map(SocketListener::local_url)
            .unwrap_or_else(|| self.url.clone())
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner
            .as_ref()
            .map(SocketListener::connection_counter)
            .unwrap_or_else(|| Arc::new(EmptyTransportConnectionCounter))
    }
}

struct UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory,
{
    url: Url,
    request: UdpSessionListenRequest,
    accept_kind: UdpSessionAcceptKind,
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    inner: Option<UdpSessionSocketListener<H>>,
    protocol_admission: Option<ServerProtocolAdmissionController>,
    tcp_socket: PhantomData<fn() -> TcpSocket>,
}

impl<H, TcpSocket> UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory,
{
    fn new(
        url: Url,
        request: UdpSessionListenRequest,
        accept_kind: UdpSessionAcceptKind,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
    ) -> Self {
        let protocol_admission = matches!(
            accept_kind,
            UdpSessionAcceptKind::Classified(crate::socket::udp::UdpSessionProtocol::Quic)
        )
        .then(ServerProtocolAdmissionController::quic);
        Self {
            url,
            request,
            accept_kind,
            host,
            dns,
            inner: None,
            protocol_admission,
            tcp_socket: PhantomData,
        }
    }

    fn inner(&mut self) -> anyhow::Result<&mut UdpSessionSocketListener<H>> {
        self.inner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("UDP transport listener is not started"))
    }
}

impl<H, TcpSocket> fmt::Debug for UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpTransportListener")
            .field("url", &self.url)
            .field("accept_kind", &self.accept_kind)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[async_trait]
impl<H, TcpSocket> SocketListener for UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory,
    TcpSocket: Send + 'static,
{
    type Accepted = AcceptedTransport<TcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_some() {
            return Ok(());
        }
        let mut request = self.request.clone();
        if request.bind.local_addr.is_none() {
            request.bind.local_addr = Some(
                resolve_listener_addr(&self.url, request.bind.context.clone(), self.dns.as_ref())
                    .await?,
            );
        }
        if let Some(local_addr) = request.bind.local_addr {
            request.bind.context.ip_version = if local_addr.is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            request.bind.only_v6 = local_addr.is_ipv6();
        }
        let mut inner = UdpSessionSocketListener::new_with_request(
            self.url.clone(),
            request,
            self.accept_kind,
            self.host.clone(),
        );
        inner.listen().await?;
        self.inner = Some(inner);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        loop {
            let session = self.inner()?.accept().await?;
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
                local_url: self.local_url(),
                admission,
            });
        }
    }

    fn local_url(&self) -> Url {
        self.inner
            .as_ref()
            .map(SocketListener::local_url)
            .unwrap_or_else(|| self.url.clone())
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner
            .as_ref()
            .map(SocketListener::connection_counter)
            .unwrap_or_else(|| Arc::new(EmptyTransportConnectionCounter))
    }
}

#[derive(Debug)]
struct EmptyTransportConnectionCounter;

impl ListenerConnectionCounter for EmptyTransportConnectionCounter {
    fn get(&self) -> Option<u32> {
        None
    }
}

async fn resolve_listener_addr(
    url: &Url,
    context: SocketContext,
    dns: &dyn DnsResolver,
) -> anyhow::Result<std::net::SocketAddr> {
    let default_port = super::plan::listener_default_port(url.scheme())
        .ok_or_else(|| anyhow::anyhow!("listener has no default port: {url}"))?;
    resolve_url_addrs(
        url,
        default_port,
        context.with_ip_version(IpVersion::Both),
        dns,
    )
    .await?
    .choose(&mut rand::thread_rng())
    .copied()
    .ok_or_else(|| anyhow::anyhow!("listener has no resolved address: {url}"))
}

type HostTransportListenerManager<H> = ListenerManager<
    AcceptedTransport<HostAcceptedTcpSocket<H>>,
    dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>,
>;

/// Owns all listeners planned by core, including host-backed external sockets.
pub(crate) struct CoreListenerRuntime<H>
where
    H: VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    manager: HostTransportListenerManager<H>,
    plan_failures: Vec<ListenerPlanFailure>,
    events: Arc<dyn ListenerEventSink>,
}

impl<H> CoreListenerRuntime<H>
where
    H: VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub(crate) fn new_with_events(
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        ring_registry: Arc<RingTunnelRegistry>,
        configs: Vec<TransportListenerConfig>,
        external_factories: Vec<ListenerFactory<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
        plan_failures: Vec<ListenerPlanFailure>,
        handler: Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
        events: Arc<dyn ListenerEventSink>,
    ) -> Self {
        let mut manager = ListenerManager::new_with_events(handler, events.clone());

        for config in configs {
            let must_succeed = config.must_succeed();
            match config {
                TransportListenerConfig::Ring { url, .. } => {
                    let ring_registry = ring_registry.clone();
                    manager.add_listener(
                        move || {
                            Box::new(RingTransportListener::new(
                                url.clone(),
                                ring_registry.clone(),
                            ))
                        },
                        must_succeed,
                    );
                }
                TransportListenerConfig::Tcp {
                    url,
                    options,
                    max_pending_upgrades,
                    ..
                } => {
                    let host = host.clone();
                    let dns = dns.clone();
                    manager.add_listener(
                        move || {
                            Box::new(TcpTransportListener::new(
                                url.clone(),
                                options.clone(),
                                max_pending_upgrades,
                                host.clone(),
                                dns.clone(),
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
                    let dns = dns.clone();
                    manager.add_listener(
                        move || {
                            Box::new(UdpTransportListener::new(
                                url.clone(),
                                request.clone(),
                                accept_kind,
                                host.clone(),
                                dns.clone(),
                            ))
                        },
                        must_succeed,
                    );
                }
            }
        }

        for factory in external_factories {
            manager.add_factory(factory);
        }

        Self {
            manager,
            plan_failures,
            events,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        for failure in &self.plan_failures {
            self.events.emit(ListenerEvent::ListenerPlanFailed {
                url: failure.url.clone(),
                error: failure.message.clone(),
            });
        }
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

    use futures::{SinkExt as _, StreamExt as _};
    use tokio::{
        io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
        sync::{Mutex, Notify, Semaphore, mpsc},
    };

    use super::*;
    use crate::{
        connectivity::protocol::{CoreServerProtocolUpgrader, ServerTunnelAcceptor},
        host::dns::{DnsQuery, DnsResolver},
        packet::ZCPacket,
        socket::{
            tcp::{VirtualTcpListener, VirtualTcpSocket},
            udp::{
                UdpBindOptions, UdpSessionKind, UdpSessionProtocol, UdpSessionSocket,
                VirtualUdpSocket, new_syn_packet,
            },
        },
    };

    struct MockDns;

    #[async_trait]
    impl DnsResolver for MockDns {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<std::net::IpAddr>> {
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }

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
        tcp_bind_options: StdMutex<Vec<TcpListenOptions>>,
        udp_bind_options: StdMutex<Vec<UdpBindOptions>>,
        tcp_listeners: StdMutex<Vec<Arc<MockTcpListener>>>,
        udp_sockets: StdMutex<Vec<Arc<MockUdpSocket>>>,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                next_tcp_port: AtomicU16::new(21000),
                next_udp_port: AtomicU16::new(22000),
                tcp_bind_options: StdMutex::new(Vec::new()),
                udp_bind_options: StdMutex::new(Vec::new()),
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

        fn tcp_bind_options(&self, index: usize) -> TcpListenOptions {
            self.tcp_bind_options.lock().unwrap()[index].clone()
        }

        fn udp_bind_options(&self, index: usize) -> UdpBindOptions {
            self.udp_bind_options.lock().unwrap()[index].clone()
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
            self.tcp_bind_options.lock().unwrap().push(options);
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
            self.udp_bind_options.lock().unwrap().push(options);
            let socket = Arc::new(MockUdpSocket::new(local_addr));
            self.udp_sockets.lock().unwrap().push(socket.clone());
            Ok(socket)
        }
    }

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

    #[derive(Debug, Default)]
    struct RecordingListenerEvents {
        events: StdMutex<Vec<ListenerEvent>>,
    }

    impl ListenerEventSink for RecordingListenerEvents {
        fn emit(&self, event: ListenerEvent) {
            self.events.lock().unwrap().push(event);
        }
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
        byte_stream_calls: AtomicUsize,
    }

    impl RecordingServerProtocolUpgrader {
        fn new() -> Self {
            Self {
                tcp_calls: AtomicUsize::new(0),
                udp_calls: AtomicUsize::new(0),
                byte_stream_calls: AtomicUsize::new(0),
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
            let first = raw::tests::upgrade_accepted_tcp(socket)?;
            let (stream, _remote) = tokio::io::duplex(64);
            let second = raw::tests::upgrade_accepted_tcp(MockTcpSocket {
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
            Ok(ServerProtocolUpgrade::Tunnel(
                raw::tests::upgrade_accepted_udp(session)?,
            ))
        }

        async fn upgrade_byte_stream(
            &self,
            socket: MockTcpSocket,
            local_url: Url,
            remote_url: Option<Url>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            self.byte_stream_calls.fetch_add(1, Ordering::Relaxed);
            Ok(ServerProtocolUpgrade::Tunnel(
                raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?,
            ))
        }
    }

    struct RecordingTunnelHandler {
        calls: AtomicUsize,
    }

    struct BlockingTunnelHandler {
        entered: Notify,
        release: Notify,
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
    impl AcceptedTunnelHandler for BlockingTunnelHandler {
        async fn handle_tunnel(
            &self,
            _tunnel: Box<dyn crate::tunnel::Tunnel>,
        ) -> anyhow::Result<()> {
            self.entered.notify_one();
            self.release.notified().await;
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
                AcceptedTransport::Tunnel { tunnel, .. } => {
                    drop(tunnel);
                }
                AcceptedTransport::Tcp {
                    socket, local_url, ..
                } => {
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
    async fn ring_listener_delivers_packet_native_tunnel() -> anyhow::Result<()> {
        let local_id = uuid::Uuid::new_v4();
        let registry = Arc::new(RingTunnelRegistry::default());
        let mut listener = RingTransportListener::<MockTcpSocket>::new(
            format!("ring://{local_id}").parse()?,
            registry.clone(),
        );
        listener.listen().await?;
        let client = registry.connect(local_id)?.into_tunnel();
        let AcceptedTransport::Tunnel { tunnel: server, .. } = listener.accept().await? else {
            anyhow::bail!("Ring listener did not produce a Tunnel");
        };
        let (_client_stream, mut client_sink) = client.split();
        let (mut server_stream, _server_sink) = server.split();

        client_sink
            .send(ZCPacket::new_with_payload(b"packet-native-listener"))
            .await?;
        let packet = server_stream.next().await.transpose()?.unwrap();
        assert_eq!(packet.payload(), b"packet-native-listener");
        Ok(())
    }

    #[tokio::test]
    async fn ring_listener_rejects_non_ring_url() {
        let registry = Arc::new(RingTunnelRegistry::default());
        let mut listener = RingTransportListener::<MockTcpSocket>::new(
            format!("tcp://{}", uuid::Uuid::new_v4()).parse().unwrap(),
            registry,
        );

        assert!(listener.listen().await.is_err());
    }

    #[tokio::test]
    async fn unresolved_listener_urls_use_core_dns_and_protocol_default_ports() -> anyhow::Result<()>
    {
        let host = Arc::new(MockHost::new());
        let mut tcp = TcpTransportListener::new(
            "tcp://listener.example".parse()?,
            super::super::plan::unresolved_tcp_listener_options(
                SocketContext::default().with_socket_mark(Some(7)),
            ),
            None,
            host.clone(),
            Arc::new(MockDns),
        );
        tcp.listen().await?;
        assert_eq!(host.tcp_listener(0).local_addr()?.port(), 11010);
        assert_eq!(
            host.tcp_bind_options(0).bind.context.ip_version,
            IpVersion::V4
        );
        assert!(!host.tcp_bind_options(0).bind.only_v6);

        let mut udp = UdpTransportListener::<MockHost, MockTcpSocket>::new(
            "wg://listener.example".parse()?,
            super::super::plan::unresolved_udp_session_listen_request(
                &"wg://listener.example".parse()?,
                SocketContext::default().with_socket_mark(Some(7)),
            ),
            UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
            host.clone(),
            Arc::new(MockDns),
        );
        udp.listen().await?;
        assert_eq!(host.udp_socket(0).local_addr()?.port(), 11011);
        assert_eq!(host.udp_bind_options(0).context.ip_version, IpVersion::V4);
        assert!(!host.udp_bind_options(0).only_v6);

        let mut tcp_v6 = TcpTransportListener::new(
            "tcp://[::1]:0".parse()?,
            super::super::plan::unresolved_tcp_listener_options(SocketContext::default()),
            None,
            host.clone(),
            Arc::new(MockDns),
        );
        tcp_v6.listen().await?;
        assert_eq!(
            host.tcp_bind_options(1).bind.context.ip_version,
            IpVersion::V6
        );
        assert!(host.tcp_bind_options(1).bind.only_v6);

        let udp_v6_url: Url = "udp://[::1]:0".parse()?;
        let mut udp_v6 = UdpTransportListener::<MockHost, MockTcpSocket>::new(
            udp_v6_url.clone(),
            super::super::plan::unresolved_udp_session_listen_request(
                &udp_v6_url,
                SocketContext::default(),
            ),
            UdpSessionAcceptKind::EasyTierMux,
            host.clone(),
            Arc::new(MockDns),
        );
        udp_v6.listen().await?;
        assert_eq!(host.udp_bind_options(1).context.ip_version, IpVersion::V6);
        assert!(host.udp_bind_options(1).only_v6);
        Ok(())
    }

    #[tokio::test]
    async fn tcp_listener_applies_protocol_upgrade_limit() -> anyhow::Result<()> {
        let host = Arc::new(MockHost::new());
        let mut listener = TcpTransportListener::new(
            "tcp://127.0.0.1:0".parse()?,
            super::super::plan::unresolved_tcp_listener_options(SocketContext::default()),
            Some(std::num::NonZeroUsize::MIN),
            host.clone(),
            Arc::new(MockDns),
        );
        listener.listen().await?;
        let socket = host.tcp_listener(0);
        socket.accept_from("127.0.0.1:31000".parse()?);
        socket.accept_from("127.0.0.1:31001".parse()?);

        let first = listener.accept().await?;
        assert!(
            crate::foundation::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        drop(first);
        crate::foundation::time::timeout(Duration::from_secs(1), listener.accept()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn tcp_upgrade_permit_is_released_before_peer_admission() -> anyhow::Result<()> {
        let tunnel_handler = Arc::new(BlockingTunnelHandler {
            entered: Notify::new(),
            release: Notify::new(),
        });
        let protocol = Arc::new(CoreServerProtocolUpgrader::new(Default::default()));
        let handler = ProtocolAcceptedTransportHandler::new(&tunnel_handler, protocol);
        let upgrade_slots = Arc::new(Semaphore::new(1));
        let permit = upgrade_slots.clone().acquire_owned().await?;
        let (stream, _remote) = tokio::io::duplex(64);

        let task = tokio::spawn(async move {
            handler
                .handle_accepted_socket(AcceptedTransport::Tcp {
                    socket: MockTcpSocket {
                        stream,
                        local_addr: "127.0.0.1:21000".parse().unwrap(),
                        peer_addr: "127.0.0.1:31000".parse().unwrap(),
                    },
                    local_url: "tcp://127.0.0.1:21000".parse().unwrap(),
                    upgrade_permit: Some(permit),
                })
                .await
        });

        tunnel_handler.entered.notified().await;
        let next_permit =
            crate::foundation::time::timeout(Duration::from_secs(1), upgrade_slots.acquire_owned())
                .await??;
        drop(next_permit);
        tunnel_handler.release.notify_one();
        task.await??;
        Ok(())
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
            Arc::new(MockDns),
        );
        listener.protocol_admission = Some(ServerProtocolAdmissionController::new(1, 1));
        listener.listen().await?;
        let socket = host.udp_socket(0);

        socket.receive_from(quic_initial_packet(1), "127.0.0.1:32001".parse()?);
        let first =
            crate::foundation::time::timeout(Duration::from_secs(1), listener.accept()).await??;
        assert!(matches!(
            &first,
            AcceptedTransport::Udp {
                admission: Some(_),
                ..
            }
        ));

        socket.receive_from(quic_initial_packet(2), "127.0.0.1:32002".parse()?);
        assert!(
            crate::foundation::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );

        drop(first);
        socket.receive_from(quic_initial_packet(3), "127.0.0.1:32003".parse()?);
        let third =
            crate::foundation::time::timeout(Duration::from_secs(1), listener.accept()).await??;
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
                upgrade_permit: None,
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

        let (stream, _remote) = tokio::io::duplex(64);
        handler
            .handle_accepted_socket(AcceptedTransport::ByteStream {
                socket: MockTcpSocket {
                    stream,
                    local_addr: "127.0.0.1:21002".parse()?,
                    peer_addr: "127.0.0.1:31002".parse()?,
                },
                local_url: "external://local".parse()?,
                remote_url: Some("external://remote".parse()?),
            })
            .await?;
        assert_eq!(protocol.byte_stream_calls.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_handler.calls.load(Ordering::Relaxed), 4);

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
                local_url: "unix:///tmp/easytier.sock".parse()?,
                remote_url: Some("unix://anonymous/remote".parse()?),
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
        let service = CoreListenerRuntime::new_with_events(
            host.clone(),
            Arc::new(MockDns),
            Arc::new(RingTunnelRegistry::default()),
            vec![
                TransportListenerConfig::Tcp {
                    url: "tcp://127.0.0.1:0".parse().unwrap(),
                    options: TcpListenOptions::manual_connect("127.0.0.1:0".parse().unwrap()),
                    max_pending_upgrades: None,
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
            Vec::new(),
            Vec::new(),
            handler,
            Arc::new(RecordingListenerEvents::default()),
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
                crate::foundation::time::timeout(Duration::from_secs(1), event_rx.recv())
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

        crate::foundation::time::timeout(Duration::from_secs(1), service.stop())
            .await
            .expect("transport listener service did not stop");
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn runtime_publishes_plan_failures_before_starting_listeners() {
        let events = Arc::new(RecordingListenerEvents::default());
        let service = CoreListenerRuntime::new_with_events(
            Arc::new(MockHost::new()),
            Arc::new(MockDns),
            Arc::new(RingTunnelRegistry::default()),
            Vec::new(),
            Vec::new(),
            vec![ListenerPlanFailure {
                url: "unsupported://listener".parse().unwrap(),
                message: "unsupported listener".to_owned(),
            }],
            Arc::new(|_: AcceptedTransport<MockTcpSocket>| async { Ok(()) }),
            events.clone(),
        );

        service.start().await.unwrap();
        assert!(matches!(
            events.events.lock().unwrap().as_slice(),
            [ListenerEvent::ListenerPlanFailed { url, error }]
                if url.as_str() == "unsupported://listener"
                    && error == "unsupported listener"
        ));
        service.stop().await;
    }
}
