use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use easytier_core::{
    connectivity::protocol::{ServerProtocolAdmission, ServerProtocolAdmissionController},
    instance::ListenerService,
    listener::{
        self as core_listener, plan as core_listener_plan,
        transport::{AcceptedTransport, AcceptedTunnelHandler, ProtocolAcceptedTransportHandler},
    },
    peers::peer_manager::PeerManagerCore,
    socket::{
        tcp::TcpSocketListener,
        udp::{UdpSession, UdpSessionAcceptKind, UdpSessionSocket, UdpSessionSocketListener},
    },
    tunnel::ring::RingTunnelRegistry,
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

#[cfg(feature = "faketcp")]
use crate::tunnel::TunnelListener;
use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    tunnel::{
        self, FromUrl, IpVersion, Tunnel,
        tcp::resolve_tcp_bind_url_addr,
        tcp_socket::{RuntimeTcpListenerFactory, RuntimeTcpSocket},
        udp::{RuntimeUdpSessionControlHandler, RuntimeUdpSocketFactory},
    },
};

pub use easytier_core::listener::plan::{is_url_host_ipv6, is_url_host_unspecified};

fn listener_scheme_registry() -> core_listener_plan::ListenerSchemeRegistry {
    let mut registry = core_listener_plan::ListenerSchemeRegistry::new()
        .support("tcp", core_listener_plan::ListenerKind::TcpStream)
        .support("udp", core_listener_plan::ListenerKind::UdpSession);

    #[cfg(feature = "wireguard")]
    {
        registry = registry.support("wg", core_listener_plan::ListenerKind::UdpSession);
    }
    #[cfg(feature = "quic")]
    {
        registry = registry
            .support("quic", core_listener_plan::ListenerKind::UdpSession)
            .disable_ipv6_shadow("quic");
    }
    #[cfg(feature = "websocket")]
    {
        registry = registry
            .support("ws", core_listener_plan::ListenerKind::TcpStream)
            .support("wss", core_listener_plan::ListenerKind::TcpStream);
    }
    #[cfg(feature = "faketcp")]
    {
        registry = registry
            .support("faketcp", core_listener_plan::ListenerKind::TcpStream)
            .disable_ipv6_shadow("faketcp");
    }
    #[cfg(unix)]
    {
        registry = registry.support("unix", core_listener_plan::ListenerKind::External);
    }

    registry
}

enum AcceptedConnection {
    ByteStream {
        stream: RuntimeTcpSocket,
        local_url: url::Url,
        remote_url: Option<url::Url>,
    },
    TcpStream {
        stream: RuntimeTcpSocket,
        local_url: url::Url,
        upgrade_permit: Option<OwnedSemaphorePermit>,
    },
    UdpSession {
        session: UdpSession,
        local_url: url::Url,
        admission: Option<ServerProtocolAdmission>,
    },
}

pub struct ListenerManager<H> {
    global_ctx: ArcGlobalCtx,
    net_ns: NetNS,
    ring_registry: Arc<RingTunnelRegistry>,
    listener_manager:
        core_listener::ListenerManager<AcceptedConnection, EasyTierAcceptedHandler<H>>,
}

impl<H: AcceptedTunnelHandler> ListenerManager<H> {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<H>) -> Self {
        Self::new_with_ring_registry(
            global_ctx,
            peer_manager,
            tunnel::ring::runtime_ring_registry(),
        )
    }

    pub(crate) fn new_with_ring_registry(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<H>,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        let protocol =
            crate::connector::protocol::runtime_server_protocol_upgrader(global_ctx.clone());
        let tunnel_handler = Arc::new(RuntimeAcceptedTunnelHandler {
            global_ctx: global_ctx.clone(),
            inner: Arc::downgrade(&peer_manager),
        });
        let protocol = ProtocolAcceptedTransportHandler::new(&tunnel_handler, protocol);
        let handler = Arc::new(EasyTierAcceptedHandler {
            _tunnel_handler: tunnel_handler,
            protocol,
        });
        let events = Arc::new(GlobalCtxListenerEventSink {
            global_ctx: global_ctx.clone(),
        });
        Self {
            global_ctx: global_ctx.clone(),
            net_ns: global_ctx.net_ns.clone(),
            ring_registry,
            listener_manager: core_listener::ListenerManager::new_with_events(handler, events),
        }
    }

    pub async fn prepare_listeners(&mut self) -> Result<(), Error> {
        let plan = core_listener_plan::plan_listeners(
            core_listener_plan::ListenerPlanRequest::new(
                self.global_ctx.get_id(),
                self.global_ctx.config.get_listener_uris(),
                self.global_ctx.config.get_flags().enable_ipv6,
            ),
            &listener_scheme_registry(),
        );

        for failure in plan.failures {
            self.global_ctx
                .issue_event(GlobalCtxEvent::ListenerAddFailed(
                    failure.url,
                    failure.message,
                ));
        }

        for listener in plan.listeners {
            self.add_planned_listener(listener).await?;
        }

        Ok(())
    }

    async fn add_planned_listener(
        &mut self,
        listener: core_listener_plan::PlannedListener,
    ) -> Result<(), Error> {
        match listener.kind {
            core_listener_plan::ListenerKind::Ring => {
                let url = listener.url;
                let ring_registry = self.ring_registry.clone();
                self.listener_manager.add_listener(
                    move || {
                        Box::new(RuntimeRingStreamListener::new(
                            url.clone(),
                            ring_registry.clone(),
                        ))
                    },
                    listener.must_succeed,
                );
                Ok(())
            }
            core_listener_plan::ListenerKind::UdpSession => {
                self.add_udp_listener(listener.url, listener.must_succeed)
                    .await
            }
            core_listener_plan::ListenerKind::TcpStream => {
                self.add_tcp_listener(listener.url, listener.must_succeed)
                    .await
            }
            core_listener_plan::ListenerKind::External => {
                #[cfg(unix)]
                if listener.url.scheme() == "unix" {
                    let url = listener.url;
                    self.listener_manager.add_listener(
                        move || Box::new(RuntimeUnixStreamListener::new(url.clone())),
                        listener.must_succeed,
                    );
                    return Ok(());
                }
                let message = format!(
                    "failed to get listener by url: {}, maybe not supported",
                    listener.url
                );
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAddFailed(listener.url, message));
                Ok(())
            }
        }
    }

    pub async fn add_tcp_listener(
        &mut self,
        listener: url::Url,
        must_succeed: bool,
    ) -> Result<(), Error> {
        use crate::common::config::ConfigLoader;

        #[cfg(feature = "faketcp")]
        if listener.scheme() == "faketcp" {
            let net_ns = self.net_ns.clone();
            self.listener_manager.add_listener(
                move || {
                    Box::new(RuntimeFakeTcpSocketListener::new(
                        listener.clone(),
                        net_ns.clone(),
                    ))
                },
                must_succeed,
            );
            return Ok(());
        }

        let socket_mark = self.global_ctx.config.get_flags().socket_mark;
        let factory = Arc::new(RuntimeTcpListenerFactory::new(self.net_ns.clone()));
        let net_ns = self.net_ns.clone();
        self.listener_manager.add_listener(
            move || {
                Box::new(RuntimeTcpSocketListener::new(
                    listener.clone(),
                    net_ns.clone(),
                    factory.clone(),
                    socket_mark,
                ))
            },
            must_succeed,
        );
        Ok(())
    }

    pub async fn add_udp_listener(
        &mut self,
        listener: url::Url,
        must_succeed: bool,
    ) -> Result<(), Error> {
        use crate::common::config::ConfigLoader;

        let socket_mark = self.global_ctx.config.get_flags().socket_mark;
        let factory = Arc::new(
            RuntimeUdpSocketFactory::new(self.net_ns.clone()).with_socket_mark(socket_mark),
        );
        let control_handler = Arc::new(RuntimeUdpSessionControlHandler);
        let net_ns = self.net_ns.clone();
        let accept_kind = match listener.scheme() {
            "udp" => UdpSessionAcceptKind::EasyTierMux,
            #[cfg(feature = "wireguard")]
            "wg" => UdpSessionAcceptKind::Classified(
                easytier_core::socket::udp::UdpSessionProtocol::WireGuard,
            ),
            #[cfg(feature = "quic")]
            "quic" => UdpSessionAcceptKind::Classified(
                easytier_core::socket::udp::UdpSessionProtocol::Quic,
            ),
            scheme => {
                return Err(Error::InvalidUrl(format!(
                    "unsupported UDP listener: {scheme}"
                )));
            }
        };
        self.listener_manager.add_listener(
            move || {
                Box::new(RuntimeUdpSessionSocketListener::new(
                    listener.clone(),
                    net_ns.clone(),
                    accept_kind,
                    factory.clone(),
                    control_handler.clone(),
                    socket_mark,
                ))
            },
            must_succeed,
        );
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.listener_manager.run().await.map_err(Into::into)
    }

    pub async fn stop(&self) {
        self.listener_manager.stop().await;
    }
}

pub(crate) struct RuntimeListenerService {
    manager: Mutex<ListenerManager<PeerManagerCore>>,
}

impl RuntimeListenerService {
    pub(crate) fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManagerCore>,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        Self {
            manager: Mutex::new(ListenerManager::new_with_ring_registry(
                global_ctx,
                peer_manager,
                ring_registry,
            )),
        }
    }
}

#[async_trait]
impl ListenerService for RuntimeListenerService {
    async fn start(&self) -> anyhow::Result<()> {
        let mut manager = self.manager.lock().await;
        manager.prepare_listeners().await?;
        manager.run().await?;
        Ok(())
    }

    async fn stop(&self) {
        self.manager.lock().await.stop().await;
    }
}

type EasyTierTcpSocketListener = TcpSocketListener<RuntimeTcpListenerFactory>;

struct RuntimeRingStreamListener {
    url: url::Url,
    ring_registry: Arc<RingTunnelRegistry>,
    inner: Option<easytier_core::tunnel::ring::RingTunnelSocketListener>,
}

impl RuntimeRingStreamListener {
    fn new(url: url::Url, ring_registry: Arc<RingTunnelRegistry>) -> Self {
        Self {
            url,
            ring_registry,
            inner: None,
        }
    }
}

impl Debug for RuntimeRingStreamListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeRingStreamListener")
            .field("url", &self.url)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[async_trait]
impl core_listener::SocketListener for RuntimeRingStreamListener {
    type Accepted = AcceptedConnection;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_some() {
            return Ok(());
        }
        let local_id = uuid::Uuid::from_url(self.url.clone(), IpVersion::Both).await?;
        self.inner = Some(self.ring_registry.bind(local_id)?);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let accepted = self
            .inner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("ring stream listener is not started"))?
            .accept()
            .await?;
        Ok(AcceptedConnection::ByteStream {
            stream: RuntimeTcpSocket::from_ring(accepted.socket)?,
            local_url: format!("ring://{}", accepted.local_id).parse()?,
            remote_url: Some(format!("ring://{}", accepted.remote_id).parse()?),
        })
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
    }

    fn connection_counter(&self) -> Arc<dyn core_listener::ListenerConnectionCounter> {
        Arc::new(ZeroConnectionCounter)
    }
}

#[cfg(unix)]
struct RuntimeUnixStreamListener {
    url: url::Url,
    inner: Option<tokio::net::UnixListener>,
}

#[cfg(unix)]
impl RuntimeUnixStreamListener {
    fn new(url: url::Url) -> Self {
        Self { url, inner: None }
    }
}

#[cfg(unix)]
fn unix_stream_remote_url(remote_addr: tokio::net::unix::SocketAddr) -> url::Url {
    crate::tunnel::unix::url_from_unix_socket_addr(remote_addr).unwrap_or_else(|| {
        format!("unix://anonymous/{}", uuid::Uuid::new_v4())
            .parse()
            .expect("synthetic Unix stream URL should be valid")
    })
}

#[cfg(unix)]
impl Debug for RuntimeUnixStreamListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeUnixStreamListener")
            .field("url", &self.url)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[cfg(unix)]
#[async_trait]
impl core_listener::SocketListener for RuntimeUnixStreamListener {
    type Accepted = AcceptedConnection;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_none() {
            self.inner = Some(tokio::net::UnixListener::bind(self.url.path())?);
        }
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let (stream, remote_addr) = self
            .inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Unix stream listener is not started"))?
            .accept()
            .await?;
        Ok(AcceptedConnection::ByteStream {
            stream: RuntimeTcpSocket::from_unix(stream),
            local_url: self.url.clone(),
            remote_url: Some(unix_stream_remote_url(remote_addr)),
        })
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
    }

    fn connection_counter(&self) -> Arc<dyn core_listener::ListenerConnectionCounter> {
        Arc::new(ZeroConnectionCounter)
    }
}

#[cfg(unix)]
impl Drop for RuntimeUnixStreamListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.url.path());
    }
}

struct RuntimeTcpSocketListener {
    url: url::Url,
    net_ns: NetNS,
    factory: Arc<RuntimeTcpListenerFactory>,
    socket_mark: Option<u32>,
    upgrade_slots: Option<Arc<Semaphore>>,
    inner: Option<EasyTierTcpSocketListener>,
}

impl RuntimeTcpSocketListener {
    fn new(
        url: url::Url,
        net_ns: NetNS,
        factory: Arc<RuntimeTcpListenerFactory>,
        socket_mark: Option<u32>,
    ) -> Self {
        let upgrade_slots = match url.scheme() {
            #[cfg(feature = "websocket")]
            "ws" | "wss" => Some(Arc::new(Semaphore::new(1))),
            _ => None,
        };
        Self {
            url,
            net_ns,
            factory,
            socket_mark,
            upgrade_slots,
            inner: None,
        }
    }

    fn inner(&mut self) -> anyhow::Result<&mut EasyTierTcpSocketListener> {
        self.inner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime tcp socket listener is not started"))
    }
}

impl Debug for RuntimeTcpSocketListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self
            .inner
            .as_ref()
            .map(core_listener::SocketListener::local_url)
            .unwrap_or_else(|| self.url.clone());
        f.debug_struct("RuntimeTcpSocketListener")
            .field("url", &url)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[async_trait]
impl core_listener::SocketListener for RuntimeTcpSocketListener {
    type Accepted = AcceptedConnection;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_some() {
            return Ok(());
        }

        let local_addr = {
            let _guard = self.net_ns.guard();
            resolve_tcp_bind_url_addr(&self.url, IpVersion::Both, self.socket_mark).await?
        };
        let options = core_listener_plan::tcp_listener_options(local_addr, self.socket_mark);
        let mut inner =
            TcpSocketListener::new_with_options(self.url.clone(), options, self.factory.clone());
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
        Ok(AcceptedConnection::TcpStream {
            stream: self.inner()?.accept().await?,
            local_url,
            upgrade_permit,
        })
    }

    fn local_url(&self) -> url::Url {
        self.inner
            .as_ref()
            .map(core_listener::SocketListener::local_url)
            .unwrap_or_else(|| self.url.clone())
    }

    fn connection_counter(&self) -> Arc<dyn core_listener::ListenerConnectionCounter> {
        self.inner
            .as_ref()
            .map(core_listener::SocketListener::connection_counter)
            .unwrap_or_else(|| Arc::new(ZeroConnectionCounter))
    }
}

type EasyTierUdpSessionSocketListener =
    UdpSessionSocketListener<RuntimeUdpSocketFactory, RuntimeUdpSessionControlHandler>;

#[cfg(feature = "faketcp")]
struct RuntimeFakeTcpSocketListener {
    net_ns: NetNS,
    inner: tunnel::fake_tcp::FakeTcpTunnelListener,
}

#[cfg(feature = "faketcp")]
impl RuntimeFakeTcpSocketListener {
    fn new(url: url::Url, net_ns: NetNS) -> Self {
        Self {
            net_ns,
            inner: tunnel::fake_tcp::FakeTcpTunnelListener::new(url),
        }
    }
}

#[cfg(feature = "faketcp")]
impl Debug for RuntimeFakeTcpSocketListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeFakeTcpSocketListener")
            .field("url", &self.inner.local_url())
            .finish()
    }
}

#[cfg(feature = "faketcp")]
#[async_trait]
impl core_listener::SocketListener for RuntimeFakeTcpSocketListener {
    type Accepted = AcceptedConnection;

    async fn listen(&mut self) -> anyhow::Result<()> {
        let _guard = self.net_ns.guard();
        self.inner.listen().await?;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = self.inner.local_url();
        let socket = self.inner.accept_socket().await?;
        Ok(AcceptedConnection::TcpStream {
            stream: RuntimeTcpSocket::from_fake_tcp(socket),
            local_url,
            upgrade_permit: None,
        })
    }

    fn local_url(&self) -> url::Url {
        self.inner.local_url()
    }

    fn connection_counter(&self) -> Arc<dyn core_listener::ListenerConnectionCounter> {
        Arc::new(ZeroConnectionCounter)
    }
}

struct RuntimeUdpSessionSocketListener {
    url: url::Url,
    net_ns: NetNS,
    accept_kind: UdpSessionAcceptKind,
    factory: Arc<RuntimeUdpSocketFactory>,
    control_handler: Arc<RuntimeUdpSessionControlHandler>,
    socket_mark: Option<u32>,
    protocol_admission: Option<ServerProtocolAdmissionController>,
    inner: Option<EasyTierUdpSessionSocketListener>,
}

impl RuntimeUdpSessionSocketListener {
    fn new(
        url: url::Url,
        net_ns: NetNS,
        accept_kind: UdpSessionAcceptKind,
        factory: Arc<RuntimeUdpSocketFactory>,
        control_handler: Arc<RuntimeUdpSessionControlHandler>,
        socket_mark: Option<u32>,
    ) -> Self {
        let protocol_admission = matches!(
            accept_kind,
            UdpSessionAcceptKind::Classified(easytier_core::socket::udp::UdpSessionProtocol::Quic)
        )
        .then(ServerProtocolAdmissionController::quic);
        Self {
            url,
            net_ns,
            accept_kind,
            factory,
            control_handler,
            socket_mark,
            protocol_admission,
            inner: None,
        }
    }

    fn inner(&mut self) -> anyhow::Result<&mut EasyTierUdpSessionSocketListener> {
        self.inner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime udp session listener is not started"))
    }
}

impl Debug for RuntimeUdpSessionSocketListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self
            .inner
            .as_ref()
            .map(core_listener::SocketListener::local_url)
            .unwrap_or_else(|| self.url.clone());
        f.debug_struct("RuntimeUdpSessionSocketListener")
            .field("url", &url)
            .field("accept_kind", &self.accept_kind)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[async_trait]
impl core_listener::SocketListener for RuntimeUdpSessionSocketListener {
    type Accepted = AcceptedConnection;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_some() {
            return Ok(());
        }

        let socket_addr = {
            let _guard = self.net_ns.guard();
            SocketAddr::from_url(self.url.clone(), IpVersion::Both).await?
        };
        let request = core_listener_plan::udp_session_listen_request(
            &self.url,
            socket_addr,
            self.socket_mark,
        );
        let mut inner = UdpSessionSocketListener::new_with_request(
            self.url.clone(),
            request,
            self.accept_kind,
            self.factory.clone(),
            self.control_handler.clone(),
        );
        inner.listen().await?;
        self.inner = Some(inner);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        loop {
            let local_url = self.local_url();
            let session = self.inner()?.accept().await?;
            let admission = match &self.protocol_admission {
                Some(controller) => match controller.try_admit() {
                    Some(admission) => Some(admission),
                    None => {
                        tracing::debug!(
                            peer_addr = ?session.peer_addr(),
                            "drop QUIC UDP session after active session limit"
                        );
                        continue;
                    }
                },
                None => None,
            };
            return Ok(AcceptedConnection::UdpSession {
                session,
                local_url,
                admission,
            });
        }
    }

    fn local_url(&self) -> url::Url {
        self.inner
            .as_ref()
            .map(core_listener::SocketListener::local_url)
            .unwrap_or_else(|| self.url.clone())
    }

    fn connection_counter(&self) -> Arc<dyn core_listener::ListenerConnectionCounter> {
        self.inner
            .as_ref()
            .map(core_listener::SocketListener::connection_counter)
            .unwrap_or_else(|| Arc::new(ZeroConnectionCounter))
    }
}

#[derive(Debug)]
struct ZeroConnectionCounter;

impl core_listener::ListenerConnectionCounter for ZeroConnectionCounter {
    fn get(&self) -> Option<u32> {
        Some(0)
    }
}

#[derive(Debug)]
struct GlobalCtxListenerEventSink {
    global_ctx: ArcGlobalCtx,
}

impl core_listener::ListenerEventSink for GlobalCtxListenerEventSink {
    fn emit(&self, event: core_listener::ListenerEvent) {
        match event {
            core_listener::ListenerEvent::ListenerAdded { url, .. } => {
                self.global_ctx.add_running_listener(url.clone());
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAdded(url));
            }
            core_listener::ListenerEvent::ListenerRemoved { .. } => {}
            core_listener::ListenerEvent::ListenerAddFailed {
                url,
                error,
                will_retry,
                ..
            } => {
                let message = if will_retry {
                    format!("error: {error}, retry listen later...")
                } else {
                    format!("error: {error}")
                };
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAddFailed(url, message));
            }
            core_listener::ListenerEvent::ListenerAcceptFailed { url, error } => {
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAcceptFailed(
                        url,
                        format!("error: {error}, retry listen later..."),
                    ));
            }
            core_listener::ListenerEvent::SocketAccepted { .. } => {}
            core_listener::ListenerEvent::AcceptedSocketHandleFailed { url, error } => {
                tracing::error!(%url, %error, "accepted socket handler failed");
            }
        }
    }
}

struct RuntimeAcceptedTunnelHandler<H> {
    global_ctx: ArcGlobalCtx,
    inner: Weak<H>,
}

impl<H> Debug for RuntimeAcceptedTunnelHandler<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeAcceptedTunnelHandler")
            .field("inner_available", &self.inner.strong_count())
            .finish()
    }
}

#[async_trait]
impl<H> AcceptedTunnelHandler for RuntimeAcceptedTunnelHandler<H>
where
    H: AcceptedTunnelHandler,
{
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        let tunnel_info = tunnel
            .info()
            .ok_or_else(|| anyhow::anyhow!("accepted tunnel has no tunnel info"))?;
        let local_url = tunnel_info
            .local_addr
            .clone()
            .unwrap_or_default()
            .to_string();
        let remote_url = tunnel_info
            .remote_addr
            .clone()
            .unwrap_or_default()
            .to_string();
        self.global_ctx
            .issue_event(GlobalCtxEvent::ConnectionAccepted(
                local_url.clone(),
                remote_url.clone(),
            ));
        tracing::info!(ret = ?tunnel, "conn accepted");

        let Some(inner) = self.inner.upgrade() else {
            let error = "peer manager is gone, cannot handle tunnel".to_owned();
            self.global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                local_url,
                remote_url,
                error.clone(),
            ));
            tracing::error!(error = %error, "handle conn error");
            return Err(anyhow::anyhow!(error));
        };
        if let Err(error) = inner.handle_tunnel(tunnel).await {
            self.global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                local_url,
                remote_url,
                error.to_string(),
            ));
            tracing::error!(?error, "handle conn error");
            return Err(error);
        }
        Ok(())
    }
}

struct EasyTierAcceptedHandler<H> {
    _tunnel_handler: Arc<RuntimeAcceptedTunnelHandler<H>>,
    protocol: ProtocolAcceptedTransportHandler<RuntimeTcpSocket, RuntimeAcceptedTunnelHandler<H>>,
}

impl<H> Debug for EasyTierAcceptedHandler<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTierAcceptedHandler").finish()
    }
}

#[async_trait]
impl<H> core_listener::AcceptedSocketHandler<AcceptedConnection> for EasyTierAcceptedHandler<H>
where
    H: AcceptedTunnelHandler,
{
    async fn handle_accepted_socket(&self, accepted: AcceptedConnection) -> anyhow::Result<()> {
        let transport = match accepted {
            AcceptedConnection::ByteStream {
                stream,
                local_url,
                remote_url,
            } => AcceptedTransport::ByteStream {
                socket: stream,
                local_url,
                remote_url,
            },
            AcceptedConnection::TcpStream {
                stream,
                local_url,
                upgrade_permit,
            } => {
                let _upgrade_permit = upgrade_permit;
                return self
                    .protocol
                    .handle_accepted_socket(AcceptedTransport::Tcp {
                        socket: stream,
                        local_url,
                    })
                    .await;
            }
            AcceptedConnection::UdpSession {
                session,
                local_url,
                admission,
            } => AcceptedTransport::Udp {
                session,
                local_url,
                admission,
            },
        };
        self.protocol.handle_accepted_socket(transport).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI32, Ordering};

    use easytier_core::connectivity::{manual::ManualConnectorHost, protocol::raw};
    use futures::{SinkExt, StreamExt};
    use tokio::time::timeout;

    use crate::{
        common::config::ConfigLoader,
        common::global_ctx::tests::get_mock_global_ctx,
        connector::runtime::RuntimeConnectorHost,
        tunnel::{TunnelConnector, TunnelError, packet_def::ZCPacket, tcp::TcpTunnelConnector},
    };

    use super::*;

    #[derive(Debug)]
    struct MockListenerHandler {}

    #[async_trait]
    impl AcceptedTunnelHandler for MockListenerHandler {
        async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            let data = "abc";
            let (_recv, mut send) = tunnel.split();

            let zc_packet = ZCPacket::new_with_payload(data.as_bytes());
            send.send(zc_packet).await.unwrap();
            Err(Error::Unknown.into())
        }
    }

    #[derive(Debug)]
    struct EchoListenerHandler;

    #[async_trait]
    impl AcceptedTunnelHandler for EchoListenerHandler {
        async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            let (mut recv, mut send) = tunnel.split();
            while let Some(packet) = recv.next().await {
                send.send(packet?).await?;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn ring_connector_and_listener_use_injected_registry() {
        let global_ctx = get_mock_global_ctx();
        let shared_registry = Arc::new(RingTunnelRegistry::default());
        let isolated_registry = Arc::new(RingTunnelRegistry::default());
        let listener_url: url::Url = format!("ring://{}", uuid::Uuid::new_v4()).parse().unwrap();
        let mut listener =
            RuntimeRingStreamListener::new(listener_url.clone(), shared_registry.clone());
        core_listener::SocketListener::listen(&mut listener)
            .await
            .unwrap();

        let isolated_host =
            RuntimeConnectorHost::new_with_ring_registry(global_ctx.clone(), isolated_registry);
        assert!(
            ManualConnectorHost::connect_byte_stream(&isolated_host, &listener_url)
                .await
                .is_err()
        );

        let shared_host = RuntimeConnectorHost::new_with_ring_registry(global_ctx, shared_registry);
        ManualConnectorHost::connect_byte_stream(&shared_host, &listener_url)
            .await
            .unwrap();
        assert!(matches!(
            core_listener::SocketListener::accept(&mut listener)
                .await
                .unwrap(),
            AcceptedConnection::ByteStream { .. }
        ));
    }

    #[tokio::test]
    async fn prepare_udp_listeners_registers_core_listener_manager() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec!["udp://127.0.0.1:0".parse().unwrap()]);
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(global_ctx, handler);

        listener_mgr.prepare_listeners().await.unwrap();

        assert_eq!(listener_mgr.listener_manager.listener_count(), 2);
    }

    #[test]
    fn listener_scheme_registry_classifies_tcp_as_tcp_stream() {
        let url = "tcp://127.0.0.1:0".parse().unwrap();

        assert_eq!(
            listener_scheme_registry().classify(&url),
            Some(core_listener_plan::ListenerKind::TcpStream)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unnamed_unix_stream_peers_receive_unique_synthetic_urls() {
        let (first, _) = tokio::net::UnixStream::pair().unwrap();
        let first_addr = first.peer_addr().unwrap();
        let (second, _) = tokio::net::UnixStream::pair().unwrap();
        let second_addr = second.peer_addr().unwrap();

        let first_url = unix_stream_remote_url(first_addr);
        let second_url = unix_stream_remote_url(second_addr);
        assert_eq!(first_url.host_str(), Some("anonymous"));
        assert_eq!(second_url.host_str(), Some("anonymous"));
        assert_ne!(first_url, second_url);
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn listener_scheme_registry_classifies_websocket_as_tcp_stream() {
        for url in ["ws://127.0.0.1:0", "wss://127.0.0.1:0"] {
            assert_eq!(
                listener_scheme_registry().classify(&url.parse().unwrap()),
                Some(core_listener_plan::ListenerKind::TcpStream)
            );
        }
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn websocket_listener_allows_only_one_pending_upgrade() {
        let global_ctx = get_mock_global_ctx();
        let factory = Arc::new(RuntimeTcpListenerFactory::new(global_ctx.net_ns.clone()));
        let mut listener = RuntimeTcpSocketListener::new(
            "ws://127.0.0.1:0".parse().unwrap(),
            global_ctx.net_ns.clone(),
            factory,
            None,
        );
        core_listener::SocketListener::listen(&mut listener)
            .await
            .unwrap();
        let addr = SocketAddr::from_url(
            core_listener::SocketListener::local_url(&listener),
            IpVersion::Both,
        )
        .await
        .unwrap();

        let _first_client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let first = core_listener::SocketListener::accept(&mut listener)
            .await
            .unwrap();
        let _second_client = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            timeout(
                std::time::Duration::from_millis(50),
                core_listener::SocketListener::accept(&mut listener),
            )
            .await
            .is_err()
        );

        drop(first);
        timeout(
            std::time::Duration::from_secs(1),
            core_listener::SocketListener::accept(&mut listener),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[cfg(feature = "wireguard")]
    #[test]
    fn listener_scheme_registry_classifies_wireguard_as_udp_session() {
        let url = "wg://127.0.0.1:0".parse().unwrap();
        assert_eq!(
            listener_scheme_registry().classify(&url),
            Some(core_listener_plan::ListenerKind::UdpSession)
        );
    }

    #[cfg(feature = "quic")]
    #[test]
    fn listener_scheme_registry_classifies_quic_as_udp_session() {
        let url = "quic://127.0.0.1:0".parse().unwrap();
        assert_eq!(
            listener_scheme_registry().classify(&url),
            Some(core_listener_plan::ListenerKind::UdpSession)
        );
    }

    #[cfg(feature = "faketcp")]
    #[test]
    fn listener_scheme_registry_classifies_faketcp_as_tcp_stream() {
        let url = "faketcp://127.0.0.1:11013".parse().unwrap();
        assert_eq!(
            listener_scheme_registry().classify(&url),
            Some(core_listener_plan::ListenerKind::TcpStream)
        );
    }

    #[tokio::test]
    async fn prepare_tcp_listeners_registers_core_listener_manager() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec!["tcp://127.0.0.1:0".parse().unwrap()]);
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(global_ctx, handler);

        listener_mgr.prepare_listeners().await.unwrap();

        assert_eq!(listener_mgr.listener_manager.listener_count(), 2);
    }

    #[tokio::test]
    async fn tcp_listener_accepts_through_core_socket_listener() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec!["tcp://127.0.0.1:0".parse().unwrap()]);
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(global_ctx.clone(), handler.clone());

        listener_mgr.prepare_listeners().await.unwrap();
        listener_mgr.run().await.unwrap();

        let listener_url = timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(url) = global_ctx
                    .get_running_listeners()
                    .into_iter()
                    .find(|url| url.scheme() == "tcp")
                {
                    break url;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let tunnel = TcpTunnelConnector::new(listener_url)
            .connect()
            .await
            .unwrap();
        let (mut recv, _send) = tunnel.split();
        assert_eq!(
            recv.next().await.unwrap().unwrap().payload(),
            "abc".as_bytes()
        );
    }

    #[cfg(feature = "websocket")]
    #[rstest::rstest]
    #[tokio::test]
    async fn websocket_listener_accepts_through_core_socket_listener(
        #[values("ws", "wss")] protocol: &str,
    ) {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec![format!("{protocol}://127.0.0.1:0").parse().unwrap()]);
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(global_ctx.clone(), handler.clone());

        listener_mgr.prepare_listeners().await.unwrap();
        listener_mgr.run().await.unwrap();

        let listener_url = timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(url) = global_ctx
                    .get_running_listeners()
                    .into_iter()
                    .find(|url| url.scheme() == protocol)
                {
                    break url;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let tunnel = tunnel::websocket::WsTunnelConnector::new(listener_url)
            .connect()
            .await
            .unwrap();
        let (mut recv, _send) = tunnel.split();
        assert_eq!(
            recv.next().await.unwrap().unwrap().payload(),
            "abc".as_bytes()
        );
    }

    #[cfg(feature = "wireguard")]
    #[tokio::test]
    async fn wireguard_listener_accepts_through_core_session_listener() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec!["wg://127.0.0.1:0".parse().unwrap()]);
        let handler = Arc::new(EchoListenerHandler);
        let mut listener_mgr = ListenerManager::new(global_ctx.clone(), handler.clone());

        listener_mgr.prepare_listeners().await.unwrap();
        listener_mgr.run().await.unwrap();

        let listener_url = timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(url) = global_ctx
                    .get_running_listeners()
                    .into_iter()
                    .find(|url| url.scheme() == "wg")
                {
                    break url;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let identity = global_ctx.get_network_identity();
        let config = tunnel::wireguard::WgConfig::new_from_network_identity(
            &identity.network_name,
            &identity.network_secret.unwrap_or_default(),
        );
        let tunnel = timeout(
            std::time::Duration::from_secs(5),
            tunnel::wireguard::WgTunnelConnector::new(listener_url, config).connect(),
        )
        .await
        .unwrap()
        .unwrap();
        let (mut recv, mut send) = tunnel.split();
        send.send(ZCPacket::new_with_payload("abc".as_bytes()))
            .await
            .unwrap();
        assert_eq!(
            recv.next().await.unwrap().unwrap().payload(),
            "abc".as_bytes()
        );
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn quic_listener_accepts_through_core_session_listener() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec!["quic://127.0.0.1:0".parse().unwrap()]);
        let handler = Arc::new(EchoListenerHandler);
        let mut listener_mgr = ListenerManager::new(global_ctx.clone(), handler.clone());

        listener_mgr.prepare_listeners().await.unwrap();
        listener_mgr.run().await.unwrap();

        let listener_url = timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(url) = global_ctx
                    .get_running_listeners()
                    .into_iter()
                    .find(|url| url.scheme() == "quic")
                {
                    break url;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let mut tunnels = Vec::new();
        for _ in 0..2 {
            tunnels.push(
                timeout(
                    std::time::Duration::from_secs(5),
                    tunnel::quic::QuicTunnelConnector::new(
                        listener_url.clone(),
                        global_ctx.clone(),
                    )
                    .connect(),
                )
                .await
                .unwrap()
                .unwrap(),
            );
        }
        for tunnel in tunnels {
            let (mut recv, mut send) = tunnel.split();
            send.send(ZCPacket::new_with_payload("abc".as_bytes()))
                .await
                .unwrap();
            assert_eq!(
                recv.next().await.unwrap().unwrap().payload(),
                "abc".as_bytes()
            );
        }
    }

    #[cfg(feature = "faketcp")]
    #[tokio::test]
    async fn faketcp_listener_accepts_through_core_socket_listener() {
        #[cfg(target_family = "unix")]
        if unsafe { nix::libc::geteuid() } != 0 {
            return;
        }

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec![format!("faketcp://127.0.0.1:{port}").parse().unwrap()]);
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(global_ctx.clone(), handler.clone());

        listener_mgr.prepare_listeners().await.unwrap();
        listener_mgr.run().await.unwrap();

        let listener_url = timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(url) = global_ctx
                    .get_running_listeners()
                    .into_iter()
                    .find(|url| url.scheme() == "faketcp")
                {
                    break url;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let tunnel = tunnel::fake_tcp::FakeTcpTunnelConnector::new(listener_url)
            .connect()
            .await
            .unwrap();
        let (mut recv, _send) = tunnel.split();
        assert_eq!(
            recv.next().await.unwrap().unwrap().payload(),
            "abc".as_bytes()
        );
    }

    #[tokio::test]
    async fn handle_error_in_accept() {
        let handler = Arc::new(MockListenerHandler {});
        let global_ctx = get_mock_global_ctx();
        let ring_id = core_listener_plan::ring_listener_url(global_ctx.get_id());
        let mut listener_mgr = ListenerManager::new(global_ctx.clone(), handler.clone());
        listener_mgr.prepare_listeners().await.unwrap();
        listener_mgr.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let host = Arc::new(RuntimeConnectorHost::new(global_ctx));
        let connect_once = |ring_id| {
            let host = host.clone();
            async move {
                let connected = host.connect_byte_stream(&ring_id).await.unwrap();
                let tunnel = raw::upgrade_connected_byte_stream(connected).unwrap();
                let (mut recv, _send) = tunnel.split();
                assert_eq!(
                    recv.next().await.unwrap().unwrap().payload(),
                    "abc".as_bytes()
                );
                tunnel
            }
        };

        timeout(std::time::Duration::from_secs(1), async move {
            connect_once(ring_id.clone()).await;
            // handle tunnel fail should not impact the second connect
            connect_once(ring_id).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retry_listen() {
        let counter = Arc::new(AtomicI32::new(0));
        let drop_counter = Arc::new(AtomicI32::new(0));
        #[derive(Debug)]
        struct MockListener {
            counter: Arc<AtomicI32>,
            drop_counter: Arc<AtomicI32>,
        }

        #[async_trait::async_trait]
        impl core_listener::SocketListener for MockListener {
            type Accepted = AcceptedConnection;

            async fn listen(&mut self) -> anyhow::Result<()> {
                self.counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }

            async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Err(TunnelError::BufferFull.into())
            }

            fn local_url(&self) -> url::Url {
                "mock://".parse().unwrap()
            }
        }

        impl Drop for MockListener {
            fn drop(&mut self) {
                self.drop_counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(get_mock_global_ctx(), handler.clone());
        let counter_clone = counter.clone();
        let drop_counter_clone = drop_counter.clone();
        listener_mgr.listener_manager.add_listener(
            move || {
                Box::new(MockListener {
                    counter: counter_clone.clone(),
                    drop_counter: drop_counter_clone.clone(),
                })
            },
            true,
        );
        listener_mgr.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        assert!(counter.load(Ordering::Relaxed) >= 2);
        assert!(drop_counter.load(Ordering::Relaxed) >= 1);
    }
}
