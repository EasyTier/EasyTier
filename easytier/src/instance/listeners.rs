use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use easytier_core::{
    listener::{self as core_listener, plan as core_listener_plan},
    socket::udp::{UdpSession, UdpSessionAcceptKind, UdpSessionSocket, UdpSessionSocketListener},
    tunnel::udp::UdpTunnelUpgrader,
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    peers::peer_manager::PeerManager,
    tunnel::{
        self, FromUrl, IpScheme, IpVersion, Tunnel, TunnelConnCounter, TunnelInfo, TunnelListener,
        TunnelScheme, build_url_from_socket_addr,
        ring::RingTunnelListener,
        tcp::TcpTunnelListener,
        udp::{RuntimeUdpSessionControlHandler, RuntimeUdpSocketFactory, UdpTunnelListener},
    },
    utils::BoxExt,
};

pub use easytier_core::listener::plan::{is_url_host_ipv6, is_url_host_unspecified};

pub fn create_listener_by_url(
    l: &url::Url,
    global_ctx: ArcGlobalCtx,
) -> Result<Box<dyn TunnelListener>, Error> {
    use crate::common::config::ConfigLoader;
    let socket_mark = global_ctx.config.get_flags().socket_mark;
    Ok(match l.try_into()? {
        TunnelScheme::Ip(scheme) => match scheme {
            IpScheme::Tcp => {
                let mut l = TcpTunnelListener::new(l.clone());
                l.set_socket_mark(socket_mark);
                l.boxed()
            }
            IpScheme::Udp => {
                let mut l = UdpTunnelListener::new(l.clone());
                l.set_socket_mark(socket_mark);
                l.boxed()
            }
            #[cfg(feature = "wireguard")]
            IpScheme::Wg => {
                use crate::tunnel::wireguard::{WgConfig, WgTunnelListener};
                let nid = global_ctx.get_network_identity();
                let wg_config = WgConfig::new_from_network_identity(
                    &nid.network_name,
                    &nid.network_secret.unwrap_or_default(),
                );
                let mut l = WgTunnelListener::new(l.clone(), wg_config);
                l.set_socket_mark(socket_mark);
                l.boxed()
            }
            #[cfg(feature = "quic")]
            IpScheme::Quic => {
                // QUIC reads socket_mark from global_ctx in QuicEndpointManager
                tunnel::quic::QuicTunnelListener::new(l.clone(), global_ctx.clone()).boxed()
            }
            #[cfg(feature = "websocket")]
            IpScheme::Ws | IpScheme::Wss => {
                let mut l = tunnel::websocket::WsTunnelListener::new(l.clone());
                l.set_socket_mark(socket_mark);
                l.boxed()
            }
            #[cfg(feature = "faketcp")]
            IpScheme::FakeTcp => tunnel::fake_tcp::FakeTcpTunnelListener::new(l.clone()).boxed(),
        },
        #[cfg(unix)]
        TunnelScheme::Unix => tunnel::unix::UnixSocketTunnelListener::new(l.clone()).boxed(),
        _ => return Err(Error::InvalidUrl(l.to_string())),
    })
}

#[async_trait]
pub trait TunnelHandlerForListener {
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error>;
}

#[async_trait]
impl TunnelHandlerForListener for PeerManager {
    #[tracing::instrument]
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
        self.add_tunnel_as_server(tunnel, true).await
    }
}

pub trait ListenerCreatorTrait: Fn() -> Box<dyn TunnelListener> + Send + Sync {}
impl<T: Send + Sync> ListenerCreatorTrait for T where T: Fn() -> Box<dyn TunnelListener> + Send {}

fn listener_scheme_registry() -> core_listener_plan::ListenerSchemeRegistry {
    let mut registry = core_listener_plan::ListenerSchemeRegistry::new()
        .support("tcp", core_listener_plan::ListenerKind::External)
        .support("udp", core_listener_plan::ListenerKind::UdpSession);

    #[cfg(feature = "wireguard")]
    {
        registry = registry.support("wg", core_listener_plan::ListenerKind::External);
    }
    #[cfg(feature = "quic")]
    {
        registry = registry
            .support("quic", core_listener_plan::ListenerKind::External)
            .disable_ipv6_shadow("quic");
    }
    #[cfg(feature = "websocket")]
    {
        registry = registry
            .support("ws", core_listener_plan::ListenerKind::External)
            .support("wss", core_listener_plan::ListenerKind::External);
    }
    #[cfg(feature = "faketcp")]
    {
        registry = registry
            .support("faketcp", core_listener_plan::ListenerKind::External)
            .disable_ipv6_shadow("faketcp");
    }
    #[cfg(unix)]
    {
        registry = registry.support("unix", core_listener_plan::ListenerKind::External);
    }

    registry
}

enum AcceptedConnection {
    Tunnel(Box<dyn Tunnel>),
    UdpSession(UdpSession),
}

pub struct ListenerManager<H> {
    global_ctx: ArcGlobalCtx,
    net_ns: NetNS,
    listener_manager:
        core_listener::ListenerManager<AcceptedConnection, EasyTierAcceptedHandler<H>>,
}

impl<H: TunnelHandlerForListener + Send + Sync + 'static + Debug> ListenerManager<H> {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<H>) -> Self {
        let peer_manager = Arc::downgrade(&peer_manager);
        let handler = Arc::new(EasyTierAcceptedHandler {
            global_ctx: global_ctx.clone(),
            peer_manager: peer_manager.clone(),
        });
        let events = Arc::new(GlobalCtxListenerEventSink {
            global_ctx: global_ctx.clone(),
        });
        Self {
            global_ctx: global_ctx.clone(),
            net_ns: global_ctx.net_ns.clone(),
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
                self.add_listener(
                    move || Box::new(RingTunnelListener::new(url.clone())),
                    listener.must_succeed,
                )
                .await
            }
            core_listener_plan::ListenerKind::UdpSession => {
                self.add_udp_listener(listener.url, listener.must_succeed)
                    .await
            }
            core_listener_plan::ListenerKind::External => {
                self.add_external_listener(listener.url, listener.must_succeed)
                    .await
            }
        }
    }

    async fn add_external_listener(
        &mut self,
        listener: url::Url,
        must_succeed: bool,
    ) -> Result<(), Error> {
        let ctx = self.global_ctx.clone();
        if create_listener_by_url(&listener, ctx.clone()).is_err() {
            let msg = format!(
                "failed to get listener by url: {}, maybe not supported",
                listener
            );
            self.global_ctx
                .issue_event(GlobalCtxEvent::ListenerAddFailed(listener, msg));
            return Ok(());
        };

        self.add_listener(
            move || create_listener_by_url(&listener, ctx.clone()).unwrap(),
            must_succeed,
        )
        .await
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
        self.listener_manager.add_listener(
            move || {
                Box::new(RuntimeUdpSessionSocketListener::new(
                    listener.clone(),
                    net_ns.clone(),
                    UdpSessionAcceptKind::EasyTierMux,
                    factory.clone(),
                    control_handler.clone(),
                    socket_mark,
                ))
            },
            must_succeed,
        );
        Ok(())
    }

    pub async fn add_listener<C: ListenerCreatorTrait + 'static>(
        &mut self,
        creator: C,
        must_succ: bool,
    ) -> Result<(), Error> {
        let net_ns = self.net_ns.clone();
        self.listener_manager.add_listener(
            move || Box::new(TunnelListenerAdapter::new(net_ns.clone(), creator())),
            must_succ,
        );
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.listener_manager.run().await.map_err(Into::into)
    }
}

type EasyTierUdpSessionSocketListener =
    UdpSessionSocketListener<RuntimeUdpSocketFactory, RuntimeUdpSessionControlHandler>;

struct TunnelListenerAdapter {
    net_ns: NetNS,
    inner: Box<dyn TunnelListener>,
}

impl TunnelListenerAdapter {
    fn new(net_ns: NetNS, inner: Box<dyn TunnelListener>) -> Self {
        Self { net_ns, inner }
    }
}

impl Debug for TunnelListenerAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelListenerAdapter")
            .field("url", &self.inner.local_url())
            .finish()
    }
}

#[async_trait]
impl core_listener::SocketListener for TunnelListenerAdapter {
    type Accepted = AcceptedConnection;

    async fn listen(&mut self) -> anyhow::Result<()> {
        let _guard = self.net_ns.guard();
        self.inner.listen().await?;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(AcceptedConnection::Tunnel(self.inner.accept().await?))
    }

    fn local_url(&self) -> url::Url {
        self.inner.local_url()
    }

    fn connection_counter(&self) -> Arc<dyn core_listener::ListenerConnectionCounter> {
        Arc::new(TunnelConnectionCounterAdapter {
            inner: self.inner.get_conn_counter(),
        })
    }
}

struct TunnelConnectionCounterAdapter {
    inner: Arc<Box<dyn TunnelConnCounter>>,
}

impl Debug for TunnelConnectionCounterAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelConnectionCounterAdapter")
            .field("count", &self.inner.get())
            .finish()
    }
}

impl core_listener::ListenerConnectionCounter for TunnelConnectionCounterAdapter {
    fn get(&self) -> Option<u32> {
        self.inner.get()
    }
}

struct RuntimeUdpSessionSocketListener {
    url: url::Url,
    net_ns: NetNS,
    accept_kind: UdpSessionAcceptKind,
    factory: Arc<RuntimeUdpSocketFactory>,
    control_handler: Arc<RuntimeUdpSessionControlHandler>,
    socket_mark: Option<u32>,
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
        Self {
            url,
            net_ns,
            accept_kind,
            factory,
            control_handler,
            socket_mark,
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
        Ok(AcceptedConnection::UdpSession(
            self.inner()?.accept().await?,
        ))
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
            core_listener::ListenerEvent::AcceptedSocketHandleFailed { .. } => {}
        }
    }
}

#[derive(Debug)]
struct EasyTierAcceptedHandler<H> {
    global_ctx: ArcGlobalCtx,
    peer_manager: Weak<H>,
}

#[async_trait]
impl<H> core_listener::AcceptedSocketHandler<AcceptedConnection> for EasyTierAcceptedHandler<H>
where
    H: TunnelHandlerForListener + Send + Sync + 'static + Debug,
{
    async fn handle_accepted_socket(&self, accepted: AcceptedConnection) -> anyhow::Result<()> {
        match accepted {
            AcceptedConnection::Tunnel(tunnel) => self.handle_tunnel(tunnel).await,
            AcceptedConnection::UdpSession(session) => self.handle_udp_session(session).await,
        }
    }
}

impl<H> EasyTierAcceptedHandler<H>
where
    H: TunnelHandlerForListener + Send + Sync + 'static + Debug,
{
    async fn handle_udp_session(&self, session: UdpSession) -> anyhow::Result<()> {
        let local_addr = session.local_addr()?;
        let remote_addr = session.peer_addr()?;
        let local_url = build_url_from_socket_addr(&local_addr.to_string(), "udp");
        let remote_url = build_url_from_socket_addr(&remote_addr.to_string(), "udp");
        let tunnel_info = TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: Some(local_url.clone().into()),
            remote_addr: Some(remote_url.clone().into()),
            resolved_remote_addr: Some(remote_url.clone().into()),
        };

        let tunnel = UdpTunnelUpgrader::new(tunnel_info).upgrade(session)?;
        self.handle_tunnel(tunnel).await
    }

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

        let Some(peer_manager) = self.peer_manager.upgrade() else {
            let error = "peer manager is gone, cannot handle tunnel".to_owned();
            self.global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                local_url,
                remote_url,
                error.clone(),
            ));
            tracing::error!(error = %error, "handle conn error");
            return Err(anyhow::anyhow!(error));
        };
        if let Err(error) = peer_manager.handle_tunnel(tunnel).await {
            self.global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                local_url,
                remote_url,
                error.to_string(),
            ));
            tracing::error!(?error, "handle conn error");
            return Err(error.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI32, Ordering};

    use futures::{SinkExt, StreamExt};
    use tokio::time::timeout;

    use crate::{
        common::config::ConfigLoader,
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{TunnelConnector, TunnelError, packet_def::ZCPacket, ring::RingTunnelConnector},
    };

    use super::*;

    #[derive(Debug)]
    struct MockListenerHandler {}

    #[async_trait]
    impl TunnelHandlerForListener for MockListenerHandler {
        async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
            let data = "abc";
            let (_recv, mut send) = tunnel.split();

            let zc_packet = ZCPacket::new_with_payload(data.as_bytes());
            send.send(zc_packet).await.unwrap();
            Err(Error::Unknown)
        }
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

    #[tokio::test]
    async fn handle_error_in_accept() {
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(get_mock_global_ctx(), handler.clone());

        let ring_id = format!("ring://{}", uuid::Uuid::new_v4());

        let ring_id_clone = ring_id.clone();
        listener_mgr
            .add_listener(
                move || Box::new(RingTunnelListener::new(ring_id_clone.parse().unwrap())),
                true,
            )
            .await
            .unwrap();
        listener_mgr.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let connect_once = |ring_id| async move {
            let tunnel = RingTunnelConnector::new(ring_id).connect().await.unwrap();
            let (mut recv, _send) = tunnel.split();
            assert_eq!(
                recv.next().await.unwrap().unwrap().payload(),
                "abc".as_bytes()
            );
            tunnel
        };

        timeout(std::time::Duration::from_secs(1), async move {
            connect_once(ring_id.parse().unwrap()).await;
            // handle tunnel fail should not impact the second connect
            connect_once(ring_id.parse().unwrap()).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retry_listen() {
        let counter = Arc::new(AtomicI32::new(0));
        let drop_counter = Arc::new(AtomicI32::new(0));
        struct MockListener {
            counter: Arc<AtomicI32>,
            drop_counter: Arc<AtomicI32>,
        }

        #[async_trait::async_trait]
        impl TunnelListener for MockListener {
            async fn listen(&mut self) -> Result<(), TunnelError> {
                self.counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }

            async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Err(TunnelError::BufferFull)
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
        listener_mgr
            .add_listener(
                move || {
                    Box::new(MockListener {
                        counter: counter_clone.clone(),
                        drop_counter: drop_counter_clone.clone(),
                    })
                },
                true,
            )
            .await
            .unwrap();
        listener_mgr.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        assert!(counter.load(Ordering::Relaxed) >= 2);
        assert!(drop_counter.load(Ordering::Relaxed) >= 1);
    }
}
