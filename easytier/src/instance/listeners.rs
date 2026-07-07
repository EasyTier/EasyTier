use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Weak},
};

use anyhow::Context;
use async_trait::async_trait;
use easytier_core::{
    listener as core_listener,
    socket::udp::{UdpSession, UdpSessionAcceptKind, UdpSessionSocket, UdpSessionSocketListener},
    tunnel::udp::UdpTunnelUpgrader,
};
use tokio::task::JoinSet;

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    peers::peer_manager::PeerManager,
    tunnel::{
        self, FromUrl, IpScheme, IpVersion, Tunnel, TunnelInfo, TunnelListener, TunnelScheme,
        TunnelUrl, build_url_from_socket_addr,
        ring::RingTunnelListener,
        tcp::TcpTunnelListener,
        udp::{RuntimeUdpSessionControlHandler, RuntimeUdpSocketFactory, UdpTunnelListener},
    },
    utils::BoxExt,
};

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

pub fn is_url_host_ipv6(l: &url::Url) -> bool {
    l.host_str().is_some_and(|h| h.contains(':'))
}

pub fn is_url_host_unspecified(l: &url::Url) -> bool {
    if let Ok(ip) = IpAddr::from_str(l.host_str().unwrap_or_default()) {
        ip.is_unspecified()
    } else {
        false
    }
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
pub type ListenerCreator = Box<dyn ListenerCreatorTrait>;

#[derive(Clone)]
struct ListenerFactory {
    creator_fn: Arc<ListenerCreator>,
    must_succ: bool,
}

pub struct ListenerManager<H> {
    global_ctx: ArcGlobalCtx,
    net_ns: NetNS,
    listeners: Vec<ListenerFactory>,
    peer_manager: Weak<H>,
    udp_listener_manager: core_listener::ListenerManager<UdpSession, UdpAcceptedSocketHandler<H>>,

    tasks: JoinSet<()>,
}

impl<H: TunnelHandlerForListener + Send + Sync + 'static + Debug> ListenerManager<H> {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<H>) -> Self {
        let peer_manager = Arc::downgrade(&peer_manager);
        let udp_handler = Arc::new(UdpAcceptedSocketHandler {
            global_ctx: global_ctx.clone(),
            peer_manager: peer_manager.clone(),
        });
        let udp_events = Arc::new(GlobalCtxListenerEventSink {
            global_ctx: global_ctx.clone(),
        });
        Self {
            global_ctx: global_ctx.clone(),
            net_ns: global_ctx.net_ns.clone(),
            listeners: Vec::new(),
            peer_manager,
            udp_listener_manager: core_listener::ListenerManager::new_with_events(
                udp_handler,
                udp_events,
            ),
            tasks: JoinSet::new(),
        }
    }

    pub async fn prepare_listeners(&mut self) -> Result<(), Error> {
        let self_id = self.global_ctx.get_id();
        self.add_listener(
            move || {
                Box::new(RingTunnelListener::new(
                    format!("ring://{}", self_id).parse().unwrap(),
                ))
            },
            true,
        )
        .await?;

        for l in self.global_ctx.config.get_listener_uris().iter() {
            let l = l.clone();
            let Ok(scheme) = TunnelScheme::try_from(&l) else {
                let msg = format!("failed to get listener by url: {}, maybe not supported", l);
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAddFailed(l.clone(), msg));
                continue;
            };

            if scheme == TunnelScheme::Ip(IpScheme::Udp) {
                self.add_udp_listener(l.clone(), true).await?;
            } else {
                let Ok(_) = create_listener_by_url(&l, self.global_ctx.clone()) else {
                    let msg = format!("failed to get listener by url: {}, maybe not supported", l);
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::ListenerAddFailed(l.clone(), msg));
                    continue;
                };
                let ctx = self.global_ctx.clone();

                let listener = l.clone();
                self.add_listener(
                    move || create_listener_by_url(&listener, ctx.clone()).unwrap(),
                    true,
                )
                .await?;
            }

            if self.global_ctx.config.get_flags().enable_ipv6
                && !is_url_host_ipv6(&l)
                && is_url_host_unspecified(&l)
                // quic enables dual-stack by default, may conflict with v4 listener
                && l.scheme() != "quic" && l.scheme() != "faketcp"
            {
                let mut ipv6_listener = l.clone();
                ipv6_listener
                    .set_host(Some("[::]".to_string().as_str()))
                    .with_context(|| format!("failed to set ipv6 host for listener: {}", l))?;
                if scheme == TunnelScheme::Ip(IpScheme::Udp) {
                    self.add_udp_listener(ipv6_listener, false).await?;
                } else {
                    let ctx = self.global_ctx.clone();
                    self.add_listener(
                        move || create_listener_by_url(&ipv6_listener, ctx.clone()).unwrap(),
                        false,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    pub async fn add_udp_listener(
        &mut self,
        listener: url::Url,
        must_succeed: bool,
    ) -> Result<(), Error> {
        use crate::common::config::ConfigLoader;

        let socket_mark = self.global_ctx.config.get_flags().socket_mark;
        let bind_device = TunnelUrl::from(listener.clone()).bind_dev();
        let factory = Arc::new(
            RuntimeUdpSocketFactory::new(self.net_ns.clone())
                .with_socket_mark(socket_mark)
                .with_port_bound_bind_device(bind_device),
        );
        let control_handler = Arc::new(RuntimeUdpSessionControlHandler);
        let net_ns = self.net_ns.clone();
        self.udp_listener_manager.add_listener(
            move || {
                Box::new(RuntimeUdpSessionSocketListener::new(
                    listener.clone(),
                    net_ns.clone(),
                    UdpSessionAcceptKind::EasyTierMux,
                    factory.clone(),
                    control_handler.clone(),
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
        self.listeners.push(ListenerFactory {
            creator_fn: Arc::new(Box::new(creator)),
            must_succ,
        });
        Ok(())
    }

    #[tracing::instrument(skip(creator))]
    async fn run_listener(
        creator: Arc<ListenerCreator>,
        peer_manager: Weak<H>,
        global_ctx: ArcGlobalCtx,
    ) {
        let mut err_count = 0;
        loop {
            let mut l = (creator)();
            let _g = global_ctx.net_ns.guard();
            match l.listen().await {
                Ok(_) => {
                    err_count = 0;
                    global_ctx.add_running_listener(l.local_url());
                    global_ctx.issue_event(GlobalCtxEvent::ListenerAdded(l.local_url()));
                }
                Err(e) => {
                    tracing::error!(?e, ?l, "listener listen error");
                    global_ctx.issue_event(GlobalCtxEvent::ListenerAddFailed(
                        l.local_url(),
                        format!("error: {:?}, retry listen later...", e),
                    ));
                    err_count += 1;
                    if err_count > 5 {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }
            loop {
                let ret = match l.accept().await {
                    Ok(ret) => ret,
                    Err(e) => {
                        global_ctx.issue_event(GlobalCtxEvent::ListenerAcceptFailed(
                            l.local_url(),
                            format!("error: {:?}, retry listen later...", e),
                        ));
                        tracing::error!(?e, ?l, "listener accept error");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break;
                    }
                };

                let tunnel_info = ret.info().unwrap();
                global_ctx.issue_event(GlobalCtxEvent::ConnectionAccepted(
                    tunnel_info
                        .local_addr
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
                    tunnel_info
                        .remote_addr
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
                ));
                tracing::info!(ret = ?ret, "conn accepted");
                let peer_manager = peer_manager.clone();
                let global_ctx = global_ctx.clone();
                tokio::spawn(async move {
                    let Some(peer_manager) = peer_manager.upgrade() else {
                        tracing::error!("peer manager is gone, cannot handle tunnel");
                        return;
                    };
                    let server_ret = peer_manager.handle_tunnel(ret).await;
                    if let Err(e) = &server_ret {
                        global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                            tunnel_info.local_addr.unwrap_or_default().to_string(),
                            tunnel_info.remote_addr.unwrap_or_default().to_string(),
                            e.to_string(),
                        ));
                        tracing::error!(error = ?e, "handle conn error");
                    }
                });
            }
        }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        if self.udp_listener_manager.listener_count() > 0 {
            self.udp_listener_manager.run().await?;
        }
        for listener in &self.listeners {
            if listener.must_succ {
                // try listen once
                let mut l = (listener.creator_fn)();
                let _g = self.net_ns.guard();
                l.listen()
                    .await
                    .with_context(|| format!("failed to listen on {}", l.local_url()))?;
            }

            self.tasks.spawn(Self::run_listener(
                listener.creator_fn.clone(),
                self.peer_manager.clone(),
                self.global_ctx.clone(),
            ));
        }

        Ok(())
    }
}

type EasyTierUdpSessionSocketListener =
    UdpSessionSocketListener<RuntimeUdpSocketFactory, RuntimeUdpSessionControlHandler>;

struct RuntimeUdpSessionSocketListener {
    url: url::Url,
    net_ns: NetNS,
    accept_kind: UdpSessionAcceptKind,
    factory: Arc<RuntimeUdpSocketFactory>,
    control_handler: Arc<RuntimeUdpSessionControlHandler>,
    inner: Option<EasyTierUdpSessionSocketListener>,
}

impl RuntimeUdpSessionSocketListener {
    fn new(
        url: url::Url,
        net_ns: NetNS,
        accept_kind: UdpSessionAcceptKind,
        factory: Arc<RuntimeUdpSocketFactory>,
        control_handler: Arc<RuntimeUdpSessionControlHandler>,
    ) -> Self {
        Self {
            url,
            net_ns,
            accept_kind,
            factory,
            control_handler,
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
    type Accepted = UdpSession;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_some() {
            return Ok(());
        }

        let socket_addr = {
            let _guard = self.net_ns.guard();
            SocketAddr::from_url(self.url.clone(), IpVersion::Both).await?
        };
        let mut inner = UdpSessionSocketListener::new_with_control_handler(
            self.url.clone(),
            socket_addr,
            self.accept_kind,
            self.factory.clone(),
            self.control_handler.clone(),
        );
        inner.listen().await?;
        self.inner = Some(inner);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        self.inner()?.accept().await
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
struct UdpAcceptedSocketHandler<H> {
    global_ctx: ArcGlobalCtx,
    peer_manager: Weak<H>,
}

#[async_trait]
impl<H> core_listener::AcceptedSocketHandler<UdpSession> for UdpAcceptedSocketHandler<H>
where
    H: TunnelHandlerForListener + Send + Sync + 'static + Debug,
{
    async fn handle_accepted_socket(&self, session: UdpSession) -> anyhow::Result<()> {
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
        self.global_ctx
            .issue_event(GlobalCtxEvent::ConnectionAccepted(
                local_url.to_string(),
                remote_url.to_string(),
            ));
        tracing::info!(ret = ?tunnel, "conn accepted");

        let Some(peer_manager) = self.peer_manager.upgrade() else {
            let error = "peer manager is gone, cannot handle tunnel".to_owned();
            self.global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                local_url.to_string(),
                remote_url.to_string(),
                error.clone(),
            ));
            tracing::error!(error = %error, "handle conn error");
            return Err(anyhow::anyhow!(error));
        };
        if let Err(error) = peer_manager.handle_tunnel(tunnel).await {
            self.global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                local_url.to_string(),
                remote_url.to_string(),
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
    async fn prepare_udp_listeners_registers_core_udp_manager() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec!["udp://127.0.0.1:0".parse().unwrap()]);
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(global_ctx, handler);

        listener_mgr.prepare_listeners().await.unwrap();

        assert_eq!(listener_mgr.listeners.len(), 1);
        assert_eq!(listener_mgr.udp_listener_manager.listener_count(), 1);
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
