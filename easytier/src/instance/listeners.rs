use std::{
    fmt::Debug,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use easytier_core::{
    instance::ListenerService,
    listener::{
        self as core_listener, plan as core_listener_plan,
        transport::{
            AcceptedTransport, AcceptedTunnelHandler, ProtocolAcceptedTransportHandler,
            TransportListenerConfig,
        },
    },
    peers::peer_manager::PeerManagerCore,
    socket::udp::{UdpSessionAcceptKind, UdpSessionProtocol},
    tunnel::ring::RingTunnelRegistry,
};
use tokio::sync::Mutex;

#[cfg(feature = "faketcp")]
use crate::tunnel::TunnelListener;
use crate::{
    common::{
        config::ConfigLoader as _,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    socket::tcp::RuntimeTcpSocket,
    tunnel::{FromUrl, IpVersion, Tunnel},
};

pub use easytier_core::listener::plan::{is_url_host_ipv6, is_url_host_unspecified};

pub(crate) fn runtime_listener_plan(global_ctx: &ArcGlobalCtx) -> core_listener_plan::ListenerPlan {
    core_listener_plan::plan_listeners(
        core_listener_plan::ListenerPlanRequest::new(
            global_ctx.get_id(),
            global_ctx.config.get_listener_uris(),
            global_ctx.config.get_flags().enable_ipv6,
        ),
        &listener_scheme_registry(),
    )
}

pub(crate) fn runtime_transport_listener_configs(
    plan: &core_listener_plan::ListenerPlan,
    socket_mark: Option<u32>,
) -> Vec<TransportListenerConfig> {
    plan.listeners
        .iter()
        .filter_map(|listener| match listener.kind {
            core_listener_plan::ListenerKind::TcpStream if listener.url.scheme() != "faketcp" => {
                Some(TransportListenerConfig::Tcp {
                    url: listener.url.clone(),
                    options: core_listener_plan::unresolved_tcp_listener_options(socket_mark),
                    must_succeed: listener.must_succeed,
                })
            }
            core_listener_plan::ListenerKind::UdpSession => {
                let accept_kind = match listener.url.scheme() {
                    "udp" => UdpSessionAcceptKind::EasyTierMux,
                    #[cfg(feature = "wireguard")]
                    "wg" => UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
                    #[cfg(feature = "quic")]
                    "quic" => UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
                    _ => return None,
                };
                Some(TransportListenerConfig::Udp {
                    url: listener.url.clone(),
                    request: core_listener_plan::unresolved_udp_session_listen_request(
                        &listener.url,
                        socket_mark,
                    ),
                    accept_kind,
                    must_succeed: listener.must_succeed,
                })
            }
            _ => None,
        })
        .collect()
}

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

pub(crate) struct RuntimeListenerService {
    manager: Mutex<
        core_listener::ListenerManager<
            AcceptedTransport<RuntimeTcpSocket>,
            RuntimeAcceptedTransportHandler,
        >,
    >,
    failures: Vec<core_listener_plan::ListenerPlanFailure>,
    global_ctx: ArcGlobalCtx,
}

impl RuntimeListenerService {
    pub(crate) fn new(
        global_ctx: ArcGlobalCtx,
        handler: Arc<RuntimeAcceptedTransportHandler>,
        ring_registry: Arc<RingTunnelRegistry>,
        plan: &core_listener_plan::ListenerPlan,
    ) -> Self {
        let events = runtime_listener_event_sink(global_ctx.clone());
        let mut manager = core_listener::ListenerManager::new_with_events(handler, events);
        for listener in &plan.listeners {
            match listener.kind {
                core_listener_plan::ListenerKind::Ring => {
                    let url = listener.url.clone();
                    let ring_registry = ring_registry.clone();
                    manager.add_listener(
                        move || {
                            Box::new(RuntimeRingStreamListener::new(
                                url.clone(),
                                ring_registry.clone(),
                            ))
                        },
                        listener.must_succeed,
                    );
                }
                #[cfg(feature = "faketcp")]
                core_listener_plan::ListenerKind::TcpStream
                    if listener.url.scheme() == "faketcp" =>
                {
                    let url = listener.url.clone();
                    let net_ns = global_ctx.net_ns.clone();
                    manager.add_listener(
                        move || {
                            Box::new(RuntimeFakeTcpSocketListener::new(
                                url.clone(),
                                net_ns.clone(),
                            ))
                        },
                        listener.must_succeed,
                    );
                }
                core_listener_plan::ListenerKind::External =>
                {
                    #[cfg(unix)]
                    if listener.url.scheme() == "unix" {
                        let url = listener.url.clone();
                        manager.add_listener(
                            move || Box::new(RuntimeUnixStreamListener::new(url.clone())),
                            listener.must_succeed,
                        );
                    }
                }
                _ => {}
            }
        }
        Self {
            manager: Mutex::new(manager),
            failures: plan.failures.clone(),
            global_ctx,
        }
    }
}

#[async_trait]
impl ListenerService for RuntimeListenerService {
    async fn start(&self) -> anyhow::Result<()> {
        for failure in &self.failures {
            self.global_ctx
                .issue_event(GlobalCtxEvent::ListenerAddFailed(
                    failure.url.clone(),
                    failure.message.clone(),
                ));
        }
        self.manager.lock().await.run().await?;
        Ok(())
    }

    async fn stop(&self) {
        self.manager.lock().await.stop().await;
    }
}

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
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_none() {
            let local_id = uuid::Uuid::from_url(self.url.clone(), IpVersion::Both).await?;
            self.inner = Some(self.ring_registry.bind(local_id)?);
        }
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let accepted = self
            .inner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("ring stream listener is not started"))?
            .accept()
            .await?;
        Ok(AcceptedTransport::ByteStream {
            socket: RuntimeTcpSocket::from_ring(accepted.socket)?,
            local_url: format!("ring://{}", accepted.local_id).parse()?,
            remote_url: Some(format!("ring://{}", accepted.remote_id).parse()?),
        })
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
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
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

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
        Ok(AcceptedTransport::ByteStream {
            socket: RuntimeTcpSocket::from_unix(stream),
            local_url: self.url.clone(),
            remote_url: Some(unix_stream_remote_url(remote_addr)),
        })
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
    }
}

#[cfg(unix)]
impl Drop for RuntimeUnixStreamListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.url.path());
    }
}

#[cfg(feature = "faketcp")]
struct RuntimeFakeTcpSocketListener {
    net_ns: NetNS,
    inner: crate::tunnel::fake_tcp::FakeTcpTunnelListener,
}

#[cfg(feature = "faketcp")]
impl RuntimeFakeTcpSocketListener {
    fn new(url: url::Url, net_ns: NetNS) -> Self {
        Self {
            net_ns,
            inner: crate::tunnel::fake_tcp::FakeTcpTunnelListener::new(url),
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
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        let _guard = self.net_ns.guard();
        self.inner.listen().await?;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = self.inner.local_url();
        let socket = self.inner.accept_socket().await?;
        Ok(AcceptedTransport::Tcp {
            socket: RuntimeTcpSocket::from_fake_tcp(socket),
            local_url,
            upgrade_permit: None,
        })
    }

    fn local_url(&self) -> url::Url {
        self.inner.local_url()
    }
}

#[derive(Debug)]
pub(crate) struct GlobalCtxListenerEventSink {
    global_ctx: ArcGlobalCtx,
}

pub(crate) fn runtime_listener_event_sink(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn core_listener::ListenerEventSink> {
    Arc::new(GlobalCtxListenerEventSink { global_ctx })
}

impl core_listener::ListenerEventSink for GlobalCtxListenerEventSink {
    fn emit(&self, event: core_listener::ListenerEvent) {
        match event {
            core_listener::ListenerEvent::ListenerAdded { url, .. } => {
                self.global_ctx.add_running_listener(url.clone());
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAdded(url));
            }
            core_listener::ListenerEvent::ListenerRemoved { url } => {
                self.global_ctx.remove_running_listener(&url);
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
            core_listener::ListenerEvent::AcceptedSocketHandleFailed { url, error } => {
                tracing::error!(%url, %error, "accepted socket handler failed");
            }
        }
    }
}

struct RuntimeAcceptedTunnelHandler {
    global_ctx: ArcGlobalCtx,
    inner: Weak<PeerManagerCore>,
}

impl Debug for RuntimeAcceptedTunnelHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeAcceptedTunnelHandler")
            .field("inner_available", &self.inner.strong_count())
            .finish()
    }
}

#[async_trait]
impl AcceptedTunnelHandler for RuntimeAcceptedTunnelHandler {
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

pub(crate) struct RuntimeAcceptedTransportHandler {
    _tunnel_handler: Arc<RuntimeAcceptedTunnelHandler>,
    protocol: ProtocolAcceptedTransportHandler<RuntimeTcpSocket, RuntimeAcceptedTunnelHandler>,
}

impl Debug for RuntimeAcceptedTransportHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeAcceptedTransportHandler")
            .finish()
    }
}

pub(crate) fn runtime_accepted_transport_handler(
    global_ctx: ArcGlobalCtx,
    peer_manager: &Arc<PeerManagerCore>,
) -> Arc<RuntimeAcceptedTransportHandler> {
    let protocol = crate::connector::protocol::runtime_server_protocol_upgrader(global_ctx.clone());
    let tunnel_handler = Arc::new(RuntimeAcceptedTunnelHandler {
        global_ctx,
        inner: Arc::downgrade(peer_manager),
    });
    Arc::new(RuntimeAcceptedTransportHandler {
        protocol: ProtocolAcceptedTransportHandler::new(&tunnel_handler, protocol),
        _tunnel_handler: tunnel_handler,
    })
}

#[async_trait]
impl core_listener::AcceptedSocketHandler<AcceptedTransport<RuntimeTcpSocket>>
    for RuntimeAcceptedTransportHandler
{
    async fn handle_accepted_socket(
        &self,
        accepted: AcceptedTransport<RuntimeTcpSocket>,
    ) -> anyhow::Result<()> {
        self.protocol.handle_accepted_socket(accepted).await
    }
}

#[cfg(test)]
pub struct ListenerManager<H> {
    service: Arc<dyn ListenerService>,
    handler: std::marker::PhantomData<fn() -> H>,
}

#[cfg(test)]
impl ListenerManager<PeerManagerCore> {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManagerCore>) -> Self {
        Self::new_with_ring_registry(
            global_ctx,
            peer_manager,
            Arc::new(RingTunnelRegistry::default()),
        )
    }

    pub(crate) fn new_with_ring_registry(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManagerCore>,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        let plan = runtime_listener_plan(&global_ctx);
        let configs =
            runtime_transport_listener_configs(&plan, global_ctx.config.get_flags().socket_mark);
        let handler = runtime_accepted_transport_handler(global_ctx.clone(), &peer_manager);
        let transport = Arc::new(
            easytier_core::listener::transport::TransportListenerService::new_with_events(
                Arc::new(
                    crate::connector::runtime::RuntimeConnectorHost::new_with_ring_registry(
                        global_ctx.clone(),
                        ring_registry.clone(),
                    ),
                ),
                Arc::new(crate::common::dns::RuntimeDnsResolver::new_with_netns(
                    global_ctx.net_ns.clone(),
                )),
                configs,
                handler.clone(),
                runtime_listener_event_sink(global_ctx.clone()),
            ),
        );
        let external = Arc::new(RuntimeListenerService::new(
            global_ctx,
            handler,
            ring_registry,
            &plan,
        ));
        Self {
            service: easytier_core::instance::ListenerServiceGroup::new(vec![transport, external]),
            handler: std::marker::PhantomData,
        }
    }

    pub async fn prepare_listeners(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.service.start().await
    }

    pub async fn stop(&self) {
        self.service.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use easytier_core::{connectivity::manual::ManualConnectorHost, listener::SocketListener as _};

    use crate::{
        common::{config::ConfigLoader, global_ctx::tests::get_mock_global_ctx},
        connector::runtime::RuntimeConnectorHost,
    };

    use super::*;

    #[tokio::test]
    async fn runtime_plan_routes_socket_transports_to_core() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.config.set_listeners(vec![
            "tcp://127.0.0.1:0".parse().unwrap(),
            "udp://127.0.0.1:0".parse().unwrap(),
        ]);
        let plan = runtime_listener_plan(&global_ctx);
        let configs = runtime_transport_listener_configs(&plan, Some(7));

        assert_eq!(configs.len(), 2);
        assert!(matches!(
            &configs[0],
            TransportListenerConfig::Tcp { options, .. }
                if options.bind.local_addr.is_none() && options.bind.socket_mark == Some(7)
        ));
        assert!(matches!(
            &configs[1],
            TransportListenerConfig::Udp { request, .. }
                if request.bind.local_addr.is_none() && request.bind.socket_mark == Some(7)
        ));
    }

    #[tokio::test]
    async fn ring_listener_uses_injected_registry() {
        let global_ctx = get_mock_global_ctx();
        let registry = Arc::new(RingTunnelRegistry::default());
        let isolated_host = RuntimeConnectorHost::new(global_ctx.clone());
        let shared_host =
            RuntimeConnectorHost::new_with_ring_registry(global_ctx, registry.clone());
        let listener_url: url::Url = format!("ring://{}", uuid::Uuid::new_v4()).parse().unwrap();
        let mut listener = RuntimeRingStreamListener::new(listener_url.clone(), registry);
        listener.listen().await.unwrap();

        assert!(
            ManualConnectorHost::connect_byte_stream(&isolated_host, &listener_url)
                .await
                .is_err()
        );
        ManualConnectorHost::connect_byte_stream(&shared_host, &listener_url)
            .await
            .unwrap();
        listener.accept().await.unwrap();
    }
}
