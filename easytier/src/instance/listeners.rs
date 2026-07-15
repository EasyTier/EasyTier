use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
#[cfg(any(feature = "wireguard", feature = "quic"))]
use easytier_core::socket::udp::UdpSessionProtocol;
use easytier_core::{
    instance::{ExternalListenerFactory, ListenerService},
    listener::{
        self as core_listener, plan as core_listener_plan,
        transport::{
            AcceptedTransport, AcceptedTunnelEvent, AcceptedTunnelEventSink,
            TransportListenerConfig,
        },
    },
    socket::{SocketContext, udp::UdpSessionAcceptKind},
};
use tokio::sync::Mutex;

#[cfg(test)]
use crate::host_runtime::native_host_runtime;
#[cfg(test)]
use easytier_core::tunnel::ring::RingTunnelRegistry;

#[cfg(feature = "faketcp")]
use crate::common::netns::NetNS;
use crate::{
    common::{
        config::ConfigLoader as _,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    socket::tcp::RuntimeTcpSocket,
};

#[cfg(test)]
use easytier_core::{
    listener::transport::ProtocolAcceptedTransportHandler, peers::peer_manager::PeerManagerCore,
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
    context: SocketContext,
) -> Vec<TransportListenerConfig> {
    plan.listeners
        .iter()
        .filter_map(|listener| match listener.kind {
            core_listener_plan::ListenerKind::Ring => Some(TransportListenerConfig::Ring {
                url: listener.url.clone(),
                must_succeed: listener.must_succeed,
            }),
            core_listener_plan::ListenerKind::TcpStream if listener.url.scheme() != "faketcp" => {
                Some(TransportListenerConfig::Tcp {
                    url: listener.url.clone(),
                    options: core_listener_plan::unresolved_tcp_listener_options(context.clone()),
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
                        context.clone(),
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
            dyn core_listener::AcceptedSocketHandler<AcceptedTransport<RuntimeTcpSocket>>,
        >,
    >,
    failures: Vec<core_listener_plan::ListenerPlanFailure>,
    global_ctx: ArcGlobalCtx,
}

pub(crate) struct RuntimeExternalListenerFactory {
    global_ctx: ArcGlobalCtx,
    plan: core_listener_plan::ListenerPlan,
}

impl RuntimeExternalListenerFactory {
    pub(crate) fn new(
        global_ctx: ArcGlobalCtx,
        plan: core_listener_plan::ListenerPlan,
    ) -> Arc<Self> {
        Arc::new(Self { global_ctx, plan })
    }
}

impl ExternalListenerFactory<AcceptedTransport<RuntimeTcpSocket>>
    for RuntimeExternalListenerFactory
{
    fn build(
        &self,
        handler: Arc<dyn core_listener::AcceptedSocketHandler<AcceptedTransport<RuntimeTcpSocket>>>,
        events: Arc<dyn core_listener::ListenerEventSink>,
    ) -> Arc<dyn ListenerService> {
        Arc::new(RuntimeListenerService::new(
            self.global_ctx.clone(),
            handler,
            &self.plan,
            events,
        ))
    }
}

impl RuntimeListenerService {
    pub(crate) fn new(
        global_ctx: ArcGlobalCtx,
        handler: Arc<dyn core_listener::AcceptedSocketHandler<AcceptedTransport<RuntimeTcpSocket>>>,
        plan: &core_listener_plan::ListenerPlan,
        events: Arc<dyn core_listener::ListenerEventSink>,
    ) -> Self {
        let mut manager = core_listener::ListenerManager::new_with_events(handler, events);
        for listener in &plan.listeners {
            match listener.kind {
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
            .field(
                "url",
                &core_listener::SocketListener::local_url(&self.inner),
            )
            .finish()
    }
}

#[cfg(feature = "faketcp")]
#[async_trait]
impl core_listener::SocketListener for RuntimeFakeTcpSocketListener {
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        let _guard = self.net_ns.guard();
        core_listener::SocketListener::listen(&mut self.inner).await?;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = core_listener::SocketListener::local_url(&self.inner);
        let socket = self.inner.accept_socket().await?;
        Ok(AcceptedTransport::Tcp {
            socket: RuntimeTcpSocket::from_fake_tcp(socket),
            local_url,
            upgrade_permit: None,
        })
    }

    fn local_url(&self) -> url::Url {
        core_listener::SocketListener::local_url(&self.inner)
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

#[derive(Debug)]
struct GlobalCtxAcceptedTunnelEventSink {
    global_ctx: ArcGlobalCtx,
}

pub(crate) fn runtime_accepted_tunnel_event_sink(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn AcceptedTunnelEventSink> {
    Arc::new(GlobalCtxAcceptedTunnelEventSink { global_ctx })
}

impl AcceptedTunnelEventSink for GlobalCtxAcceptedTunnelEventSink {
    fn emit(&self, event: AcceptedTunnelEvent) {
        let event = match event {
            AcceptedTunnelEvent::Accepted {
                local_url,
                remote_url,
            } => GlobalCtxEvent::ConnectionAccepted(local_url, remote_url),
            AcceptedTunnelEvent::AdmissionFailed {
                local_url,
                remote_url,
                error,
            } => GlobalCtxEvent::ConnectionError(local_url, remote_url, error),
        };
        self.global_ctx.issue_event(event);
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
        let configs = runtime_transport_listener_configs(
            &plan,
            crate::instance::composition::runtime_socket_context(&global_ctx),
        );
        let handler: Arc<
            dyn core_listener::AcceptedSocketHandler<AcceptedTransport<RuntimeTcpSocket>>,
        > = Arc::new(ProtocolAcceptedTransportHandler::new(
            &peer_manager,
            crate::tunnel::protocol::runtime_server_protocol_upgrader(global_ctx.clone()),
        ));
        let transport = Arc::new(
            easytier_core::listener::transport::TransportListenerService::new_with_events(
                crate::instance::host::native_instance_host(global_ctx.clone()),
                native_host_runtime(),
                ring_registry,
                configs,
                handler.clone(),
                runtime_listener_event_sink(global_ctx.clone()),
            ),
        );
        let events = runtime_listener_event_sink(global_ctx.clone());
        let external = Arc::new(RuntimeListenerService::new(
            global_ctx, handler, &plan, events,
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
    use crate::common::{config::ConfigLoader, global_ctx::tests::get_mock_global_ctx};

    use super::*;

    #[tokio::test]
    async fn runtime_plan_routes_socket_transports_to_core() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.config.set_listeners(vec![
            "tcp://127.0.0.1:0".parse().unwrap(),
            "udp://127.0.0.1:0".parse().unwrap(),
        ]);
        let plan = runtime_listener_plan(&global_ctx);
        let configs = runtime_transport_listener_configs(
            &plan,
            SocketContext::default().with_socket_mark(Some(7)),
        );

        assert_eq!(configs.len(), 3);
        assert!(matches!(&configs[0], TransportListenerConfig::Ring { .. }));
        assert!(matches!(
            &configs[1],
            TransportListenerConfig::Tcp { options, .. }
                if options.bind.local_addr.is_none()
                    && options.bind.context.socket_mark == Some(7)
        ));
        assert!(matches!(
            &configs[2],
            TransportListenerConfig::Udp { request, .. }
                if request.bind.local_addr.is_none()
                    && request.bind.context.socket_mark == Some(7)
        ));
    }
}
