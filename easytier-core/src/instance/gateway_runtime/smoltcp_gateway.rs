#[cfg(feature = "proxy-smoltcp-stack")]
#[path = "smoltcp_gateway_enabled.rs"]
mod selected;

#[cfg(not(feature = "proxy-smoltcp-stack"))]
#[path = "smoltcp_gateway_disabled.rs"]
mod selected;

use std::sync::Arc;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    gateway::{GatewayEventSink, proxy::wrapped_transport::WrappedTransportProxyModule},
    host::dns::DnsResolver,
    instance::CoreInstanceHost,
    peers::peer_manager::PeerManagerCore,
    socket::SocketContext,
};

pub(in crate::instance) use selected::SmoltcpGatewayRuntime;

#[allow(dead_code)]
pub(in crate::instance) struct SmoltcpGatewayRuntimeInputs<H>
where
    H: CoreInstanceHost,
{
    pub(in crate::instance) runtime_config: CoreRuntimeConfigStore,
    pub(in crate::instance) peer_manager: Arc<PeerManagerCore>,
    pub(in crate::instance) wrapped_transport: Option<Arc<WrappedTransportProxyModule>>,
    pub(in crate::instance) host: Arc<H>,
    pub(in crate::instance) dns: Arc<dyn DnsResolver>,
    pub(in crate::instance) socket_context: SocketContext,
    pub(in crate::instance) events: Arc<dyn GatewayEventSink>,
}
