#[cfg(feature = "proxy-packet")]
#[path = "packet_proxy_enabled.rs"]
mod selected;

#[cfg(not(feature = "proxy-packet"))]
#[path = "packet_proxy_disabled.rs"]
mod selected;

use std::sync::Arc;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    gateway::proxy::{cidr_table::ProxyCidrTable, icmp_host::IcmpProxyHost},
    instance::CoreInstanceHost,
    listener::RunningListenerRegistry,
    peers::peer_manager::PeerManagerCore,
    process_runtime::ProtectedTcpPortRegistry,
    socket::SocketContext,
};

pub(in crate::instance) use selected::PacketProxyRuntime;

#[allow(dead_code)]
pub(in crate::instance) struct PacketProxyRuntimeInputs<H>
where
    H: CoreInstanceHost,
{
    pub(in crate::instance) peer_manager: Arc<PeerManagerCore>,
    pub(in crate::instance) host: Arc<H>,
    pub(in crate::instance) protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
    pub(in crate::instance) running_listeners: Arc<RunningListenerRegistry>,
    pub(in crate::instance) runtime_config: CoreRuntimeConfigStore,
    pub(in crate::instance) cidr_table: Arc<ProxyCidrTable>,
    pub(in crate::instance) tcp_socket_context: SocketContext,
    pub(in crate::instance) udp_socket_context: SocketContext,
    pub(in crate::instance) icmp_socket_context: SocketContext,
    pub(in crate::instance) icmp_host: Option<Arc<dyn IcmpProxyHost>>,
}
