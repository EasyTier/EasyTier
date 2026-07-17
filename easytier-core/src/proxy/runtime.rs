use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use cidr::Ipv4Inet;
use tokio::io::{AsyncRead, AsyncWrite};

use super::tcp_proxy_engine::TcpProxyMode;
use super::udp_proxy_engine::UdpNatEntryId;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProxyRuntimeSnapshot {
    pub local_inet: Option<Ipv4Inet>,
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub no_tun: bool,
    pub enable_exit_node: bool,
    pub smoltcp_enabled: bool,
    pub latency_first: bool,
}

pub(crate) trait ProxyRuntimeInfo: Send + Sync {
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot;
    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool;
}

pub(crate) trait WrappedTcpDestinationRuntime: Send + Sync {
    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool;
    fn no_tun(&self) -> bool;
    fn should_deny_tcp_proxy(&self, dst: SocketAddr) -> bool;
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyRuntimeError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::io::Error> for ProxyRuntimeError {
    fn from(value: std::io::Error) -> Self {
        Self::Other(value.into())
    }
}

#[async_trait::async_trait]
pub trait IcmpProxySocket: Send + Sync + 'static {
    async fn send(&self, destination: Ipv4Addr, packet: &[u8]) -> Result<(), ProxyRuntimeError>;

    async fn recv(&self) -> Result<(IpAddr, Vec<u8>), ProxyRuntimeError>;

    fn close(&self) {}
}

#[async_trait::async_trait]
pub trait IcmpProxyHost: Send + Sync + 'static {
    async fn open_icmp_v4(
        &self,
        context: crate::socket::SocketContext,
    ) -> Result<Arc<dyn IcmpProxySocket>, ProxyRuntimeError>;
}

#[async_trait::async_trait]
pub(crate) trait IcmpProxyRuntime: ProxyRuntimeInfo {
    type Socket: IcmpProxySocket + ?Sized;

    async fn start_icmp(&self) -> Result<Arc<Self::Socket>, ProxyRuntimeError>;

    fn stop_icmp(&self);
}

#[async_trait::async_trait]
pub(crate) trait UdpProxyResponseSink: Send + Sync {
    async fn handle_socket_response(
        &self,
        entry_id: UdpNatEntryId,
        src: SocketAddr,
        payload: Bytes,
    );
}

pub(crate) trait UdpProxyPolicy: ProxyRuntimeInfo {
    fn should_deny_udp_proxy(&self, dst: SocketAddr) -> bool;
    fn udp_response_ipv4_mtu(&self) -> usize;
}

#[async_trait::async_trait]
pub(crate) trait UdpProxyRuntime: ProxyRuntimeInfo {
    fn should_deny_udp_proxy(&self, dst: SocketAddr) -> bool;
    fn udp_response_ipv4_mtu(&self) -> usize;

    async fn send_udp_to_socket(
        &self,
        entry_id: UdpNatEntryId,
        dst: SocketAddr,
        payload: Bytes,
        response_sink: Weak<dyn UdpProxyResponseSink>,
    ) -> Result<(), ProxyRuntimeError>;

    fn close_udp_socket(&self, entry_id: UdpNatEntryId);
}

pub trait TcpProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TcpProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TcpProxyConnectContext {
    pub src: SocketAddr,
    pub real_dst: SocketAddr,
    pub mapped_dst: SocketAddr,
}

pub(crate) trait TcpProxyRuntime: ProxyRuntimeInfo {
    fn should_deny_tcp_proxy(&self, dst: SocketAddr) -> bool;

    fn record_tcp_proxy_connect(&self, ctx: TcpProxyConnectContext, socket_dst: SocketAddr);
}

#[async_trait::async_trait]
pub(crate) trait TcpProxyDestinationConnector: Send + Sync + 'static {
    type DstStream: TcpProxyStream + 'static;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream>;

    fn proxy_mode(&self) -> TcpProxyMode;
}
