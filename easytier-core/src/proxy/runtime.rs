use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Weak;

use bytes::Bytes;
use cidr::Ipv4Inet;
use tokio::io::{AsyncRead, AsyncWrite};

use super::tcp_proxy::TcpNatEntryId;
use super::udp_proxy::UdpNatEntryId;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProxyRuntimeSnapshot {
    pub local_inet: Option<Ipv4Inet>,
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub no_tun: bool,
    pub enable_exit_node: bool,
    pub smoltcp_enabled: bool,
    pub latency_first: bool,
}

pub trait ProxyRuntimeInfo: Send + Sync {
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot;
    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool;
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
pub trait UdpProxyResponseSink: Send + Sync {
    async fn handle_socket_response(
        &self,
        entry_id: UdpNatEntryId,
        src: SocketAddr,
        payload: Bytes,
    );
}

#[async_trait::async_trait]
pub trait UdpProxyRuntime: ProxyRuntimeInfo {
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

pub trait TcpProxySrcStream: TcpProxyStream {}

impl<T> TcpProxySrcStream for T where T: TcpProxyStream {}

pub trait TcpProxyDstStream: TcpProxyStream {}

impl<T> TcpProxyDstStream for T where T: TcpProxyStream {}

#[derive(Debug, Clone, Copy)]
pub struct TcpProxyConnectContext {
    pub entry_id: TcpNatEntryId,
    pub src: SocketAddr,
    pub real_dst: SocketAddr,
    pub mapped_dst: SocketAddr,
}

#[async_trait::async_trait]
pub trait TcpProxyKernelListener: Send + Sync {
    fn local_port(&self) -> u16;
    fn close(&self);

    async fn accept(&self) -> Result<(SocketAddr, Box<dyn TcpProxySrcStream>), ProxyRuntimeError>;
}

#[async_trait::async_trait]
pub trait TcpProxyRuntime: ProxyRuntimeInfo {
    fn should_deny_tcp_proxy(&self, dst: SocketAddr) -> bool;

    async fn bind_kernel_listener(
        &self,
    ) -> Result<Box<dyn TcpProxyKernelListener>, ProxyRuntimeError>;

    async fn connect_dst(
        &self,
        ctx: TcpProxyConnectContext,
    ) -> Result<Box<dyn TcpProxyDstStream>, ProxyRuntimeError>;

    async fn copy_bidirectional_no_shutdown(
        &self,
        entry_id: TcpNatEntryId,
        src: &mut dyn TcpProxySrcStream,
        dst: &mut dyn TcpProxyDstStream,
    ) -> Result<(), ProxyRuntimeError>;
}
