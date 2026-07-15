//! Composes process-wide socket capabilities with instance-scoped network facts.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use url::Url;

use crate::{
    connectivity::{
        direct::DirectConnectorHost,
        manual::{ManualConnectorHost, ManualInterfaceAddrs},
        transport::ConnectedByteStream,
    },
    proto::peer_rpc::GetIpListResponse,
    socket::{
        SocketContext,
        tcp::{
            TcpConnectOptions, TcpListenOptions, VirtualTcpListenerFactory, VirtualTcpSocketFactory,
        },
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory,
        },
    },
};

/// Instance facts and environment queries consumed by portable connector policy.
///
/// Socket creation and I/O are deliberately absent; those belong to the
/// process-wide socket runtime passed separately to [`ConnectorHostAdapter`].
#[async_trait]
pub trait ConnectorEnvironment<TcpSocket>: Send + Sync + 'static {
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr>;

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs>;

    async fn connect_byte_stream(
        &self,
        url: &Url,
    ) -> anyhow::Result<ConnectedByteStream<TcpSocket>> {
        anyhow::bail!("environment does not support external byte stream: {url}")
    }

    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse;

    async fn collect_foreign_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        self.collect_ip_addrs(context).await
    }

    fn mapped_listeners(&self) -> Vec<Url>;
    fn is_local_ip(&self, ip: &IpAddr) -> bool;
    fn is_protected_tcp_port(&self, port: u16) -> bool;
    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool;

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source>;

    async fn preferred_foreign_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        self.preferred_ipv6_source(ip, context).await
    }
}

/// Deep adapter that combines one socket runtime with one instance environment.
pub struct ConnectorHostAdapter<S, E> {
    sockets: Arc<S>,
    environment: Arc<E>,
}

impl<S, E> ConnectorHostAdapter<S, E> {
    pub fn new(sockets: Arc<S>, environment: Arc<E>) -> Self {
        Self {
            sockets,
            environment,
        }
    }
}

#[async_trait]
impl<S, E> VirtualTcpSocketFactory for ConnectorHostAdapter<S, E>
where
    S: VirtualTcpSocketFactory,
    E: Send + Sync + 'static,
{
    type Socket = S::Socket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        self.sockets.connect_tcp(options).await
    }
}

#[async_trait]
impl<S, E> VirtualTcpListenerFactory for ConnectorHostAdapter<S, E>
where
    S: VirtualTcpListenerFactory,
    E: Send + Sync + 'static,
{
    type Listener = S::Listener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.sockets.bind_tcp(options).await
    }
}

#[async_trait]
impl<S, E> VirtualUdpSocketFactory for ConnectorHostAdapter<S, E>
where
    S: VirtualUdpSocketFactory,
    E: Send + Sync + 'static,
{
    type Socket = S::Socket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.sockets.bind_udp(options).await
    }
}

#[async_trait]
impl<S, E> UdpSessionControlHandler<S::Socket> for ConnectorHostAdapter<S, E>
where
    S: VirtualUdpSocketFactory + UdpSessionControlHandler<S::Socket>,
    E: Send + Sync + 'static,
{
    async fn send_v4_hole_punch(
        &self,
        socket: Arc<S::Socket>,
        dst_addr: SocketAddrV4,
    ) -> std::io::Result<usize> {
        self.sockets.send_v4_hole_punch(socket, dst_addr).await
    }

    async fn send_v6_hole_punch(
        &self,
        socket: Arc<S::Socket>,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    ) -> std::io::Result<usize> {
        self.sockets
            .send_v6_hole_punch(socket, dst_addr, preferred_src)
            .await
    }
}

#[async_trait]
impl<S, E> ManualConnectorHost for ConnectorHostAdapter<S, E>
where
    S: VirtualTcpSocketFactory
        + VirtualUdpSocketFactory
        + UdpSessionControlHandler<<S as VirtualUdpSocketFactory>::Socket>,
    E: ConnectorEnvironment<<S as VirtualTcpSocketFactory>::Socket>,
{
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        self.environment
            .local_addr_for_remote(remote_addr, context)
            .await
    }

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
        self.environment.interface_addrs().await
    }

    async fn connect_byte_stream(
        &self,
        url: &Url,
    ) -> anyhow::Result<ConnectedByteStream<<Self as VirtualTcpSocketFactory>::Socket>> {
        self.environment.connect_byte_stream(url).await
    }
}

#[async_trait]
impl<S, E> DirectConnectorHost for ConnectorHostAdapter<S, E>
where
    S: VirtualTcpSocketFactory
        + VirtualUdpSocketFactory
        + UdpSessionControlHandler<<S as VirtualUdpSocketFactory>::Socket>,
    E: ConnectorEnvironment<<S as VirtualTcpSocketFactory>::Socket>,
{
    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        self.environment.collect_ip_addrs(context).await
    }

    async fn collect_foreign_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        self.environment.collect_foreign_ip_addrs(context).await
    }

    fn mapped_listeners(&self) -> Vec<Url> {
        self.environment.mapped_listeners()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.environment.is_local_ip(ip)
    }

    fn is_protected_tcp_port(&self, port: u16) -> bool {
        self.environment.is_protected_tcp_port(port)
    }

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.environment.is_easytier_managed_ipv6(ip)
    }

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        self.environment.preferred_ipv6_source(ip, context).await
    }

    async fn preferred_foreign_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        self.environment
            .preferred_foreign_ipv6_source(ip, context)
            .await
    }
}
