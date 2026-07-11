//! Composition adapter for connector logic driven by host-owned sockets.

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
    hole_punch::tcp::{TcpHolePunchEnvironment, TcpHolePunchHost},
    proto::{common::NatType, peer_rpc::GetIpListResponse},
    socket::{
        host::{
            HostSocketRuntime, HostTcpStream,
            factory::{HostSocketBackend, HostSocketFactory},
            listener::{HostTcpListener, HostTcpListenerBackend, HostTcpListenerFactory},
            udp::HostUdpSocket,
        },
        tcp::{
            TcpConnectOptions, TcpListenOptions, VirtualTcpListenerFactory, VirtualTcpSocketFactory,
        },
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory,
        },
    },
};

/// Non-socket capabilities required by manual connectivity.
#[async_trait]
pub trait ManualConnectorEnvironment: Send + Sync + 'static {
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr>;

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs>;

    async fn connect_byte_stream(
        &self,
        url: &Url,
    ) -> anyhow::Result<ConnectedByteStream<HostTcpStream>> {
        anyhow::bail!("host does not support external byte stream: {url}")
    }
}

/// Runtime state and address-policy capabilities required by direct connectivity.
#[async_trait]
pub trait DirectConnectorEnvironment: ManualConnectorEnvironment {
    async fn collect_ip_addrs(&self) -> anyhow::Result<GetIpListResponse>;

    fn mapped_listeners(&self) -> Vec<Url>;

    fn running_listeners(&self) -> Vec<Url>;

    fn is_local_ip(&self, ip: &IpAddr) -> bool;

    fn is_protected_tcp_port(&self, port: u16) -> bool;

    fn stun_public_ips(&self) -> Vec<IpAddr>;

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool;

    async fn udp_port_mapping(&self, socket: Arc<HostUdpSocket>) -> anyhow::Result<SocketAddr>;

    async fn preferred_ipv6_source(&self, ip: Ipv6Addr) -> Option<PreferredIpv6Source>;
}

/// One host handle domain capable of creating and operating connector sockets.
pub trait HostConnectorSocketBackend: HostSocketBackend + HostTcpListenerBackend {}

impl<T> HostConnectorSocketBackend for T where T: HostSocketBackend + HostTcpListenerBackend {}

/// Recombines mechanical host sockets with injected connector environment state.
///
/// This keeps the existing connector manager interfaces stable while ensuring
/// TCP connect, UDP bind, TCP listen, and accepted streams use one host backend.
pub struct HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
{
    sockets: HostSocketFactory<B>,
    listeners: HostTcpListenerFactory<B>,
    environment: Arc<E>,
}

impl<B, E> HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
{
    pub fn new(runtime: HostSocketRuntime, backend: Arc<B>, environment: Arc<E>) -> Self {
        Self {
            sockets: HostSocketFactory::new(runtime.clone(), backend.clone()),
            listeners: HostTcpListenerFactory::new(runtime, backend),
            environment,
        }
    }
}

#[async_trait]
impl<B, E> VirtualTcpSocketFactory for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: Send + Sync + 'static,
{
    type Socket = HostTcpStream;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        self.sockets.connect_tcp(options).await
    }
}

#[async_trait]
impl<B, E> VirtualUdpSocketFactory for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: Send + Sync + 'static,
{
    type Socket = HostUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.sockets.bind_udp(options).await
    }
}

#[async_trait]
impl<B, E> VirtualTcpListenerFactory for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: Send + Sync + 'static,
{
    type Listener = HostTcpListener<B>;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.listeners.bind_tcp(options).await
    }
}

#[async_trait]
impl<B, E> UdpSessionControlHandler<HostUdpSocket> for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: UdpSessionControlHandler<HostUdpSocket>,
{
    async fn send_v4_hole_punch(
        &self,
        socket: Arc<HostUdpSocket>,
        dst_addr: SocketAddrV4,
    ) -> std::io::Result<usize> {
        self.environment.send_v4_hole_punch(socket, dst_addr).await
    }

    async fn send_v6_hole_punch(
        &self,
        socket: Arc<HostUdpSocket>,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    ) -> std::io::Result<usize> {
        self.environment
            .send_v6_hole_punch(socket, dst_addr, preferred_src)
            .await
    }
}

#[async_trait]
impl<B, E> ManualConnectorHost for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: ManualConnectorEnvironment + UdpSessionControlHandler<HostUdpSocket>,
{
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
        self.environment.local_addr_for_remote(remote_addr).await
    }

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
        self.environment.interface_addrs().await
    }

    async fn connect_byte_stream(
        &self,
        url: &Url,
    ) -> anyhow::Result<ConnectedByteStream<HostTcpStream>> {
        self.environment.connect_byte_stream(url).await
    }
}

#[async_trait]
impl<B, E> DirectConnectorHost for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: DirectConnectorEnvironment + UdpSessionControlHandler<HostUdpSocket>,
{
    async fn collect_ip_addrs(&self) -> anyhow::Result<GetIpListResponse> {
        self.environment.collect_ip_addrs().await
    }

    fn mapped_listeners(&self) -> Vec<Url> {
        self.environment.mapped_listeners()
    }

    fn running_listeners(&self) -> Vec<Url> {
        self.environment.running_listeners()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.environment.is_local_ip(ip)
    }

    fn is_protected_tcp_port(&self, port: u16) -> bool {
        self.environment.is_protected_tcp_port(port)
    }

    fn stun_public_ips(&self) -> Vec<IpAddr> {
        self.environment.stun_public_ips()
    }

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.environment.is_easytier_managed_ipv6(ip)
    }

    async fn udp_port_mapping(
        &self,
        socket: Arc<<Self as VirtualUdpSocketFactory>::Socket>,
    ) -> anyhow::Result<SocketAddr> {
        self.environment.udp_port_mapping(socket).await
    }

    async fn preferred_ipv6_source(&self, ip: Ipv6Addr) -> Option<PreferredIpv6Source> {
        self.environment.preferred_ipv6_source(ip).await
    }
}

#[async_trait]
impl<B, E> TcpHolePunchHost for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: TcpHolePunchEnvironment + Send + Sync + 'static,
{
    fn tcp_nat_type(&self) -> NatType {
        self.environment.tcp_nat_type()
    }

    async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        self.environment.tcp_port_mapping(local_port).await
    }
}
