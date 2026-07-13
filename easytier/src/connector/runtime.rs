use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        direct::DirectConnectorHost,
        manual::{ManualConnectorHost, ManualInterfaceAddrs},
        transport::ConnectedByteStream,
    },
    hole_punch::tcp::TcpHolePunchHost,
    proto::common::NatType,
    socket::{
        tcp::{
            TcpConnectOptions, TcpListenOptions, TcpSocketPurpose, VirtualTcpListenerFactory,
            VirtualTcpSocketFactory,
        },
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory,
        },
    },
    tunnel::ring::RingTunnelRegistry,
};

use crate::{
    common::{global_ctx::ArcGlobalCtx, network::IPCollector, stun::StunInfoCollectorTrait},
    proto::peer_rpc::GetIpListResponse,
    socket::tcp::{self, RuntimeTcpListener, RuntimeTcpListenerFactory, RuntimeTcpSocket},
    tunnel::udp::{RuntimeUdpSessionControlHandler, RuntimeUdpSocket, RuntimeUdpSocketFactory},
};

pub(crate) struct RuntimeConnectorHost {
    global_ctx: ArcGlobalCtx,
    ring_registry: Arc<RingTunnelRegistry>,
    tcp_listener_factory: RuntimeTcpListenerFactory,
    udp_socket_factory: RuntimeUdpSocketFactory,
}

impl RuntimeConnectorHost {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self::new_with_ring_registry(global_ctx, Arc::new(RingTunnelRegistry::default()))
    }

    pub(crate) fn new_with_ring_registry(
        global_ctx: ArcGlobalCtx,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        Self {
            tcp_listener_factory: RuntimeTcpListenerFactory::new(global_ctx.net_ns.clone()),
            udp_socket_factory: RuntimeUdpSocketFactory::new(global_ctx.net_ns.clone()),
            global_ctx,
            ring_registry,
        }
    }
}

#[async_trait]
impl TcpHolePunchHost for RuntimeConnectorHost {
    fn tcp_nat_type(&self) -> NatType {
        NatType::try_from(
            self.global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown)
    }

    async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        self.global_ctx
            .get_stun_info_collector()
            .get_tcp_port_mapping(local_port)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait]
impl VirtualTcpListenerFactory for RuntimeConnectorHost {
    type Listener = RuntimeTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.tcp_listener_factory.bind_tcp(options).await
    }
}

#[async_trait]
impl VirtualTcpSocketFactory for RuntimeConnectorHost {
    type Socket = RuntimeTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        #[cfg(feature = "faketcp")]
        if options.purpose == TcpSocketPurpose::FakeTcp {
            let remote_addr = options.remote_addr;
            let socket_mark = options.bind.socket_mark;
            let socket = self
                .global_ctx
                .net_ns
                .run_async(|| async move {
                    crate::tunnel::fake_tcp::connect_socket(remote_addr, socket_mark).await
                })
                .await?;
            return Ok(RuntimeTcpSocket::from_fake_tcp(socket));
        }

        #[cfg(not(feature = "faketcp"))]
        if options.purpose == TcpSocketPurpose::FakeTcp {
            anyhow::bail!("FakeTCP socket support is disabled")
        }

        self.global_ctx
            .net_ns
            .run_async(
                || async move { tcp::connect_tcp(options).await.map_err(anyhow::Error::from) },
            )
            .await
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for RuntimeConnectorHost {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        let socket = self.udp_socket_factory.bind_udp(options).await?;
        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.socket().as_ref())?;
        Ok(socket)
    }
}

#[async_trait]
impl UdpSessionControlHandler<RuntimeUdpSocket> for RuntimeConnectorHost {
    async fn send_v4_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV4,
    ) -> std::io::Result<usize> {
        RuntimeUdpSessionControlHandler
            .send_v4_hole_punch(socket, dst_addr)
            .await
    }

    async fn send_v6_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    ) -> std::io::Result<usize> {
        RuntimeUdpSessionControlHandler
            .send_v6_hole_punch(socket, dst_addr, preferred_src)
            .await
    }
}

#[async_trait]
impl ManualConnectorHost for RuntimeConnectorHost {
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
        let socket = self
            .global_ctx
            .net_ns
            .run_async(|| tokio::net::UdpSocket::bind("[::]:0"))
            .await?;
        socket.connect(remote_addr).await?;
        Ok(socket.local_addr()?)
    }

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
        let addrs = self.global_ctx.get_ip_collector().collect_ip_addrs().await;
        Ok(ManualInterfaceAddrs {
            interface_ipv4s: addrs
                .interface_ipv4s
                .into_iter()
                .map(std::net::Ipv4Addr::from)
                .collect(),
            interface_ipv6s: addrs
                .interface_ipv6s
                .into_iter()
                .map(std::net::Ipv6Addr::from)
                .collect(),
            public_ipv6: addrs.public_ipv6.map(std::net::Ipv6Addr::from),
        })
    }

    async fn connect_byte_stream(
        &self,
        url: &url::Url,
    ) -> anyhow::Result<ConnectedByteStream<RuntimeTcpSocket>> {
        if url.scheme() == "ring" {
            let remote_id = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("ring URL has no peer id: {url}"))?
                .parse()?;
            let dialed = self.ring_registry.connect(remote_id)?;
            let local_url = format!("ring://{}", dialed.local_id).parse()?;
            let socket = RuntimeTcpSocket::from_ring(dialed.socket)?;
            return Ok(ConnectedByteStream::new(
                socket,
                Some(local_url),
                url.clone(),
                Some(url.clone()),
            ));
        }

        #[cfg(unix)]
        if url.scheme() == "unix" {
            let stream = tokio::net::UnixStream::connect(url.path()).await?;
            let local_url = stream
                .local_addr()
                .ok()
                .and_then(crate::tunnel::unix::url_from_unix_socket_addr);
            return Ok(ConnectedByteStream::new(
                RuntimeTcpSocket::from_unix(stream),
                local_url,
                url.clone(),
                Some(url.clone()),
            ));
        }

        anyhow::bail!("unsupported runtime byte stream: {url}")
    }
}

#[async_trait]
impl DirectConnectorHost for RuntimeConnectorHost {
    async fn collect_ip_addrs(&self) -> anyhow::Result<GetIpListResponse> {
        Ok(self.global_ctx.get_ip_collector().collect_ip_addrs().await)
    }

    fn mapped_listeners(&self) -> Vec<url::Url> {
        self.global_ctx.config.get_mapped_listeners()
    }

    fn running_listeners(&self) -> Vec<url::Url> {
        self.global_ctx.get_running_listeners()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_local_ip(ip)
    }

    fn is_protected_tcp_port(&self, port: u16) -> bool {
        self.global_ctx.is_protected_tcp_port(port)
    }

    fn stun_public_ips(&self) -> Vec<IpAddr> {
        self.global_ctx
            .get_stun_info_collector()
            .get_stun_info()
            .public_ip
            .into_iter()
            .filter_map(|ip| ip.parse().ok())
            .collect()
    }

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.global_ctx.is_ip_easytier_managed_ipv6(ip)
    }

    async fn udp_port_mapping(
        &self,
        socket: Arc<<Self as VirtualUdpSocketFactory>::Socket>,
    ) -> anyhow::Result<SocketAddr> {
        self.global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping_with_socket(socket.socket())
            .await
            .map_err(anyhow::Error::from)
    }

    async fn preferred_ipv6_source(&self, ip: Ipv6Addr) -> Option<PreferredIpv6Source> {
        if self.global_ctx.is_ip_easytier_managed_ipv6(&ip)
            || ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_unique_local()
            || ip.is_unicast_link_local()
            || ip.is_multicast()
        {
            return None;
        }

        IPCollector::collect_interfaces(self.global_ctx.net_ns.clone(), false)
            .await
            .into_iter()
            .find(|interface| {
                interface
                    .ips
                    .iter()
                    .any(|local| matches!(local.ip(), IpAddr::V6(local_ip) if local_ip == ip))
            })
            .map(|interface| PreferredIpv6Source {
                ip,
                ifindex: interface.index,
            })
    }
}
