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
    socket::{
        tcp::{
            TcpConnectOptions, TcpListenOptions, VirtualTcpListenerFactory, VirtualTcpSocketFactory,
        },
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory,
        },
    },
};

use crate::{
    common::{global_ctx::ArcGlobalCtx, network::IPCollector},
    host_runtime::{NativeHostRuntime, native_host_runtime},
    proto::peer_rpc::GetIpListResponse,
    socket::{
        tcp::{RuntimeTcpListener, RuntimeTcpSocket},
        udp::RuntimeUdpSocket,
    },
};

pub(crate) struct RuntimeConnectorHost {
    global_ctx: ArcGlobalCtx,
    runtime: Arc<NativeHostRuntime>,
}

impl RuntimeConnectorHost {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            runtime: native_host_runtime(),
        }
    }
}

#[async_trait]
impl VirtualTcpListenerFactory for RuntimeConnectorHost {
    type Listener = RuntimeTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.runtime.bind_tcp(options).await
    }
}

#[async_trait]
impl VirtualTcpSocketFactory for RuntimeConnectorHost {
    type Socket = RuntimeTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        self.runtime.connect_tcp(options).await
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for RuntimeConnectorHost {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.runtime.bind_udp(options).await
    }
}

#[async_trait]
impl UdpSessionControlHandler<RuntimeUdpSocket> for RuntimeConnectorHost {
    async fn send_v4_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV4,
    ) -> std::io::Result<usize> {
        self.runtime.send_v4_hole_punch(socket, dst_addr).await
    }

    async fn send_v6_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    ) -> std::io::Result<usize> {
        self.runtime
            .send_v6_hole_punch(socket, dst_addr, preferred_src)
            .await
    }
}

#[async_trait]
impl ManualConnectorHost for RuntimeConnectorHost {
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
        let socket = self.global_ctx.net_ns.run(|| {
            let socket = std::net::UdpSocket::bind("[::]:0")?;
            socket.set_nonblocking(true)?;
            std::io::Result::Ok(socket)
        })?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;
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

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.global_ctx.is_ip_easytier_managed_ipv6(ip)
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
