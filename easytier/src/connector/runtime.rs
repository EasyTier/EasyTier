use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        direct::DirectConnectorHost,
        manual::{ManualConnectorHost, ManualInterfaceAddrs},
        transport::ConnectedByteStream,
    },
    socket::{
        NetNamespace, SocketContext,
        tcp::{
            TcpConnectOptions, TcpListenOptions, VirtualTcpListenerFactory, VirtualTcpSocketFactory,
        },
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory,
        },
    },
};

use crate::{
    common::{global_ctx::ArcGlobalCtx, network::CACHED_IP_LIST_TIMEOUT_SEC},
    host_runtime::{NativeHostRuntime, native_host_runtime},
    proto::peer_rpc::GetIpListResponse,
    socket::{
        tcp::{RuntimeTcpListener, RuntimeTcpSocket},
        udp::RuntimeUdpSocket,
    },
};

/// Instance-scoped connector facts projected onto the process-wide host runtime.
///
/// This is not an OS capability owner: all real socket operations delegate to
/// [`NativeHostRuntime`]. `GlobalCtx` is retained only for instance facts such as
/// current listeners, protected ports, and collected interface addresses.
pub(crate) struct RuntimeConnectorHost {
    global_ctx: ArcGlobalCtx,
    runtime: Arc<NativeHostRuntime>,
    foreign_interface_cache: tokio::sync::Mutex<Option<CachedInterfaceAddrs>>,
}

struct CachedInterfaceAddrs {
    netns: Option<NetNamespace>,
    collected_at: Instant,
    response: GetIpListResponse,
}

impl CachedInterfaceAddrs {
    fn is_fresh_for(&self, context: &SocketContext) -> bool {
        self.netns.as_ref() == context.netns.as_ref()
            && self.collected_at.elapsed() < Duration::from_secs(CACHED_IP_LIST_TIMEOUT_SEC)
    }
}

impl RuntimeConnectorHost {
    fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            runtime: native_host_runtime(),
            foreign_interface_cache: tokio::sync::Mutex::new(None),
        }
    }

    async fn collect_foreign_interface_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        let mut cache = self.foreign_interface_cache.lock().await;
        if let Some(cached) = cache.as_ref().filter(|cached| cached.is_fresh_for(context)) {
            return cached.response.clone();
        }

        let response = self.runtime.collect_ip_addrs(context).await;
        *cache = Some(CachedInterfaceAddrs {
            netns: context.netns.clone(),
            collected_at: Instant::now(),
            response: response.clone(),
        });
        response
    }
}

pub(crate) fn runtime_connector_host(global_ctx: ArcGlobalCtx) -> Arc<RuntimeConnectorHost> {
    Arc::new(RuntimeConnectorHost::new(global_ctx))
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
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        self.runtime
            .local_addr_for_remote(remote_addr, context)
            .await
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
        self.runtime.connect_byte_stream(url).await
    }
}

#[async_trait]
impl DirectConnectorHost for RuntimeConnectorHost {
    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        let _ = context;
        self.global_ctx.get_ip_collector().collect_ip_addrs().await
    }

    async fn collect_foreign_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        let mut response = self.global_ctx.get_ip_collector().collect_ip_addrs().await;
        let local = self.collect_foreign_interface_addrs(context).await;
        response.interface_ipv4s = local.interface_ipv4s;
        response.interface_ipv6s = local.interface_ipv6s;
        response
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

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        if self.is_easytier_managed_ipv6(&ip)
            || ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_unique_local()
            || ip.is_unicast_link_local()
            || ip.is_multicast()
        {
            return None;
        }

        self.runtime.preferred_ipv6_source(ip, context).await
    }

    async fn preferred_foreign_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_unique_local()
            || ip.is_unicast_link_local()
            || ip.is_multicast()
        {
            return None;
        }

        self.runtime.preferred_ipv6_source(ip, context).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use easytier_core::{
        connectivity::direct::DirectConnectorHost as _,
        socket::{NetNamespace, SocketContext},
    };

    use crate::{
        common::{
            config::TomlConfigLoader, global_ctx::GlobalCtx, network::CACHED_IP_LIST_TIMEOUT_SEC,
        },
        proto::peer_rpc::GetIpListResponse,
    };

    use super::{CachedInterfaceAddrs, runtime_connector_host};

    #[test]
    fn foreign_interface_cache_is_keyed_by_netns_and_ttl() {
        let context = SocketContext::default().with_netns(Some(NetNamespace::new("foreign-a")));
        let cached = CachedInterfaceAddrs {
            netns: context.netns.clone(),
            collected_at: Instant::now(),
            response: GetIpListResponse::default(),
        };

        assert!(cached.is_fresh_for(&context));
        assert!(!cached.is_fresh_for(
            &SocketContext::default().with_netns(Some(NetNamespace::new("foreign-b")))
        ));

        let expired = CachedInterfaceAddrs {
            collected_at: Instant::now() - Duration::from_secs(CACHED_IP_LIST_TIMEOUT_SEC + 1),
            ..cached
        };
        assert!(!expired.is_fresh_for(&context));
    }

    #[tokio::test]
    async fn instance_address_view_does_not_populate_foreign_cache() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfigLoader::default()));
        let host = runtime_connector_host(global_ctx);

        host.collect_ip_addrs(&SocketContext::default()).await;

        assert!(host.foreign_interface_cache.lock().await.is_none());
    }
}
