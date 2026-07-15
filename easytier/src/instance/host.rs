use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        composite::{ConnectorEnvironment, ConnectorHostAdapter},
        manual::ManualInterfaceAddrs,
        transport::ConnectedByteStream,
    },
    socket::{NetNamespace, SocketContext, udp::PreferredIpv6Source},
};

use crate::{
    common::{global_ctx::ArcGlobalCtx, network::CACHED_IP_LIST_TIMEOUT_SEC},
    host_runtime::{NativeHostRuntime, native_host_runtime},
    proto::peer_rpc::GetIpListResponse,
    socket::tcp::RuntimeTcpSocket,
};

pub(crate) type NativeInstanceHost =
    ConnectorHostAdapter<NativeHostRuntime, NativeInstanceEnvironment>;

/// Instance facts queried by portable connector policy.
///
/// This Adapter never creates or operates sockets. Mechanical network I/O is
/// owned by the process-wide [`NativeHostRuntime`] composed beside it.
pub(crate) struct NativeInstanceEnvironment {
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

impl NativeInstanceEnvironment {
    fn new(global_ctx: ArcGlobalCtx, runtime: Arc<NativeHostRuntime>) -> Self {
        Self {
            global_ctx,
            runtime,
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

    fn valid_public_ipv6_candidate(ip: Ipv6Addr) -> bool {
        !(ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_unique_local()
            || ip.is_unicast_link_local()
            || ip.is_multicast())
    }
}

pub(crate) fn native_instance_host(global_ctx: ArcGlobalCtx) -> Arc<NativeInstanceHost> {
    let runtime = native_host_runtime();
    Arc::new(ConnectorHostAdapter::new(
        runtime.clone(),
        Arc::new(NativeInstanceEnvironment::new(global_ctx, runtime)),
    ))
}

#[async_trait]
impl ConnectorEnvironment<RuntimeTcpSocket> for NativeInstanceEnvironment {
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

    async fn collect_ip_addrs(&self, _context: &SocketContext) -> GetIpListResponse {
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
        if self.is_easytier_managed_ipv6(&ip) || !Self::valid_public_ipv6_candidate(ip) {
            return None;
        }
        self.runtime.preferred_ipv6_source(ip, context).await
    }

    async fn preferred_foreign_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        if !Self::valid_public_ipv6_candidate(ip) {
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
        connectivity::composite::ConnectorEnvironment as _,
        socket::{NetNamespace, SocketContext},
    };

    use crate::{
        common::{
            config::TomlConfigLoader, global_ctx::GlobalCtx, network::CACHED_IP_LIST_TIMEOUT_SEC,
        },
        proto::peer_rpc::GetIpListResponse,
    };

    use super::{CachedInterfaceAddrs, NativeInstanceEnvironment};

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
        let runtime = crate::host_runtime::native_host_runtime();
        let environment = NativeInstanceEnvironment::new(global_ctx, runtime);

        environment
            .collect_ip_addrs(&SocketContext::default())
            .await;

        assert!(environment.foreign_interface_cache.lock().await.is_none());
    }
}
