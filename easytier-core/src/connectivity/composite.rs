//! Composes process-wide socket capabilities with instance-scoped network facts.

use std::{
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
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
        udp::{PreferredIpv6Source, UdpBindOptions, VirtualUdpSocketFactory},
    },
};

const INTERFACE_ADDR_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct CachedInterfaceAddrs {
    collected_at: Instant,
    response: GetIpListResponse,
}

struct InterfaceAddrCacheEntry {
    context: SocketContext,
    value: Arc<tokio::sync::Mutex<Option<CachedInterfaceAddrs>>>,
}

struct InterfaceAddrCache {
    entries: tokio::sync::Mutex<Vec<InterfaceAddrCacheEntry>>,
    ttl: Duration,
}

impl InterfaceAddrCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: tokio::sync::Mutex::new(Vec::new()),
            ttl,
        }
    }

    async fn get_or_collect<F, Fut>(&self, context: &SocketContext, collect: F) -> GetIpListResponse
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = GetIpListResponse>,
    {
        let value = {
            let mut entries = self.entries.lock().await;
            entries.retain(|entry| {
                if Arc::strong_count(&entry.value) > 1 {
                    return true;
                }
                entry.value.try_lock().map_or(true, |cached| {
                    cached
                        .as_ref()
                        .is_some_and(|cached| cached.collected_at.elapsed() < self.ttl)
                })
            });
            if let Some(entry) = entries.iter().find(|entry| &entry.context == context) {
                entry.value.clone()
            } else {
                let value = Arc::new(tokio::sync::Mutex::new(None));
                entries.push(InterfaceAddrCacheEntry {
                    context: context.clone(),
                    value: value.clone(),
                });
                value
            }
        };

        // Only collectors for the same socket context share this lock. A slow
        // namespace observation cannot block fresh hits or refreshes elsewhere.
        let mut cached = value.lock().await;
        if let Some(cached) = cached
            .as_ref()
            .filter(|cached| cached.collected_at.elapsed() < self.ttl)
        {
            return cached.response.clone();
        }

        let response = collect().await;
        *cached = Some(CachedInterfaceAddrs {
            collected_at: Instant::now(),
            response: response.clone(),
        });
        response
    }
}

/// Mechanical connector operations supplied by one process-wide runtime.
#[async_trait]
pub trait ConnectorRuntime: VirtualTcpSocketFactory + Send + Sync + 'static {
    async fn connect_byte_stream(
        &self,
        url: &Url,
    ) -> anyhow::Result<ConnectedByteStream<Self::Socket>>;

    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr>;

    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse;

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source>;
}

/// Instance facts consumed by portable connector policy.
///
/// Socket creation, route probing and host interface I/O are deliberately
/// absent; those belong to the process-wide [`ConnectorRuntime`].
pub trait ConnectorEnvironment: Send + Sync + 'static {
    fn socket_context(&self) -> SocketContext;

    fn mapped_listeners(&self) -> Vec<Url>;
    fn is_local_ip(&self, ip: &IpAddr) -> bool;
}

/// Deep adapter that combines one socket runtime with one instance environment.
pub struct ConnectorHostAdapter<S, E> {
    sockets: Arc<S>,
    environment: Arc<E>,
    interface_addrs: InterfaceAddrCache,
}

impl<S, E> ConnectorHostAdapter<S, E> {
    pub fn new(sockets: Arc<S>, environment: Arc<E>) -> Self {
        Self {
            sockets,
            environment,
            interface_addrs: InterfaceAddrCache::new(INTERFACE_ADDR_CACHE_TTL),
        }
    }
}

impl<S, E> ConnectorHostAdapter<S, E>
where
    S: ConnectorRuntime,
{
    async fn cached_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        self.interface_addrs
            .get_or_collect(context, || self.sockets.collect_ip_addrs(context))
            .await
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
impl<S, E> ManualConnectorHost for ConnectorHostAdapter<S, E>
where
    S: ConnectorRuntime + VirtualUdpSocketFactory,
    E: ConnectorEnvironment,
{
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        self.sockets
            .local_addr_for_remote(remote_addr, context)
            .await
    }

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
        let addrs = self
            .cached_ip_addrs(&self.environment.socket_context())
            .await;
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
        url: &Url,
    ) -> anyhow::Result<ConnectedByteStream<<Self as VirtualTcpSocketFactory>::Socket>> {
        self.sockets.connect_byte_stream(url).await
    }
}

#[async_trait]
impl<S, E> DirectConnectorHost for ConnectorHostAdapter<S, E>
where
    S: ConnectorRuntime + VirtualUdpSocketFactory,
    E: ConnectorEnvironment,
{
    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        self.cached_ip_addrs(context).await
    }

    async fn collect_foreign_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        self.cached_ip_addrs(context).await
    }

    fn mapped_listeners(&self) -> Vec<Url> {
        self.environment.mapped_listeners()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.environment.is_local_ip(ip)
    }

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        if !valid_public_ipv6_candidate(ip) {
            return None;
        }
        self.sockets.preferred_ipv6_source(ip, context).await
    }

    async fn preferred_foreign_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        if !valid_public_ipv6_candidate(ip) {
            return None;
        }
        self.sockets.preferred_ipv6_source(ip, context).await
    }
}

fn valid_public_ipv6_candidate(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::oneshot;

    use super::*;
    use crate::socket::{IpVersion, NetNamespace};

    #[tokio::test]
    async fn concurrent_cache_misses_share_one_collection() {
        let cache = Arc::new(InterfaceAddrCache::new(Duration::from_secs(60)));
        let context = SocketContext::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();

        let first = tokio::spawn({
            let cache = cache.clone();
            let context = context.clone();
            let calls = calls.clone();
            async move {
                cache
                    .get_or_collect(&context, || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let _ = started_tx.send(());
                        let _ = release_rx.await;
                        GetIpListResponse::default()
                    })
                    .await
            }
        });
        started_rx.await.unwrap();

        let (second_started_tx, second_started_rx) = oneshot::channel();
        let second = tokio::spawn({
            let cache = cache.clone();
            let context = context.clone();
            let calls = calls.clone();
            async move {
                let _ = second_started_tx.send(());
                cache
                    .get_or_collect(&context, || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        GetIpListResponse::default()
                    })
                    .await
            }
        });
        second_started_rx.await.unwrap();
        tokio::task::yield_now().await;
        let _ = release_tx.send(());

        first.await.unwrap();
        second.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_keys_include_the_complete_socket_context() {
        let cache = InterfaceAddrCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        let contexts = [
            SocketContext::default(),
            SocketContext::default().with_ip_version(IpVersion::V4),
            SocketContext::default().with_socket_mark(Some(7)),
            SocketContext::default().with_netns(Some(NetNamespace::new("foreign-a"))),
        ];

        for context in &contexts {
            cache
                .get_or_collect(context, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    GetIpListResponse::default()
                })
                .await;
        }
        cache
            .get_or_collect(&contexts[0], || async {
                calls.fetch_add(1, Ordering::SeqCst);
                GetIpListResponse::default()
            })
            .await;

        assert_eq!(calls.load(Ordering::SeqCst), contexts.len());
    }

    #[tokio::test]
    async fn slow_collection_does_not_block_a_different_context() {
        let cache = Arc::new(InterfaceAddrCache::new(Duration::from_secs(60)));
        let slow_context = SocketContext::default().with_socket_mark(Some(1));
        let other_context = SocketContext::default().with_socket_mark(Some(2));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let slow = tokio::spawn({
            let cache = cache.clone();
            async move {
                cache
                    .get_or_collect(&slow_context, || async move {
                        let _ = started_tx.send(());
                        let _ = release_rx.await;
                        GetIpListResponse::default()
                    })
                    .await
            }
        });
        started_rx.await.unwrap();

        tokio::time::timeout(
            Duration::from_millis(100),
            cache.get_or_collect(&other_context, || async { GetIpListResponse::default() }),
        )
        .await
        .expect("different socket contexts must collect independently");

        let _ = release_tx.send(());
        slow.await.unwrap();
    }

    #[tokio::test]
    async fn slow_collection_does_not_block_a_fresh_hit() {
        let cache = Arc::new(InterfaceAddrCache::new(Duration::from_secs(60)));
        let cached_context = SocketContext::default().with_socket_mark(Some(1));
        let slow_context = SocketContext::default().with_socket_mark(Some(2));
        cache
            .get_or_collect(&cached_context, || async { GetIpListResponse::default() })
            .await;

        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let slow = tokio::spawn({
            let cache = cache.clone();
            async move {
                cache
                    .get_or_collect(&slow_context, || async move {
                        let _ = started_tx.send(());
                        let _ = release_rx.await;
                        GetIpListResponse::default()
                    })
                    .await
            }
        });
        started_rx.await.unwrap();

        tokio::time::timeout(
            Duration::from_millis(100),
            cache.get_or_collect(&cached_context, || async {
                panic!("fresh cache hit must not recollect")
            }),
        )
        .await
        .expect("fresh hit must not wait for another socket context");

        let _ = release_tx.send(());
        slow.await.unwrap();
    }

    #[tokio::test]
    async fn expired_entries_are_recollected() {
        let cache = InterfaceAddrCache::new(Duration::ZERO);
        let calls = AtomicUsize::new(0);
        let context = SocketContext::default();

        for _ in 0..2 {
            cache
                .get_or_collect(&context, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    GetIpListResponse::default()
                })
                .await;
        }

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
