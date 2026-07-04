use std::{
    fmt::Debug,
    net::IpAddr,
    sync::{Arc, LazyLock},
};

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::socket::SocketContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub host: String,
    pub context: SocketContext,
}

impl DnsQuery {
    pub fn new(host: impl Into<String>, context: SocketContext) -> Self {
        Self {
            host: host.into(),
            context,
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>>;
}

#[derive(Debug, thiserror::Error)]
pub enum DnsResolveError {
    #[error("dns resolver is not registered")]
    NotRegistered,
    #[error("dns resolve failed for {query:?}: {source}")]
    Resolve {
        query: DnsQuery,
        source: anyhow::Error,
    },
}

#[derive(Default)]
pub struct DnsResolverRegistry {
    resolver: RwLock<Option<Arc<dyn DnsResolver>>>,
}

impl Debug for DnsResolverRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolverRegistry")
            .field("registered", &self.resolver.read().is_some())
            .finish()
    }
}

impl DnsResolverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, resolver: Arc<dyn DnsResolver>) -> Option<Arc<dyn DnsResolver>> {
        self.resolver.write().replace(resolver)
    }

    pub fn unregister(&self) -> Option<Arc<dyn DnsResolver>> {
        self.resolver.write().take()
    }

    pub async fn resolve(&self, query: DnsQuery) -> Result<Vec<IpAddr>, DnsResolveError> {
        let resolver = self
            .resolver
            .read()
            .clone()
            .ok_or(DnsResolveError::NotRegistered)?;

        resolver
            .resolve(query.clone())
            .await
            .map_err(|source| DnsResolveError::Resolve { query, source })
    }
}

static GLOBAL_DNS_RESOLVER: LazyLock<DnsResolverRegistry> = LazyLock::new(DnsResolverRegistry::new);

pub fn global_dns_resolver() -> &'static DnsResolverRegistry {
    &GLOBAL_DNS_RESOLVER
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticDnsResolver {
        addrs: Vec<IpAddr>,
    }

    #[async_trait]
    impl DnsResolver for StaticDnsResolver {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            Ok(self.addrs.clone())
        }
    }

    #[tokio::test]
    async fn registry_uses_registered_resolver() {
        let registry = DnsResolverRegistry::new();
        let addr = IpAddr::from([127, 0, 0, 1]);
        registry.register(Arc::new(StaticDnsResolver { addrs: vec![addr] }));

        let addrs = registry
            .resolve(DnsQuery::new("example.com", SocketContext::default()))
            .await
            .unwrap();

        assert_eq!(addrs, vec![addr]);
    }

    #[tokio::test]
    async fn registry_reports_missing_resolver() {
        let registry = DnsResolverRegistry::new();
        let error = registry
            .resolve(DnsQuery::new("example.com", SocketContext::default()))
            .await
            .unwrap_err();

        assert!(matches!(error, DnsResolveError::NotRegistered));
    }
}
