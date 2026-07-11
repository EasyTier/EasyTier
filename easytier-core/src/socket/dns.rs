use std::net::IpAddr;

use async_trait::async_trait;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// Resolves non-address DNS records used by EasyTier endpoint discovery.
#[async_trait]
pub trait DnsRecordResolver: Send + Sync + 'static {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String>;

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_keeps_host_and_socket_context() {
        let context = SocketContext::default();
        assert_eq!(
            DnsQuery::new("example.com", context.clone()),
            DnsQuery {
                host: "example.com".to_owned(),
                context,
            }
        );
    }

    #[test]
    fn srv_record_keeps_dns_selection_fields() {
        let record = DnsSrvRecord {
            priority: 10,
            weight: 20,
            port: 11010,
            target: "peer.example.com.".to_owned(),
        };

        assert_eq!(record.priority, 10);
        assert_eq!(record.weight, 20);
        assert_eq!(record.port, 11010);
        assert_eq!(record.target, "peer.example.com.");
    }
}
