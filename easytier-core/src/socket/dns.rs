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
}
