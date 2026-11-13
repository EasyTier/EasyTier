use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::socket::{IpVersion, SocketContext, tcp::TcpBindOptions};

#[cfg(feature = "endpoint-discovery")]
mod implementation;

#[cfg(feature = "endpoint-discovery")]
pub(crate) use implementation::CoreManualEndpointResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualEndpointDiscoveryConfig {
    pub user_agent: String,
    pub network_name: String,
    pub http_timeout: Duration,
    pub http_ip_version: IpVersion,
    pub http_tcp_bind: TcpBindOptions,
    pub dns_record_context: SocketContext,
    pub srv_protocols: Vec<String>,
}

impl Default for ManualEndpointDiscoveryConfig {
    fn default() -> Self {
        Self {
            user_agent: "easytier-core".to_owned(),
            network_name: String::new(),
            http_timeout: Duration::from_secs(20),
            http_ip_version: IpVersion::Both,
            http_tcp_bind: TcpBindOptions::default(),
            dns_record_context: SocketContext::default(),
            srv_protocols: vec!["tcp".to_owned(), "udp".to_owned()],
        }
    }
}

#[cfg(not(feature = "endpoint-discovery"))]
pub(crate) struct CoreManualEndpointResolver<H>
where
    H: crate::socket::tcp::VirtualTcpSocketFactory,
{
    _host: std::marker::PhantomData<fn() -> H>,
}

#[cfg(not(feature = "endpoint-discovery"))]
impl<H> CoreManualEndpointResolver<H>
where
    H: crate::socket::tcp::VirtualTcpSocketFactory,
{
    pub fn new(
        host: std::sync::Arc<H>,
        dns: std::sync::Arc<dyn crate::host::dns::DnsResolver>,
        dns_records: std::sync::Arc<dyn crate::host::dns::DnsRecordResolver>,
        config: ManualEndpointDiscoveryConfig,
    ) -> Self {
        let _ = (host, dns, dns_records, config);
        Self {
            _host: std::marker::PhantomData,
        }
    }
}

#[cfg(not(feature = "endpoint-discovery"))]
#[async_trait::async_trait]
impl<H> super::ManualEndpointResolver for CoreManualEndpointResolver<H>
where
    H: crate::socket::tcp::VirtualTcpSocketFactory,
{
    async fn resolve_endpoint(&self, url: &url::Url) -> anyhow::Result<url::Url> {
        anyhow::bail!("endpoint discovery is disabled for {url}")
    }
}
