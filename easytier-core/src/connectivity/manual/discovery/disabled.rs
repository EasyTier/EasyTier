use std::{marker::PhantomData, sync::Arc};

use url::Url;

use crate::{
    host::dns::{DnsRecordResolver, DnsResolver},
    socket::tcp::VirtualTcpSocketFactory,
};

use super::super::ManualEndpointResolver;
use super::ManualEndpointDiscoveryConfig;

pub(crate) struct CoreManualEndpointResolver<H>
where
    H: VirtualTcpSocketFactory,
{
    _host: PhantomData<fn() -> H>,
}

impl<H> CoreManualEndpointResolver<H>
where
    H: VirtualTcpSocketFactory,
{
    pub fn new(
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        dns_records: Arc<dyn DnsRecordResolver>,
        config: ManualEndpointDiscoveryConfig,
    ) -> Self {
        let _ = (host, dns, dns_records, config);
        Self { _host: PhantomData }
    }
}

#[async_trait::async_trait]
impl<H> ManualEndpointResolver for CoreManualEndpointResolver<H>
where
    H: VirtualTcpSocketFactory,
{
    async fn resolve_endpoint(&self, url: &Url) -> anyhow::Result<Url> {
        anyhow::bail!("endpoint discovery is disabled for {url}")
    }
}
