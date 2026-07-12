use std::{net::SocketAddr, sync::Arc};

use super::{create_connector_by_url, http_connector::TunnelWithInfo};
use crate::{
    common::{dns::RuntimeDnsResolver, error::Error, global_ctx::ArcGlobalCtx},
    proto::common::TunnelInfo,
    tunnel::{IpScheme, IpVersion, Tunnel, TunnelConnector, TunnelError, TunnelScheme},
};
use anyhow::Context;
use easytier_core::{
    connectivity::manual::discovery, socket::SocketContext, tunnel::ring::RingTunnelRegistry,
};
use strum::VariantArray;

pub struct DnsTunnelConnector {
    scheme: TunnelScheme,
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
    ring_registry: Arc<RingTunnelRegistry>,
    ip_version: IpVersion,
}

impl std::fmt::Debug for DnsTunnelConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnsTunnelConnector")
            .field("scheme", &self.scheme)
            .field("addr", &self.addr)
            .field("bind_addrs", &self.bind_addrs)
            .field("ip_version", &self.ip_version)
            .finish_non_exhaustive()
    }
}

impl DnsTunnelConnector {
    pub fn new(
        addr: url::Url,
        global_ctx: ArcGlobalCtx,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        Self {
            scheme: (&addr).try_into().unwrap(),
            addr,
            bind_addrs: Vec::new(),
            global_ctx,
            ring_registry,
            ip_version: IpVersion::Both,
        }
    }

    #[tracing::instrument(ret, err)]
    pub async fn resolve_txt_endpoint(&self, domain_name: &str) -> Result<url::Url, Error> {
        discovery::resolve_txt_endpoint(
            &RuntimeDnsResolver::new(),
            domain_name,
            SocketContext::default(),
        )
        .await
        .map_err(Into::into)
    }

    pub async fn handle_txt_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        let url = self.resolve_txt_endpoint(domain_name).await?;
        create_connector_by_url(
            url.as_str(),
            &self.global_ctx,
            self.ip_version,
            self.ring_registry.clone(),
        )
        .await
    }

    #[tracing::instrument(ret, err)]
    pub async fn resolve_srv_endpoint(&self, domain_name: &str) -> Result<url::Url, Error> {
        let protocols = IpScheme::VARIANTS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        discovery::resolve_srv_endpoint(
            &RuntimeDnsResolver::new(),
            domain_name,
            &protocols,
            SocketContext::default(),
        )
        .await
        .map_err(Into::into)
    }

    pub async fn handle_srv_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        let url = self.resolve_srv_endpoint(domain_name).await?;
        create_connector_by_url(
            url.as_str(),
            &self.global_ctx,
            self.ip_version,
            self.ring_registry.clone(),
        )
        .await
    }
}

#[async_trait::async_trait]
impl super::TunnelConnector for DnsTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let mut conn = match self.scheme {
            TunnelScheme::Txt => self
                .handle_txt_record(
                    self.addr
                        .host_str()
                        .as_ref()
                        .ok_or(anyhow::anyhow!("host should not be empty in txt url"))?,
                )
                .await
                .with_context(|| "get txt record url failed")?,
            TunnelScheme::Srv => self
                .handle_srv_record(
                    self.addr
                        .host_str()
                        .as_ref()
                        .ok_or(anyhow::anyhow!("host should not be empty in srv url"))?,
                )
                .await
                .with_context(|| "get srv record url failed")?,
            _ => return Err(anyhow::anyhow!("unsupported dns scheme: {:?}", self.scheme).into()),
        };
        let t = conn.connect().await?;
        let info = t.info().unwrap_or_default();
        Ok(Box::new(TunnelWithInfo::new(
            t,
            TunnelInfo {
                local_addr: info.local_addr.clone(),
                remote_addr: Some(self.addr.clone().into()),
                resolved_remote_addr: info
                    .resolved_remote_addr
                    .clone()
                    .or(info.remote_addr.clone()),
                tunnel_type: format!("{}-{}", self.addr.scheme(), info.tunnel_type),
            },
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;

    #[tokio::test]
    async fn test_txt() {
        let url = "txt://txt.easytier.cn";
        let global_ctx = get_mock_global_ctx();
        let mut connector = DnsTunnelConnector::new(
            url.parse().unwrap(),
            global_ctx,
            Arc::new(RingTunnelRegistry::default()),
        );
        connector.set_ip_version(IpVersion::V4);
        for _ in 0..5 {
            match connector.connect().await {
                Ok(ret) => {
                    println!("{:?}", ret.info());
                    return;
                }
                Err(e) => {
                    println!("{:?}", e);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_srv() {
        let url = "srv://easytier.cn";
        let global_ctx = get_mock_global_ctx();
        let mut connector = DnsTunnelConnector::new(
            url.parse().unwrap(),
            global_ctx,
            Arc::new(RingTunnelRegistry::default()),
        );
        connector.set_ip_version(IpVersion::V4);
        for _ in 0..5 {
            match connector.connect().await {
                Ok(ret) => {
                    println!("{:?}", ret.info());
                    return;
                }
                Err(e) => {
                    println!("{:?}", e);
                }
            }
        }
    }
}
