use std::{net::SocketAddr, sync::Arc};

use super::{create_connector_by_url, http_connector::TunnelWithInfo};
use crate::{
    common::{
        dns::{RESOLVER, resolve_txt_record},
        error::Error,
        global_ctx::ArcGlobalCtx,
        log,
    },
    connector::dynamic_connector_manager::GlobalDynamicConnectorManager,
    proto::common::TunnelInfo,
    tunnel::{IpScheme, IpVersion, Tunnel, TunnelConnector, TunnelError, TunnelScheme},
};
use anyhow::Context;
use dashmap::DashSet;
use hickory_resolver::proto::rr::rdata::SRV;
use rand::{Rng as _, seq::SliceRandom};
use strum::VariantArray;

fn weighted_choice<T>(options: &[(T, u64)]) -> Option<&T> {
    let total_weight = options.iter().map(|(_, weight)| *weight).sum();
    let mut rng = rand::thread_rng();
    let rand_value = rng.gen_range(0..total_weight);
    let mut accumulated_weight = 0;

    for (item, weight) in options {
        accumulated_weight += *weight;
        if rand_value < accumulated_weight {
            return Some(item);
        }
    }

    None
}

#[derive(Debug)]
pub struct DnsTunnelConnector {
    scheme: TunnelScheme,
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
    dynamic_manager: Option<Arc<GlobalDynamicConnectorManager>>,
}

impl DnsTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            scheme: (&addr).try_into().unwrap(),
            addr,
            bind_addrs: Vec::new(),
            global_ctx,
            ip_version: IpVersion::Both,
            dynamic_manager: None,
        }
    }

    /// 创建带有动态连接器管理器的 DNS 连接器
    pub fn with_dynamic_manager(
        addr: url::Url,
        global_ctx: ArcGlobalCtx,
        dynamic_manager: Arc<GlobalDynamicConnectorManager>,
    ) -> Self {
        Self {
            scheme: (&addr).try_into().unwrap(),
            addr,
            bind_addrs: Vec::new(),
            global_ctx,
            ip_version: IpVersion::Both,
            dynamic_manager: Some(dynamic_manager),
        }
    }

    #[tracing::instrument(ret, err)]
    pub async fn handle_txt_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        let txt_data = resolve_txt_record(domain_name)
            .await
            .with_context(|| format!("resolve txt record failed, domain_name: {}", domain_name))?;

        let mut candidate_urls = txt_data
            .split(" ")
            .map(|s| s.to_string())
            .filter_map(|s| url::Url::parse(s.as_str()).ok())
            .collect::<Vec<_>>();

        if candidate_urls.is_empty() {
            return Err(anyhow::anyhow!(
                "no valid url found, txt_data: {}, expecting an url list splitted by space",
                txt_data
            ).into());
        }

        // shuffle candidate_urls for load balancing
        candidate_urls.shuffle(&mut rand::thread_rng());

        tracing::info!("Found {} valid URLs from TXT record", candidate_urls.len());

        // Add all URLs except the first one to the manual connector manager
        if candidate_urls.len() > 1 {
            if let Some(conn_manager) = self.global_ctx.get_manual_connector_manager() {
                for url in candidate_urls.iter().skip(1) {
                    tracing::info!("Adding additional connector from TXT record: {}", url);
                    if let Err(e) = conn_manager.add_connector_by_url(url.clone()).await {
                        tracing::warn!("Failed to add connector {}: {:?}", url, e);
                    }
                }
                tracing::info!(
                    "Added {} additional connectors from TXT record",
                    candidate_urls.len() - 1
                );
            } else {
                tracing::warn!("ManualConnectorManager not available, cannot add additional connectors");
            }
        }

        // Return the first URL as the primary connector
        let primary_url = &candidate_urls[0];
        tracing::info!("Using primary connector from TXT record: {}", primary_url);
        
        // Register with global dynamic connector manager for auto-refresh
        self.register_for_auto_refresh_txt();
        
        let connector =
            create_connector_by_url(primary_url.as_str(), &self.global_ctx, self.ip_version).await?;
        Ok(connector)
    }

    /// 注册 TXT 到全局动态连接器管理器
    fn register_for_auto_refresh_txt(&self) {
        // 如果没有注入 dynamic_manager，则使用全局单例
        let dynamic_manager = match &self.dynamic_manager {
            Some(manager) => manager.clone(),
            None => GlobalDynamicConnectorManager::get_instance().clone(),
        };
        
        let source_url = self.addr.clone();
        let ip_version = self.ip_version;
        
        tokio::spawn(async move {
            if let Err(e) = dynamic_manager.add_dynamic_connector(
                source_url.clone(),
                crate::connector::dynamic_connector_manager::DynamicConnectorType::Txt,
                ip_version,
                300,
            ).await {
                tracing::warn!("Failed to register TXT connector for auto-refresh: {:?}", e);
            }
        });
    }

    fn handle_one_srv_record(record: &SRV, protocol: IpScheme) -> Result<(url::Url, u64), Error> {
        // port must be non-zero
        if record.port() == 0 {
            return Err(anyhow::anyhow!("port must be non-zero").into());
        }

        let connector_dst = record.target().to_utf8();
        let dst_url = format!("{}://{}:{}", protocol, connector_dst, record.port());

        Ok((
            dst_url.parse().with_context(|| {
                format!(
                    "parse dst_url failed, protocol: {}, connector_dst: {}, port: {}, dst_url: {}",
                    protocol,
                    connector_dst,
                    record.port(),
                    dst_url
                )
            })?,
            record.priority() as _,
        ))
    }

    #[tracing::instrument(ret, err)]
    pub async fn handle_srv_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        tracing::info!("handle_srv_record: {}", domain_name);

        let srv_domains = IpScheme::VARIANTS
            .iter()
            .map(|s| (s, format!("_easytier._{}.{}", s, domain_name)))
            .collect::<Vec<_>>();
        tracing::info!("build srv_domains: {:?}", srv_domains);
        let responses = Arc::new(DashSet::new());
        let srv_lookup_tasks = srv_domains
            .iter()
            .map(|(protocol, srv_domain)| {
                let resolver = RESOLVER.clone();
                let responses = responses.clone();
                async move {
                    let response = resolver.srv_lookup(srv_domain).await.with_context(|| {
                        format!("srv_lookup failed, srv_domain: {}", srv_domain)
                    })?;
                    tracing::info!(?response, ?srv_domain, "srv_lookup response");
                    for record in response.iter() {
                        let parsed_record = Self::handle_one_srv_record(record, **protocol);
                        tracing::info!(?parsed_record, ?srv_domain, "parsed_record");
                        if let Err(e) = &parsed_record {
                            log::warn!("got invalid srv record {:?}", e);
                            continue;
                        }
                        responses.insert(parsed_record.unwrap());
                    }
                    Ok::<_, Error>(())
                }
            })
            .collect::<Vec<_>>();
        let _ = futures::future::join_all(srv_lookup_tasks).await;

        let srv_records = responses.iter().map(|r| r.clone()).collect::<Vec<_>>();
        if srv_records.is_empty() {
            return Err(anyhow::anyhow!("no srv record found").into());
        }

        tracing::info!("Found {} valid SRV records", srv_records.len());

        // Add all URLs except the first one to the manual connector manager
        if srv_records.len() > 1 {
            if let Some(conn_manager) = self.global_ctx.get_manual_connector_manager() {
                for (url, _) in srv_records.iter().skip(1) {
                    tracing::info!("Adding additional connector from SRV record: {}", url);
                    if let Err(e) = conn_manager.add_connector_by_url(url.clone()).await {
                        tracing::warn!("Failed to add connector {}: {:?}", url, e);
                    }
                }
                tracing::info!(
                    "Added {} additional connectors from SRV record",
                    srv_records.len() - 1
                );
            } else {
                tracing::warn!("ManualConnectorManager not available, cannot add additional connectors");
            }
        }

        // Use weighted choice for the primary connector
        let (primary_url, _) = weighted_choice(srv_records.as_slice()).with_context(|| {
            format!(
                "failed to choose a srv record, domain_name: {}, srv_records: {:?}",
                domain_name, srv_records
            )
        })?;

        tracing::info!("Using primary connector from SRV record: {}", primary_url);
        
        // Register with global dynamic connector manager for auto-refresh
        self.register_for_auto_refresh_srv();
        
        let connector =
            create_connector_by_url(primary_url.as_str(), &self.global_ctx, self.ip_version).await?;
        Ok(connector)
    }

    /// 注册 SRV 到全局动态连接器管理器
    fn register_for_auto_refresh_srv(&self) {
        // 如果没有注入 dynamic_manager，则使用全局单例
        let dynamic_manager = match &self.dynamic_manager {
            Some(manager) => manager.clone(),
            None => GlobalDynamicConnectorManager::get_instance().clone(),
        };
        
        let source_url = self.addr.clone();
        let ip_version = self.ip_version;
        
        tokio::spawn(async move {
            if let Err(e) = dynamic_manager.add_dynamic_connector(
                source_url.clone(),
                crate::connector::dynamic_connector_manager::DynamicConnectorType::Srv,
                ip_version,
                300,
            ).await {
                tracing::warn!("Failed to register SRV connector for auto-refresh: {:?}", e);
            }
        });
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
        let mut connector = DnsTunnelConnector::new(url.parse().unwrap(), global_ctx);
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
        let mut connector = DnsTunnelConnector::new(url.parse().unwrap(), global_ctx);
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
