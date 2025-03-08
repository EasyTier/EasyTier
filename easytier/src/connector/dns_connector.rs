use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
};

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    tunnel::{
        Tunnel, TunnelConnector, TunnelError, ZCPacketSink, ZCPacketStream, PROTO_PORT_OFFSET,
    },
};
use anyhow::Context;
use dashmap::DashSet;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    proto::rr::rdata::SRV,
    TokioAsyncResolver,
};
use rand::{seq::SliceRandom, Rng as _};

use crate::proto::common::TunnelInfo;

use super::{create_connector_by_url, http_connector::TunnelWithInfo};

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
pub struct DNSTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,

    default_resolve_config: ResolverConfig,
    default_resolve_opts: ResolverOpts,
}

impl DNSTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        let mut default_resolve_config = ResolverConfig::new();
        default_resolve_config.add_name_server(NameServerConfig::new(
            "223.5.5.5:53".parse().unwrap(),
            Protocol::Udp,
        ));
        default_resolve_config.add_name_server(NameServerConfig::new(
            "180.184.1.1:53".parse().unwrap(),
            Protocol::Udp,
        ));
        Self {
            addr,
            bind_addrs: Vec::new(),
            global_ctx,

            default_resolve_config,
            default_resolve_opts: ResolverOpts::default(),
        }
    }

    #[tracing::instrument(ret, err)]
    pub async fn handle_txt_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or(
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
        );

        let response = resolver.txt_lookup(domain_name).await.with_context(|| {
            format!(
                "txt_lookup failed, domain_name: {}",
                domain_name.to_string()
            )
        })?;

        let txt_record = response.iter().next().with_context(|| {
            format!(
                "no txt record found, domain_name: {}",
                domain_name.to_string()
            )
        })?;

        let txt_data = String::from_utf8_lossy(&txt_record.txt_data()[0]);
        tracing::info!(?txt_data, ?domain_name, "get txt record");

        let candidate_urls = txt_data
            .split(" ")
            .map(|s| s.to_string())
            .filter_map(|s| url::Url::parse(s.as_str()).ok())
            .collect::<Vec<_>>();

        // shuffle candidate_urls and get the first one
        let url = candidate_urls
            .choose(&mut rand::thread_rng())
            .with_context(|| {
                format!(
                    "no valid url found, txt_data: {}, expecting an url list splitted by space",
                    txt_data
                )
            })?;

        let connector = create_connector_by_url(url.as_str(), &self.global_ctx).await;

        connector
    }

    fn handle_one_srv_record(record: &SRV, protocol: &str) -> Result<(url::Url, u64), Error> {
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

        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or(
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
        );

        let srv_domains = PROTO_PORT_OFFSET
            .iter()
            .map(|(p, _)| (format!("_easytier._{}.{}", p, domain_name), *p)) // _easytier._udp.{domain_name}
            .collect::<Vec<_>>();
        tracing::info!("build srv_domains: {:?}", srv_domains);
        let responses = Arc::new(DashSet::new());
        let srv_lookup_tasks = srv_domains
            .iter()
            .map(|(srv_domain, protocol)| {
                let resolver = resolver.clone();
                let responses = responses.clone();
                async move {
                    let response = resolver.srv_lookup(srv_domain).await.with_context(|| {
                        format!("srv_lookup failed, srv_domain: {}", srv_domain.to_string())
                    })?;
                    tracing::info!(?response, ?srv_domain, "srv_lookup response");
                    for record in response.iter() {
                        let parsed_record = Self::handle_one_srv_record(record, &protocol);
                        tracing::info!(?parsed_record, ?srv_domain, "parsed_record");
                        if parsed_record.is_err() {
                            eprintln!(
                                "got invalid srv record {:?}",
                                parsed_record.as_ref().unwrap_err()
                            );
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

        let url = weighted_choice(srv_records.as_slice()).with_context(|| {
            format!(
                "failed to choose a srv record, domain_name: {}, srv_records: {:?}",
                domain_name.to_string(),
                srv_records
            )
        })?;

        let connector = create_connector_by_url(url.as_str(), &self.global_ctx).await;
        connector
    }
}

#[async_trait::async_trait]
impl super::TunnelConnector for DNSTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let mut conn = if self.addr.scheme() == "txt" {
            self.handle_txt_record(self.addr.host_str().as_ref().unwrap())
                .await
                .with_context(|| "get txt record url failed")?
        } else if self.addr.scheme() == "srv" {
            self.handle_srv_record(self.addr.host_str().as_ref().unwrap())
                .await
                .with_context(|| "get srv record url failed")?
        } else {
            return Err(anyhow::anyhow!(
                "unsupported dns scheme: {}, expecting txt or srv",
                self.addr.scheme()
            )
            .into());
        };
        let t = conn.connect().await?;
        let info = t.info().unwrap_or_default();
        Ok(Box::new(TunnelWithInfo::new(
            t,
            TunnelInfo {
                local_addr: info.local_addr.clone(),
                remote_addr: Some(self.addr.clone().into()),
                tunnel_type: format!(
                    "{}-{}",
                    self.addr.scheme(),
                    info.remote_addr.unwrap_or_default()
                ),
            },
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::{tests::get_mock_global_ctx, GlobalCtx};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_txt() {
        let url = "txt://txt.easytier.cn";
        let global_ctx = get_mock_global_ctx();
        let mut connector = DNSTunnelConnector::new(url.parse().unwrap(), global_ctx);
        let ret = connector.connect().await.unwrap();
        println!("{:?}", ret.info());
    }

    #[tokio::test]
    async fn test_srv() {
        let url = "srv://easytier.cn";
        let global_ctx = get_mock_global_ctx();
        let mut connector = DNSTunnelConnector::new(url.parse().unwrap(), global_ctx);
        let ret = connector.connect().await.unwrap();
        println!("{:?}", ret.info());
    }
}
