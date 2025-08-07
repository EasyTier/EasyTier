use std::{net::SocketAddr, sync::Arc};

use crate::{
    common::{
        dns::{resolve_txt_record, RESOLVER},
        error::Error,
        global_ctx::ArcGlobalCtx,
    },
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelError, PROTO_PORT_OFFSET},
};
use anyhow::Context;
use hickory_resolver::proto::rr::rdata::SRV;
use rand::{seq::SliceRandom, Rng as _};
use std::sync::Mutex;

use crate::proto::common::TunnelInfo;

use super::{create_connector_by_url, http_connector::TunnelWithInfo};

#[derive(Debug, Clone)]
struct SrvRecord {
    url: url::Url,
    priority: u16,
    weight: u16,
}

//Struct to keep srv records with minimum priority(i.e. the most wanted dst)
#[derive(Debug)]
struct MinPriorityRecords {
    records: Vec<SrvRecord>,
    current_min_priority: Option<u16>,
}

impl MinPriorityRecords {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            current_min_priority: None,
        }
    }

    fn add_record(&mut self, record: SrvRecord) {
        match self.current_min_priority {
            None => {
                // As first record
                self.current_min_priority = Some(record.priority);
                self.records.push(record);
            }
            Some(current_min) => {
                if record.priority < current_min {
                    // Remove all the exisitng records as append the new on as the first record, when a record with smaller priority is found
                    self.records.clear();
                    self.current_min_priority = Some(record.priority);
                    self.records.push(record);
                } else if record.priority == current_min {
                    // append the record to the array if they're in same priority
                    self.records.push(record);
                }
                // if priority > current_min，ignore
            }
        }
    }

    // select the record by weight according to RFC 2782
    fn select_by_weight(&self) -> Option<&SrvRecord> {
        if self.records.is_empty() {
            return None;
        }

        let total_weight: u32 = self.records.iter().map(|r| r.weight as u32).sum();

        // randomly pick if all of the records weight 0
        if total_weight == 0 {
            return self.records.choose(&mut rand::thread_rng());
        }

        // Otherwise, use the classical method which pick a random number x ∈ [1, total_weight]
        let mut rng = rand::thread_rng();
        let rand_val = rng.gen_range(1..=total_weight);
        let mut accumulated_weight = 0u32;

        for record in &self.records {
            accumulated_weight += record.weight as u32;
            if accumulated_weight >= rand_val {
                return Some(record);
            }
        }

        // Ensure there is at least an return for any unknown case
        self.records.first()
    }
}

#[derive(Debug)]
pub struct DNSTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
}

impl DNSTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            addr,
            bind_addrs: Vec::new(),
            global_ctx,
            ip_version: IpVersion::Both,
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

        let connector =
            create_connector_by_url(url.as_str(), &self.global_ctx, self.ip_version).await?;
        Ok(connector)
    }

    fn handle_one_srv_record(record: &SRV, protocol: &str) -> Result<SrvRecord, Error> {
        // port must be non-zero
        if record.port() == 0 {
            return Err(anyhow::anyhow!("port must be non-zero").into());
        }

        let connector_dst = record.target().to_utf8();
        let dst_url = format!("{}://{}:{}", protocol, connector_dst, record.port());

        Ok(SrvRecord {
            url: dst_url.parse().with_context(|| {
                format!(
                    "parse dst_url failed, protocol: {}, connector_dst: {}, port: {}, dst_url: {}",
                    protocol,
                    connector_dst,
                    record.port(),
                    dst_url
                )
            })?,
            priority: record.priority(),
            weight: record.weight(),
        })
    }

    #[tracing::instrument(ret, err)]
    pub async fn handle_srv_record(
        &self,
        domain_name: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        tracing::info!("handle_srv_record: {}", domain_name);

        let srv_domains = PROTO_PORT_OFFSET
            .iter()
            .map(|(p, _)| (format!("_easytier._{}.{}", p, domain_name), *p))
            .collect::<Vec<_>>();
        tracing::info!("build srv_domains: {:?}", srv_domains);
        
        // I think my variable naming should be quite straight forward......
        let min_priority_records = Arc::new(Mutex::new(MinPriorityRecords::new()));
        
        let srv_lookup_tasks = srv_domains
            .iter()
            .map(|(srv_domain, protocol)| {
                let resolver = RESOLVER.clone();
                let min_priority_records = min_priority_records.clone();
                let srv_domain = srv_domain.clone();
                let protocol = protocol.clone();
                async move {
                    match resolver.srv_lookup(&srv_domain).await {
                        Ok(response) => {
                            tracing::info!(?response, ?srv_domain, "srv_lookup response");
                            for record in response.iter() {
                                match Self::handle_one_srv_record(record, &protocol) {
                                    Ok(srv_record) => {
                                        tracing::info!(?srv_record, ?srv_domain, "parsed_record");
                                        // using add_record to process the new record fund
                                        min_priority_records.lock().unwrap().add_record(srv_record);
                                    }
                                    Err(e) => {
                                        tracing::warn!(?e, ?srv_domain, "invalid srv record");
                                        continue;
                                    }
                                }
                            }
                            Ok::<_, Error>(())
                        }
                        Err(e) => {
                            tracing::debug!(?e, ?srv_domain, "srv_lookup failed");
                            Ok(()) // ignore any failure
                        }
                    }
                }
            })
            .collect::<Vec<_>>();
        
        // wait for all srv lookup finish
        let _ = futures::future::join_all(srv_lookup_tasks).await;

        // comes up with the final srv 
        let selected_record = min_priority_records
            .lock()
            .unwrap()
            .select_by_weight()
            .cloned();

        match selected_record {
            Some(record) => {
                tracing::info!(?record, "selected srv record");
                let connector = create_connector_by_url(
                    record.url.as_str(), 
                    &self.global_ctx, 
                    self.ip_version
                ).await?;
                Ok(connector)
            }
            None => {
                Err(anyhow::anyhow!("no srv record found").into())
            }
        }
    }
}

#[async_trait::async_trait]
impl super::TunnelConnector for DNSTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let mut conn = if self.addr.scheme() == "txt" {
            self.handle_txt_record(
                self.addr
                    .host_str()
                    .as_ref()
                    .ok_or(anyhow::anyhow!("host should not be empty in txt url"))?,
            )
            .await
            .with_context(|| "get txt record url failed")?
        } else if self.addr.scheme() == "srv" {
            self.handle_srv_record(
                self.addr
                    .host_str()
                    .as_ref()
                    .ok_or(anyhow::anyhow!("host should not be empty in srv url"))?,
            )
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
        let mut connector = DNSTunnelConnector::new(url.parse().unwrap(), global_ctx);
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
        let mut connector = DNSTunnelConnector::new(url.parse().unwrap(), global_ctx);
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
