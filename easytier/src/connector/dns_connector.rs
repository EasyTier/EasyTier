use std::{net::SocketAddr, sync::Arc};
use dashmap::DashMap;

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
    target: String,
    port: u16,
    priority: u16,
    weight: u16,
}

#[derive(Debug)]
struct MinPriorityRecords {
    records: DashMap<String, Vec<SrvRecord>>,
}

impl MinPriorityRecords {
    fn new() -> Self {
        Self {
            records: DashMap::new(),
        }
    }

    fn add_record(&mut self, record: SrvRecord, protocol: String) {
        match self.records.get_mut(&protocol) {
            None => {
                //If it is the first record or this protocol is new, initialize the corresponding vector
                self.records.entry(protocol.clone())
                    .or_insert_with(Vec::new)
                    .push(record);
            }
            Some(mut current_record) if record.priority < current_record[0].priority => {
                //Find a smaller priority, clear all existing records, and start over.
                current_record.clear();
                current_record.push(record.clone());
            }
            Some(mut current_record) if record.priority == current_record[0].priority => {
                // If the priority is the same, add to the corresponding protocol's records
                current_record.push(record.clone());
            }
            Some(_) => {
                // Ignore the rest
            }
        }
    }

    //Selects the final record from all protocols, returning an array of URLs containing multiple protocols
    fn select_by_weight(&self) -> Option<Vec<String>> {
        if self.records.is_empty() {
            return None;
        }
        let final_records: DashMap<String, SrvRecord> = DashMap::new();
        //Select a record from each protocol as recommended in RFC 2782
        for srv_records_of_same_protocol in self.records.iter() {
            let total_weight: u32 = srv_records_of_same_protocol.value()
                .iter()
                .map(|r| r.weight as u32)
                .sum();
            
            if total_weight > 0 {
                // Randomly select using weights
                let mut rng = rand::thread_rng();
                let rand_val = rng.gen_range(0..=total_weight);
                let mut accumulated_weight = 0u32;

                for record in srv_records_of_same_protocol.value().iter() {
                    accumulated_weight += record.weight as u32;
                    if accumulated_weight >= rand_val {
                        final_records.insert(srv_records_of_same_protocol.key().clone(), record.clone());
                        break;
                    }
                }
            } else {
                // Randomly select if all weights are zero
                if let Some(record) = srv_records_of_same_protocol.value().choose(&mut rand::thread_rng()) {
                    final_records.insert(srv_records_of_same_protocol.key().clone(), record.clone());
                }
            }

        }

        if final_records.is_empty() {
            return None;
        } else {
            // From the final records, generate URLs for each protocol
            let urls: Vec<String> = final_records
                .iter()
                .map(|entry| {
                    let protocol = entry.key();
                    let record = entry.value();
                    let url = format!("{}://{}:{}", protocol, record.target, record.port);
                    tracing::info!(
                        protocol = %protocol,
                        target = %record.target,
                        port = record.port,
                        priority = record.priority,
                        weight = record.weight,
                        url = %url,
                        "Selected record for protocol"
                    );
                    url
                })
                .collect();
            
            tracing::info!(urls = ?urls, total_protocols = urls.len(), "Generated URLs from all protocols");
            Some(urls)
        }
    }
    
}

#[derive(Debug)]
pub struct MultiURLTunnelConnector {
    urls: Vec<String>,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
}

impl MultiURLTunnelConnector {
    pub fn new(urls: Vec<String>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            urls,
            bind_addrs: Vec::new(),
            global_ctx,
            ip_version: IpVersion::Both,
        }
    }
}

#[async_trait::async_trait]
impl super::TunnelConnector for MultiURLTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        // Try to connect to all URLs, returning the first successful connection
        let mut last_error = None;
        
        for url in &self.urls {
            tracing::info!(url = %url, "attempting to connect to URL");
            
            match create_connector_by_url(url, &self.global_ctx, self.ip_version).await {
                Ok(mut connector) => {
                    connector.set_bind_addrs(self.bind_addrs.clone());
                    connector.set_ip_version(self.ip_version);
                    
                    match connector.connect().await {
                        Ok(tunnel) => {
                            tracing::info!(url = %url, "successfully connected");
                            return Ok(tunnel);
                        }
                        Err(e) => {
                            tracing::warn!(url = %url, error = ?e, "failed to connect to URL");
                            last_error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(url = %url, error = ?e, "failed to create connector for URL");
                    // Error contains TunnelError variant and can be directly converted
                    last_error = Some(match e {
                        crate::common::error::Error::TunnelError(te) => te,
                        other => TunnelError::from(anyhow::Error::from(other)),
                    });
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("no URLs available for connection").into()
        }))
    }

    fn remote_url(&self) -> url::Url {
        // Return the first URL, or a special multi:// URL
        self.urls.first()
            .and_then(|s| url::Url::parse(s).ok())
            .unwrap_or_else(|| url::Url::parse("multi://unknown").unwrap())
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
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

    fn handle_one_srv_record(record: &SRV, _protocol: &str) -> Result<SrvRecord, Error> {
        // port must be non-zero
        if record.port() == 0 {
            return Err(anyhow::anyhow!("port must be non-zero").into());
        }

        let connector_dst = record.target().to_utf8();
        let target_host = connector_dst.trim_end_matches('.');

        Ok(SrvRecord {
            target: target_host.to_string(),
            port: record.port(),
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
                let protocol = *protocol;
                async move {
                    match resolver.srv_lookup(&srv_domain).await {
                        Ok(response) => {
                            tracing::info!(?response, ?srv_domain, "srv_lookup response");
                            for record in response.iter() {
                                match Self::handle_one_srv_record(record, &protocol) {
                                    Ok(srv_record) => {
                                        tracing::info!(?srv_record, ?srv_domain, "parsed_record");
                                        // using add_record to process the new record fund
                                        min_priority_records.lock().unwrap().add_record(srv_record, protocol.to_string());
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
        let selected_urls = min_priority_records
            .lock()
            .unwrap()
            .select_by_weight();

        match selected_urls {
            Some(urls) => {
                tracing::info!(urls = ?urls, "selected srv record URLs from all protocols");
                // Return a MultiURLTunnelConnector with the selected URLs
                let multi_connector = MultiURLTunnelConnector::new(urls, self.global_ctx.clone());
                Ok(Box::new(multi_connector))
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
