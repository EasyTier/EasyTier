use std::net::SocketAddr;
// use dashmap::DashMap;

use crate::{
    common::{
        dns::resolve_txt_record,
        error::Error,
        global_ctx::ArcGlobalCtx,
    },
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelError},
};
use anyhow::Context;
// use hickory_resolver::proto::rr::rdata::SRV;
use rand::seq::SliceRandom;
// use std::sync::Mutex;

use crate::proto::common::TunnelInfo;

use super::{create_connector_by_url, http_connector::TunnelWithInfo};

// SRV functionality has been moved to multi_connector.rs
// Commenting out SRV-related code to avoid conflicts

/*
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
        tracing::info!(
            protocol = %protocol,
            target = %record.target,
            port = record.port,
            priority = record.priority,
            weight = record.weight,
            "Processing SRV record for protocol"
        );

        match self.records.get_mut(&protocol) {
            None => {
                // If it is the first record or this protocol is new, initialize the corresponding vector
                tracing::info!(
                    protocol = %protocol,
                    srv_domain = %format!("_easytier._{}.domain.name", protocol),
                    target = %record.target,
                    priority = record.priority,
                    "First record for protocol, initializing new vector"
                );
                self.records.entry(protocol.clone())
                    .or_insert_with(Vec::new)
                    .push(record);
            }
            Some(mut current_record) if record.priority < current_record[0].priority => {
                // Find a smaller priority, clear all existing records, and start over.
                let old_priority = current_record[0].priority;
                tracing::info!(
                    protocol = %protocol,
                    srv_domain = %format!("_easytier._{}.domain.name", protocol),
                    target = %record.target,
                    old_priority = old_priority,
                    new_priority = record.priority,
                    cleared_records = current_record.len(),
                    "Clear current records due to found smaller priority record (old value {} > new value {})",
                    old_priority, record.priority
                );
                current_record.clear();
                current_record.push(record.clone());
            }
            Some(mut current_record) if record.priority == current_record[0].priority => {
                // If the priority is the same, add to the corresponding protocol's records
                tracing::info!(
                    protocol = %protocol,
                    srv_domain = %format!("_easytier._{}.domain.name", protocol),
                    target = %record.target,
                    priority = record.priority,
                    current_count = current_record.len(),
                    "Push same priority record to current record vector"
                );
                current_record.push(record.clone());
            }
            Some(current_record) => {
                // Ignore higher priority records
                let current_priority = current_record[0].priority;
                tracing::info!(
                    protocol = %protocol,
                    srv_domain = %format!("_easytier._{}.domain.name", protocol),
                    target = %record.target,
                    old_priority = current_priority,
                    new_priority = record.priority,
                    "Ignore higher priority record (old value {} < new value {})",
                    current_priority, record.priority
                );
            }
        }
    }

    //Selects the final record from all protocols, returning an array of URLs containing multiple protocols
    fn select_by_weight(&self) -> Option<Vec<String>> {
        if self.records.is_empty() {
            tracing::info!("No SRV records available for weight selection");
            return None;
        }

        tracing::info!(
            total_protocols = self.records.len(),
            "Starting weight-based selection for all protocols"
        );

        let final_records: DashMap<String, SrvRecord> = DashMap::new();
        // Select a record from each protocol as recommended in RFC 2782
        for srv_records_of_same_protocol in self.records.iter() {
            let protocol = srv_records_of_same_protocol.key();
            let records = srv_records_of_same_protocol.value();
            
            tracing::info!(
                protocol = %protocol,
                candidate_records = records.len(),
                "Processing protocol for weight selection"
            );

            let total_weight: u32 = records
                .iter()
                .map(|r| r.weight as u32)
                .sum();
            
            if total_weight > 0 {
                // Randomly select using weights
                let mut rng = rand::thread_rng();
                let rand_val = rng.gen_range(1..=total_weight);
                let mut accumulated_weight = 0u32;

                tracing::info!(
                    protocol = %protocol,
                    total_weight = total_weight,
                    random_value = rand_val,
                    "Using weight-based selection for protocol"
                );

                for record in records.iter() {
                    accumulated_weight += record.weight as u32;
                    if accumulated_weight >= rand_val {
                        tracing::error!(
                            protocol = %protocol,
                            target = %record.target,
                            port = record.port,
                            priority = record.priority,
                            weight = record.weight,
                            accumulated_weight = accumulated_weight,
                            random_value = rand_val,
                            "Selected final SRV record for protocol using weight"
                        );
                        final_records.insert(protocol.clone(), record.clone());
                        break;
                    }
                }
            } else {
                // Randomly select if all weights are zero
                tracing::info!(
                    protocol = %protocol,
                    "All weights are zero, using random selection"
                );
                
                if let Some(record) = records.choose(&mut rand::thread_rng()) {
                    tracing::error!(
                        protocol = %protocol,
                        target = %record.target,
                        port = record.port,
                        priority = record.priority,
                        weight = record.weight,
                        "Selected final SRV record for protocol using random selection (zero weights)"
                    );
                    final_records.insert(protocol.clone(), record.clone());
                }
            }
        }

        if final_records.is_empty() {
            tracing::error!("No final records selected from any protocol");
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
                        "Generated URL from selected SRV record"
                    );
                    url
                })
                .collect();
            
            tracing::error!(urls = ?urls, total_protocols = urls.len(), "SRV resolution completed, final URL group generated");
            Some(urls)
        }
    }
    
}
*/

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

    /*
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
        tracing::info!("Starting SRV record resolution for domain: {}", domain_name);

        let srv_domains = PROTO_PORT_OFFSET
            .iter()
            .map(|(p, _)| (format!("_easytier._{}.{}", p, domain_name), *p))
            .collect::<Vec<_>>();
        tracing::info!(srv_domains = ?srv_domains, "Built SRV domain lookup list");
        
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
                    tracing::info!(srv_domain = %srv_domain, protocol = %protocol, "Starting DNS SRV lookup");
                    
                    match resolver.srv_lookup(&srv_domain).await {
                        Ok(response) => {
                            let record_count = response.iter().count();
                            tracing::info!(
                                srv_domain = %srv_domain,
                                protocol = %protocol,
                                record_count = record_count,
                                "NSLookup success on {}: found {} records",
                                srv_domain, record_count
                            );
                            
                            for (index, record) in response.iter().enumerate() {
                                tracing::info!(
                                    srv_domain = %srv_domain,
                                    protocol = %protocol,
                                    record_index = index + 1,
                                    target = %record.target().to_utf8().trim_end_matches('.'),
                                    port = record.port(),
                                    priority = record.priority(),
                                    weight = record.weight(),
                                    "Found SRV record"
                                );
                                
                                match Self::handle_one_srv_record(record, &protocol) {
                                    Ok(srv_record) => {
                                        tracing::info!(
                                            srv_domain = %srv_domain,
                                            protocol = %protocol,
                                            ?srv_record,
                                            "Successfully parsed SRV record"
                                        );
                                        // using add_record to process the new record fund
                                        min_priority_records.lock().unwrap().add_record(srv_record, protocol.to_string());
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            srv_domain = %srv_domain,
                                            protocol = %protocol,
                                            error = ?e,
                                            "Failed to parse SRV record, skipping"
                                        );
                                        continue;
                                    }
                                }
                            }
                            Ok::<_, Error>(())
                        }
                        Err(e) => {
                            tracing::info!(
                                srv_domain = %srv_domain,
                                protocol = %protocol,
                                error = ?e,
                                "NSLookup failed for {}, ignoring",
                                srv_domain
                            );
                            Ok(()) // ignore any failure
                        }
                    }
                }
            })
            .collect::<Vec<_>>();
        
        tracing::info!("Waiting for all SRV lookup tasks to complete");
        // wait for all srv lookup finish
        let _ = futures::future::join_all(srv_lookup_tasks).await;

        tracing::info!("All SRV lookups completed, starting final selection");
        // comes up with the final srv 
        let selected_urls = min_priority_records
            .lock()
            .unwrap()
            .select_by_weight();

        match selected_urls {
            Some(urls) => {
                tracing::error!(urls = ?urls, total_protocols = urls.len(), "SRV record resolution completed successfully, selected URLs from all protocols");
                
                // 统一使用SrvConnector，无论单协议还是多协议
                let srv_connector = SrvConnector::new(urls, self.global_ctx.clone());
                Ok(Box::new(srv_connector))
            }
            None => {
                tracing::error!("SRV record resolution failed: no valid records found");
                Err(anyhow::anyhow!("no srv record found").into())
            }
        }
    }
    */
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
        // SRV handling is now done in multi_connector.rs at the instance level
        // } else if self.addr.scheme() == "srv" {
        //     self.handle_srv_record(
        //         self.addr
        //             .host_str()
        //             .as_ref()
        //             .ok_or(anyhow::anyhow!("host should not be empty in srv url"))?,
        //     )
        //     .await
        //     .with_context(|| "get srv record url failed")?
        } else {
            return Err(anyhow::anyhow!(
                "unsupported dns scheme: {}, expecting txt. SRV is handled by multi_connector",
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

/*
#[derive(Debug)]
pub struct SrvConnector {
    urls: Vec<String>,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
    bind_addrs: Vec<SocketAddr>,
}

impl SrvConnector {
    pub fn new(urls: Vec<String>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            urls,
            global_ctx,
            ip_version: IpVersion::Both,
            bind_addrs: Vec::new(),
        }
    }
    
    pub fn get_urls(&self) -> &Vec<String> {
        &self.urls
    }
}

#[async_trait::async_trait]
impl TunnelConnector for SrvConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, crate::tunnel::TunnelError> {
        tracing::error!(urls = ?self.urls, url_count = self.urls.len(), "SrvConnector: Starting connection attempts for {} protocol(s)", self.urls.len());
        
        // 为每个URL创建连接任务
        let mut connect_tasks = Vec::new();
        let mut connectors = Vec::new();
        
        for url in &self.urls {
            let url_clone = url.clone();
            let global_ctx = self.global_ctx.clone();
            let bind_addrs = self.bind_addrs.clone();
            let ip_version = self.ip_version;
            
            // 创建连接器
            match create_connector_by_url(&url_clone, &global_ctx, ip_version).await {
                Ok(mut connector) => {
                    connector.set_bind_addrs(bind_addrs);
                    connector.set_ip_version(ip_version);
                    connectors.push((url_clone.clone(), connector));
                }
                Err(e) => {
                    tracing::error!(url = %url_clone, error = ?e, "Failed to create connector for URL");
                    continue;
                }
            }
        }
        
        if connectors.is_empty() {
            tracing::error!("No valid connectors created for any URL");
            return Err(anyhow::anyhow!("No valid connectors created").into());
        }
        
        // Try all peers
        for (url, mut connector) in connectors {
            let task = tokio::spawn(async move {
                tracing::error!(url = %url, "Attempting connection");
                match connector.connect().await {
                    Ok(tunnel) => {
                        tracing::error!(url = %url, tunnel_info = ?tunnel.info(), "Successfully connected via protocol");
                        Ok((url, tunnel))
                    }
                    Err(e) => {
                        tracing::error!(url = %url, error = ?e, "Failed to connect via protocol");
                        Err((url, e))
                    }
                }
            });
            connect_tasks.push(task);
        }
        
        // 使用tokio::select!等待第一个成功的连接
        let mut remaining_tasks = connect_tasks;
        
        while !remaining_tasks.is_empty() {
            let (result, _index, remaining) = futures::future::select_all(remaining_tasks).await;
            remaining_tasks = remaining;
            
            match result {
                Ok(Ok((url, tunnel))) => {
                    tracing::error!(url = %url, remaining_attempts = remaining_tasks.len(), 
                        "SrvConnector: Connection successful, {} other attempts still running in background",
                        remaining_tasks.len());
                    
                    // Return the first successful tunnel

                    /* 
                    At this stage, other conenction tasks will continue running in the background, but we need to kill them since easytier only supports one tunnel at a time, but if multi-tunnelling is supported in future, we can add some stuff here. 
                    */
                    for task in remaining_tasks {
                        task.abort();
                    }
                    
                    return Ok(tunnel);
                }
                Ok(Err((url, e))) => {
                    tracing::error!(url = %url, error = ?e, remaining_attempts = remaining_tasks.len(),
                        "Connection attempt failed, {} attempts remaining", remaining_tasks.len());
                    continue;
                }
                Err(e) => {
                    tracing::error!(error = ?e, "Task panicked");
                    continue;
                }
            }
        }
        
        tracing::error!("All SRV connection attempts failed");
        Err(anyhow::anyhow!("All SRV connection attempts failed").into())
    }

    fn remote_url(&self) -> url::Url {
        // Return the first URL
        self.urls.first()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "srv://unknown".parse().unwrap())
    }

    fn set_bind_addrs(&mut self, bind_addrs: Vec<std::net::SocketAddr>) {
        self.bind_addrs = bind_addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}
*/

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

    /*
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
    */
}
