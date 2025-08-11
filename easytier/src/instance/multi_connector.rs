use std::collections::HashSet;
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;
use std::net::SocketAddr;

use crate::{
    common::{
        dns::RESOLVER,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtx},
    },
    connector::manual::{ManualConnectorManager},
    tunnel::{TunnelConnector, Tunnel, TunnelError, IpVersion},
};

use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use rand::seq::SliceRandom;
use rand::Rng;
use futures;

#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

const SUPPORTED_PROTOCOLS: &[&str] = &[
    "tcp",
    "udp", 
    "wg",
    "ws",
    "wss",
];

#[derive(Debug, Default)]
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
        tracing::debug!(
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
                tracing::debug!(
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
                // If a smaller priority was found, clear all existing records, and start over.
                let old_priority = current_record[0].priority;
                tracing::debug!(
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
                // If the priority is the same, add to the corresponding protocol's records to the vector
                tracing::debug!(
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
                tracing::debug!(
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
            tracing::debug!("No SRV records available for weight selection");
            return None;
        }

        tracing::debug!(
            total_protocols = self.records.len(),
            "Starting weight-based selection for all protocols"
        );

        let final_records: DashMap<String, SrvRecord> = DashMap::new();
        // Select a record from each protocol as recommended in RFC 2782
        for srv_records_of_same_protocol in self.records.iter() {
            let protocol = srv_records_of_same_protocol.key();
            let records = srv_records_of_same_protocol.value();
            
            tracing::debug!(
                protocol = %protocol,
                candidate_records = records.len(),
                "Processing protocol for weight selection"
            );

            let total_weight: u32 = records
                .iter()
                .map(|r| r.weight as u32)
                .sum();
            
            if total_weight > 0 {
                // Adjust weights: set zero weights to 1/total_weight, then recalculate total weight
                let zero_weight_value = 1.0 / total_weight as f64;
                let adjusted_weights: Vec<f64> = records.iter()
                    .map(|r| if r.weight == 0 { zero_weight_value } else { r.weight as f64 })
                    .collect();
                
                let new_total_weight: f64 = adjusted_weights.iter().sum();
                
                // Build Alias Method table
                let n = adjusted_weights.len();
                let mut probs: Vec<f64> = adjusted_weights.iter()
                    .map(|&w| w * n as f64 / new_total_weight)
                    .collect();
                
                let mut prob = vec![0.0; n];
                let mut alias = vec![0; n];
                
                // Separate small and large probabilities
                let mut small = Vec::new();
                let mut large = Vec::new();
                
                for (i, &p) in probs.iter().enumerate() {
                    if p < 1.0 {
                        small.push(i);
                    } else {
                        large.push(i);
                    }
                }
                
                // Build alias table
                while !small.is_empty() && !large.is_empty() {
                    let small_idx = small.pop().unwrap();
                    let large_idx = large.pop().unwrap();
                    
                    prob[small_idx] = probs[small_idx];
                    alias[small_idx] = large_idx;
                    
                    probs[large_idx] = probs[large_idx] + probs[small_idx] - 1.0;
                    
                    if probs[large_idx] < 1.0 {
                        small.push(large_idx);
                    } else {
                        large.push(large_idx);
                    }
                }
                
                // Handle remaining items
                while !large.is_empty() {
                    prob[large.pop().unwrap()] = 1.0;
                }
                while !small.is_empty() {
                    prob[small.pop().unwrap()] = 1.0;
                }
                
                // Sample using Alias Method
                let mut rng = rand::thread_rng();
                let i = rng.gen_range(0..n);
                let coin = rng.gen::<f64>();
                
                let selected_idx = if coin < prob[i] { i } else { alias[i] };
                
                if let Some(record) = records.get(selected_idx) {
                    tracing::info!(
                        protocol = %protocol,
                        target = %record.target,
                        port = record.port,
                        priority = record.priority,
                        weight = record.weight,
                        "Selected final SRV record for protocol using Alias Method"
                    );
                    final_records.insert(protocol.clone(), record.clone());
                }
            } else {
                // Randomly select if all weights are zero
                tracing::debug!(
                    protocol = %protocol,
                    "All weights are zero, using random selection"
                );
                
                if let Some(record) = records.choose(&mut rand::thread_rng()) {
                    tracing::info!(
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
                    tracing::debug!(
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
            
            tracing::info!(urls = ?urls, total_protocols = urls.len(), "SRV resolution completed, final URL group generated");
            Some(urls)
        }
    }
}

pub struct MultiConnector {
    url: url::Url,
    global_ctx: ArcGlobalCtx,
    conn_manager: Option<Arc<ManualConnectorManager>>, // Use to add resolved URLs into peers
    processed_urls: Arc<DashSet<String>>, // Bucket to prevent processing duplicate URLs
    ip_version: IpVersion,
}

impl MultiConnector {
    pub fn new(
        url: url::Url, 
        global_ctx: ArcGlobalCtx,
        conn_manager: Option<Arc<ManualConnectorManager>>
    ) -> Self {
        Self {
            url,
            global_ctx,
            conn_manager,
            processed_urls: Arc::new(DashSet::new()),
            ip_version: IpVersion::Both,
        }
    }

    pub async fn resolve_txt_domain(
        target_url: &str,
        conn_manager: &Arc<ManualConnectorManager>,
        _global_ctx: &Arc<GlobalCtx>,
    ) -> Result<usize, Error> {
        let mut visited = HashSet::new();
        let mut all_urls = Vec::new();

        // Extract domain from txt://domain
        let domain = if let Some(domain) = target_url.strip_prefix("txt://") {
            domain
        } else {
            return Err(anyhow::anyhow!("Invalid TXT URL format: {}", target_url).into());
        };

        Self::resolve_txt_to_urls(domain, &mut visited, &mut all_urls, 0).await?;
        
        Self::add_urls_as_peers(all_urls, conn_manager).await
    }

    pub async fn resolve_srv_domain(
        target_url: &str,
        conn_manager: &Arc<ManualConnectorManager>, 
        _global_ctx: &Arc<GlobalCtx>,
    ) -> Result<usize, Error> {
        // Extract domain from srv://domain
        let domain = if let Some(domain) = target_url.strip_prefix("srv://") {
            domain
        } else {
            return Err(anyhow::anyhow!("Invalid SRV URL format: {}", target_url).into());
        };

        let resolved_urls = Self::resolve_srv_to_urls_parallel(domain).await?;
        
        if resolved_urls.is_empty() {
            tracing::warn!(domain = %domain, "No URLs resolved from SRV records");
            return Ok(0);
        }

        // Add all resolved URLs
        Self::add_urls_as_peers(resolved_urls, conn_manager).await
    }

    async fn resolve_srv_to_urls_parallel(domain_name: &str) -> Result<Vec<String>, Error> {
        tracing::info!(
            domain_name = %domain_name,
            "MultiConnector: Starting parallel SRV record resolution"
        );

        // Create srv resolv tasks for all protocol
        let protocol_tasks = SUPPORTED_PROTOCOLS
            .iter()
            .map(|&protocol| {
                let domain_name = domain_name.to_string();
                let protocol = protocol.to_string();
                
                async move {
                    // Process each protocol in different tasks
                    Self::resolve_single_protocol_srv(&domain_name, &protocol).await
                }
            })
            .collect::<Vec<_>>();
        
        tracing::debug!(
            protocol_count = SUPPORTED_PROTOCOLS.len(),
            "MultiConnector: Created {} parallel SRV resolution tasks",
            SUPPORTED_PROTOCOLS.len()
        );

        // Wait for all protocol resolution results
        let results = futures::future::join_all(protocol_tasks).await;

        // Collect all successfully resolved URLs
        let mut resolved_urls = Vec::new();
        for (protocol_index, result) in results.into_iter().enumerate() {
            let protocol = SUPPORTED_PROTOCOLS[protocol_index];
            match result {
                Ok(Some(url)) => {
                    tracing::info!(
                        protocol = %protocol,
                        url = %url,
                        "MultiConnector: Successfully resolved SRV for protocol"
                    );
                    resolved_urls.push(url);
                }
                Ok(None) => {
                    tracing::debug!(
                        protocol = %protocol,
                        "MultiConnector: No SRV records found for protocol"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        protocol = %protocol,
                        error = ?e,
                        "MultiConnector: SRV resolution failed for protocol"
                    );
                }
            }
        }

        if !resolved_urls.is_empty() {
            tracing::info!(
                domain_name = %domain_name,
                resolved_count = resolved_urls.len(),
                resolved_urls = ?resolved_urls,
                "MultiConnector: Parallel SRV resolution completed successfully"
            );
            Ok(resolved_urls)
        } else {
            tracing::error!(
                domain_name = %domain_name,
                "MultiConnector: No SRV records found for any protocol"
            );
            Err(anyhow::anyhow!("No SRV records found for domain: {}", domain_name).into())
        }
    }

    /// Method to add URLs as peers
    async fn add_urls_as_peers(
        all_urls: Vec<String>,
        conn_manager: &Arc<ManualConnectorManager>,
    ) -> Result<usize, Error> {
        if all_urls.is_empty() {
            tracing::warn!("MultiConnector: No URLs to add");
            return Ok(0);
        }

        tracing::info!(
            url_count = all_urls.len(),
            "MultiConnector: Starting parallel connector addition"
        );

        // Create connector for every resolved urls
        let tasks = all_urls.into_iter().map(|url| {
            let conn_manager = conn_manager.clone();
            async move {
                tracing::debug!(url = %url, "MultiConnector: Adding connector for URL");
                match conn_manager.add_connector_by_url(&url).await {
                    Ok(_) => {
                        tracing::debug!(url = %url, "MultiConnector: Successfully added connector");
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!(url = %url, error = ?e, "MultiConnector: Failed to add connector");
                        Err((url, e))
                    }
                }
            }
        }).collect::<Vec<_>>();

        // Wait for all tasks to complete
        let results = futures::future::join_all(tasks).await;

        // Collect results
        let mut total_peers_added = 0;
        let mut failed_urls = Vec::new();
        
        for result in results {
            match result {
                Ok(_) => {
                    total_peers_added += 1;
                }
                Err((url, e)) => {
                    failed_urls.push((url, e));
                }
            }
        }

        if !failed_urls.is_empty() {
            tracing::warn!(
                failed_count = failed_urls.len(),
                "MultiConnector: {} URLs failed to add as connectors",
                failed_urls.len()
            );
            for (url, e) in &failed_urls {
                tracing::debug!(url = %url, error = ?e, "Failed URL details");
            }
        }

        Ok(total_peers_added)
    }

    /// TXT record resolution to collect URLs
    fn resolve_txt_to_urls<'a>(
        domain_name: &'a str,
        visited: &'a mut HashSet<String>,
        all_urls: &'a mut Vec<String>,
        depth: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            tracing::debug!(
                domain_name = %domain_name,
                depth = depth,
                "MultiConnector: Starting TXT record resolution"
            );

            match RESOLVER.txt_lookup(domain_name).await {
                Ok(response) => {
                    // Get all TXT record entries
                    let mut all_entries = Vec::new();
                    for txt_record in response.iter() {
                        // Convert txt record to string
                        let record_data = format!("{}", txt_record);
                        tracing::debug!(
                            domain_name = %domain_name,
                            record_data = %record_data,
                            "MultiConnector: Processing TXT record"
                        );

                        // Parse comma-separated URLs from TXT record and collect owned strings
                        let entries: Vec<String> = record_data
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                        all_entries.extend(entries);
                    }

                    // Classify and process different types of entries
                    let mut direct_urls = Vec::new();
                    let mut nested_txt_urls = Vec::new();
                    let mut nested_srv_urls = Vec::new();
                    
                    for entry in all_entries {
                        if entry.is_empty() {
                            continue;
                        }

                        tracing::debug!(
                            domain_name = %domain_name,
                            entry = %entry,
                            "MultiConnector: Processing entry from TXT record"
                        );

                        // Match entry format: protocol://domain:port
                        if let Some((protocol, rest)) = entry.split_once("://") {
                            match protocol.to_lowercase().as_str() {
                                "tcp" | "udp" | "ws" | "wss" | "wg" => {
                                    // Basic protocols
                                    tracing::debug!(
                                        entry = %entry,
                                        protocol = %protocol,
                                        "MultiConnector: Adding supported protocol URL"
                                    );
                                    direct_urls.push(entry.clone());
                                }
                                "txt" => {
                                    // Nested TXT
                                    tracing::debug!(
                                        entry = %entry,
                                        nested_domain = %rest,
                                        "MultiConnector: Found nested TXT URL"
                                    );
                                    nested_txt_urls.push(rest.to_string());
                                }
                                "srv" => {
                                    // Srv
                                    tracing::debug!(
                                        entry = %entry,
                                        nested_domain = %rest,
                                        "MultiConnector: Found nested SRV URL"
                                    );
                                    nested_srv_urls.push(rest.to_string());
                                }
                                _ => {
                                    tracing::warn!(
                                        entry = %entry,
                                        protocol = %protocol,
                                        "MultiConnector: Unsupported protocol, skipping"
                                    );
                                }
                            }
                        } else {
                            tracing::warn!(
                                entry = %entry,
                                "MultiConnector: Invalid entry format, expected protocol://domain:port"
                            );
                        }
                    }

                    // Add all basic urls
                    all_urls.extend(direct_urls);

                    // Process nested TXT URLs
                    let txt_count = nested_txt_urls.len();
                    for nested_domain in &nested_txt_urls {
                        let nested_url = format!("txt://{}", nested_domain);
                        
                        // Check if visited
                        if visited.contains(&nested_url) {
                            tracing::warn!(
                                nested_url = %nested_url,
                                "MultiConnector: Cycle detected for nested TXT URL, skipping"
                            );
                            continue;
                        }
                        
                        // Using Box::pin to process TXT record recursively
                        visited.insert(nested_url.clone());
                        match Self::resolve_txt_to_urls(nested_domain, visited, all_urls, depth + 1).await {
                            Ok(_) => {
                                tracing::debug!(
                                    nested_url = %nested_url,
                                    "Successfully resolved nested TXT URL"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    nested_url = %nested_url,
                                    error = ?e,
                                    "Failed to resolve nested TXT URL"
                                );
                            }
                        }
                        visited.remove(&nested_url);
                    }

                    // Process SRV URLs
                    let srv_count = nested_srv_urls.len();
                    for nested_domain in &nested_srv_urls {
                        let nested_url = format!("srv://{}", nested_domain);

                        // Resolve SRV records and add to results
                        match Self::resolve_srv_to_urls_parallel(nested_domain).await {
                            Ok(mut srv_urls) => {
                                tracing::debug!(
                                    nested_url = %nested_url,
                                    resolved_count = srv_urls.len(),
                                    "Successfully resolved nested SRV URL"
                                );
                                all_urls.append(&mut srv_urls);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    nested_url = %nested_url,
                                    error = ?e,
                                    "Failed to resolve nested SRV URL"
                                );
                            }
                        }
                    }

                    // Wait for all nested resolution tasks to complete
                    if txt_count > 0 || srv_count > 0 {
                        tracing::debug!(
                            txt_tasks = txt_count,
                            srv_tasks = srv_count,
                            "MultiConnector: Completed {} nested resolution tasks (TXT: {}, SRV: {})",
                            txt_count + srv_count, txt_count, srv_count
                        );
                    }

                    tracing::debug!(
                        domain_name = %domain_name,
                        urls_count = all_urls.len(),
                        "MultiConnector: TXT resolution completed"
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::error!(
                        domain_name = %domain_name,
                        error = ?e,
                        "MultiConnector: TXT lookup failed"
                    );
                    Err(anyhow::anyhow!("TXT lookup failed for domain: {}", domain_name).into())
                }
            }
        })
    }

    async fn resolve_single_protocol_srv(
        domain_name: &str,
        protocol: &str,
    ) -> Result<Option<String>, Error> {
        let srv_domain = format!("_easytier._{}.{}", protocol, domain_name);
        
        tracing::debug!(
            srv_domain = %srv_domain,
            protocol = %protocol,
            "MultiConnector: Starting SRV lookup for single protocol"
        );

        // Resolve SRV
        match RESOLVER.srv_lookup(&srv_domain).await {
            Ok(response) => {
                let record_count = response.iter().count();
                if record_count == 0 {
                    tracing::debug!(
                        srv_domain = %srv_domain,
                        protocol = %protocol,
                        "MultiConnector: No SRV records found for protocol"
                    );
                    return Ok(None);
                }

                tracing::debug!(
                    srv_domain = %srv_domain,
                    protocol = %protocol,
                    record_count = record_count,
                    "MultiConnector: Found {} SRV records for protocol",
                    record_count
                );

                // Maintain the lowest priority
                let mut min_priority_records = MinPriorityRecords::new();
                
                for (index, record) in response.iter().enumerate() {
                    tracing::debug!(
                        srv_domain = %srv_domain,
                        protocol = %protocol,
                        record_index = index + 1,
                        target = %record.target().to_utf8().trim_end_matches('.'),
                        port = record.port(),
                        priority = record.priority(),
                        weight = record.weight(),
                        "MultiConnector: Processing SRV record for protocol"
                    );
                    
                    match Self::handle_one_srv_record(record, protocol) {
                        Ok(srv_record) => {
                            tracing::debug!(
                                srv_domain = %srv_domain,
                                protocol = %protocol,
                                ?srv_record,
                                "MultiConnector: Successfully parsed SRV record"
                            );
                            min_priority_records.add_record(srv_record, protocol.to_string());
                        }
                        Err(e) => {
                            tracing::warn!(
                                srv_domain = %srv_domain,
                                protocol = %protocol,
                                error = ?e,
                                "MultiConnector: Failed to parse SRV record, skipping"
                            );
                        }
                    }
                }

                // Select by weight
                match min_priority_records.select_by_weight() {
                    Some(urls) if !urls.is_empty() => {
                        // 取第一个URL (应该只有一个，因为只处理一个协议)
                        let selected_url = urls[0].clone();
                        tracing::info!(
                            srv_domain = %srv_domain,
                            protocol = %protocol,
                            selected_url = %selected_url,
                            "MultiConnector: Selected URL for protocol using weight algorithm"
                        );
                        Ok(Some(selected_url))
                    }
                    _ => {
                        tracing::warn!(
                            srv_domain = %srv_domain,
                            protocol = %protocol,
                            "MultiConnector: Weight selection failed for protocol"
                        );
                        Ok(None)
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    srv_domain = %srv_domain,
                    protocol = %protocol,
                    error = ?e,
                    "MultiConnector: SRV lookup failed for protocol"
                );
                Ok(None) // Return None so that other resolve process can keep going
            }
        }
    }

    fn handle_one_srv_record(
        record: &hickory_resolver::proto::rr::rdata::SRV,
        _protocol: &str,
    ) -> Result<SrvRecord, Error> {
        let target = record.target().to_utf8().trim_end_matches('.').to_string();
        let port = record.port();
        let priority = record.priority();
        let weight = record.weight();

        if target.is_empty() || port == 0 {
            return Err(anyhow::anyhow!("Invalid SRV record: empty target or zero port").into());
        }

        Ok(SrvRecord {
            target,
            port,
            priority,
            weight,
        })
    }
}

#[async_trait]
impl TunnelConnector for MultiConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let scheme = self.url.scheme().to_string();
        let url_str = self.url.to_string();
        
        tracing::info!(url = %url_str, scheme = %scheme, "MultiConnector: Starting resolution");

        // if conn_manager，carry out resolve and create connector
        if let Some(conn_manager) = &self.conn_manager {
            let result = match scheme.as_str() {
                "txt" => {
                    Self::resolve_txt_domain(&url_str, conn_manager, &self.global_ctx).await
                }
                "srv" => {
                    Self::resolve_srv_domain(&url_str, conn_manager, &self.global_ctx).await
                }
                _ => {
                    return Err(TunnelError::Anyhow(
                        anyhow::anyhow!("Unsupported scheme for MultiConnector: {}", scheme)
                    ));
                }
            };
            
            match result {
                Ok(count) => {
                    tracing::info!(url = %url_str, count = count, "MultiConnector: Resolution completed");
                }
                Err(e) => {
                    tracing::error!(url = %url_str, error = ?e, "MultiConnector: Resolution failed");
                    return Err(TunnelError::Anyhow(e.into()));
                }
            }
        }

        // Trigger an error since multi do not return any tunnel directly
        Err(TunnelError::Anyhow(
            anyhow::anyhow!("MultiConnector completed resolution, no direct tunnel created")
        ))
    }

    fn remote_url(&self) -> url::Url {
        self.url.clone()
    }

    fn set_bind_addrs(&mut self, _addrs: Vec<SocketAddr>) {
        // MultiConnector no need to bind addrs
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}