use std::collections::HashSet;
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;

use crate::{
    common::{
        dns::RESOLVER,
        error::Error,
        global_ctx::GlobalCtx,
    },
    connector::manual::{ManualConnectorManager},
};

use tokio::sync::Mutex;
use dashmap::DashMap;
use rand::seq::SliceRandom;
use rand::Rng;

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
                // Randomly select using weights
                let mut rng = rand::thread_rng();
                let rand_val = rng.gen_range(1..=total_weight);
                let mut accumulated_weight = 0u32;

                tracing::debug!(
                    protocol = %protocol,
                    total_weight = total_weight,
                    random_value = rand_val,
                    "Using weight-based selection for protocol"
                );

                for record in records.iter() {
                    accumulated_weight += record.weight as u32;
                    if accumulated_weight >= rand_val {
                        tracing::info!(
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

pub struct MultiConnector;

impl MultiConnector {
    /// Start TXT domain resolution
    pub async fn resolve_txt_domain(
        target_url: &str,
        conn_manager: &Arc<ManualConnectorManager>,
        _global_ctx: &Arc<GlobalCtx>,
    ) -> Result<usize, Error> {
        let mut visited = HashSet::new();
        let mut all_urls = Vec::new();

        // Start TXT resolution process, notice this is a recursive process
        Self::resolve_txt_record(target_url, &mut visited, &mut all_urls, 0).await?;
        
        Self::add_urls_as_peers(all_urls, conn_manager).await
    }

    /// Start SRV domain resolution  
    pub async fn resolve_srv_domain(
        target_url: &str,
        conn_manager: &Arc<ManualConnectorManager>, 
        _global_ctx: &Arc<GlobalCtx>,
    ) -> Result<usize, Error> {
        let mut all_urls = Vec::new();
        
        // Extract domain from srv://domain
        let domain = if let Some(domain) = target_url.strip_prefix("srv://") {
            domain
        } else {
            return Err(anyhow::anyhow!("Invalid SRV URL format: {}", target_url).into());
        };
        
        // Resolve SRV records to URLs into protocol://domain:port
        Self::resolve_srv_to_urls(domain, &mut all_urls).await?;
        
        Self::add_urls_as_peers(all_urls, conn_manager).await
    }

    /// Method to add URLs as peers
    async fn add_urls_as_peers(
        all_urls: Vec<String>,
        conn_manager: &Arc<ManualConnectorManager>,
    ) -> Result<usize, Error> {
        let mut total_peers_added = 0;
        
        
        for url in all_urls {
            tracing::debug!(url = %url, "MultiConnector: Adding connector for collected URL");
            match conn_manager.add_connector_by_url(&url).await {
                Ok(_) => {
                    tracing::debug!(url = %url, "MultiConnector: Successfully added connector");
                    total_peers_added += 1;
                }
                Err(e) => {
                    tracing::error!(url = %url, error = ?e, "MultiConnector: Failed to add connector");
                }
            }
        }
        
        if total_peers_added > 0 {
            println!("MultiConnector: Successfully resolved and added {} peer connections", total_peers_added);
            tracing::info!(
                "MultiConnector: Successfully added {} peer connections",
                total_peers_added
            );
            Ok(total_peers_added)
        } else {
            tracing::error!("MultiConnector: No peer connections added");
            Err(anyhow::anyhow!("No peer connections added").into())
        }
    }

    // Record resolution to collect URLs - only accepts target_url parameter
    fn resolve_txt_record<'a>(
        target_url: &'a str,
        visited: &'a mut HashSet<String>,
        all_urls: &'a mut Vec<String>,
        depth: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
        Box::pin(async move {
            const MAX_DEPTH: usize = 10;
            
            if depth > MAX_DEPTH {
                tracing::warn!("MultiConnector: Maximum depth {} exceeded for target_url {}", MAX_DEPTH, target_url);
                return Err(anyhow::anyhow!("Maximum depth exceeded").into());
            }
            
            // Parse target_url to get scheme and domain
            let (scheme, domain) = if let Some((scheme, rest)) = target_url.split_once("://") {
                (scheme.to_lowercase(), rest)
            } else {
                return Err(anyhow::anyhow!("Invalid URL format: {}", target_url).into());
            };
            
            if visited.contains(target_url) {
                tracing::warn!("MultiConnector: Cycle detected for target_url {}, skipping", target_url);
                return Ok(()); // Don't error on cycles, just skip
            }
            
            visited.insert(target_url.to_string());
            
            tracing::debug!(
                target_url = %target_url,
                scheme = %scheme,
                domain = %domain,
                depth = depth,
                "MultiConnector: Starting record resolution"
            );

            match scheme.as_str() {
                "txt" => {
                    // TXT records support nesting records
                    match Self::resolve_txt_to_urls(domain, visited, all_urls, depth).await {
                        Ok(_) => {
                            tracing::debug!(
                                target_url = %target_url,
                                "MultiConnector: TXT resolution completed"
                            );
                            // Remove from visited set after successful resolution
                            visited.remove(target_url);
                            Ok(())
                        }
                        Err(e) => {
                            tracing::error!(
                                target_url = %target_url,
                                error = ?e,
                                "MultiConnector: TXT resolution failed"
                            );
                            visited.remove(target_url);
                            Err(e)
                        }
                    }
                }
                "srv" => {
                    // SRV records can "be unziped" into protocol://domain:port(s)
                    match Self::resolve_srv_to_urls(domain, all_urls).await {
                        Ok(_) => {
                            tracing::debug!(
                                target_url = %target_url,
                                "MultiConnector: SRV resolution completed"
                            );
                            visited.remove(target_url);
                            Ok(())
                        }
                        Err(e) => {
                            tracing::error!(
                                target_url = %target_url,
                                error = ?e,
                                "MultiConnector: SRV resolution failed"
                            );
                            visited.remove(target_url);
                            Err(e)
                        }
                    }
                }
                _ => {
                    tracing::error!(
                        target_url = %target_url,
                        scheme = %scheme,
                        "MultiConnector: Unsupported scheme"
                    );
                    visited.remove(target_url);
                    Err(anyhow::anyhow!("Unsupported scheme: {}", scheme).into())
                }
            }
        })
    }

    /// TXT record resolution to collect URLs
    async fn resolve_txt_to_urls(
        domain_name: &str,
        visited: &mut HashSet<String>,
        all_urls: &mut Vec<String>,
        depth: usize,
    ) -> Result<(), Error> {
        tracing::debug!(
            domain_name = %domain_name,
            depth = depth,
            "MultiConnector: Starting TXT record resolution"
        );

        match RESOLVER.txt_lookup(domain_name).await {
            Ok(response) => {
                for txt_record in response.iter() {
                    let record_data = txt_record.to_string();
                    tracing::debug!(
                        domain_name = %domain_name,
                        record_data = %record_data,
                        "MultiConnector: Processing TXT record"
                    );

                    // Parse comma-separated URLs from TXT record
                    let entries: Vec<&str> = record_data.split(',').map(|s| s.trim()).collect();
                    
                    for entry in entries {
                        if entry.is_empty() {
                            continue;
                        }

                        tracing::debug!(
                            domain_name = %domain_name,
                            entry = %entry,
                            "MultiConnector: Processing entry from TXT record"
                        );

                        // Match entry format: protocol://domain:port
                        if let Some((protocol, _rest)) = entry.split_once("://") {
                            match protocol.to_lowercase().as_str() {
                                "tcp" | "udp" | "ws" | "wss" | "wg" => {
                                    // Fundamental protocols - add to urls directly
                                    tracing::debug!(
                                        entry = %entry,
                                        protocol = %protocol,
                                        "MultiConnector: Adding supported protocol URL"
                                    );
                                    all_urls.push(entry.to_string());
                                }
                                "txt" => {
                                    // Nested TXT record -> keep resolving
                                    let nested_url = entry.to_string();
                                    tracing::debug!(
                                        entry = %entry,
                                        nested_url = %nested_url,
                                        "MultiConnector: Found nested TXT URL, resolving"
                                    );
                                    
                                    if let Err(e) = Self::resolve_txt_record(&nested_url, visited, all_urls, depth + 1).await {
                                        tracing::warn!(
                                            nested_url = %nested_url,
                                            error = ?e,
                                            "MultiConnector: Failed to resolve nested TXT URL"
                                        );
                                    }
                                }
                                "srv" => {
                                    // SRV record -> let resolve_srv_to_urls handle it
                                    let nested_url = entry.to_string();
                                    tracing::debug!(
                                        entry = %entry,
                                        nested_url = %nested_url,
                                        "MultiConnector: Found nested SRV URL, resolving"
                                    );
                                    
                                    if let Err(e) = Self::resolve_txt_record(&nested_url, visited, all_urls, depth + 1).await {
                                        tracing::warn!(
                                            nested_url = %nested_url,
                                            error = ?e,
                                            "MultiConnector: Failed to resolve nested SRV URL"
                                        );
                                    }
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
    }

    /// SRV record resolution to collect URLs
    async fn resolve_srv_to_urls(
        domain_name: &str,
        all_urls: &mut Vec<String>,
    ) -> Result<(), Error> {
        tracing::info!(
            domain_name = %domain_name,
            "MultiConnector: Starting SRV record resolution"
        );

        // Build the SRV domain lookup list for all supported protocols
        // Example: _easytier._tcp.domain.name
        let srv_domains = SUPPORTED_PROTOCOLS
            .iter()
            .map(|p| (format!("_easytier._{}.{}", p, domain_name), *p))
            .collect::<Vec<_>>();
        tracing::debug!(srv_domains = ?srv_domains, "MultiConnector: Built SRV domain lookup list");
        
        let min_priority_records = Arc::new(Mutex::new(MinPriorityRecords::new()));
        
        let srv_lookup_tasks = srv_domains
            .iter()
            .map(|(srv_domain, protocol)| {
                let resolver = RESOLVER.clone();
                let min_priority_records = min_priority_records.clone();
                let srv_domain = srv_domain.clone();
                let protocol = *protocol;
                async move {
                    tracing::debug!(srv_domain = %srv_domain, protocol = %protocol, "MultiConnector: Starting DNS SRV lookup");
                    
                    match resolver.srv_lookup(&srv_domain).await {
                        Ok(response) => {
                            let record_count = response.iter().count();
                            tracing::debug!(
                                srv_domain = %srv_domain,
                                protocol = %protocol,
                                record_count = record_count,
                                "MultiConnector: NSLookup success on {}: found {} records",
                                srv_domain, record_count
                            );
                            
                            // Process each SRV record
                            for (index, record) in response.iter().enumerate() {
                                tracing::debug!(
                                    srv_domain = %srv_domain,
                                    protocol = %protocol,
                                    record_index = index + 1,
                                    target = %record.target().to_utf8().trim_end_matches('.'),
                                    port = record.port(),
                                    priority = record.priority(),
                                    weight = record.weight(),
                                    "MultiConnector: Found SRV record"
                                );
                                
                                // Handle SRV record and convert to "SrvRecord" data structure
                                match Self::handle_one_srv_record(record, &protocol) {
                                    Ok(srv_record) => {
                                        tracing::debug!(
                                            srv_domain = %srv_domain,
                                            protocol = %protocol,
                                            ?srv_record,
                                            "MultiConnector: Successfully parsed SRV record"
                                        );
                                        min_priority_records.lock().await.add_record(srv_record, protocol.to_string());
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            srv_domain = %srv_domain,
                                            protocol = %protocol,
                                            error = ?e,
                                            "MultiConnector: Failed to parse SRV record, skipping"
                                        );
                                        continue;
                                    }
                                }
                            }
                            Ok::<_, Error>(())
                        }
                        Err(e) => {
                            tracing::debug!(
                                srv_domain = %srv_domain,
                                protocol = %protocol,
                                error = ?e,
                                "MultiConnector: NSLookup failed for {}, ignoring",
                                srv_domain
                            );
                            Ok(())
                        }
                    }
                }
            })
            .collect::<Vec<_>>();
        
        tracing::debug!("MultiConnector: Waiting for all SRV lookup tasks to complete");
        let _ = futures::future::join_all(srv_lookup_tasks).await;

        tracing::debug!("MultiConnector: All SRV lookups completed, starting final selection");
        let selected_urls = min_priority_records
            .lock()
            .await
            .select_by_weight();

        match selected_urls {
            Some(urls) => {
                tracing::info!(urls = ?urls, total_protocols = urls.len(), "MultiConnector: SRV record resolution completed successfully, selected URLs from all protocols");
                
                for url in urls {
                    tracing::debug!(url = %url, "MultiConnector: Adding SRV resolved URL");
                    all_urls.push(url);
                }
                
                tracing::info!(
                    "MultiConnector: Successfully collected {} URLs from SRV resolution for domain {}",
                    all_urls.len(),
                    domain_name
                );
                Ok(())
            }
            None => {
                tracing::error!("MultiConnector: SRV record resolution failed: no valid records found");
                Err(anyhow::anyhow!("No SRV records found for domain: {}", domain_name).into())
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
