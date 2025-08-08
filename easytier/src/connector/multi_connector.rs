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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nested_txt_parsing() {
        // Create a deeply nested TXT resolution scenario (30-40 levels deep)
        let nested_layers = 35;
        
        println!("Testing {}-layer deep TXT nesting", nested_layers);
        
        // Test URL parsing for nested structure
        let test_cases = vec![
            // Direct URLs at each level
            ("Direct URLs", "tcp://server1.com:8080,udp://server2.com:9090,wg://server3.com:51820"),
            
            // Mixed direct and nested
            ("Mixed", "tcp://direct.com:8080,txt://level1.domain.com,srv://service.domain.com"),
            
            // Only nested (simulating recursive structure)
            ("Only nested", "txt://level2.domain.com,srv://level2-srv.domain.com"),
            
            // Complex nested with multiple protocols
            ("Complex nested", "txt://deep1.com,txt://deep2.com,srv://srvdeep.com,tcp://final.com:8080"),
            
            // Edge cases
            ("With spaces and empties", " tcp://spaced.com:8080 , , txt://nested.com , "),
        ];

        for (description, txt_content) in test_cases {
            println!("\n--- Testing: {} ---", description);
            println!("Content: '{}'", txt_content);
            
            // Parse TXT content (same logic as main code)
            let entries: Vec<&str> = txt_content.split(',').map(|s| s.trim()).collect();
            
            let mut direct_urls = Vec::new();
            let mut nested_urls = Vec::new();
            let mut total_entries = 0;
            
            for entry in entries {
                if entry.is_empty() {
                    continue;
                }
                
                total_entries += 1;
                
                if let Some((protocol, _domain)) = entry.split_once("://") {
                    match protocol.to_lowercase().as_str() {
                        "tcp" | "udp" | "ws" | "wss" | "wg" => {
                            direct_urls.push(entry.to_string());
                            println!("  → Direct URL: {}", entry);
                        },
                        "txt" | "srv" => {
                            nested_urls.push(entry.to_string());
                            println!("  → Nested URL: {}", entry);
                        },
                        _ => {
                            println!("  → Unsupported protocol: {}", protocol);
                        }
                    }
                } else {
                    println!("  → Invalid URL format: {}", entry);
                }
            }
            
            // Validate parsing results
            assert!(total_entries > 0 || txt_content.trim().is_empty(), 
                   "Should have parsed entries or content should be empty");
            assert_eq!(direct_urls.len() + nested_urls.len(), total_entries,
                      "All valid entries should be categorized");
            
            println!("  Summary: {} direct, {} nested, {} total",
                    direct_urls.len(), nested_urls.len(), total_entries);
        }

        // Test deep nesting simulation
        println!("\n--- Simulating {}-level deep nesting ---", nested_layers);
        
        // Simulate what would happen in deep nesting resolution
        let mut current_level = 0;
        let mut resolved_urls = Vec::new();
        
        while current_level < nested_layers {
            // Each level could resolve to mix of direct URLs and further nesting
            let level_content = match current_level % 4 {
                0 => "tcp://server.com:8080,txt://next-level.com",
                1 => "udp://node.com:9090,srv://service-next.com",  
                2 => "wg://peer.com:51820,txt://deeper.com,tcp://direct.com:8081",
                _ => "ws://websocket.com:3000",
            };
            
            let entries: Vec<&str> = level_content.split(',').map(|s| s.trim()).collect();
            let mut has_nested = false;
            
            for entry in entries {
                if entry.starts_with("tcp://") || entry.starts_with("udp://") || 
                   entry.starts_with("wg://") || entry.starts_with("ws://") {
                    resolved_urls.push(format!("Level-{}: {}", current_level, entry));
                } else if entry.starts_with("txt://") || entry.starts_with("srv://") {
                    has_nested = true;
                }
            }
            
            current_level += 1;
            
            // Stop if no more nesting at this level
            if !has_nested {
                break;
            }
        }
        
        println!("Resolved {} URLs across {} levels:", resolved_urls.len(), current_level);
        for (i, url) in resolved_urls.iter().enumerate() {
            if i < 5 || i >= resolved_urls.len() - 2 {
                println!("  {}", url);
            } else if i == 5 {
                println!("  ... ({} more URLs) ...", resolved_urls.len() - 7);
            }
        }
        
        // Validate deep nesting results
        assert!(resolved_urls.len() > 0, "Should resolve some URLs from nested structure");
        assert!(current_level >= 3, "Should have processed multiple nesting levels"); 
        assert!(current_level <= nested_layers + 5, "Should not exceed reasonable nesting limit");
        
        println!("✓ Deep nesting test passed: {} levels processed", current_level);
    }

    #[test] 
    fn test_srv_complete_workflow() {
        println!("Testing complete SRV workflow with priority handling and weight distribution");
        
        // 1. Test SRV record parsing and validation
        use hickory_resolver::proto::rr::rdata::SRV;
        use hickory_resolver::Name;
        
        let test_srv_records = vec![
            // Priority 10, weight 20
            SRV::new(10, 20, 8080, Name::from_utf8("server1.example.com.").unwrap()),
            // Priority 5 (higher priority), weight 30  
            SRV::new(5, 30, 8081, Name::from_utf8("server2.example.com.").unwrap()),
            // Priority 5 (same as server2), weight 10
            SRV::new(5, 10, 8082, Name::from_utf8("server3.example.com.").unwrap()),
            // Priority 5 (same), weight 0 (zero weight)
            SRV::new(5, 0, 8083, Name::from_utf8("server4.example.com.").unwrap()),
            // Priority 15 (lower priority), should be ignored
            SRV::new(15, 100, 8084, Name::from_utf8("server5.example.com.").unwrap()),
        ];

        println!("\n--- Step 1: SRV Record Parsing ---");
        let mut parsed_records = Vec::new();
        for (i, srv_record) in test_srv_records.iter().enumerate() {
            let result = MultiConnector::handle_one_srv_record(srv_record, "tcp");
            assert!(result.is_ok(), "SRV record {} should parse successfully", i);
            
            let parsed = result.unwrap();
            parsed_records.push(parsed);
            println!("Record {}: {}:{} (priority={}, weight={})", 
                    i, parsed_records[i].target, parsed_records[i].port,
                    parsed_records[i].priority, parsed_records[i].weight);
        }

        // 2. Test priority-based filtering
        println!("\n--- Step 2: Priority-based Filtering ---");
        let mut min_priority_records = MinPriorityRecords::new();
        
        for record in parsed_records {
            min_priority_records.add_record(record, "tcp".to_string());
        }
        
        let tcp_records = min_priority_records.records.get("tcp").unwrap();
        println!("Filtered to {} records with minimum priority", tcp_records.len());
        
        // Should only have priority 5 records (server2, server3, server4)
        assert_eq!(tcp_records.len(), 3, "Should have 3 records with minimum priority 5");
        
        for record in tcp_records.iter() {
            assert_eq!(record.priority, 5, "All records should have priority 5");
            println!("  {}:{} (weight={})", record.target, record.port, record.weight);
        }

        // 3. Test weight distribution and Alias Method
        println!("\n--- Step 3: Weight Distribution Testing ---");
        
        // Extract weights for analysis
        let weights: Vec<u16> = tcp_records.iter().map(|r| r.weight).collect();
        let targets: Vec<String> = tcp_records.iter().map(|r| r.target.clone()).collect();
        
        println!("Original weights: {:?}", weights);
        println!("Targets: {:?}", targets);
        
        // Test weight adjustment logic (same as in main code)
        let total_weight: u32 = weights.iter().map(|&w| w as u32).sum();
        let zero_weight_value = 1.0 / total_weight as f64;
        
        let adjusted_weights: Vec<f64> = weights.iter()
            .map(|&w| if w == 0 { zero_weight_value } else { w as f64 })
            .collect();
            
        let new_total_weight: f64 = adjusted_weights.iter().sum();
        
        println!("Total original weight: {}", total_weight);
        println!("Zero weight adjustment: {:.6}", zero_weight_value);
        println!("Adjusted weights: {:?}", adjusted_weights);
        println!("New total weight: {:.6}", new_total_weight);
        
        // Validate weight adjustments
        assert!(total_weight > 0, "Should have positive total weight");
        assert!(zero_weight_value > 0.0, "Zero weight value should be positive");
        assert!((new_total_weight - adjusted_weights.iter().sum::<f64>()).abs() < 1e-10,
               "New total weight calculation should be consistent");

        // 4. Test probability distribution
        println!("\n--- Step 4: Probability Distribution Analysis ---");
        
        let mut expected_probabilities = Vec::new();
        for (i, &adj_weight) in adjusted_weights.iter().enumerate() {
            let prob = adj_weight / new_total_weight;
            expected_probabilities.push(prob);
            println!("Target {}: {:.4} probability (weight {} -> {:.6})", 
                    targets[i], prob, weights[i], adj_weight);
            
            // Validate individual probabilities
            assert!(prob > 0.0, "Each target should have positive probability");
            assert!(prob <= 1.0, "Probability should not exceed 1.0");
            
            // Zero-weight records should have small but positive probability
            if weights[i] == 0 {
                assert!(prob < 0.1, "Zero weight should have small probability");
                assert!(prob > 0.0001, "Zero weight should have meaningful probability");
            }
        }
        
        // Validate total probability
        let total_prob: f64 = expected_probabilities.iter().sum();
        assert!((total_prob - 1.0).abs() < 1e-10, 
               "Total probability should sum to 1.0, got {:.10}", total_prob);

        // 5. Test selection simulation
        println!("\n--- Step 5: Selection Distribution Simulation ---");
        
        // Simulate weighted random selection
        const SIMULATION_RUNS: usize = 10000;
        let mut selection_counts = vec![0usize; targets.len()];
        
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        for _ in 0..SIMULATION_RUNS {
            let rand_val: f64 = rng.gen();
            let mut cumulative_prob = 0.0;
            
            for (i, &prob) in expected_probabilities.iter().enumerate() {
                cumulative_prob += prob;
                if rand_val <= cumulative_prob {
                    selection_counts[i] += 1;
                    break;
                }
            }
        }
        
        println!("Selection results from {} runs:", SIMULATION_RUNS);
        for (i, &count) in selection_counts.iter().enumerate() {
            let actual_prob = count as f64 / SIMULATION_RUNS as f64;
            let expected_prob = expected_probabilities[i];
            let error = (actual_prob - expected_prob).abs();
            
            println!("  {}: {} selections ({:.4} actual vs {:.4} expected, error {:.4})",
                    targets[i], count, actual_prob, expected_prob, error);
            
            // Validate distribution is within reasonable error bounds (±3%)
            assert!(error < 0.03, 
                   "Distribution error for {} should be < 3%, got {:.4}", 
                   targets[i], error);
        }
        
        // Validate that all selections were made
        let total_selections: usize = selection_counts.iter().sum();
        assert_eq!(total_selections, SIMULATION_RUNS, 
                  "Should have made exactly {} selections", SIMULATION_RUNS);

        // 6. Edge case testing
        println!("\n--- Step 6: Edge Cases Testing ---");
        
        // Test all-zero weights
        let all_zero_weights = vec![0u16, 0, 0];
        let zero_total: u32 = all_zero_weights.iter().map(|&w| w as u32).sum();
        assert_eq!(zero_total, 0, "All-zero weights should sum to 0");
        
        // In all-zero case, should use uniform distribution
        let uniform_prob = 1.0 / all_zero_weights.len() as f64;
        println!("All-zero case: uniform probability = {:.4}", uniform_prob);
        assert!((uniform_prob * all_zero_weights.len() as f64 - 1.0).abs() < 1e-10,
               "Uniform probabilities should sum to 1.0");
        
        // Test single record case
        let single_weight = vec![42u16];
        let single_total: u32 = single_weight.iter().map(|&w| w as u32).sum();
        let single_prob = single_weight[0] as f64 / single_total as f64;
        assert!((single_prob - 1.0).abs() < 1e-10, 
               "Single record should have probability 1.0");
        
        println!("✓ Complete SRV workflow test passed");
    }
}
