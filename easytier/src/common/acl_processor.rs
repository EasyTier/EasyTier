use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use tokio::sync::{RwLock, RwLock as AsyncRwLock};

use crate::common::token_bucket::TokenBucket;
use crate::proto::{acl::*, common::IpInet};

// Fast lookup structures for performance optimization
#[derive(Debug, Clone)]
pub struct FastLookupRule {
    pub priority: u32,
    pub protocol: Protocol,
    pub src_ip_ranges: Vec<cidr::IpCidr>,
    pub dst_ip_ranges: Vec<cidr::IpCidr>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub action: Action,
    pub enabled: bool,
    pub stateful: bool,
    pub rate_limit: u32,
    pub burst_limit: u32,
}

// Connection tracking entry
#[derive(Debug, Clone)]
pub struct ConnTrackEntry {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub protocol: u8,
    pub state: ConnState,
    pub created_at: u64,
    pub last_seen: u64,
    pub packet_count: u64,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    New,
    Established,
    Related,
    Invalid,
}

// Cache key combining packet info and chain type
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AclCacheKey {
    pub chain_type: ChainType,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl AclCacheKey {
    pub fn from_packet_info(packet_info: &PacketInfo, chain_type: ChainType) -> Self {
        Self {
            chain_type,
            protocol: packet_info.protocol,
            src_ip: packet_info.src_ip,
            dst_ip: packet_info.dst_ip,
            src_port: packet_info.src_port.unwrap_or(0),
            dst_port: packet_info.dst_port.unwrap_or(0),
        }
    }
}

// Cache entry with timestamp for LRU cleanup
#[derive(Debug, Clone)]
pub struct AclCacheEntry {
    pub action: Action,
    pub matched_rule: String,
    pub last_access: u64,
}

// Packet info extracted for ACL processing
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8,
    pub packet_size: usize,
}

// ACL processing result
#[derive(Debug, Clone)]
pub struct AclResult {
    pub action: Action,
    pub matched_rule: Option<String>,
    pub should_log: bool,
    pub log_context: Option<AclLogContext>,
}

// Context for lazy log message construction
#[derive(Debug, Clone)]
pub enum AclLogContext {
    StatefulMatch {
        src_ip: IpAddr,
        dst_ip: IpAddr,
    },
    RuleMatch {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        action: Action,
    },
    DefaultDrop,
    UnsupportedChainType,
}

impl AclLogContext {
    pub fn to_message(&self) -> String {
        match self {
            AclLogContext::StatefulMatch { src_ip, dst_ip } => {
                format!("Stateful match: {} -> {}", src_ip, dst_ip)
            }
            AclLogContext::RuleMatch {
                src_ip,
                dst_ip,
                action,
            } => {
                format!("Rule match: {} -> {} action: {:?}", src_ip, dst_ip, action)
            }
            AclLogContext::DefaultDrop => "No matching rule, default drop".to_string(),
            AclLogContext::UnsupportedChainType => "Unsupported chain type".to_string(),
        }
    }
}

// High-performance ACL processor
pub struct AclProcessor {
    // Fast lookup structures organized by chain type
    inbound_rules: Arc<RwLock<Vec<FastLookupRule>>>,
    outbound_rules: Arc<RwLock<Vec<FastLookupRule>>>,
    forward_rules: Arc<RwLock<Vec<FastLookupRule>>>,

    // Connection tracking table
    conn_track: Arc<DashMap<String, ConnTrackEntry>>,

    // Rate limiting buckets per rule using TokenBucket
    rate_limiters: Arc<DashMap<String, Arc<TokenBucket>>>,

    // Rule lookup cache with LRU cleanup
    rule_cache: Arc<DashMap<AclCacheKey, AclCacheEntry>>,
    cache_max_size: usize,
    cache_cleanup_interval: Duration,

    // Global configuration
    config: Arc<AsyncRwLock<Acl>>,

    // Statistics
    stats: Arc<DashMap<AclStatKey, u64>>,
}

impl AclProcessor {
    pub fn new(acl_config: Acl) -> Self {
        let processor = Self {
            inbound_rules: Arc::new(RwLock::new(Vec::new())),
            outbound_rules: Arc::new(RwLock::new(Vec::new())),
            forward_rules: Arc::new(RwLock::new(Vec::new())),
            conn_track: Arc::new(DashMap::new()),
            rate_limiters: Arc::new(DashMap::new()),
            rule_cache: Arc::new(DashMap::new()),
            cache_max_size: 10000, // Limit cache to 10k entries
            cache_cleanup_interval: Duration::from_secs(300), // Cleanup every 5 minutes
            config: Arc::new(AsyncRwLock::new(acl_config.clone())),
            stats: Arc::new(DashMap::new()),
        };

        // Note: Use new_with_async_init for proper async initialization
        processor
    }

    /// Create a new ACL processor with async initialization
    pub async fn new_with_async_init(acl_config: Acl) -> Self {
        let processor = Self::new(acl_config.clone());
        processor.reload_rules(&acl_config).await;
        processor.start_cache_cleanup_task();
        processor
    }

    /// Start periodic cache cleanup task
    fn start_cache_cleanup_task(&self) {
        let rule_cache = self.rule_cache.clone();
        let cache_max_size = self.cache_max_size;
        let cleanup_interval = self.cache_cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                Self::cleanup_cache(&rule_cache, cache_max_size).await;
            }
        });
    }

    /// Clean up cache using LRU strategy
    async fn cleanup_cache(cache: &DashMap<AclCacheKey, AclCacheEntry>, max_size: usize) {
        let current_size = cache.len();
        if current_size <= max_size {
            return;
        }

        // Remove oldest entries (LRU cleanup)
        let mut entries: Vec<(AclCacheKey, u64)> = cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().last_access))
            .collect();

        // Sort by last_access (oldest first)
        entries.sort_by_key(|(_, last_access)| *last_access);

        // Remove oldest 20% of entries
        let to_remove = current_size - max_size + (max_size / 5);
        for (key, _) in entries.into_iter().take(to_remove) {
            cache.remove(&key);
        }

        tracing::debug!(
            "Cache cleanup completed: removed {} entries, current size: {}",
            to_remove,
            cache.len()
        );
    }

    /// Reload ACL rules and rebuild lookup structures
    pub async fn reload_rules(&self, acl_config: &Acl) {
        let mut inbound = self.inbound_rules.write().await;
        let mut outbound = self.outbound_rules.write().await;
        let mut forward = self.forward_rules.write().await;

        inbound.clear();
        outbound.clear();
        forward.clear();

        // Access chains through acl_v1
        if let Some(ref acl_v1) = acl_config.acl_v1 {
            for chain in &acl_v1.chains {
                if !chain.enabled {
                    continue;
                }

                let rules = chain
                    .rules
                    .iter()
                    .filter(|rule| rule.enabled)
                    .map(|rule| self.convert_to_fast_lookup_rule(rule))
                    .collect::<Vec<_>>();

                match chain.chain_type() {
                    ChainType::Inbound => {
                        inbound.extend(rules);
                        inbound.sort_by(|a, b| b.priority.cmp(&a.priority));
                    }
                    ChainType::Outbound => {
                        outbound.extend(rules);
                        outbound.sort_by(|a, b| b.priority.cmp(&a.priority));
                    }
                    ChainType::Forward => {
                        forward.extend(rules);
                        forward.sort_by(|a, b| b.priority.cmp(&a.priority));
                    }
                    _ => {}
                }
            }
        }

        // Clear cache when rules change
        self.rule_cache.clear();
        tracing::info!(
            "ACL rules reloaded: {} inbound, {} outbound, {} forward",
            inbound.len(),
            outbound.len(),
            forward.len()
        );
    }

    /// Process a packet through ACL rules
    pub async fn process_packet(
        &self,
        packet_info: &PacketInfo,
        chain_type: ChainType,
    ) -> AclResult {
        // Check cache first for performance
        let cache_key = AclCacheKey::from_packet_info(packet_info, chain_type);
        if let Some(mut cached) = self.rule_cache.get_mut(&cache_key) {
            // Update last access time for LRU
            cached.last_access = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.increment_stat(AclStatKey::CacheHits);
            return AclResult {
                action: cached.action.clone(),
                matched_rule: Some(cached.matched_rule.clone()),
                should_log: false,
                log_context: None,
            };
        }

        // Clone rules to avoid holding lock across await points
        let rules = match chain_type {
            ChainType::Inbound => self.inbound_rules.read().await.clone(),
            ChainType::Outbound => self.outbound_rules.read().await.clone(),
            ChainType::Forward => self.forward_rules.read().await.clone(),
            _ => {
                return AclResult {
                    action: Action::Drop,
                    matched_rule: None,
                    should_log: false,
                    log_context: Some(AclLogContext::UnsupportedChainType),
                }
            }
        };

        // Process rules in priority order
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if self.rule_matches(rule, packet_info).await {
                // Check rate limiting
                if rule.rate_limit > 0 {
                    let rule_key = format!("{}:{}", chain_type as i32, rule.priority);
                    if !self
                        .check_rate_limit(&rule_key, rule.rate_limit, rule.burst_limit)
                        .await
                    {
                        continue; // Rate limited, try next rule
                    }
                }

                // Handle stateful connections
                if rule.stateful {
                    match self.check_connection_state(packet_info, &rule.action) {
                        Some(conn_action) => {
                            let result = AclResult {
                                action: conn_action,
                                matched_rule: Some(format!("stateful-{}", rule.priority)),
                                should_log: false,
                                log_context: Some(AclLogContext::StatefulMatch {
                                    src_ip: packet_info.src_ip,
                                    dst_ip: packet_info.dst_ip,
                                }),
                            };

                            // Cache the result
                            self.cache_result(&cache_key, &result);
                            return result;
                        }
                        None => continue,
                    }
                }

                // Rule matched, return action
                let result = AclResult {
                    action: rule.action.clone(),
                    matched_rule: Some(rule.priority.to_string()),
                    should_log: false,
                    log_context: Some(AclLogContext::RuleMatch {
                        src_ip: packet_info.src_ip,
                        dst_ip: packet_info.dst_ip,
                        action: rule.action,
                    }),
                };

                // Cache the result for frequently accessed patterns
                self.cache_result(&cache_key, &result);

                self.increment_stat(AclStatKey::RuleMatches);
                return result;
            }
        }

        // No rule matched, return default drop
        self.increment_stat(AclStatKey::DefaultDrops);
        let result = AclResult {
            action: Action::Drop,
            matched_rule: None,
            should_log: false,
            log_context: Some(AclLogContext::DefaultDrop),
        };

        // Cache the default result too
        self.cache_result(&cache_key, &result);
        result
    }

    /// Cache an ACL result
    fn cache_result(&self, cache_key: &AclCacheKey, result: &AclResult) {
        let entry = AclCacheEntry {
            action: result.action.clone(),
            matched_rule: result.matched_rule.clone().unwrap_or_default(),
            last_access: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.rule_cache.insert(cache_key.clone(), entry);

        // Trigger cleanup if cache is getting too large
        if self.rule_cache.len() > self.cache_max_size * 2 {
            let cache = self.rule_cache.clone();
            let max_size = self.cache_max_size;
            tokio::spawn(async move {
                Self::cleanup_cache(&cache, max_size).await;
            });
        }
    }

    /// Check if a rule matches the packet
    async fn rule_matches(&self, rule: &FastLookupRule, packet_info: &PacketInfo) -> bool {
        // Protocol check
        if rule.protocol != Protocol::Any && rule.protocol as i32 != packet_info.protocol as i32 {
            return false;
        }

        // Source IP check
        if !rule.src_ip_ranges.is_empty() {
            let matches = rule
                .src_ip_ranges
                .iter()
                .any(|cidr| match (cidr, packet_info.src_ip) {
                    (cidr::IpCidr::V4(v4_cidr), IpAddr::V4(v4_addr)) => v4_cidr.contains(&v4_addr),
                    (cidr::IpCidr::V6(v6_cidr), IpAddr::V6(v6_addr)) => v6_cidr.contains(&v6_addr),
                    _ => false,
                });
            if !matches {
                return false;
            }
        }

        // Destination IP check
        if !rule.dst_ip_ranges.is_empty() {
            let matches = rule
                .dst_ip_ranges
                .iter()
                .any(|cidr| match (cidr, packet_info.dst_ip) {
                    (cidr::IpCidr::V4(v4_cidr), IpAddr::V4(v4_addr)) => v4_cidr.contains(&v4_addr),
                    (cidr::IpCidr::V6(v6_cidr), IpAddr::V6(v6_addr)) => v6_cidr.contains(&v6_addr),
                    _ => false,
                });
            if !matches {
                return false;
            }
        }

        // Source port check
        if let (Some(src_port), Some(start), Some(end)) =
            (packet_info.src_port, rule.src_port_start, rule.src_port_end)
        {
            if src_port < start || src_port > end {
                return false;
            }
        }

        // Destination port check
        if let (Some(dst_port), Some(start), Some(end)) =
            (packet_info.dst_port, rule.dst_port_start, rule.dst_port_end)
        {
            if dst_port < start || dst_port > end {
                return false;
            }
        }

        true
    }

    /// Check connection state for stateful rules
    fn check_connection_state(
        &self,
        packet_info: &PacketInfo,
        rule_action: &Action,
    ) -> Option<Action> {
        let conn_key = format!(
            "{}:{}->{}:{}",
            packet_info.src_ip,
            packet_info.src_port.unwrap_or(0),
            packet_info.dst_ip,
            packet_info.dst_port.unwrap_or(0)
        );

        match self.conn_track.get_mut(&conn_key) {
            Some(mut entry) => {
                entry.last_seen = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                entry.packet_count += 1;
                entry.byte_count += packet_info.packet_size as u64;

                match entry.state {
                    ConnState::Established => Some(Action::Allow),
                    ConnState::New => {
                        if rule_action == &Action::Allow {
                            entry.state = ConnState::Established;
                            Some(Action::Allow)
                        } else {
                            Some(rule_action.clone())
                        }
                    }
                    ConnState::Invalid => Some(Action::Drop),
                    _ => Some(rule_action.clone()),
                }
            }
            None => {
                // New connection
                if rule_action == &Action::Allow {
                    let entry = ConnTrackEntry {
                        src_addr: SocketAddr::new(
                            packet_info.src_ip,
                            packet_info.src_port.unwrap_or(0),
                        ),
                        dst_addr: SocketAddr::new(
                            packet_info.dst_ip,
                            packet_info.dst_port.unwrap_or(0),
                        ),
                        protocol: packet_info.protocol,
                        state: ConnState::New,
                        created_at: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        last_seen: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        packet_count: 1,
                        byte_count: packet_info.packet_size as u64,
                    };
                    self.conn_track.insert(conn_key, entry);
                    Some(Action::Allow)
                } else {
                    Some(rule_action.clone())
                }
            }
        }
    }

    /// Check rate limiting for a rule
    async fn check_rate_limit(&self, rule_key: &str, rate: u32, burst: u32) -> bool {
        if rate == 0 {
            return true; // No rate limiting
        }

        // Insert if not exists first
        if !self.rate_limiters.contains_key(rule_key) {
            // Convert rate (packets per second) to token bucket parameters
            // For ACL, we typically want 1 token per packet, so capacity = burst, fill_rate = rate
            let bucket = TokenBucket::new(
                burst as u64,              // capacity (burst limit)
                rate as u64,               // fill_rate (tokens per second)
                Duration::from_millis(10), // refill_interval
            );
            self.rate_limiters.insert(rule_key.to_string(), bucket);
        }

        // Get reference to the bucket
        let bucket = self.rate_limiters.get(rule_key).unwrap().clone();

        // Try to consume 1 token (1 packet)
        bucket.try_consume(1)
    }

    /// Convert proto Rule to FastLookupRule
    fn convert_to_fast_lookup_rule(&self, rule: &Rule) -> FastLookupRule {
        let src_ip_ranges = rule
            .source_ips
            .iter()
            .filter_map(|ip_inet| self.convert_ip_inet_to_cidr(ip_inet))
            .collect();

        let dst_ip_ranges = rule
            .destination_ips
            .iter()
            .filter_map(|ip_inet| self.convert_ip_inet_to_cidr(ip_inet))
            .collect();

        FastLookupRule {
            priority: rule.priority,
            protocol: rule.protocol(),
            src_ip_ranges,
            dst_ip_ranges,
            src_port_start: rule.source_port_range.as_ref().map(|r| r.port_start as u16),
            src_port_end: rule.source_port_range.as_ref().map(|r| r.port_end as u16),
            dst_port_start: rule.port_range.as_ref().map(|r| r.port_start as u16),
            dst_port_end: rule.port_range.as_ref().map(|r| r.port_end as u16),
            action: rule.action(),
            enabled: rule.enabled,
            stateful: rule.stateful,
            rate_limit: rule.rate_limit,
            burst_limit: rule.burst_limit,
        }
    }

    /// Convert IpInet to CIDR for fast lookup
    fn convert_ip_inet_to_cidr(&self, _ip_inet: &IpInet) -> Option<cidr::IpCidr> {
        // This would need to be implemented based on the actual IpInet structure
        // For now, returning None as placeholder
        None
    }

    /// Increment statistics counter
    pub fn increment_stat(&self, key: AclStatKey) {
        self.stats
            .entry(key)
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
    }

    /// Get statistics
    pub fn get_stats(&self) -> HashMap<String, u64> {
        let mut stats = self
            .stats
            .iter()
            .map(|entry| (entry.key().as_str(), *entry.value()))
            .collect::<HashMap<_, _>>();

        // Add cache statistics using enum keys
        stats.insert(AclStatKey::CacheSize.as_str(), self.rule_cache.len() as u64);
        stats.insert(
            AclStatKey::CacheMaxSize.as_str(),
            self.cache_max_size as u64,
        );

        stats
    }

    /// Clean up expired connection tracking entries
    pub async fn cleanup_expired_connections(&self, timeout_secs: u64) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let keys_to_remove: Vec<String> = self
            .conn_track
            .iter()
            .filter_map(|entry| {
                if current_time - entry.last_seen > timeout_secs {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        for key in keys_to_remove {
            self.conn_track.remove(&key);
        }
    }

    /// Force cache cleanup (for manual management)
    pub async fn cleanup_cache_now(&self) {
        Self::cleanup_cache(&self.rule_cache, self.cache_max_size).await;
    }

    /// Get cache hit rate
    pub fn get_cache_hit_rate(&self) -> f64 {
        let cache_hits = self
            .stats
            .get(&AclStatKey::CacheHits)
            .map(|v| *v.value())
            .unwrap_or(0);
        let total_requests = cache_hits
            + self
                .stats
                .get(&AclStatKey::RuleMatches)
                .map(|v| *v.value())
                .unwrap_or(0);

        if total_requests == 0 {
            0.0
        } else {
            cache_hits as f64 / total_requests as f64
        }
    }
}

// Statistics key enum for better performance
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum AclStatKey {
    // Cache statistics
    CacheHits,
    CacheSize,
    CacheMaxSize,
    RuleMatches,
    DefaultDrops,

    // Global packet statistics
    PacketsTotal,
    PacketsAllowed,
    PacketsDropped,
    PacketsNoop,

    // Per-chain statistics
    InboundPacketsTotal,
    InboundPacketsAllowed,
    InboundPacketsDropped,
    InboundPacketsNoop,

    OutboundPacketsTotal,
    OutboundPacketsAllowed,
    OutboundPacketsDropped,
    OutboundPacketsNoop,

    ForwardPacketsTotal,
    ForwardPacketsAllowed,
    ForwardPacketsDropped,
    ForwardPacketsNoop,

    UnknownPacketsTotal,
    UnknownPacketsAllowed,
    UnknownPacketsDropped,
    UnknownPacketsNoop,
}

impl AclStatKey {
    pub fn as_str(&self) -> String {
        format!("{:?}", self)
    }

    pub fn from_chain_and_action(chain_type: ChainType, stat_type: AclStatType) -> Self {
        match (chain_type, stat_type) {
            (ChainType::Inbound, AclStatType::Total) => AclStatKey::InboundPacketsTotal,
            (ChainType::Inbound, AclStatType::Allowed) => AclStatKey::InboundPacketsAllowed,
            (ChainType::Inbound, AclStatType::Dropped) => AclStatKey::InboundPacketsDropped,
            (ChainType::Inbound, AclStatType::Noop) => AclStatKey::InboundPacketsNoop,

            (ChainType::Outbound, AclStatType::Total) => AclStatKey::OutboundPacketsTotal,
            (ChainType::Outbound, AclStatType::Allowed) => AclStatKey::OutboundPacketsAllowed,
            (ChainType::Outbound, AclStatType::Dropped) => AclStatKey::OutboundPacketsDropped,
            (ChainType::Outbound, AclStatType::Noop) => AclStatKey::OutboundPacketsNoop,

            (ChainType::Forward, AclStatType::Total) => AclStatKey::ForwardPacketsTotal,
            (ChainType::Forward, AclStatType::Allowed) => AclStatKey::ForwardPacketsAllowed,
            (ChainType::Forward, AclStatType::Dropped) => AclStatKey::ForwardPacketsDropped,
            (ChainType::Forward, AclStatType::Noop) => AclStatKey::ForwardPacketsNoop,

            (_, AclStatType::Total) => AclStatKey::UnknownPacketsTotal,
            (_, AclStatType::Allowed) => AclStatKey::UnknownPacketsAllowed,
            (_, AclStatType::Dropped) => AclStatKey::UnknownPacketsDropped,
            (_, AclStatType::Noop) => AclStatKey::UnknownPacketsNoop,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AclStatType {
    Total,
    Allowed,
    Dropped,
    Noop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{Hash, Hasher};
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_acl_config() -> Acl {
        let mut acl_config = Acl::default();
        acl_config.version = AclVersion::V1 as i32;

        let mut acl_v1 = AclV1::default();

        // Create inbound chain
        let mut chain = Chain::default();
        chain.name = "test_inbound".to_string();
        chain.chain_type = ChainType::Inbound as i32;
        chain.enabled = true;

        // Allow all rule
        let mut rule = Rule::default();
        rule.name = "allow_all".to_string();
        rule.priority = 100;
        rule.enabled = true;
        rule.action = Action::Allow as i32;
        rule.protocol = Protocol::Any as i32;

        chain.rules.push(rule);
        acl_v1.chains.push(chain);
        acl_config.acl_v1 = Some(acl_v1);

        acl_config
    }

    fn create_test_packet_info() -> PacketInfo {
        PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: 6, // TCP
            packet_size: 1024,
        }
    }

    #[tokio::test]
    async fn test_acl_cache_key_creation() {
        let packet_info = create_test_packet_info();
        let cache_key = AclCacheKey::from_packet_info(&packet_info, ChainType::Inbound);

        assert_eq!(cache_key.chain_type, ChainType::Inbound);
        assert_eq!(cache_key.protocol, 6);
        assert_eq!(
            cache_key.src_ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(cache_key.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(cache_key.src_port, 12345);
        assert_eq!(cache_key.dst_port, 80);
    }

    #[tokio::test]
    async fn test_acl_cache_key_equality() {
        let packet_info1 = create_test_packet_info();
        let packet_info2 = create_test_packet_info();

        let key1 = AclCacheKey::from_packet_info(&packet_info1, ChainType::Inbound);
        let key2 = AclCacheKey::from_packet_info(&packet_info2, ChainType::Inbound);

        assert_eq!(key1, key2);

        // Test hash consistency
        use std::collections::hash_map::DefaultHasher;
        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        key1.hash(&mut hasher1);
        key2.hash(&mut hasher2);
        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[tokio::test]
    async fn test_acl_processor_basic_functionality() {
        let acl_config = create_test_acl_config();
        let processor = AclProcessor::new_with_async_init(acl_config).await;
        let packet_info = create_test_packet_info();

        let result = processor
            .process_packet(&packet_info, ChainType::Inbound)
            .await;

        assert_eq!(result.action, Action::Allow);
        assert!(result.matched_rule.is_some());
    }

    #[tokio::test]
    async fn test_acl_cache_hit() {
        let acl_config = create_test_acl_config();
        let processor = AclProcessor::new_with_async_init(acl_config).await;
        let packet_info = create_test_packet_info();

        // First request - should be a cache miss
        let result1 = processor
            .process_packet(&packet_info, ChainType::Inbound)
            .await;

        // Second request - should be a cache hit
        let result2 = processor
            .process_packet(&packet_info, ChainType::Inbound)
            .await;

        assert_eq!(result1.action, result2.action);
        assert_eq!(result1.matched_rule, result2.matched_rule);

        // Check cache statistics
        let stats = processor.get_stats();
        assert_eq!(stats.get(&AclStatKey::CacheHits.as_str()).unwrap_or(&0), &1);
        assert!(processor.get_cache_hit_rate() > 0.0);
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let acl_config = create_test_acl_config();
        let mut processor = AclProcessor::new_with_async_init(acl_config).await;
        processor.cache_max_size = 2; // Small cache for testing

        let packet_info1 = PacketInfo {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "192.168.1.2".parse().unwrap(),
            src_port: Some(80),
            dst_port: Some(443),
            protocol: 6,
            packet_size: 1024,
        };
        let packet_info2 = PacketInfo {
            src_ip: "192.168.1.3".parse().unwrap(),
            dst_ip: "192.168.1.4".parse().unwrap(),
            src_port: Some(80),
            dst_port: Some(443),
            protocol: 6,
            packet_size: 1024,
        };
        let packet_info3 = PacketInfo {
            src_ip: "192.168.1.5".parse().unwrap(),
            dst_ip: "192.168.1.6".parse().unwrap(),
            src_port: Some(80),
            dst_port: Some(443),
            protocol: 6,
            packet_size: 1024,
        };

        // Process packets to fill cache beyond max size
        processor
            .process_packet(&packet_info1, ChainType::Inbound)
            .await;
        processor
            .process_packet(&packet_info2, ChainType::Inbound)
            .await;
        processor
            .process_packet(&packet_info3, ChainType::Inbound)
            .await;

        // Trigger cache cleanup
        processor.cleanup_cache_now().await;

        // Cache should be reduced
        let stats = processor.get_stats();
        let cache_size = stats.get(&AclStatKey::CacheSize.as_str()).unwrap_or(&0);
        assert!(*cache_size <= processor.cache_max_size as u64);
    }

    #[tokio::test]
    async fn test_different_chain_types() {
        let acl_config = create_test_acl_config();
        let processor = AclProcessor::new_with_async_init(acl_config).await;
        let packet_info = create_test_packet_info();

        // Test inbound - should match our rule
        let inbound_result = processor
            .process_packet(&packet_info, ChainType::Inbound)
            .await;
        assert_eq!(inbound_result.action, Action::Allow);

        // Test outbound - should get default drop (no outbound rules)
        let outbound_result = processor
            .process_packet(&packet_info, ChainType::Outbound)
            .await;
        assert_eq!(outbound_result.action, Action::Drop);
    }

    #[tokio::test]
    async fn test_cache_entry_with_timestamp() {
        let entry = AclCacheEntry {
            action: Action::Allow,
            matched_rule: "test_rule".to_string(),
            last_access: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        assert_eq!(entry.action, Action::Allow);
        assert_eq!(entry.matched_rule, "test_rule");
        assert!(entry.last_access > 0);
    }

    #[tokio::test]
    async fn test_packet_info_hash_consistency() {
        let packet_info1 = PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(8080),
            dst_port: Some(80),
            protocol: 6,
            packet_size: 1500,
        };

        let packet_info2 = PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(8080),
            dst_port: Some(80),
            protocol: 6,
            packet_size: 1500,
        };

        // Same content should produce same hash
        assert_eq!(packet_info1, packet_info2);

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();

        packet_info1.hash(&mut hasher1);
        packet_info2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let acl_config = create_test_acl_config();
        let processor = AclProcessor::new_with_async_init(acl_config).await;

        let packet_info = create_test_packet_info();

        // Process same packet multiple times to test caching and statistics
        for _ in 0..5 {
            processor
                .process_packet(&packet_info, ChainType::Inbound)
                .await;
        }

        let stats = processor.get_stats();

        // Should have 1 rule match and 4 cache hits
        assert_eq!(
            stats.get(&AclStatKey::RuleMatches.as_str()).unwrap_or(&0),
            &1
        );
        assert_eq!(stats.get(&AclStatKey::CacheHits.as_str()).unwrap_or(&0), &4);

        // Cache hit rate should be 0.8 (4/5)
        let hit_rate = processor.get_cache_hit_rate();
        assert!((hit_rate - 0.8).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_lazy_log_context() {
        let acl_config = create_test_acl_config();
        let processor = AclProcessor::new_with_async_init(acl_config).await;
        let packet_info = create_test_packet_info();

        let result = processor
            .process_packet(&packet_info, ChainType::Inbound)
            .await;

        // Verify log context is created but message is not yet constructed
        assert!(result.log_context.is_some());

        // Test lazy message construction
        if let Some(context) = result.log_context {
            let message = context.to_message();
            assert!(message.contains("Rule match"));
            assert!(message.contains(&packet_info.src_ip.to_string()));
            assert!(message.contains(&packet_info.dst_ip.to_string()));
        }
    }

    #[tokio::test]
    async fn test_different_log_contexts() {
        let packet_info = create_test_packet_info();

        // Test StatefulMatch context
        let stateful_context = AclLogContext::StatefulMatch {
            src_ip: packet_info.src_ip,
            dst_ip: packet_info.dst_ip,
        };
        let message = stateful_context.to_message();
        assert!(message.contains("Stateful match"));

        // Test RuleMatch context
        let rule_context = AclLogContext::RuleMatch {
            src_ip: packet_info.src_ip,
            dst_ip: packet_info.dst_ip,
            action: Action::Allow,
        };
        let message = rule_context.to_message();
        assert!(message.contains("Rule match"));
        assert!(message.contains("Allow"));

        // Test DefaultDrop context
        let drop_context = AclLogContext::DefaultDrop;
        let message = drop_context.to_message();
        assert_eq!(message, "No matching rule, default drop");

        // Test UnsupportedChainType context
        let unsupported_context = AclLogContext::UnsupportedChainType;
        let message = unsupported_context.to_message();
        assert_eq!(message, "Unsupported chain type");
    }

    #[tokio::test]
    async fn test_enum_based_statistics() {
        let acl_config = create_test_acl_config();
        let processor = AclProcessor::new_with_async_init(acl_config).await;

        // Test enum-based statistics
        processor.increment_stat(AclStatKey::PacketsTotal);
        processor.increment_stat(AclStatKey::PacketsAllowed);
        processor.increment_stat(AclStatKey::InboundPacketsTotal);
        processor.increment_stat(AclStatKey::OutboundPacketsDropped);

        let stats = processor.get_stats();

        // Verify enum keys are properly converted to strings
        assert_eq!(
            stats.get(&AclStatKey::PacketsTotal.as_str()).unwrap_or(&0),
            &1
        );
        assert_eq!(
            stats
                .get(&AclStatKey::PacketsAllowed.as_str())
                .unwrap_or(&0),
            &1
        );
        assert_eq!(
            stats
                .get(&AclStatKey::InboundPacketsTotal.as_str())
                .unwrap_or(&0),
            &1
        );
        assert_eq!(
            stats
                .get(&AclStatKey::OutboundPacketsDropped.as_str())
                .unwrap_or(&0),
            &1
        );

        // Test helper function for chain-specific stats
        let inbound_total_key =
            AclStatKey::from_chain_and_action(ChainType::Inbound, AclStatType::Total);
        assert_eq!(inbound_total_key, AclStatKey::InboundPacketsTotal);

        let outbound_dropped_key =
            AclStatKey::from_chain_and_action(ChainType::Outbound, AclStatType::Dropped);
        assert_eq!(outbound_dropped_key, AclStatKey::OutboundPacketsDropped);

        let forward_allowed_key =
            AclStatKey::from_chain_and_action(ChainType::Forward, AclStatType::Allowed);
        assert_eq!(forward_allowed_key, AclStatKey::ForwardPacketsAllowed);

        // Test unknown chain type
        let unknown_key =
            AclStatKey::from_chain_and_action(ChainType::UnspecifiedChain, AclStatType::Noop);
        assert_eq!(unknown_key, AclStatKey::UnknownPacketsNoop);
    }
}
