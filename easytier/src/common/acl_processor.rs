use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr as _,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::common::{config::ConfigLoader, global_ctx::ArcGlobalCtx, token_bucket::TokenBucket};
use crate::proto::acl::*;
use anyhow::Context as _;
use dashmap::DashMap;
use tokio::task::JoinSet;

// Performance-optimized key for rate limiting to avoid string allocations
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RateLimitKey {
    pub chain_type: ChainType,
    pub rule_priority: u32,
}

impl RateLimitKey {
    pub fn new(chain_type: ChainType, rule_priority: u32) -> Self {
        Self {
            chain_type,
            rule_priority,
        }
    }
}

// Performance-optimized rule identifier to avoid string allocations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleId {
    Priority(u32),
    Stateful(u32),
    Default,
}

impl RuleId {
    /// Convert to string only when actually needed (lazy evaluation)
    pub fn to_string_cached(&self) -> String {
        match self {
            RuleId::Priority(p) => p.to_string(),
            RuleId::Stateful(p) => format!("stateful-{}", p),
            RuleId::Default => "default".to_string(),
        }
    }

    /// Get string representation for logging (optimized for hot path)
    pub fn as_str(&self) -> String {
        self.to_string_cached()
    }
}

// Fast lookup structures for performance optimization
#[derive(Debug, Clone)]
pub struct FastLookupRule {
    pub priority: u32,
    pub protocol: Protocol,
    pub src_ip_ranges: Vec<cidr::IpCidr>,
    pub dst_ip_ranges: Vec<cidr::IpCidr>,
    pub src_port_ranges: Vec<(u16, u16)>,
    pub dst_port_ranges: Vec<(u16, u16)>,
    pub action: Action,
    pub enabled: bool,
    pub stateful: bool,
    pub rate_limit: u32,
    pub burst_limit: u32,
    pub rule_stats: Arc<RuleStats>,
}

// Cache key combining packet info and chain type
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AclCacheKey {
    pub chain_type: ChainType,
    pub protocol: Protocol,
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
    pub matched_rule: RuleId,
    pub last_access: u64,
    // New fields to track rule characteristics for proper cache behavior
    pub conn_track_key: Option<String>,
    pub rate_limit_keys: Vec<RateLimitKey>,
    pub chain_type: ChainType,
    pub acl_result: Option<AclResult>,
    pub rule_stats_vec: Vec<Arc<RuleStats>>,
}

// Packet info extracted for ACL processing
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub packet_size: usize,
}

// ACL processing result
#[derive(Debug, Clone)]
pub struct AclResult {
    pub action: Action,
    pub matched_rule: Option<RuleId>,
    pub should_log: bool,
    pub log_context: Option<AclLogContext>,
}

impl AclResult {
    /// Get matched rule as string (lazy evaluation)
    pub fn matched_rule_string(&self) -> Option<String> {
        self.matched_rule.as_ref().map(|r| r.to_string_cached())
    }

    /// Get matched rule as string reference for logging (compatibility method)
    pub fn matched_rule_str(&self) -> Option<String> {
        self.matched_rule.as_ref().map(|r| r.as_str())
    }
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
    DefaultAllow,
    UnsupportedChainType,
    RateLimitDrop,
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
            AclLogContext::DefaultAllow => "No matching rule, default allow".to_string(),
            AclLogContext::UnsupportedChainType => "Unsupported chain type".to_string(),
            AclLogContext::RateLimitDrop => "Rate limit drop".to_string(),
        }
    }
}

// High-performance ACL processor - No more internal locks!
pub struct AclProcessor {
    // Immutable rule vectors - no locks needed since they're never modified after creation
    inbound_rules: Vec<FastLookupRule>,
    outbound_rules: Vec<FastLookupRule>,
    forward_rules: Vec<FastLookupRule>,

    default_inbound_action: Action,
    default_outbound_action: Action,
    default_forward_action: Action,

    default_rule_stats: Arc<RuleStats>,

    // Connection tracking table - shared across different processor instances if needed
    conn_track: Arc<DashMap<String, ConnTrackEntry>>,

    // Rate limiting buckets per rule using TokenBucket with optimized keys
    rate_limiters: Arc<DashMap<RateLimitKey, Arc<TokenBucket>>>,

    // Rule lookup cache with LRU cleanup
    rule_cache: Arc<DashMap<AclCacheKey, AclCacheEntry>>,
    cache_max_size: usize,
    cache_cleanup_interval: Duration,

    // Statistics
    stats: Arc<DashMap<AclStatKey, u64>>,

    tasks: JoinSet<()>,
}

impl AclProcessor {
    /// Create a new ACL processor with pre-built immutable rules
    /// This is the main constructor that should be used
    pub fn new(acl_config: Acl) -> Self {
        Self::new_with_shared_state(acl_config, None, None, None)
    }

    /// Create a new ACL processor while preserving connection tracking and rate limiting state
    /// This is useful for hot reloading where you want to preserve established connections
    pub fn new_with_shared_state(
        acl_config: Acl,
        conn_track: Option<Arc<DashMap<String, ConnTrackEntry>>>,
        rate_limiters: Option<Arc<DashMap<RateLimitKey, Arc<TokenBucket>>>>,
        stats: Option<Arc<DashMap<AclStatKey, u64>>>,
    ) -> Self {
        let (inbound_rules, outbound_rules, forward_rules) = Self::build_rules(&acl_config);
        let (default_inbound_action, default_outbound_action, default_forward_action) =
            Self::build_default_actions(&acl_config);
        let tasks = JoinSet::new();

        let mut processor = Self {
            inbound_rules,
            outbound_rules,
            forward_rules,

            default_inbound_action,
            default_outbound_action,
            default_forward_action,

            default_rule_stats: Arc::new(RuleStats {
                rule: None,
                stat: Some(StatItem {
                    packet_count: 0,
                    byte_count: 0,
                }),
            }),
            conn_track: conn_track.unwrap_or_else(|| Arc::new(DashMap::new())),
            rate_limiters: rate_limiters.unwrap_or_else(|| Arc::new(DashMap::new())),
            rule_cache: Arc::new(DashMap::new()), // Always start with fresh cache
            cache_max_size: 10000,                // Limit cache to 10k entries
            cache_cleanup_interval: Duration::from_secs(20), // Cleanup every 5 minutes
            stats: stats.unwrap_or_else(|| Arc::new(DashMap::new())),
            tasks,
        };

        processor.start_cache_cleanup_task();
        processor
    }

    fn build_default_actions(acl_config: &Acl) -> (Action, Action, Action) {
        let default_inbound_action = acl_config
            .acl_v1
            .as_ref()
            .and_then(|v1| {
                v1.chains
                    .iter()
                    .find(|c| c.chain_type == ChainType::Inbound as i32)
            })
            .map(|c| c.default_action())
            .unwrap_or(Action::Allow);

        let default_outbound_action = acl_config
            .acl_v1
            .as_ref()
            .and_then(|v1| {
                v1.chains
                    .iter()
                    .find(|c| c.chain_type == ChainType::Outbound as i32)
            })
            .map(|c| c.default_action())
            .unwrap_or(Action::Allow);

        let default_forward_action = acl_config
            .acl_v1
            .as_ref()
            .and_then(|v1| {
                v1.chains
                    .iter()
                    .find(|c| c.chain_type == ChainType::Forward as i32)
            })
            .map(|c| c.default_action())
            .unwrap_or(Action::Allow);

        (
            default_inbound_action,
            default_outbound_action,
            default_forward_action,
        )
    }

    /// Build all rule vectors from configuration
    fn build_rules(
        acl_config: &Acl,
    ) -> (
        Vec<FastLookupRule>,
        Vec<FastLookupRule>,
        Vec<FastLookupRule>,
    ) {
        let mut inbound_rules = Vec::new();
        let mut outbound_rules = Vec::new();
        let mut forward_rules = Vec::new();

        // Build new rule vectors
        if let Some(ref acl_v1) = acl_config.acl_v1 {
            for chain in &acl_v1.chains {
                if !chain.enabled {
                    continue;
                }

                let mut rules = chain
                    .rules
                    .iter()
                    .filter(|rule| rule.enabled)
                    .map(|rule| Self::convert_to_fast_lookup_rule(rule))
                    .collect::<Vec<_>>();

                // Sort by priority (higher priority first)
                rules.sort_by(|a, b| b.priority.cmp(&a.priority));

                match chain.chain_type() {
                    ChainType::Inbound => inbound_rules.extend(rules),
                    ChainType::Outbound => outbound_rules.extend(rules),
                    ChainType::Forward => forward_rules.extend(rules),
                    _ => {}
                }
            }
        }

        tracing::info!(
            "ACL rules built: {} inbound, {} outbound, {} forward",
            inbound_rules.len(),
            outbound_rules.len(),
            forward_rules.len(),
        );

        (inbound_rules, outbound_rules, forward_rules)
    }

    /// Start periodic cache cleanup task
    fn start_cache_cleanup_task(&mut self) {
        let rule_cache = self.rule_cache.clone();
        let cache_max_size = self.cache_max_size;
        let cleanup_interval = self.cache_cleanup_interval;

        self.tasks.spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                Self::cleanup_cache(&rule_cache, cache_max_size);
            }
        });

        let conn_track = self.conn_track.clone();
        self.tasks.spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                Self::cleanup_expired_connections(conn_track.clone(), 60);
            }
        });
    }

    /// Clean up cache using LRU strategy
    fn cleanup_cache(cache: &DashMap<AclCacheKey, AclCacheEntry>, max_size: usize) {
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

    pub fn process_packet_with_cache_entry(
        &self,
        packet_info: &PacketInfo,
        cache_entry: &AclCacheEntry,
    ) -> AclResult {
        for rate_limit_key in cache_entry.rate_limit_keys.iter() {
            // bucket should already be created, so rate and burst are not important
            if !self.check_rate_limit(rate_limit_key, 1, 1, false) {
                return AclResult {
                    action: Action::Drop,
                    matched_rule: Some(cache_entry.matched_rule.clone()),
                    should_log: false,
                    log_context: Some(AclLogContext::RateLimitDrop),
                };
            }
        }

        if let Some(conn_track_key) = cache_entry.conn_track_key.as_ref() {
            self.check_connection_state(conn_track_key, packet_info);
        }

        self.inc_cache_entry_stats(cache_entry, packet_info);

        return cache_entry.acl_result.clone().unwrap();
    }

    fn inc_cache_entry_stats(&self, cache_entry: &AclCacheEntry, packet_info: &PacketInfo) {
        for rule_stats in cache_entry.rule_stats_vec.iter() {
            // Use unsafe code to mutate the contents behind the Arc
            let stat_ptr = rule_stats.stat.as_ref().unwrap() as *const StatItem as *mut StatItem;
            unsafe {
                (*stat_ptr).packet_count += 1;
                (*stat_ptr).byte_count += packet_info.packet_size as u64;
            }
        }
    }

    pub fn get_rules_stats(&self) -> Vec<RuleStats> {
        let mut stats: Vec<RuleStats> = Vec::new();
        for rule in self.inbound_rules.iter() {
            stats.push((*rule.rule_stats).clone());
        }
        for rule in self.outbound_rules.iter() {
            stats.push((*rule.rule_stats).clone());
        }
        for rule in self.forward_rules.iter() {
            stats.push((*rule.rule_stats).clone());
        }
        stats
    }

    /// Process a packet through ACL rules - Now lock-free!
    pub fn process_packet(&self, packet_info: &PacketInfo, chain_type: ChainType) -> AclResult {
        // Check cache first for performance
        let cache_key = AclCacheKey::from_packet_info(packet_info, chain_type);

        // If cache hit and can skip checks, return cached result
        if let Some(mut cached) = self.rule_cache.get_mut(&cache_key) {
            // Update last access time for LRU
            cached.last_access = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.increment_stat(AclStatKey::CacheHits);
            return self.process_packet_with_cache_entry(packet_info, &cached);
        }

        // Direct access to rules - no locks needed!
        let rules = match chain_type {
            ChainType::Inbound => &self.inbound_rules,
            ChainType::Outbound => &self.outbound_rules,
            ChainType::Forward => &self.forward_rules,
            _ => {
                return AclResult {
                    action: Action::Drop,
                    matched_rule: Some(RuleId::Default),
                    should_log: false,
                    log_context: Some(AclLogContext::UnsupportedChainType),
                }
            }
        };

        let mut cache_entry = AclCacheEntry {
            action: Action::Allow,
            matched_rule: RuleId::Default,
            last_access: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            conn_track_key: None,
            rate_limit_keys: vec![],
            chain_type,
            acl_result: None,
            rule_stats_vec: vec![],
        };

        // Process rules in priority order
        for rule in rules.iter() {
            if !rule.enabled || !self.rule_matches(rule, packet_info) {
                continue;
            }

            // Check rate limiting if configured
            if rule.rate_limit > 0 {
                let rule_key = RateLimitKey::new(chain_type, rule.priority);
                cache_entry.rate_limit_keys.push(rule_key.clone());
                cache_entry.rule_stats_vec.push(rule.rule_stats.clone());
                if !self.check_rate_limit(&rule_key, rule.rate_limit, rule.burst_limit, true) {
                    // rate limited, drop packet
                    return AclResult {
                        action: Action::Drop,
                        matched_rule: Some(RuleId::Priority(rule.priority)),
                        should_log: false,
                        log_context: Some(AclLogContext::RateLimitDrop),
                    };
                }
            }

            // Handle stateful connections if configured
            if rule.stateful && rule.action == Action::Allow {
                let conn_track_key = self.conn_track_key(packet_info);
                self.check_connection_state(&conn_track_key, packet_info);
                cache_entry.rule_stats_vec.push(rule.rule_stats.clone());
                cache_entry.matched_rule = RuleId::Stateful(rule.priority);
                cache_entry.conn_track_key = Some(conn_track_key);
                cache_entry.acl_result = Some(AclResult {
                    action: Action::Allow,
                    matched_rule: Some(RuleId::Stateful(rule.priority)),
                    should_log: false,
                    log_context: Some(AclLogContext::StatefulMatch {
                        src_ip: packet_info.src_ip,
                        dst_ip: packet_info.dst_ip,
                    }),
                });
            } else {
                // Rule matched, return action
                cache_entry.rule_stats_vec.push(rule.rule_stats.clone());
                cache_entry.matched_rule = RuleId::Priority(rule.priority);
                cache_entry.acl_result = Some(AclResult {
                    action: rule.action.clone(),
                    matched_rule: Some(RuleId::Priority(rule.priority)),
                    should_log: false,
                    log_context: Some(AclLogContext::RuleMatch {
                        src_ip: packet_info.src_ip,
                        dst_ip: packet_info.dst_ip,
                        action: rule.action,
                    }),
                });
            }

            // Cache the result with rule info
            self.increment_stat(AclStatKey::RuleMatches);
            self.inc_cache_entry_stats(&cache_entry, packet_info);
            self.cache_result(&cache_key, cache_entry.clone());
            return cache_entry.acl_result.clone().unwrap();
        }

        let default_action = match chain_type {
            ChainType::Inbound => self.default_inbound_action,
            ChainType::Outbound => self.default_outbound_action,
            ChainType::Forward => self.default_forward_action,
            _ => Action::Allow,
        };

        // No rule matched, return default drop
        if default_action == Action::Drop {
            self.increment_stat(AclStatKey::DefaultDrops);
        } else {
            self.increment_stat(AclStatKey::DefaultAllows);
        }

        let log_context = if default_action == Action::Drop {
            AclLogContext::DefaultDrop
        } else {
            AclLogContext::DefaultAllow
        };

        cache_entry
            .rule_stats_vec
            .push(self.default_rule_stats.clone());
        cache_entry.matched_rule = RuleId::Default;
        cache_entry.acl_result = Some(AclResult {
            action: default_action,
            matched_rule: Some(RuleId::Default),
            should_log: false,
            log_context: Some(log_context),
        });

        // Cache the default result (no rule info)
        self.inc_cache_entry_stats(&cache_entry, packet_info);
        self.cache_result(&cache_key, cache_entry.clone());
        cache_entry.acl_result.clone().unwrap()
    }

    /// Get shared state for preserving across hot reloads
    pub fn get_shared_state(
        &self,
    ) -> (
        Arc<DashMap<String, ConnTrackEntry>>,
        Arc<DashMap<RateLimitKey, Arc<TokenBucket>>>,
        Arc<DashMap<AclStatKey, u64>>,
    ) {
        (
            self.conn_track.clone(),
            self.rate_limiters.clone(),
            self.stats.clone(),
        )
    }

    /// Cache an ACL result
    fn cache_result(&self, cache_key: &AclCacheKey, cache_entry: AclCacheEntry) {
        self.rule_cache.insert(cache_key.clone(), cache_entry);

        // Trigger cleanup if cache is getting too large
        if self.rule_cache.len() > self.cache_max_size * 2 {
            let cache = self.rule_cache.clone();
            let max_size = self.cache_max_size;
            Self::cleanup_cache(&cache, max_size);
        }
    }

    /// Check if a rule matches the packet
    fn rule_matches(&self, rule: &FastLookupRule, packet_info: &PacketInfo) -> bool {
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
        if let Some(src_port) = packet_info.src_port {
            if !rule.src_port_ranges.is_empty() {
                let matches = rule
                    .src_port_ranges
                    .iter()
                    .any(|(start, end)| src_port >= *start && src_port <= *end);
                if !matches {
                    return false;
                }
            }
        }

        // Destination port check
        if let Some(dst_port) = packet_info.dst_port {
            if !rule.dst_port_ranges.is_empty() {
                let matches = rule
                    .dst_port_ranges
                    .iter()
                    .any(|(start, end)| dst_port >= *start && dst_port <= *end);
                if !matches {
                    return false;
                }
            }
        }

        true
    }

    fn conn_track_key(&self, packet_info: &PacketInfo) -> String {
        format!(
            "{}:{}->{}:{}",
            packet_info.src_ip,
            packet_info.src_port.unwrap_or(0),
            packet_info.dst_ip,
            packet_info.dst_port.unwrap_or(0)
        )
    }

    /// Check connection state for stateful rules
    fn check_connection_state(&self, conn_track_key: &String, packet_info: &PacketInfo) {
        self.conn_track
            .entry(conn_track_key.clone())
            .and_modify(|x| {
                x.last_seen = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                x.packet_count += 1;
                x.byte_count += packet_info.packet_size as u64;
                x.state = ConnState::Established as i32;
            })
            .or_insert_with(|| ConnTrackEntry {
                src_addr: Some(
                    SocketAddr::new(packet_info.src_ip, packet_info.src_port.unwrap_or(0)).into(),
                ),
                dst_addr: Some(
                    SocketAddr::new(packet_info.dst_ip, packet_info.dst_port.unwrap_or(0)).into(),
                ),
                protocol: packet_info.protocol as i32,
                state: ConnState::New as i32,
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
            });
    }

    /// Check rate limiting for a rule
    fn check_rate_limit(
        &self,
        rule_key: &RateLimitKey,
        rate: u32,
        burst: u32,
        allow_create: bool,
    ) -> bool {
        if rate == 0 {
            return true; // No rate limiting
        }

        let bucket = self
            .rate_limiters
            .entry(rule_key.clone())
            .or_insert_with(|| {
                if !allow_create {
                    panic!("Rate limit bucket not found");
                }
                TokenBucket::new(burst as u64, rate as u64, Duration::from_millis(10))
            })
            .clone();

        // Try to consume 1 token (1 packet)
        bucket.try_consume(1)
    }

    /// Convert proto Rule to FastLookupRule
    fn convert_to_fast_lookup_rule(rule: &Rule) -> FastLookupRule {
        let src_ip_ranges = rule
            .source_ips
            .iter()
            .filter_map(|ip_inet| Self::convert_ip_inet_to_cidr(ip_inet))
            .collect();

        let dst_ip_ranges = rule
            .destination_ips
            .iter()
            .filter_map(|ip_inet| Self::convert_ip_inet_to_cidr(ip_inet))
            .collect();

        let src_port_ranges = rule
            .source_ports
            .iter()
            .filter_map(|port_range| {
                if let Some((start, end)) = parse_port_range(port_range) {
                    Some((start, end))
                } else {
                    None
                }
            })
            .collect();

        let dst_port_ranges = rule
            .ports
            .iter()
            .filter_map(|port_range| {
                if let Some((start, end)) = parse_port_range(port_range) {
                    Some((start, end))
                } else {
                    None
                }
            })
            .collect();

        FastLookupRule {
            priority: rule.priority,
            protocol: rule.protocol(),
            src_ip_ranges,
            dst_ip_ranges,
            src_port_ranges,
            dst_port_ranges,
            action: rule.action(),
            enabled: rule.enabled,
            stateful: rule.stateful,
            rate_limit: rule.rate_limit,
            burst_limit: rule.burst_limit,
            rule_stats: Arc::new(RuleStats {
                rule: Some(rule.clone()),
                stat: Some(StatItem {
                    packet_count: 0,
                    byte_count: 0,
                }),
            }),
        }
    }

    /// Convert IpInet to CIDR for fast lookup
    fn convert_ip_inet_to_cidr(input: &String) -> Option<cidr::IpCidr> {
        cidr::IpCidr::from_str(input.as_str()).ok()
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
    pub fn cleanup_expired_connections(
        conn_track: Arc<DashMap<String, ConnTrackEntry>>,
        timeout_secs: u64,
    ) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let keys_to_remove: Vec<String> = conn_track
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
            conn_track.remove(&key);
        }
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

// 新增辅助函数
fn parse_port_start(
    port_strs: &::prost::alloc::vec::Vec<::prost::alloc::string::String>,
) -> Option<u16> {
    port_strs
        .iter()
        .filter_map(|s| parse_port_range(s).map(|(start, _)| start))
        .min()
}
fn parse_port_end(
    port_strs: &::prost::alloc::vec::Vec<::prost::alloc::string::String>,
) -> Option<u16> {
    port_strs
        .iter()
        .filter_map(|s| parse_port_range(s).map(|(_, end)| end))
        .max()
}
fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    if let Some((start, end)) = s.split_once('-') {
        let start = start.trim().parse().ok()?;
        let end = end.trim().parse().ok()?;
        Some((start, end))
    } else {
        let port = s.trim().parse().ok()?;
        Some((port, port))
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
    DefaultAllows,
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

pub struct AclRuleBuilder {
    pub acl: Option<Acl>,
    pub tcp_whitelist: Vec<String>,
    pub udp_whitelist: Vec<String>,
    pub whitelist_priority: Option<u32>,
}

impl AclRuleBuilder {
    fn parse_port_list(port_list: &[String]) -> anyhow::Result<Vec<String>> {
        let mut ports = Vec::new();

        for port_spec in port_list {
            if port_spec.contains('-') {
                // Handle port range like "8000-9000"
                let parts: Vec<&str> = port_spec.split('-').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!("Invalid port range format: {}", port_spec));
                }

                let start: u16 = parts[0]
                    .parse()
                    .with_context(|| format!("Invalid start port in range: {}", port_spec))?;
                let end: u16 = parts[1]
                    .parse()
                    .with_context(|| format!("Invalid end port in range: {}", port_spec))?;

                if start > end {
                    return Err(anyhow::anyhow!(
                        "Start port must be <= end port in range: {}",
                        port_spec
                    ));
                }

                // acl can handle port range
                ports.push(port_spec.clone());
            } else {
                // Handle single port
                let port: u16 = port_spec
                    .parse()
                    .with_context(|| format!("Invalid port number: {}", port_spec))?;
                ports.push(port.to_string());
            }
        }

        Ok(ports)
    }

    fn generate_acl_from_whitelists(&mut self) -> anyhow::Result<()> {
        if self.tcp_whitelist.is_empty() && self.udp_whitelist.is_empty() {
            return Ok(());
        }

        // Create inbound chain for whitelist rules
        let mut inbound_chain = Chain {
            name: "inbound_whitelist".to_string(),
            chain_type: ChainType::Inbound as i32,
            description: "Auto-generated inbound whitelist from CLI".to_string(),
            enabled: true,
            rules: vec![],
            default_action: Action::Drop as i32, // Default deny
        };

        let mut rule_priority = self.whitelist_priority.unwrap_or(1000u32);

        // Add TCP whitelist rules
        if !self.tcp_whitelist.is_empty() {
            let tcp_ports = Self::parse_port_list(&self.tcp_whitelist)?;
            let tcp_rule = Rule {
                name: "tcp_whitelist".to_string(),
                description: "Auto-generated TCP whitelist rule".to_string(),
                priority: rule_priority,
                enabled: true,
                protocol: Protocol::Tcp as i32,
                ports: tcp_ports,
                source_ips: vec![],
                destination_ips: vec![],
                source_ports: vec![],
                action: Action::Allow as i32,
                rate_limit: 0,
                burst_limit: 0,
                stateful: true,
            };
            inbound_chain.rules.push(tcp_rule);
            rule_priority -= 1;
        }

        // Add UDP whitelist rules
        if !self.udp_whitelist.is_empty() {
            let udp_ports = Self::parse_port_list(&self.udp_whitelist)?;
            let udp_rule = Rule {
                name: "udp_whitelist".to_string(),
                description: "Auto-generated UDP whitelist rule".to_string(),
                priority: rule_priority,
                enabled: true,
                protocol: Protocol::Udp as i32,
                ports: udp_ports,
                source_ips: vec![],
                destination_ips: vec![],
                source_ports: vec![],
                action: Action::Allow as i32,
                rate_limit: 0,
                burst_limit: 0,
                stateful: false,
            };
            inbound_chain.rules.push(udp_rule);
        }

        if self.acl.is_none() {
            self.acl = Some(Acl::default());
        }

        let acl = self.acl.as_mut().unwrap();

        if let Some(ref mut acl_v1) = acl.acl_v1 {
            acl_v1.chains.push(inbound_chain);
        } else {
            acl.acl_v1 = Some(AclV1 {
                chains: vec![inbound_chain],
            });
        }

        Ok(())
    }

    fn do_build(mut self) -> anyhow::Result<Option<Acl>> {
        self.generate_acl_from_whitelists()?;
        Ok(self.acl.clone())
    }

    pub fn build(global_ctx: &ArcGlobalCtx) -> anyhow::Result<Option<Acl>> {
        let builder = AclRuleBuilder {
            acl: global_ctx.config.get_acl(),
            tcp_whitelist: global_ctx.config.get_tcp_whitelist(),
            udp_whitelist: global_ctx.config.get_udp_whitelist(),
            whitelist_priority: None,
        };
        builder.do_build()
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
            protocol: Protocol::Tcp,
            packet_size: 1024,
        }
    }

    #[test]
    fn test_acl_cache_key_creation() {
        let packet_info = create_test_packet_info();
        let cache_key = AclCacheKey::from_packet_info(&packet_info, ChainType::Inbound);

        assert_eq!(cache_key.chain_type, ChainType::Inbound);
        assert_eq!(cache_key.protocol, Protocol::Tcp);
        assert_eq!(
            cache_key.src_ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(cache_key.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(cache_key.src_port, 12345);
        assert_eq!(cache_key.dst_port, 80);
    }

    #[test]
    fn test_acl_cache_key_equality() {
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
        let processor = AclProcessor::new(acl_config);
        let packet_info = create_test_packet_info();

        let result = processor.process_packet(&packet_info, ChainType::Inbound);

        assert_eq!(result.action, Action::Allow);
        assert!(result.matched_rule.is_some());
    }

    #[tokio::test]
    async fn test_acl_cache_hit() {
        let acl_config = create_test_acl_config();
        let processor = AclProcessor::new(acl_config);
        let packet_info = create_test_packet_info();

        // First request - should be a cache miss
        let result1 = processor.process_packet(&packet_info, ChainType::Inbound);

        // Second request - should be a cache hit
        let result2 = processor.process_packet(&packet_info, ChainType::Inbound);

        assert_eq!(result1.action, result2.action);
        assert_eq!(result1.matched_rule, result2.matched_rule);

        // Check cache statistics
        let stats = processor.get_stats();
        assert_eq!(stats.get(&AclStatKey::CacheHits.as_str()).unwrap_or(&0), &1);
        assert!(processor.get_cache_hit_rate() > 0.0);
    }

    #[tokio::test]
    async fn test_lock_free_hot_reload_demo() {
        println!("\n=== ACL 优化演示：无锁热加载 ===");

        // 创建初始配置
        let initial_config = create_test_acl_config();
        let processor = AclProcessor::new(initial_config);
        let packet_info = create_test_packet_info();

        // 处理一些数据包
        println!("1. 处理初始数据包...");
        let result1 = processor.process_packet(&packet_info, ChainType::Inbound);
        assert_eq!(result1.action, Action::Allow);
        println!("   ✓ 数据包被允许通过");

        // 获取共享状态
        let (conn_track, rate_limiters, stats) = processor.get_shared_state();
        println!("2. 保存连接跟踪和统计状态...");
        println!("   ✓ 连接数: {}", conn_track.len());
        println!("   ✓ 限流器数量: {}", rate_limiters.len());
        println!("   ✓ 统计计数器数量: {}", stats.len());

        // 创建新配置（模拟热加载）
        let mut new_config = create_test_acl_config();
        if let Some(ref mut acl_v1) = new_config.acl_v1 {
            let mut drop_rule = Rule::default();
            drop_rule.name = "drop_all".to_string();
            drop_rule.priority = 200;
            drop_rule.enabled = true;
            drop_rule.action = Action::Drop as i32;
            drop_rule.protocol = Protocol::Any as i32;
            acl_v1.chains[0].rules.push(drop_rule);
        }

        // 创建新的处理器实例（热加载）
        println!("3. 执行热加载（创建新的处理器实例）...");
        let new_processor = AclProcessor::new_with_shared_state(
            new_config,
            Some(conn_track.clone()),
            Some(rate_limiters.clone()),
            Some(stats.clone()),
        );

        // 验证新处理器的行为
        let result2 = new_processor.process_packet(&packet_info, ChainType::Inbound);
        assert_eq!(result2.action, Action::Drop); // 新规则应该拒绝
        println!("   ✓ 新规则生效：数据包被拒绝");

        // 验证状态被保留
        let (new_conn_track, new_rate_limiters, new_stats) = new_processor.get_shared_state();
        assert!(Arc::ptr_eq(&conn_track, &new_conn_track));
        assert!(Arc::ptr_eq(&rate_limiters, &new_rate_limiters));
        assert!(Arc::ptr_eq(&stats, &new_stats));
        println!("   ✓ 连接状态和统计信息被完整保留");

        println!("\n=== 性能优化效果 ===");
        println!("✓ 无锁访问：处理器内部不再有任何锁");
        println!("✓ 零拷贝：规则访问直接引用，无需克隆Arc");
        println!("✓ 热加载：创建新实例替换，保留所有状态");
        println!("✓ 内存效率：消除了多层Arc包装的开销");
    }

    #[tokio::test]
    async fn test_performance_and_security_balance() {
        // Create ACL config with different rule types
        let mut acl_config = Acl::default();

        let mut acl_v1 = AclV1::default();
        let mut chain = Chain::default();
        chain.name = "performance_test".to_string();
        chain.chain_type = ChainType::Inbound as i32;
        chain.enabled = true;

        // 1. High-priority simple rule for UDP (can be cached efficiently)
        let mut simple_rule = Rule::default();
        simple_rule.name = "simple_udp".to_string();
        simple_rule.priority = 300;
        simple_rule.enabled = true;
        simple_rule.action = Action::Allow as i32;
        simple_rule.protocol = Protocol::Udp as i32;
        // No stateful or rate limit - can benefit from full cache optimization
        chain.rules.push(simple_rule);

        // 2. Medium-priority stateful + rate-limited rule for TCP (security critical)
        let mut security_rule = Rule::default();
        security_rule.name = "security_tcp".to_string();
        security_rule.priority = 200;
        security_rule.enabled = true;
        security_rule.action = Action::Allow as i32;
        security_rule.protocol = Protocol::Tcp as i32;
        security_rule.stateful = true;
        security_rule.rate_limit = 100; // 100 packets/sec
        security_rule.burst_limit = 200;
        chain.rules.push(security_rule);

        // 3. Low-priority default allow rule for Any
        let mut default_rule = Rule::default();
        default_rule.name = "default_allow".to_string();
        default_rule.priority = 100;
        default_rule.enabled = true;
        default_rule.action = Action::Allow as i32;
        default_rule.protocol = Protocol::Any as i32;
        chain.rules.push(default_rule);

        acl_v1.chains.push(chain);
        acl_config.acl_v1 = Some(acl_v1);

        let processor = AclProcessor::new(acl_config);

        // Test simple UDP packet (should hit high-priority simple rule and be cached)
        let udp_packet = PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(12345),
            dst_port: Some(53),      // DNS
            protocol: Protocol::Udp, // UDP
            packet_size: 512,
        };

        // Test TCP packet (should hit stateful+rate-limited rule)
        let tcp_packet = PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(12345),
            dst_port: Some(80),      // HTTP
            protocol: Protocol::Tcp, // TCP
            packet_size: 1024,
        };

        // Process UDP packets multiple times
        println!("\n=== Performance Test Results ===");
        for i in 1..=5 {
            let result = processor.process_packet(&udp_packet, ChainType::Inbound);
            assert_eq!(result.action, Action::Allow);
            // UDP packets should match the highest priority rule that applies
            // Since all rules allow "Any" protocol, UDP will match the highest priority one
            println!(
                "UDP packet {}: Allowed by rule (priority {:?})",
                i, result.matched_rule
            );
        }

        // Process TCP packets multiple times (stateful + rate limited)
        for i in 1..=3 {
            let result = processor.process_packet(&tcp_packet, ChainType::Inbound);
            println!(
                "TCP packet {}: {:?} by rule (priority {:?})",
                i, result.action, result.matched_rule
            );
        }

        let stats = processor.get_stats();
        println!("\nStatistics:");
        println!(
            "  Cache hits: {}",
            stats.get(&AclStatKey::CacheHits.as_str()).unwrap_or(&0)
        );
        println!(
            "  Rule matches: {}",
            stats.get(&AclStatKey::RuleMatches.as_str()).unwrap_or(&0)
        );
        println!(
            "  Cache hit rate: {:.1}%",
            processor.get_cache_hit_rate() * 100.0
        );

        println!("\n✓ Stateful + rate-limited rules: Always processed for security");
        println!("✓ Simple rules: Cached for performance");
        println!(
            "✓ Cache hit rate: {:.1}%",
            processor.get_cache_hit_rate() * 100.0
        );
    }

    #[test]
    fn test_rate_limit_drop_log_context() {
        // Test that RateLimitDrop log context is properly created
        let context = AclLogContext::RateLimitDrop;
        let message = context.to_message();
        assert_eq!(message, "Rate limit drop");
    }

    #[tokio::test]
    async fn test_rate_limit_drop_behavior() {
        let mut acl_config = create_test_acl_config();

        // Create a very restrictive rate-limited rule
        if let Some(ref mut acl_v1) = acl_config.acl_v1 {
            let mut rule = Rule::default();
            rule.name = "strict_rate_limit".to_string();
            rule.priority = 200;
            rule.enabled = true;
            rule.action = Action::Allow as i32;
            rule.protocol = Protocol::Any as i32;
            rule.rate_limit = 1; // Allow only 1 packet per second
            rule.burst_limit = 1; // Burst of 1 packet

            acl_v1.chains[0].rules.push(rule);
        }

        let processor = AclProcessor::new(acl_config);
        let packet_info = create_test_packet_info();

        // First request should be allowed
        let result1 = processor.process_packet(&packet_info, ChainType::Inbound);
        assert_eq!(result1.action, Action::Allow);
        assert_eq!(result1.matched_rule, Some(RuleId::Priority(200)));

        // Second request should be rate limited and dropped immediately
        let result2 = processor.process_packet(&packet_info, ChainType::Inbound);
        assert_eq!(result2.action, Action::Drop);
        assert_eq!(result2.matched_rule, Some(RuleId::Priority(200)));
        assert!(!result2.should_log);

        // Verify the specific log context
        assert!(matches!(
            result2.log_context,
            Some(AclLogContext::RateLimitDrop)
        ));
    }
}
