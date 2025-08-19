use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::{
    net::IpAddr,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet as _,
};

use crate::proto::acl::{AclStats, Protocol};
use crate::tunnel::packet_def::PacketType;
use crate::{
    common::acl_processor::{AclProcessor, AclResult, AclStatKey, AclStatType, PacketInfo},
    proto::acl::{Acl, Action, ChainType},
    tunnel::packet_def::ZCPacket,
};

// Cache entry for IP to groups mapping
#[derive(Debug, Clone)]
struct GroupCacheEntry {
    groups: Arc<Vec<String>>,
    timestamp: Instant,
}

impl GroupCacheEntry {
    fn new(groups: Vec<String>) -> Self {
        Self {
            groups: Arc::new(groups),
            timestamp: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.timestamp.elapsed() > ttl
    }
}

// Configuration constants for group cache
const GROUP_CACHE_TTL: Duration = Duration::from_millis(500);
const GROUP_CACHE_MAX_SIZE: usize = 1000;

/// ACL filter that can be inserted into the packet processing pipeline
/// Optimized with lock-free hot reloading via atomic processor replacement
pub struct AclFilter {
    // Use ArcSwap for lock-free atomic replacement during hot reload
    acl_processor: ArcSwap<AclProcessor>,
    acl_enabled: Arc<AtomicBool>,
    // Cache for IP to groups mapping to reduce frequent route lookups
    group_cache: DashMap<IpAddr, GroupCacheEntry>,
}

impl Default for AclFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl AclFilter {
    pub fn new() -> Self {
        Self {
            acl_processor: ArcSwap::from(Arc::new(AclProcessor::new(Acl::default()))),
            acl_enabled: Arc::new(AtomicBool::new(false)),
            group_cache: DashMap::new(),
        }
    }

    /// Hot reload ACL rules by creating a new processor instance
    /// Preserves connection tracking and rate limiting state across reloads
    /// Now lock-free and doesn't require &mut self!
    pub fn reload_rules(&self, acl_config: Option<&Acl>) {
        let Some(acl_config) = acl_config else {
            self.acl_enabled.store(false, Ordering::Relaxed);
            return;
        };

        // Get current processor to extract shared state
        let current_processor = self.acl_processor.load();
        let (conn_track, rate_limiters, stats) = current_processor.get_shared_state();

        // Create new processor with preserved state
        let new_processor = AclProcessor::new_with_shared_state(
            acl_config.clone(),
            Some(conn_track),
            Some(rate_limiters),
            Some(stats),
        );

        // Atomic replacement - this is completely lock-free!
        self.acl_processor.store(Arc::new(new_processor));
        self.acl_enabled.store(true, Ordering::Relaxed);

        tracing::info!("ACL rules hot reloaded with preserved state (lock-free)");
    }

    /// Get current processor for processing packets
    pub fn get_processor(&self) -> Arc<AclProcessor> {
        self.acl_processor.load_full()
    }

    /// Get groups for an IP address with caching
    async fn get_groups_with_cache(
        &self,
        ip: &IpAddr,
        route: &(dyn super::route_trait::Route + Send + Sync + 'static),
    ) -> Arc<Vec<String>> {
        // Check cache first
        if let Some(entry) = self.group_cache.get(ip) {
            if !entry.is_expired(GROUP_CACHE_TTL) {
                tracing::trace!("Group cache hit for IP: {}", ip);
                return entry.groups.clone();
            } else {
                // Remove expired entry
                drop(entry);
                self.group_cache.remove(ip);
                tracing::trace!("Group cache expired for IP: {}", ip);
            }
        }

        // Cache miss, query route
        tracing::trace!("Group cache miss for IP: {}", ip);
        let groups = route.get_peer_groups_by_ip(ip).await;
        let entry = GroupCacheEntry::new(groups);
        let result = entry.groups.clone();

        // Store in cache with size limit
        if self.group_cache.len() < GROUP_CACHE_MAX_SIZE {
            self.group_cache.insert(*ip, entry);
        } else {
            // Optionally clean up some expired entries
            self.cleanup_expired_cache_entries();
            if self.group_cache.len() < GROUP_CACHE_MAX_SIZE {
                self.group_cache.insert(*ip, entry);
            }
        }

        result
    }

    /// Clean up expired cache entries
    fn cleanup_expired_cache_entries(&self) {
        let now = Instant::now();
        self.group_cache
            .retain(|_, entry| now.duration_since(entry.timestamp) <= GROUP_CACHE_TTL);
    }

    /// Clear group cache (useful for testing or configuration changes)
    pub fn clear_group_cache(&self) {
        self.group_cache.clear();
    }

    pub fn get_stats(&self) -> AclStats {
        let processor = self.get_processor();
        let global_stats = processor.get_stats();
        let (conn_track, _, _) = processor.get_shared_state();
        let rules_stats = processor.get_rules_stats();

        AclStats {
            global: global_stats.into_iter().collect(),
            conn_track: conn_track.iter().map(|x| *x.value()).collect(),
            rules: rules_stats,
        }
    }

    /// Extract packet information for ACL processing
    fn extract_packet_info(&self, packet: &ZCPacket) -> Option<PacketInfo> {
        let payload = packet.payload();

        let src_ip;
        let dst_ip;
        let src_port;
        let dst_port;
        let protocol;

        let ipv4_packet = Ipv4Packet::new(payload)?;
        if ipv4_packet.get_version() == 4 {
            src_ip = IpAddr::V4(ipv4_packet.get_source());
            dst_ip = IpAddr::V4(ipv4_packet.get_destination());
            protocol = ipv4_packet.get_next_level_protocol();

            (src_port, dst_port) = match protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                    )
                }
                _ => (None, None),
            };
        } else if ipv4_packet.get_version() == 6 {
            let ipv6_packet = Ipv6Packet::new(payload)?;
            src_ip = IpAddr::V6(ipv6_packet.get_source());
            dst_ip = IpAddr::V6(ipv6_packet.get_destination());
            protocol = ipv6_packet.get_next_header();

            (src_port, dst_port) = match protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv6_packet.payload())?;
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                    )
                }
                _ => (None, None),
            };
        } else {
            return None;
        }

        let acl_protocol = match protocol {
            IpNextHeaderProtocols::Tcp => Protocol::Tcp,
            IpNextHeaderProtocols::Udp => Protocol::Udp,
            IpNextHeaderProtocols::Icmp => Protocol::Icmp,
            IpNextHeaderProtocols::Icmpv6 => Protocol::IcmPv6,
            _ => Protocol::Unspecified,
        };

        Some(PacketInfo {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: acl_protocol,
            packet_size: payload.len(),
            src_groups: Arc::new(Vec::<String>::new()),
            dst_groups: Arc::new(Vec::<String>::new()),
        })
    }

    /// Process ACL result and log if needed
    pub fn handle_acl_result(
        &self,
        result: &AclResult,
        packet_info: &PacketInfo,
        chain_type: ChainType,
        processor: &AclProcessor,
    ) {
        if result.should_log {
            if let Some(ref log_context) = result.log_context {
                let log_message = log_context.to_message();
                tracing::info!(
                    src_ip = %packet_info.src_ip,
                    dst_ip = %packet_info.dst_ip,
                    src_port = packet_info.src_port,
                    dst_port = packet_info.dst_port,
                    src_group = packet_info.src_groups.join(","),
                    dst_group = packet_info.dst_groups.join(","),
                    protocol = ?packet_info.protocol,
                    action = ?result.action,
                    rule = result.matched_rule_str().as_deref().unwrap_or("unknown"),
                    chain_type = ?chain_type,
                    "ACL: {}", log_message
                );
            }
        }

        // Update global statistics in the ACL processor
        match result.action {
            Action::Allow => {
                processor.increment_stat(AclStatKey::PacketsAllowed);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Allowed,
                ));
                tracing::trace!("ACL: Packet allowed");
            }
            Action::Drop => {
                processor.increment_stat(AclStatKey::PacketsDropped);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Dropped,
                ));
                tracing::debug!("ACL: Packet dropped");
            }
            Action::Noop => {
                processor.increment_stat(AclStatKey::PacketsNoop);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Noop,
                ));
                tracing::trace!("ACL: No operation");
            }
        }

        // Track total packets processed per chain
        processor.increment_stat(AclStatKey::from_chain_and_action(
            chain_type,
            AclStatType::Total,
        ));
        processor.increment_stat(AclStatKey::PacketsTotal);
    }

    /// Common ACL processing logic
    pub async fn process_packet_with_acl(
        &self,
        packet: &ZCPacket,
        is_in: bool,
        my_ipv4: Option<Ipv4Addr>,
        my_ipv6: Option<Ipv6Addr>,
        route: &(dyn super::route_trait::Route + Send + Sync + 'static),
    ) -> bool {
        if !self.acl_enabled.load(Ordering::Relaxed) {
            return true;
        }

        if packet.peer_manager_header().unwrap().packet_type != PacketType::Data as u8 {
            return true;
        }

        // Extract packet information
        let packet_info = match self.extract_packet_info(packet) {
            Some(mut info) => {
                // Parallel group lookup for src and dst IPs to reduce latency
                let (src_groups, dst_groups) = tokio::join!(
                    self.get_groups_with_cache(&info.src_ip, route),
                    self.get_groups_with_cache(&info.dst_ip, route)
                );

                info.src_groups = src_groups;
                info.dst_groups = dst_groups;
                info
            }
            None => {
                tracing::warn!(
                    "Failed to extract packet info from {:?} packet, header: {:?}",
                    if is_in { "inbound" } else { "outbound" },
                    packet.peer_manager_header()
                );
                // allow all unknown packets
                return true;
            }
        };

        let chain_type = if is_in {
            if packet_info.dst_ip == my_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED)
                || packet_info.dst_ip == my_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED)
            {
                ChainType::Inbound
            } else {
                ChainType::Forward
            }
        } else {
            ChainType::Outbound
        };

        // Get current processor atomically
        let processor = self.get_processor();

        // Process through ACL rules
        let acl_result = processor.process_packet(&packet_info, chain_type);

        self.handle_acl_result(&acl_result, &packet_info, chain_type, &processor);

        // Check if packet should be allowed
        match acl_result.action {
            Action::Allow | Action::Noop => true,
            Action::Drop => {
                tracing::trace!(
                    "ACL: Dropping {:?} packet from {} to {}, chain_type: {:?}",
                    packet_info.protocol,
                    packet_info.src_ip,
                    packet_info.dst_ip,
                    chain_type,
                );

                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::PeerId;
    use crate::peers::route_trait::{Route, RouteInterfaceBox};
    use crate::proto::peer_rpc::RoutePeerInfo;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    // Mock route implementation for testing
    struct MockRouteWithGroups {
        ip_to_groups: DashMap<IpAddr, Vec<String>>,
        call_count: std::sync::atomic::AtomicUsize,
    }

    impl MockRouteWithGroups {
        fn new() -> Self {
            let route = Self {
                ip_to_groups: DashMap::new(),
                call_count: std::sync::atomic::AtomicUsize::new(0),
            };

            // Setup test data
            route.ip_to_groups.insert(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                vec!["admin".to_string(), "dev".to_string()],
            );
            route.ip_to_groups.insert(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                vec!["db-server".to_string()],
            );
            route.ip_to_groups.insert(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)),
                vec!["guest".to_string()],
            );

            route
        }

        fn get_call_count(&self) -> usize {
            self.call_count.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn reset_call_count(&self) {
            self.call_count
                .store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[async_trait::async_trait]
    impl Route for MockRouteWithGroups {
        async fn open(&self, _interface: RouteInterfaceBox) -> Result<u8, ()> {
            Ok(0)
        }

        async fn close(&self) {}

        async fn get_next_hop(&self, _peer_id: PeerId) -> Option<PeerId> {
            None
        }

        async fn list_routes(&self) -> Vec<crate::proto::cli::Route> {
            vec![]
        }

        async fn get_peer_info(&self, _peer_id: PeerId) -> Option<RoutePeerInfo> {
            None
        }

        async fn get_peer_info_last_update_time(&self) -> std::time::Instant {
            std::time::Instant::now()
        }

        fn get_peer_groups(&self, _peer_id: PeerId) -> Vec<String> {
            vec![]
        }

        async fn get_peer_groups_by_ip(&self, ip: &IpAddr) -> Vec<String> {
            // Increment call counter for testing
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Simulate some async work
            tokio::task::yield_now().await;

            self.ip_to_groups
                .get(ip)
                .map(|groups| groups.clone())
                .unwrap_or_default()
        }
    }

    #[tokio::test]
    async fn test_group_cache_basic_functionality() {
        let filter = AclFilter::new();
        let route = MockRouteWithGroups::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        // First call should miss cache
        let groups1 = filter.get_groups_with_cache(&ip, &route).await;
        assert_eq!(*groups1, vec!["admin", "dev"]);
        assert_eq!(route.get_call_count(), 1);

        // Second call should hit cache
        let groups2 = filter.get_groups_with_cache(&ip, &route).await;
        assert_eq!(*groups2, vec!["admin", "dev"]);
        assert_eq!(route.get_call_count(), 1); // No additional call

        // Verify both results are the same Arc
        assert!(Arc::ptr_eq(&groups1, &groups2));
    }

    #[tokio::test]
    async fn test_group_cache_expiration() {
        let filter = AclFilter::new();
        let route = MockRouteWithGroups::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        // First call
        let _groups1 = filter.get_groups_with_cache(&ip, &route).await;
        assert_eq!(route.get_call_count(), 1);

        // // Manually expire the cache entry by modifying its timestamp
        if let Some(mut entry) = filter.group_cache.get_mut(&ip) {
            // 设置为已过期并立即释放 guard，避免后续 await 导致死锁
            entry.timestamp = Instant::now() - GROUP_CACHE_TTL - Duration::from_millis(100);
            drop(entry);
        }

        // Second call should miss cache due to expiration
        let _groups2 = filter.get_groups_with_cache(&ip, &route).await;
        assert_eq!(route.get_call_count(), 2);
    }

    #[tokio::test]
    async fn test_parallel_group_lookup() {
        let filter = AclFilter::new();
        let route = MockRouteWithGroups::new();

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

        route.reset_call_count();
        let start = Instant::now();

        // Parallel lookup
        let (groups1, groups2) = tokio::join!(
            filter.get_groups_with_cache(&ip1, &route),
            filter.get_groups_with_cache(&ip2, &route)
        );

        let duration = start.elapsed();

        assert_eq!(*groups1, vec!["admin", "dev"]);
        assert_eq!(*groups2, vec!["db-server"]);
        assert_eq!(route.get_call_count(), 2);

        // Parallel execution should be faster than sequential
        // (This is a basic check - in real scenarios the difference would be more significant)
        assert!(duration < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_cache_size_limit() {
        let filter = AclFilter::new();
        let route = MockRouteWithGroups::new();

        // Fill cache beyond limit
        for i in 0..GROUP_CACHE_MAX_SIZE + 10 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
            let _ = filter.get_groups_with_cache(&ip, &route).await;
        }

        // Cache size should not exceed the limit significantly
        assert!(filter.group_cache.len() <= GROUP_CACHE_MAX_SIZE + 5);
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let filter = AclFilter::new();
        let route = MockRouteWithGroups::new();

        // Add some entries
        for i in 0..10 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i + 1));
            let _ = filter.get_groups_with_cache(&ip, &route).await;
        }

        let initial_size = filter.group_cache.len();
        assert!(initial_size > 0);

        // Manually expire all entries
        for mut entry in filter.group_cache.iter_mut() {
            entry.timestamp = Instant::now() - Duration::from_secs(2);
        }

        // Trigger cleanup
        filter.cleanup_expired_cache_entries();

        // All entries should be removed
        assert_eq!(filter.group_cache.len(), 0);
    }

    #[tokio::test]
    async fn test_clear_group_cache() {
        let filter = AclFilter::new();
        let route = MockRouteWithGroups::new();

        // Add some entries
        for i in 0..5 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i + 1));
            let _ = filter.get_groups_with_cache(&ip, &route).await;
        }

        assert!(!filter.group_cache.is_empty());

        // Clear cache
        filter.clear_group_cache();

        assert_eq!(filter.group_cache.len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_cache_access() {
        let filter = Arc::new(AclFilter::new());
        let route = Arc::new(MockRouteWithGroups::new());
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        // Use a smaller number of concurrent tasks to avoid overwhelming the test
        let mut handles = vec![];
        for _ in 0..5 {
            let filter_clone = filter.clone();
            let route_clone = route.clone();
            let handle = tokio::spawn(async move {
                filter_clone
                    .get_groups_with_cache(&ip, route_clone.as_ref())
                    .await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete with individual timeouts
        let mut results = vec![];
        for handle in handles {
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(groups)) => results.push(groups),
                Ok(Err(e)) => panic!("Task failed: {:?}", e),
                Err(_) => panic!("Task timed out"),
            }
        }

        // All should succeed and return the same groups
        for groups in results {
            assert_eq!(*groups, vec!["admin", "dev"]);
        }

        // Should have made only a few calls due to caching
        assert!(route.get_call_count() <= 5);
    }

    #[tokio::test]
    async fn test_memory_efficiency_with_arc() {
        let filter = AclFilter::new();
        let route = MockRouteWithGroups::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        // Get groups once
        let groups1 = filter.get_groups_with_cache(&ip, &route).await;

        // Get groups again from cache
        let groups2 = filter.get_groups_with_cache(&ip, &route).await;

        // Verify both results are the same Arc (sharing memory)
        assert!(Arc::ptr_eq(&groups1, &groups2));

        // Verify content is correct
        assert_eq!(*groups1, vec!["admin", "dev"]);
        assert_eq!(*groups2, vec!["admin", "dev"]);

        // Only one route call should be made due to caching
        assert_eq!(route.get_call_count(), 1);
    }
}
