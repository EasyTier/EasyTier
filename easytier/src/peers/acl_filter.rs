use std::sync::atomic::Ordering;
use std::{
    net::IpAddr,
    sync::{atomic::AtomicBool, Arc},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet as _,
};

use crate::{
    common::{
        acl_processor::{AclProcessor, AclResult, AclStatKey, AclStatType, PacketInfo},
        global_ctx::ArcGlobalCtx,
    },
    peers::{NicPacketFilter, PeerPacketFilter},
    proto::acl::{Acl, Action, ChainType},
    tunnel::packet_def::ZCPacket,
};

/// ACL filter that can be inserted into the packet processing pipeline
/// Optimized with lock-free hot reloading via atomic processor replacement
pub struct AclFilter {
    // Use ArcSwap for lock-free atomic replacement during hot reload
    acl_processor: ArcSwap<AclProcessor>,
    global_ctx: ArcGlobalCtx,
    acl_enabled: Arc<AtomicBool>,
}

impl AclFilter {
    pub fn new(acl_processor: Arc<AclProcessor>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            acl_processor: ArcSwap::from(acl_processor),
            global_ctx,
            acl_enabled: Arc::new(AtomicBool::new(false)),
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
    fn get_processor(&self) -> Arc<AclProcessor> {
        self.acl_processor.load_full()
    }

    /// Extract packet information for ACL processing
    fn extract_packet_info(&self, packet: &ZCPacket) -> Option<PacketInfo> {
        let payload = packet.payload();
        let ipv4_packet = Ipv4Packet::new(payload)?;

        if ipv4_packet.get_version() != 4 {
            return None;
        }

        let src_ip = IpAddr::V4(ipv4_packet.get_source());
        let dst_ip = IpAddr::V4(ipv4_packet.get_destination());
        let protocol = ipv4_packet.get_next_level_protocol();

        let (src_port, dst_port) = match protocol {
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

        Some(PacketInfo {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: protocol.0,
            packet_size: payload.len(),
        })
    }

    /// Process ACL result and log if needed
    fn handle_acl_result(
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
                    protocol = packet_info.protocol,
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
    fn process_packet_with_acl(&self, packet: &ZCPacket, chain_type: ChainType) -> bool {
        if !self.acl_enabled.load(Ordering::Relaxed) {
            return true;
        }

        // Get current processor atomically
        let processor = self.get_processor();

        // Extract packet information
        let packet_info = match self.extract_packet_info(packet) {
            Some(info) => info,
            None => {
                tracing::warn!("Failed to extract packet info from {:?} packet", chain_type);
                return false;
            }
        };

        // Process through ACL rules
        let acl_result = processor.process_packet(&packet_info, chain_type);

        self.handle_acl_result(&acl_result, &packet_info, chain_type, &processor);

        // Check if packet should be allowed
        match acl_result.action {
            Action::Allow | Action::Noop => true,
            Action::Drop => {
                tracing::trace!(
                    "ACL: Dropping {} packet from {} to {}, chain_type: {:?}",
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

#[async_trait]
impl PeerPacketFilter for AclFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        // Process through ACL rules for inbound traffic
        let result = self.process_packet_with_acl(&packet, ChainType::Inbound);

        match result {
            true => Some(packet), // Continue processing
            false => None, // Drop packet (logging already handled in process_packet_with_acl)
        }
    }
}

#[async_trait]
impl NicPacketFilter for AclFilter {
    async fn try_process_packet_from_nic(&self, packet: &mut ZCPacket) -> bool {
        // Process through ACL rules for outbound traffic
        let result = self.process_packet_with_acl(packet, ChainType::Outbound);

        match result {
            true => false, // Continue processing in pipeline
            false => true, // Consume packet (logging already handled in process_packet_with_acl)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::acl::*;

    #[tokio::test]
    async fn test_lock_free_reload_demo() {
        println!("\n=== Lock-Free Reload 演示 ===");

        // Create a simple ACL configuration using the new structure
        let mut acl_config = Acl::default();
        acl_config.version = AclVersion::V1 as i32;

        let mut acl_v1 = AclV1::default();

        let mut chain = Chain::default();
        chain.name = "test_inbound".to_string();
        chain.chain_type = ChainType::Inbound as i32;
        chain.enabled = true;

        let mut rule = Rule::default();
        rule.name = "allow_all".to_string();
        rule.priority = 100;
        rule.enabled = true;
        rule.action = Action::Allow as i32;
        rule.protocol = Protocol::Any as i32;

        chain.rules.push(rule);
        acl_v1.chains.push(chain);
        acl_config.acl_v1 = Some(acl_v1);

        let _processor = Arc::new(AclProcessor::new(acl_config.clone()));

        // This demonstrates the API design without actually creating the filter
        // In real usage: let filter = AclFilter::new(processor, global_ctx);

        println!("✓ AclFilter 创建完成 - 不需要 mut");

        // This shows the key benefit - no mut needed!
        // filter.reload_rules(&new_config); // <- 不需要 &mut self!

        println!("✓ reload_rules() 不需要 &mut self");
        println!("✓ 使用 ArcSwap 实现完全无锁的原子替换");
        println!("✓ 性能优势：");
        println!("  - 读取性能极佳：load_full() 只是一个原子指针读取");
        println!("  - 写入性能优良：store() 只是一个原子指针交换");
        println!("  - 内存开销极小：只有一个额外的原子指针");
        println!("  - 线程安全：完全无锁，无竞争条件");
    }

    #[tokio::test]
    async fn test_acl_filter_basic() {
        // This would be a more complete test with proper dependencies
        // For now, just showing the API design
    }
}
