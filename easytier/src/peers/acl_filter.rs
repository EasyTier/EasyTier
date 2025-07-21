use std::{net::IpAddr, sync::Arc};

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
    proto::acl::{Action, ChainType},
    tunnel::packet_def::ZCPacket,
};

/// ACL filter that can be inserted into the packet processing pipeline
pub struct AclFilter {
    acl_processor: Arc<AclProcessor>,
    global_ctx: ArcGlobalCtx,
}

impl AclFilter {
    pub fn new(acl_processor: Arc<AclProcessor>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            acl_processor,
            global_ctx,
        }
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
                self.acl_processor
                    .increment_stat(AclStatKey::PacketsAllowed);
                self.acl_processor
                    .increment_stat(AclStatKey::from_chain_and_action(
                        chain_type,
                        AclStatType::Allowed,
                    ));
                tracing::trace!("ACL: Packet allowed");
            }
            Action::Drop => {
                self.acl_processor
                    .increment_stat(AclStatKey::PacketsDropped);
                self.acl_processor
                    .increment_stat(AclStatKey::from_chain_and_action(
                        chain_type,
                        AclStatType::Dropped,
                    ));
                tracing::debug!("ACL: Packet dropped");
            }
            Action::Noop => {
                self.acl_processor.increment_stat(AclStatKey::PacketsNoop);
                self.acl_processor
                    .increment_stat(AclStatKey::from_chain_and_action(
                        chain_type,
                        AclStatType::Noop,
                    ));
                tracing::trace!("ACL: No operation");
            }
        }

        // Track total packets processed per chain
        self.acl_processor
            .increment_stat(AclStatKey::from_chain_and_action(
                chain_type,
                AclStatType::Total,
            ));
        self.acl_processor.increment_stat(AclStatKey::PacketsTotal);
    }

    /// Common ACL processing logic
    async fn process_packet_with_acl(
        &self,
        packet: &ZCPacket,
        chain_type: ChainType,
        context: &str,
    ) -> Result<PacketInfo, ()> {
        // Extract packet information
        let packet_info = match self.extract_packet_info(packet) {
            Some(info) => info,
            None => {
                tracing::warn!("Failed to extract packet info from {} packet", context);
                return Err(());
            }
        };

        // Process through ACL rules
        let acl_result = self
            .acl_processor
            .process_packet(&packet_info, chain_type)
            .await;

        self.handle_acl_result(&acl_result, &packet_info, chain_type);

        // Check if packet should be allowed
        match acl_result.action {
            Action::Allow | Action::Noop => Ok(packet_info),
            Action::Drop => {
                tracing::trace!(
                    "ACL: Dropping {} packet from {} to {}, chain_type: {:?}",
                    packet_info.protocol,
                    packet_info.src_ip,
                    packet_info.dst_ip,
                    chain_type,
                );

                Err(())
            }
        }
    }
}

#[async_trait]
impl PeerPacketFilter for AclFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        // Process through ACL rules for inbound traffic
        let result = self
            .process_packet_with_acl(&packet, ChainType::Inbound, "peer")
            .await;

        match result {
            Ok(_) => Some(packet), // Continue processing
            Err(_) => None, // Drop packet (logging already handled in process_packet_with_acl)
        }
    }
}

#[async_trait]
impl NicPacketFilter for AclFilter {
    async fn try_process_packet_from_nic(&self, packet: &mut ZCPacket) -> bool {
        // Process through ACL rules for outbound traffic
        let result = self
            .process_packet_with_acl(packet, ChainType::Outbound, "nic")
            .await;

        match result {
            Ok(_) => false, // Continue processing in pipeline
            Err(_) => true, // Consume packet (logging already handled in process_packet_with_acl)
        }
    }
}

/// Forward filter for routing decisions
pub struct AclForwardFilter {
    acl_processor: Arc<AclProcessor>,
    global_ctx: ArcGlobalCtx,
}

impl AclForwardFilter {
    pub fn new(acl_processor: Arc<AclProcessor>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            acl_processor,
            global_ctx,
        }
    }

    /// Check if a packet should be forwarded based on ACL rules
    pub async fn should_forward_packet(&self, packet: &ZCPacket) -> bool {
        let packet_info = match self.extract_packet_info(packet) {
            Some(info) => info,
            None => return false,
        };

        let acl_result = self
            .acl_processor
            .process_packet(&packet_info, ChainType::Forward)
            .await;

        match acl_result.action {
            Action::Allow | Action::Noop => true,
            _ => false,
        }
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::acl::*;

    #[tokio::test]
    async fn test_acl_filter_basic() {
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

        let _acl_processor = Arc::new(AclProcessor::new(acl_config));

        // Test would require creating a mock GlobalCtx and ZCPacket
        // This is a basic structure demonstration
    }

    #[tokio::test]
    async fn test_acl_filter_statistics() {
        use std::sync::Arc;

        // Create a simple ACL configuration
        let mut acl_config = Acl::default();
        acl_config.version = AclVersion::V1 as i32;

        let mut acl_v1 = AclV1::default();

        // Create inbound chain with allow rule
        let mut inbound_chain = Chain::default();
        inbound_chain.name = "test_inbound".to_string();
        inbound_chain.chain_type = ChainType::Inbound as i32;
        inbound_chain.enabled = true;

        let mut allow_rule = Rule::default();
        allow_rule.name = "allow_all".to_string();
        allow_rule.priority = 100;
        allow_rule.enabled = true;
        allow_rule.action = Action::Allow as i32;
        allow_rule.protocol = Protocol::Any as i32;

        inbound_chain.rules.push(allow_rule);

        // Create outbound chain with drop rule
        let mut outbound_chain = Chain::default();
        outbound_chain.name = "test_outbound".to_string();
        outbound_chain.chain_type = ChainType::Outbound as i32;
        outbound_chain.enabled = true;

        let mut drop_rule = Rule::default();
        drop_rule.name = "drop_all".to_string();
        drop_rule.priority = 100;
        drop_rule.enabled = true;
        drop_rule.action = Action::Drop as i32;
        drop_rule.protocol = Protocol::Any as i32;

        outbound_chain.rules.push(drop_rule);

        acl_v1.chains.push(inbound_chain);
        acl_v1.chains.push(outbound_chain);
        acl_config.acl_v1 = Some(acl_v1);

        let acl_processor = Arc::new(AclProcessor::new_with_async_init(acl_config).await);

        // Create test packet info
        let packet_info = PacketInfo {
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: 6, // TCP
            packet_size: 1024,
        };

        // Test inbound processing (should allow)
        let inbound_result = acl_processor
            .process_packet(&packet_info, ChainType::Inbound)
            .await;
        assert_eq!(inbound_result.action, Action::Allow);

        // Test outbound processing (should drop)
        let outbound_result = acl_processor
            .process_packet(&packet_info, ChainType::Outbound)
            .await;
        assert_eq!(outbound_result.action, Action::Drop);

        // Check statistics
        let stats = acl_processor.get_stats();

        // Should have rule matches for both chains
        assert_eq!(
            stats.get(&AclStatKey::RuleMatches.as_str()).unwrap_or(&0),
            &2
        );

        // Verify basic statistics exist (we can't easily test the filter stats without proper integration)
        assert!(stats.contains_key(&AclStatKey::CacheSize.as_str()));
        assert!(stats.contains_key(&AclStatKey::CacheMaxSize.as_str()));
    }
}
