use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex, atomic::AtomicBool},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use easytier_proto::acl::{Acl, AclStats, Action, ChainType, Protocol};
use quanta::Instant;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    packet::{
        PacketType, ZCPacket,
        ip::{
            IP_PROTO_ICMP, IP_PROTO_ICMPV6, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_UNSPECIFIED,
            ParsedIpPacket, parse_ip_packet, parse_transport_ports,
        },
    },
    peers::acl::processor::{AclProcessor, AclResult, AclStatKey, AclStatType, PacketInfo},
};

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

impl ParsedIpPacket<'_> {
    fn can_use_allow_record(&self, is_in: bool) -> bool {
        let expected_type = match (self.protocol, is_in) {
            (IP_PROTO_ICMP, false) => ICMP_ECHO_REQUEST,
            (IP_PROTO_ICMP, true) => ICMP_ECHO_REPLY,
            (IP_PROTO_ICMPV6, false) => ICMPV6_ECHO_REQUEST,
            (IP_PROTO_ICMPV6, true) => ICMPV6_ECHO_REPLY,
            (IP_PROTO_UNSPECIFIED, _) => return false,
            _ => return true,
        };
        if self.is_non_initial_fragment {
            // Tails have no ICMP header. They may use an existing response record,
            // but must not create one. A reverse request still needs an allowed
            // first fragment before the destination can reassemble it.
            return is_in;
        }
        self.transport_payload.len() >= 8
            && self.transport_payload[0] == expected_type
            && self.transport_payload[1] == 0
    }
}

fn acl_protocol(protocol: u8) -> Protocol {
    match protocol {
        IP_PROTO_TCP => Protocol::Tcp,
        IP_PROTO_UDP => Protocol::Udp,
        IP_PROTO_ICMP => Protocol::Icmp,
        IP_PROTO_ICMPV6 => Protocol::IcmPv6,
        _ => Protocol::Unspecified,
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
struct OutboundAllowRecord {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Protocol,
}

impl OutboundAllowRecord {
    fn new_from_inbound_packet(p: &PacketInfo) -> Self {
        Self {
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            src_port: p.src_port,
            dst_port: p.dst_port,
            protocol: p.protocol,
        }
    }

    fn new_from_outbound_packet(p: &PacketInfo) -> Self {
        Self {
            src_ip: p.dst_ip,
            dst_ip: p.src_ip,
            src_port: p.dst_port,
            dst_port: p.src_port,
            protocol: p.protocol,
        }
    }
}

/// ACL filter that can be inserted into the packet processing pipeline
/// Optimized with lock-free hot reloading via atomic processor replacement
pub struct AclFilter {
    // Use ArcSwap for lock-free atomic replacement during hot reload
    acl_processor: ArcSwap<AclProcessor>,
    acl_enabled: Arc<AtomicBool>,

    // Track allowed outbound packets and automatically allow their corresponding inbound response
    // packets, even if they would normally be dropped by ACL rules
    outbound_allow_records: Arc<DashMap<OutboundAllowRecord, Instant>>,
    #[allow(dead_code)]
    clean_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl Default for AclFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl AclFilter {
    pub fn new() -> Self {
        let outbound_allow_records = Arc::new(DashMap::new());
        let record_clone = outbound_allow_records.clone();
        Self {
            acl_processor: ArcSwap::from(Arc::new(AclProcessor::new(Acl::default()))),
            acl_enabled: Arc::new(AtomicBool::new(false)),
            outbound_allow_records,
            clean_task: Mutex::new(Some(AbortOnDropHandle::new(tokio::spawn(async move {
                let max_life = std::time::Duration::from_secs(30);
                loop {
                    record_clone.retain(|_, v| v.elapsed() < max_life);
                    crate::foundation::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            })))),
        }
    }

    pub(crate) async fn stop_cleanup_task(&self) {
        let task = self.clean_task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    /// Hot reload ACL rules by creating a new processor instance
    /// Preserves connection tracking and rate limiting state across reloads
    /// Now lock-free and doesn't require &mut self!
    pub fn reload_rules(&self, acl_config: Option<&Acl>) {
        self.outbound_allow_records.clear();

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
    fn extract_packet_info(
        &self,
        packet: &ZCPacket,
        is_in: bool,
        route: &(dyn crate::peers::route::Route + Send + Sync + 'static),
    ) -> Option<(PacketInfo, bool)> {
        let payload = packet.payload();

        let parsed = parse_ip_packet(payload)?;
        let (src_port, dst_port) =
            parse_transport_ports(parsed.protocol, parsed.transport_payload)?;
        let acl_protocol = acl_protocol(parsed.protocol);

        let src_groups = packet
            .get_src_peer_id()
            .map(|peer_id| route.get_peer_groups(peer_id))
            .unwrap_or_else(|| Arc::new(Vec::new()));
        let dst_groups = packet
            .get_dst_peer_id()
            .map(|peer_id| route.get_peer_groups(peer_id))
            .unwrap_or_else(|| Arc::new(Vec::new()));

        Some((
            PacketInfo {
                src_ip: parsed.src_ip,
                dst_ip: parsed.dst_ip,
                src_port,
                dst_port,
                protocol: acl_protocol,
                packet_size: payload.len(),
                src_groups,
                dst_groups,
            },
            parsed.can_use_allow_record(is_in),
        ))
    }

    /// Process ACL result and log if needed
    pub fn handle_acl_result(
        &self,
        result: &AclResult,
        packet_info: &PacketInfo,
        chain_type: ChainType,
        processor: &AclProcessor,
    ) {
        if result.should_log
            && let Some(ref log_context) = result.log_context
        {
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

    fn classify_chain_type(
        is_in: bool,
        packet_info: &PacketInfo,
        my_ipv4: Option<Ipv4Addr>,
        is_local_ipv6: impl Fn(Ipv6Addr) -> bool,
    ) -> ChainType {
        if !is_in {
            return ChainType::Outbound;
        }

        let is_local_dst = packet_info.dst_ip == my_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED)
            || matches!(packet_info.dst_ip, IpAddr::V6(dst) if is_local_ipv6(dst));

        if is_local_dst {
            ChainType::Inbound
        } else {
            ChainType::Forward
        }
    }

    /// Common ACL processing logic
    pub fn process_packet_with_acl(
        &self,
        packet: &ZCPacket,
        is_in: bool,
        my_ipv4: Option<Ipv4Addr>,
        is_local_ipv6: impl Fn(Ipv6Addr) -> bool,
        route: &(dyn crate::peers::route::Route + Send + Sync + 'static),
    ) -> bool {
        if !self.acl_enabled.load(Ordering::Relaxed) {
            return true;
        }

        if packet.peer_manager_header().unwrap().packet_type != PacketType::Data as u8 {
            return true;
        }

        // Extract packet information
        let (packet_info, can_use_allow_record) =
            match self.extract_packet_info(packet, is_in, route) {
                Some(info) => info,
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

        let chain_type = Self::classify_chain_type(is_in, &packet_info, my_ipv4, is_local_ipv6);

        // Get current processor atomically
        let processor = self.get_processor();

        // Process through ACL rules
        let acl_result = processor.process_packet(&packet_info, chain_type);

        self.handle_acl_result(&acl_result, &packet_info, chain_type, &processor);

        // Check if packet should be allowed
        match acl_result.action {
            Action::Allow | Action::Noop => {
                if matches!(chain_type, ChainType::Outbound) && can_use_allow_record {
                    self.outbound_allow_records.insert(
                        OutboundAllowRecord::new_from_outbound_packet(&packet_info),
                        Instant::now(),
                    );
                }
                true
            }
            Action::Drop => {
                if is_in && can_use_allow_record {
                    let record = OutboundAllowRecord::new_from_inbound_packet(&packet_info);
                    let entry = self.outbound_allow_records.entry(record);
                    if let dashmap::Entry::Occupied(mut entry) = entry {
                        entry.insert(Instant::now());
                        tracing::trace!(
                            "ACL: Allowing {:?} packet from {} to {} because of existing allow record, chain_type: {:?}",
                            packet_info.protocol,
                            packet_info.src_ip,
                            packet_info.dst_ip,
                            chain_type,
                        );
                        return true;
                    }
                }

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
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use quanta::Instant;

    use easytier_proto::acl::{Acl, AclV1, Action, Chain, ChainType, Protocol, Rule};

    use crate::{
        packet::ip::{
            IPV6_AUTHENTICATION, IPV6_DESTINATION_OPTIONS, IPV6_FRAGMENT, IPV6_HOP_BY_HOP,
            IPV6_ROUTING,
        },
        peers::acl::processor::PacketInfo,
    };

    use super::{
        AclFilter, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
        IP_PROTO_ICMP, IP_PROTO_ICMPV6, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_UNSPECIFIED,
        OutboundAllowRecord, PacketType, ZCPacket, acl_protocol, parse_ip_packet,
        parse_transport_ports,
    };

    impl AclFilter {
        pub(crate) fn cleanup_task_is_stopped(&self) -> bool {
            self.clean_task.lock().unwrap().is_none()
        }
    }

    fn packet_info(dst_ip: IpAddr) -> PacketInfo {
        PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip,
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Tcp,
            packet_size: 64,
            src_groups: Arc::new(Vec::new()),
            dst_groups: Arc::new(Vec::new()),
        }
    }

    #[test]
    fn parse_ipv4_tcp_packet_extracts_addrs_and_ports() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = IP_PROTO_TCP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80u16.to_be_bytes());

        let parsed = parse_ip_packet(&packet).unwrap();
        let (src_port, dst_port) =
            parse_transport_ports(parsed.protocol, parsed.transport_payload).unwrap();

        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(acl_protocol(parsed.protocol), Protocol::Tcp);
        assert_eq!(src_port, Some(1234));
        assert_eq!(dst_port, Some(80));
    }

    #[test]
    fn parse_ipv6_udp_packet_extracts_addrs_and_ports() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = IP_PROTO_UDP;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet[40..42].copy_from_slice(&5353u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53u16.to_be_bytes());

        let parsed = parse_ip_packet(&packet).unwrap();
        let (src_port, dst_port) =
            parse_transport_ports(parsed.protocol, parsed.transport_payload).unwrap();

        assert_eq!(parsed.src_ip, IpAddr::V6(src));
        assert_eq!(parsed.dst_ip, IpAddr::V6(dst));
        assert_eq!(acl_protocol(parsed.protocol), Protocol::Udp);
        assert_eq!(src_port, Some(5353));
        assert_eq!(dst_port, Some(53));
    }

    #[test]
    fn parse_ipv4_uses_declared_total_length() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&24u16.to_be_bytes());
        packet[9] = IP_PROTO_TCP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80u16.to_be_bytes());

        let parsed = parse_ip_packet(&packet).unwrap();

        assert_eq!(parsed.transport_payload.len(), 4);
        assert!(parse_transport_ports(parsed.protocol, parsed.transport_payload).is_none());
    }

    #[test]
    fn parse_ipv6_uses_declared_payload_length() {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&4u16.to_be_bytes());
        packet[6] = IP_PROTO_UDP;
        packet[40..42].copy_from_slice(&5353u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53u16.to_be_bytes());

        let parsed = parse_ip_packet(&packet).unwrap();

        assert_eq!(parsed.transport_payload.len(), 4);
        assert!(parse_transport_ports(parsed.protocol, parsed.transport_payload).is_none());
    }

    #[test]
    fn parse_ipv4_keeps_pnet_ihl_less_than_five_behavior() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x44;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = IP_PROTO_TCP;
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80u16.to_be_bytes());

        let parsed = parse_ip_packet(&packet).unwrap();
        let (src_port, dst_port) =
            parse_transport_ports(parsed.protocol, parsed.transport_payload).unwrap();

        assert_eq!(parsed.transport_payload.len(), 20);
        assert_eq!(src_port, Some(1234));
        assert_eq!(dst_port, Some(80));
    }

    #[test]
    fn parse_ipv4_keeps_pnet_truncated_options_behavior() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x4f;
        packet[2..4].copy_from_slice(&60u16.to_be_bytes());
        packet[9] = IP_PROTO_ICMP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let parsed = parse_ip_packet(&packet).unwrap();
        let (src_port, dst_port) =
            parse_transport_ports(parsed.protocol, parsed.transport_payload).unwrap();

        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(acl_protocol(parsed.protocol), Protocol::Icmp);
        assert!(parsed.transport_payload.is_empty());
        assert_eq!(src_port, None);
        assert_eq!(dst_port, None);
    }

    #[test]
    fn classify_chain_type_treats_public_ipv6_lease_as_inbound() {
        let leased_ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 0x123);
        let packet_info = packet_info(IpAddr::V6(leased_ipv6));

        let chain =
            AclFilter::classify_chain_type(true, &packet_info, None, |ip| ip == leased_ipv6);

        assert_eq!(chain, ChainType::Inbound);
    }

    #[test]
    fn classify_chain_type_keeps_non_local_ipv6_as_forward() {
        let leased_ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 0x123);
        let packet_info = packet_info(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 2, 0, 0, 0, 0x100,
        )));

        let chain =
            AclFilter::classify_chain_type(true, &packet_info, None, |ip| ip == leased_ipv6);

        assert_eq!(chain, ChainType::Forward);
    }

    // Include both an extension header and a Fragment Header in IPv6 packets.
    // Offset zero uses an atomic fragment; IPv4 uses an unfragmented packet.
    fn icmp_packet(ipv6: bool, message_type: u8, fragment_offset: u16) -> Vec<u8> {
        let mut packet = if ipv6 {
            let mut packet = vec![0u8; 64];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&24u16.to_be_bytes());
            packet[6] = IPV6_HOP_BY_HOP;
            packet[40] = IPV6_FRAGMENT;
            packet[48] = IP_PROTO_ICMPV6;
            packet[50..52].copy_from_slice(&(fragment_offset << 3).to_be_bytes());
            packet
        } else {
            let mut packet = vec![0u8; 28];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&28u16.to_be_bytes());
            packet[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
            packet[9] = IP_PROTO_ICMP;
            packet
        };
        let icmp_offset = packet.len() - 8;
        packet[icmp_offset] = message_type;
        packet
    }

    #[test]
    fn icmp_allow_records_only_accept_requests_outbound_and_replies_inbound() {
        for (ipv6, request, reply) in [
            (false, ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY),
            (true, ICMPV6_ECHO_REQUEST, ICMPV6_ECHO_REPLY),
        ] {
            for (message_type, is_in) in [(request, false), (reply, true)] {
                let mut packet = icmp_packet(ipv6, message_type, 0);
                let parsed = parse_ip_packet(&packet).unwrap();
                assert!(parsed.can_use_allow_record(is_in));
                assert!(!parsed.can_use_allow_record(!is_in));

                // The same checks apply to first fragments with more data pending.
                if ipv6 {
                    packet[51] |= 1;
                } else {
                    packet[6] |= 0x20;
                }
                let parsed = parse_ip_packet(&packet).unwrap();
                assert!(!parsed.is_non_initial_fragment);
                assert!(parsed.can_use_allow_record(is_in));
                assert!(!parsed.can_use_allow_record(!is_in));

                let code_offset = packet.len() - 7;
                packet[code_offset] = 1;
                assert!(
                    !parse_ip_packet(&packet)
                        .unwrap()
                        .can_use_allow_record(is_in)
                );
                packet[code_offset] = 0;
                packet.pop();
                assert!(
                    !parse_ip_packet(&packet)
                        .unwrap()
                        .can_use_allow_record(is_in)
                );
            }
            let packet = icmp_packet(ipv6, 3, 0);
            let parsed = parse_ip_packet(&packet).unwrap();
            assert!(!parsed.can_use_allow_record(false));
            assert!(!parsed.can_use_allow_record(true));

            // Tail bytes can look like a request, but are not an ICMP header.
            let packet = icmp_packet(ipv6, request, 1);
            let parsed = parse_ip_packet(&packet).unwrap();
            assert!(parsed.is_non_initial_fragment);
            assert!(parsed.can_use_allow_record(true));
            assert!(!parsed.can_use_allow_record(false));
        }
    }

    #[test]
    fn ipv6_fragment_tails_do_not_infer_icmp_from_payload() {
        let mut packet = icmp_packet(true, ICMPV6_ECHO_REPLY, 1);
        packet[48] = IPV6_DESTINATION_OPTIONS;
        packet[56] = IP_PROTO_ICMPV6;
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, IP_PROTO_UNSPECIFIED);
        assert!(!parsed.can_use_allow_record(true));

        packet[48] = IP_PROTO_UDP;
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(acl_protocol(parsed.protocol), Protocol::Unspecified);
        assert!(!parsed.can_use_allow_record(true));
    }

    #[test]
    fn parse_ipv6_keeps_addresses_when_fragment_header_exceeds_declared_payload() {
        let mut packet = icmp_packet(true, ICMPV6_ECHO_REPLY, 0);
        packet[4..6].copy_from_slice(&12u16.to_be_bytes());
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, IP_PROTO_UNSPECIFIED);
        assert!(!parsed.can_use_allow_record(true));
    }

    struct TestRoute;

    #[async_trait::async_trait]
    impl crate::peers::route::Route for TestRoute {
        async fn open(&self, _: crate::peers::route::RouteInterfaceBox) -> Result<u8, ()> {
            unreachable!()
        }
        async fn close(&self) {
            unreachable!()
        }
        async fn get_next_hop(&self, _: u32) -> Option<u32> {
            unreachable!()
        }
        async fn list_routes(&self) -> Vec<crate::proto::core_peer::peer::Route> {
            unreachable!()
        }
        async fn list_proxy_cidrs(&self) -> std::collections::BTreeSet<cidr::Ipv4Cidr> {
            unreachable!()
        }
        async fn list_proxy_cidrs_v6(&self) -> std::collections::BTreeSet<cidr::Ipv6Cidr> {
            unreachable!()
        }
        async fn get_peer_info(&self, _: u32) -> Option<crate::proto::peer_rpc::RoutePeerInfo> {
            unreachable!()
        }
        async fn get_peer_info_last_update_time(&self) -> Instant {
            unreachable!()
        }
        fn get_peer_groups(&self, _: u32) -> Arc<Vec<String>> {
            Arc::new(vec![])
        }
    }

    fn assert_ipv6_unknown_payload_follows_acl(next_header: u8, payload: &[u8]) {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut bytes = vec![0u8; 40];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes[6] = next_header;
        bytes[8..24].copy_from_slice(&src.octets());
        bytes[24..40].copy_from_slice(&dst.octets());
        bytes.extend_from_slice(payload);
        let mut packet = ZCPacket::new_with_payload(&bytes);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let filter = AclFilter::new();
        let (info, can_use_allow_record) = filter
            .extract_packet_info(&packet, true, &TestRoute)
            .unwrap();
        assert_eq!(info.src_ip, IpAddr::V6(src));
        assert_eq!(info.dst_ip, IpAddr::V6(dst));
        assert_eq!(info.protocol, Protocol::Unspecified);
        assert_eq!((info.src_port, info.dst_port), (None, None));
        assert!(!can_use_allow_record);

        // Unknown payloads still obey the chain policy, and cannot match a
        // transport port rule using bytes that only happen to look like ports.
        for action in [Action::Drop, Action::Allow] {
            filter.reload_rules(Some(&Acl {
                acl_v1: Some(AclV1 {
                    chains: vec![Chain {
                        name: "inbound".into(),
                        chain_type: ChainType::Inbound as i32,
                        enabled: true,
                        default_action: action as i32,
                        rules: [Protocol::Tcp, Protocol::Udp]
                            .into_iter()
                            .map(|protocol| Rule {
                                name: format!("allow_{protocol:?}_8081"),
                                enabled: true,
                                action: Action::Allow as i32,
                                protocol: protocol as i32,
                                ports: vec!["8081".into()],
                                ..Default::default()
                            })
                            .collect(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }));
            assert_eq!(
                filter.process_packet_with_acl(&packet, true, None, |ip| ip == dst, &TestRoute),
                action == Action::Allow,
            );
            assert!(filter.process_packet_with_acl(&packet, false, None, |_| false, &TestRoute));
            assert!(filter.outbound_allow_records.is_empty());
        }
    }

    #[tokio::test]
    async fn ipv6_malformed_extension_headers_follow_acl() {
        for protocol in [
            IPV6_HOP_BY_HOP,
            IPV6_ROUTING,
            IPV6_DESTINATION_OPTIONS,
            IPV6_AUTHENTICATION,
            IPV6_FRAGMENT,
        ] {
            for len in [0, 1, 4, 7] {
                assert_ipv6_unknown_payload_follows_acl(protocol, &vec![0; len]);
            }
        }
        // The length field extends beyond the available option/AH header.
        for protocol in [IPV6_HOP_BY_HOP, IPV6_AUTHENTICATION] {
            assert_ipv6_unknown_payload_follows_acl(protocol, &[IP_PROTO_UDP, 2, 0, 0, 0, 0, 0, 0]);
        }
        // A second Fragment Header must not reach the global parse-failure path.
        assert_ipv6_unknown_payload_follows_acl(
            IPV6_FRAGMENT,
            &[
                IPV6_FRAGMENT,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                IP_PROTO_ICMPV6,
                0,
                0,
                0,
                0,
                0,
                0,
                2,
            ],
        );
        // A valid extension header followed by a truncated transport header.
        for protocol in [IP_PROTO_TCP, IP_PROTO_UDP] {
            assert_ipv6_unknown_payload_follows_acl(
                IPV6_HOP_BY_HOP,
                &[protocol, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x1f, 0x91],
            );
        }
    }

    #[tokio::test]
    async fn ipv6_transport_fragment_tails_follow_acl() {
        for protocol in [IP_PROTO_TCP, IP_PROTO_UDP] {
            for len in [4, 8, 24] {
                let mut payload = vec![protocol, 0, 0, 8, 0, 0, 0, 1];
                payload.extend_from_slice(&[0x12, 0x34, 0x1f, 0x91]);
                payload.resize(8 + len, 0);
                assert_ipv6_unknown_payload_follows_acl(IPV6_FRAGMENT, &payload);
            }
        }
    }

    #[tokio::test]
    async fn reload_rules_clears_outbound_allow_records() {
        let filter = AclFilter::new();
        filter.outbound_allow_records.insert(
            OutboundAllowRecord {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: Some(1234),
                dst_port: Some(80),
                protocol: Protocol::Tcp,
            },
            Instant::now(),
        );
        assert_eq!(filter.outbound_allow_records.len(), 1);

        filter.reload_rules(Some(&Acl::default()));

        assert_eq!(filter.outbound_allow_records.len(), 0);

        filter.outbound_allow_records.insert(
            OutboundAllowRecord {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: Some(4321),
                dst_port: Some(443),
                protocol: Protocol::Tcp,
            },
            Instant::now(),
        );
        assert_eq!(filter.outbound_allow_records.len(), 1);

        filter.reload_rules(None);

        assert_eq!(filter.outbound_allow_records.len(), 0);
    }
}
