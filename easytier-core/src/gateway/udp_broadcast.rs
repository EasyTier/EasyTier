use std::net::Ipv4Addr;

use cidr::Ipv4Inet;
use smoltcp::wire::{
    IPV4_HEADER_LEN, IpAddress, IpProtocol, Ipv4Packet, UDP_HEADER_LEN, UdpPacket,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PhysicalInterface {
    addr: Ipv4Addr,
    directed_broadcast: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonContiguousIpv4Netmask(Ipv4Addr);

impl NonContiguousIpv4Netmask {
    pub fn netmask(self) -> Ipv4Addr {
        self.0
    }
}

impl PhysicalInterface {
    pub fn from_observation(
        addr: Ipv4Addr,
        netmask: Option<Ipv4Addr>,
        is_internal: bool,
        virtual_addr: Ipv4Addr,
    ) -> Result<Option<Self>, NonContiguousIpv4Netmask> {
        if is_internal || addr == virtual_addr {
            return Ok(None);
        }

        let Some(netmask) = netmask else {
            return Ok(None);
        };
        let prefix = prefix_len_from_netmask(netmask).ok_or(NonContiguousIpv4Netmask(netmask))?;
        Ok(Self::from_ip_and_prefix(addr, prefix))
    }

    pub fn from_ip_and_prefix(addr: Ipv4Addr, prefix: u8) -> Option<Self> {
        if should_ignore_interface_addr(addr) || prefix > 30 {
            return None;
        }

        Some(Self {
            addr,
            directed_broadcast: directed_broadcast(addr, prefix)?,
        })
    }

    pub fn address(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn directed_broadcast(&self) -> Ipv4Addr {
        self.directed_broadcast
    }
}

#[derive(Debug, Clone)]
pub struct BroadcastRelayConfig {
    virtual_ipv4: Ipv4Inet,
    physical_interfaces: Vec<PhysicalInterface>,
}

impl BroadcastRelayConfig {
    pub fn new(virtual_ipv4: Ipv4Inet, physical_interfaces: Vec<PhysicalInterface>) -> Self {
        let mut eligible_interfaces = Vec::with_capacity(physical_interfaces.len());
        for interface in physical_interfaces {
            if interface.addr == virtual_ipv4.address() || eligible_interfaces.contains(&interface)
            {
                continue;
            }
            eligible_interfaces.push(interface);
        }

        Self {
            virtual_ipv4,
            physical_interfaces: eligible_interfaces,
        }
    }

    pub fn virtual_ipv4(&self) -> &Ipv4Inet {
        &self.virtual_ipv4
    }

    pub fn physical_interfaces(&self) -> &[PhysicalInterface] {
        &self.physical_interfaces
    }

    fn is_physical_source(&self, addr: Ipv4Addr) -> bool {
        self.physical_interfaces
            .iter()
            .any(|iface| iface.addr == addr)
    }

    fn normalize_destination(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        if dst.is_broadcast() || dst.is_multicast() {
            return Some(dst);
        }

        self.physical_interfaces
            .iter()
            .any(|iface| iface.directed_broadcast == dst)
            .then_some(self.virtual_ipv4.last_address())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPacket {
    pub packet: Vec<u8>,
    pub destination: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketSummary {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_len: usize,
    pub udp_len: usize,
    pub payload_len: usize,
}

impl UdpPacketSummary {
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < IPV4_HEADER_LEN {
            return None;
        }
        let ipv4_packet = Ipv4Packet::new_unchecked(packet);
        if ipv4_packet.version() != 4 || ipv4_packet.next_header() != IpProtocol::Udp {
            return None;
        }

        let header_len = usize::from(ipv4_packet.header_len());
        let total_len = usize::from(ipv4_packet.total_len());
        if header_len < IPV4_HEADER_LEN
            || total_len < header_len + UDP_HEADER_LEN
            || total_len > packet.len()
        {
            return None;
        }

        let udp_packet = UdpPacket::new_unchecked(&packet[header_len..total_len]);
        let udp_len = usize::from(udp_packet.len());
        if udp_len < UDP_HEADER_LEN || header_len + udp_len != total_len {
            return None;
        }

        Some(Self {
            src: ipv4_packet.src_addr(),
            dst: ipv4_packet.dst_addr(),
            src_port: udp_packet.src_port(),
            dst_port: udp_packet.dst_port(),
            ip_len: total_len,
            udp_len,
            payload_len: udp_len - UDP_HEADER_LEN,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpBroadcastPacketRejection {
    MalformedIpv4,
    NotUdpIpv4,
    Fragmented,
    BadIpv4Length,
    IgnoredSource,
    VirtualSourceDuplicate,
    NonPhysicalSource,
    UnsupportedDestination,
    LoopbackDestination,
    MalformedUdp,
    BadUdpLength,
}

impl UdpBroadcastPacketRejection {
    pub fn reason(self) -> &'static str {
        match self {
            Self::MalformedIpv4 => "malformed_ipv4",
            Self::NotUdpIpv4 => "not_udp_ipv4",
            Self::Fragmented => "fragmented",
            Self::BadIpv4Length => "bad_ipv4_length",
            Self::IgnoredSource => "ignored_source",
            Self::VirtualSourceDuplicate => "virtual_source_duplicate",
            Self::NonPhysicalSource => "non_physical_source",
            Self::UnsupportedDestination => "unsupported_destination",
            Self::LoopbackDestination => "loopback_destination",
            Self::MalformedUdp => "malformed_udp",
            Self::BadUdpLength => "bad_udp_length",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedUdpBroadcastPacket {
    header_len: usize,
    udp_len: usize,
    normalized_destination: Ipv4Addr,
}

fn should_ignore_interface_addr(addr: Ipv4Addr) -> bool {
    addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() || addr.is_broadcast()
}

fn prefix_len_from_netmask(mask: Ipv4Addr) -> Option<u8> {
    let raw = u32::from(mask);
    let prefix = raw.count_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (raw == expected).then_some(prefix)
}

fn directed_broadcast(addr: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix > 32 {
        return None;
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some(Ipv4Addr::from(u32::from(addr) | !mask))
}

fn parse_udp_broadcast(
    packet: &[u8],
    config: &BroadcastRelayConfig,
) -> Result<ParsedUdpBroadcastPacket, UdpBroadcastPacketRejection> {
    if packet.len() < IPV4_HEADER_LEN {
        return Err(UdpBroadcastPacketRejection::MalformedIpv4);
    }
    let ipv4_packet = Ipv4Packet::new_unchecked(packet);
    if ipv4_packet.version() != 4 || ipv4_packet.next_header() != IpProtocol::Udp {
        return Err(UdpBroadcastPacketRejection::NotUdpIpv4);
    }

    if ipv4_packet.frag_offset() != 0 || ipv4_packet.more_frags() {
        return Err(UdpBroadcastPacketRejection::Fragmented);
    }

    let header_len = usize::from(ipv4_packet.header_len());
    let total_len = usize::from(ipv4_packet.total_len());
    if header_len < IPV4_HEADER_LEN
        || total_len < header_len + UDP_HEADER_LEN
        || total_len > packet.len()
    {
        return Err(UdpBroadcastPacketRejection::BadIpv4Length);
    }

    let src = ipv4_packet.src_addr();
    let dst = ipv4_packet.dst_addr();
    if should_ignore_interface_addr(src) {
        return Err(UdpBroadcastPacketRejection::IgnoredSource);
    }
    if src == config.virtual_ipv4.address() {
        return Err(UdpBroadcastPacketRejection::VirtualSourceDuplicate);
    }
    if !config.is_physical_source(src) {
        return Err(UdpBroadcastPacketRejection::NonPhysicalSource);
    }

    let normalized_destination = config
        .normalize_destination(dst)
        .ok_or(UdpBroadcastPacketRejection::UnsupportedDestination)?;
    if normalized_destination.is_loopback() {
        return Err(UdpBroadcastPacketRejection::LoopbackDestination);
    }

    let udp_packet = UdpPacket::new_unchecked(&packet[header_len..total_len]);
    let udp_len = usize::from(udp_packet.len());
    if udp_len < UDP_HEADER_LEN || header_len + udp_len != total_len {
        return Err(UdpBroadcastPacketRejection::BadUdpLength);
    }

    Ok(ParsedUdpBroadcastPacket {
        header_len,
        udp_len,
        normalized_destination,
    })
}

pub fn normalize_udp_broadcast_packet(
    packet: &[u8],
    config: &BroadcastRelayConfig,
) -> Result<NormalizedPacket, UdpBroadcastPacketRejection> {
    let parsed = parse_udp_broadcast(packet, config)?;
    let header_len = parsed.header_len;
    let packet_len = header_len + parsed.udp_len;
    let destination = parsed.normalized_destination;
    let virtual_ipv4 = config.virtual_ipv4.address();
    let mut normalized = packet[..packet_len].to_vec();

    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut normalized);
        ipv4_packet.set_src_addr(virtual_ipv4);
        ipv4_packet.set_dst_addr(destination);
        ipv4_packet.set_total_len(packet_len as u16);
        ipv4_packet.set_checksum(0);
    }

    {
        let mut udp_packet = UdpPacket::new_unchecked(&mut normalized[header_len..packet_len]);
        udp_packet.fill_checksum(
            &IpAddress::Ipv4(virtual_ipv4),
            &IpAddress::Ipv4(destination),
        );
    }

    {
        Ipv4Packet::new_unchecked(&mut normalized).fill_checksum();
    }

    Ok(NormalizedPacket {
        packet: normalized,
        destination,
    })
}

#[derive(Clone)]
pub struct UdpBroadcastRelayStats {
    packets_captured: crate::foundation::stats::CounterHandle,
    packets_ignored: crate::foundation::stats::CounterHandle,
    packets_forwarded: crate::foundation::stats::CounterHandle,
    packets_forward_failed: crate::foundation::stats::CounterHandle,
}

impl UdpBroadcastRelayStats {
    pub(crate) fn new(
        packets_captured: crate::foundation::stats::CounterHandle,
        packets_ignored: crate::foundation::stats::CounterHandle,
        packets_forwarded: crate::foundation::stats::CounterHandle,
        packets_forward_failed: crate::foundation::stats::CounterHandle,
    ) -> Self {
        Self {
            packets_captured,
            packets_ignored,
            packets_forwarded,
            packets_forward_failed,
        }
    }

    pub fn record_captured(&self) {
        self.packets_captured.inc();
    }

    pub fn record_ignored(&self) {
        self.packets_ignored.inc();
    }

    pub fn record_forwarded(&self) {
        self.packets_forwarded.inc();
    }

    pub fn record_forward_failed(&self) {
        self.packets_forward_failed.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BroadcastRelayConfig {
        BroadcastRelayConfig::new(
            "10.144.144.1/24".parse().unwrap(),
            vec![PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(192, 168, 1, 7), 24).unwrap()],
        )
    }

    fn build_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 20 + 8 + payload.len()];
        {
            let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_len(20);
            ipv4_packet.set_total_len((20 + 8 + payload.len()) as u16);
            ipv4_packet.set_hop_limit(64);
            ipv4_packet.set_next_header(IpProtocol::Udp);
            ipv4_packet.set_src_addr(src);
            ipv4_packet.set_dst_addr(dst);
        }

        {
            let mut udp_packet = UdpPacket::new_unchecked(&mut packet[20..]);
            udp_packet.set_src_port(12345);
            udp_packet.set_dst_port(37020);
            udp_packet.set_len((8 + payload.len()) as u16);
            udp_packet.payload_mut().copy_from_slice(payload);
            udp_packet.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
        }

        Ipv4Packet::new_unchecked(&mut packet).fill_checksum();

        packet
    }

    fn assert_valid_checksums(packet: &[u8]) {
        let ipv4_packet = Ipv4Packet::new_checked(packet).unwrap();
        assert!(ipv4_packet.verify_checksum());
        let udp_packet = UdpPacket::new_checked(ipv4_packet.payload()).unwrap();
        assert!(udp_packet.verify_checksum(
            &IpAddress::Ipv4(ipv4_packet.src_addr()),
            &IpAddress::Ipv4(ipv4_packet.dst_addr()),
        ));
    }

    #[test]
    fn rewrites_limited_broadcast() {
        let packet = build_udp_packet(Ipv4Addr::new(192, 168, 1, 7), Ipv4Addr::BROADCAST, b"hello");

        let normalized = normalize_udp_broadcast_packet(&packet, &config()).unwrap();
        let ipv4_packet = Ipv4Packet::new_checked(&normalized.packet).unwrap();

        assert_eq!(normalized.destination, Ipv4Addr::BROADCAST);
        assert_eq!(ipv4_packet.src_addr(), Ipv4Addr::new(10, 144, 144, 1));
        assert_eq!(ipv4_packet.dst_addr(), Ipv4Addr::BROADCAST);
        assert_eq!(&ipv4_packet.payload()[8..], b"hello");
        assert_valid_checksums(&normalized.packet);
    }

    #[test]
    fn rewrites_directed_broadcast() {
        let packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::new(192, 168, 1, 255),
            b"directed",
        );

        let normalized = normalize_udp_broadcast_packet(&packet, &config()).unwrap();
        let ipv4_packet = Ipv4Packet::new_checked(&normalized.packet).unwrap();

        assert_eq!(normalized.destination, Ipv4Addr::new(10, 144, 144, 255));
        assert_eq!(ipv4_packet.src_addr(), Ipv4Addr::new(10, 144, 144, 1));
        assert_eq!(ipv4_packet.dst_addr(), Ipv4Addr::new(10, 144, 144, 255));
        assert_eq!(&ipv4_packet.payload()[8..], b"directed");
        assert_valid_checksums(&normalized.packet);
    }

    #[test]
    fn preserves_multicast_destination() {
        let multicast = Ipv4Addr::new(239, 255, 255, 250);
        let packet = build_udp_packet(Ipv4Addr::new(192, 168, 1, 7), multicast, b"multicast");

        let normalized = normalize_udp_broadcast_packet(&packet, &config()).unwrap();
        let ipv4_packet = Ipv4Packet::new_checked(&normalized.packet).unwrap();

        assert_eq!(normalized.destination, multicast);
        assert_eq!(ipv4_packet.src_addr(), Ipv4Addr::new(10, 144, 144, 1));
        assert_eq!(ipv4_packet.dst_addr(), multicast);
        assert_eq!(&ipv4_packet.payload()[8..], b"multicast");
        assert_valid_checksums(&normalized.packet);
    }

    #[test]
    fn rejects_malformed_packets() {
        assert_eq!(
            normalize_udp_broadcast_packet(&[], &config()),
            Err(UdpBroadcastPacketRejection::MalformedIpv4)
        );

        let mut packet =
            build_udp_packet(Ipv4Addr::new(192, 168, 1, 7), Ipv4Addr::BROADCAST, b"bad");
        packet[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(
            normalize_udp_broadcast_packet(&packet, &config()),
            Err(UdpBroadcastPacketRejection::BadIpv4Length)
        );
    }

    #[test]
    fn rejects_fragments() {
        let mut packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::BROADCAST,
            b"fragment",
        );
        {
            let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
            ipv4_packet.set_more_frags(true);
        }

        assert_eq!(
            normalize_udp_broadcast_packet(&packet, &config()),
            Err(UdpBroadcastPacketRejection::Fragmented)
        );
    }

    #[test]
    fn rejects_non_broadcast_destinations() {
        let packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::new(192, 168, 1, 10),
            b"unicast",
        );

        assert_eq!(
            normalize_udp_broadcast_packet(&packet, &config()),
            Err(UdpBroadcastPacketRejection::UnsupportedDestination)
        );
    }

    #[test]
    fn rejects_virtual_source_duplicates() {
        let packet = build_udp_packet(Ipv4Addr::new(10, 144, 144, 1), Ipv4Addr::BROADCAST, b"loop");

        assert_eq!(
            normalize_udp_broadcast_packet(&packet, &config()),
            Err(UdpBroadcastPacketRejection::VirtualSourceDuplicate)
        );
    }

    #[test]
    fn rejects_non_udp_ipv4_packets() {
        let mut packet =
            build_udp_packet(Ipv4Addr::new(192, 168, 1, 7), Ipv4Addr::BROADCAST, b"tcp");
        Ipv4Packet::new_unchecked(&mut packet).set_next_header(IpProtocol::Tcp);

        assert_eq!(
            normalize_udp_broadcast_packet(&packet, &config()),
            Err(UdpBroadcastPacketRejection::NotUdpIpv4)
        );
    }

    #[test]
    fn rejects_ignored_and_non_physical_sources() {
        let ignored = build_udp_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::BROADCAST, b"ignored");
        assert_eq!(
            normalize_udp_broadcast_packet(&ignored, &config()),
            Err(UdpBroadcastPacketRejection::IgnoredSource)
        );

        let non_physical =
            build_udp_packet(Ipv4Addr::new(192, 168, 1, 8), Ipv4Addr::BROADCAST, b"other");
        assert_eq!(
            normalize_udp_broadcast_packet(&non_physical, &config()),
            Err(UdpBroadcastPacketRejection::NonPhysicalSource)
        );
    }

    #[test]
    fn rejects_loopback_destination_after_mapping() {
        let config = BroadcastRelayConfig::new(
            "127.0.0.1/24".parse().unwrap(),
            vec![PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(192, 168, 1, 7), 24).unwrap()],
        );
        let packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::new(192, 168, 1, 255),
            b"loopback",
        );

        assert_eq!(
            normalize_udp_broadcast_packet(&packet, &config),
            Err(UdpBroadcastPacketRejection::LoopbackDestination)
        );
    }

    #[test]
    fn summarizes_packets_and_rejects_bad_udp_length() {
        let mut packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::BROADCAST,
            b"summary",
        );
        assert_eq!(
            UdpPacketSummary::parse(&packet),
            Some(UdpPacketSummary {
                src: Ipv4Addr::new(192, 168, 1, 7),
                dst: Ipv4Addr::BROADCAST,
                src_port: 12345,
                dst_port: 37020,
                ip_len: 35,
                udp_len: 15,
                payload_len: 7,
            })
        );

        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(
            normalize_udp_broadcast_packet(&packet, &config()),
            Err(UdpBroadcastPacketRejection::BadUdpLength)
        );
        assert_eq!(UdpPacketSummary::parse(&packet), None);
    }

    #[test]
    fn rejection_reasons_preserve_log_values() {
        let reasons = [
            (UdpBroadcastPacketRejection::MalformedIpv4, "malformed_ipv4"),
            (UdpBroadcastPacketRejection::NotUdpIpv4, "not_udp_ipv4"),
            (UdpBroadcastPacketRejection::Fragmented, "fragmented"),
            (
                UdpBroadcastPacketRejection::BadIpv4Length,
                "bad_ipv4_length",
            ),
            (UdpBroadcastPacketRejection::IgnoredSource, "ignored_source"),
            (
                UdpBroadcastPacketRejection::VirtualSourceDuplicate,
                "virtual_source_duplicate",
            ),
            (
                UdpBroadcastPacketRejection::NonPhysicalSource,
                "non_physical_source",
            ),
            (
                UdpBroadcastPacketRejection::UnsupportedDestination,
                "unsupported_destination",
            ),
            (
                UdpBroadcastPacketRejection::LoopbackDestination,
                "loopback_destination",
            ),
            (UdpBroadcastPacketRejection::MalformedUdp, "malformed_udp"),
            (UdpBroadcastPacketRejection::BadUdpLength, "bad_udp_length"),
        ];

        for (rejection, reason) in reasons {
            assert_eq!(rejection.reason(), reason);
        }
    }

    #[test]
    fn detects_directed_broadcast_from_prefix() {
        let physical =
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(172, 16, 5, 10), 20).unwrap();
        assert_eq!(
            physical.directed_broadcast(),
            Ipv4Addr::new(172, 16, 15, 255)
        );
        assert_eq!(
            prefix_len_from_netmask(Ipv4Addr::new(255, 255, 240, 0)),
            Some(20)
        );
        assert_eq!(prefix_len_from_netmask(Ipv4Addr::new(255, 0, 255, 0)), None);
    }

    #[test]
    fn classifies_physical_interface_observations() {
        let addr = Ipv4Addr::new(192, 168, 1, 7);
        let virtual_addr = Ipv4Addr::new(10, 144, 144, 1);
        let netmask = Ipv4Addr::new(255, 255, 255, 0);
        let non_contiguous = Ipv4Addr::new(255, 0, 255, 0);

        assert_eq!(
            PhysicalInterface::from_observation(addr, Some(netmask), false, virtual_addr),
            Ok(PhysicalInterface::from_ip_and_prefix(addr, 24))
        );
        assert_eq!(
            PhysicalInterface::from_observation(addr, None, false, virtual_addr),
            Ok(None)
        );
        assert_eq!(
            PhysicalInterface::from_observation(addr, Some(non_contiguous), true, virtual_addr),
            Ok(None)
        );
        assert_eq!(
            PhysicalInterface::from_observation(
                virtual_addr,
                Some(non_contiguous),
                false,
                virtual_addr,
            ),
            Ok(None)
        );
        assert_eq!(
            PhysicalInterface::from_observation(addr, Some(non_contiguous), false, virtual_addr,),
            Err(NonContiguousIpv4Netmask(non_contiguous))
        );
    }

    #[test]
    fn keeps_link_local_interfaces() {
        let physical =
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(169, 254, 13, 10), 16).unwrap();
        assert_eq!(
            physical.directed_broadcast(),
            Ipv4Addr::new(169, 254, 255, 255)
        );
    }

    #[test]
    fn rejects_ineligible_interface_addresses_and_prefixes() {
        for addr in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(239, 1, 2, 3),
            Ipv4Addr::BROADCAST,
        ] {
            assert_eq!(PhysicalInterface::from_ip_and_prefix(addr, 24), None);
        }
        assert_eq!(
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(192, 168, 1, 7), 31),
            None
        );
    }

    #[test]
    fn config_excludes_virtual_and_duplicate_interfaces() {
        let virtual_interface =
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(10, 144, 144, 1), 24).unwrap();
        let physical_interface =
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(192, 168, 1, 7), 24).unwrap();

        let config = BroadcastRelayConfig::new(
            "10.144.144.1/24".parse().unwrap(),
            vec![virtual_interface, physical_interface, physical_interface],
        );

        assert_eq!(config.physical_interfaces(), &[physical_interface]);
    }
}
