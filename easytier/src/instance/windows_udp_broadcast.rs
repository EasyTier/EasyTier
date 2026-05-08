use std::net::Ipv4Addr;

use cidr::Ipv4Inet;
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
};

#[cfg(any(windows, test))]
use {
    crate::{
        common::stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        peers::peer_manager::PeerManager,
        tunnel::packet_def::ZCPacket,
    },
    anyhow::Context,
    network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig},
    socket2::{Domain, Protocol, SockAddr, Socket, Type},
    std::{
        io,
        net::{IpAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
        sync::Arc,
    },
    tokio_util::task::AbortOnDropHandle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PhysicalInterface {
    addr: Ipv4Addr,
    directed_broadcast: Ipv4Addr,
}

impl PhysicalInterface {
    fn from_ip_and_prefix(addr: Ipv4Addr, prefix: u8) -> Option<Self> {
        if should_ignore_interface_addr(addr) || prefix > 30 {
            return None;
        }

        Some(Self {
            addr,
            directed_broadcast: directed_broadcast(addr, prefix)?,
        })
    }
}

#[derive(Debug, Clone)]
struct BroadcastRelayConfig {
    virtual_ipv4: Ipv4Inet,
    physical_interfaces: Vec<PhysicalInterface>,
}

impl BroadcastRelayConfig {
    fn new(virtual_ipv4: Ipv4Inet, physical_interfaces: Vec<PhysicalInterface>) -> Self {
        Self {
            virtual_ipv4,
            physical_interfaces,
        }
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
struct NormalizedPacket {
    packet: Vec<u8>,
    destination: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpPacketSummary {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ip_len: usize,
    udp_len: usize,
    payload_len: usize,
}

impl UdpPacketSummary {
    fn parse(packet: &[u8]) -> Option<Self> {
        let ipv4_packet = Ipv4Packet::new(packet)?;
        if ipv4_packet.get_version() != 4
            || ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp
        {
            return None;
        }

        let header_len = usize::from(ipv4_packet.get_header_length()) * 4;
        let total_len = usize::from(ipv4_packet.get_total_length());
        if header_len < Ipv4Packet::minimum_packet_size()
            || total_len < header_len + UdpPacket::minimum_packet_size()
            || total_len > packet.len()
        {
            return None;
        }

        let udp_packet = UdpPacket::new(&packet[header_len..total_len])?;
        let udp_len = usize::from(udp_packet.get_length());
        if udp_len < UdpPacket::minimum_packet_size() || header_len + udp_len != total_len {
            return None;
        }

        Some(Self {
            src: ipv4_packet.get_source(),
            dst: ipv4_packet.get_destination(),
            src_port: udp_packet.get_source(),
            dst_port: udp_packet.get_destination(),
            ip_len: total_len,
            udp_len,
            payload_len: udp_len - UdpPacket::minimum_packet_size(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedUdpBroadcastPacket {
    header_len: usize,
    udp_len: usize,
    normalized_destination: Ipv4Addr,
    summary: UdpPacketSummary,
}

#[cfg(any(windows, test))]
#[derive(Clone)]
struct BroadcastRelayStats {
    packets_captured: CounterHandle,
    packets_ignored: CounterHandle,
    packets_forwarded: CounterHandle,
    packets_forward_failed: CounterHandle,
}

#[cfg(any(windows, test))]
impl BroadcastRelayStats {
    fn new(peer_manager: &PeerManager) -> Self {
        let global_ctx = peer_manager.get_global_ctx();
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(global_ctx.get_network_name()));
        let stats_manager = global_ctx.stats_manager();

        Self {
            packets_captured: stats_manager.get_counter(
                MetricName::UdpBroadcastRelayPacketsCaptured,
                label_set.clone(),
            ),
            packets_ignored: stats_manager.get_counter(
                MetricName::UdpBroadcastRelayPacketsIgnored,
                label_set.clone(),
            ),
            packets_forwarded: stats_manager.get_counter(
                MetricName::UdpBroadcastRelayPacketsForwarded,
                label_set.clone(),
            ),
            packets_forward_failed: stats_manager
                .get_counter(MetricName::UdpBroadcastRelayPacketsForwardFailed, label_set),
        }
    }

    fn record_captured(&self) {
        self.packets_captured.inc();
    }

    fn record_ignored(&self) {
        self.packets_ignored.inc();
    }

    fn record_forwarded(&self) {
        self.packets_forwarded.inc();
    }

    fn record_forward_failed(&self) {
        self.packets_forward_failed.inc();
    }
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
) -> Result<ParsedUdpBroadcastPacket, &'static str> {
    let ipv4_packet = Ipv4Packet::new(packet).ok_or("malformed_ipv4")?;
    if ipv4_packet.get_version() != 4
        || ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp
    {
        return Err("not_udp_ipv4");
    }

    if ipv4_packet.get_fragment_offset() != 0
        || ipv4_packet.get_flags() & Ipv4Flags::MoreFragments != 0
    {
        return Err("fragmented");
    }

    let header_len = usize::from(ipv4_packet.get_header_length()) * 4;
    let total_len = usize::from(ipv4_packet.get_total_length());
    if header_len < Ipv4Packet::minimum_packet_size()
        || total_len < header_len + UdpPacket::minimum_packet_size()
        || total_len > packet.len()
    {
        return Err("bad_ipv4_length");
    }

    let src = ipv4_packet.get_source();
    let dst = ipv4_packet.get_destination();
    if should_ignore_interface_addr(src) {
        return Err("ignored_source");
    }
    if src == config.virtual_ipv4.address() {
        return Err("virtual_source_duplicate");
    }
    if !config.is_physical_source(src) {
        return Err("non_physical_source");
    }

    let normalized_destination = config
        .normalize_destination(dst)
        .ok_or("unsupported_destination")?;
    if normalized_destination.is_loopback() {
        return Err("loopback_destination");
    }

    let udp_packet = UdpPacket::new(&packet[header_len..total_len]).ok_or("malformed_udp")?;
    let udp_len = usize::from(udp_packet.get_length());
    if udp_len < UdpPacket::minimum_packet_size() || header_len + udp_len != total_len {
        return Err("bad_udp_length");
    }

    Ok(ParsedUdpBroadcastPacket {
        header_len,
        udp_len,
        normalized_destination,
        summary: UdpPacketSummary {
            src,
            dst,
            src_port: udp_packet.get_source(),
            dst_port: udp_packet.get_destination(),
            ip_len: total_len,
            udp_len,
            payload_len: udp_len - UdpPacket::minimum_packet_size(),
        },
    })
}

fn log_ignored_udp_packet(packet: &[u8], reason: &'static str) {
    if let Some(summary) = UdpPacketSummary::parse(packet) {
        tracing::debug!(
            src = %summary.src,
            dst = %summary.dst,
            src_port = summary.src_port,
            dst_port = summary.dst_port,
            ip_len = summary.ip_len,
            udp_len = summary.udp_len,
            payload_len = summary.payload_len,
            reason,
            "ignored Windows UDP broadcast packet"
        );
    } else {
        tracing::debug!(
            packet_len = packet.len(),
            reason,
            "ignored malformed Windows UDP raw packet"
        );
    }
}

fn normalize_udp_broadcast_packet(
    packet: &[u8],
    config: &BroadcastRelayConfig,
) -> Option<NormalizedPacket> {
    let parsed = match parse_udp_broadcast(packet, config) {
        Ok(parsed) => parsed,
        Err(reason) => {
            if tracing::enabled!(tracing::Level::DEBUG) {
                log_ignored_udp_packet(packet, reason);
            }
            return None;
        }
    };
    let header_len = parsed.header_len;
    let udp_len = parsed.udp_len;
    let destination = parsed.normalized_destination;
    let summary = parsed.summary;
    let packet_len = header_len + udp_len;
    let virtual_ipv4 = config.virtual_ipv4.address();
    let mut normalized = packet[..packet_len].to_vec();

    {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut normalized)?;
        ipv4_packet.set_source(virtual_ipv4);
        ipv4_packet.set_destination(destination);
        ipv4_packet.set_total_length(packet_len as u16);
        ipv4_packet.set_checksum(0);
    }

    {
        let mut udp_packet = MutableUdpPacket::new(&mut normalized[header_len..packet_len])?;
        udp_packet.set_checksum(0);
        let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &virtual_ipv4, &destination);
        udp_packet.set_checksum(checksum);
    }

    {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut normalized)?;
        let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
    }

    tracing::debug!(
        src = %summary.src,
        dst = %summary.dst,
        src_port = summary.src_port,
        dst_port = summary.dst_port,
        ip_len = summary.ip_len,
        udp_len = summary.udp_len,
        payload_len = summary.payload_len,
        normalized_src = %virtual_ipv4,
        normalized_dst = %destination,
        "normalized Windows UDP broadcast packet"
    );

    Some(NormalizedPacket {
        packet: normalized,
        destination,
    })
}

#[cfg(any(windows, test))]
fn log_captured_udp_packet(packet: &[u8]) {
    if let Some(summary) = UdpPacketSummary::parse(packet) {
        tracing::debug!(
            src = %summary.src,
            dst = %summary.dst,
            src_port = summary.src_port,
            dst_port = summary.dst_port,
            ip_len = summary.ip_len,
            udp_len = summary.udp_len,
            payload_len = summary.payload_len,
            "captured Windows UDP raw packet"
        );
    } else {
        tracing::debug!(
            packet_len = packet.len(),
            "captured malformed Windows UDP raw packet"
        );
    }
}

#[cfg(any(windows, test))]
fn collect_physical_interfaces(virtual_ipv4: Ipv4Inet) -> anyhow::Result<Vec<PhysicalInterface>> {
    let mut ret = Vec::new();
    for iface in NetworkInterface::show().context("failed to list Windows network interfaces")? {
        if iface.internal {
            continue;
        }

        for addr in iface.addr {
            let Addr::V4(v4) = addr else {
                continue;
            };
            if v4.ip == virtual_ipv4.address() {
                continue;
            }

            let Some(netmask) = v4.netmask else {
                continue;
            };
            let Some(prefix) = prefix_len_from_netmask(netmask) else {
                tracing::debug!(
                    iface = %iface.name,
                    ip = %v4.ip,
                    mask = %netmask,
                    "ignoring interface with non-contiguous IPv4 netmask"
                );
                continue;
            };
            let Some(physical) = PhysicalInterface::from_ip_and_prefix(v4.ip, prefix) else {
                continue;
            };
            if !ret.contains(&physical) {
                ret.push(physical);
            }
        }
    }
    Ok(ret)
}

#[cfg(any(windows, test))]
fn open_raw_udp_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    // Match ubihazard/broadcast: use one raw UDP listener on loopback, then
    // inspect the IPv4 header to identify the real physical source interface.
    socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(windows)]
fn socket2_into_udp_socket(socket: Socket) -> StdUdpSocket {
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};

    // The raw socket handle came from socket2 and is transferred exactly once.
    unsafe { StdUdpSocket::from_raw_socket(socket.into_raw_socket()) }
}

#[cfg(all(not(windows), unix))]
fn socket2_into_udp_socket(socket: Socket) -> StdUdpSocket {
    use std::os::fd::{FromRawFd, IntoRawFd};

    // The raw socket fd came from socket2 and is transferred exactly once.
    unsafe { StdUdpSocket::from_raw_fd(socket.into_raw_fd()) }
}

#[cfg(any(windows, test))]
struct RawUdpCaptureSocket {
    socket: tokio::net::UdpSocket,
    buf: Vec<u8>,
}

#[cfg(any(windows, test))]
impl RawUdpCaptureSocket {
    const MAX_PACKET_LEN: usize = 65_535;

    fn open() -> anyhow::Result<Self> {
        let socket = open_raw_udp_socket().with_context(|| {
            "failed to open Windows raw UDP broadcast listener; administrator privileges are required"
        })?;
        let socket = socket2_into_udp_socket(socket);
        let socket = tokio::net::UdpSocket::from_std(socket)
            .context("failed to register Windows raw UDP broadcast listener with Tokio")?;

        Ok(Self {
            socket,
            buf: vec![0; Self::MAX_PACKET_LEN],
        })
    }

    async fn recv(&mut self) -> io::Result<&[u8]> {
        let len = self.socket.recv(&mut self.buf).await?;
        Ok(&self.buf[..len])
    }
}

#[cfg(any(windows, test))]
fn open_capture_socket() -> anyhow::Result<RawUdpCaptureSocket> {
    RawUdpCaptureSocket::open()
}

#[cfg(any(windows, test))]
async fn forward_normalized_packet(
    peer_manager: &PeerManager,
    normalized: NormalizedPacket,
    stats: &BroadcastRelayStats,
) {
    let packet = ZCPacket::new_with_payload(&normalized.packet);
    let ret = peer_manager
        .send_msg_by_ip(packet, IpAddr::V4(normalized.destination), true)
        .await;

    let summary = UdpPacketSummary::parse(&normalized.packet);
    match ret {
        Ok(_) => {
            stats.record_forwarded();

            if let Some(summary) = summary {
                tracing::debug!(
                    src = %summary.src,
                    dst = %summary.dst,
                    src_port = summary.src_port,
                    dst_port = summary.dst_port,
                    ip_len = summary.ip_len,
                    udp_len = summary.udp_len,
                    payload_len = summary.payload_len,
                    peer_dst = %normalized.destination,
                    broadcast = true,
                    "forwarded Windows UDP broadcast packet"
                );
            } else {
                tracing::debug!(
                    packet_len = normalized.packet.len(),
                    peer_dst = %normalized.destination,
                    broadcast = true,
                    "forwarded Windows UDP broadcast packet"
                );
            }
        }
        Err(err) => {
            stats.record_forward_failed();

            if let Some(summary) = summary {
                tracing::debug!(
                    src = %summary.src,
                    dst = %summary.dst,
                    src_port = summary.src_port,
                    dst_port = summary.dst_port,
                    ip_len = summary.ip_len,
                    udp_len = summary.udp_len,
                    payload_len = summary.payload_len,
                    peer_dst = %normalized.destination,
                    broadcast = true,
                    ?err,
                    "failed to forward Windows UDP broadcast packet"
                );
            } else {
                tracing::debug!(
                    packet_len = normalized.packet.len(),
                    peer_dst = %normalized.destination,
                    broadcast = true,
                    ?err,
                    "failed to forward Windows UDP broadcast packet"
                );
            }
        }
    }
}

#[cfg(any(windows, test))]
async fn capture_loop(
    peer_manager: Arc<PeerManager>,
    config: BroadcastRelayConfig,
    mut socket: RawUdpCaptureSocket,
    stats: BroadcastRelayStats,
) {
    loop {
        let normalized = match socket.recv().await {
            Ok(packet) => {
                stats.record_captured();
                if tracing::enabled!(tracing::Level::DEBUG) {
                    log_captured_udp_packet(packet);
                }
                let normalized = normalize_udp_broadcast_packet(packet, &config);
                if normalized.is_none() {
                    stats.record_ignored();
                }
                normalized
            }
            Err(err) => {
                tracing::warn!(?err, "Windows UDP broadcast raw socket receive failed");
                continue;
            }
        };

        if let Some(normalized) = normalized {
            forward_normalized_packet(&peer_manager, normalized, &stats).await;
        }
    }
}

#[cfg(any(windows, test))]
pub(crate) fn start(
    peer_manager: Arc<PeerManager>,
    virtual_ipv4: Ipv4Inet,
) -> anyhow::Result<AbortOnDropHandle<()>> {
    let physical_interfaces = collect_physical_interfaces(virtual_ipv4)?;
    if physical_interfaces.is_empty() {
        anyhow::bail!("no physical IPv4 interface is available for UDP broadcast relay");
    }

    tracing::debug!(
        virtual_ipv4 = %virtual_ipv4,
        physical_interfaces = ?physical_interfaces,
        "starting Windows UDP broadcast relay"
    );

    let socket = open_capture_socket()?;
    let config = BroadcastRelayConfig::new(virtual_ipv4, physical_interfaces);
    let stats = BroadcastRelayStats::new(&peer_manager);
    let task = tokio::spawn(capture_loop(peer_manager, config, socket, stats));
    Ok(AbortOnDropHandle::new(task))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::{MutablePacket, Packet};

    fn config() -> BroadcastRelayConfig {
        BroadcastRelayConfig::new(
            "10.144.144.1/24".parse().unwrap(),
            vec![PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(192, 168, 1, 7), 24).unwrap()],
        )
    }

    fn build_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 20 + 8 + payload.len()];
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length((20 + 8 + payload.len()) as u16);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_source(src);
            ipv4_packet.set_destination(dst);
        }

        {
            let mut udp_packet = MutableUdpPacket::new(&mut packet[20..]).unwrap();
            udp_packet.set_source(12345);
            udp_packet.set_destination(37020);
            udp_packet.set_length((8 + payload.len()) as u16);
            udp_packet.payload_mut().copy_from_slice(payload);
            let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dst);
            udp_packet.set_checksum(checksum);
        }

        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
            let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);
        }

        packet
    }

    fn assert_valid_checksums(packet: &[u8]) {
        let ipv4_packet = Ipv4Packet::new(packet).unwrap();
        assert_eq!(ipv4::checksum(&ipv4_packet), ipv4_packet.get_checksum());
        let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(
            udp::ipv4_checksum(
                &udp_packet,
                &ipv4_packet.get_source(),
                &ipv4_packet.get_destination()
            ),
            udp_packet.get_checksum()
        );
    }

    #[test]
    fn windows_udp_broadcast_rewrites_limited_broadcast() {
        let packet = build_udp_packet(Ipv4Addr::new(192, 168, 1, 7), Ipv4Addr::BROADCAST, b"hello");

        let normalized = normalize_udp_broadcast_packet(&packet, &config()).unwrap();
        let ipv4_packet = Ipv4Packet::new(&normalized.packet).unwrap();

        assert_eq!(normalized.destination, Ipv4Addr::BROADCAST);
        assert_eq!(ipv4_packet.get_source(), Ipv4Addr::new(10, 144, 144, 1));
        assert_eq!(ipv4_packet.get_destination(), Ipv4Addr::BROADCAST);
        assert_eq!(&ipv4_packet.payload()[8..], b"hello");
        assert_valid_checksums(&normalized.packet);
    }

    #[test]
    fn windows_udp_broadcast_rewrites_directed_broadcast() {
        let packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::new(192, 168, 1, 255),
            b"directed",
        );

        let normalized = normalize_udp_broadcast_packet(&packet, &config()).unwrap();
        let ipv4_packet = Ipv4Packet::new(&normalized.packet).unwrap();

        assert_eq!(normalized.destination, Ipv4Addr::new(10, 144, 144, 255));
        assert_eq!(ipv4_packet.get_source(), Ipv4Addr::new(10, 144, 144, 1));
        assert_eq!(
            ipv4_packet.get_destination(),
            Ipv4Addr::new(10, 144, 144, 255)
        );
        assert_eq!(&ipv4_packet.payload()[8..], b"directed");
        assert_valid_checksums(&normalized.packet);
    }

    #[test]
    fn windows_udp_broadcast_preserves_multicast_destination() {
        let multicast = Ipv4Addr::new(239, 255, 255, 250);
        let packet = build_udp_packet(Ipv4Addr::new(192, 168, 1, 7), multicast, b"multicast");

        let normalized = normalize_udp_broadcast_packet(&packet, &config()).unwrap();
        let ipv4_packet = Ipv4Packet::new(&normalized.packet).unwrap();

        assert_eq!(normalized.destination, multicast);
        assert_eq!(ipv4_packet.get_source(), Ipv4Addr::new(10, 144, 144, 1));
        assert_eq!(ipv4_packet.get_destination(), multicast);
        assert_eq!(&ipv4_packet.payload()[8..], b"multicast");
        assert_valid_checksums(&normalized.packet);
    }

    #[test]
    fn windows_udp_broadcast_rejects_malformed_packets() {
        assert!(normalize_udp_broadcast_packet(&[], &config()).is_none());

        let mut packet =
            build_udp_packet(Ipv4Addr::new(192, 168, 1, 7), Ipv4Addr::BROADCAST, b"bad");
        packet[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert!(normalize_udp_broadcast_packet(&packet, &config()).is_none());
    }

    #[test]
    fn windows_udp_broadcast_rejects_fragments() {
        let mut packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::BROADCAST,
            b"fragment",
        );
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
            ipv4_packet.set_flags(Ipv4Flags::MoreFragments);
        }

        assert!(normalize_udp_broadcast_packet(&packet, &config()).is_none());
    }

    #[test]
    fn windows_udp_broadcast_rejects_non_broadcast_destinations() {
        let packet = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 7),
            Ipv4Addr::new(192, 168, 1, 10),
            b"unicast",
        );

        assert!(normalize_udp_broadcast_packet(&packet, &config()).is_none());
    }

    #[test]
    fn windows_udp_broadcast_rejects_virtual_source_duplicates() {
        let packet = build_udp_packet(Ipv4Addr::new(10, 144, 144, 1), Ipv4Addr::BROADCAST, b"loop");

        assert!(normalize_udp_broadcast_packet(&packet, &config()).is_none());
    }

    #[test]
    fn windows_udp_broadcast_detects_directed_broadcast_from_prefix() {
        let physical =
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(172, 16, 5, 10), 20).unwrap();
        assert_eq!(physical.directed_broadcast, Ipv4Addr::new(172, 16, 15, 255));
        assert_eq!(
            prefix_len_from_netmask(Ipv4Addr::new(255, 255, 240, 0)),
            Some(20)
        );
        assert_eq!(prefix_len_from_netmask(Ipv4Addr::new(255, 0, 255, 0)), None);
    }

    #[test]
    fn windows_udp_broadcast_keeps_link_local_interfaces() {
        let physical =
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(169, 254, 13, 10), 16).unwrap();
        assert_eq!(
            physical.directed_broadcast,
            Ipv4Addr::new(169, 254, 255, 255)
        );
    }
}
