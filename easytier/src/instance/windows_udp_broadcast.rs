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
        common::global_ctx::GlobalCtxEvent,
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

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
use windivert::{
    WinDivert,
    error::WinDivertError,
    layer,
    packet::WinDivertPacket,
    prelude::{WinDivertFlags, WinDivertShutdownMode},
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
            "captured Windows UDP broadcast candidate"
        );
    } else {
        tracing::debug!(
            packet_len = packet.len(),
            "captured malformed Windows UDP broadcast candidate"
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
fn join_addr_equals(field: &str, addrs: &[Ipv4Addr]) -> String {
    addrs
        .iter()
        .map(|addr| format!("{field} == {addr}"))
        .collect::<Vec<_>>()
        .join(" or ")
}

#[cfg(any(windows, test))]
fn build_windivert_udp_filter(physical_interfaces: &[PhysicalInterface]) -> String {
    let mut src_addrs = Vec::new();
    let mut directed_broadcasts = Vec::new();

    for iface in physical_interfaces {
        if !src_addrs.contains(&iface.addr) {
            src_addrs.push(iface.addr);
        }
        if !directed_broadcasts.contains(&iface.directed_broadcast) {
            directed_broadcasts.push(iface.directed_broadcast);
        }
    }

    if src_addrs.is_empty() {
        return "false".to_owned();
    }

    let src_filter = join_addr_equals("ip.SrcAddr", &src_addrs);
    let mut dst_filters = vec!["ip.DstAddr == 255.255.255.255".to_owned()];
    if !directed_broadcasts.is_empty() {
        dst_filters.push(join_addr_equals("ip.DstAddr", &directed_broadcasts));
    }
    dst_filters.push("(ip.DstAddr >= 224.0.0.0 and ip.DstAddr <= 239.255.255.255)".to_owned());

    format!(
        "outbound and ip and udp and ({}) and ({})",
        src_filter,
        dst_filters.join(" or ")
    )
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

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
struct WinDivertCaptureReader {
    inner: std::cell::UnsafeCell<WinDivert<layer::NetworkLayer>>,
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
unsafe impl Send for WinDivertCaptureReader {}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
unsafe impl Sync for WinDivertCaptureReader {}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
impl WinDivertCaptureReader {
    fn new(inner: WinDivert<layer::NetworkLayer>) -> Self {
        Self {
            inner: std::cell::UnsafeCell::new(inner),
        }
    }

    fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::NetworkLayer>, WinDivertError> {
        let inner = unsafe { &*self.inner.get() };
        inner.recv(buffer)
    }

    fn shutdown(&self) -> anyhow::Result<()> {
        let inner = unsafe { &mut *self.inner.get() };
        inner
            .shutdown(WinDivertShutdownMode::Recv)
            .with_context(|| "WinDivert UDP broadcast capture shutdown failed")?;
        Ok(())
    }

    fn close(&self) -> anyhow::Result<()> {
        let inner = unsafe { &mut *self.inner.get() };
        inner
            .close(windivert::CloseAction::Nothing)
            .with_context(|| "WinDivert UDP broadcast capture close failed")?;
        Ok(())
    }
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
impl Drop for WinDivertCaptureReader {
    fn drop(&mut self) {
        if let Err(err) = self.close() {
            tracing::error!(?err, "WinDivert UDP broadcast capture close failed");
        }
    }
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
struct WinDivertCaptureSocket {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reader: Arc<WinDivertCaptureReader>,
    buf: Vec<u8>,
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
impl WinDivertCaptureSocket {
    const CHANNEL_CAPACITY: usize = 1024;
    const MAX_PACKET_LEN: usize = 65_535;

    fn open(config: &BroadcastRelayConfig) -> anyhow::Result<Self> {
        let filter = build_windivert_udp_filter(&config.physical_interfaces);
        tracing::debug!(
            filter = %filter,
            "opening WinDivert UDP broadcast capture backend"
        );

        let flags = WinDivertFlags::default().set_sniff();
        let reader = WinDivert::network(&filter, 0, flags)
            .map_err(io::Error::other)
            .with_context(|| "failed to open WinDivert UDP broadcast capture")?;
        let reader = Arc::new(WinDivertCaptureReader::new(reader));
        let reader_clone = reader.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(Self::CHANNEL_CAPACITY);

        std::thread::Builder::new()
            .name("easytier-udp-broadcast-windivert".to_owned())
            .spawn(move || {
                let mut buffer = vec![0; Self::MAX_PACKET_LEN];
                loop {
                    match reader_clone.recv(Some(&mut buffer)) {
                        Ok(packet) => {
                            if tx.blocking_send(packet.data.to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::warn!(?err, "WinDivert UDP broadcast capture receive failed");
                            break;
                        }
                    }
                }
            })
            .with_context(|| "failed to spawn WinDivert UDP broadcast capture thread")?;

        Ok(Self {
            rx,
            reader,
            buf: Vec::new(),
        })
    }

    async fn recv(&mut self) -> io::Result<&[u8]> {
        self.buf = self.rx.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WinDivert UDP broadcast capture stopped",
            )
        })?;
        Ok(&self.buf)
    }
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
impl Drop for WinDivertCaptureSocket {
    fn drop(&mut self) {
        if let Err(err) = self.reader.shutdown() {
            tracing::debug!(?err, "WinDivert UDP broadcast capture shutdown failed");
        }
    }
}

#[cfg(any(windows, test))]
enum CaptureSocket {
    Raw(RawUdpCaptureSocket),
    #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
    WinDivert(WinDivertCaptureSocket),
}

#[cfg(any(windows, test))]
impl CaptureSocket {
    async fn recv(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Raw(socket) => socket.recv().await,
            #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
            Self::WinDivert(socket) => socket.recv().await,
        }
    }

    fn backend_name(&self) -> &'static str {
        match self {
            Self::Raw(_) => "raw_socket",
            #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
            Self::WinDivert(_) => "windivert",
        }
    }

    fn fallback_to_raw(&mut self) -> anyhow::Result<bool> {
        #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
        {
            if matches!(self, Self::WinDivert(_)) {
                *self = Self::Raw(RawUdpCaptureSocket::open()?);
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
fn open_capture_socket(config: &BroadcastRelayConfig) -> anyhow::Result<CaptureSocket> {
    match WinDivertCaptureSocket::open(config) {
        Ok(socket) => Ok(CaptureSocket::WinDivert(socket)),
        Err(err) => {
            tracing::warn!(
                ?err,
                "WinDivert UDP broadcast capture unavailable; falling back to raw socket"
            );
            RawUdpCaptureSocket::open().map(CaptureSocket::Raw)
        }
    }
}

#[cfg(all(
    any(windows, test),
    not(all(windows, any(target_arch = "x86_64", target_arch = "x86")))
))]
fn open_capture_socket(_config: &BroadcastRelayConfig) -> anyhow::Result<CaptureSocket> {
    RawUdpCaptureSocket::open().map(CaptureSocket::Raw)
}

#[cfg(any(windows, test))]
fn issue_start_result_event(
    peer_manager: &PeerManager,
    capture_backend: Option<&str>,
    error: Option<String>,
) {
    peer_manager
        .get_global_ctx()
        .issue_event(GlobalCtxEvent::UdpBroadcastRelayStartResult {
            capture_backend: capture_backend.map(str::to_owned),
            error,
        });
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
    mut socket: CaptureSocket,
    stats: BroadcastRelayStats,
) {
    let mut capture_backend = socket.backend_name();

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
                tracing::warn!(
                    ?err,
                    capture_backend,
                    "Windows UDP broadcast capture receive failed"
                );
                match socket.fallback_to_raw() {
                    Ok(true) => {
                        let old_backend = capture_backend;
                        capture_backend = socket.backend_name();
                        tracing::warn!(
                            old_backend,
                            new_backend = capture_backend,
                            "Windows UDP broadcast capture backend fell back"
                        );
                    }
                    Ok(false) => {}
                    Err(fallback_err) => {
                        tracing::error!(
                            ?fallback_err,
                            "Windows UDP broadcast raw socket fallback failed; stopping relay"
                        );
                        break;
                    }
                }
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
    let physical_interfaces = match collect_physical_interfaces(virtual_ipv4) {
        Ok(interfaces) => interfaces,
        Err(err) => {
            issue_start_result_event(&peer_manager, None, Some(format!("{err:#}")));
            return Err(err);
        }
    };
    if physical_interfaces.is_empty() {
        let msg = "no physical IPv4 interface is available for UDP broadcast relay";
        issue_start_result_event(&peer_manager, None, Some(msg.to_owned()));
        anyhow::bail!(msg);
    }

    let config = BroadcastRelayConfig::new(virtual_ipv4, physical_interfaces);
    let socket = match open_capture_socket(&config) {
        Ok(socket) => socket,
        Err(err) => {
            issue_start_result_event(&peer_manager, None, Some(format!("{err:#}")));
            return Err(err);
        }
    };
    let capture_backend = socket.backend_name();
    issue_start_result_event(&peer_manager, Some(capture_backend), None);

    tracing::debug!(
        virtual_ipv4 = %config.virtual_ipv4,
        physical_interfaces = ?config.physical_interfaces,
        capture_backend,
        "starting Windows UDP broadcast relay"
    );

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

    #[test]
    fn windows_udp_broadcast_windivert_filter_is_constrained() {
        let interfaces = vec![
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(192, 168, 1, 7), 24).unwrap(),
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(169, 254, 13, 10), 16).unwrap(),
            PhysicalInterface::from_ip_and_prefix(Ipv4Addr::new(169, 254, 156, 121), 16).unwrap(),
        ];

        let filter = build_windivert_udp_filter(&interfaces);

        assert!(filter.starts_with("outbound and ip and udp and "));
        assert!(filter.contains("ip.SrcAddr == 192.168.1.7"));
        assert!(filter.contains("ip.SrcAddr == 169.254.13.10"));
        assert!(filter.contains("ip.DstAddr == 255.255.255.255"));
        assert!(filter.contains("ip.DstAddr == 192.168.1.255"));
        assert!(filter.contains("ip.DstAddr == 169.254.255.255"));
        assert!(filter.contains("ip.DstAddr >= 224.0.0.0"));
        assert!(filter.contains("ip.DstAddr <= 239.255.255.255"));
        assert_eq!(filter.matches("ip.DstAddr == 169.254.255.255").count(), 1);
    }
}
