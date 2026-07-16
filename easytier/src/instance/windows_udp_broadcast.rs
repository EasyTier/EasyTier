use std::net::Ipv4Addr;

use cidr::Ipv4Inet;
use easytier_core::packet::udp_broadcast::{
    BroadcastRelayConfig, NormalizedPacket, PhysicalInterface, UdpBroadcastPacketRejection,
    UdpPacketSummary, normalize_udp_broadcast_packet,
};

#[cfg(any(windows, test))]
use {
    crate::{
        common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        instance::composition::NativeCoreInstance,
    },
    anyhow::Context,
    easytier_core::instance::UdpBroadcastRelayStats,
    network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig},
    socket2::{Domain, Protocol, SockAddr, Socket, Type},
    std::{
        io,
        net::{SocketAddrV4, UdpSocket as StdUdpSocket},
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

fn log_ignored_udp_packet(packet: &[u8], rejection: UdpBroadcastPacketRejection) {
    let reason = rejection.reason();
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

fn log_normalized_udp_packet(
    packet: &[u8],
    config: &BroadcastRelayConfig,
    normalized: &NormalizedPacket,
) {
    let Some(summary) = UdpPacketSummary::parse(packet) else {
        return;
    };

    tracing::debug!(
        src = %summary.src,
        dst = %summary.dst,
        src_port = summary.src_port,
        dst_port = summary.dst_port,
        ip_len = summary.ip_len,
        udp_len = summary.udp_len,
        payload_len = summary.payload_len,
        normalized_src = %config.virtual_ipv4().address(),
        normalized_dst = %normalized.destination,
        "normalized Windows UDP broadcast packet"
    );
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
        for addr in iface.addr {
            let Addr::V4(v4) = addr else {
                continue;
            };
            let physical = match PhysicalInterface::from_observation(
                v4.ip,
                v4.netmask,
                iface.internal,
                virtual_ipv4.address(),
            ) {
                Ok(Some(physical)) => physical,
                Ok(None) => continue,
                Err(non_contiguous) => {
                    tracing::debug!(
                        iface = %iface.name,
                        ip = %v4.ip,
                        mask = %non_contiguous.netmask(),
                        "ignoring interface with non-contiguous IPv4 netmask"
                    );
                    continue;
                }
            };
            ret.push(physical);
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
        if !src_addrs.contains(&iface.address()) {
            src_addrs.push(iface.address());
        }
        if !directed_broadcasts.contains(&iface.directed_broadcast()) {
            directed_broadcasts.push(iface.directed_broadcast());
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
        let filter = build_windivert_udp_filter(config.physical_interfaces());
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
    global_ctx: &ArcGlobalCtx,
    capture_backend: Option<&str>,
    error: Option<String>,
) {
    global_ctx.issue_event(GlobalCtxEvent::UdpBroadcastRelayStartResult {
        capture_backend: capture_backend.map(str::to_owned),
        error,
    });
}

#[cfg(any(windows, test))]
async fn forward_normalized_packet(
    core_instance: &NativeCoreInstance,
    normalized: NormalizedPacket,
    stats: &UdpBroadcastRelayStats,
) {
    let ret = core_instance
        .send_local_ip_packet(normalized.packet.clone())
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
    core_instance: Arc<NativeCoreInstance>,
    config: BroadcastRelayConfig,
    mut socket: CaptureSocket,
    stats: UdpBroadcastRelayStats,
) {
    let mut capture_backend = socket.backend_name();

    loop {
        let normalized = match socket.recv().await {
            Ok(packet) => {
                stats.record_captured();
                if tracing::enabled!(tracing::Level::DEBUG) {
                    log_captured_udp_packet(packet);
                }
                let normalized = match normalize_udp_broadcast_packet(packet, &config) {
                    Ok(normalized) => {
                        if tracing::enabled!(tracing::Level::DEBUG) {
                            log_normalized_udp_packet(packet, &config, &normalized);
                        }
                        Some(normalized)
                    }
                    Err(rejection) => {
                        if tracing::enabled!(tracing::Level::DEBUG) {
                            log_ignored_udp_packet(packet, rejection);
                        }
                        None
                    }
                };
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
            forward_normalized_packet(&core_instance, normalized, &stats).await;
        }
    }
}

#[cfg(any(windows, test))]
pub(crate) fn start(
    core_instance: Arc<NativeCoreInstance>,
    global_ctx: ArcGlobalCtx,
    virtual_ipv4: Ipv4Inet,
) -> anyhow::Result<AbortOnDropHandle<()>> {
    let physical_interfaces = match collect_physical_interfaces(virtual_ipv4) {
        Ok(interfaces) => interfaces,
        Err(err) => {
            issue_start_result_event(&global_ctx, None, Some(format!("{err:#}")));
            return Err(err);
        }
    };
    let config = BroadcastRelayConfig::new(virtual_ipv4, physical_interfaces);
    if config.physical_interfaces().is_empty() {
        let msg = "no physical IPv4 interface is available for UDP broadcast relay";
        issue_start_result_event(&global_ctx, None, Some(msg.to_owned()));
        anyhow::bail!(msg);
    }

    let socket = match open_capture_socket(&config) {
        Ok(socket) => socket,
        Err(err) => {
            issue_start_result_event(&global_ctx, None, Some(format!("{err:#}")));
            return Err(err);
        }
    };
    let capture_backend = socket.backend_name();
    issue_start_result_event(&global_ctx, Some(capture_backend), None);

    tracing::debug!(
        virtual_ipv4 = %config.virtual_ipv4(),
        physical_interfaces = ?config.physical_interfaces(),
        capture_backend,
        "starting Windows UDP broadcast relay"
    );

    let stats = core_instance.udp_broadcast_relay_stats();
    let task = tokio::spawn(capture_loop(core_instance, config, socket, stats));
    Ok(AbortOnDropHandle::new(task))
}

#[cfg(test)]
mod tests {
    use super::*;

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
