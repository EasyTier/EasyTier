use std::net::Ipv4Addr;

use cidr::Ipv4Inet;
use easytier_core::gateway::udp_broadcast::PhysicalInterface;
use easytier_core::gateway::udp_broadcast::{
    BroadcastRelayConfig, NormalizedPacket, UdpBroadcastPacketRejection, UdpPacketSummary,
    normalize_udp_broadcast_packet,
};

use {
    crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    anyhow::Context,
    easytier_core::{gateway::udp_broadcast::UdpBroadcastRelayStats, instance::CorePacketPlane},
    network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig},
    socket2::{Domain, Protocol, SockAddr, Socket, Type},
    std::{
        io,
        net::{SocketAddrV4, UdpSocket as StdUdpSocket},
        sync::Arc,
    },
    tokio_util::task::AbortOnDropHandle,
};

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
#[path = "capture_raw.rs"]
mod capture;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[path = "capture_windivert.rs"]
mod capture;

use capture::{CaptureSocket, open_capture_socket};

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

fn open_raw_udp_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    // Match ubihazard/broadcast: use one raw UDP listener on loopback, then
    // inspect the IPv4 header to identify the real physical source interface.
    socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn socket2_into_udp_socket(socket: Socket) -> StdUdpSocket {
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};

    // The raw socket handle came from socket2 and is transferred exactly once.
    unsafe { StdUdpSocket::from_raw_socket(socket.into_raw_socket()) }
}

struct RawUdpCaptureSocket {
    socket: tokio::net::UdpSocket,
    buf: Vec<u8>,
}

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

async fn forward_normalized_packet(
    packet_plane: &CorePacketPlane,
    normalized: NormalizedPacket,
    stats: &UdpBroadcastRelayStats,
) {
    let ret = packet_plane
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

async fn capture_loop(
    packet_plane: Arc<CorePacketPlane>,
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
            forward_normalized_packet(&packet_plane, normalized, &stats).await;
        }
    }
}

pub(crate) fn start(
    packet_plane: Arc<CorePacketPlane>,
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

    let stats = packet_plane.udp_broadcast_relay_stats();
    let task = tokio::spawn(capture_loop(packet_plane, config, socket, stats));
    Ok(AbortOnDropHandle::new(task))
}
