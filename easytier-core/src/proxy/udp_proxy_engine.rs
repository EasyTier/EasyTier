use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use dashmap::{DashMap, mapref::entry::Entry};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};

use crate::{
    config::PeerId,
    packet::{PacketType, ZCPacket},
};

use super::{
    cidr_table::ProxyCidrTable,
    ip_reassembler::{ComposeIpv4PacketArgs, IpReassembler, compose_ipv4_packet},
    runtime::UdpProxyRuntime,
};

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub struct UdpNatKey {
    pub src_socket: SocketAddr,
    pub dst_socket: SocketAddr,
}

impl UdpNatKey {
    pub fn new(src_socket: SocketAddr, dst_socket: SocketAddr) -> Self {
        Self {
            src_socket,
            dst_socket,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct UdpNatEntryId(uuid::Uuid);

impl UdpNatEntryId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for UdpNatEntryId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct UdpNatEntry {
    id: UdpNatEntryId,
    src_peer_id: PeerId,
    my_peer_id: PeerId,
    src_socket: SocketAddr,
    real_dst_ip: Ipv4Addr,
    mapped_dst_ip: Ipv4Addr,
    virtual_ipv4: Ipv4Addr,
    last_active_time: parking_lot::Mutex<Instant>,
    stopped: AtomicBool,
    denied: bool,
}

impl UdpNatEntry {
    fn new(
        src_peer_id: PeerId,
        my_peer_id: PeerId,
        src_socket: SocketAddr,
        real_dst_ip: Ipv4Addr,
        mapped_dst_ip: Ipv4Addr,
        virtual_ipv4: Ipv4Addr,
        denied: bool,
    ) -> Self {
        Self {
            id: UdpNatEntryId::new(),
            src_peer_id,
            my_peer_id,
            src_socket,
            real_dst_ip,
            mapped_dst_ip,
            virtual_ipv4,
            last_active_time: parking_lot::Mutex::new(Instant::now()),
            stopped: AtomicBool::new(false),
            denied,
        }
    }

    pub fn id(&self) -> UdpNatEntryId {
        self.id
    }

    pub fn is_denied(&self) -> bool {
        self.denied
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    fn mark_active(&self) {
        *self.last_active_time.lock() = Instant::now();
    }

    fn is_active(&self, ttl: Duration) -> bool {
        self.last_active_time.lock().elapsed() < ttl && !self.is_stopped()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UdpProxyPeerContext {
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub enable_exit_node: bool,
    pub no_tun: bool,
}

#[derive(Debug)]
pub enum UdpProxyAction {
    ForwardToSocket {
        entry_id: UdpNatEntryId,
        dst: SocketAddr,
        payload: Bytes,
    },
    Drop,
    Pass,
}

#[derive(Debug)]
pub struct UdpProxyEngine {
    cidr_table: Arc<ProxyCidrTable>,
    nat_table: DashMap<UdpNatKey, Arc<UdpNatEntry>>,
    nat_ids: DashMap<UdpNatEntryId, UdpNatKey>,
    ip_reassembler: IpReassembler,
    entry_ttl: Duration,
    next_ip_id: AtomicU16,
}

impl UdpProxyEngine {
    pub fn new(cidr_table: Arc<ProxyCidrTable>, fragment_timeout: Duration) -> Self {
        Self {
            cidr_table,
            nat_table: DashMap::new(),
            nat_ids: DashMap::new(),
            ip_reassembler: IpReassembler::new(fragment_timeout),
            entry_ttl: Duration::from_secs(180),
            next_ip_id: AtomicU16::new(1),
        }
    }

    pub fn entry_ids(&self) -> Vec<UdpNatEntryId> {
        self.nat_ids.iter().map(|entry| *entry.key()).collect()
    }

    pub fn remove_expired_entries(&self) -> Vec<UdpNatEntryId> {
        let mut removed = Vec::new();
        self.nat_table.retain(|_, entry| {
            if entry.is_active(self.entry_ttl) {
                true
            } else {
                tracing::info!(?entry, "udp nat table entry removed");
                entry.stop();
                self.nat_ids.remove(&entry.id());
                removed.push(entry.id());
                false
            }
        });
        self.nat_table.shrink_to_fit();
        self.nat_ids.shrink_to_fit();
        removed
    }

    pub fn remove_entry(&self, entry_id: UdpNatEntryId) {
        if let Some((_, key)) = self.nat_ids.remove(&entry_id)
            && let Some((_, entry)) = self.nat_table.remove(&key)
        {
            entry.stop();
        }
    }

    pub fn remove_expired_fragments(&self) {
        self.ip_reassembler.remove_expired_packets();
    }

    pub fn handle_peer_packet(
        &self,
        packet: &ZCPacket,
        ctx: UdpProxyPeerContext,
        runtime: &impl UdpProxyRuntime,
    ) -> UdpProxyAction {
        if self.cidr_table.is_empty() && !ctx.enable_exit_node && !ctx.no_tun {
            return UdpProxyAction::Pass;
        }

        let Some(virtual_ipv4) = ctx.virtual_ipv4 else {
            return UdpProxyAction::Pass;
        };
        let Some(hdr) = packet.peer_manager_header() else {
            return UdpProxyAction::Pass;
        };
        let is_exit_node = hdr.is_exit_node();
        if hdr.packet_type != PacketType::Data as u8 || hdr.is_no_proxy() {
            return UdpProxyAction::Pass;
        };

        let Ok(ipv4) = Ipv4Packet::new_checked(packet.payload()) else {
            return UdpProxyAction::Pass;
        };
        if ipv4.version() != 4 || ipv4.next_header() != IpProtocol::Udp {
            return UdpProxyAction::Pass;
        }

        let origin_dst_ip = ipv4.dst_addr();
        let mut real_dst_ip = origin_dst_ip;
        let no_tun_local_virtual_ip =
            ctx.no_tun && Some(origin_dst_ip) == ctx.virtual_ipv4.as_ref().copied();
        if let Some(mapped_real_ip) = self.cidr_table.lookup_v4(origin_dst_ip) {
            real_dst_ip = mapped_real_ip;
        } else if !is_exit_node && !no_tun_local_virtual_ip {
            return UdpProxyAction::Pass;
        }

        let reassembled_buf;
        let udp_packet = if IpReassembler::is_packet_fragmented(&ipv4) {
            let Some(buf) = self.ip_reassembler.add_fragment(&ipv4) else {
                return UdpProxyAction::Drop;
            };
            reassembled_buf = buf;
            let Ok(udp_packet) = UdpPacket::new_checked(reassembled_buf.as_slice()) else {
                return UdpProxyAction::Pass;
            };
            udp_packet
        } else {
            let Ok(udp_packet) = UdpPacket::new_checked(ipv4.payload()) else {
                return UdpProxyAction::Pass;
            };
            udp_packet
        };

        let dst_socket = if runtime.is_ip_local_virtual_ip(&IpAddr::V4(real_dst_ip)) {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), udp_packet.dst_port())
        } else {
            SocketAddr::new(real_dst_ip.into(), udp_packet.dst_port())
        };

        tracing::trace!(
            ?packet,
            ?ipv4,
            ?udp_packet,
            "udp nat packet request received"
        );

        let nat_key = UdpNatKey::new(
            SocketAddr::new(ipv4.src_addr().into(), udp_packet.src_port()),
            SocketAddr::new(origin_dst_ip.into(), udp_packet.dst_port()),
        );
        let deny_dst = SocketAddr::new(real_dst_ip.into(), udp_packet.dst_port());
        let nat_entry = match self.nat_table.entry(nat_key) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let denied = runtime.should_deny_udp_proxy(deny_dst);
                let nat_entry = Arc::new(UdpNatEntry::new(
                    hdr.from_peer_id.get(),
                    hdr.to_peer_id.get(),
                    nat_key.src_socket,
                    real_dst_ip,
                    origin_dst_ip,
                    virtual_ipv4,
                    denied,
                ));
                self.nat_ids.insert(nat_entry.id(), nat_key);
                tracing::info!(?packet, ?ipv4, ?udp_packet, "udp nat table entry created");
                entry.insert(nat_entry).clone()
            }
        };

        if nat_entry.is_denied() {
            tracing::debug!(
                dst_port = udp_packet.dst_port(),
                "dst socket is in running listeners, ignore it"
            );
            return UdpProxyAction::Drop;
        }

        nat_entry.mark_active();
        UdpProxyAction::ForwardToSocket {
            entry_id: nat_entry.id(),
            dst: dst_socket,
            payload: Bytes::copy_from_slice(udp_packet.payload()),
        }
    }

    pub fn handle_socket_response(
        &self,
        entry_id: UdpNatEntryId,
        src_socket: SocketAddr,
        payload: &[u8],
        ipv4_mtu: usize,
    ) -> anyhow::Result<Vec<ZCPacket>> {
        let Some(key) = self.nat_ids.get(&entry_id).map(|entry| *entry.value()) else {
            return Ok(Vec::new());
        };
        let Some(entry) = self.nat_table.get(&key).map(|entry| entry.clone()) else {
            return Ok(Vec::new());
        };
        entry.mark_active();

        let SocketAddr::V4(mut src_v4) = src_socket else {
            return Ok(Vec::new());
        };
        let SocketAddr::V4(nat_src_v4) = entry.src_socket else {
            return Ok(Vec::new());
        };

        let has_mapped_dst = entry.real_dst_ip != entry.mapped_dst_ip;
        let mut reply_src_ip = *src_v4.ip();
        if has_mapped_dst && reply_src_ip == entry.real_dst_ip {
            reply_src_ip = entry.mapped_dst_ip;
        } else if reply_src_ip.is_loopback() {
            reply_src_ip = entry.virtual_ipv4;
        }
        if has_mapped_dst && reply_src_ip == entry.real_dst_ip {
            reply_src_ip = entry.mapped_dst_ip;
        }
        src_v4.set_ip(reply_src_ip);

        let payload_mtu = ipv4_mtu
            .saturating_sub(smoltcp::wire::IPV4_HEADER_LEN)
            .max(8);
        let payload_mtu = payload_mtu - (payload_mtu % 8);
        let ip_id = self.next_ip_id.fetch_add(1, Ordering::Relaxed);
        compose_udp_ipv4_response(&entry, &src_v4, &nat_src_v4, payload, payload_mtu, ip_id)
    }
}

fn compose_udp_ipv4_response(
    entry: &UdpNatEntry,
    src_v4: &SocketAddrV4,
    nat_src_v4: &SocketAddrV4,
    payload: &[u8],
    payload_mtu: usize,
    ip_id: u16,
) -> anyhow::Result<Vec<ZCPacket>> {
    assert_eq!(0, payload_mtu % 8);

    let mut buf =
        vec![0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::UDP_HEADER_LEN + payload.len()];
    let udp_start = smoltcp::wire::IPV4_HEADER_LEN;
    let udp_len = smoltcp::wire::UDP_HEADER_LEN + payload.len();
    {
        let mut udp_packet = UdpPacket::new_unchecked(&mut buf[udp_start..udp_start + udp_len]);
        udp_packet.set_src_port(src_v4.port());
        udp_packet.set_dst_port(nat_src_v4.port());
        udp_packet.set_len(udp_len as u16);
        udp_packet.payload_mut().copy_from_slice(payload);
        udp_packet.fill_checksum(
            &IpAddress::Ipv4(*src_v4.ip()),
            &IpAddress::Ipv4(*nat_src_v4.ip()),
        );
    }

    let mut packets = Vec::new();
    compose_ipv4_packet(
        ComposeIpv4PacketArgs {
            buf: &mut buf,
            src_v4: src_v4.ip(),
            dst_v4: nat_src_v4.ip(),
            next_protocol: IpProtocol::Udp,
            payload_len: udp_len,
            payload_mtu,
            ip_id,
        },
        |buf| {
            let mut packet = ZCPacket::new_with_payload(buf);
            packet.fill_peer_manager_hdr(
                entry.my_peer_id,
                entry.src_peer_id,
                PacketType::Data as u8,
            );
            packet
                .mut_peer_manager_header()
                .expect("peer manager header")
                .set_no_proxy(true);
            packets.push(packet);
            Ok(())
        },
    )?;

    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{
        cidr_table::{ProxyCidrRule, ProxyCidrSnapshot},
        runtime::{
            ProxyRuntimeError, ProxyRuntimeInfo, ProxyRuntimeSnapshot, UdpProxyResponseSink,
        },
    };

    struct TestRuntime;

    impl ProxyRuntimeInfo for TestRuntime {
        fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
            ProxyRuntimeSnapshot::default()
        }

        fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
            matches!(ip, IpAddr::V4(ip) if *ip == Ipv4Addr::new(10, 144, 144, 204))
        }
    }

    #[async_trait::async_trait]
    impl UdpProxyRuntime for TestRuntime {
        fn should_deny_udp_proxy(&self, _dst_socket: SocketAddr) -> bool {
            false
        }

        fn udp_response_ipv4_mtu(&self) -> usize {
            1280
        }

        async fn send_udp_to_socket(
            &self,
            _entry_id: UdpNatEntryId,
            _dst: SocketAddr,
            _payload: bytes::Bytes,
            _response_sink: std::sync::Weak<dyn UdpProxyResponseSink>,
        ) -> Result<(), ProxyRuntimeError> {
            Ok(())
        }

        fn close_udp_socket(&self, _entry_id: UdpNatEntryId) {}
    }

    #[test]
    fn socket_response_uses_mapped_source_for_mapped_destination() {
        let table = Arc::new(ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "10.144.144.204/32".parse().unwrap(),
                mapped_cidr: Some("10.10.10.3/32".parse().unwrap()),
            }],
        }));
        let engine = UdpProxyEngine::new(table, Duration::from_secs(10));

        let mut request =
            vec![0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::UDP_HEADER_LEN + 7];
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(&mut request);
            ipv4.set_version(4);
            ipv4.set_header_len(smoltcp::wire::IPV4_HEADER_LEN as u8);
            ipv4.set_total_len(
                (smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::UDP_HEADER_LEN + 7) as u16,
            );
            ipv4.set_hop_limit(64);
            ipv4.set_next_header(IpProtocol::Udp);
            ipv4.set_src_addr("10.144.144.206".parse().unwrap());
            ipv4.set_dst_addr("10.10.10.3".parse().unwrap());
            ipv4.fill_checksum();
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut request[smoltcp::wire::IPV4_HEADER_LEN..]);
            udp.set_src_port(53864);
            udp.set_dst_port(12345);
            udp.set_len((smoltcp::wire::UDP_HEADER_LEN + 7) as u16);
            udp.payload_mut().copy_from_slice(b"request");
            udp.fill_checksum(
                &IpAddress::Ipv4("10.144.144.206".parse().unwrap()),
                &IpAddress::Ipv4("10.10.10.3".parse().unwrap()),
            );
        }

        let mut zc = ZCPacket::new_with_payload(&request);
        zc.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

        let action = engine.handle_peer_packet(
            &zc,
            UdpProxyPeerContext {
                virtual_ipv4: Some("10.144.144.204".parse().unwrap()),
                enable_exit_node: false,
                no_tun: false,
            },
            &TestRuntime,
        );
        let UdpProxyAction::ForwardToSocket { entry_id, .. } = action else {
            panic!("expected forward action");
        };

        let packets = engine
            .handle_socket_response(entry_id, "127.0.0.1:12345".parse().unwrap(), b"reply", 1280)
            .unwrap();
        assert_eq!(packets.len(), 1);
        let ipv4 = Ipv4Packet::new_checked(packets[0].payload()).unwrap();
        assert_eq!(ipv4.src_addr(), Ipv4Addr::new(10, 10, 10, 3));
        assert_eq!(ipv4.dst_addr(), Ipv4Addr::new(10, 144, 144, 206));
        let udp = UdpPacket::new_checked(ipv4.payload()).unwrap();
        assert_eq!(udp.src_port(), 12345);
        assert_eq!(udp.dst_port(), 53864);
        assert_eq!(udp.payload(), b"reply");
    }
}
