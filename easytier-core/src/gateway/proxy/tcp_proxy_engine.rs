use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cidr::Ipv4Inet;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket};

use crate::packet::{PacketType, ZCPacket};

use super::cidr_table::ProxyCidrTable;

pub(crate) type TcpNatEntryId = uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpProxyMode {
    Tcp,
    KcpSrc,
    QuicSrc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpNatEntryState {
    SynReceived,
    ConnectingDst,
    Connected,
    ClosingSrc,
    ClosingDst,
    Closed,
}

#[derive(Debug, Clone)]
pub struct TcpNatEntrySnapshot {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub mapped_dst: SocketAddr,
    pub start_time: u64,
    pub state: TcpNatEntryState,
}

#[derive(Debug)]
pub(crate) struct TcpNatEntry {
    id: TcpNatEntryId,
    src: SocketAddr,
    real_dst: SocketAddr,
    mapped_dst: SocketAddr,
    start_time: Instant,
    start_time_unix_secs: u64,
    state: AtomicCell<TcpNatEntryState>,
}

impl TcpNatEntry {
    fn new(src: SocketAddr, real_dst: SocketAddr, mapped_dst: SocketAddr) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            src,
            real_dst,
            mapped_dst,
            start_time: Instant::now(),
            start_time_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default(),
            state: AtomicCell::new(TcpNatEntryState::SynReceived),
        }
    }

    pub fn id(&self) -> TcpNatEntryId {
        self.id
    }

    pub fn src(&self) -> SocketAddr {
        self.src
    }

    pub fn real_dst(&self) -> SocketAddr {
        self.real_dst
    }

    pub fn mapped_dst(&self) -> SocketAddr {
        self.mapped_dst
    }

    pub fn state(&self) -> TcpNatEntryState {
        self.state.load()
    }

    pub fn set_state(&self, state: TcpNatEntryState) {
        self.state.store(state);
    }

    fn snapshot(&self) -> TcpNatEntrySnapshot {
        TcpNatEntrySnapshot {
            src: self.src,
            dst: self.real_dst,
            mapped_dst: self.mapped_dst,
            start_time: self.start_time_unix_secs,
            state: self.state(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpProxyPeerContext {
    pub local_inet: Option<Ipv4Inet>,
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub local_port: u16,
    pub enable_exit_node: bool,
    pub no_tun: bool,
    pub smoltcp_enabled: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpProxyNicContext {
    pub local_inet: Option<Ipv4Inet>,
    pub local_port: u16,
    pub my_peer_id: u32,
    pub smoltcp_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpProxyPacketAction {
    Handled { new_syn: bool },
    Pass,
}

#[derive(Debug)]
pub(crate) struct TcpProxyEngine {
    cidr_table: Arc<ProxyCidrTable>,
    local_port: AtomicU16,
    syn_map: DashMap<SocketAddr, Arc<TcpNatEntry>>,
    conn_map: DashMap<uuid::Uuid, Arc<TcpNatEntry>>,
    addr_conn_map: DashMap<SocketAddr, Arc<TcpNatEntry>>,
}

impl TcpProxyEngine {
    pub fn new(cidr_table: Arc<ProxyCidrTable>) -> Self {
        Self {
            cidr_table,
            local_port: AtomicU16::new(0),
            syn_map: DashMap::new(),
            conn_map: DashMap::new(),
            addr_conn_map: DashMap::new(),
        }
    }

    pub fn set_local_port(&self, port: u16) {
        self.local_port.store(port, Ordering::Relaxed);
    }

    pub fn local_port(&self) -> u16 {
        self.local_port.load(Ordering::Relaxed)
    }

    pub fn check_packet_from_peer_fast(
        &self,
        mode: TcpProxyMode,
        ctx: &TcpProxyPeerContext,
    ) -> bool {
        match mode {
            TcpProxyMode::Tcp => !self.cidr_table.is_empty() || ctx.enable_exit_node || ctx.no_tun,
            TcpProxyMode::KcpSrc | TcpProxyMode::QuicSrc => true,
        }
    }

    pub fn try_handle_peer_packet(
        &self,
        mode: TcpProxyMode,
        packet: &mut ZCPacket,
        ctx: TcpProxyPeerContext,
    ) -> TcpProxyPacketAction {
        if !self.check_packet_from_peer_fast(mode, &ctx) {
            return TcpProxyPacketAction::Pass;
        }

        let Some(local_inet) = ctx.local_inet else {
            return TcpProxyPacketAction::Pass;
        };
        let local_ip = local_inet.address();
        let Some(hdr) = packet.peer_manager_header() else {
            return TcpProxyPacketAction::Pass;
        };
        if hdr.is_no_proxy() {
            return TcpProxyPacketAction::Pass;
        }

        let allowed_packet_type = match mode {
            TcpProxyMode::Tcp => hdr.packet_type == PacketType::Data as u8,
            TcpProxyMode::KcpSrc => {
                hdr.packet_type == PacketType::DataWithKcpSrcModified as u8
                    && hdr.from_peer_id == hdr.to_peer_id
            }
            TcpProxyMode::QuicSrc => {
                hdr.packet_type == PacketType::DataWithQuicSrcModified as u8
                    && hdr.from_peer_id == hdr.to_peer_id
            }
        };
        if !allowed_packet_type {
            return TcpProxyPacketAction::Pass;
        }

        let Ok(ip_packet) = Ipv4Packet::new_checked(packet.payload()) else {
            return TcpProxyPacketAction::Pass;
        };
        if ip_packet.version() != 4 || ip_packet.next_header() != IpProtocol::Tcp {
            return TcpProxyPacketAction::Pass;
        }
        let origin_ip = ip_packet.dst_addr();

        let Some(real_dst_ip) =
            self.real_dst_ip_for_mode(mode, origin_ip, hdr.is_exit_node(), &ctx)
        else {
            return TcpProxyPacketAction::Pass;
        };

        let hdr = packet
            .mut_peer_manager_header()
            .expect("peer manager header");
        hdr.packet_type = PacketType::Data as u8;

        let payload_bytes = packet.mut_payload();
        let ip_packet = Ipv4Packet::new_checked(&payload_bytes[..]).expect("checked ipv4 packet");
        let tcp_packet = TcpPacket::new_checked(ip_packet.payload()).expect("checked tcp packet");

        let source_ip = ip_packet.src_addr();
        let source_port = tcp_packet.src_port();
        let src = SocketAddr::V4(SocketAddrV4::new(source_ip, source_port));

        let mut new_syn = false;
        if tcp_packet.syn() && !tcp_packet.ack() {
            let dest_ip = ip_packet.dst_addr();
            let dest_port = tcp_packet.dst_port();
            let mapped_dst = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));
            let real_dst = SocketAddr::V4(SocketAddrV4::new(real_dst_ip, dest_port));

            let old_val = self
                .syn_map
                .insert(src, Arc::new(TcpNatEntry::new(src, real_dst, mapped_dst)));
            tracing::info!(
                ?src,
                ?real_dst,
                ?mapped_dst,
                old_entry = ?old_val,
                "tcp syn received"
            );
            new_syn = true;
        } else if !self.addr_conn_map.contains_key(&src) && !self.syn_map.contains_key(&src) {
            return TcpProxyPacketAction::Pass;
        }

        let mut ip_packet = Ipv4Packet::new_checked(payload_bytes).expect("checked ipv4 packet");
        if !ctx.smoltcp_enabled && source_ip == local_ip {
            ip_packet.set_src_addr(Self::fake_local_ipv4(&local_inet));
        }
        ip_packet.set_dst_addr(local_ip);
        let source = ip_packet.src_addr();
        {
            let mut tcp_packet =
                TcpPacket::new_checked(ip_packet.payload_mut()).expect("checked tcp packet");
            tcp_packet.set_dst_port(ctx.local_port);
            tcp_packet.fill_checksum(&IpAddress::Ipv4(source), &IpAddress::Ipv4(local_ip));
        }
        ip_packet.fill_checksum();

        tracing::trace!(?source, ?local_ip, ?packet, "tcp packet after modified");
        TcpProxyPacketAction::Handled { new_syn }
    }

    pub fn try_process_packet_from_nic(
        &self,
        zc_packet: &mut ZCPacket,
        ctx: TcpProxyNicContext,
    ) -> bool {
        let Some(local_inet) = ctx.local_inet else {
            return false;
        };
        let local_ip = local_inet.address();

        let data = zc_packet.payload();
        let Ok(ip_packet) = Ipv4Packet::new_checked(data) else {
            return false;
        };
        if ip_packet.version() != 4
            || ip_packet.src_addr() != local_ip
            || ip_packet.next_header() != IpProtocol::Tcp
        {
            return false;
        }

        let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) else {
            return false;
        };
        if tcp_packet.src_port() != ctx.local_port {
            return false;
        }

        let mut dst_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.dst_addr(),
            tcp_packet.dst_port(),
        ));
        let mut need_transform_dst = false;

        if !ctx.smoltcp_enabled && dst_addr.ip() == Self::fake_local_ipv4(&local_inet) {
            dst_addr.set_ip(IpAddr::V4(local_ip));
            need_transform_dst = true;
        }

        tracing::trace!(?dst_addr, "tcp packet try find entry");
        let entry = if let Some(entry) = self.addr_conn_map.get(&dst_addr) {
            entry.clone()
        } else {
            let Some(syn_entry) = self.syn_map.get(&dst_addr) else {
                return false;
            };
            syn_entry.clone()
        };
        assert_eq!(entry.src, dst_addr);

        let IpAddr::V4(mapped_dst_ip) = entry.mapped_dst.ip() else {
            panic!("v4 nat entry src ip is not v4");
        };

        let hdr = zc_packet
            .mut_peer_manager_header()
            .expect("peer manager header");
        hdr.set_no_proxy(true);
        if need_transform_dst {
            hdr.to_peer_id = ctx.my_peer_id.into();
        }

        let mut ip_packet =
            Ipv4Packet::new_checked(zc_packet.mut_payload()).expect("checked ipv4 packet");
        ip_packet.set_src_addr(mapped_dst_ip);
        if need_transform_dst {
            ip_packet.set_dst_addr(local_ip);
        }
        let dst = ip_packet.dst_addr();

        {
            let mut tcp_packet =
                TcpPacket::new_checked(ip_packet.payload_mut()).expect("checked tcp packet");
            tcp_packet.set_src_port(entry.real_dst.port());
            tcp_packet.fill_checksum(&IpAddress::Ipv4(mapped_dst_ip), &IpAddress::Ipv4(dst));
        }
        ip_packet.fill_checksum();

        tracing::trace!(?dst_addr, nat_entry = ?entry, packet = ?ip_packet, "tcp packet after modified");
        true
    }

    pub fn accept_connection(
        &self,
        mut socket_addr: SocketAddr,
        virtual_inet: Option<Ipv4Inet>,
    ) -> Option<Arc<TcpNatEntry>> {
        if let Some(my_ip_inet) = virtual_inet {
            let my_ip = my_ip_inet.address();
            if socket_addr.ip() == Self::fake_local_ipv4(&my_ip_inet) {
                socket_addr.set_ip(IpAddr::V4(my_ip));
            }
        }

        let (_, entry) = self.syn_map.remove(&socket_addr)?;
        if entry.state() != TcpNatEntryState::SynReceived {
            return None;
        }

        entry.set_state(TcpNatEntryState::ConnectingDst);
        self.addr_conn_map.insert(entry.src, entry.clone());
        let old_nat_val = self.conn_map.insert(entry.id, entry.clone());
        assert!(old_nat_val.is_none());
        Some(entry)
    }

    pub fn remove_entry(&self, entry_id: TcpNatEntryId) {
        let Some((_, entry)) = self.conn_map.remove(&entry_id) else {
            return;
        };
        self.addr_conn_map
            .remove_if(&entry.src, |_, current| current.id == entry.id);
        if self.conn_map.capacity() - self.conn_map.len() > 16 {
            self.conn_map.shrink_to_fit();
        }
        if self.addr_conn_map.capacity() - self.addr_conn_map.len() > 16 {
            self.addr_conn_map.shrink_to_fit();
        }
    }

    pub fn cleanup_expired_syn(&self, timeout: Duration) {
        self.syn_map.retain(|_, entry| {
            if entry.start_time.elapsed() > timeout {
                tracing::warn!(?entry, "syn nat entry expired");
                entry.set_state(TcpNatEntryState::Closed);
                false
            } else {
                true
            }
        });
        self.syn_map.shrink_to_fit();
    }

    pub fn is_tcp_proxy_connection(&self, src: SocketAddr) -> bool {
        self.syn_map.contains_key(&src) || self.addr_conn_map.contains_key(&src)
    }

    pub fn list_entries(&self) -> Vec<TcpNatEntrySnapshot> {
        let mut entries = Vec::new();
        for entry in self.syn_map.iter() {
            entries.push(entry.value().snapshot());
        }
        for entry in self.conn_map.iter() {
            entries.push(entry.value().snapshot());
        }
        entries
    }

    pub fn fake_local_ipv4(local_ip: &Ipv4Inet) -> Ipv4Addr {
        local_ip.first_address()
    }

    fn real_dst_ip_for_mode(
        &self,
        mode: TcpProxyMode,
        origin_ip: Ipv4Addr,
        is_exit_node: bool,
        ctx: &TcpProxyPeerContext,
    ) -> Option<Ipv4Addr> {
        match mode {
            TcpProxyMode::Tcp => {
                if let Some(real_ip) = self.cidr_table.lookup_v4(origin_ip) {
                    return Some(real_ip);
                }
                let no_tun_local_virtual_ip = ctx.no_tun && Some(origin_ip) == ctx.virtual_ipv4;
                (is_exit_node || no_tun_local_virtual_ip).then_some(origin_ip)
            }
            TcpProxyMode::KcpSrc | TcpProxyMode::QuicSrc => Some(origin_ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gateway::proxy::cidr_table::{ProxyCidrRule, ProxyCidrSnapshot},
        packet::PeerManagerHeader,
    };
    use smoltcp::wire::{IpAddress, TcpPacket};

    fn build_tcp_packet(src: SocketAddrV4, dst: SocketAddrV4, syn: bool, ack: bool) -> ZCPacket {
        let mut raw = vec![0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN];
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(&mut raw);
            ipv4.set_version(4);
            ipv4.set_header_len(smoltcp::wire::IPV4_HEADER_LEN as u8);
            ipv4.set_total_len(
                (smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN) as u16,
            );
            ipv4.set_hop_limit(64);
            ipv4.set_next_header(IpProtocol::Tcp);
            ipv4.set_src_addr(*src.ip());
            ipv4.set_dst_addr(*dst.ip());
            ipv4.fill_checksum();
        }
        {
            let mut tcp = TcpPacket::new_unchecked(&mut raw[smoltcp::wire::IPV4_HEADER_LEN..]);
            tcp.set_src_port(src.port());
            tcp.set_dst_port(dst.port());
            tcp.set_header_len(smoltcp::wire::TCP_HEADER_LEN as u8);
            tcp.set_syn(syn);
            tcp.set_ack(ack);
            tcp.fill_checksum(&IpAddress::Ipv4(*src.ip()), &IpAddress::Ipv4(*dst.ip()));
        }

        let mut packet = ZCPacket::new_with_payload(&raw);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn tcp_engine() -> TcpProxyEngine {
        TcpProxyEngine::new(Arc::new(ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "127.0.0.0/24".parse().unwrap(),
                mapped_cidr: Some("10.10.10.0/24".parse().unwrap()),
            }],
        })))
    }

    fn peer_ctx() -> TcpProxyPeerContext {
        TcpProxyPeerContext {
            local_inet: Some("10.144.144.204/24".parse().unwrap()),
            virtual_ipv4: Some("10.144.144.204".parse().unwrap()),
            local_port: 8899,
            enable_exit_node: false,
            no_tun: false,
            smoltcp_enabled: false,
        }
    }

    #[test]
    fn peer_syn_creates_entry_and_rewrites_to_local_stack() {
        let engine = tcp_engine();
        let src = SocketAddrV4::new("10.144.144.206".parse().unwrap(), 50000);
        let mapped_dst = SocketAddrV4::new("10.10.10.42".parse().unwrap(), 80);
        let mut packet = build_tcp_packet(src, mapped_dst, true, false);

        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut packet, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        );

        let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), *src.ip());
        assert_eq!(
            ipv4.dst_addr(),
            "10.144.144.204".parse::<Ipv4Addr>().unwrap()
        );
        let tcp = TcpPacket::new_checked(ipv4.payload()).unwrap();
        assert_eq!(tcp.src_port(), src.port());
        assert_eq!(tcp.dst_port(), 8899);

        let entries = engine.list_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].src, SocketAddr::V4(src));
        assert_eq!(
            entries[0].dst,
            SocketAddr::V4(SocketAddrV4::new("127.0.0.42".parse().unwrap(), 80))
        );
        assert_eq!(entries[0].mapped_dst, SocketAddr::V4(mapped_dst));
    }

    #[test]
    fn nic_response_rewrites_back_to_mapped_destination() {
        let engine = tcp_engine();
        let src = SocketAddrV4::new("10.144.144.206".parse().unwrap(), 50000);
        let mapped_dst = SocketAddrV4::new("10.10.10.42".parse().unwrap(), 80);
        let mut request = build_tcp_packet(src, mapped_dst, true, false);
        assert!(matches!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut request, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        ));
        let entry = engine
            .accept_connection(
                SocketAddr::V4(src),
                Some("10.144.144.204/24".parse().unwrap()),
            )
            .unwrap();
        assert_eq!(entry.state(), TcpNatEntryState::ConnectingDst);

        let local = SocketAddrV4::new("10.144.144.204".parse().unwrap(), 8899);
        let mut response = build_tcp_packet(local, src, false, true);
        assert!(engine.try_process_packet_from_nic(
            &mut response,
            TcpProxyNicContext {
                local_inet: Some("10.144.144.204/24".parse().unwrap()),
                local_port: 8899,
                my_peer_id: 2,
                smoltcp_enabled: false,
            },
        ));

        let hdr: &PeerManagerHeader = response.peer_manager_header().unwrap();
        assert!(hdr.is_no_proxy());
        let ipv4 = Ipv4Packet::new_checked(response.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), *mapped_dst.ip());
        assert_eq!(ipv4.dst_addr(), *src.ip());
        let tcp = TcpPacket::new_checked(ipv4.payload()).unwrap();
        assert_eq!(tcp.src_port(), mapped_dst.port());
        assert_eq!(tcp.dst_port(), src.port());
    }

    #[test]
    fn accept_connection_does_not_resurrect_closed_syn_entry() {
        let engine = tcp_engine();
        let src = SocketAddrV4::new("10.144.144.206".parse().unwrap(), 50000);
        let mapped_dst = SocketAddrV4::new("10.10.10.42".parse().unwrap(), 80);
        let mut request = build_tcp_packet(src, mapped_dst, true, false);
        assert!(matches!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut request, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        ));
        let entry = engine.syn_map.get(&SocketAddr::V4(src)).unwrap().clone();
        entry.set_state(TcpNatEntryState::Closed);

        assert!(
            engine
                .accept_connection(
                    SocketAddr::V4(src),
                    Some("10.144.144.204/24".parse().unwrap()),
                )
                .is_none()
        );
        assert!(engine.syn_map.get(&SocketAddr::V4(src)).is_none());
        assert!(engine.addr_conn_map.get(&SocketAddr::V4(src)).is_none());
        assert!(engine.conn_map.is_empty());
    }
}
