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
use dashmap::{DashMap, mapref::entry::Entry};
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

impl TcpProxyMode {
    pub(super) const fn smoltcp_listener_port(self) -> u16 {
        match self {
            Self::Tcp => 8899,
            Self::KcpSrc => 8900,
            Self::QuicSrc => 8901,
        }
    }
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpNatFlowKey {
    src: SocketAddr,
    mapped_dst: SocketAddr,
}

#[derive(Debug)]
pub(crate) struct TcpNatEntry {
    id: TcpNatEntryId,
    flow: TcpNatFlowKey,
    translated_src: SocketAddr,
    real_dst: SocketAddr,
    start_time: Instant,
    start_time_unix_secs: u64,
    state: AtomicCell<TcpNatEntryState>,
}

impl TcpNatEntry {
    fn new(flow: TcpNatFlowKey, translated_src: SocketAddr, real_dst: SocketAddr) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            flow,
            translated_src,
            real_dst,
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
        self.flow.src
    }

    pub fn real_dst(&self) -> SocketAddr {
        self.real_dst
    }

    pub fn mapped_dst(&self) -> SocketAddr {
        self.flow.mapped_dst
    }

    pub fn state(&self) -> TcpNatEntryState {
        self.state.load()
    }

    pub fn set_state(&self, state: TcpNatEntryState) {
        self.state.store(state);
    }

    fn snapshot(&self) -> TcpNatEntrySnapshot {
        TcpNatEntrySnapshot {
            src: self.src(),
            dst: self.real_dst,
            mapped_dst: self.mapped_dst(),
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
    Drop,
    Pass,
}

#[derive(Debug)]
pub(crate) struct TcpProxyEngine {
    cidr_table: Arc<ProxyCidrTable>,
    local_port: AtomicU16,
    next_translated_port: AtomicU16,
    flow_map: DashMap<TcpNatFlowKey, Arc<TcpNatEntry>>,
    translated_src_map: DashMap<SocketAddr, Arc<TcpNatEntry>>,
    conn_map: DashMap<uuid::Uuid, Arc<TcpNatEntry>>,
}

impl TcpProxyEngine {
    pub fn new(cidr_table: Arc<ProxyCidrTable>) -> Self {
        Self {
            cidr_table,
            local_port: AtomicU16::new(0),
            next_translated_port: AtomicU16::new(1),
            flow_map: DashMap::new(),
            translated_src_map: DashMap::new(),
            conn_map: DashMap::new(),
        }
    }

    pub fn set_local_port(&self, port: u16) {
        self.local_port.store(port, Ordering::Relaxed);
    }

    pub fn local_port(&self) -> u16 {
        self.local_port.load(Ordering::Relaxed)
    }

    fn allocate_entry(
        &self,
        flow: TcpNatFlowKey,
        real_dst: SocketAddr,
    ) -> Option<Arc<TcpNatEntry>> {
        let local_port = self.local_port();
        for _ in 0..u16::MAX {
            let translated_port = self
                .next_translated_port
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |port| {
                    Some(if port == u16::MAX { 1 } else { port + 1 })
                })
                .expect("translated port counter update cannot fail");
            if translated_port == local_port {
                continue;
            }
            let translated_src = SocketAddr::new(flow.src.ip(), translated_port);
            let Entry::Vacant(slot) = self.translated_src_map.entry(translated_src) else {
                continue;
            };
            let entry = Arc::new(TcpNatEntry::new(flow, translated_src, real_dst));
            slot.insert(entry.clone());
            return Some(entry);
        }
        None
    }

    fn entry_for_syn(
        &self,
        flow: TcpNatFlowKey,
        real_dst: SocketAddr,
    ) -> Option<(Arc<TcpNatEntry>, bool)> {
        match self.flow_map.entry(flow) {
            Entry::Occupied(mut slot) => {
                let entry = slot.get();
                if !matches!(
                    entry.state(),
                    TcpNatEntryState::ClosingSrc
                        | TcpNatEntryState::ClosingDst
                        | TcpNatEntryState::Closed
                ) {
                    return Some((entry.clone(), false));
                }
                let entry = self.allocate_entry(flow, real_dst)?;
                slot.insert(entry.clone());
                Some((entry, true))
            }
            Entry::Vacant(slot) => {
                let entry = self.allocate_entry(flow, real_dst)?;
                slot.insert(entry.clone());
                Some((entry, true))
            }
        }
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
        let dest_ip = ip_packet.dst_addr();
        let dest_port = tcp_packet.dst_port();
        let flow = TcpNatFlowKey {
            src: SocketAddr::V4(SocketAddrV4::new(source_ip, source_port)),
            mapped_dst: SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port)),
        };

        let is_syn = tcp_packet.syn() && !tcp_packet.ack();
        let (entry, new_syn) = if is_syn {
            let real_dst = SocketAddr::V4(SocketAddrV4::new(real_dst_ip, dest_port));
            let Some(entry) = self.entry_for_syn(flow, real_dst) else {
                tracing::error!(?flow, "tcp proxy translated source ports exhausted");
                return TcpProxyPacketAction::Drop;
            };
            entry
        } else {
            let Some(entry) = self.flow_map.get(&flow) else {
                return TcpProxyPacketAction::Pass;
            };
            (entry.clone(), false)
        };

        if new_syn {
            tracing::info!(
                src = ?entry.src(),
                translated_src = ?entry.translated_src,
                real_dst = ?entry.real_dst(),
                mapped_dst = ?entry.mapped_dst(),
                "tcp syn received"
            );
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
            tcp_packet.set_src_port(entry.translated_src.port());
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
        let Some(entry) = self.translated_src_map.get(&dst_addr) else {
            return false;
        };
        let entry = entry.clone();
        assert_eq!(entry.translated_src, dst_addr);

        let IpAddr::V4(mapped_dst_ip) = entry.mapped_dst().ip() else {
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
            tcp_packet.set_dst_port(entry.src().port());
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

        let entry = self.translated_src_map.get(&socket_addr)?.clone();
        if entry
            .state
            .compare_exchange(
                TcpNatEntryState::SynReceived,
                TcpNatEntryState::ConnectingDst,
            )
            .is_err()
        {
            if entry.state() == TcpNatEntryState::Closed {
                self.remove_indices(&entry);
            }
            return None;
        }

        let old_nat_val = self.conn_map.insert(entry.id, entry.clone());
        assert!(old_nat_val.is_none());
        Some(entry)
    }

    fn remove_indices(&self, entry: &TcpNatEntry) {
        self.flow_map
            .remove_if(&entry.flow, |_, current| current.id == entry.id);
        self.translated_src_map
            .remove_if(&entry.translated_src, |_, current| current.id == entry.id);
    }

    pub fn remove_entry(&self, entry_id: TcpNatEntryId) {
        let Some((_, entry)) = self.conn_map.remove(&entry_id) else {
            return;
        };
        self.remove_indices(&entry);
        if self.conn_map.capacity() - self.conn_map.len() > 16 {
            self.conn_map.shrink_to_fit();
        }
        if self.flow_map.capacity() - self.flow_map.len() > 16 {
            self.flow_map.shrink_to_fit();
        }
        if self.translated_src_map.capacity() - self.translated_src_map.len() > 16 {
            self.translated_src_map.shrink_to_fit();
        }
    }

    pub fn clear(&self) {
        for entry in self.flow_map.iter() {
            entry.set_state(TcpNatEntryState::Closed);
        }
        for entry in self.conn_map.iter() {
            entry.set_state(TcpNatEntryState::Closed);
        }
        self.flow_map.clear();
        self.translated_src_map.clear();
        self.conn_map.clear();
    }

    pub fn cleanup_expired_syn(&self, timeout: Duration) {
        self.flow_map.retain(|_, entry| {
            let expired = entry.start_time.elapsed() > timeout
                && entry
                    .state
                    .compare_exchange(TcpNatEntryState::SynReceived, TcpNatEntryState::Closed)
                    .is_ok();
            if expired {
                tracing::warn!(?entry, "syn nat entry expired");
                self.translated_src_map
                    .remove_if(&entry.translated_src, |_, current| current.id == entry.id);
            }
            !expired
        });
        self.flow_map.shrink_to_fit();
        self.translated_src_map.shrink_to_fit();
    }

    pub fn is_tcp_proxy_flow(&self, src: SocketAddr, mapped_dst: SocketAddr) -> bool {
        self.flow_map
            .contains_key(&TcpNatFlowKey { src, mapped_dst })
    }

    pub fn list_entries(&self) -> Vec<TcpNatEntrySnapshot> {
        let mut entries = Vec::new();
        for entry in self.flow_map.iter() {
            if entry.state() == TcpNatEntryState::SynReceived {
                entries.push(entry.value().snapshot());
            }
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

    fn packet_src(packet: &ZCPacket) -> SocketAddrV4 {
        let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
        let tcp = TcpPacket::new_checked(ipv4.payload()).unwrap();
        SocketAddrV4::new(ipv4.src_addr(), tcp.src_port())
    }

    fn nic_ctx() -> TcpProxyNicContext {
        TcpProxyNicContext {
            local_inet: Some("10.144.144.204/24".parse().unwrap()),
            local_port: 8899,
            my_peer_id: 2,
            smoltcp_enabled: false,
        }
    }

    #[test]
    fn smoltcp_listener_ports_are_unique_per_proxy_mode() {
        let tcp = TcpProxyMode::Tcp.smoltcp_listener_port();
        let kcp = TcpProxyMode::KcpSrc.smoltcp_listener_port();
        let quic = TcpProxyMode::QuicSrc.smoltcp_listener_port();

        assert_ne!(tcp, kcp);
        assert_ne!(tcp, quic);
        assert_ne!(kcp, quic);
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
        assert_ne!(tcp.src_port(), src.port());
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
        let translated_src = packet_src(&request);
        let entry = engine
            .accept_connection(
                SocketAddr::V4(translated_src),
                Some("10.144.144.204/24".parse().unwrap()),
            )
            .unwrap();
        assert_eq!(entry.state(), TcpNatEntryState::ConnectingDst);

        let local = SocketAddrV4::new("10.144.144.204".parse().unwrap(), 8899);
        let mut response = build_tcp_packet(local, translated_src, false, true);
        assert!(engine.try_process_packet_from_nic(&mut response, nic_ctx()));

        let hdr: &PeerManagerHeader = response.peer_manager_header().unwrap();
        assert!(hdr.is_no_proxy());
        let ipv4 = Ipv4Packet::new_checked(response.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), *mapped_dst.ip());
        assert_eq!(ipv4.dst_addr(), *src.ip());
        let tcp = TcpPacket::new_checked(ipv4.payload()).unwrap();
        assert_eq!(tcp.src_port(), mapped_dst.port());
        assert_eq!(tcp.dst_port(), src.port());

        engine.remove_entry(entry.id());
        assert!(!engine.is_tcp_proxy_flow(SocketAddr::V4(src), SocketAddr::V4(mapped_dst),));
        assert!(
            engine
                .translated_src_map
                .get(&SocketAddr::V4(translated_src))
                .is_none()
        );
    }

    #[test]
    fn same_source_port_to_mapped_and_real_destinations_stay_distinct() {
        let engine = tcp_engine();
        let src = SocketAddrV4::new("10.144.144.206".parse().unwrap(), 50000);
        let mapped_dst = SocketAddrV4::new("10.10.10.42".parse().unwrap(), 80);
        let real_dst = SocketAddrV4::new("127.0.0.42".parse().unwrap(), 80);

        let mut mapped_request = build_tcp_packet(src, mapped_dst, true, false);
        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut mapped_request, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        );
        let mapped_translated_src = packet_src(&mapped_request);
        engine
            .accept_connection(
                SocketAddr::V4(mapped_translated_src),
                Some("10.144.144.204/24".parse().unwrap()),
            )
            .unwrap();

        let mut real_request = build_tcp_packet(src, real_dst, true, false);
        real_request
            .mut_peer_manager_header()
            .unwrap()
            .set_exit_node(true);
        let mut real_ctx = peer_ctx();
        real_ctx.enable_exit_node = true;
        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut real_request, real_ctx),
            TcpProxyPacketAction::Handled { new_syn: true }
        );
        let real_translated_src = packet_src(&real_request);
        engine
            .accept_connection(
                SocketAddr::V4(real_translated_src),
                Some("10.144.144.204/24".parse().unwrap()),
            )
            .unwrap();

        assert_ne!(mapped_translated_src, real_translated_src);

        let local = SocketAddrV4::new("10.144.144.204".parse().unwrap(), 8899);
        for (translated_src, expected_source) in [
            (mapped_translated_src, mapped_dst),
            (real_translated_src, real_dst),
        ] {
            let mut response = build_tcp_packet(local, translated_src, false, true);
            assert!(engine.try_process_packet_from_nic(&mut response, nic_ctx()));

            let ipv4 = Ipv4Packet::new_checked(response.payload()).unwrap();
            assert_eq!(ipv4.src_addr(), *expected_source.ip());
            assert_eq!(ipv4.dst_addr(), *src.ip());
            let tcp = TcpPacket::new_checked(ipv4.payload()).unwrap();
            assert_eq!(tcp.src_port(), expected_source.port());
            assert_eq!(tcp.dst_port(), src.port());
        }
    }

    #[test]
    fn clear_discards_accepted_entries_before_restart() {
        let engine = tcp_engine();
        let src = SocketAddrV4::new("10.144.144.206".parse().unwrap(), 50000);
        let mapped_dst = SocketAddrV4::new("10.10.10.42".parse().unwrap(), 80);
        let mut request = build_tcp_packet(src, mapped_dst, true, false);
        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut request, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        );
        let old_entry = engine
            .accept_connection(
                SocketAddr::V4(packet_src(&request)),
                Some("10.144.144.204/24".parse().unwrap()),
            )
            .unwrap();

        engine.clear();

        assert_eq!(old_entry.state(), TcpNatEntryState::Closed);
        assert!(engine.flow_map.is_empty());
        assert!(engine.translated_src_map.is_empty());
        assert!(engine.conn_map.is_empty());

        let mut retry = build_tcp_packet(src, mapped_dst, true, false);
        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut retry, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        );
        let new_entry = engine
            .accept_connection(
                SocketAddr::V4(packet_src(&retry)),
                Some("10.144.144.204/24".parse().unwrap()),
            )
            .unwrap();
        assert_ne!(old_entry.id(), new_entry.id());
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
        let translated_src = packet_src(&request);
        let entry = engine
            .translated_src_map
            .get(&SocketAddr::V4(translated_src))
            .unwrap()
            .clone();
        entry.set_state(TcpNatEntryState::Closed);

        assert!(
            engine
                .accept_connection(
                    SocketAddr::V4(translated_src),
                    Some("10.144.144.204/24".parse().unwrap()),
                )
                .is_none()
        );
        assert!(engine.flow_map.is_empty());
        assert!(engine.translated_src_map.is_empty());
        assert!(engine.conn_map.is_empty());
    }

    #[test]
    fn retransmitted_syn_keeps_the_pending_and_accepted_mapping() {
        let engine = tcp_engine();
        let src = "10.144.144.206:50000".parse().unwrap();
        let dst = "10.10.10.42:80".parse().unwrap();
        let mut first = build_tcp_packet(src, dst, true, false);
        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut first, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        );
        let translated_src = SocketAddr::V4(packet_src(&first));

        for accepted in [false, true] {
            if accepted {
                engine.accept_connection(translated_src, None).unwrap();
                engine.cleanup_expired_syn(Duration::ZERO);
            }
            let mut retry = build_tcp_packet(src, dst, true, false);
            assert_eq!(
                engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut retry, peer_ctx()),
                TcpProxyPacketAction::Handled { new_syn: false }
            );
            assert_eq!(SocketAddr::V4(packet_src(&retry)), translated_src);
            assert_eq!(engine.flow_map.len(), 1);
            assert_eq!(engine.translated_src_map.len(), 1);
            assert_eq!(engine.list_entries().len(), 1);
        }
        assert!(engine.accept_connection(translated_src, None).is_none());
    }

    #[test]
    fn removing_closing_connection_preserves_replacement_flow() {
        for state in [
            TcpNatEntryState::ClosingSrc,
            TcpNatEntryState::ClosingDst,
            TcpNatEntryState::Closed,
        ] {
            let engine = tcp_engine();
            let flow = TcpNatFlowKey {
                src: "10.144.144.206:50000".parse().unwrap(),
                mapped_dst: "10.10.10.42:80".parse().unwrap(),
            };
            let real_dst = "127.0.0.42:80".parse().unwrap();
            let (old, _) = engine.entry_for_syn(flow, real_dst).unwrap();
            engine.accept_connection(old.translated_src, None).unwrap();
            old.set_state(state);
            let (replacement, new_syn) = engine.entry_for_syn(flow, real_dst).unwrap();
            assert!(new_syn);
            assert_ne!(old.translated_src, replacement.translated_src);
            assert_eq!(engine.translated_src_map.len(), 2);

            engine.remove_entry(old.id());
            assert!(engine.is_tcp_proxy_flow(flow.src, flow.mapped_dst));
            assert!(!engine.translated_src_map.contains_key(&old.translated_src));
            assert_eq!(engine.flow_map.get(&flow).unwrap().id(), replacement.id());
            assert_eq!(
                engine
                    .accept_connection(replacement.translated_src, None)
                    .unwrap()
                    .id(),
                replacement.id()
            );

            let local = "10.144.144.204:8899".parse().unwrap();
            let SocketAddr::V4(translated_src) = replacement.translated_src else {
                unreachable!();
            };
            let mut response = build_tcp_packet(local, translated_src, false, true);
            assert!(engine.try_process_packet_from_nic(&mut response, nic_ctx()));
            let ip = Ipv4Packet::new_checked(response.payload()).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(SocketAddr::V4(packet_src(&response)), flow.mapped_dst);
            assert_eq!(tcp.dst_port(), flow.src.port());
            assert!(ip.verify_checksum());
            assert!(tcp.verify_checksum(
                &IpAddress::Ipv4(ip.src_addr()),
                &IpAddress::Ipv4(ip.dst_addr())
            ));
        }
    }

    #[test]
    fn expired_syn_releases_both_indices_without_removing_accepted_flow() {
        let engine = tcp_engine();
        let pending_flow = TcpNatFlowKey {
            src: "10.144.144.206:50000".parse().unwrap(),
            mapped_dst: "10.10.10.42:80".parse().unwrap(),
        };
        let accepted_flow = TcpNatFlowKey {
            mapped_dst: "10.10.10.43:80".parse().unwrap(),
            ..pending_flow
        };
        let real_dst = "127.0.0.42:80".parse().unwrap();
        let (pending, _) = engine.entry_for_syn(pending_flow, real_dst).unwrap();
        let (accepted, _) = engine.entry_for_syn(accepted_flow, real_dst).unwrap();
        engine
            .accept_connection(accepted.translated_src, None)
            .unwrap();

        engine.cleanup_expired_syn(Duration::ZERO);

        assert_eq!(pending.state(), TcpNatEntryState::Closed);
        assert!(
            engine
                .accept_connection(pending.translated_src, None)
                .is_none()
        );
        assert!(!engine.is_tcp_proxy_flow(pending_flow.src, pending_flow.mapped_dst));
        assert!(engine.is_tcp_proxy_flow(accepted_flow.src, accepted_flow.mapped_dst));
        assert_eq!(engine.translated_src_map.len(), 1);
        assert_eq!(engine.conn_map.len(), 1);
        assert_eq!(accepted.state(), TcpNatEntryState::ConnectingDst);
    }

    #[test]
    fn translated_port_wrap_skips_live_ports_and_listener() {
        let engine = tcp_engine();
        engine.set_local_port(8899);
        let flow = TcpNatFlowKey {
            src: "10.144.144.206:50000".parse().unwrap(),
            mapped_dst: "10.10.10.42:80".parse().unwrap(),
        };
        let real_dst = "127.0.0.42:80".parse().unwrap();
        engine
            .next_translated_port
            .store(u16::MAX, Ordering::Relaxed);
        let last = engine.allocate_entry(flow, real_dst).unwrap();
        let first = engine.allocate_entry(flow, real_dst).unwrap();
        assert_eq!(last.translated_src.port(), u16::MAX);
        assert_eq!(first.translated_src.port(), 1);

        engine
            .next_translated_port
            .store(u16::MAX, Ordering::Relaxed);
        let next = engine.allocate_entry(flow, real_dst).unwrap();
        assert_eq!(next.translated_src.port(), 2);
        assert_eq!(
            engine
                .translated_src_map
                .get(&last.translated_src)
                .unwrap()
                .id(),
            last.id()
        );
        assert_eq!(
            engine
                .translated_src_map
                .get(&first.translated_src)
                .unwrap()
                .id(),
            first.id()
        );

        engine.next_translated_port.store(8899, Ordering::Relaxed);
        let after_listener = engine.allocate_entry(flow, real_dst).unwrap();
        assert_eq!(after_listener.translated_src.port(), 8900);
    }

    #[test]
    fn exhausted_translated_ports_are_isolated_and_reusable_after_cleanup() {
        let engine = tcp_engine();
        engine.set_local_port(8899);
        let src_ip = "10.144.144.206".parse().unwrap();
        let dst = "10.10.10.42:80".parse().unwrap();
        let real_dst = "127.0.0.42:80".parse().unwrap();
        for port in 1..u16::MAX {
            let flow = TcpNatFlowKey {
                src: SocketAddr::V4(SocketAddrV4::new(src_ip, port)),
                mapped_dst: SocketAddr::V4(dst),
            };
            assert!(engine.entry_for_syn(flow, real_dst).is_some());
        }
        assert_eq!(engine.translated_src_map.len(), usize::from(u16::MAX) - 1);
        let src = SocketAddrV4::new(src_ip, u16::MAX);
        let mut exhausted = build_tcp_packet(src, dst, true, false);
        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut exhausted, peer_ctx()),
            TcpProxyPacketAction::Drop
        );
        assert!(!engine.is_tcp_proxy_flow(SocketAddr::V4(src), SocketAddr::V4(dst)));

        let other_flow = TcpNatFlowKey {
            src: "10.144.144.207:50000".parse().unwrap(),
            mapped_dst: SocketAddr::V4(dst),
        };
        assert!(engine.entry_for_syn(other_flow, real_dst).is_some());

        let released_addr = SocketAddr::V4(SocketAddrV4::new(src_ip, 1));
        let released = engine.accept_connection(released_addr, None).unwrap();
        released.set_state(TcpNatEntryState::Closed);
        engine.remove_entry(released.id());
        let mut retry = build_tcp_packet(src, dst, true, false);
        assert_eq!(
            engine.try_handle_peer_packet(TcpProxyMode::Tcp, &mut retry, peer_ctx()),
            TcpProxyPacketAction::Handled { new_syn: true }
        );
        assert_eq!(SocketAddr::V4(packet_src(&retry)), released_addr);
        assert!(engine.accept_connection(released_addr, None).is_some());

        engine.clear();
        assert!(engine.flow_map.is_empty());
        assert!(engine.translated_src_map.is_empty());
        assert!(engine.conn_map.is_empty());
        assert!(engine.entry_for_syn(other_flow, real_dst).is_some());
    }

    #[test]
    fn concurrent_syns_share_one_mapping_and_only_one_accept() {
        let engine = tcp_engine();
        let barrier = std::sync::Barrier::new(8);
        let flow = TcpNatFlowKey {
            src: "10.144.144.206:50000".parse().unwrap(),
            mapped_dst: "10.10.10.42:80".parse().unwrap(),
        };
        let results = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let (entry, new_syn) = engine.entry_for_syn(flow, flow.mapped_dst).unwrap();
                        let accepted = engine
                            .accept_connection(entry.translated_src, None)
                            .is_some();
                        (entry.id(), new_syn, accepted)
                    })
                })
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(results.iter().all(|result| result.0 == results[0].0));
        assert_eq!(results.iter().filter(|result| result.1).count(), 1);
        assert_eq!(results.iter().filter(|result| result.2).count(), 1);
        assert_eq!(engine.flow_map.len(), 1);
        assert_eq!(engine.translated_src_map.len(), 1);
        assert_eq!(engine.conn_map.len(), 1);
    }
}
