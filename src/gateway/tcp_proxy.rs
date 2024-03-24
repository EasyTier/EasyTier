use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::AtomicU16;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::bytes::{Bytes, BytesMut};
use tracing::Instrument;

use crate::common::error::Result;
use crate::common::global_ctx::GlobalCtx;
use crate::common::join_joinset_background;
use crate::common::netns::NetNS;
use crate::peers::packet::{self, ArchivedPacket};
use crate::peers::peer_manager::PeerManager;
use crate::peers::{NicPacketFilter, PeerPacketFilter};

use super::CidrSet;

#[derive(Debug, Clone, Copy, PartialEq)]
enum NatDstEntryState {
    // receive syn packet but not start connecting to dst
    SynReceived,
    // connecting to dst
    ConnectingDst,
    // connected to dst
    Connected,
    // connection closed
    Closed,
}

#[derive(Debug)]
pub struct NatDstEntry {
    id: uuid::Uuid,
    src: SocketAddr,
    dst: SocketAddr,
    start_time: Instant,
    tasks: Mutex<JoinSet<()>>,
    state: AtomicCell<NatDstEntryState>,
}

impl NatDstEntry {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            src,
            dst,
            start_time: Instant::now(),
            tasks: Mutex::new(JoinSet::new()),
            state: AtomicCell::new(NatDstEntryState::SynReceived),
        }
    }
}

type ArcNatDstEntry = Arc<NatDstEntry>;

type SynSockMap = Arc<DashMap<SocketAddr, ArcNatDstEntry>>;
type ConnSockMap = Arc<DashMap<uuid::Uuid, ArcNatDstEntry>>;
// peer src addr to nat entry, when respond tcp packet, should modify the tcp src addr to the nat entry's dst addr
type AddrConnSockMap = Arc<DashMap<SocketAddr, ArcNatDstEntry>>;

#[derive(Debug)]
pub struct TcpProxy {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Arc<PeerManager>,
    local_port: AtomicU16,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    syn_map: SynSockMap,
    conn_map: ConnSockMap,
    addr_conn_map: AddrConnSockMap,

    cidr_set: CidrSet,
}

#[async_trait::async_trait]
impl PeerPacketFilter for TcpProxy {
    async fn try_process_packet_from_peer(&self, packet: &ArchivedPacket, _: &Bytes) -> Option<()> {
        let ipv4_addr = self.global_ctx.get_ipv4()?;

        if packet.packet_type != packet::PacketType::Data {
            return None;
        };

        let payload_bytes = packet.payload.as_bytes();

        let ipv4 = Ipv4Packet::new(payload_bytes)?;
        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None;
        }

        if !self.cidr_set.contains_v4(ipv4.get_destination()) {
            return None;
        }

        tracing::trace!(ipv4 = ?ipv4, cidr_set = ?self.cidr_set, "proxy tcp packet received");

        let mut packet_buffer = BytesMut::with_capacity(payload_bytes.len());
        packet_buffer.extend_from_slice(&payload_bytes.to_vec());

        let (ip_buffer, tcp_buffer) =
            packet_buffer.split_at_mut(ipv4.get_header_length() as usize * 4);

        let mut ip_packet = MutableIpv4Packet::new(ip_buffer).unwrap();
        let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();

        let is_tcp_syn = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0;
        if is_tcp_syn {
            let source_ip = ip_packet.get_source();
            let source_port = tcp_packet.get_source();
            let src = SocketAddr::V4(SocketAddrV4::new(source_ip, source_port));

            let dest_ip = ip_packet.get_destination();
            let dest_port = tcp_packet.get_destination();
            let dst = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));

            let old_val = self
                .syn_map
                .insert(src, Arc::new(NatDstEntry::new(src, dst)));
            tracing::trace!(src = ?src, dst = ?dst, old_entry = ?old_val, "tcp syn received");
        }

        ip_packet.set_destination(ipv4_addr);
        tcp_packet.set_destination(self.get_local_port());
        Self::update_ipv4_packet_checksum(&mut ip_packet, &mut tcp_packet);

        tracing::trace!(ip_packet = ?ip_packet, tcp_packet = ?tcp_packet, "tcp packet forwarded");

        if let Err(e) = self
            .peer_manager
            .get_nic_channel()
            .send(packet_buffer.freeze())
            .await
        {
            tracing::error!("send to nic failed: {:?}", e);
        }

        Some(())
    }
}

#[async_trait::async_trait]
impl NicPacketFilter for TcpProxy {
    async fn try_process_packet_from_nic(&self, mut data: BytesMut) -> BytesMut {
        let Some(my_ipv4) = self.global_ctx.get_ipv4() else {
            return data;
        };

        let header_len = {
            let Some(ipv4) = &Ipv4Packet::new(&data[..]) else {
                return data;
            };

            if ipv4.get_version() != 4
                || ipv4.get_source() != my_ipv4
                || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
            {
                return data;
            }

            ipv4.get_header_length() as usize * 4
        };

        let (ip_buffer, tcp_buffer) = data.split_at_mut(header_len);
        let mut ip_packet = MutableIpv4Packet::new(ip_buffer).unwrap();
        let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();

        if tcp_packet.get_source() != self.get_local_port() {
            return data;
        }

        let dst_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_destination(),
            tcp_packet.get_destination(),
        ));

        tracing::trace!(dst_addr = ?dst_addr, "tcp packet try find entry");
        let entry = if let Some(entry) = self.addr_conn_map.get(&dst_addr) {
            entry
        } else {
            let Some(syn_entry) = self.syn_map.get(&dst_addr) else {
                return data;
            };
            syn_entry
        };
        let nat_entry = entry.clone();
        drop(entry);
        assert_eq!(nat_entry.src, dst_addr);

        let IpAddr::V4(ip) = nat_entry.dst.ip() else {
            panic!("v4 nat entry src ip is not v4");
        };

        ip_packet.set_source(ip);
        tcp_packet.set_source(nat_entry.dst.port());
        Self::update_ipv4_packet_checksum(&mut ip_packet, &mut tcp_packet);

        tracing::trace!(dst_addr = ?dst_addr, nat_entry = ?nat_entry, packet = ?ip_packet, "tcp packet after modified");

        data
    }
}

impl TcpProxy {
    pub fn new(global_ctx: Arc<GlobalCtx>, peer_manager: Arc<PeerManager>) -> Arc<Self> {
        Arc::new(Self {
            global_ctx: global_ctx.clone(),
            peer_manager,

            local_port: AtomicU16::new(0),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),

            syn_map: Arc::new(DashMap::new()),
            conn_map: Arc::new(DashMap::new()),
            addr_conn_map: Arc::new(DashMap::new()),

            cidr_set: CidrSet::new(global_ctx),
        })
    }

    fn update_ipv4_packet_checksum(
        ipv4_packet: &mut MutableIpv4Packet,
        tcp_packet: &mut MutableTcpPacket,
    ) {
        tcp_packet.set_checksum(ipv4_checksum(
            &tcp_packet.to_immutable(),
            &ipv4_packet.get_source(),
            &ipv4_packet.get_destination(),
        ));

        ipv4_packet.set_checksum(pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable()));
    }

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        self.run_syn_map_cleaner().await?;
        self.run_listener().await?;
        self.peer_manager
            .add_packet_process_pipeline(Box::new(self.clone()))
            .await;
        self.peer_manager
            .add_nic_packet_process_pipeline(Box::new(self.clone()))
            .await;
        join_joinset_background(self.tasks.clone(), "TcpProxy".to_owned());

        Ok(())
    }

    async fn run_syn_map_cleaner(&self) -> Result<()> {
        let syn_map = self.syn_map.clone();
        let tasks = self.tasks.clone();
        let syn_map_cleaner_task = async move {
            loop {
                syn_map.retain(|_, entry| {
                    if entry.start_time.elapsed() > Duration::from_secs(30) {
                        tracing::warn!(entry = ?entry, "syn nat entry expired");
                        entry.state.store(NatDstEntryState::Closed);
                        false
                    } else {
                        true
                    }
                });
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        };
        tasks.lock().unwrap().spawn(syn_map_cleaner_task);

        Ok(())
    }

    async fn run_listener(&self) -> Result<()> {
        // bind on both v4 & v6
        let listen_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);

        let net_ns = self.global_ctx.net_ns.clone();
        let tcp_listener = net_ns
            .run_async(|| async { TcpListener::bind(&listen_addr).await })
            .await?;

        self.local_port.store(
            tcp_listener.local_addr()?.port(),
            std::sync::atomic::Ordering::Relaxed,
        );

        let tasks = self.tasks.clone();
        let syn_map = self.syn_map.clone();
        let conn_map = self.conn_map.clone();
        let addr_conn_map = self.addr_conn_map.clone();
        let accept_task = async move {
            tracing::info!(listener = ?tcp_listener, "tcp connection start accepting");

            let conn_map = conn_map.clone();
            while let Ok((tcp_stream, socket_addr)) = tcp_listener.accept().await {
                let Some(entry) = syn_map.get(&socket_addr) else {
                    tracing::error!("tcp connection from unknown source: {:?}", socket_addr);
                    continue;
                };
                assert_eq!(entry.state.load(), NatDstEntryState::SynReceived);

                let entry_clone = entry.clone();
                drop(entry);
                syn_map.remove_if(&socket_addr, |_, entry| entry.id == entry_clone.id);

                entry_clone.state.store(NatDstEntryState::ConnectingDst);

                let _ = addr_conn_map.insert(entry_clone.src, entry_clone.clone());
                let old_nat_val = conn_map.insert(entry_clone.id, entry_clone.clone());
                assert!(old_nat_val.is_none());

                tasks.lock().unwrap().spawn(Self::connect_to_nat_dst(
                    net_ns.clone(),
                    tcp_stream,
                    conn_map.clone(),
                    addr_conn_map.clone(),
                    entry_clone,
                ));
            }
            tracing::error!("nat tcp listener exited");
            panic!("nat tcp listener exited");
        };
        self.tasks
            .lock()
            .unwrap()
            .spawn(accept_task.instrument(tracing::info_span!("tcp_proxy_listener")));

        Ok(())
    }

    fn remove_entry_from_all_conn_map(
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        conn_map.remove(&nat_entry.id);
        addr_conn_map.remove_if(&nat_entry.src, |_, entry| entry.id == nat_entry.id);
    }

    async fn connect_to_nat_dst(
        net_ns: NetNS,
        src_tcp_stream: TcpStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        if let Err(e) = src_tcp_stream.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }

        let _guard = net_ns.guard();
        let socket = TcpSocket::new_v4().unwrap();
        if let Err(e) = socket.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }
        let Ok(Ok(dst_tcp_stream)) = tokio::time::timeout(
            Duration::from_secs(10),
            TcpSocket::new_v4().unwrap().connect(nat_entry.dst),
        )
        .await
        else {
            tracing::error!("connect to dst failed: {:?}", nat_entry);
            nat_entry.state.store(NatDstEntryState::Closed);
            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry);
            return;
        };
        drop(_guard);

        assert_eq!(nat_entry.state.load(), NatDstEntryState::ConnectingDst);
        nat_entry.state.store(NatDstEntryState::Connected);

        Self::handle_nat_connection(
            src_tcp_stream,
            dst_tcp_stream,
            conn_map,
            addr_conn_map,
            nat_entry,
        )
        .await;
    }

    async fn handle_nat_connection(
        mut src_tcp_stream: TcpStream,
        mut dst_tcp_stream: TcpStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        let nat_entry_clone = nat_entry.clone();
        nat_entry.tasks.lock().await.spawn(async move {
            let ret = copy_bidirectional(&mut src_tcp_stream, &mut dst_tcp_stream).await;
            tracing::trace!(nat_entry = ?nat_entry_clone, ret = ?ret, "nat tcp connection closed");
            nat_entry_clone.state.store(NatDstEntryState::Closed);

            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry_clone);
        });
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_port.load(std::sync::atomic::Ordering::Relaxed)
    }
}
