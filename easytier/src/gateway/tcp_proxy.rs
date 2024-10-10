use cidr::Ipv4Inet;
use core::panic;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpPacket};
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::join_joinset_background;

use crate::peers::peer_manager::PeerManager;
use crate::peers::{NicPacketFilter, PeerPacketFilter};
use crate::tunnel::packet_def::{PacketType, ZCPacket};

use super::CidrSet;

#[cfg(feature = "smoltcp")]
use super::tokio_smoltcp::{self, channel_device, Net, NetConfig};

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

enum ProxyTcpStream {
    KernelTcpStream(TcpStream),
    #[cfg(feature = "smoltcp")]
    SmolTcpStream(tokio_smoltcp::TcpStream),
}

impl ProxyTcpStream {
    pub fn set_nodelay(&self, nodelay: bool) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => stream.set_nodelay(nodelay).map_err(Into::into),
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(_stream) => {
                tracing::warn!("smol tcp stream set_nodelay not implemented");
                Ok(())
            }
        }
    }

    pub async fn copy_bidirectional(&mut self, dst: &mut TcpStream) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => {
                copy_bidirectional(stream, dst).await?;
                Ok(())
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(stream) => {
                copy_bidirectional(stream, dst).await?;
                Ok(())
            }
        }
    }
}

#[cfg(feature = "smoltcp")]
struct SmolTcpListener {
    listener_task: JoinSet<()>,
    listen_count: usize,

    stream_rx: mpsc::UnboundedReceiver<Result<(tokio_smoltcp::TcpStream, SocketAddr)>>,
}

#[cfg(feature = "smoltcp")]
impl SmolTcpListener {
    pub async fn new(net: Arc<Mutex<Option<Net>>>, listen_count: usize) -> Self {
        let mut tasks = JoinSet::new();

        let (tx, rx) = mpsc::unbounded_channel();
        let locked_net = net.lock().await;
        for _ in 0..listen_count {
            let mut tcp = locked_net
                .as_ref()
                .unwrap()
                .tcp_bind("0.0.0.0:8899".parse().unwrap())
                .await
                .unwrap();
            let tx = tx.clone();
            tasks.spawn(async move {
                loop {
                    tx.send(tcp.accept().await.map_err(|e| {
                        anyhow::anyhow!("smol tcp listener accept failed: {:?}", e).into()
                    }))
                    .unwrap();
                }
            });
        }

        Self {
            listener_task: tasks,
            listen_count,
            stream_rx: rx,
        }
    }

    pub async fn accept(&mut self) -> Result<(tokio_smoltcp::TcpStream, SocketAddr)> {
        self.stream_rx.recv().await.unwrap()
    }
}

enum ProxyTcpListener {
    KernelTcpListener(TcpListener),
    #[cfg(feature = "smoltcp")]
    SmolTcpListener(SmolTcpListener),
}

impl ProxyTcpListener {
    pub async fn accept(&mut self) -> Result<(ProxyTcpStream, SocketAddr)> {
        match self {
            Self::KernelTcpListener(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((ProxyTcpStream::KernelTcpStream(stream), addr))
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpListener(listener) => {
                let Ok((stream, src)) = listener.accept().await else {
                    return Err(anyhow::anyhow!("smol tcp listener closed").into());
                };
                tracing::info!(?src, "smol tcp listener accepted");
                Ok((ProxyTcpStream::SmolTcpStream(stream), src))
            }
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

    smoltcp_stack_sender: Option<mpsc::Sender<ZCPacket>>,
    smoltcp_stack_receiver: Arc<Mutex<Option<mpsc::Receiver<ZCPacket>>>>,
    #[cfg(feature = "smoltcp")]
    smoltcp_net: Arc<Mutex<Option<Net>>>,
    enable_smoltcp: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl PeerPacketFilter for TcpProxy {
    async fn try_process_packet_from_peer(&self, mut packet: ZCPacket) -> Option<ZCPacket> {
        if let Some(_) = self.try_handle_peer_packet(&mut packet).await {
            if self
                .enable_smoltcp
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                let smoltcp_stack_sender = self.smoltcp_stack_sender.as_ref().unwrap();
                if let Err(e) = smoltcp_stack_sender.try_send(packet) {
                    tracing::error!("send to smoltcp stack failed: {:?}", e);
                }
            } else {
                if let Err(e) = self.peer_manager.get_nic_channel().send(packet).await {
                    tracing::error!("send to nic failed: {:?}", e);
                }
            }
            return None;
        } else {
            Some(packet)
        }
    }
}

#[async_trait::async_trait]
impl NicPacketFilter for TcpProxy {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) {
        let Some(my_ipv4) = self.get_local_ip() else {
            return;
        };

        let data = zc_packet.payload();
        let ip_packet = Ipv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4
            || ip_packet.get_source() != my_ipv4
            || ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return;
        }

        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();
        if tcp_packet.get_source() != self.get_local_port() {
            return;
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
                return;
            };
            syn_entry
        };
        let nat_entry = entry.clone();
        drop(entry);
        assert_eq!(nat_entry.src, dst_addr);

        let IpAddr::V4(ip) = nat_entry.dst.ip() else {
            panic!("v4 nat entry src ip is not v4");
        };

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_no_proxy(true);

        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload()).unwrap();
        ip_packet.set_source(ip);
        let dst = ip_packet.get_destination();

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(nat_entry.dst.port());

        Self::update_tcp_packet_checksum(&mut tcp_packet, &ip, &dst);
        drop(tcp_packet);
        Self::update_ip_packet_checksum(&mut ip_packet);

        tracing::trace!(dst_addr = ?dst_addr, nat_entry = ?nat_entry, packet = ?ip_packet, "tcp packet after modified");
    }
}

impl TcpProxy {
    pub fn new(global_ctx: Arc<GlobalCtx>, peer_manager: Arc<PeerManager>) -> Arc<Self> {
        let (smoltcp_stack_sender, smoltcp_stack_receiver) = mpsc::channel::<ZCPacket>(1000);

        Arc::new(Self {
            global_ctx: global_ctx.clone(),
            peer_manager,

            local_port: AtomicU16::new(0),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),

            syn_map: Arc::new(DashMap::new()),
            conn_map: Arc::new(DashMap::new()),
            addr_conn_map: Arc::new(DashMap::new()),

            cidr_set: CidrSet::new(global_ctx),

            smoltcp_stack_sender: Some(smoltcp_stack_sender),
            smoltcp_stack_receiver: Arc::new(Mutex::new(Some(smoltcp_stack_receiver))),

            #[cfg(feature = "smoltcp")]
            smoltcp_net: Arc::new(Mutex::new(None)),

            enable_smoltcp: Arc::new(AtomicBool::new(true)),
        })
    }

    fn update_tcp_packet_checksum(
        tcp_packet: &mut MutableTcpPacket,
        ipv4_src: &Ipv4Addr,
        ipv4_dst: &Ipv4Addr,
    ) {
        tcp_packet.set_checksum(ipv4_checksum(
            &tcp_packet.to_immutable(),
            ipv4_src,
            ipv4_dst,
        ));
    }

    fn update_ip_packet_checksum(ip_packet: &mut MutableIpv4Packet) {
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
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

    async fn get_proxy_listener(&self) -> Result<ProxyTcpListener> {
        #[cfg(feature = "smoltcp")]
        if self.global_ctx.get_flags().use_smoltcp || self.global_ctx.no_tun() {
            // use smoltcp network stack
            self.local_port
                .store(8899, std::sync::atomic::Ordering::Relaxed);

            let mut cap = smoltcp::phy::DeviceCapabilities::default();
            cap.max_transmission_unit = 1280;
            cap.medium = smoltcp::phy::Medium::Ip;
            let (dev, stack_sink, mut stack_stream) = channel_device::ChannelDevice::new(cap);

            let mut smoltcp_stack_receiver =
                self.smoltcp_stack_receiver.lock().await.take().unwrap();
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(packet) = smoltcp_stack_receiver.recv().await {
                    tracing::trace!(?packet, "receive from peer send to smoltcp packet");
                    if let Err(e) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                        tracing::error!("send to smoltcp stack failed: {:?}", e);
                    }
                }
                tracing::error!("smoltcp stack sink exited");
                panic!("smoltcp stack sink exited");
            });

            let peer_mgr = self.peer_manager.clone();
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(data) = stack_stream.recv().await {
                    tracing::trace!(
                        ?data,
                        "receive from smoltcp stack and send to peer mgr packet"
                    );
                    let Some(ipv4) = Ipv4Packet::new(&data) else {
                        tracing::error!(?data, "smoltcp stack stream get non ipv4 packet");
                        continue;
                    };

                    let dst = ipv4.get_destination();
                    let packet = ZCPacket::new_with_payload(&data);
                    if let Err(e) = peer_mgr.send_msg_ipv4(packet, dst).await {
                        tracing::error!("send to peer failed in smoltcp sender: {:?}", e);
                    }
                }
                tracing::error!("smoltcp stack stream exited");
                panic!("smoltcp stack stream exited");
            });

            let interface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
            let net = Net::new(
                dev,
                NetConfig::new(
                    interface_config,
                    format!("{}/24", self.get_local_ip().unwrap())
                        .parse()
                        .unwrap(),
                    vec![format!("{}", self.get_local_ip().unwrap()).parse().unwrap()],
                ),
            );
            net.set_any_ip(true);
            self.smoltcp_net.lock().await.replace(net);
            let tcp = SmolTcpListener::new(self.smoltcp_net.clone(), 64).await;

            self.enable_smoltcp
                .store(true, std::sync::atomic::Ordering::Relaxed);

            return Ok(ProxyTcpListener::SmolTcpListener(tcp));
        }

        {
            // use kernel network stack
            let listen_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
            let net_ns = self.global_ctx.net_ns.clone();
            let tcp_listener = net_ns
                .run_async(|| async { TcpListener::bind(&listen_addr).await })
                .await?;
            self.local_port.store(
                tcp_listener.local_addr()?.port(),
                std::sync::atomic::Ordering::Relaxed,
            );

            self.enable_smoltcp
                .store(false, std::sync::atomic::Ordering::Relaxed);

            return Ok(ProxyTcpListener::KernelTcpListener(tcp_listener));
        }
    }

    async fn run_listener(&self) -> Result<()> {
        // bind on both v4 & v6
        let mut tcp_listener = self.get_proxy_listener().await?;

        let global_ctx = self.global_ctx.clone();
        let tasks = self.tasks.clone();
        let syn_map = self.syn_map.clone();
        let conn_map = self.conn_map.clone();
        let addr_conn_map = self.addr_conn_map.clone();
        let accept_task = async move {
            let conn_map = conn_map.clone();
            while let Ok((tcp_stream, socket_addr)) = tcp_listener.accept().await {
                let Some(entry) = syn_map.get(&socket_addr) else {
                    tracing::error!("tcp connection from unknown source: {:?}", socket_addr);
                    continue;
                };
                tracing::info!(
                    ?socket_addr,
                    "tcp connection accepted for proxy, nat dst: {:?}",
                    entry.dst
                );
                assert_eq!(entry.state.load(), NatDstEntryState::SynReceived);

                let entry_clone = entry.clone();
                drop(entry);
                syn_map.remove_if(&socket_addr, |_, entry| entry.id == entry_clone.id);

                entry_clone.state.store(NatDstEntryState::ConnectingDst);

                let _ = addr_conn_map.insert(entry_clone.src, entry_clone.clone());
                let old_nat_val = conn_map.insert(entry_clone.id, entry_clone.clone());
                assert!(old_nat_val.is_none());

                tasks.lock().unwrap().spawn(Self::connect_to_nat_dst(
                    global_ctx.clone(),
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
        global_ctx: ArcGlobalCtx,
        src_tcp_stream: ProxyTcpStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        if let Err(e) = src_tcp_stream.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }

        let _guard = global_ctx.net_ns.guard();
        let socket = TcpSocket::new_v4().unwrap();
        if let Err(e) = socket.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }

        let nat_dst = if Some(nat_entry.dst.ip())
            == global_ctx.get_ipv4().map(|ip| IpAddr::V4(ip.address()))
        {
            format!("127.0.0.1:{}", nat_entry.dst.port())
                .parse()
                .unwrap()
        } else {
            nat_entry.dst
        };

        let Ok(Ok(dst_tcp_stream)) = tokio::time::timeout(
            Duration::from_secs(10),
            TcpSocket::new_v4().unwrap().connect(nat_dst),
        )
        .await
        else {
            tracing::error!("connect to dst failed: {:?}", nat_entry);
            nat_entry.state.store(NatDstEntryState::Closed);
            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry);
            return;
        };
        drop(_guard);

        tracing::info!(?nat_entry, ?nat_dst, "tcp connection to dst established");

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
        mut src_tcp_stream: ProxyTcpStream,
        mut dst_tcp_stream: TcpStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        let nat_entry_clone = nat_entry.clone();
        nat_entry.tasks.lock().await.spawn(async move {
            let ret = src_tcp_stream.copy_bidirectional(&mut dst_tcp_stream).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "nat tcp connection closed");
            nat_entry_clone.state.store(NatDstEntryState::Closed);

            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry_clone);
        });
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_port.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_local_ip(&self) -> Option<Ipv4Addr> {
        if self
            .enable_smoltcp
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            Some(Ipv4Addr::new(192, 88, 99, 254))
        } else {
            self.global_ctx
                .get_ipv4()
                .as_ref()
                .map(cidr::Ipv4Inet::address)
        }
    }

    async fn try_handle_peer_packet(&self, packet: &mut ZCPacket) -> Option<()> {
        if self.cidr_set.is_empty()
            && !self.global_ctx.enable_exit_node()
            && !self.global_ctx.no_tun()
        {
            return None;
        }

        let ipv4_addr = self.get_local_ip()?;
        let hdr = packet.peer_manager_header().unwrap();
        let is_exit_node = hdr.is_exit_node();

        if hdr.packet_type != PacketType::Data as u8 || hdr.is_no_proxy() {
            return None;
        };

        let payload_bytes = packet.mut_payload();

        let ipv4 = Ipv4Packet::new(payload_bytes)?;
        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None;
        }

        if !self.cidr_set.contains_v4(ipv4.get_destination())
            && !is_exit_node
            && !(self.global_ctx.no_tun()
                && Some(ipv4.get_destination())
                    == self.global_ctx.get_ipv4().as_ref().map(Ipv4Inet::address))
        {
            return None;
        }

        tracing::trace!(ipv4 = ?ipv4, cidr_set = ?self.cidr_set, "proxy tcp packet received");

        let ip_packet = Ipv4Packet::new(payload_bytes).unwrap();
        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

        let source_ip = ip_packet.get_source();
        let source_port = tcp_packet.get_source();
        let src = SocketAddr::V4(SocketAddrV4::new(source_ip, source_port));

        let is_tcp_syn = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0;
        let is_tcp_ack = tcp_packet.get_flags() & pnet::packet::tcp::TcpFlags::ACK != 0;
        if is_tcp_syn && !is_tcp_ack {
            let dest_ip = ip_packet.get_destination();
            let dest_port = tcp_packet.get_destination();
            let dst = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));

            let old_val = self
                .syn_map
                .insert(src, Arc::new(NatDstEntry::new(src, dst)));
            tracing::info!(src = ?src, dst = ?dst, old_entry = ?old_val, "tcp syn received");
        } else if !self.addr_conn_map.contains_key(&src) && !self.syn_map.contains_key(&src) {
            // if not in syn map and addr conn map, may forwarding n2n packet
            return None;
        }

        let mut ip_packet = MutableIpv4Packet::new(payload_bytes).unwrap();
        ip_packet.set_destination(ipv4_addr);
        let source = ip_packet.get_source();

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_destination(self.get_local_port());

        Self::update_tcp_packet_checksum(&mut tcp_packet, &source, &ipv4_addr);
        drop(tcp_packet);
        Self::update_ip_packet_checksum(&mut ip_packet);

        tracing::trace!(?source, ?ipv4_addr, ?packet, "tcp packet after modified");

        Some(())
    }
}
