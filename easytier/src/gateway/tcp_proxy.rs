use anyhow::Context;
use cidr::Ipv4Inet;
use core::panic;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpPacket};
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use socket2::{SockRef, TcpKeepalive};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::Instrument;

use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::join_joinset_background;

use crate::peers::peer_manager::PeerManager;
use crate::peers::{NicPacketFilter, PeerPacketFilter};
use crate::proto::cli::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::{PacketType, PeerManagerHeader, ZCPacket};

use super::CidrSet;

#[cfg(feature = "smoltcp")]
use super::tokio_smoltcp::{self, channel_device, Net, NetConfig};

#[async_trait::async_trait]
pub(crate) trait NatDstConnector: Send + Sync + Clone + 'static {
    type DstStream: AsyncRead + AsyncWrite + Unpin + Send;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> Result<Self::DstStream>;
    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool;
    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &Ipv4Packet,
    ) -> bool;
    fn transport_type(&self) -> TcpProxyEntryTransportType;
}

#[derive(Debug, Clone)]
pub struct NatDstTcpConnector;

#[async_trait::async_trait]
impl NatDstConnector for NatDstTcpConnector {
    type DstStream = TcpStream;
    async fn connect(&self, _src: SocketAddr, nat_dst: SocketAddr) -> Result<Self::DstStream> {
        let socket = TcpSocket::new_v4().unwrap();
        if let Err(e) = socket.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }

        const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(5);
        const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
        const TCP_KEEPALIVE_RETRIES: u32 = 2;

        let stream = timeout(Duration::from_secs(10), socket.connect(nat_dst))
            .await?
            .with_context(|| format!("connect to nat dst failed: {:?}", nat_dst))?;

        let ka = TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_TIME)
            .with_interval(TCP_KEEPALIVE_INTERVAL);

        #[cfg(not(target_os = "windows"))]
        let ka = ka.with_retries(TCP_KEEPALIVE_RETRIES);

        let sf = SockRef::from(&stream);
        sf.set_tcp_keepalive(&ka)?;

        Ok(stream)
    }

    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool {
        !cidr_set.is_empty() || global_ctx.enable_exit_node() || global_ctx.no_tun()
    }

    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &Ipv4Packet,
    ) -> bool {
        let is_exit_node = hdr.is_exit_node();

        if !cidr_set.contains_v4(ipv4.get_destination())
            && !is_exit_node
            && !(global_ctx.no_tun()
                && Some(ipv4.get_destination())
                    == global_ctx.get_ipv4().as_ref().map(Ipv4Inet::address))
        {
            return false;
        }

        true
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Tcp
    }
}

type NatDstEntryState = TcpProxyEntryState;

#[derive(Debug)]
pub struct NatDstEntry {
    id: uuid::Uuid,
    src: SocketAddr,
    dst: SocketAddr,
    start_time: Instant,
    start_time_local: chrono::DateTime<chrono::Local>,
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
            start_time_local: chrono::Local::now(),
            tasks: Mutex::new(JoinSet::new()),
            state: AtomicCell::new(NatDstEntryState::SynReceived),
        }
    }

    fn into_pb(&self, transport_type: TcpProxyEntryTransportType) -> TcpProxyEntry {
        TcpProxyEntry {
            src: Some(self.src.clone().into()),
            dst: Some(self.dst.clone().into()),
            start_time: self.start_time_local.timestamp() as u64,
            state: self.state.load().into(),
            transport_type: transport_type.into(),
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

    pub async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::KernelTcpStream(stream) => {
                stream.shutdown().await?;
                Ok(())
            }
            #[cfg(feature = "smoltcp")]
            Self::SmolTcpStream(stream) => {
                stream.shutdown().await?;
                Ok(())
            }
        }
    }

    pub async fn copy_bidirectional<D: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        dst: &mut D,
    ) -> Result<()> {
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
                let mut not_listening_count = 0;
                loop {
                    select! {
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {
                            if tcp.is_listening() {
                                not_listening_count = 0;
                                continue;
                            }

                            not_listening_count += 1;
                            if not_listening_count >= 2 {
                                tracing::error!("smol tcp listener not listening");
                                tcp.relisten();
                            }
                        }
                        accept_ret = tcp.accept() => {
                            tx.send(accept_ret.map_err(|e| {
                                anyhow::anyhow!("smol tcp listener accept failed: {:?}", e).into()
                            }))
                            .unwrap();
                            not_listening_count = 0;
                        }
                    }
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
pub struct TcpProxy<C: NatDstConnector> {
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

    connector: C,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> PeerPacketFilter for TcpProxy<C> {
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
impl<C: NatDstConnector> NicPacketFilter for TcpProxy<C> {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        let Some(my_ipv4_inet) = self.get_local_inet() else {
            return false;
        };
        let my_ipv4 = my_ipv4_inet.address();

        let data = zc_packet.payload();
        let ip_packet = Ipv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4
            || ip_packet.get_source() != my_ipv4
            || ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return false;
        }

        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();
        if tcp_packet.get_source() != self.get_local_port() {
            return false;
        }

        let mut dst_addr = SocketAddr::V4(SocketAddrV4::new(
            ip_packet.get_destination(),
            tcp_packet.get_destination(),
        ));
        let mut need_transform_dst = false;

        // for kcp proxy, the src ip of nat entry will be converted from my ip to fake ip
        // here we need to convert it back
        if !self.is_smoltcp_enabled() && dst_addr.ip() == Self::get_fake_local_ipv4(&my_ipv4_inet) {
            dst_addr.set_ip(IpAddr::V4(my_ipv4));
            need_transform_dst = true;
        }

        tracing::trace!(dst_addr = ?dst_addr, "tcp packet try find entry");
        let entry = if let Some(entry) = self.addr_conn_map.get(&dst_addr) {
            entry
        } else {
            let Some(syn_entry) = self.syn_map.get(&dst_addr) else {
                return false;
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
        if need_transform_dst {
            zc_packet.mut_peer_manager_header().unwrap().to_peer_id = self.get_my_peer_id().into();
        }

        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload()).unwrap();
        ip_packet.set_source(ip);
        if need_transform_dst {
            ip_packet.set_destination(my_ipv4);
        }
        let dst = ip_packet.get_destination();

        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(nat_entry.dst.port());

        Self::update_tcp_packet_checksum(&mut tcp_packet, &ip, &dst);
        drop(tcp_packet);
        Self::update_ip_packet_checksum(&mut ip_packet);

        tracing::trace!(dst_addr = ?dst_addr, nat_entry = ?nat_entry, packet = ?ip_packet, "tcp packet after modified");

        true
    }
}

impl<C: NatDstConnector> TcpProxy<C> {
    pub fn new(peer_manager: Arc<PeerManager>, connector: C) -> Arc<Self> {
        let (smoltcp_stack_sender, smoltcp_stack_receiver) = mpsc::channel::<ZCPacket>(1000);
        let global_ctx = peer_manager.get_global_ctx();

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

            connector,
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

    pub async fn start(self: &Arc<Self>, add_pipeline: bool) -> Result<()> {
        self.run_syn_map_cleaner().await?;
        self.run_listener().await?;
        if add_pipeline {
            self.peer_manager
                .add_packet_process_pipeline(Box::new(self.clone()))
                .await;
            self.peer_manager
                .add_nic_packet_process_pipeline(Box::new(self.clone()))
                .await;
        }
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
        if self.global_ctx.get_flags().use_smoltcp
            || self.global_ctx.no_tun()
            || cfg!(target_os = "android")
        {
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
        let connector = self.connector.clone();
        let accept_task = async move {
            let conn_map = conn_map.clone();
            loop {
                let accept_ret = tcp_listener.accept().await;
                let Ok((tcp_stream, mut socket_addr)) = accept_ret else {
                    tracing::error!("nat tcp listener accept failed: {:?}", accept_ret.err());
                    continue;
                };

                let my_ip_inet = global_ctx.get_ipv4();
                let my_ip = my_ip_inet
                    .as_ref()
                    .map(Ipv4Inet::address)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);

                if my_ip_inet.is_some()
                    && socket_addr.ip() == Self::get_fake_local_ipv4(&my_ip_inet.unwrap())
                {
                    socket_addr.set_ip(IpAddr::V4(my_ip));
                }

                let Some(entry) = syn_map.get(&socket_addr) else {
                    tracing::error!(
                        ?my_ip,
                        ?socket_addr,
                        "tcp connection from unknown source, ignore it"
                    );
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
                    connector.clone(),
                    global_ctx.clone(),
                    tcp_stream,
                    conn_map.clone(),
                    addr_conn_map.clone(),
                    entry_clone,
                ));
            }
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
        connector: C,
        global_ctx: ArcGlobalCtx,
        src_tcp_stream: ProxyTcpStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        if let Err(e) = src_tcp_stream.set_nodelay(true) {
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

        let _guard = global_ctx.net_ns.guard();
        let Ok(dst_tcp_stream) = connector.connect(nat_entry.src, nat_dst).await else {
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
        mut dst_tcp_stream: C::DstStream,
        conn_map: ConnSockMap,
        addr_conn_map: AddrConnSockMap,
        nat_entry: ArcNatDstEntry,
    ) {
        let nat_entry_clone = nat_entry.clone();
        nat_entry.tasks.lock().await.spawn(async move {
            let ret = src_tcp_stream.copy_bidirectional(&mut dst_tcp_stream).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "nat tcp connection closed");

            nat_entry_clone.state.store(NatDstEntryState::ClosingSrc);
            let ret = timeout(Duration::from_secs(10), src_tcp_stream.shutdown()).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "src tcp stream shutdown");

            nat_entry_clone.state.store(NatDstEntryState::ClosingDst);
            let ret = timeout(Duration::from_secs(10), dst_tcp_stream.shutdown()).await;
            tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "dst tcp stream shutdown");

            drop(src_tcp_stream);
            drop(dst_tcp_stream);

            nat_entry_clone.state.store(NatDstEntryState::Closed);
            // sleep later so the fin packet can be processed
            tokio::time::sleep(Duration::from_secs(10)).await;

            Self::remove_entry_from_all_conn_map(conn_map, addr_conn_map, nat_entry_clone);
        });
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_port.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_my_peer_id(&self) -> u32 {
        self.peer_manager.my_peer_id()
    }

    pub fn get_local_ip(&self) -> Option<Ipv4Addr> {
        self.get_local_inet().map(|inet| inet.address())
    }

    pub fn get_local_inet(&self) -> Option<Ipv4Inet> {
        if self.is_smoltcp_enabled() {
            Some(Ipv4Inet::new(Ipv4Addr::new(192, 88, 99, 254), 24).unwrap())
        } else {
            self.global_ctx.get_ipv4().as_ref().cloned()
        }
    }

    pub fn get_global_ctx(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub fn is_smoltcp_enabled(&self) -> bool {
        self.enable_smoltcp
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_fake_local_ipv4(local_ip: &Ipv4Inet) -> Ipv4Addr {
        local_ip.first_address()
    }

    async fn try_handle_peer_packet(&self, packet: &mut ZCPacket) -> Option<()> {
        if !self
            .connector
            .check_packet_from_peer_fast(&self.cidr_set, &self.global_ctx)
        {
            return None;
        }

        let ipv4_inet = self.get_local_inet()?;
        let ipv4_addr = ipv4_inet.address();
        let hdr = packet.peer_manager_header().unwrap().clone();

        if hdr.packet_type != PacketType::Data as u8 || hdr.is_no_proxy() {
            return None;
        };

        let payload_bytes = packet.mut_payload();

        let ipv4 = Ipv4Packet::new(payload_bytes)?;
        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None;
        }

        if !self
            .connector
            .check_packet_from_peer(&self.cidr_set, &self.global_ctx, &hdr, &ipv4)
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
        if !self.is_smoltcp_enabled() && source_ip == ipv4_addr {
            // modify the source so the response packet can be handled by tun device
            ip_packet.set_source(Self::get_fake_local_ipv4(&ipv4_inet));
        }
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

    pub fn get_peer_manager(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }

    pub fn is_tcp_proxy_connection(&self, src: SocketAddr) -> bool {
        self.syn_map.contains_key(&src) || self.addr_conn_map.contains_key(&src)
    }

    pub fn list_proxy_entries(&self) -> Vec<TcpProxyEntry> {
        let mut entries: Vec<TcpProxyEntry> = Vec::new();
        let transport_type = self.connector.transport_type();
        for entry in self.syn_map.iter() {
            entries.push(entry.value().as_ref().into_pb(transport_type));
        }
        for entry in self.conn_map.iter() {
            entries.push(entry.value().as_ref().into_pb(transport_type));
        }
        entries
    }
}

#[derive(Clone)]
pub struct TcpProxyRpcService<C: NatDstConnector> {
    tcp_proxy: Weak<TcpProxy<C>>,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> TcpProxyRpc for TcpProxyRpcService<C> {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.tcp_proxy.upgrade() {
            reply.entries = tcp_proxy.list_proxy_entries();
        }
        Ok(reply)
    }
}

impl<C: NatDstConnector> TcpProxyRpcService<C> {
    pub fn new(tcp_proxy: Arc<TcpProxy<C>>) -> Self {
        Self {
            tcp_proxy: Arc::downgrade(&tcp_proxy),
        }
    }
}
