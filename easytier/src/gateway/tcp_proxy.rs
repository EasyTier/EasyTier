use anyhow::Context;
use cidr::Ipv4Inet;
use easytier_core::proxy::tcp_proxy::{
    TcpNatEntry, TcpNatEntrySnapshot, TcpNatEntryState as CoreTcpNatEntryState, TcpProxyCore,
    TcpProxyMode, TcpProxyNicContext, TcpProxyPacketAction, TcpProxyPeerContext,
};
use socket2::{SockRef, TcpKeepalive};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::Instrument;

use crate::common::error::Result;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::join_joinset_background;
use crate::common::log;
use crate::common::stats_manager::{LabelSet, LabelType, MetricName};
use crate::peers::peer_manager::PeerManager;
use crate::peers::{NicPacketFilter, PeerPacketFilter};
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::ZCPacket;

use super::CidrSet;

#[cfg(feature = "smoltcp")]
use super::tokio_smoltcp::{self, Net, NetConfig, channel_device};
#[cfg(feature = "smoltcp")]
use smoltcp::wire::Ipv4Packet;

#[async_trait::async_trait]
pub(crate) trait NatDstConnector: Send + Sync + Clone + 'static {
    type DstStream: AsyncRead + AsyncWrite + Unpin + Send;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream>;
    fn proxy_mode(&self) -> TcpProxyMode;
    fn transport_type(&self) -> TcpProxyEntryTransportType;
}

#[derive(Debug, Clone)]
pub struct NatDstTcpConnector;

#[async_trait::async_trait]
impl NatDstConnector for NatDstTcpConnector {
    type DstStream = TcpStream;
    async fn connect(
        &self,
        _src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> anyhow::Result<Self::DstStream> {
        let socket = TcpSocket::new_v4()
            .inspect_err(|error| log::error!(?error, "create v4 socket failed"))?;

        let stream = timeout(Duration::from_secs(10), socket.connect(nat_dst))
            .await?
            .with_context(|| format!("connect to nat dst failed: {:?}", nat_dst))?;

        prepare_kernel_tcp_socket(&stream)?;

        Ok(stream)
    }

    fn proxy_mode(&self) -> TcpProxyMode {
        TcpProxyMode::Tcp
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Tcp
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
type SmolTcpAcceptResult = Result<(tokio_smoltcp::TcpStream, SocketAddr)>;
#[cfg(feature = "smoltcp")]
struct SmolTcpListener {
    stream_tx: mpsc::UnboundedSender<SmolTcpAcceptResult>,
    stream_rx: mpsc::UnboundedReceiver<SmolTcpAcceptResult>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

#[cfg(feature = "smoltcp")]
impl SmolTcpListener {
    pub async fn new() -> Self {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "smoltcp listener".to_owned());

        let (tx, rx) = mpsc::unbounded_channel();

        Self {
            stream_tx: tx,
            stream_rx: rx,
            tasks,
        }
    }

    pub async fn accept(&mut self) -> SmolTcpAcceptResult {
        self.stream_rx.recv().await.unwrap()
    }

    pub fn stream_tx(&self) -> mpsc::UnboundedSender<SmolTcpAcceptResult> {
        self.stream_tx.clone()
    }

    pub async fn add_listener(
        tx: mpsc::UnboundedSender<SmolTcpAcceptResult>,
        net: Arc<Mutex<Option<Net>>>,
        tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    ) {
        let locked_net = net.lock().await;
        let mut tcp = locked_net
            .as_ref()
            .unwrap()
            .tcp_bind("0.0.0.0:8899".parse().unwrap())
            .await
            .unwrap();
        tasks.lock().unwrap().spawn(async move {
            let ret = timeout(Duration::from_secs(10), tcp.accept()).await;
            if let Ok(accept_ret) = ret {
                tx.send(accept_ret.map_err(|e| {
                    anyhow::anyhow!("smol tcp listener accept failed: {:?}", e).into()
                }))
                .unwrap();
            } else {
                tracing::error!("smol tcp listener accept timeout");
            }
        });
    }
}

enum ProxyTcpListener {
    KernelTcpListener(TcpListener),
    #[cfg(feature = "smoltcp")]
    SmolTcpListener(SmolTcpListener),
}

fn prepare_kernel_tcp_socket(stream: &TcpStream) -> Result<()> {
    const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(5);
    const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
    const TCP_KEEPALIVE_RETRIES: u32 = 2;

    let ka = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);

    #[cfg(not(target_os = "windows"))]
    let ka = ka.with_retries(TCP_KEEPALIVE_RETRIES);

    let sf = SockRef::from(&stream);
    sf.set_tcp_keepalive(&ka)?;
    if let Err(e) = sf.set_nodelay(true) {
        tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
    }

    Ok(())
}

impl ProxyTcpListener {
    pub async fn accept(&mut self) -> Result<(ProxyTcpStream, SocketAddr)> {
        match self {
            Self::KernelTcpListener(listener) => {
                let (stream, addr) = listener.accept().await?;
                prepare_kernel_tcp_socket(&stream)?;
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

type ArcNatDstEntry = Arc<TcpNatEntry>;

#[derive(Debug)]
pub struct TcpProxy<C: NatDstConnector> {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Weak<PeerManager>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    cidr_set: CidrSet,
    core: Arc<TcpProxyCore>,

    smoltcp_stack_sender: Option<mpsc::Sender<ZCPacket>>,
    smoltcp_stack_receiver: Arc<Mutex<Option<mpsc::Receiver<ZCPacket>>>>,
    #[cfg(feature = "smoltcp")]
    smoltcp_net: Arc<Mutex<Option<Net>>>,
    #[cfg(feature = "smoltcp")]
    smoltcp_listener_tx: std::sync::Mutex<Option<mpsc::UnboundedSender<SmolTcpAcceptResult>>>,
    enable_smoltcp: Arc<AtomicBool>,

    connector: C,
}

#[async_trait::async_trait]
impl<C: NatDstConnector> PeerPacketFilter for TcpProxy<C> {
    async fn try_process_packet_from_peer(&self, mut packet: ZCPacket) -> Option<ZCPacket> {
        let action = self.core.try_handle_peer_packet(
            self.connector.proxy_mode(),
            &mut packet,
            TcpProxyPeerContext {
                local_inet: self.get_local_inet(),
                virtual_ipv4: self.global_ctx.get_ipv4().map(|inet| inet.address()),
                local_port: self.get_local_port(),
                enable_exit_node: self.global_ctx.enable_exit_node(),
                no_tun: self.global_ctx.no_tun(),
                smoltcp_enabled: self.is_smoltcp_enabled(),
            },
        );
        let TcpProxyPacketAction::Handled { new_syn: _new_syn } = action else {
            return Some(packet);
        };

        #[cfg(feature = "smoltcp")]
        if _new_syn && self.is_smoltcp_enabled() {
            let smoltcp_listener_tx = self.smoltcp_listener_tx.lock().unwrap().clone().unwrap();
            SmolTcpListener::add_listener(
                smoltcp_listener_tx,
                self.smoltcp_net.clone(),
                self.tasks.clone(),
            )
            .await;
            tracing::info!("smol tcp listener added");
        }

        if self.is_smoltcp_enabled() {
            let smoltcp_stack_sender = self.smoltcp_stack_sender.as_ref().unwrap();
            if let Err(e) = smoltcp_stack_sender.try_send(packet) {
                tracing::error!("send to smoltcp stack failed: {:?}", e);
            }
        } else if let Some(peer_manager) = self.get_peer_manager()
            && let Err(e) = peer_manager.get_nic_channel().send(packet).await
        {
            tracing::error!("send to nic failed: {:?}", e);
        }
        None
    }
}

#[async_trait::async_trait]
impl<C: NatDstConnector> NicPacketFilter for TcpProxy<C> {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        self.core.try_process_packet_from_nic(
            zc_packet,
            TcpProxyNicContext {
                local_inet: self.get_local_inet(),
                local_port: self.get_local_port(),
                my_peer_id: self.get_my_peer_id(),
                smoltcp_enabled: self.is_smoltcp_enabled(),
            },
        )
    }
}

impl<C: NatDstConnector> TcpProxy<C> {
    pub fn new(peer_manager: Arc<PeerManager>, connector: C) -> Arc<Self> {
        let (smoltcp_stack_sender, smoltcp_stack_receiver) = mpsc::channel::<ZCPacket>(1000);
        let global_ctx = peer_manager.get_global_ctx();
        let cidr_set = CidrSet::new(global_ctx.clone());
        let core = Arc::new(TcpProxyCore::new(cidr_set.table()));

        Arc::new(Self {
            global_ctx: global_ctx.clone(),
            peer_manager: Arc::downgrade(&peer_manager),

            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),

            cidr_set,
            core,

            smoltcp_stack_sender: Some(smoltcp_stack_sender),
            smoltcp_stack_receiver: Arc::new(Mutex::new(Some(smoltcp_stack_receiver))),

            #[cfg(feature = "smoltcp")]
            smoltcp_net: Arc::new(Mutex::new(None)),
            #[cfg(feature = "smoltcp")]
            smoltcp_listener_tx: std::sync::Mutex::new(None),

            enable_smoltcp: Arc::new(AtomicBool::new(true)),

            connector,
        })
    }

    pub fn get_peer_manager(&self) -> Option<Arc<PeerManager>> {
        self.peer_manager.upgrade()
    }

    pub async fn start(self: &Arc<Self>, add_pipeline: bool) -> Result<()> {
        self.run_syn_map_cleaner().await?;
        self.run_listener().await?;
        if add_pipeline {
            let peer_manager = self
                .get_peer_manager()
                .ok_or_else(|| anyhow::anyhow!("peer manager is gone"))?;
            peer_manager
                .add_packet_process_pipeline(Box::new(self.clone()))
                .await;
            peer_manager
                .add_nic_packet_process_pipeline(Box::new(self.clone()))
                .await;
        }
        join_joinset_background(self.tasks.clone(), "TcpProxy".to_owned());

        Ok(())
    }

    async fn run_syn_map_cleaner(&self) -> Result<()> {
        let core = self.core.clone();
        let tasks = self.tasks.clone();
        let syn_map_cleaner_task = async move {
            loop {
                core.cleanup_expired_syn(Duration::from_secs(30));
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
            || cfg!(any(
                target_os = "android",
                any(
                    target_os = "ios",
                    all(target_os = "macos", feature = "macos-ne")
                ),
                target_env = "ohos"
            ))
        {
            // use smoltcp network stack

            use crate::gateway::tokio_smoltcp::BufferSize;
            self.core.set_local_port(8899);

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
            });

            let peer_mgr = self.peer_manager.clone();
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(data) = stack_stream.recv().await {
                    tracing::trace!(
                        ?data,
                        "receive from smoltcp stack and send to peer mgr packet"
                    );
                    let Ok(ipv4) = Ipv4Packet::new_checked(data.as_slice()) else {
                        tracing::error!(?data, "smoltcp stack stream get non ipv4 packet");
                        continue;
                    };

                    let dst = ipv4.dst_addr();
                    let packet = ZCPacket::new_with_payload(&data);
                    let Some(peer_mgr) = peer_mgr.upgrade() else {
                        tracing::warn!("peer manager is gone, smoltcp sender exited");
                        return;
                    };
                    if let Err(e) = peer_mgr
                        .send_msg_by_ip(packet, std::net::IpAddr::V4(dst), false)
                        .await
                    {
                        tracing::error!("send to peer failed in smoltcp sender: {:?}", e);
                    }
                }
                tracing::error!("smoltcp stack stream exited");
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
                    Some(BufferSize {
                        tcp_rx_size: 1024 * 16,
                        tcp_tx_size: 1024 * 16,
                        ..Default::default()
                    }),
                ),
            );
            net.set_any_ip(true);
            self.smoltcp_net.lock().await.replace(net);
            let tcp = SmolTcpListener::new().await;
            self.smoltcp_listener_tx
                .lock()
                .unwrap()
                .replace(tcp.stream_tx());

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
            self.core.set_local_port(tcp_listener.local_addr()?.port());

            self.enable_smoltcp
                .store(false, std::sync::atomic::Ordering::Relaxed);

            Ok(ProxyTcpListener::KernelTcpListener(tcp_listener))
        }
    }

    async fn run_listener(&self) -> Result<()> {
        // bind on both v4 & v6
        let mut tcp_listener = self.get_proxy_listener().await?;

        let global_ctx = self.global_ctx.clone();
        let tasks = Arc::downgrade(&self.tasks);
        let core = self.core.clone();
        let connector = self.connector.clone();
        let accept_task = async move {
            loop {
                let accept_ret = tcp_listener.accept().await;
                let Ok((tcp_stream, socket_addr)) = accept_ret else {
                    tracing::error!("nat tcp listener accept failed: {:?}", accept_ret.err());
                    continue;
                };

                let Some(entry) = core.accept_connection(socket_addr, global_ctx.get_ipv4()) else {
                    tracing::error!(
                        ?socket_addr,
                        "tcp connection from unknown source, ignore it"
                    );
                    continue;
                };
                tracing::info!(
                    ?socket_addr,
                    "tcp connection accepted for proxy, nat dst: {:?}",
                    entry.real_dst()
                );

                let Some(tasks) = tasks.upgrade() else {
                    tracing::error!("tcp proxy tasks is dropped, exit accept loop");
                    break;
                };

                tasks.lock().unwrap().spawn(Self::connect_to_nat_dst(
                    connector.clone(),
                    global_ctx.clone(),
                    tcp_stream,
                    core.clone(),
                    entry,
                ));
            }
        };
        self.tasks
            .lock()
            .unwrap()
            .spawn(accept_task.instrument(tracing::info_span!("tcp_proxy_listener")));

        Ok(())
    }

    async fn connect_to_nat_dst(
        connector: C,
        global_ctx: ArcGlobalCtx,
        src_tcp_stream: ProxyTcpStream,
        core: Arc<TcpProxyCore>,
        nat_entry: ArcNatDstEntry,
    ) {
        if let Err(e) = src_tcp_stream.set_nodelay(true) {
            tracing::warn!("set_nodelay failed, ignore it: {:?}", e);
        }

        if global_ctx.should_deny_proxy(&nat_entry.real_dst(), false) {
            tracing::error!(
                ?nat_entry,
                "nat dst port {} is in running listeners, ignore it",
                nat_entry.real_dst().port()
            );
            nat_entry.set_state(CoreTcpNatEntryState::Closed);
            core.remove_entry(nat_entry.id());
            return;
        }

        let nat_dst = if global_ctx.is_ip_local_virtual_ip(&nat_entry.real_dst().ip()) {
            format!("127.0.0.1:{}", nat_entry.real_dst().port())
                .parse()
                .unwrap()
        } else {
            nat_entry.real_dst()
        };

        global_ctx
            .stats_manager()
            .get_counter(
                MetricName::TcpProxyConnect,
                LabelSet::new()
                    .with_label_type(LabelType::Protocol(
                        connector.transport_type().as_str_name().to_string(),
                    ))
                    .with_label_type(LabelType::DstIp(nat_dst.ip().to_string()))
                    .with_label_type(LabelType::MappedDstIp(
                        nat_entry.mapped_dst().ip().to_string(),
                    )),
            )
            .inc();

        let _guard = global_ctx.net_ns.guard();
        let Ok(dst_tcp_stream) = connector.connect(nat_entry.src(), nat_dst).await else {
            tracing::error!("connect to dst failed: {:?}", nat_entry);
            nat_entry.set_state(CoreTcpNatEntryState::Closed);
            core.remove_entry(nat_entry.id());
            return;
        };
        drop(_guard);

        tracing::info!(?nat_entry, ?nat_dst, "tcp connection to dst established");

        assert_eq!(nat_entry.state(), CoreTcpNatEntryState::ConnectingDst);
        nat_entry.set_state(CoreTcpNatEntryState::Connected);

        Self::handle_nat_connection(src_tcp_stream, dst_tcp_stream, core, nat_entry).await;
    }

    async fn handle_nat_connection(
        mut src_tcp_stream: ProxyTcpStream,
        mut dst_tcp_stream: C::DstStream,
        core: Arc<TcpProxyCore>,
        nat_entry: ArcNatDstEntry,
    ) {
        let nat_entry_clone = nat_entry.clone();
        let ret = src_tcp_stream.copy_bidirectional(&mut dst_tcp_stream).await;
        tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "nat tcp connection closed");

        nat_entry_clone.set_state(CoreTcpNatEntryState::ClosingSrc);
        let ret = timeout(Duration::from_secs(10), src_tcp_stream.shutdown()).await;
        tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "src tcp stream shutdown");

        nat_entry_clone.set_state(CoreTcpNatEntryState::ClosingDst);
        let ret = timeout(Duration::from_secs(10), dst_tcp_stream.shutdown()).await;
        tracing::info!(nat_entry = ?nat_entry_clone, ret = ?ret, "dst tcp stream shutdown");

        drop(src_tcp_stream);
        drop(dst_tcp_stream);

        nat_entry_clone.set_state(CoreTcpNatEntryState::Closed);
        // sleep later so the fin packet can be processed
        tokio::time::sleep(Duration::from_secs(10)).await;

        core.remove_entry(nat_entry_clone.id());
    }

    pub fn get_local_port(&self) -> u16 {
        self.core.local_port()
    }

    pub fn get_my_peer_id(&self) -> u32 {
        self.peer_manager
            .upgrade()
            .map(|pm| pm.my_peer_id())
            .unwrap_or_default()
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

    pub fn is_tcp_proxy_connection(&self, src: SocketAddr) -> bool {
        self.core.is_tcp_proxy_connection(src)
    }

    pub fn list_proxy_entries(&self) -> Vec<TcpProxyEntry> {
        let transport_type = self.connector.transport_type();
        self.core
            .list_entries()
            .into_iter()
            .map(|entry| tcp_entry_snapshot_to_pb(entry, transport_type))
            .collect()
    }

    pub fn get_transport_type(&self) -> TcpProxyEntryTransportType {
        self.connector.transport_type()
    }
}

fn tcp_entry_snapshot_to_pb(
    entry: TcpNatEntrySnapshot,
    transport_type: TcpProxyEntryTransportType,
) -> TcpProxyEntry {
    TcpProxyEntry {
        src: Some(entry.src.into()),
        dst: Some(entry.dst.into()),
        start_time: entry.start_time,
        state: tcp_entry_state_to_pb(entry.state).into(),
        transport_type: transport_type.into(),
    }
}

fn tcp_entry_state_to_pb(state: CoreTcpNatEntryState) -> TcpProxyEntryState {
    match state {
        CoreTcpNatEntryState::SynReceived => TcpProxyEntryState::SynReceived,
        CoreTcpNatEntryState::ConnectingDst => TcpProxyEntryState::ConnectingDst,
        CoreTcpNatEntryState::Connected => TcpProxyEntryState::Connected,
        CoreTcpNatEntryState::ClosingSrc => TcpProxyEntryState::ClosingSrc,
        CoreTcpNatEntryState::ClosingDst => TcpProxyEntryState::ClosingDst,
        CoreTcpNatEntryState::Closed => TcpProxyEntryState::Closed,
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
