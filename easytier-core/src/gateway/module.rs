use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use std::sync::atomic::AtomicUsize;

use crossbeam::atomic::AtomicCell;
use quanta::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::AbortOnDropHandle;

use anyhow::Context;
use dashmap::DashMap;
use pnet_packet::{Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket};
use tokio::{
    select,
    sync::{Mutex, Notify, mpsc},
    task::JoinSet,
    time::timeout,
};

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    gateway::{
        proxy::{
            runtime::TcpProxyStream,
            wrapped_transport::{WrappedTransportKind, WrappedTransportProxyModule},
        },
        smoltcp::{BufferSize, Net, NetConfig, UdpSocket, channel_device},
        socks5::{
            Socks5Entry, Socks5EntryKind, Socks5EntryTable, Socks5PeerPacketRoute,
            Socks5TcpConnectPlan, Socks5TcpRoute,
            protocol::{
                Result as SocksResult, SocksError,
                runtime::{HostSocks5ServerRuntime, HostSocks5TcpConnector},
                server::{
                    AcceptAuthentication, AsyncTcpConnector, Config, Socks5ServerRuntime,
                    Socks5Socket,
                },
            },
        },
    },
    host::dns::DnsResolver,
    packet::{PacketType, ZCPacket},
    peers::{
        PeerPacketFilter,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
    socket::{
        SocketContext,
        tcp::{
            TcpListenOptions, TcpSocketPurpose, VirtualTcpListener, VirtualTcpListenerFactory,
            VirtualTcpSocket, VirtualTcpSocketFactory,
        },
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

use super::{GatewayEvent, GatewayEventSink, PortForwardConfig};

mod dataplane;

pub use dataplane::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};

enum GatewayUdpSocket {
    Host(Arc<dyn VirtualUdpSocket>),
    SmolUdpSocket(UdpSocket),
}

impl GatewayUdpSocket {
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        match self {
            Self::Host(socket) => socket.send_to(buf, addr).await,
            Self::SmolUdpSocket(socket) => socket.send_to(buf, addr).await,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        match self {
            Self::Host(socket) => socket.recv_from(buf).await,
            Self::SmolUdpSocket(socket) => socket.recv_from(buf).await,
        }
    }
}

enum GatewayEntryData {
    Tcp {
        _reservation: Arc<dyn Any + Send + Sync>,
    },
    // a data-plane routing entry that owns no resource. the entry_type in the
    // key distinguishes a listen route from an actively outbound route.
    DataPlaneRoute,
    Udp((Arc<GatewayUdpSocket>, UdpClientKey)), // hold the socket to send data to dst
}

const UDP_ENTRY: Socks5EntryKind = Socks5EntryKind::Udp;
const TCP_ENTRY: Socks5EntryKind = Socks5EntryKind::Tcp;
const TCP_LISTEN_ENTRY: Socks5EntryKind = Socks5EntryKind::TcpListen;

type GatewayEntrySet = Arc<Socks5EntryTable<GatewayEntryData>>;
type GatewayTcpStream = Box<dyn TcpProxyStream>;

struct SmolTcpConnector<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    net: Arc<Net>,
    entries: GatewayEntrySet,
    current_entry: std::sync::Mutex<Option<Socks5Entry>>,
    host: Arc<H>,
    socket_context: SocketContext,
    kernel_purpose: TcpSocketPurpose,
}

#[async_trait::async_trait]
impl<H> AsyncTcpConnector for SmolTcpConnector<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    type S = GatewayTcpStream;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> SocksResult<Self::S> {
        let listen_options = TcpListenOptions::port_lease("0.0.0.0:0".parse().unwrap());
        let tmp_listener = self
            .host
            .bind_tcp(
                listen_options.clone().with_bind(
                    listen_options
                        .bind
                        .with_context(self.socket_context.clone()),
                ),
            )
            .await
            .map_err(SocksError::Other)?;
        let local_addr = self.net.get_address();
        let port = tmp_listener.local_addr()?.port();

        let entry = Socks5Entry {
            src: SocketAddr::new(local_addr, port),
            dst: addr,
            kind: TCP_ENTRY,
        };
        *self.current_entry.lock().unwrap() = Some(entry.clone());
        let insert = self.entries.insert(
            entry.clone(),
            GatewayEntryData::Tcp {
                _reservation: tmp_listener,
            },
        );
        tracing::trace!(
            ?entry,
            replaced = insert.replaced,
            old_entry_count = insert.count.previous,
            new_entry_count = insert.count.current,
            entries_len = self.entries.len(),
            "socks5 inserted smoltcp tcp connector entry"
        );

        if addr.ip() == local_addr {
            let modified_addr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), addr.port());

            let connector = HostSocks5TcpConnector::new(
                self.host.clone(),
                self.socket_context.clone(),
                self.kernel_purpose,
            );
            Ok(Box::new(
                connector.tcp_connect(modified_addr, timeout_s).await?,
            ))
        } else {
            let remote_socket = timeout(
                Duration::from_secs(timeout_s),
                self.net.tcp_connect(addr, port),
            )
            .await
            .with_context(|| "connect to remote timeout")?;

            Ok(Box::new(
                remote_socket.map_err(|e| SocksError::Other(e.into()))?,
            ))
        }
    }
}

impl<H> Drop for SmolTcpConnector<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    fn drop(&mut self) {
        if let Some(entry) = self.current_entry.lock().unwrap().take() {
            tracing::debug!("drop smoltcp connector entry {:?}", entry);
            let removal = self.entries.remove(&entry);
            tracing::trace!(
                ?entry,
                removed = removal.removed,
                old_entry_count = removal.count.previous,
                new_entry_count = removal.count.current,
                entries_len = self.entries.len(),
                "socks5 removed smoltcp tcp connector entry"
            );
        }
    }
}

struct Socks5KcpConnector {
    transport_proxy: Weak<WrappedTransportProxyModule>,
    src_addr: SocketAddr,
}

#[async_trait::async_trait]
impl AsyncTcpConnector for Socks5KcpConnector {
    type S = GatewayTcpStream;

    async fn tcp_connect(&self, addr: SocketAddr, _timeout_s: u64) -> SocksResult<Self::S> {
        let Some(transport_proxy) = self.transport_proxy.upgrade() else {
            return Err(anyhow::anyhow!("KCP source is not ready").into());
        };
        transport_proxy
            .connect_source(WrappedTransportKind::Kcp, self.src_addr, addr)
            .await
            .map_err(SocksError::Other)
    }
}

struct Socks5AutoConnector<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    transport_proxy: Option<Weak<WrappedTransportProxyModule>>,
    peer_mgr: Weak<PeerManagerCore>,
    entries: GatewayEntrySet,
    smoltcp_net: Option<Arc<Net>>,
    src_addr: SocketAddr,
    host: Arc<H>,
    socket_context: SocketContext,
    kernel_purpose: TcpSocketPurpose,

    inner_connector: parking_lot::Mutex<Option<Box<dyn Any + Send>>>,
}

#[async_trait::async_trait]
impl<H> AsyncTcpConnector for Socks5AutoConnector<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    type S = GatewayTcpStream;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> SocksResult<Self::S> {
        if self.inner_connector.lock().is_some() {
            return Err(anyhow::anyhow!("inner connector is already set").into());
        }

        let Some(peer_mgr_arc) = self.peer_mgr.upgrade() else {
            tracing::error!("peer manager is dropped");
            return Err(anyhow::anyhow!("peer manager is dropped").into());
        };

        let has_smoltcp_net = self.smoltcp_net.is_some();
        let kcp_available = match self.transport_proxy.as_ref().and_then(Weak::upgrade) {
            Some(transport_proxy) => {
                transport_proxy
                    .source_connect_ready(WrappedTransportKind::Kcp)
                    .await
            }
            None => false,
        };
        let plan = Socks5TcpConnectPlan::new(
            addr,
            self.smoltcp_net.as_ref().map(|net| net.get_address()),
            has_smoltcp_net,
            kcp_available,
        );
        let addr = plan.destination();
        let dst_peers = if plan.needs_virtual_network_lookup() {
            Some(peer_mgr_arc.get_msg_dst_peer(&addr.ip()).await.0)
        } else {
            None
        };
        let destination_in_virtual_network =
            dst_peers.as_ref().is_some_and(|peers| !peers.is_empty());

        if plan.route(destination_in_virtual_network, false) == Socks5TcpRoute::Kernel {
            // cannot find dst in virtual network, so try connect to dst directly
            tracing::trace!(
                ?addr,
                src_addr = ?self.src_addr,
                has_smoltcp_net,
                dst_peer_count = dst_peers.as_ref().map(Vec::len),
                is_loopback = addr.ip().is_loopback(),
                "socks5 auto connector falling back to kernel tcp connect"
            );
            let connector = HostSocks5TcpConnector::new(
                self.host.clone(),
                self.socket_context.clone(),
                self.kernel_purpose,
            );
            return Ok(Box::new(connector.tcp_connect(addr, timeout_s).await?));
        }

        let dst_allow_kcp = peer_mgr_arc.check_allow_kcp_to_dst(&addr.ip()).await;
        tracing::debug!("dst_allow_kcp: {:?}", dst_allow_kcp);
        let route = plan.route(destination_in_virtual_network, dst_allow_kcp);

        let connector: Box<dyn AsyncTcpConnector<S = GatewayTcpStream> + Send> = match route {
            Socks5TcpRoute::Kcp => {
                let transport_proxy = self
                    .transport_proxy
                    .as_ref()
                    .expect("KCP route requires an available source");
                tracing::trace!(
                    ?addr,
                    src_addr = ?self.src_addr,
                    dst_peer_count = dst_peers.as_ref().map(Vec::len),
                    "socks5 auto connector selected kcp"
                );
                Box::new(Socks5KcpConnector {
                    transport_proxy: transport_proxy.clone(),
                    src_addr: self.src_addr,
                })
            }
            Socks5TcpRoute::Smoltcp => {
                tracing::trace!(
                    ?addr,
                    src_addr = ?self.src_addr,
                    dst_peer_count = dst_peers.as_ref().map(Vec::len),
                    dst_allow_kcp,
                    kcp_available,
                    "socks5 auto connector selected smoltcp"
                );
                Box::new(SmolTcpConnector {
                    net: self.smoltcp_net.clone().unwrap(),
                    entries: self.entries.clone(),
                    current_entry: std::sync::Mutex::new(None),
                    host: self.host.clone(),
                    socket_context: self.socket_context.clone(),
                    kernel_purpose: self.kernel_purpose,
                })
            }
            Socks5TcpRoute::Kernel => unreachable!("kernel route returned above"),
        };

        let ret = connector.tcp_connect(addr, timeout_s).await;
        self.inner_connector.lock().replace(Box::new(connector));
        ret
    }
}

struct Socks5ServerNet<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    ipv4_addr: cidr::Ipv4Inet,

    smoltcp_net: Arc<Net>,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    command_runtime: Arc<dyn Socks5ServerRuntime>,
    _host: std::marker::PhantomData<H>,
}

impl<H> Socks5ServerNet<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub fn new(
        ipv4_addr: cidr::Ipv4Inet,
        peer_manager: Weak<PeerManagerCore>,
        packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,
        command_runtime: Arc<dyn Socks5ServerRuntime>,
    ) -> Self {
        let mut forward_tasks = JoinSet::new();
        let mut cap = smoltcp::phy::DeviceCapabilities::default();
        cap.max_transmission_unit = 1284; // 1284 - 20 can be divided by 8 (fragment offset unit)
        cap.medium = smoltcp::phy::Medium::Ip;
        let (dev, stack_sink, mut stack_stream) = channel_device::ChannelDevice::new(cap);

        forward_tasks.spawn(async move {
            let mut smoltcp_stack_receiver = packet_recv.lock().await;
            while let Some(packet) = smoltcp_stack_receiver.recv().await {
                tracing::trace!(?packet, "receive from peer send to smoltcp packet");
                if let Err(e) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                    tracing::error!("send to smoltcp stack failed: {:?}", e);
                }
            }
            tracing::warn!("smoltcp stack sink exited");
        });

        forward_tasks.spawn(async move {
            while let Some(data) = stack_stream.recv().await {
                tracing::trace!(
                    ?data,
                    "receive from smoltcp stack and send to peer mgr packet, len = {}",
                    data.len()
                );
                let Some(ipv4) = Ipv4Packet::new(&data) else {
                    tracing::error!(?data, "smoltcp stack stream get non ipv4 packet");
                    continue;
                };

                let dst = ipv4.get_destination();
                let packet = ZCPacket::new_with_payload(&data);
                let Some(peer_manager) = peer_manager.upgrade() else {
                    tracing::warn!("peer manager is gone, smoltcp sender exited");
                    return;
                };
                if let Err(e) = peer_manager
                    .send_msg_by_ip(packet, IpAddr::V4(dst), false)
                    .await
                {
                    tracing::error!("send to peer failed in smoltcp sender: {:?}", e);
                }
            }
            tracing::warn!("smoltcp stack stream exited");
        });

        let interface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let net = Net::new(
            dev,
            NetConfig::new(
                interface_config,
                format!("{}/{}", ipv4_addr.address(), ipv4_addr.network_length())
                    .parse()
                    .unwrap(),
                vec![format!("{}", ipv4_addr.address()).parse().unwrap()],
                Some(BufferSize {
                    tcp_rx_size: 1024 * 128,
                    tcp_tx_size: 1024 * 128,
                    ..Default::default()
                }),
            ),
        );

        let forward_tasks = Arc::new(std::sync::Mutex::new(forward_tasks));
        join_joinset_background(forward_tasks.clone(), "Socks5ServerNet");

        Self {
            ipv4_addr,

            smoltcp_net: Arc::new(net),
            forward_tasks,
            command_runtime,
            _host: std::marker::PhantomData,
        }
    }

    async fn handle_tcp_stream_task<S>(
        stream: S,
        connector: Socks5AutoConnector<H>,
        command_runtime: Arc<dyn Socks5ServerRuntime>,
    ) where
        S: VirtualTcpSocket,
    {
        let mut config = Config::<AcceptAuthentication>::default();
        config.set_request_timeout(10);
        config.set_skip_auth(false);
        config.set_allow_no_auth(true);

        let socket = Socks5Socket::new(stream, Arc::new(config), connector, command_runtime);

        match socket.upgrade_to_socks5().await {
            Ok(_) => {
                tracing::info!("socks5 handle success");
            }
            Err(e) => {
                tracing::error!("socks5 handshake failed: {:?}", e);
            }
        };
    }

    fn handle_tcp_stream<S>(&self, stream: S, connector: Socks5AutoConnector<H>)
    where
        S: VirtualTcpSocket,
    {
        self.forward_tasks
            .lock()
            .unwrap()
            .spawn(Self::handle_tcp_stream_task(
                stream,
                connector,
                self.command_runtime.clone(),
            ));
    }
}

struct UdpClientInfo<H>
where
    H: VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    port_holder_socket: Arc<H::Socket>,
    local_addr: SocketAddr,
    last_active: AtomicCell<Instant>,
    entry_key: Socks5Entry,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct UdpClientKey {
    client_addr: SocketAddr,
    dst_addr: SocketAddr,
}

pub(crate) struct GatewayModule<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    operation: Mutex<()>,
    started: AtomicBool,
    runtime_config: CoreRuntimeConfigStore,
    peer_manager: Weak<PeerManagerCore>,
    transport_proxy: Option<Weak<WrappedTransportProxyModule>>,
    host: Arc<H>,
    socket_context: SocketContext,
    command_runtime: Arc<dyn Socks5ServerRuntime>,
    events: Arc<dyn GatewayEventSink>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    packet_sender: mpsc::Sender<ZCPacket>,
    packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,

    net: Arc<Mutex<Option<Socks5ServerNet<H>>>>,
    entries: GatewayEntrySet,

    udp_client_map: Arc<DashMap<UdpClientKey, Arc<UdpClientInfo<H>>>>,
    udp_forward_task: Arc<DashMap<UdpClientKey, AbortOnDropHandle<()>>>,

    socks5_enabled: Arc<AtomicBool>,
    data_plane_refs: Arc<AtomicUsize>,
    // Tracks whether the smoltcp `net` is ready for data-plane callers.
    data_plane_net_ready: tokio::sync::watch::Sender<bool>,
    cancel_tokens: Arc<DashMap<PortForwardConfig, DropGuard>>,
    port_forward_list_change_notifier: Arc<Notify>,
    pipeline_guard: Mutex<Option<PipelineRegistrationGuard>>,
}

#[async_trait::async_trait]
impl<H> PeerPacketFilter for GatewayModule<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let entry_count = self.entries.count();
        let socks5_enabled = self.socks5_enabled.load(Ordering::Relaxed);
        if entry_count == 0 && !socks5_enabled && self.entries.is_empty() {
            if tracing::enabled!(tracing::Level::TRACE)
                && let Some(hdr) = packet.peer_manager_header()
                && matches!(
                    hdr.packet_type,
                    x if x == PacketType::Data as u8
                        || x == PacketType::DataWithKcpSrcModified as u8
                        || x == PacketType::DataWithQuicSrcModified as u8
                )
            {
                if let Some(ipv4) = Ipv4Packet::new(packet.payload()) {
                    let (tcp_src_port, tcp_dst_port, tcp_flags) =
                        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            TcpPacket::new(ipv4.payload())
                                .map(|tcp| {
                                    (
                                        Some(tcp.get_source()),
                                        Some(tcp.get_destination()),
                                        Some(tcp.get_flags()),
                                    )
                                })
                                .unwrap_or((None, None, None))
                        } else {
                            (None, None, None)
                        };
                    tracing::trace!(
                        packet_type = hdr.packet_type,
                        from_peer_id = hdr.from_peer_id.get(),
                        to_peer_id = hdr.to_peer_id.get(),
                        ipv4_src = %ipv4.get_source(),
                        ipv4_dst = %ipv4.get_destination(),
                        next_protocol = ?ipv4.get_next_level_protocol(),
                        ?tcp_src_port,
                        ?tcp_dst_port,
                        ?tcp_flags,
                        entry_count,
                        socks5_enabled,
                        "socks5 fast gate passed packet from peer"
                    );
                } else {
                    tracing::trace!(
                        packet_type = hdr.packet_type,
                        from_peer_id = hdr.from_peer_id.get(),
                        to_peer_id = hdr.to_peer_id.get(),
                        entry_count,
                        socks5_enabled,
                        "socks5 fast gate passed non-ipv4 packet from peer"
                    );
                }
            }
            return Some(packet);
        }
        let route = self.entries.route_peer_packet(&packet, true);
        let (entry_key, tcp_flags) = match route {
            Socks5PeerPacketRoute::Pass => return Some(packet),
            Socks5PeerPacketRoute::Unmatched { entry, tcp_flags } => {
                tracing::trace!(
                    entry_key = ?entry,
                    ?tcp_flags,
                    ipv4_src = %entry.dst.ip(),
                    ipv4_dst = %entry.src.ip(),
                    entry_count = self.entries.count(),
                    socks5_enabled = self.socks5_enabled.load(Ordering::Relaxed),
                    "socks5 no entry for packet from peer"
                );
                return Some(packet);
            }
            Socks5PeerPacketRoute::Deliver { entry, tcp_flags } => (entry, tcp_flags),
            Socks5PeerPacketRoute::FragmentedUdp { source, mirror } => {
                let source: IpAddr = source.into();
                tracing::trace!(
                    is_in_entries = mirror,
                    "ipv4 src = {:?}, check need send both smoltcp and kernel tun",
                    source
                );
                if mirror {
                    // if the packet is fragmented, no matther what the payload is, need send it to both smoltcp and kernel tun. because
                    // we cannot determine the udp port of the packet.
                    match self.packet_sender.try_send(packet.clone()) {
                        Ok(()) => tracing::trace!(
                            ?source,
                            entry_count = self.entries.count(),
                            "socks5 delivered fragmented packet from peer to smoltcp"
                        ),
                        Err(err) => tracing::trace!(
                            ?source,
                            ?err,
                            entry_count = self.entries.count(),
                            "socks5 failed to deliver fragmented packet from peer to smoltcp"
                        ),
                    }
                }
                return Some(packet);
            }
        };

        tracing::trace!(
            ?entry_key,
            ?tcp_flags,
            ipv4_src = %entry_key.dst.ip(),
            ipv4_dst = %entry_key.src.ip(),
            entry_count = self.entries.count(),
            "socks5 found entry for packet from peer"
        );

        match self.packet_sender.try_send(packet) {
            Ok(()) => tracing::trace!(
                ?entry_key,
                ?tcp_flags,
                entry_count = self.entries.count(),
                "socks5 delivered packet from peer to smoltcp"
            ),
            Err(err) => tracing::trace!(
                ?entry_key,
                ?tcp_flags,
                ?err,
                entry_count = self.entries.count(),
                "socks5 failed to deliver packet from peer to smoltcp"
            ),
        }

        None
    }
}

impl<H> GatewayModule<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub(crate) fn new(
        runtime_config: CoreRuntimeConfigStore,
        peer_manager: Arc<PeerManagerCore>,
        transport_proxy: Option<&Arc<WrappedTransportProxyModule>>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        socket_context: SocketContext,
        events: Arc<dyn GatewayEventSink>,
    ) -> Arc<Self> {
        let (packet_sender, packet_recv) = mpsc::channel(1024);
        let command_runtime = Arc::new(HostSocks5ServerRuntime::new(
            host.clone(),
            dns,
            socket_context.clone(),
        ));
        Arc::new(Self {
            operation: Mutex::new(()),
            started: AtomicBool::new(false),
            runtime_config,
            peer_manager: Arc::downgrade(&peer_manager),
            transport_proxy: transport_proxy.map(Arc::downgrade),
            host,
            socket_context,
            command_runtime,
            events,

            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            packet_recv: Arc::new(Mutex::new(packet_recv)),
            packet_sender,

            net: Arc::new(Mutex::new(None)),
            entries: Arc::new(Socks5EntryTable::default()),

            udp_client_map: Arc::new(DashMap::new()),
            udp_forward_task: Arc::new(DashMap::new()),

            socks5_enabled: Arc::new(AtomicBool::new(false)),
            data_plane_refs: Arc::new(AtomicUsize::new(0)),
            data_plane_net_ready: tokio::sync::watch::channel(false).0,
            cancel_tokens: Arc::new(DashMap::new()),
            port_forward_list_change_notifier: Arc::new(Notify::new()),
            pipeline_guard: Mutex::new(None),
        })
    }

    fn runtime_ipv4(runtime_config: &CoreRuntimeConfigStore) -> Option<cidr::Ipv4Inet> {
        let prefix = runtime_config
            .snapshot()
            .peer
            .runtime
            .core
            .routes
            .ipv4
            .clone()?;
        let IpAddr::V4(address) = prefix.address else {
            return None;
        };
        cidr::Ipv4Inet::new(address, prefix.prefix_len).ok()
    }

    async fn run_net_update_task(self: &Arc<Self>) {
        let net = self.net.clone();
        let runtime_config = self.runtime_config.clone();
        let peer_manager = self.peer_manager.clone();
        let packet_recv = self.packet_recv.clone();
        let entries = self.entries.clone();
        let udp_client_map = self.udp_client_map.clone();
        let cancel_tokens = self.cancel_tokens.clone();
        let port_forward_list_change_notifier = self.port_forward_list_change_notifier.clone();
        let socks5_enabled = self.socks5_enabled.clone();
        let command_runtime = self.command_runtime.clone();
        let data_plane_refs = self.data_plane_refs.clone();
        let data_plane_net_ready = self.data_plane_net_ready.clone();
        self.tasks.lock().unwrap().spawn(async move {
            let mut prev_ipv4 = None;
            let mut peer_changes = runtime_config.subscribe_peer_runtime_changes();
            let mut service_changes = runtime_config.subscribe_service_runtime_changes();
            loop {
                let data_plane_active = data_plane_refs.load(Ordering::Relaxed) > 0;

                let active_port_forwards = cancel_tokens.len();
                let is_socks5_enabled = socks5_enabled.load(Ordering::Relaxed);
                if active_port_forwards == 0 && !is_socks5_enabled && !data_plane_active {
                    let had_net = {
                        let mut net_guard = net.lock().await;
                        net_guard.take().is_some()
                    };
                    tracing::trace!(
                        had_net,
                        active_port_forwards,
                        is_socks5_enabled,
                        data_plane_active,
                        entry_count = entries.count(),
                        entries_len = entries.len(),
                        "socks5 net update waiting for consumers"
                    );
                    let _ = data_plane_net_ready.send_replace(false);
                    port_forward_list_change_notifier.notified().await;
                    continue;
                }

                let cur_ipv4 = Self::runtime_ipv4(&runtime_config);
                if prev_ipv4 != cur_ipv4 {
                    let old_ipv4 = prev_ipv4;
                    prev_ipv4 = cur_ipv4;

                    tracing::trace!(
                        ?old_ipv4,
                        ?cur_ipv4,
                        old_entry_count = entries.count(),
                        old_entries_len = entries.len(),
                        udp_client_count = udp_client_map.len(),
                        "socks5 net update resetting entries for ipv4 change"
                    );
                    let cleared = entries.clear();
                    udp_client_map.clear();
                    tracing::trace!(
                        ?old_ipv4,
                        ?cur_ipv4,
                        removed_entries = cleared.removed,
                        new_entry_count = cleared.count.current,
                        new_entries_len = entries.len(),
                        udp_client_count = udp_client_map.len(),
                        "socks5 net update reset entries complete"
                    );

                    if let Some(cur_ipv4) = cur_ipv4 {
                        net.lock().await.replace(Socks5ServerNet::new(
                            cur_ipv4,
                            peer_manager.clone(),
                            packet_recv.clone(),
                            command_runtime.clone(),
                        ));
                        tracing::trace!(
                            ?cur_ipv4,
                            entry_count = entries.count(),
                            entries_len = entries.len(),
                            "socks5 net update installed smoltcp net"
                        );
                        // Wake any data-plane callers waiting in
                        // `wait_data_plane_net` for the smoltcp net to appear.
                        let _ = data_plane_net_ready.send_replace(true);
                    } else {
                        let _ = net.lock().await.take();
                        tracing::trace!(
                            entry_count = entries.count(),
                            entries_len = entries.len(),
                            "socks5 net update removed smoltcp net"
                        );
                        let _ = data_plane_net_ready.send_replace(false);
                    }
                }

                select! {
                    _ = peer_changes.changed() => {}
                    _ = service_changes.changed() => {}
                    _ = tokio::time::sleep(Duration::from_secs(120)) => {}
                }
            }
        });
    }

    async fn start_inner(self: &Arc<Self>) -> anyhow::Result<()> {
        let gateway_config = self.runtime_config.snapshot().services.gateway.clone();
        join_joinset_background(self.tasks.clone(), "gateway");
        if let Some(bind_addr) = gateway_config.socks5_bind {
            let options = TcpListenOptions::socks5(bind_addr);
            let bind = options
                .bind
                .clone()
                .with_context(self.socket_context.clone());
            let listener = self.host.bind_tcp(options.with_bind(bind)).await?;

            let entries = self.entries.clone();
            let peer_manager = self.peer_manager.clone();
            let net = self.net.clone();
            let command_runtime = self.command_runtime.clone();
            let host = self.host.clone();
            let socket_context = self.socket_context.clone();
            let transport_proxy = self.transport_proxy.clone();
            self.tasks.lock().unwrap().spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((socket, addr)) => {
                            tracing::info!(?addr, "accept a new SOCKS connection");
                            let connector = Socks5AutoConnector {
                                smoltcp_net: net
                                    .lock()
                                    .await
                                    .as_ref()
                                    .map(|net| net.smoltcp_net.clone()),
                                entries: entries.clone(),
                                transport_proxy: transport_proxy.clone(),
                                peer_mgr: peer_manager.clone(),
                                src_addr: addr,
                                host: host.clone(),
                                socket_context: socket_context.clone(),
                                kernel_purpose: TcpSocketPurpose::Socks5,
                                inner_connector: parking_lot::Mutex::new(None),
                            };
                            if let Some(net) = net.lock().await.as_ref() {
                                net.handle_tcp_stream(socket, connector);
                            } else {
                                tokio::spawn(Socks5ServerNet::<H>::handle_tcp_stream_task(
                                    socket,
                                    connector,
                                    command_runtime.clone(),
                                ));
                            }
                        }
                        Err(err) => tracing::error!("accept error = {:?}", err),
                    }
                }
            });

            self.socks5_enabled.store(true, Ordering::Relaxed);
        };

        let cfgs = gateway_config.port_forwards;
        self.apply_port_forwards(&cfgs).await?;

        let Some(peer_manager) = self.peer_manager.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is gone").into());
        };
        let guard = peer_manager
            .add_managed_packet_process_pipeline(Box::new(self.clone()))
            .await;
        self.pipeline_guard.lock().await.replace(guard);
        tracing::trace!(
            cfg_count = cfgs.len(),
            cancel_token_count = self.cancel_tokens.len(),
            entry_count = self.entries.count(),
            entries_len = self.entries.len(),
            "socks5 peer packet pipeline registered"
        );

        self.run_net_update_task().await;

        Ok(())
    }

    pub(crate) async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Err(error) = self.start_inner().await {
            self.stop_inner().await;
            return Err(error);
        }
        self.started.store(true, Ordering::Release);
        Ok(())
    }

    async fn stop_inner(&self) {
        self.started.store(false, Ordering::Release);
        self.socks5_enabled.store(false, Ordering::Release);
        self.cancel_tokens.clear();
        self.udp_forward_task.clear();
        if let Some(guard) = self.pipeline_guard.lock().await.take() {
            guard.close();
        }
        self.net.lock().await.take();
        let _ = self.data_plane_net_ready.send_replace(false);
        self.entries.clear();
        self.udp_client_map.clear();
        let mut tasks = {
            let mut tasks = self.tasks.lock().unwrap();
            std::mem::replace(&mut *tasks, JoinSet::new())
        };
        tasks.shutdown().await;
    }

    pub(crate) async fn stop(&self) {
        let _operation = self.operation.lock().await;
        self.stop_inner().await;
    }

    pub(crate) async fn reload_port_forwards(
        &self,
        cfgs: &[PortForwardConfig],
    ) -> anyhow::Result<()> {
        if !self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        self.apply_port_forwards(cfgs).await
    }

    async fn apply_port_forwards(&self, cfgs: &[PortForwardConfig]) -> anyhow::Result<()> {
        // remove entries not in new cfg
        self.cancel_tokens.retain(|k, _| {
            cfgs.iter().any(|cfg| {
                if cfg.dst_addr.ip().is_unspecified() {
                    k.bind_addr == cfg.bind_addr && k.proto == cfg.proto
                } else {
                    k == cfg
                }
            })
        });
        // add new ones
        for cfg in cfgs {
            if !self.cancel_tokens.contains_key(cfg) {
                self.add_port_forward(cfg.clone()).await?;
            }
        }
        self.port_forward_list_change_notifier.notify_one();
        Ok(())
    }

    async fn handle_port_forward_connection<S>(
        mut incoming_socket: S,
        connector: Box<dyn AsyncTcpConnector<S = GatewayTcpStream> + Send>,
        dst_addr: SocketAddr,
    ) where
        S: VirtualTcpSocket,
    {
        tracing::trace!(?dst_addr, "port forward: connecting to destination");
        let outgoing_socket = match connector.tcp_connect(dst_addr, 10).await {
            Ok(socket) => socket,
            Err(e) => {
                tracing::error!("port forward: failed to connect to destination: {:?}", e);
                return;
            }
        };
        tracing::trace!(?dst_addr, "port forward: connected to destination");

        let mut outgoing_socket = outgoing_socket;
        match tokio::io::copy_bidirectional(&mut incoming_socket, &mut outgoing_socket).await {
            Ok((from_client, from_server)) => {
                tracing::info!(
                    "port forward connection finished: client->server: {} bytes, server->client: {} bytes",
                    from_client,
                    from_server
                );
            }
            Err(e) => {
                tracing::error!("port forward connection error: {:?}", e);
            }
        }
    }

    async fn add_port_forward(&self, cfg: PortForwardConfig) -> anyhow::Result<()> {
        match cfg.proto.to_lowercase().as_str() {
            "tcp" => {
                self.add_tcp_port_forward(&cfg).await?;
            }
            "udp" => {
                self.add_udp_port_forward(&cfg).await?;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported protocol: {}, only support udp / tcp",
                    cfg.proto
                ));
            }
        }
        self.events.emit(GatewayEvent::PortForwardAdded(cfg));
        Ok(())
    }

    async fn add_tcp_port_forward(&self, cfg: &PortForwardConfig) -> anyhow::Result<()> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let options = TcpListenOptions::port_forward(bind_addr);
        let bind = options
            .bind
            .clone()
            .with_context(self.socket_context.clone());
        let listener = self.host.bind_tcp(options.with_bind(bind)).await?;

        let net = self.net.clone();
        let entries = self.entries.clone();
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "tcp port forward");
        let forward_tasks = tasks;
        let transport_proxy = self.transport_proxy.clone();
        let peer_mgr = self.peer_manager.clone();
        let host = self.host.clone();
        let socket_context = self.socket_context.clone();
        let cancel_token = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel_token.clone().drop_guard());

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let (incoming_socket, addr) = select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        tracing::info!("port forward for {:?} cancelled", bind_addr);
                        break;
                    }
                    res = listener.accept() => {
                        match res {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::error!("port forward accept error = {:?}", err);
                                continue;
                            }
                        }
                    }
                };

                tracing::info!(
                    "port forward: accept new connection from {:?} to {:?}",
                    bind_addr,
                    dst_addr
                );

                let (smoltcp_net, net_ipv4) = {
                    let net_guard = net.lock().await;
                    (
                        net_guard.as_ref().map(|net| net.smoltcp_net.clone()),
                        net_guard.as_ref().map(|net| net.ipv4_addr),
                    )
                };
                tracing::trace!(
                    ?bind_addr,
                    ?dst_addr,
                    client_addr = ?addr,
                    has_smoltcp_net = smoltcp_net.is_some(),
                    ?net_ipv4,
                    entry_count = entries.count(),
                    entries_len = entries.len(),
                    "port forward: preparing connector"
                );

                let connector = Socks5AutoConnector {
                    transport_proxy: transport_proxy.clone(),
                    peer_mgr: peer_mgr.clone(),
                    entries: entries.clone(),
                    smoltcp_net,
                    src_addr: addr,
                    host: host.clone(),
                    socket_context: socket_context.clone(),
                    kernel_purpose: TcpSocketPurpose::PortForward,
                    inner_connector: parking_lot::Mutex::new(None),
                };

                forward_tasks
                    .lock()
                    .unwrap()
                    .spawn(Self::handle_port_forward_connection(
                        incoming_socket,
                        Box::new(connector),
                        dst_addr,
                    ));
            }
        });

        Ok(())
    }

    #[tracing::instrument(name = "add_udp_port_forward", skip(self))]
    async fn add_udp_port_forward(&self, cfg: &PortForwardConfig) -> anyhow::Result<()> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let socket = self
            .host
            .bind_udp(
                UdpBindOptions::port_forward(bind_addr).with_context(self.socket_context.clone()),
            )
            .await?;

        let entries = self.entries.clone();
        let net = self.net.clone();
        let host = self.host.clone();
        let socket_context = self.socket_context.clone();
        let udp_client_map = self.udp_client_map.clone();
        let udp_forward_task = self.udp_forward_task.clone();
        let cancel_token = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel_token.clone().drop_guard());

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                // we set the max buffer size of smoltcp to 8192, so we need to use a buffer size that is less than 8192 here.
                let mut buf = vec![0u8; 8192];
                let (len, addr) = select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        tracing::info!("udp port forward for {:?} cancelled", bind_addr);
                        break;
                    }
                    res = socket.recv_from(&mut buf) => {
                        match res {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::error!("udp port forward recv error = {:?}", err);
                                continue;
                            }
                        }
                    }
                };

                tracing::trace!(
                    "udp port forward recv packet from {:?}, len = {}",
                    addr,
                    len
                );

                let udp_client_key = UdpClientKey {
                    client_addr: addr,
                    dst_addr,
                };

                let binded_socket = udp_client_map.get(&udp_client_key);
                let client_info = match binded_socket {
                    Some(s) => s.clone(),
                    None => {
                        // reserve a port so os will not use it to connect to the virtual network
                        let binded_socket = host
                            .bind_udp(
                                UdpBindOptions::port_lease("0.0.0.0:0".parse().unwrap())
                                    .with_context(socket_context.clone()),
                            )
                            .await;
                        let binded_socket = match binded_socket {
                            Ok(socket) => socket,
                            Err(error) => {
                                tracing::error!(?error, "udp port forward bind error");
                                continue;
                            }
                        };
                        let mut local_addr = binded_socket.local_addr().unwrap();
                        let Some(cur_ipv4) = net.lock().await.as_ref().map(|net| net.ipv4_addr) else {
                            continue;
                        };
                        local_addr.set_ip(cur_ipv4.address().into());

                        let entry_key = Socks5Entry {
                            src: local_addr,
                            dst: dst_addr,
                            kind: UDP_ENTRY,
                        };

                        tracing::debug!("udp port forward binded socket = {:?}, entry_key = {:?}", local_addr, entry_key);

                        let client_info = Arc::new(UdpClientInfo {
                            port_holder_socket: binded_socket,
                            local_addr,
                            last_active: AtomicCell::new(Instant::now()),
                            entry_key,
                        });
                        udp_client_map.insert(udp_client_key.clone(), client_info.clone());
                        client_info
                    }
                };

                client_info.last_active.store(Instant::now());

                let udp_socket = match entries.with_entry(&client_info.entry_key, |data| {
                    match data {
                        GatewayEntryData::Udp((socket, _)) => socket.clone(),
                        _ => panic!("udp entry data is not udp entry data"),
                    }
                }) {
                    Some(socket) => socket,
                    None => {
                        let guard = net.lock().await;
                        let Some(net) = guard.as_ref() else {
                            continue;
                        };
                        let local_addr = net.ipv4_addr;
                        let sokcs_udp = if dst_addr.ip() == local_addr.address() {
                            GatewayUdpSocket::Host(client_info.port_holder_socket.clone())
                        } else {
                            tracing::debug!("udp port forward bind new smol udp socket, {:?}", local_addr);
                            GatewayUdpSocket::SmolUdpSocket(
                                net.smoltcp_net
                                    .udp_bind(SocketAddr::new(
                                        IpAddr::V4(local_addr.address()),
                                        client_info.local_addr.port(),
                                    ))
                                    .await
                                    .unwrap(),
                            )
                        };
                        let socks_udp = Arc::new(sokcs_udp);
                        entries.insert(
                            client_info.entry_key.clone(),
                            GatewayEntryData::Udp((socks_udp.clone(), udp_client_key.clone())),
                        );

                        let socks = socket.clone();
                        let client_addr = addr;
                        udp_forward_task.insert(
                            udp_client_key.clone(),
                            AbortOnDropHandle::new(tokio::spawn(async move {
                                loop {
                                    let mut buf = vec![0u8; 8192];
                                    match socks_udp.recv_from(&mut buf).await {
                                        Ok((len, dst_addr)) => {
                                            tracing::trace!(
                                                "udp port forward recv response packet from {:?}, len = {}, client_addr = {:?}",
                                                dst_addr,
                                                len,
                                                client_addr
                                            );
                                            if let Err(e) = socks.send_to(&buf[..len], client_addr).await {
                                                tracing::error!("udp forward send error = {:?}", e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!("udp forward recv error = {:?}", e);
                                        }
                                    }
                                }
                            })),
                        );

                        entries
                            .with_entry(&client_info.entry_key, |data| match data {
                                GatewayEntryData::Udp((socket, _)) => socket.clone(),
                                _ => panic!("udp entry data is not udp entry data"),
                            })
                            .unwrap()
                    }
                };

                if let Err(e) = udp_socket.send_to(&buf[..len], dst_addr).await {
                    tracing::error!(?dst_addr, ?len, "udp port forward send error = {:?}", e);
                } else {
                    tracing::trace!(?dst_addr, ?len, "udp port forward send packet success");
                }
            }
        });

        // clean up task
        let udp_client_map = self.udp_client_map.clone();
        let udp_forward_task = self.udp_forward_task.clone();
        let entries = self.entries.clone();
        let cancel_tokens = self.cancel_tokens.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = Instant::now();
                udp_client_map.retain(|_, client_info| {
                    now.duration_since(client_info.last_active.load()).as_secs() < 600
                });
                udp_forward_task.retain(|k, _| udp_client_map.contains_key(k));
                entries.retain(|_, data| match data {
                    GatewayEntryData::Udp((_, udp_client_key)) => {
                        udp_client_map.contains_key(udp_client_key)
                    }
                    _ => true,
                });

                udp_client_map.shrink_to_fit();
                udp_forward_task.shrink_to_fit();
                entries.shrink_to_fit();
                cancel_tokens.shrink_to_fit();
            }
        });

        Ok(())
    }
}

fn join_joinset_background(tasks: Arc<std::sync::Mutex<JoinSet<()>>>, origin: &'static str) {
    let tasks = Arc::downgrade(&tasks);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let Some(tasks) = tasks.upgrade() else {
                break;
            };
            while tasks.lock().unwrap().try_join_next().is_some() {}
        }
        tracing::debug!(origin, "gateway joinset reaper exited");
    });
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use pnet_packet::{
        MutablePacket,
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        tcp::{self, MutableTcpPacket, TcpFlags},
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::*;
    use crate::{
        config::{IpPrefix, NetworkIdentity},
        host::dns::DnsQuery,
        peers::{
            PacketRecvChanReceiver, context::PeerRuntimeSnapshot, create_packet_recv_chan,
            peer_manager::PortablePeerManagerConfig,
        },
        socket::{tcp::TcpConnectOptions, udp::UdpBindOptions},
        tunnel::ring::RingTunnelRegistry,
    };

    struct TestTcpSocket(tokio::io::DuplexStream);

    impl AsyncRead for TestTcpSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestTcpSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl VirtualTcpSocket for TestTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    struct TestTcpListener;

    #[async_trait::async_trait]
    impl VirtualTcpListener for TestTcpListener {
        type Socket = TestTcpSocket;

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
            std::future::pending().await
        }
    }

    struct TestUdpSocket;

    #[async_trait::async_trait]
    impl VirtualUdpSocket for TestUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(data.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("unused test socket"))
        }
    }

    #[derive(Default)]
    struct TestHost {
        tcp_binds: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl VirtualTcpSocketFactory for TestHost {
        type Socket = TestTcpSocket;

        async fn connect_tcp(&self, _options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
            anyhow::bail!("unused test host")
        }
    }

    #[async_trait::async_trait]
    impl VirtualTcpListenerFactory for TestHost {
        type Listener = TestTcpListener;

        async fn bind_tcp(
            &self,
            _options: TcpListenOptions,
        ) -> anyhow::Result<Arc<Self::Listener>> {
            self.tcp_binds.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(TestTcpListener))
        }
    }

    #[async_trait::async_trait]
    impl VirtualUdpSocketFactory for TestHost {
        type Socket = TestUdpSocket;

        async fn bind_udp(&self, _options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            anyhow::bail!("unused test host")
        }
    }

    struct TestDns;

    #[async_trait::async_trait]
    impl DnsResolver for TestDns {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            anyhow::bail!("unused test DNS")
        }
    }

    fn test_gateway() -> Arc<GatewayModule<TestHost>> {
        let runtime_config = CoreRuntimeConfigStore::new(
            crate::config::runtime::CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let host = Arc::new(TestHost::default());
        let (packet_sender, packet_recv) = mpsc::channel(16);
        Arc::new(GatewayModule {
            operation: Mutex::new(()),
            started: AtomicBool::new(false),
            runtime_config,
            peer_manager: Weak::new(),
            transport_proxy: None,
            host: host.clone(),
            socket_context: SocketContext::default(),
            command_runtime: Arc::new(HostSocks5ServerRuntime::new(
                host,
                Arc::new(TestDns),
                SocketContext::default(),
            )),
            events: Arc::new(()),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            packet_sender,
            packet_recv: Arc::new(Mutex::new(packet_recv)),
            net: Arc::new(Mutex::new(None)),
            entries: Arc::new(Socks5EntryTable::default()),
            udp_client_map: Arc::new(DashMap::new()),
            udp_forward_task: Arc::new(DashMap::new()),
            socks5_enabled: Arc::new(AtomicBool::new(false)),
            data_plane_refs: Arc::new(AtomicUsize::new(0)),
            data_plane_net_ready: tokio::sync::watch::channel(false).0,
            cancel_tokens: Arc::new(DashMap::new()),
            port_forward_list_change_notifier: Arc::new(Notify::new()),
            pipeline_guard: Mutex::new(None),
        })
    }

    struct DataPlaneEndpoint {
        gateway: Arc<GatewayModule<TestHost>>,
        peer_manager: Arc<PeerManagerCore>,
        _packet_receiver: PacketRecvChanReceiver,
        ip: cidr::Ipv4Inet,
    }

    fn data_plane_endpoint(
        host: Arc<TestHost>,
        peer_id: u32,
        ip: cidr::Ipv4Inet,
    ) -> DataPlaneEndpoint {
        const NETWORK_NAME: &str = "gateway-data-plane";

        let mut runtime = PeerRuntimeSnapshot::default().runtime;
        runtime.core.node.peer_id = Some(peer_id);
        runtime.core.node.network_name = NETWORK_NAME.to_owned();
        runtime.core.routes.ipv4 = Some(
            IpPrefix::new(IpAddr::V4(ip.address()), ip.network_length())
                .expect("test IPv4 prefix should be valid"),
        );
        runtime.network_identity = NetworkIdentity {
            network_name: NETWORK_NAME.to_owned(),
            network_secret: Some("shared-secret".to_owned()),
            network_secret_digest: None,
        };
        let peer_config = PortablePeerManagerConfig::new(runtime);
        let runtime_config = CoreRuntimeConfigStore::new(
            crate::config::runtime::CoreRuntimeConfig::default(),
            Arc::new(peer_config.snapshot.clone()),
        );
        let (packet_sender, packet_receiver) = create_packet_recv_chan();
        let dns = Arc::new(TestDns);
        let peer_manager = Arc::new(
            PeerManagerCore::new_portable_for_test(peer_config, dns.clone(), packet_sender)
                .expect("build portable peer manager"),
        );
        let gateway = GatewayModule::new(
            runtime_config,
            peer_manager.clone(),
            None,
            host,
            dns,
            SocketContext::default(),
            Arc::new(()),
        );

        DataPlaneEndpoint {
            gateway,
            peer_manager,
            _packet_receiver: packet_receiver,
            ip,
        }
    }

    async fn setup_data_plane_pair() -> (DataPlaneEndpoint, DataPlaneEndpoint) {
        let host = Arc::new(TestHost::default());
        let a = data_plane_endpoint(host.clone(), 1, "10.126.126.1/24".parse().unwrap());
        let b = data_plane_endpoint(host, 2, "10.126.126.2/24".parse().unwrap());

        let (run_a, run_b) = tokio::join!(a.peer_manager.run(), b.peer_manager.run());
        run_a.unwrap();
        run_b.unwrap();
        let (start_a, start_b) = tokio::join!(a.gateway.start(), b.gateway.start());
        start_a.unwrap();
        start_b.unwrap();

        let registry = Arc::new(RingTunnelRegistry::default());
        let listener_id = uuid::Uuid::new_v4();
        let mut listener = registry.bind(listener_id).unwrap();
        let client_tunnel = registry.connect(listener_id).unwrap().into_tunnel();
        let server_tunnel = listener.accept().await.unwrap().into_tunnel();
        let (client, server) = tokio::join!(
            b.peer_manager.add_client_tunnel(client_tunnel, true),
            a.peer_manager.add_tunnel_as_server(server_tunnel, true),
        );
        client.unwrap();
        server.unwrap();

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if a.peer_manager
                    .list_route_snapshots()
                    .await
                    .iter()
                    .any(|route| route.peer_id == 2 && route.ipv4_addr == Some(b.ip.into()))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Ring peers did not exchange routes");

        (a, b)
    }

    async fn stop_data_plane_pair(a: &DataPlaneEndpoint, b: &DataPlaneEndpoint) {
        tokio::join!(a.gateway.stop(), b.gateway.stop());
        tokio::join!(
            a.peer_manager.clear_resources(),
            b.peer_manager.clear_resources()
        );
    }

    fn build_tcp_packet(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        let src_ip = match src.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("test only supports ipv4"),
        };
        let dst_ip = match dst.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("test only supports ipv4"),
        };

        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buf).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(40);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(src_ip);
            ip_packet.set_destination(dst_ip);

            let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
            tcp_packet.set_source(src.port());
            tcp_packet.set_destination(dst.port());
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::SYN | TcpFlags::ACK);
            tcp_packet.set_window(65535);
            tcp_packet.set_checksum(tcp::ipv4_checksum(
                &tcp_packet.to_immutable(),
                &src_ip,
                &dst_ip,
            ));

            ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
        }

        buf
    }

    fn build_udp_followup_fragment(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buf).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(28);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_fragment_offset(1);
            ip_packet.set_source(src);
            ip_packet.set_destination(dst);
            ip_packet
                .payload_mut()
                .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);

            ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
        }

        buf
    }

    #[tokio::test]
    async fn data_plane_tcp_pingpong() {
        let (a, b) = setup_data_plane_pair().await;
        let timeout = Duration::from_secs(10);
        let mut listener = b.gateway.data_plane_tcp_bind(0, timeout).await.unwrap();
        let listen_addr = SocketAddr::new(b.ip.address().into(), listener.local_addr().port());

        let accept = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut client = a
            .gateway
            .data_plane_tcp_connect(listen_addr, timeout)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        accept.await.unwrap();

        stop_data_plane_pair(&a, &b).await;
    }

    #[tokio::test]
    async fn data_plane_udp_pingpong() {
        let (a, b) = setup_data_plane_pair().await;
        let timeout = Duration::from_secs(10);
        let socket_a = a.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
        let socket_b = b.gateway.data_plane_udp_bind(0, timeout).await.unwrap();
        let addr_a = SocketAddr::new(a.ip.address().into(), socket_a.local_addr().port());
        let addr_b = SocketAddr::new(b.ip.address().into(), socket_b.local_addr().port());

        socket_b.send_to(b"warmup", addr_a).await.unwrap();
        socket_a.send_to(b"ping", addr_b).await.unwrap();
        let mut buf = [0u8; 16];
        let (len, from) = tokio::time::timeout(timeout, socket_b.recv_from(&mut buf))
            .await
            .expect("receive ping timed out")
            .unwrap();
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(from, addr_a);

        socket_b.send_to(b"pong", addr_a).await.unwrap();
        loop {
            let (len, from) = tokio::time::timeout(timeout, socket_a.recv_from(&mut buf))
                .await
                .expect("receive pong timed out")
                .unwrap();
            if &buf[..len] == b"pong" {
                assert_eq!(from, addr_b);
                break;
            }
        }

        stop_data_plane_pair(&a, &b).await;
    }

    #[tokio::test]
    async fn startup_applies_initial_port_forwards_and_cleans_up_on_failure() {
        let gateway = test_gateway();
        gateway.runtime_config.update_services(|services| {
            services.gateway.port_forwards = vec![PortForwardConfig {
                bind_addr: "127.0.0.1:11010".parse().unwrap(),
                dst_addr: "10.0.0.2:80".parse().unwrap(),
                proto: "tcp".to_owned(),
            }];
        });

        let error = gateway.start().await.unwrap_err();

        assert!(error.to_string().contains("peer manager is gone"));
        assert_eq!(gateway.host.tcp_binds.load(Ordering::Relaxed), 1);
        assert!(gateway.cancel_tokens.is_empty());
        assert!(!gateway.started.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn socks5_consumes_modified_data_when_entry_matches() {
        let gateway = test_gateway();

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
        let entry = Socks5Entry {
            src: local,
            dst: remote,
            kind: TCP_ENTRY,
        };
        gateway.entries.insert(
            entry,
            GatewayEntryData::Tcp {
                _reservation: Arc::new(()),
            },
        );

        for packet_type in [
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
        ] {
            let mut packet = ZCPacket::new_with_payload(&build_tcp_packet(remote, local));
            packet.fill_peer_manager_hdr(1, 1, packet_type as u8);

            let result = gateway.try_process_packet_from_peer(packet).await;
            assert!(result.is_none());

            let mut receiver = gateway.packet_recv.lock().await;
            let received = receiver.try_recv().unwrap();
            assert_eq!(
                received.peer_manager_header().unwrap().packet_type,
                packet_type as u8
            );
        }
    }

    #[tokio::test]
    async fn socks5_passes_through_unmatched_or_malformed_modified_data() {
        let gateway = test_gateway();
        gateway.entries.insert(
            Socks5Entry {
                src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000),
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22),
                kind: TCP_ENTRY,
            },
            GatewayEntryData::Tcp {
                _reservation: Arc::new(()),
            },
        );

        let unmatched_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40001);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
        let mut unmatched_packet =
            ZCPacket::new_with_payload(&build_tcp_packet(remote, unmatched_local));
        unmatched_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);
        let result = gateway.try_process_packet_from_peer(unmatched_packet).await;
        assert!(result.is_some());

        let mut malformed_packet = ZCPacket::new_with_payload(&[0u8; 8]);
        malformed_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithQuicSrcModified as u8);
        let result = gateway.try_process_packet_from_peer(malformed_packet).await;
        assert!(result.is_some());

        let mut receiver = gateway.packet_recv.lock().await;
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn socks5_passes_through_non_loopback_modified_data_even_when_entry_matches() {
        let gateway = test_gateway();

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
        let entry = Socks5Entry {
            src: local,
            dst: remote,
            kind: TCP_ENTRY,
        };
        gateway.entries.insert(
            entry,
            GatewayEntryData::Tcp {
                _reservation: Arc::new(()),
            },
        );

        let mut packet = ZCPacket::new_with_payload(&build_tcp_packet(remote, local));
        packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);

        let result = gateway.try_process_packet_from_peer(packet).await;
        assert!(result.is_some());

        let mut receiver = gateway.packet_recv.lock().await;
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn socks5_mirrors_fragmented_udp_when_entry_matches() {
        let gateway = test_gateway();

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 53);
        gateway.entries.insert(
            Socks5Entry {
                src: local,
                dst: remote,
                kind: UDP_ENTRY,
            },
            GatewayEntryData::Udp((
                Arc::new(GatewayUdpSocket::Host(Arc::new(TestUdpSocket))),
                UdpClientKey {
                    client_addr: local,
                    dst_addr: remote,
                },
            )),
        );
        assert_eq!(gateway.entries.count(), 1);

        let mut packet = ZCPacket::new_with_payload(&build_udp_followup_fragment(
            match remote.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => unreachable!(),
            },
            match local.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => unreachable!(),
            },
        ));
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

        let result = gateway.try_process_packet_from_peer(packet).await;
        assert!(result.is_some());

        let mut receiver = gateway.packet_recv.lock().await;
        let received = receiver.try_recv().unwrap();
        assert_eq!(
            received.peer_manager_header().unwrap().packet_type,
            PacketType::Data as u8
        );
    }
}
