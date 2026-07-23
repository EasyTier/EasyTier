//! Data-plane access built on top of the core gateway smoltcp stack.
//!
//! This module exposes TCP streams and UDP sockets (mainly for FFI callers that
//! send traffic through EasyTier without creating OS-level proxy listeners).
//!
//! Typical usage:
//!
//! ```ignore
//! let instance = CoreInstance::new(...);
//! instance.start().await?;
//!
//! let socket = instance.data_plane_udp_bind(local_port, timeout).await?;
//! socket.send_to(buf, peer_addr).await?;
//! ```

use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Context as _;
use crossbeam::atomic::AtomicCell;
use quanta::Instant;
use tokio_util::sync::DropGuard;
use tokio_util::task::AbortOnDropHandle;

use dashmap::DashMap;
use pnet_packet::{Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    select,
    sync::{Mutex, Notify, mpsc},
    task::JoinSet,
    time::timeout,
};

use crate::{
    config::{gateway::PortForwardConfig, runtime::CoreRuntimeConfigStore},
    foundation::task::reap_joinset_background,
    gateway::{
        proxy::{
            traits::TcpProxyStream,
            wrapped_transport::{WrappedTransportKind, WrappedTransportProxyModule},
        },
        smoltcp::{BufferSize, Net, NetConfig, TcpListener, UdpSocket, channel_device},
        socks5::{
            AcceptAuthentication, AsyncTcpConnector, Config, HostSocks5ServerRuntime,
            HostSocks5TcpConnector, Result as SocksResult, Socks5Entry, Socks5EntryGuard,
            Socks5EntryKind, Socks5EntryTable, Socks5PeerPacketRoute, Socks5ServerRuntime,
            Socks5Socket, Socks5TcpConnectPlan, Socks5TcpRoute, SocksError,
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
        udp::{VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

use super::GatewayEventSink;

mod port_forward;
#[cfg(test)]
mod tests;

pub(super) enum GatewayUdpSocket {
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

pub(super) enum GatewayEntryData {
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

pub(super) struct Socks5ServerNet<H>
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
        tokio::spawn(reap_joinset_background(
            forward_tasks.clone(),
            "Socks5ServerNet",
        ));

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

pub(super) struct UdpClientInfo<H>
where
    H: VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    port_holder_socket: Arc<H::Socket>,
    local_addr: SocketAddr,
    last_active: AtomicCell<Instant>,
    entry_key: Socks5Entry,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub(super) struct UdpClientKey {
    client_addr: SocketAddr,
    dst_addr: SocketAddr,
}

pub(crate) struct GatewayModule<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    operation: Mutex<()>,
    pub(super) started: AtomicBool,
    runtime_config: CoreRuntimeConfigStore,
    pub(super) peer_manager: Weak<PeerManagerCore>,
    pub(super) transport_proxy: Option<Weak<WrappedTransportProxyModule>>,
    pub(super) host: Arc<H>,
    pub(super) socket_context: SocketContext,
    command_runtime: Arc<dyn Socks5ServerRuntime>,
    pub(super) events: Arc<dyn GatewayEventSink>,

    pub(super) tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    packet_sender: mpsc::Sender<ZCPacket>,
    packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,

    pub(super) net: Arc<Mutex<Option<Socks5ServerNet<H>>>>,
    pub(super) entries: GatewayEntrySet,

    pub(super) udp_client_map: Arc<DashMap<UdpClientKey, Arc<UdpClientInfo<H>>>>,
    pub(super) udp_forward_task: Arc<DashMap<UdpClientKey, AbortOnDropHandle<()>>>,

    socks5_enabled: Arc<AtomicBool>,
    data_plane_refs: Arc<AtomicUsize>,
    // Tracks whether the smoltcp `net` is ready for data-plane callers.
    data_plane_net_ready: tokio::sync::watch::Sender<bool>,
    pub(super) cancel_tokens: Arc<DashMap<PortForwardConfig, DropGuard>>,
    pub(super) port_forward_list_change_notifier: Arc<Notify>,
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
        tokio::spawn(reap_joinset_background(self.tasks.clone(), "gateway"));
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
            return Err(anyhow::anyhow!("peer manager is gone"));
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
}

struct DataPlaneRef {
    refs: Arc<AtomicUsize>,
    notifier: Arc<tokio::sync::Notify>,
}

/// Tracks how an established data-plane TCP stream keeps its inbound route alive.
///
/// The two variants capture the intrinsic asymmetry between the connect and
/// accept paths. An outbound stream reserved a source port through the
/// [`Socks5AutoConnector`], which owns the matching route entry and clears it on
/// drop. An accepted stream instead inherits its port and peer from the
/// listener, so it carries merely a [`Socks5EntryGuard`].
enum DataPlaneTcpStreamRoute {
    Outbound {
        _connector: Box<dyn std::any::Any + Send>,
    },
    Accepted {
        _entry: Socks5EntryGuard<GatewayEntryData>,
    },
}

/// A TCP stream created by the data plane API.
/// Can be either an actively requested outbound connection or an outbound request accepted from a TCP listener.
pub struct DataPlaneTcpStream {
    stream: GatewayTcpStream,
    local_addr: SocketAddr,
    _data_plane_ref: DataPlaneRef,
    _route: DataPlaneTcpStreamRoute,
}

/// A TCP listener created by the data plane API.
/// It accepts inbound connections and produces [`DataPlaneTcpStream`]s.
pub struct DataPlaneTcpListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    entries: GatewayEntrySet,
    _listen_route: Socks5EntryGuard<GatewayEntryData>,
    _data_plane_ref: DataPlaneRef,
}

pub struct DataPlaneUdpSocket {
    socket: Arc<GatewayUdpSocket>,
    entries: GatewayEntrySet,
    local_addr: SocketAddr,
    _data_plane_ref: DataPlaneRef,
}

impl Drop for DataPlaneRef {
    fn drop(&mut self) {
        if self.refs.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.notifier.notify_one();
        }
    }
}

impl DataPlaneTcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl DataPlaneTcpListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn accept(&mut self) -> Result<(DataPlaneTcpStream, SocketAddr), std::io::Error> {
        let (stream, peer_addr) = self.listener.accept().await?;
        let local_addr = stream.local_addr()?;
        let (route, _) = Socks5EntryGuard::register(
            self.entries.clone(),
            Socks5Entry {
                src: local_addr,
                dst: peer_addr,
                kind: TCP_ENTRY,
            },
            GatewayEntryData::DataPlaneRoute,
        );
        let accepted = DataPlaneTcpStream {
            stream: Box::new(stream),
            local_addr,
            _data_plane_ref: self._data_plane_ref.clone(),
            _route: DataPlaneTcpStreamRoute::Accepted { _entry: route },
        };
        Ok((accepted, peer_addr))
    }
}

impl AsyncRead for DataPlaneTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DataPlaneTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl DataPlaneUdpSocket {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        let key = Socks5Entry {
            src: self.local_addr,
            dst: addr,
            kind: UDP_ENTRY,
        };
        self.entries.try_insert(
            key,
            GatewayEntryData::Udp((
                self.socket.clone(),
                UdpClientKey {
                    client_addr: self.local_addr,
                    dst_addr: addr,
                },
            )),
        );
        self.socket.send_to(buf, addr).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.socket.recv_from(buf).await
    }
}

impl Drop for DataPlaneUdpSocket {
    fn drop(&mut self) {
        self.entries.retain(|_, data| {
            !matches!(data, GatewayEntryData::Udp((socket, _)) if Arc::ptr_eq(socket, &self.socket))
        });
    }
}

impl Clone for DataPlaneRef {
    fn clone(&self) -> Self {
        self.refs.fetch_add(1, Ordering::Relaxed);
        Self {
            refs: self.refs.clone(),
            notifier: self.notifier.clone(),
        }
    }
}

impl<H> GatewayModule<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    fn acquire_data_plane_ref(&self) -> DataPlaneRef {
        self.data_plane_refs.fetch_add(1, Ordering::Relaxed);
        self.port_forward_list_change_notifier.notify_one();
        DataPlaneRef {
            refs: self.data_plane_refs.clone(),
            notifier: self.port_forward_list_change_notifier.clone(),
        }
    }

    async fn wait_data_plane_net(
        &self,
        deadline: Instant,
    ) -> anyhow::Result<(cidr::Ipv4Inet, Arc<Net>)> {
        let mut ready = self.data_plane_net_ready.subscribe();
        loop {
            if let Some(net) = self
                .net
                .lock()
                .await
                .as_ref()
                .map(|net| (net.ipv4_addr, net.smoltcp_net.clone()))
            {
                return Ok(net);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(anyhow::anyhow!("data plane net is not ready"));
            }
            let _ = tokio::time::timeout(deadline - now, ready.wait_for(|ready| *ready)).await;
        }
    }

    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpStream> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        // FIXME: This is the data-plane source address reserved for route
        // matching. `Socks5AutoConnector` may fall back to direct TCP for
        // non-virtual destinations, so this is not always the OS socket's
        // local address.
        let local_port = smoltcp_net.get_port();
        let local_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let connector = Socks5AutoConnector {
            transport_proxy: self.transport_proxy.clone(),
            peer_mgr: self.peer_manager.clone(),
            entries: self.entries.clone(),
            smoltcp_net: Some(smoltcp_net),
            src_addr: local_addr,
            host: self.host.clone(),
            socket_context: self.socket_context.clone(),
            kernel_purpose: TcpSocketPurpose::DataPlane,
            inner_connector: parking_lot::Mutex::new(None),
        };

        let remaining = deadline.saturating_duration_since(Instant::now());
        let inner_timeout_s = remaining.as_secs().saturating_add(1);
        let stream =
            tokio::time::timeout(remaining, connector.tcp_connect(dst_addr, inner_timeout_s))
                .await
                .with_context(|| "data plane tcp connect timeout")?
                .map_err(anyhow::Error::from)?;
        Ok(DataPlaneTcpStream {
            stream,
            local_addr,
            _data_plane_ref: data_plane_ref,
            _route: DataPlaneTcpStreamRoute::Outbound {
                _connector: Box::new(connector),
            },
        })
    }

    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpListener> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let listener = smoltcp_net.tcp_bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let listen_route = Socks5EntryGuard::try_register(
            self.entries.clone(),
            Socks5Entry {
                src: local_addr,
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                kind: TCP_LISTEN_ENTRY,
            },
            GatewayEntryData::DataPlaneRoute,
        )
        .ok_or_else(|| anyhow::anyhow!("data plane tcp listener already exists"))?;

        Ok(DataPlaneTcpListener {
            listener,
            local_addr,
            entries: self.entries.clone(),
            _listen_route: listen_route,
            _data_plane_ref: data_plane_ref,
        })
    }

    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneUdpSocket> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let smol = smoltcp_net.udp_bind(bind_addr).await?;
        let local_addr = smol.local_addr()?;
        let socket = Arc::new(GatewayUdpSocket::SmolUdpSocket(smol));

        Ok(DataPlaneUdpSocket {
            socket,
            entries: self.entries.clone(),
            local_addr,
            _data_plane_ref: data_plane_ref,
        })
    }
}
