use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use crossbeam::atomic::AtomicCell;
#[cfg(feature = "kcp")]
use kcp_sys::{endpoint::KcpEndpoint, stream::KcpStream};
use quanta::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::AbortOnDropHandle;

#[cfg(feature = "kcp")]
use crate::gateway::kcp_proxy::NatDstKcpConnector;
use crate::{
    common::{config::PortForwardConfig, global_ctx::GlobalCtxEvent, join_joinset_background},
    gateway::{
        fast_socks5::{
            server::{
                AcceptAuthentication, AsyncTcpConnector, Config, SimpleUserPassword, Socks5Socket,
            },
            util::stream::tcp_connect_with_timeout,
        },
        ip_reassembler::IpReassembler,
        tokio_smoltcp::{BufferSize, Net, NetConfig, channel_device},
    },
    tunnel::packet_def::{PacketType, ZCPacket},
};
use anyhow::Context;
use dashmap::{DashMap, mapref::entry::Entry};
use pnet::packet::{
    Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UdpSocket},
    select,
    sync::{Mutex, Notify, mpsc},
    task::JoinSet,
    time::timeout,
};

#[cfg(feature = "kcp")]
use super::tcp_proxy::NatDstConnector as _;
use crate::tunnel::common::bind;
use crate::{
    common::{error::Error, global_ctx::GlobalCtx},
    peers::{PeerPacketFilter, peer_manager::PeerManager},
};

#[cfg(feature = "ffi-dataplane")]
mod dataplane;

#[cfg(feature = "ffi-dataplane")]
pub use dataplane::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};

enum SocksUdpSocket {
    UdpSocket(Arc<tokio::net::UdpSocket>),
    SmolUdpSocket(super::tokio_smoltcp::UdpSocket),
}

impl SocksUdpSocket {
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        match self {
            SocksUdpSocket::UdpSocket(socket) => socket.send_to(buf, addr).await,
            SocksUdpSocket::SmolUdpSocket(socket) => socket.send_to(buf, addr).await,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        match self {
            SocksUdpSocket::UdpSocket(socket) => socket.recv_from(buf).await,
            SocksUdpSocket::SmolUdpSocket(socket) => socket.recv_from(buf).await,
        }
    }
}

enum SocksTcpStream {
    Tcp(tokio::net::TcpStream),
    SmolTcp(super::tokio_smoltcp::TcpStream),
    #[cfg(feature = "kcp")]
    Kcp(KcpStream),
}

impl AsyncRead for SocksTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SocksTcpStream::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            SocksTcpStream::SmolTcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "kcp")]
            SocksTcpStream::Kcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SocksTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            SocksTcpStream::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            SocksTcpStream::SmolTcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "kcp")]
            SocksTcpStream::Kcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            SocksTcpStream::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            SocksTcpStream::SmolTcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "kcp")]
            SocksTcpStream::Kcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            SocksTcpStream::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            SocksTcpStream::SmolTcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "kcp")]
            SocksTcpStream::Kcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

enum Socks5EntryData {
    Tcp(TcpListener), // hold a binded socket to hold the tcp port
    #[cfg(feature = "ffi-dataplane")]
    // a data-plane routing entry that owns no resource. the entry_type in the
    // key distinguishes a listen route from an actively outbound route.
    DataPlaneRoute,
    Udp((Arc<SocksUdpSocket>, UdpClientKey)), // hold the socket to send data to dst
}

const UDP_ENTRY: u8 = 1;
const TCP_ENTRY: u8 = 2;
#[cfg(feature = "ffi-dataplane")]
const TCP_LISTEN_ENTRY: u8 = 3;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct Socks5Entry {
    src: SocketAddr,
    dst: SocketAddr,
    entry_type: u8,
}

type Socks5EntrySet = Arc<DashMap<Socks5Entry, Socks5EntryData>>;

fn increment_entry_count(entry_count: &AtomicUsize) -> (usize, usize) {
    let old_entry_count = entry_count
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            count.checked_add(1)
        })
        .unwrap_or_else(|count| count);
    (old_entry_count, old_entry_count.saturating_add(1))
}

fn decrement_entry_count(entry_count: &AtomicUsize) -> (usize, usize) {
    decrement_entry_count_by(entry_count, 1)
}

fn decrement_entry_count_by(entry_count: &AtomicUsize, delta: usize) -> (usize, usize) {
    if delta == 0 {
        let current = entry_count.load(Ordering::Relaxed);
        return (current, current);
    }

    let old_entry_count = entry_count
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            Some(count.saturating_sub(delta))
        })
        .unwrap_or_else(|count| count);
    (old_entry_count, old_entry_count.saturating_sub(delta))
}

fn insert_entry_and_increment_count(
    entries: &Socks5EntrySet,
    entry_count: &AtomicUsize,
    entry: Socks5Entry,
    data: Socks5EntryData,
) -> (bool, usize, usize) {
    match entries.entry(entry) {
        Entry::Occupied(mut occupied) => {
            occupied.insert(data);
            let current = entry_count.load(Ordering::Relaxed);
            (true, current, current)
        }
        Entry::Vacant(vacant) => {
            // Keep the count update inside the VacantEntry shard lock so bulk clear
            // cannot observe the inserted entry before its count is reserved.
            let (old_entry_count, new_entry_count) = increment_entry_count(entry_count);
            vacant.insert(data);
            (false, old_entry_count, new_entry_count)
        }
    }
}

fn try_insert_entry_and_increment_count(
    entries: &Socks5EntrySet,
    entry_count: &AtomicUsize,
    entry: Socks5Entry,
    data: Socks5EntryData,
) -> bool {
    match entries.entry(entry) {
        Entry::Occupied(_) => false,
        Entry::Vacant(vacant) => {
            // See insert_entry_and_increment_count for why the count is reserved first.
            increment_entry_count(entry_count);
            vacant.insert(data);
            true
        }
    }
}

fn remove_entry_and_decrement_count(
    entries: &Socks5EntrySet,
    entry_count: &AtomicUsize,
    entry: &Socks5Entry,
) -> (bool, usize, usize) {
    let removed = entries.remove(entry).is_some();
    let (old_entry_count, new_entry_count) = if removed {
        decrement_entry_count(entry_count)
    } else {
        let current = entry_count.load(Ordering::Relaxed);
        (current, current)
    };
    (removed, old_entry_count, new_entry_count)
}

struct SmolTcpConnector {
    net: Arc<Net>,
    entries: Socks5EntrySet,
    entry_count: Arc<AtomicUsize>,
    current_entry: std::sync::Mutex<Option<Socks5Entry>>,
}

#[async_trait::async_trait]
impl AsyncTcpConnector for SmolTcpConnector {
    type S = SocksTcpStream;

    async fn tcp_connect(
        &self,
        addr: SocketAddr,
        timeout_s: u64,
    ) -> crate::gateway::fast_socks5::Result<SocksTcpStream> {
        let tmp_listener = TcpListener::bind("0.0.0.0:0").await?;
        let local_addr = self.net.get_address();
        let port = tmp_listener.local_addr()?.port();

        let entry = Socks5Entry {
            src: SocketAddr::new(local_addr, port),
            dst: addr,
            entry_type: TCP_ENTRY,
        };
        *self.current_entry.lock().unwrap() = Some(entry.clone());
        let (replaced, old_entry_count, new_entry_count) = insert_entry_and_increment_count(
            &self.entries,
            &self.entry_count,
            entry.clone(),
            Socks5EntryData::Tcp(tmp_listener),
        );
        tracing::trace!(
            ?entry,
            replaced,
            old_entry_count,
            new_entry_count,
            entries_len = self.entries.len(),
            "socks5 inserted smoltcp tcp connector entry"
        );

        if addr.ip() == local_addr {
            let modified_addr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), addr.port());

            Ok(SocksTcpStream::Tcp(
                tcp_connect_with_timeout(modified_addr, timeout_s).await?,
            ))
        } else {
            let remote_socket = timeout(
                Duration::from_secs(timeout_s),
                self.net.tcp_connect(addr, port),
            )
            .await
            .with_context(|| "connect to remote timeout")?;

            Ok(SocksTcpStream::SmolTcp(remote_socket.map_err(|e| {
                super::fast_socks5::SocksError::Other(e.into())
            })?))
        }
    }
}

impl Drop for SmolTcpConnector {
    fn drop(&mut self) {
        if let Some(entry) = self.current_entry.lock().unwrap().take() {
            tracing::debug!("drop smoltcp connector entry {:?}", entry);
            let (removed, old_entry_count, new_entry_count) =
                remove_entry_and_decrement_count(&self.entries, &self.entry_count, &entry);
            tracing::trace!(
                ?entry,
                removed,
                old_entry_count,
                new_entry_count,
                entries_len = self.entries.len(),
                "socks5 removed smoltcp tcp connector entry"
            );
        }
    }
}

#[cfg(feature = "kcp")]
struct Socks5KcpConnector {
    kcp_endpoint: Weak<KcpEndpoint>,
    peer_mgr: Weak<PeerManager>,
    src_addr: SocketAddr,
}

#[cfg(feature = "kcp")]
#[async_trait::async_trait]
impl AsyncTcpConnector for Socks5KcpConnector {
    type S = SocksTcpStream;

    async fn tcp_connect(
        &self,
        addr: SocketAddr,
        _timeout_s: u64,
    ) -> crate::gateway::fast_socks5::Result<SocksTcpStream> {
        let Some(kcp_endpoint) = self.kcp_endpoint.upgrade() else {
            return Err(anyhow::anyhow!("kcp endpoint is not ready").into());
        };
        let c = NatDstKcpConnector {
            kcp_endpoint,
            peer_mgr: self.peer_mgr.clone(),
        };
        let ret = c
            .connect(self.src_addr, addr)
            .await
            .map_err(super::fast_socks5::SocksError::Other)?;
        Ok(SocksTcpStream::Kcp(ret))
    }
}

struct Socks5AutoConnector {
    #[cfg(feature = "kcp")]
    kcp_endpoint: Option<Weak<KcpEndpoint>>,
    peer_mgr: Weak<PeerManager>,
    entries: Socks5EntrySet,
    entry_count: Arc<AtomicUsize>,
    smoltcp_net: Option<Arc<Net>>,
    src_addr: SocketAddr,

    inner_connector: parking_lot::Mutex<Option<Box<dyn Any + Send>>>,
}

#[async_trait::async_trait]
impl AsyncTcpConnector for Socks5AutoConnector {
    type S = SocksTcpStream;

    async fn tcp_connect(
        &self,
        mut addr: SocketAddr,
        timeout_s: u64,
    ) -> crate::gateway::fast_socks5::Result<SocksTcpStream> {
        if self.inner_connector.lock().is_some() {
            return Err(anyhow::anyhow!("inner connector is already set").into());
        }

        let Some(peer_mgr_arc) = self.peer_mgr.upgrade() else {
            tracing::error!("peer manager is dropped");
            return Err(anyhow::anyhow!("peer manager is dropped").into());
        };

        if let Some(local_addr) = self.smoltcp_net.as_ref().map(|n| n.get_address())
            && local_addr == addr.ip()
        {
            addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), addr.port());
        }

        let has_smoltcp_net = self.smoltcp_net.is_some();
        let dst_peers = if has_smoltcp_net && !addr.ip().is_loopback() {
            Some(peer_mgr_arc.get_msg_dst_peer(&addr.ip()).await.0)
        } else {
            None
        };

        if !has_smoltcp_net
            || dst_peers.as_ref().is_some_and(Vec::is_empty)
            || addr.ip().is_loopback()
        {
            // cannot find dst in virtual network, so try connect to dst directly
            tracing::trace!(
                ?addr,
                src_addr = ?self.src_addr,
                has_smoltcp_net,
                dst_peer_count = dst_peers.as_ref().map(Vec::len),
                is_loopback = addr.ip().is_loopback(),
                "socks5 auto connector falling back to kernel tcp connect"
            );
            return Ok(SocksTcpStream::Tcp(
                tcp_connect_with_timeout(addr, timeout_s).await?,
            ));
        }

        let dst_allow_kcp = peer_mgr_arc.check_allow_kcp_to_dst(&addr.ip()).await;
        tracing::debug!("dst_allow_kcp: {:?}", dst_allow_kcp);

        #[cfg(feature = "kcp")]
        let connector: Box<dyn AsyncTcpConnector<S = SocksTcpStream> + Send> =
            match (&self.kcp_endpoint, dst_allow_kcp) {
                (Some(kcp_endpoint), true) => {
                    tracing::trace!(
                        ?addr,
                        src_addr = ?self.src_addr,
                        dst_peer_count = dst_peers.as_ref().map(Vec::len),
                        "socks5 auto connector selected kcp"
                    );
                    Box::new(Socks5KcpConnector {
                        kcp_endpoint: kcp_endpoint.clone(),
                        peer_mgr: self.peer_mgr.clone(),
                        src_addr: self.src_addr,
                    })
                }
                (_, _) => {
                    tracing::trace!(
                        ?addr,
                        src_addr = ?self.src_addr,
                        dst_peer_count = dst_peers.as_ref().map(Vec::len),
                        dst_allow_kcp,
                        has_kcp_endpoint = self.kcp_endpoint.is_some(),
                        "socks5 auto connector selected smoltcp"
                    );
                    Box::new(SmolTcpConnector {
                        net: self.smoltcp_net.clone().unwrap(),
                        entries: self.entries.clone(),
                        entry_count: self.entry_count.clone(),
                        current_entry: std::sync::Mutex::new(None),
                    })
                }
            };
        #[cfg(not(feature = "kcp"))]
        let connector = {
            tracing::trace!(
                ?addr,
                src_addr = ?self.src_addr,
                dst_peer_count = dst_peers.as_ref().map(Vec::len),
                "socks5 auto connector selected smoltcp"
            );
            Box::new(SmolTcpConnector {
                net: self.smoltcp_net.clone().unwrap(),
                entries: self.entries.clone(),
                entry_count: self.entry_count.clone(),
                current_entry: std::sync::Mutex::new(None),
            })
        };

        let ret = connector.tcp_connect(addr, timeout_s).await;
        self.inner_connector.lock().replace(Box::new(connector));
        ret
    }
}

struct Socks5ServerNet {
    ipv4_addr: cidr::Ipv4Inet,
    auth: Option<SimpleUserPassword>,

    smoltcp_net: Arc<Net>,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    entries: Socks5EntrySet,
}

impl Socks5ServerNet {
    pub fn new(
        ipv4_addr: cidr::Ipv4Inet,
        auth: Option<SimpleUserPassword>,
        peer_manager: Weak<PeerManager>,
        packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,
        entries: Socks5EntrySet,
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
        join_joinset_background(forward_tasks.clone(), "Socks5ServerNet".to_string());

        Self {
            ipv4_addr,
            auth,

            smoltcp_net: Arc::new(net),
            forward_tasks,

            entries,
        }
    }

    async fn handle_tcp_stream_task(stream: tokio::net::TcpStream, connector: Socks5AutoConnector) {
        let mut config = Config::<AcceptAuthentication>::default();
        config.set_request_timeout(10);
        config.set_skip_auth(false);
        config.set_allow_no_auth(true);

        let socket = Socks5Socket::new(stream, Arc::new(config), connector);

        match socket.upgrade_to_socks5().await {
            Ok(_) => {
                tracing::info!("socks5 handle success");
            }
            Err(e) => {
                tracing::error!("socks5 handshake failed: {:?}", e);
            }
        };
    }

    fn handle_tcp_stream(&self, stream: tokio::net::TcpStream, connector: Socks5AutoConnector) {
        self.forward_tasks
            .lock()
            .unwrap()
            .spawn(Self::handle_tcp_stream_task(stream, connector));
    }
}

struct UdpClientInfo {
    client_addr: SocketAddr,
    port_holder_socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    last_active: AtomicCell<Instant>,
    entries: Socks5EntrySet,
    entry_key: Socks5Entry,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct UdpClientKey {
    client_addr: SocketAddr,
    dst_addr: SocketAddr,
}

pub struct Socks5Server {
    global_ctx: Arc<GlobalCtx>,
    peer_manager: Weak<PeerManager>,
    auth: Option<SimpleUserPassword>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    packet_sender: mpsc::Sender<ZCPacket>,
    packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,

    net: Arc<Mutex<Option<Socks5ServerNet>>>,
    entries: Socks5EntrySet,

    udp_client_map: Arc<DashMap<UdpClientKey, Arc<UdpClientInfo>>>,
    udp_forward_task: Arc<DashMap<UdpClientKey, AbortOnDropHandle<()>>>,

    #[cfg(feature = "kcp")]
    kcp_endpoint: Mutex<Option<Weak<KcpEndpoint>>>,

    socks5_enabled: Arc<AtomicBool>,
    #[cfg(feature = "ffi-dataplane")]
    data_plane_refs: Arc<AtomicUsize>,
    // Tracks whether the smoltcp `net` is ready for data-plane callers.
    #[cfg(feature = "ffi-dataplane")]
    data_plane_net_ready: tokio::sync::watch::Sender<bool>,
    cancel_tokens: Arc<DashMap<PortForwardConfig, DropGuard>>,
    port_forward_list_change_notifier: Arc<Notify>,
    entry_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl PeerPacketFilter for Socks5Server {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let entry_count = self.entry_count.load(Ordering::Relaxed);
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
        let hdr = packet.peer_manager_header().unwrap();
        let is_modified_src_packet = matches!(
            hdr.packet_type,
            x if x == PacketType::DataWithKcpSrcModified as u8
                || x == PacketType::DataWithQuicSrcModified as u8
        );
        if hdr.packet_type != PacketType::Data as u8 && !is_modified_src_packet {
            return Some(packet);
        }
        if is_modified_src_packet && hdr.from_peer_id != hdr.to_peer_id {
            tracing::trace!(
                packet_type = hdr.packet_type,
                from_peer_id = hdr.from_peer_id.get(),
                to_peer_id = hdr.to_peer_id.get(),
                "socks5 passed non-loopback modified-source packet from peer"
            );
            return Some(packet);
        }

        let payload_bytes = packet.payload();

        let Some(ipv4) = Ipv4Packet::new(payload_bytes) else {
            return Some(packet);
        };
        if ipv4.get_version() != 4 {
            return Some(packet);
        }

        let (entry_key, tcp_flags) = match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let Some(tcp_packet) = TcpPacket::new(ipv4.payload()) else {
                    return Some(packet);
                };
                let entry = Socks5Entry {
                    dst: SocketAddr::new(ipv4.get_source().into(), tcp_packet.get_source()),
                    src: SocketAddr::new(
                        ipv4.get_destination().into(),
                        tcp_packet.get_destination(),
                    ),
                    entry_type: TCP_ENTRY,
                };
                #[cfg(feature = "ffi-dataplane")]
                let entry = if self.entries.contains_key(&entry) {
                    // Case 1: it is an established connection that has an exactly matched inbound.
                    entry
                } else {
                    // Case 2: it could be a new TCP SYN packet that has not been accepted.
                    Socks5Entry {
                        src: entry.src,
                        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        entry_type: TCP_LISTEN_ENTRY,
                    }
                };
                (entry, Some(tcp_packet.get_flags()))
            }

            IpNextHeaderProtocols::Udp => {
                if IpReassembler::is_packet_fragmented(&ipv4) {
                    let ipv4_src: IpAddr = ipv4.get_source().into();
                    // only send to smoltcp if the ipv4 src is in the entries
                    let is_in_entries = self.entries.iter().any(|x| x.key().dst.ip() == ipv4_src);
                    tracing::trace!(
                        ?is_in_entries,
                        "ipv4 src = {:?}, check need send both smoltcp and kernel tun",
                        ipv4_src
                    );
                    if is_in_entries {
                        // if the packet is fragmented, no matther what the payload is, need send it to both smoltcp and kernel tun. because
                        // we cannot determine the udp port of the packet.
                        match self.packet_sender.try_send(packet.clone()) {
                            Ok(()) => tracing::trace!(
                                ?ipv4_src,
                                entry_count = self.entry_count.load(Ordering::Relaxed),
                                "socks5 delivered fragmented packet from peer to smoltcp"
                            ),
                            Err(err) => tracing::trace!(
                                ?ipv4_src,
                                ?err,
                                entry_count = self.entry_count.load(Ordering::Relaxed),
                                "socks5 failed to deliver fragmented packet from peer to smoltcp"
                            ),
                        }
                    }
                    return Some(packet);
                }

                let Some(udp_packet) = UdpPacket::new(ipv4.payload()) else {
                    return Some(packet);
                };
                (
                    Socks5Entry {
                        dst: SocketAddr::new(ipv4.get_source().into(), udp_packet.get_source()),
                        src: SocketAddr::new(
                            ipv4.get_destination().into(),
                            udp_packet.get_destination(),
                        ),
                        entry_type: UDP_ENTRY,
                    },
                    None,
                )
            }
            _ => {
                return Some(packet);
            }
        };

        if !self.entries.contains_key(&entry_key) {
            tracing::trace!(
                ?entry_key,
                ?tcp_flags,
                ipv4_src = %ipv4.get_source(),
                ipv4_dst = %ipv4.get_destination(),
                entry_count = self.entry_count.load(Ordering::Relaxed),
                socks5_enabled = self.socks5_enabled.load(Ordering::Relaxed),
                "socks5 no entry for packet from peer"
            );
            return Some(packet);
        }

        tracing::trace!(
            ?entry_key,
            ?tcp_flags,
            ?ipv4,
            entry_count = self.entry_count.load(Ordering::Relaxed),
            "socks5 found entry for packet from peer"
        );

        match self.packet_sender.try_send(packet) {
            Ok(()) => tracing::trace!(
                ?entry_key,
                ?tcp_flags,
                entry_count = self.entry_count.load(Ordering::Relaxed),
                "socks5 delivered packet from peer to smoltcp"
            ),
            Err(err) => tracing::trace!(
                ?entry_key,
                ?tcp_flags,
                ?err,
                entry_count = self.entry_count.load(Ordering::Relaxed),
                "socks5 failed to deliver packet from peer to smoltcp"
            ),
        }

        None
    }
}

impl Socks5Server {
    pub fn new(
        global_ctx: Arc<GlobalCtx>,
        peer_manager: Arc<PeerManager>,
        auth: Option<SimpleUserPassword>,
    ) -> Arc<Self> {
        let (packet_sender, packet_recv) = mpsc::channel(1024);
        Arc::new(Self {
            global_ctx,
            peer_manager: Arc::downgrade(&peer_manager),
            auth,

            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            packet_recv: Arc::new(Mutex::new(packet_recv)),
            packet_sender,

            net: Arc::new(Mutex::new(None)),
            entries: Arc::new(DashMap::new()),

            udp_client_map: Arc::new(DashMap::new()),
            udp_forward_task: Arc::new(DashMap::new()),

            #[cfg(feature = "kcp")]
            kcp_endpoint: Mutex::new(None),

            socks5_enabled: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "ffi-dataplane")]
            data_plane_refs: Arc::new(AtomicUsize::new(0)),
            #[cfg(feature = "ffi-dataplane")]
            data_plane_net_ready: tokio::sync::watch::channel(false).0,
            cancel_tokens: Arc::new(DashMap::new()),
            port_forward_list_change_notifier: Arc::new(Notify::new()),
            entry_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    async fn run_net_update_task(self: &Arc<Self>) {
        let net = self.net.clone();
        let global_ctx = self.global_ctx.clone();
        let peer_manager = self.peer_manager.clone();
        let packet_recv = self.packet_recv.clone();
        let entries = self.entries.clone();
        let entry_count = self.entry_count.clone();
        let udp_client_map = self.udp_client_map.clone();
        let cancel_tokens = self.cancel_tokens.clone();
        let port_forward_list_change_notifier = self.port_forward_list_change_notifier.clone();
        let socks5_enabled = self.socks5_enabled.clone();
        #[cfg(feature = "ffi-dataplane")]
        let data_plane_refs = self.data_plane_refs.clone();
        #[cfg(feature = "ffi-dataplane")]
        let data_plane_net_ready = self.data_plane_net_ready.clone();
        self.tasks.lock().unwrap().spawn(async move {
            let mut prev_ipv4 = None;
            loop {
                #[cfg(feature = "ffi-dataplane")]
                let data_plane_active = data_plane_refs.load(Ordering::Relaxed) > 0;
                #[cfg(not(feature = "ffi-dataplane"))]
                let data_plane_active = false;

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
                        entry_count = entry_count.load(Ordering::Relaxed),
                        entries_len = entries.len(),
                        "socks5 net update waiting for consumers"
                    );
                    #[cfg(feature = "ffi-dataplane")]
                    let _ = data_plane_net_ready.send_replace(false);
                    port_forward_list_change_notifier.notified().await;
                    continue;
                }

                let mut event_recv = global_ctx.subscribe();

                let cur_ipv4 = global_ctx.get_ipv4();
                if prev_ipv4 != cur_ipv4 {
                    let old_ipv4 = prev_ipv4;
                    prev_ipv4 = cur_ipv4;

                    tracing::trace!(
                        ?old_ipv4,
                        ?cur_ipv4,
                        old_entry_count = entry_count.load(Ordering::Relaxed),
                        old_entries_len = entries.len(),
                        udp_client_count = udp_client_map.len(),
                        "socks5 net update resetting entries for ipv4 change"
                    );
                    let mut removed_entries = 0;
                    entries.retain(|_, _| {
                        removed_entries += 1;
                        false
                    });
                    let (_, new_entry_count) =
                        decrement_entry_count_by(&entry_count, removed_entries);
                    udp_client_map.clear();
                    tracing::trace!(
                        ?old_ipv4,
                        ?cur_ipv4,
                        removed_entries,
                        new_entry_count,
                        new_entries_len = entries.len(),
                        udp_client_count = udp_client_map.len(),
                        "socks5 net update reset entries complete"
                    );

                    if let Some(cur_ipv4) = cur_ipv4 {
                        net.lock().await.replace(Socks5ServerNet::new(
                            cur_ipv4,
                            None,
                            peer_manager.clone(),
                            packet_recv.clone(),
                            entries.clone(),
                        ));
                        tracing::trace!(
                            ?cur_ipv4,
                            entry_count = entry_count.load(Ordering::Relaxed),
                            entries_len = entries.len(),
                            "socks5 net update installed smoltcp net"
                        );
                        // Wake any data-plane callers waiting in
                        // `wait_data_plane_net` for the smoltcp net to appear.
                        #[cfg(feature = "ffi-dataplane")]
                        let _ = data_plane_net_ready.send_replace(true);
                    } else {
                        let _ = net.lock().await.take();
                        tracing::trace!(
                            entry_count = entry_count.load(Ordering::Relaxed),
                            entries_len = entries.len(),
                            "socks5 net update removed smoltcp net"
                        );
                        #[cfg(feature = "ffi-dataplane")]
                        let _ = data_plane_net_ready.send_replace(false);
                    }
                }

                select! {
                    _ = event_recv.recv() => {}
                    _ = tokio::time::sleep(Duration::from_secs(120)) => {}
                }
            }
        });
    }

    pub async fn run(
        self: &Arc<Self>,
        #[cfg(feature = "kcp")] kcp_endpoint: Option<Weak<KcpEndpoint>>,
    ) -> Result<(), Error> {
        #[cfg(feature = "kcp")]
        {
            *self.kcp_endpoint.lock().await = kcp_endpoint.clone();
        }
        if let Some(proxy_url) = self.global_ctx.config.get_socks5_portal() {
            let bind_addr = format!(
                "{}:{}",
                proxy_url.host_str().unwrap(),
                proxy_url.port().unwrap()
            );

            let listener = bind::<TcpListener>()
                .addr(bind_addr.parse::<SocketAddr>().unwrap())
                .net_ns(self.global_ctx.net_ns.clone())
                .call()?;

            let entries = self.entries.clone();
            let entry_count = self.entry_count.clone();
            let peer_manager = self.peer_manager.clone();
            let net = self.net.clone();
            self.tasks.lock().unwrap().spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((socket, addr)) => {
                            tracing::info!("accept a new connection, {:?}", socket);
                            let connector = Socks5AutoConnector {
                                smoltcp_net: net
                                    .lock()
                                    .await
                                    .as_ref()
                                    .map(|net| net.smoltcp_net.clone()),
                                entries: entries.clone(),
                                #[cfg(feature = "kcp")]
                                kcp_endpoint: kcp_endpoint.clone(),
                                peer_mgr: peer_manager.clone(),
                                src_addr: addr,
                                inner_connector: parking_lot::Mutex::new(None),
                                entry_count: entry_count.clone(),
                            };
                            if let Some(net) = net.lock().await.as_ref() {
                                net.handle_tcp_stream(socket, connector);
                            } else {
                                tokio::spawn(Socks5ServerNet::handle_tcp_stream_task(
                                    socket, connector,
                                ));
                            }
                        }
                        Err(err) => tracing::error!("accept error = {:?}", err),
                    }
                }
            });

            self.socks5_enabled.store(true, Ordering::Relaxed);
            join_joinset_background(self.tasks.clone(), "socks5 server".to_string());
        };

        let cfgs = self.global_ctx.config.get_port_forwards();
        self.reload_port_forwards(&cfgs).await?;

        let Some(peer_manager) = self.peer_manager.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is gone").into());
        };
        peer_manager
            .add_packet_process_pipeline(Box::new(self.clone()))
            .await;
        tracing::trace!(
            cfg_count = cfgs.len(),
            cancel_token_count = self.cancel_tokens.len(),
            entry_count = self.entry_count.load(Ordering::Relaxed),
            entries_len = self.entries.len(),
            "socks5 peer packet pipeline registered"
        );

        self.run_net_update_task().await;

        Ok(())
    }

    pub async fn reload_port_forwards(&self, cfgs: &Vec<PortForwardConfig>) -> Result<(), Error> {
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

    async fn handle_port_forward_connection(
        mut incoming_socket: tokio::net::TcpStream,
        connector: Box<dyn AsyncTcpConnector<S = SocksTcpStream> + Send>,
        dst_addr: SocketAddr,
    ) {
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

    pub async fn add_port_forward(&self, cfg: PortForwardConfig) -> Result<(), Error> {
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
                )
                .into());
            }
        }
        self.global_ctx
            .issue_event(GlobalCtxEvent::PortForwardAdded(cfg.clone().into()));
        Ok(())
    }

    pub fn remove_port_forward(&self, cfg: PortForwardConfig) {
        let _ = self.cancel_tokens.remove(&cfg);
    }

    pub async fn add_tcp_port_forward(&self, cfg: &PortForwardConfig) -> Result<(), Error> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let listener = bind::<TcpListener>()
            .addr(bind_addr)
            .net_ns(self.global_ctx.net_ns.clone())
            .call()?;

        let net = self.net.clone();
        let entries = self.entries.clone();
        let entry_count = self.entry_count.clone();
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "tcp port forward".to_string());
        let forward_tasks = tasks;
        #[cfg(feature = "kcp")]
        let kcp_endpoint = self.kcp_endpoint.lock().await.clone();
        let peer_mgr = self.peer_manager.clone();
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
                    entry_count = entry_count.load(Ordering::Relaxed),
                    entries_len = entries.len(),
                    "port forward: preparing connector"
                );

                let connector = Socks5AutoConnector {
                    #[cfg(feature = "kcp")]
                    kcp_endpoint: kcp_endpoint.clone(),
                    peer_mgr: peer_mgr.clone(),
                    entries: entries.clone(),
                    smoltcp_net,
                    src_addr: addr,
                    entry_count: entry_count.clone(),
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
    pub async fn add_udp_port_forward(&self, cfg: &PortForwardConfig) -> Result<(), Error> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let socket = Arc::new(
            bind::<UdpSocket>()
                .addr(bind_addr)
                .net_ns(self.global_ctx.net_ns.clone())
                .call()?,
        );

        let entries = self.entries.clone();
        let entry_count = self.entry_count.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let net = self.net.clone();
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
                        let _g = net_ns.guard();
                        // reserve a port so os will not use it to connect to the virtual network
                        let binded_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await;
                        if binded_socket.is_err() {
                            tracing::error!("udp port forward bind error = {:?}", binded_socket);
                            continue;
                        }
                        let binded_socket = binded_socket.unwrap();
                        let mut local_addr = binded_socket.local_addr().unwrap();
                        let Some(cur_ipv4) = net.lock().await.as_ref().map(|net| net.ipv4_addr) else {
                            continue;
                        };
                        local_addr.set_ip(cur_ipv4.address().into());

                        let entry_key = Socks5Entry {
                            src: local_addr,
                            dst: dst_addr,
                            entry_type: UDP_ENTRY,
                        };

                        tracing::debug!("udp port forward binded socket = {:?}, entry_key = {:?}", local_addr, entry_key);

                        let client_info = Arc::new(UdpClientInfo {
                            client_addr: addr,
                            port_holder_socket: Arc::new(binded_socket),
                            local_addr,
                            last_active: AtomicCell::new(Instant::now()),
                            entries: entries.clone(),
                            entry_key,
                        });
                        udp_client_map.insert(udp_client_key.clone(), client_info.clone());
                        client_info
                    }
                };

                client_info.last_active.store(Instant::now());

                let entry_data = match entries.get(&client_info.entry_key) {
                    Some(data) => data,
                    None => {
                        let guard = net.lock().await;
                        let Some(net) = guard.as_ref() else {
                            continue;
                        };
                        let local_addr = net.ipv4_addr;
                        let sokcs_udp = if dst_addr.ip() == local_addr.address() {
                            SocksUdpSocket::UdpSocket(client_info.port_holder_socket.clone())
                        } else {
                            tracing::debug!("udp port forward bind new smol udp socket, {:?}", local_addr);
                            SocksUdpSocket::SmolUdpSocket(
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
                        insert_entry_and_increment_count(
                            &entries,
                            &entry_count,
                            client_info.entry_key.clone(),
                            Socks5EntryData::Udp((socks_udp.clone(), udp_client_key.clone())),
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

                        entries.get(&client_info.entry_key).unwrap()
                    }
                };

                let s = match entry_data.value() {
                    Socks5EntryData::Udp((s, _)) => s.clone(),
                    _ => {
                        panic!("udp entry data is not udp entry data");
                    }
                };
                drop(entry_data);

                if let Err(e) = s.send_to(&buf[..len], dst_addr).await {
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
        let entry_count = self.entry_count.clone();
        let cancel_tokens = self.cancel_tokens.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = Instant::now();
                udp_client_map.retain(|_, client_info| {
                    now.duration_since(client_info.last_active.load()).as_secs() < 600
                });
                udp_forward_task.retain(|k, _| udp_client_map.contains_key(k));
                let mut removed_entries = 0;
                entries.retain(|_, data| match data {
                    Socks5EntryData::Udp((_, udp_client_key)) => {
                        let keep = udp_client_map.contains_key(udp_client_key);
                        if !keep {
                            removed_entries += 1;
                        }
                        keep
                    }
                    _ => true,
                });
                decrement_entry_count_by(&entry_count, removed_entries);

                udp_client_map.shrink_to_fit();
                udp_forward_task.shrink_to_fit();
                entries.shrink_to_fit();
                cancel_tokens.shrink_to_fit();
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use pnet::packet::{
        MutablePacket,
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        tcp::{self, MutableTcpPacket, TcpFlags},
    };

    use super::*;
    use crate::peers::tests::create_mock_peer_manager;

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
    async fn socks5_consumes_modified_data_when_entry_matches() {
        let peer_manager = create_mock_peer_manager().await;
        let server = Socks5Server::new(peer_manager.get_global_ctx(), peer_manager, None);

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
        let entry = Socks5Entry {
            src: local,
            dst: remote,
            entry_type: TCP_ENTRY,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        insert_entry_and_increment_count(
            &server.entries,
            &server.entry_count,
            entry,
            Socks5EntryData::Tcp(listener),
        );

        for packet_type in [
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
        ] {
            let mut packet = ZCPacket::new_with_payload(&build_tcp_packet(remote, local));
            packet.fill_peer_manager_hdr(1, 1, packet_type as u8);

            let result = server.try_process_packet_from_peer(packet).await;
            assert!(result.is_none());

            let mut receiver = server.packet_recv.lock().await;
            let received = receiver.try_recv().unwrap();
            assert_eq!(
                received.peer_manager_header().unwrap().packet_type,
                packet_type as u8
            );
        }
    }

    #[tokio::test]
    async fn socks5_passes_through_unmatched_or_malformed_modified_data() {
        let peer_manager = create_mock_peer_manager().await;
        let server = Socks5Server::new(peer_manager.get_global_ctx(), peer_manager, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        insert_entry_and_increment_count(
            &server.entries,
            &server.entry_count,
            Socks5Entry {
                src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000),
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22),
                entry_type: TCP_ENTRY,
            },
            Socks5EntryData::Tcp(listener),
        );

        let unmatched_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40001);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
        let mut unmatched_packet =
            ZCPacket::new_with_payload(&build_tcp_packet(remote, unmatched_local));
        unmatched_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);
        let result = server.try_process_packet_from_peer(unmatched_packet).await;
        assert!(result.is_some());

        let mut malformed_packet = ZCPacket::new_with_payload(&[0u8; 8]);
        malformed_packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithQuicSrcModified as u8);
        let result = server.try_process_packet_from_peer(malformed_packet).await;
        assert!(result.is_some());

        let mut receiver = server.packet_recv.lock().await;
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn socks5_passes_through_non_loopback_modified_data_even_when_entry_matches() {
        let peer_manager = create_mock_peer_manager().await;
        let server = Socks5Server::new(peer_manager.get_global_ctx(), peer_manager, None);

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 22);
        let entry = Socks5Entry {
            src: local,
            dst: remote,
            entry_type: TCP_ENTRY,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        insert_entry_and_increment_count(
            &server.entries,
            &server.entry_count,
            entry,
            Socks5EntryData::Tcp(listener),
        );

        let mut packet = ZCPacket::new_with_payload(&build_tcp_packet(remote, local));
        packet.fill_peer_manager_hdr(1, 2, PacketType::DataWithKcpSrcModified as u8);

        let result = server.try_process_packet_from_peer(packet).await;
        assert!(result.is_some());

        let mut receiver = server.packet_recv.lock().await;
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn socks5_mirrors_fragmented_udp_even_when_entry_count_is_stale_zero() {
        let peer_manager = create_mock_peer_manager().await;
        let server = Socks5Server::new(peer_manager.get_global_ctx(), peer_manager, None);

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 1)), 40000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 144, 144, 3)), 53);
        let udp_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        server.entries.insert(
            Socks5Entry {
                src: local,
                dst: remote,
                entry_type: UDP_ENTRY,
            },
            Socks5EntryData::Udp((
                Arc::new(SocksUdpSocket::UdpSocket(udp_socket)),
                UdpClientKey {
                    client_addr: local,
                    dst_addr: remote,
                },
            )),
        );
        assert_eq!(server.entry_count.load(Ordering::Relaxed), 0);

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

        let result = server.try_process_packet_from_peer(packet).await;
        assert!(result.is_some());

        let mut receiver = server.packet_recv.lock().await;
        let received = receiver.try_recv().unwrap();
        assert_eq!(
            received.peer_manager_header().unwrap().packet_type,
            PacketType::Data as u8
        );
    }

    #[test]
    fn decrement_entry_count_does_not_underflow() {
        let entry_count = AtomicUsize::new(0);

        let (old_entry_count, new_entry_count) = decrement_entry_count(&entry_count);

        assert_eq!(old_entry_count, 0);
        assert_eq!(new_entry_count, 0);
        assert_eq!(entry_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn removing_missing_entry_does_not_decrement_entry_count() {
        let entries = Arc::new(DashMap::new());
        let entry_count = AtomicUsize::new(1);
        let entry = Socks5Entry {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2)), 40000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)), 22),
            entry_type: TCP_ENTRY,
        };

        let (removed, old_entry_count, new_entry_count) =
            remove_entry_and_decrement_count(&entries, &entry_count, &entry);

        assert!(!removed);
        assert_eq!(old_entry_count, 1);
        assert_eq!(new_entry_count, 1);
        assert_eq!(entry_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn removing_present_entry_decrements_entry_count_once() {
        let entries = Arc::new(DashMap::new());
        let entry_count = AtomicUsize::new(0);
        let entry = Socks5Entry {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2)), 40000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)), 22),
            entry_type: TCP_ENTRY,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        insert_entry_and_increment_count(
            &entries,
            &entry_count,
            entry.clone(),
            Socks5EntryData::Tcp(listener),
        );

        let (removed, old_entry_count, new_entry_count) =
            remove_entry_and_decrement_count(&entries, &entry_count, &entry);
        let (removed_again, old_entry_count_again, new_entry_count_again) =
            remove_entry_and_decrement_count(&entries, &entry_count, &entry);

        assert!(removed);
        assert_eq!(old_entry_count, 1);
        assert_eq!(new_entry_count, 0);
        assert!(!removed_again);
        assert_eq!(old_entry_count_again, 0);
        assert_eq!(new_entry_count_again, 0);
        assert_eq!(entry_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn replacing_present_entry_does_not_increment_entry_count() {
        let entries = Arc::new(DashMap::new());
        let entry_count = AtomicUsize::new(0);
        let entry = Socks5Entry {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2)), 40000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)), 22),
            entry_type: TCP_ENTRY,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let replacement = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        let (replaced, old_entry_count, new_entry_count) = insert_entry_and_increment_count(
            &entries,
            &entry_count,
            entry.clone(),
            Socks5EntryData::Tcp(listener),
        );
        let (replaced_again, old_entry_count_again, new_entry_count_again) =
            insert_entry_and_increment_count(
                &entries,
                &entry_count,
                entry,
                Socks5EntryData::Tcp(replacement),
            );

        assert!(!replaced);
        assert_eq!(old_entry_count, 0);
        assert_eq!(new_entry_count, 1);
        assert!(replaced_again);
        assert_eq!(old_entry_count_again, 1);
        assert_eq!(new_entry_count_again, 1);
        assert_eq!(entry_count.load(Ordering::Relaxed), 1);
    }
}
