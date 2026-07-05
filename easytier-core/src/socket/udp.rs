use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::{
    sync::{Mutex as TokioMutex, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
};
use zerocopy::{AsBytes, FromBytes};

use crate::{
    packet::{
        UDP_TUNNEL_HEADER_SIZE, UDPTunnelHeader, UdpPacketType, V4HolePunchPacket,
        V6HolePunchPacket, ZCPacket, ZCPacketType,
    },
    socket::ring::{RingSocket, RingSocketReceiver, RingSocketSendError, RingSocketSender},
};

const UDP_SESSION_RESEND_INTERVAL: Duration = Duration::from_millis(200);
const UDP_SESSION_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const UDP_SESSION_QUEUE_CAPACITY: usize = 128;

#[async_trait]
pub trait VirtualUdpSocket: Send + Sync + 'static {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

#[async_trait]
pub trait UdpSessionControlHandler<S>: Send + Sync + 'static
where
    S: VirtualUdpSocket,
{
    async fn respond_stun(
        &self,
        _socket: Arc<S>,
        _datagram: &[u8],
        _remote_addr: SocketAddr,
    ) -> io::Result<()> {
        Ok(())
    }

    async fn send_v4_hole_punch(
        &self,
        _socket: Arc<S>,
        _dst_addr: SocketAddrV4,
    ) -> io::Result<usize> {
        Ok(0)
    }

    async fn send_v6_hole_punch(
        &self,
        _socket: Arc<S>,
        _dst_addr: SocketAddrV6,
        _preferred_src: Option<PreferredIpv6Source>,
    ) -> io::Result<usize> {
        Ok(0)
    }
}

#[derive(Debug, Default)]
pub struct NoopUdpSessionControlHandler;

#[async_trait]
impl<S> UdpSessionControlHandler<S> for NoopUdpSessionControlHandler where S: VirtualUdpSocket {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketPurpose {
    HolePunchControl,
    HolePunchCandidate,
    DirectConnect,
    PortBoundListener,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpBindOptions {
    pub local_addr: Option<SocketAddr>,
    pub purpose: UdpSocketPurpose,
}

impl UdpBindOptions {
    pub fn hole_punch_control() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::HolePunchControl,
        }
    }

    pub fn hole_punch_candidate() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::HolePunchCandidate,
        }
    }

    pub fn direct_connect() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::DirectConnect,
        }
    }

    pub fn port_bound_listener(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: Some(local_addr),
            purpose: UdpSocketPurpose::PortBoundListener,
        }
    }
}

impl Default for UdpBindOptions {
    fn default() -> Self {
        Self::hole_punch_control()
    }
}

#[async_trait]
pub trait VirtualUdpSocketFactory: Send + Sync + 'static {
    type Socket: VirtualUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreferredIpv6Source {
    pub ip: Ipv6Addr,
    pub ifindex: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum UdpSessionPacketError {
    #[error("udp packet size too small: {datagram_size:?}, packet: {packet:?}")]
    TooSmall {
        datagram_size: usize,
        packet: BytesMut,
    },
    #[error(
        "udp packet payload len not match: header len: {header_len:?}, real len: {datagram_size:?}"
    )]
    PayloadLenMismatch {
        header_len: usize,
        datagram_size: usize,
    },
}

fn new_udp_packet<F>(f: F, udp_body: &[u8]) -> ZCPacket
where
    F: FnOnce(&mut UDPTunnelHeader),
{
    let mut buf = BytesMut::new();
    buf.resize(UDP_TUNNEL_HEADER_SIZE + udp_body.len(), 0);
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(udp_body);

    let mut ret = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = ret.mut_udp_tunnel_header().unwrap();
    f(header);
    ret
}

pub fn new_syn_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Syn as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        &magic.to_le_bytes(),
    )
}

pub fn new_sack_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Sack as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        &magic.to_le_bytes(),
    )
}

fn new_data_packet(conn_id: u32, payload: &[u8]) -> io::Result<ZCPacket> {
    let len = udp_session_payload_len(payload)?;

    Ok(new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Data as u8;
            header.conn_id.set(conn_id);
            header.len.set(len);
        },
        payload,
    ))
}

fn udp_session_payload_len(payload: &[u8]) -> io::Result<u16> {
    u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("udp session payload too large: {}", payload.len()),
        )
    })
}

pub fn new_v6_hole_punch_packet(
    dst: &SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) -> ZCPacket {
    let mut body = V6HolePunchPacket::default();
    body.dst_ipv6.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    if let Some(src) = preferred_src {
        body.preferred_src_ipv6.copy_from_slice(&src.ip.octets());
        body.preferred_src_ifindex.set(src.ifindex);
    }
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V6HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V6HolePunchPacket>() as u16);
        },
        body.as_bytes(),
    )
}

pub fn new_v4_hole_punch_packet(dst: &SocketAddrV4) -> ZCPacket {
    let mut body = V4HolePunchPacket::default();
    body.dst_ipv4.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V4HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V4HolePunchPacket>() as u16);
        },
        body.as_bytes(),
    )
}

pub fn extract_dst_addr_from_v4_hole_punch_packet(buf: &[u8]) -> Option<SocketAddrV4> {
    let body = V4HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv4Addr::from(body.dst_ipv4);
    Some(SocketAddrV4::new(ip, body.dst_port.get()))
}

pub fn extract_v6_hole_punch_packet(
    buf: &[u8],
) -> Option<(SocketAddrV6, Option<PreferredIpv6Source>)> {
    let body = V6HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv6Addr::from(body.dst_ipv6);
    let preferred_src_ipv6 = Ipv6Addr::from(body.preferred_src_ipv6);
    let preferred_src = (!preferred_src_ipv6.is_unspecified()).then_some(PreferredIpv6Source {
        ip: preferred_src_ipv6,
        ifindex: body.preferred_src_ifindex.get(),
    });
    Some((
        SocketAddrV6::new(ip, body.dst_port.get(), 0, 0),
        preferred_src,
    ))
}

pub fn is_stun_packet(data: &[u8]) -> bool {
    data.len() >= UDP_TUNNEL_HEADER_SIZE
        && data[4..8] == [0x21, 0x12, 0xA4, 0x42]
        && data[0] & 0xC0 == 0
}

pub fn parse_udp_session_datagram(
    buf: BytesMut,
    allow_stun: bool,
) -> Result<ZCPacket, UdpSessionPacketError> {
    let datagram_size = buf.len();
    if datagram_size < UDP_TUNNEL_HEADER_SIZE {
        return Err(UdpSessionPacketError::TooSmall {
            datagram_size,
            packet: buf,
        });
    }

    if allow_stun && is_stun_packet(&buf[..UDP_TUNNEL_HEADER_SIZE]) {
        return Ok(ZCPacket::new_from_buf(buf, ZCPacketType::UDP));
    }

    let zc_packet = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = zc_packet.udp_tunnel_header().unwrap();
    let header_len = header.len.get() as usize;
    let real_len = datagram_size - UDP_TUNNEL_HEADER_SIZE;
    if header_len != real_len {
        return Err(UdpSessionPacketError::PayloadLenMismatch {
            header_len,
            datagram_size,
        });
    }

    Ok(zc_packet)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionKind {
    Direct,
    EasyTierMux,
}

#[derive(Debug, thiserror::Error)]
pub enum UdpSessionConnectError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("timeout")]
    Timeout,
    #[error("invalid packet: {0}")]
    InvalidPacket(String),
}

#[async_trait]
pub trait UdpSessionSocket: Send + Sync + 'static {
    fn kind(&self) -> UdpSessionKind;

    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    fn peer_addr(&self) -> std::io::Result<SocketAddr>;

    async fn send(&self, data: &[u8]) -> std::io::Result<usize>;

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionConnectRequest {
    pub remote_addr: SocketAddr,
    pub bind: UdpBindOptions,
}

impl UdpSessionConnectRequest {
    pub fn direct(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: UdpBindOptions::direct_connect(),
        }
    }

    pub fn with_bind(mut self, bind: UdpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionListenRequest {
    pub bind: UdpBindOptions,
}

impl UdpSessionListenRequest {
    pub fn new(bind: UdpBindOptions) -> Self {
        Self { bind }
    }
}

#[async_trait]
pub trait UdpSessionConnector: Send {
    type Session: UdpSessionSocket;

    async fn connect(&mut self, request: UdpSessionConnectRequest)
    -> anyhow::Result<Self::Session>;
}

#[async_trait]
pub trait UdpSessionListener: Send {
    type Session: UdpSessionSocket;

    async fn listen(&mut self, request: UdpSessionListenRequest) -> anyhow::Result<()>;

    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn accept(&mut self) -> anyhow::Result<Self::Session>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    peer_addr: SocketAddr,
    conn_id: u32,
}

impl UdpSessionKey {
    fn new(peer_addr: SocketAddr, conn_id: u32) -> Self {
        Self { peer_addr, conn_id }
    }
}

type UdpSessionRegistry = DashMap<UdpSessionKey, UdpSessionRegistryEntry>;
type DirectUdpSessionRegistry = DashMap<SocketAddr, UdpSessionRegistryEntry>;
type PendingUdpSessionConnects = DashMap<u32, PendingUdpSessionConnect>;

#[derive(Debug, Clone)]
struct UdpSessionRegistryEntry {
    incoming: Arc<StdMutex<RingSocketSender<BytesMut>>>,
    close: watch::Sender<bool>,
}

#[derive(Debug, Clone)]
struct PendingUdpSessionConnect {
    expected_addr: SocketAddr,
    magic: u64,
    session_key: Arc<StdMutex<Option<UdpSessionKey>>>,
    entry: UdpSessionRegistryEntry,
    control: mpsc::Sender<UdpConnectControl>,
    sack: watch::Sender<Option<SocketAddr>>,
}

#[derive(Debug)]
enum UdpConnectControl {
    HolePunch { recv_addr: SocketAddr },
    InvalidPacket(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpSessionLayerControl {
    Stun {
        remote_addr: SocketAddr,
        datagram: BytesMut,
    },
    V4HolePunch {
        remote_addr: SocketAddr,
        dst_addr: SocketAddrV4,
    },
    V6HolePunch {
        remote_addr: SocketAddr,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    },
}

#[derive(Debug)]
pub struct UdpSession {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    kind: UdpSessionKind,
    incoming: TokioMutex<RingSocketReceiver<BytesMut>>,
    outgoing: TokioMutex<RingSocketSender<UdpSessionOutbound>>,
    closed: watch::Receiver<bool>,
    _cleanup: UdpSessionCleanup,
}

struct UdpSessionOutbound {
    payload: BytesMut,
    completion: oneshot::Sender<io::Result<usize>>,
}

struct UdpSessionCleanup {
    session_key: Option<UdpSessionKey>,
    sessions: Option<Arc<UdpSessionRegistry>>,
    direct_peer_addr: Option<SocketAddr>,
    direct_sessions: Option<Arc<DirectUdpSessionRegistry>>,
    shutdown: Option<watch::Sender<bool>>,
    tasks: Vec<JoinHandle<()>>,
    layer_guard: Option<Box<dyn Send + Sync>>,
}

#[derive(Clone)]
struct DirectUdpSessionClose {
    peer_addr: SocketAddr,
    close: watch::Sender<bool>,
    direct_sessions: Option<Arc<DirectUdpSessionRegistry>>,
}

impl DirectUdpSessionClose {
    #[cfg(test)]
    fn standalone(peer_addr: SocketAddr, close: watch::Sender<bool>) -> Self {
        Self {
            peer_addr,
            close,
            direct_sessions: None,
        }
    }

    fn registered(
        peer_addr: SocketAddr,
        close: watch::Sender<bool>,
        direct_sessions: Arc<DirectUdpSessionRegistry>,
    ) -> Self {
        Self {
            peer_addr,
            close,
            direct_sessions: Some(direct_sessions),
        }
    }

    fn close(&self) {
        if let Some(direct_sessions) = &self.direct_sessions {
            close_direct_udp_session(direct_sessions, self.peer_addr);
        } else {
            let _ = self.close.send(true);
        }
    }
}

impl std::fmt::Debug for UdpSessionCleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSessionCleanup")
            .field("session_key", &self.session_key)
            .field("has_sessions", &self.sessions.is_some())
            .field("direct_peer_addr", &self.direct_peer_addr)
            .field("has_direct_sessions", &self.direct_sessions.is_some())
            .field("has_shutdown", &self.shutdown.is_some())
            .field("tasks", &self.tasks.len())
            .field("has_layer_guard", &self.layer_guard.is_some())
            .finish()
    }
}

impl Drop for UdpSessionCleanup {
    fn drop(&mut self) {
        if let Some(shutdown) = &self.shutdown {
            let _ = shutdown.send(true);
        }
        if let (Some(sessions), Some(session_key)) = (&self.sessions, self.session_key) {
            close_udp_session(sessions, session_key);
        }
        if let (Some(direct_sessions), Some(peer_addr)) =
            (&self.direct_sessions, self.direct_peer_addr)
        {
            close_direct_udp_session(direct_sessions, peer_addr);
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl UdpSession {
    #[cfg(test)]
    fn direct_standalone<S>(socket: Arc<S>, peer_addr: SocketAddr) -> io::Result<Self>
    where
        S: VirtualUdpSocket,
    {
        let local_addr = socket.local_addr()?;
        let rings = create_udp_session_rings();
        let (shutdown_tx, _) = watch::channel(false);
        let send_task = tokio::spawn(forward_direct_udp_session_to_socket(
            socket.clone(),
            peer_addr,
            rings.core_outgoing,
            shutdown_tx.subscribe(),
            DirectUdpSessionClose::standalone(peer_addr, rings.close_tx.clone()),
        ));
        let recv_task = tokio::spawn(forward_direct_socket_to_udp_session(
            socket,
            peer_addr,
            rings.core_incoming.clone(),
            shutdown_tx.subscribe(),
            DirectUdpSessionClose::standalone(peer_addr, rings.close_tx.clone()),
        ));

        Ok(Self {
            local_addr,
            peer_addr,
            kind: UdpSessionKind::Direct,
            incoming: TokioMutex::new(rings.session_incoming),
            outgoing: TokioMutex::new(rings.session_outgoing),
            closed: rings.close_rx,
            _cleanup: UdpSessionCleanup {
                session_key: None,
                sessions: None,
                direct_peer_addr: None,
                direct_sessions: None,
                shutdown: Some(shutdown_tx),
                tasks: vec![send_task, recv_task],
                layer_guard: None,
            },
        })
    }

    fn direct_registered<S>(
        socket: Arc<S>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        rings: UdpSessionRingParts,
        direct_sessions: Arc<DirectUdpSessionRegistry>,
        shutdown: watch::Receiver<bool>,
    ) -> Self
    where
        S: VirtualUdpSocket,
    {
        if *shutdown.borrow() {
            let _ = rings.close_tx.send(true);
        }
        let send_task = tokio::spawn(forward_direct_udp_session_to_socket(
            socket,
            peer_addr,
            rings.core_outgoing,
            shutdown,
            DirectUdpSessionClose::registered(
                peer_addr,
                rings.close_tx.clone(),
                direct_sessions.clone(),
            ),
        ));

        Self {
            local_addr,
            peer_addr,
            kind: UdpSessionKind::Direct,
            incoming: TokioMutex::new(rings.session_incoming),
            outgoing: TokioMutex::new(rings.session_outgoing),
            closed: rings.close_rx,
            _cleanup: UdpSessionCleanup {
                session_key: None,
                sessions: None,
                direct_peer_addr: Some(peer_addr),
                direct_sessions: Some(direct_sessions),
                shutdown: None,
                tasks: vec![send_task],
                layer_guard: None,
            },
        }
    }

    fn easy_tier_mux<S>(
        socket: Arc<S>,
        local_addr: SocketAddr,
        key: UdpSessionKey,
        rings: UdpSessionRingParts,
        sessions: Arc<UdpSessionRegistry>,
        shutdown: watch::Receiver<bool>,
    ) -> Self
    where
        S: VirtualUdpSocket,
    {
        if *shutdown.borrow() {
            let _ = rings.close_tx.send(true);
        }
        let send_task = tokio::spawn(forward_easy_tier_mux_session_to_udp_socket(
            socket,
            key,
            sessions.clone(),
            rings.core_outgoing,
            shutdown,
            rings.close_tx.clone(),
        ));

        Self {
            local_addr,
            peer_addr: key.peer_addr,
            kind: UdpSessionKind::EasyTierMux,
            incoming: TokioMutex::new(rings.session_incoming),
            outgoing: TokioMutex::new(rings.session_outgoing),
            closed: rings.close_rx,
            _cleanup: UdpSessionCleanup {
                session_key: Some(key),
                sessions: Some(sessions),
                direct_peer_addr: None,
                direct_sessions: None,
                shutdown: None,
                tasks: vec![send_task],
                layer_guard: None,
            },
        }
    }
}

#[derive(Debug)]
pub struct EasyTierUdpSessionLayer<S, H = NoopUdpSessionControlHandler> {
    socket: Arc<S>,
    _control_handler: Arc<H>,
    sessions: Arc<UdpSessionRegistry>,
    direct_sessions: Arc<DirectUdpSessionRegistry>,
    pending_connects: Arc<PendingUdpSessionConnects>,
    accepted_rx: TokioMutex<mpsc::Receiver<UdpSession>>,
    direct_accepted_rx: TokioMutex<mpsc::Receiver<UdpSession>>,
    direct_accept_enabled: Arc<AtomicBool>,
    priority_control_rx: TokioMutex<mpsc::Receiver<UdpSessionLayerControl>>,
    control_rx: TokioMutex<mpsc::Receiver<UdpSessionLayerControl>>,
    session_shutdown_tx: watch::Sender<bool>,
    recv_task: JoinHandle<()>,
}

impl<S> EasyTierUdpSessionLayer<S>
where
    S: VirtualUdpSocket,
{
    pub fn new(socket: Arc<S>) -> Self {
        Self::new_with_control_handler(socket, Arc::new(NoopUdpSessionControlHandler))
    }
}

impl<S, H> EasyTierUdpSessionLayer<S, H>
where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    pub fn new_with_control_handler(socket: Arc<S>, control_handler: Arc<H>) -> Self {
        let sessions = Arc::new(DashMap::new());
        let direct_sessions = Arc::new(DashMap::new());
        let pending_connects = Arc::new(DashMap::new());
        let (accepted_tx, accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (direct_accepted_tx, direct_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let direct_accept_enabled = Arc::new(AtomicBool::new(false));
        let (priority_control_tx, priority_control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (session_shutdown_tx, _) = watch::channel(false);
        let recv_task = tokio::spawn(easy_tier_mux_layer_recv_task(
            socket.clone(),
            sessions.clone(),
            direct_sessions.clone(),
            pending_connects.clone(),
            accepted_tx,
            direct_accepted_tx,
            direct_accept_enabled.clone(),
            priority_control_tx,
            control_tx,
            control_handler.clone(),
            session_shutdown_tx.clone(),
        ));

        Self {
            socket,
            _control_handler: control_handler,
            sessions,
            direct_sessions,
            pending_connects,
            accepted_rx: TokioMutex::new(accepted_rx),
            direct_accepted_rx: TokioMutex::new(direct_accepted_rx),
            direct_accept_enabled,
            priority_control_rx: TokioMutex::new(priority_control_rx),
            control_rx: TokioMutex::new(control_rx),
            session_shutdown_tx,
            recv_task,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn active_direct_session_count(&self) -> usize {
        self.direct_sessions.len()
    }

    pub fn open_direct_session(&self, remote_addr: SocketAddr) -> io::Result<UdpSession> {
        let local_addr = self.socket.local_addr()?;
        let rings = create_udp_session_rings();
        match self.direct_sessions.entry(remote_addr) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(udp_session_registry_entry(&rings));
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("direct udp session already exists for {remote_addr}"),
                ));
            }
        }

        Ok(UdpSession::direct_registered(
            self.socket.clone(),
            local_addr,
            remote_addr,
            rings,
            self.direct_sessions.clone(),
            self.session_shutdown_tx.subscribe(),
        ))
    }

    pub async fn connect(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<UdpSession, UdpSessionConnectError> {
        let local_addr = self.socket.local_addr()?;
        let magic = rand::random();
        let (control_tx, mut control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (sack_tx, mut sack_rx) = watch::channel(None);
        let rings = create_udp_session_rings();
        let session_key = Arc::new(StdMutex::new(None));
        let conn_id = loop {
            let conn_id = rand::random();
            if self
                .sessions
                .contains_key(&UdpSessionKey::new(remote_addr, conn_id))
            {
                continue;
            }

            let pending = PendingUdpSessionConnect {
                expected_addr: remote_addr,
                magic,
                session_key: session_key.clone(),
                entry: udp_session_registry_entry(&rings),
                control: control_tx.clone(),
                sack: sack_tx.clone(),
            };
            if let dashmap::mapref::entry::Entry::Vacant(entry) =
                self.pending_connects.entry(conn_id)
            {
                entry.insert(pending);
                break conn_id;
            }
        };
        let mut cleanup_guard = PendingUdpSessionGuard::new(
            self.sessions.clone(),
            self.pending_connects.clone(),
            session_key,
            conn_id,
        );

        let result = self
            .connect_with_registered_attempt(
                remote_addr,
                conn_id,
                magic,
                &mut control_rx,
                &mut sack_rx,
            )
            .await;

        match result {
            Ok(recv_addr) => {
                let key = UdpSessionKey::new(recv_addr, conn_id);
                if cleanup_guard.session_key() != Some(key) {
                    return Err(UdpSessionConnectError::InvalidPacket(format!(
                        "udp session was not registered: {key:?}"
                    )));
                }
                cleanup_guard.set_session_key(key);
                cleanup_guard.disarm_keep_session();

                Ok(UdpSession::easy_tier_mux(
                    self.socket.clone(),
                    local_addr,
                    key,
                    rings,
                    self.sessions.clone(),
                    self.session_shutdown_tx.subscribe(),
                ))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn accept(&self) -> io::Result<UdpSession> {
        let mut accepted_rx = self.accepted_rx.lock().await;
        accepted_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "udp listener closed"))
    }

    pub async fn accept_direct(&self) -> io::Result<UdpSession> {
        self.direct_accept_enabled.store(true, Ordering::Relaxed);
        let mut direct_accepted_rx = self.direct_accepted_rx.lock().await;
        direct_accepted_rx.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "direct udp listener closed")
        })
    }

    pub async fn recv_control(&self) -> io::Result<UdpSessionLayerControl> {
        let mut priority_control_rx = self.priority_control_rx.lock().await;
        let mut control_rx = self.control_rx.lock().await;
        if let Ok(packet) = priority_control_rx.try_recv() {
            return Ok(packet);
        }
        if let Ok(packet) = control_rx.try_recv() {
            return Ok(packet);
        }

        let packet = tokio::select! {
            biased;
            packet = priority_control_rx.recv() => packet,
            packet = control_rx.recv() => packet,
        };
        if let Some(packet) = packet {
            return Ok(packet);
        }

        control_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "udp listener closed"))
    }

    async fn connect_with_registered_attempt(
        &self,
        remote_addr: SocketAddr,
        conn_id: u32,
        magic: u64,
        control_rx: &mut mpsc::Receiver<UdpConnectControl>,
        sack_rx: &mut watch::Receiver<Option<SocketAddr>>,
    ) -> Result<SocketAddr, UdpSessionConnectError> {
        let syn_packet = new_syn_packet(conn_id, magic).into_bytes();
        self.socket.send_to(&syn_packet, remote_addr).await?;

        let timeout = tokio::time::sleep(UDP_SESSION_CONNECT_TIMEOUT);
        let resend_sleep = tokio::time::sleep(UDP_SESSION_RESEND_INTERVAL);
        tokio::pin!(timeout);
        tokio::pin!(resend_sleep);

        loop {
            if let Some(recv_addr) = *sack_rx.borrow_and_update() {
                return Ok(recv_addr);
            }

            tokio::select! {
                biased;
                sack = sack_rx.changed() => {
                    if sack.is_err() {
                        return Err(UdpSessionConnectError::InvalidPacket(
                            "udp sack channel closed".to_owned(),
                        ));
                    }
                    if let Some(recv_addr) = *sack_rx.borrow_and_update() {
                        return Ok(recv_addr);
                    }
                }
                _ = &mut timeout => return Err(UdpSessionConnectError::Timeout),
                _ = &mut resend_sleep => {
                    self.socket.send_to(&syn_packet, remote_addr).await?;
                    resend_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + UDP_SESSION_RESEND_INTERVAL);
                }
                control = control_rx.recv() => {
                    match control {
                        Some(UdpConnectControl::HolePunch { recv_addr }) => {
                            self.socket.send_to(&syn_packet, recv_addr).await?;
                        }
                        Some(UdpConnectControl::InvalidPacket(reason)) => {
                            tracing::debug!(?reason, "udp wait sack error");
                        }
                        None => {
                            return Err(UdpSessionConnectError::InvalidPacket(
                                "udp connect control channel closed".to_owned(),
                            ));
                        }
                    }
                }
            }
        }
    }
}

impl<S, H> Drop for EasyTierUdpSessionLayer<S, H> {
    fn drop(&mut self) {
        let _ = self.session_shutdown_tx.send(true);
        self.pending_connects.clear();
        close_all_udp_sessions(&self.sessions);
        close_all_direct_udp_sessions(&self.direct_sessions);
        self.recv_task.abort();
    }
}

#[async_trait]
impl UdpSessionSocket for UdpSession {
    fn kind(&self) -> UdpSessionKind {
        self.kind
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        if self.kind == UdpSessionKind::EasyTierMux {
            udp_session_payload_len(data)?;
        }
        let mut closed = self.closed.clone();
        if *closed.borrow() {
            return Err(udp_session_closed_error());
        }
        let (completion, sent) = oneshot::channel();
        let outbound = UdpSessionOutbound {
            payload: BytesMut::from(data),
            completion,
        };
        tokio::select! {
            biased;
            _ = closed.changed() => return Err(udp_session_closed_error()),
            ret = async {
                let mut outgoing = self.outgoing.lock().await;
                outgoing.send(outbound).await
            } => ret.map_err(ring_socket_error_to_io)?,
        }

        tokio::select! {
            biased;
            ret = sent => ret.map_err(|_| udp_session_closed_error())?,
            _ = closed.changed() => Err(udp_session_closed_error()),
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut closed = self.closed.clone();
        if *closed.borrow() {
            return Err(udp_session_closed_error());
        }
        let mut incoming = self.incoming.lock().await;
        let payload = tokio::select! {
            biased;
            _ = closed.changed() => return Err(udp_session_closed_error()),
            payload = incoming.next() => payload
                .ok_or_else(udp_session_closed_error)?
                .map_err(ring_socket_error_to_io)?,
        };
        let len = payload.len().min(buf.len());
        buf[..len].copy_from_slice(&payload[..len]);
        Ok(len)
    }
}

struct UdpSessionRingParts {
    session_incoming: RingSocketReceiver<BytesMut>,
    session_outgoing: RingSocketSender<UdpSessionOutbound>,
    core_incoming: Arc<StdMutex<RingSocketSender<BytesMut>>>,
    core_outgoing: RingSocketReceiver<UdpSessionOutbound>,
    close_tx: watch::Sender<bool>,
    close_rx: watch::Receiver<bool>,
}

fn create_udp_session_rings() -> UdpSessionRingParts {
    let (session_incoming_socket, core_incoming_socket) =
        RingSocket::pair(UDP_SESSION_QUEUE_CAPACITY);
    let (core_outgoing_socket, session_outgoing_socket) =
        RingSocket::pair(UDP_SESSION_QUEUE_CAPACITY);
    let (session_incoming, _unused_session_incoming_tx) = session_incoming_socket.split();
    let (_unused_core_incoming_rx, core_incoming) = core_incoming_socket.split();
    let (core_outgoing, _unused_core_outgoing_tx) = core_outgoing_socket.split();
    let (_unused_session_outgoing_rx, session_outgoing) = session_outgoing_socket.split();
    let (close_tx, close_rx) = watch::channel(false);
    UdpSessionRingParts {
        session_incoming,
        session_outgoing,
        core_incoming: Arc::new(StdMutex::new(core_incoming)),
        core_outgoing,
        close_tx,
        close_rx,
    }
}

fn udp_session_registry_entry(rings: &UdpSessionRingParts) -> UdpSessionRegistryEntry {
    UdpSessionRegistryEntry {
        incoming: rings.core_incoming.clone(),
        close: rings.close_tx.clone(),
    }
}

fn close_udp_session(sessions: &UdpSessionRegistry, key: UdpSessionKey) {
    if let Some((_, entry)) = sessions.remove(&key) {
        let _ = entry.close.send(true);
    }
}

fn close_direct_udp_session(direct_sessions: &DirectUdpSessionRegistry, peer_addr: SocketAddr) {
    if let Some((_, entry)) = direct_sessions.remove(&peer_addr) {
        let _ = entry.close.send(true);
    }
}

fn close_all_udp_sessions(sessions: &UdpSessionRegistry) {
    let close_senders = sessions
        .iter()
        .map(|entry| entry.value().close.clone())
        .collect::<Vec<_>>();
    for close in close_senders {
        let _ = close.send(true);
    }
    sessions.clear();
}

fn close_all_direct_udp_sessions(direct_sessions: &DirectUdpSessionRegistry) {
    let close_senders = direct_sessions
        .iter()
        .map(|entry| entry.value().close.clone())
        .collect::<Vec<_>>();
    for close in close_senders {
        let _ = close.send(true);
    }
    direct_sessions.clear();
}

fn ring_socket_error_to_io(error: crate::socket::ring::RingSocketError) -> io::Error {
    let kind = match error {
        crate::socket::ring::RingSocketError::Closed => io::ErrorKind::UnexpectedEof,
        crate::socket::ring::RingSocketError::Full => io::ErrorKind::WouldBlock,
        crate::socket::ring::RingSocketError::AlreadySplit => io::ErrorKind::Other,
    };
    io::Error::new(kind, error.to_string())
}

fn udp_session_closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "udp session closed")
}

async fn forward_direct_udp_session_to_socket<S>(
    socket: Arc<S>,
    peer_addr: SocketAddr,
    mut outgoing: RingSocketReceiver<UdpSessionOutbound>,
    mut shutdown: watch::Receiver<bool>,
    close: DirectUdpSessionClose,
) where
    S: VirtualUdpSocket,
{
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                close.close();
                break;
            }
            outbound = outgoing.next() => {
                let Some(outbound) = outbound else {
                    break;
                };
                let outbound = match outbound {
                    Ok(outbound) => outbound,
                    Err(err) => {
                        tracing::debug!(?err, ?peer_addr, "udp direct session outgoing ring closed");
                        close.close();
                        break;
                    }
                };
                match socket.send_to(&outbound.payload, peer_addr).await {
                    Ok(len) => {
                        let _ = outbound.completion.send(Ok(len));
                    }
                    Err(err) => {
                        tracing::debug!(?err, ?peer_addr, "udp direct session send error");
                        let _ = outbound.completion.send(Err(err));
                        close.close();
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
async fn forward_direct_socket_to_udp_session<S>(
    socket: Arc<S>,
    peer_addr: SocketAddr,
    incoming: Arc<StdMutex<RingSocketSender<BytesMut>>>,
    mut shutdown: watch::Receiver<bool>,
    close: DirectUdpSessionClose,
) where
    S: VirtualUdpSocket,
{
    let mut buf = [0u8; 65535];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                close.close();
                break;
            }
            ret = socket.recv_from(&mut buf) => {
                let (len, remote_addr) = match ret {
                    Ok(ret) => ret,
                    Err(err) => {
                        tracing::debug!(?err, ?peer_addr, "udp direct session recv error");
                        close.close();
                        break;
                    }
                };
                if remote_addr != peer_addr {
                    continue;
                }
                if !dispatch_payload_to_session(&incoming, BytesMut::from(&buf[..len])) {
                    close.close();
                    break;
                }
            }
        }
    }
}

async fn forward_easy_tier_mux_session_to_udp_socket<S>(
    socket: Arc<S>,
    key: UdpSessionKey,
    sessions: Arc<UdpSessionRegistry>,
    mut outgoing: RingSocketReceiver<UdpSessionOutbound>,
    mut shutdown: watch::Receiver<bool>,
    close: watch::Sender<bool>,
) where
    S: VirtualUdpSocket,
{
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                let _ = close.send(true);
                break;
            }
            outbound = outgoing.next() => {
                let Some(outbound) = outbound else {
                    break;
                };
                let outbound = match outbound {
                    Ok(outbound) => outbound,
                    Err(err) => {
                        tracing::debug!(?err, ?key, "udp mux session outgoing ring closed");
                        close_udp_session(&sessions, key);
                        break;
                    }
                };
                let payload_len = outbound.payload.len();
                let packet = match new_data_packet(key.conn_id, &outbound.payload) {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::debug!(?err, ?key, "udp mux session data packet build error");
                        let _ = outbound.completion.send(Err(err));
                        close_udp_session(&sessions, key);
                        break;
                    }
                };
                if let Err(err) = socket.send_to(&packet.into_bytes(), key.peer_addr).await {
                    tracing::debug!(?err, ?key, "udp mux session send error");
                    let _ = outbound.completion.send(Err(err));
                    close_udp_session(&sessions, key);
                    break;
                }
                let _ = outbound.completion.send(Ok(payload_len));
            }
        }
    }
}

fn dispatch_payload_to_session(
    incoming: &Arc<StdMutex<RingSocketSender<BytesMut>>>,
    payload: BytesMut,
) -> bool {
    let result = {
        let mut incoming = incoming.lock().unwrap();
        incoming.force_send(payload)
    };
    match result {
        Ok(()) => true,
        Err(RingSocketSendError::Full(_)) => {
            tracing::trace!("udp session data queue full");
            true
        }
        Err(RingSocketSendError::Closed(_)) => false,
    }
}

struct PendingUdpSessionGuard {
    sessions: Arc<UdpSessionRegistry>,
    pending_connects: Arc<PendingUdpSessionConnects>,
    session_key: Arc<StdMutex<Option<UdpSessionKey>>>,
    conn_id: u32,
    active: bool,
}

impl PendingUdpSessionGuard {
    fn new(
        sessions: Arc<UdpSessionRegistry>,
        pending_connects: Arc<PendingUdpSessionConnects>,
        session_key: Arc<StdMutex<Option<UdpSessionKey>>>,
        conn_id: u32,
    ) -> Self {
        Self {
            sessions,
            pending_connects,
            session_key,
            conn_id,
            active: true,
        }
    }

    fn session_key(&self) -> Option<UdpSessionKey> {
        *self.session_key.lock().unwrap()
    }

    fn set_session_key(&mut self, session_key: UdpSessionKey) {
        *self.session_key.lock().unwrap() = Some(session_key);
    }

    fn disarm_keep_session(mut self) {
        self.pending_connects.remove(&self.conn_id);
        self.active = false;
    }
}

impl Drop for PendingUdpSessionGuard {
    fn drop(&mut self) {
        if self.active {
            self.pending_connects.remove(&self.conn_id);
            if let Some(session_key) = self.session_key() {
                close_udp_session(&self.sessions, session_key);
            }
        }
    }
}

fn move_pending_udp_session_sender(
    sessions: &UdpSessionRegistry,
    pending: &PendingUdpSessionConnect,
    new_key: UdpSessionKey,
) -> bool {
    let mut current_key = pending.session_key.lock().unwrap();
    if let Some(current_key) = *current_key {
        return current_key == new_key;
    }

    match sessions.entry(new_key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(pending.entry.clone());
            *current_key = Some(new_key);
            true
        }
        dashmap::mapref::entry::Entry::Occupied(_) => false,
    }
}

async fn easy_tier_mux_layer_recv_task<S, H>(
    socket: Arc<S>,
    sessions: Arc<UdpSessionRegistry>,
    direct_sessions: Arc<DirectUdpSessionRegistry>,
    pending_connects: Arc<PendingUdpSessionConnects>,
    accepted: mpsc::Sender<UdpSession>,
    direct_accepted: mpsc::Sender<UdpSession>,
    direct_accept_enabled: Arc<AtomicBool>,
    priority_control: mpsc::Sender<UdpSessionLayerControl>,
    control: mpsc::Sender<UdpSessionLayerControl>,
    control_handler: Arc<H>,
    session_shutdown_tx: watch::Sender<bool>,
) where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    let mut buf = [0u8; 65535];
    let control_handler_permits = Arc::new(Semaphore::new(UDP_SESSION_QUEUE_CAPACITY));
    loop {
        let (len, remote_addr) = match socket.recv_from(&mut buf).await {
            Ok(ret) => ret,
            Err(err) => {
                tracing::debug!(?err, "udp session recv loop stopped");
                let _ = session_shutdown_tx.send(true);
                pending_connects.clear();
                close_all_udp_sessions(&sessions);
                close_all_direct_udp_sessions(&direct_sessions);
                break;
            }
        };

        let datagram = BytesMut::from(&buf[..len]);
        if is_stun_packet(&datagram) {
            spawn_stun_control_handler(
                socket.clone(),
                control_handler.clone(),
                control_handler_permits.clone(),
                datagram.clone(),
                remote_addr,
            );
            dispatch_control_packet(
                &control,
                UdpSessionLayerControl::Stun {
                    remote_addr,
                    datagram,
                },
            );
            continue;
        }

        let packet = match parse_udp_session_datagram(datagram.clone(), false) {
            Ok(packet) => packet,
            Err(err) => {
                tracing::debug!(?err, "udp session packet parse error");
                dispatch_direct_udp_datagram(
                    socket.clone(),
                    &direct_sessions,
                    &direct_accepted,
                    direct_accept_enabled.load(Ordering::Relaxed),
                    session_shutdown_tx.subscribe(),
                    remote_addr,
                    datagram,
                );
                continue;
            }
        };
        let header = packet.udp_tunnel_header().unwrap();
        let conn_id = header.conn_id.get();
        match header.msg_type {
            msg_type if msg_type == UdpPacketType::Data as u8 => {
                dispatch_data_packet(&sessions, remote_addr, conn_id, packet);
            }
            msg_type if msg_type == UdpPacketType::Syn as u8 => {
                handle_new_easy_tier_mux_connect(
                    socket.clone(),
                    sessions.clone(),
                    accepted.clone(),
                    remote_addr,
                    conn_id,
                    packet,
                    session_shutdown_tx.subscribe(),
                );
            }
            msg_type if msg_type == UdpPacketType::Sack as u8 => {
                dispatch_sack_packet(&sessions, &pending_connects, remote_addr, conn_id, packet);
            }
            msg_type if msg_type == UdpPacketType::HolePunch as u8 => {
                dispatch_hole_punch_packet(&pending_connects, remote_addr);
            }
            msg_type if msg_type == UdpPacketType::V4HolePunch as u8 => {
                dispatch_v4_hole_punch_control(
                    socket.clone(),
                    control_handler.clone(),
                    control_handler_permits.clone(),
                    &priority_control,
                    remote_addr,
                    packet,
                );
            }
            msg_type if msg_type == UdpPacketType::V6HolePunch as u8 => {
                dispatch_v6_hole_punch_control(
                    socket.clone(),
                    control_handler.clone(),
                    control_handler_permits.clone(),
                    &priority_control,
                    remote_addr,
                    packet,
                );
            }
            _ => {
                dispatch_direct_udp_datagram(
                    socket.clone(),
                    &direct_sessions,
                    &direct_accepted,
                    direct_accept_enabled.load(Ordering::Relaxed),
                    session_shutdown_tx.subscribe(),
                    remote_addr,
                    packet.into_bytes().into(),
                );
            }
        }
    }
}

fn dispatch_data_packet(
    sessions: &UdpSessionRegistry,
    peer_addr: SocketAddr,
    conn_id: u32,
    packet: ZCPacket,
) {
    let key = UdpSessionKey::new(peer_addr, conn_id);
    let Some(entry) = sessions.get(&key).map(|entry| entry.value().clone()) else {
        return;
    };

    let payload = BytesMut::from(packet.udp_payload());
    if !dispatch_payload_to_session(&entry.incoming, payload) {
        close_udp_session(sessions, key);
        tracing::debug!(?key, "udp session data queue closed");
    }
}

fn dispatch_direct_udp_datagram<S>(
    socket: Arc<S>,
    direct_sessions: &Arc<DirectUdpSessionRegistry>,
    direct_accepted: &mpsc::Sender<UdpSession>,
    direct_accept_enabled: bool,
    session_shutdown: watch::Receiver<bool>,
    remote_addr: SocketAddr,
    datagram: BytesMut,
) where
    S: VirtualUdpSocket,
{
    if let Some(entry) = direct_sessions
        .get(&remote_addr)
        .map(|entry| entry.value().clone())
    {
        if !dispatch_payload_to_session(&entry.incoming, datagram) {
            close_direct_udp_session(direct_sessions, remote_addr);
            tracing::debug!(?remote_addr, "direct udp session data queue closed");
        }
        return;
    }

    if !direct_accept_enabled {
        return;
    }

    let accept_permit = match direct_accepted.clone().try_reserve_owned() {
        Ok(permit) => permit,
        Err(err) => {
            tracing::debug!(?err, ?remote_addr, "direct udp accept queue unavailable");
            return;
        }
    };
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::debug!(?err, ?remote_addr, "direct udp get local addr error");
            return;
        }
    };
    let rings = create_udp_session_rings();
    match direct_sessions.entry(remote_addr) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(udp_session_registry_entry(&rings));
        }
        dashmap::mapref::entry::Entry::Occupied(entry) => {
            let entry = entry.get().clone();
            if !dispatch_payload_to_session(&entry.incoming, datagram) {
                close_direct_udp_session(direct_sessions, remote_addr);
                tracing::debug!(?remote_addr, "direct udp session data queue closed");
            }
            return;
        }
    }
    if !dispatch_payload_to_session(&rings.core_incoming, datagram) {
        close_direct_udp_session(direct_sessions, remote_addr);
        tracing::debug!(?remote_addr, "direct udp session data queue closed");
        return;
    }
    let session = UdpSession::direct_registered(
        socket,
        local_addr,
        remote_addr,
        rings,
        direct_sessions.clone(),
        session_shutdown,
    );
    accept_permit.send(session);
}

fn handle_new_easy_tier_mux_connect<S>(
    socket: Arc<S>,
    sessions: Arc<UdpSessionRegistry>,
    accepted: mpsc::Sender<UdpSession>,
    remote_addr: SocketAddr,
    conn_id: u32,
    packet: ZCPacket,
    session_shutdown: watch::Receiver<bool>,
) where
    S: VirtualUdpSocket,
{
    let payload = packet.udp_payload();
    if payload.len() != 8 {
        tracing::warn!(
            payload_len = payload.len(),
            ?remote_addr,
            ?conn_id,
            "udp syn packet payload len not match",
        );
        return;
    }

    let magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
    let key = UdpSessionKey::new(remote_addr, conn_id);
    let sack_packet = new_sack_packet(conn_id, magic).into_bytes();
    if sessions.contains_key(&key) {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(err) = socket.send_to(&sack_packet, remote_addr).await {
                tracing::debug!(?err, ?key, "udp resend sack packet error");
                close_udp_session(&sessions, key);
            }
        });
        return;
    }

    let accept_permit = match accepted.clone().try_reserve_owned() {
        Ok(permit) => permit,
        Err(err) => {
            tracing::debug!(?err, ?key, "udp accept queue unavailable");
            return;
        }
    };
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::debug!(?err, ?key, "udp get local addr for accepted session error");
            return;
        }
    };
    let rings = create_udp_session_rings();
    sessions.insert(key, udp_session_registry_entry(&rings));
    let session = UdpSession::easy_tier_mux(
        socket.clone(),
        local_addr,
        key,
        rings,
        sessions.clone(),
        session_shutdown,
    );
    tokio::spawn(async move {
        if let Err(err) = socket.send_to(&sack_packet, remote_addr).await {
            close_udp_session(&sessions, key);
            tracing::debug!(?err, ?key, "udp send sack packet error");
            return;
        }

        accept_permit.send(session);
    });
}

fn dispatch_sack_packet(
    sessions: &UdpSessionRegistry,
    pending_connects: &PendingUdpSessionConnects,
    recv_addr: SocketAddr,
    conn_id: u32,
    packet: ZCPacket,
) {
    let payload = packet.udp_payload();
    if payload.len() != 8 {
        if let Some(pending) = pending_connects
            .get(&conn_id)
            .map(|entry| entry.value().control.clone())
        {
            let _ = pending.try_send(UdpConnectControl::InvalidPacket(
                "udp sack packet payload len not match".to_owned(),
            ));
        }
        return;
    }

    let magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
    let Some((_, pending)) = pending_connects.remove_if(&conn_id, |_, pending| {
        pending.magic == magic && *pending.session_key.lock().unwrap() == None
    }) else {
        if let Some(pending) = pending_connects
            .get(&conn_id)
            .map(|entry| entry.value().control.clone())
        {
            let _ = pending.try_send(UdpConnectControl::InvalidPacket(
                "udp sack magic not match".to_owned(),
            ));
        }
        return;
    };

    let new_key = UdpSessionKey::new(recv_addr, conn_id);
    if !move_pending_udp_session_sender(sessions, &pending, new_key) {
        let _ = pending.control.try_send(UdpConnectControl::InvalidPacket(
            "udp session already exists".to_owned(),
        ));
        return;
    }
    if pending.sack.send(Some(recv_addr)).is_err() {
        close_udp_session(sessions, new_key);
    }
}

fn dispatch_hole_punch_packet(pending_connects: &PendingUdpSessionConnects, recv_addr: SocketAddr) {
    let controls = pending_connects
        .iter()
        .filter(|entry| entry.value().expected_addr == recv_addr)
        .map(|entry| entry.value().control.clone())
        .collect::<Vec<_>>();

    for control in controls {
        let _ = control.try_send(UdpConnectControl::HolePunch { recv_addr });
    }
}

fn spawn_stun_control_handler<S, H>(
    socket: Arc<S>,
    control_handler: Arc<H>,
    permits: Arc<Semaphore>,
    datagram: BytesMut,
    remote_addr: SocketAddr,
) where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    let Ok(permit) = permits.try_acquire_owned() else {
        tracing::debug!(?remote_addr, "udp control handler queue full");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(err) = control_handler
            .respond_stun(socket, &datagram, remote_addr)
            .await
        {
            tracing::debug!(?err, ?remote_addr, "udp respond stun packet error");
        }
    });
}

fn spawn_v4_hole_punch_control_handler<S, H>(
    socket: Arc<S>,
    control_handler: Arc<H>,
    permits: Arc<Semaphore>,
    remote_addr: SocketAddr,
    dst_addr: SocketAddrV4,
) where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    let Ok(permit) = permits.try_acquire_owned() else {
        tracing::debug!(?remote_addr, ?dst_addr, "udp control handler queue full");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(err) = control_handler.send_v4_hole_punch(socket, dst_addr).await {
            tracing::debug!(
                ?err,
                ?remote_addr,
                ?dst_addr,
                "udp send v4 hole punch packet error"
            );
        }
    });
}

fn spawn_v6_hole_punch_control_handler<S, H>(
    socket: Arc<S>,
    control_handler: Arc<H>,
    permits: Arc<Semaphore>,
    remote_addr: SocketAddr,
    dst_addr: SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    let Ok(permit) = permits.try_acquire_owned() else {
        tracing::debug!(?remote_addr, ?dst_addr, "udp control handler queue full");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(err) = control_handler
            .send_v6_hole_punch(socket, dst_addr, preferred_src)
            .await
        {
            tracing::debug!(
                ?err,
                ?remote_addr,
                ?dst_addr,
                ?preferred_src,
                "udp send v6 hole punch packet error"
            );
        }
    });
}

fn dispatch_v4_hole_punch_control<S, H>(
    socket: Arc<S>,
    control_handler: Arc<H>,
    permits: Arc<Semaphore>,
    control: &mpsc::Sender<UdpSessionLayerControl>,
    remote_addr: SocketAddr,
    packet: ZCPacket,
) where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    if !remote_addr.ip().is_loopback() {
        tracing::warn!(?remote_addr, "v4 hole punch packet should be from loopback");
        return;
    }
    if !remote_addr.ip().is_ipv4() {
        tracing::warn!(
            ?remote_addr,
            "v4 hole punch packet should be sent from ipv4"
        );
        return;
    }
    let Some(dst_addr) = extract_dst_addr_from_v4_hole_punch_packet(packet.udp_payload()) else {
        tracing::debug!(?remote_addr, "invalid v4 hole punch packet");
        return;
    };
    spawn_v4_hole_punch_control_handler(socket, control_handler, permits, remote_addr, dst_addr);
    dispatch_control_packet(
        control,
        UdpSessionLayerControl::V4HolePunch {
            remote_addr,
            dst_addr,
        },
    );
}

fn dispatch_v6_hole_punch_control<S, H>(
    socket: Arc<S>,
    control_handler: Arc<H>,
    permits: Arc<Semaphore>,
    control: &mpsc::Sender<UdpSessionLayerControl>,
    remote_addr: SocketAddr,
    packet: ZCPacket,
) where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    if !remote_addr.ip().is_loopback() {
        tracing::warn!(?remote_addr, "v6 hole punch packet should be from loopback");
        return;
    }
    if !remote_addr.ip().is_ipv6() {
        tracing::warn!(
            ?remote_addr,
            "v6 hole punch packet should be sent from ipv6"
        );
        return;
    }
    let Some((dst_addr, preferred_src)) = extract_v6_hole_punch_packet(packet.udp_payload()) else {
        tracing::debug!(?remote_addr, "invalid v6 hole punch packet");
        return;
    };
    spawn_v6_hole_punch_control_handler(
        socket,
        control_handler,
        permits,
        remote_addr,
        dst_addr,
        preferred_src,
    );
    dispatch_control_packet(
        control,
        UdpSessionLayerControl::V6HolePunch {
            remote_addr,
            dst_addr,
            preferred_src,
        },
    );
}

fn dispatch_control_packet(
    control: &mpsc::Sender<UdpSessionLayerControl>,
    packet: UdpSessionLayerControl,
) {
    if let Err(err) = control.try_send(packet) {
        tracing::debug!(?err, "udp session control queue full");
    }
}

#[derive(Debug)]
pub struct UdpSessionDialer<F> {
    factory: Arc<F>,
}

impl<F> UdpSessionDialer<F>
where
    F: VirtualUdpSocketFactory,
{
    pub fn new(factory: Arc<F>) -> Self {
        Self { factory }
    }
}

#[async_trait]
impl<F> UdpSessionConnector for UdpSessionDialer<F>
where
    F: VirtualUdpSocketFactory,
{
    type Session = UdpSession;

    async fn connect(
        &mut self,
        request: UdpSessionConnectRequest,
    ) -> anyhow::Result<Self::Session> {
        let socket = self.factory.bind_udp(request.bind).await?;
        let layer = Arc::new(EasyTierUdpSessionLayer::new(socket));
        let mut session = layer.open_direct_session(request.remote_addr)?;
        session._cleanup.layer_guard = Some(Box::new(layer));
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{
            Mutex,
            atomic::{AtomicU16, Ordering},
        },
    };

    use super::*;

    #[test]
    fn bind_options_constructors_describe_socket_purpose() {
        let listener_addr = SocketAddr::from(([0, 0, 0, 0], 12345));

        assert_eq!(
            UdpBindOptions::hole_punch_control(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::HolePunchControl,
            }
        );
        assert_eq!(
            UdpBindOptions::hole_punch_candidate(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::HolePunchCandidate,
            }
        );
        assert_eq!(
            UdpBindOptions::direct_connect(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::DirectConnect,
            }
        );
        assert_eq!(
            UdpBindOptions::port_bound_listener(listener_addr),
            UdpBindOptions {
                local_addr: Some(listener_addr),
                purpose: UdpSocketPurpose::PortBoundListener,
            }
        );
        assert_eq!(
            UdpBindOptions::default(),
            UdpBindOptions::hole_punch_control()
        );
    }

    #[test]
    fn session_connect_request_keeps_peer_scoped_udp_shape() {
        let remote_addr = SocketAddr::from(([192, 0, 2, 1], 11010));
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 22020));

        let request = UdpSessionConnectRequest::direct(remote_addr)
            .with_bind(UdpBindOptions::port_bound_listener(bind_addr));

        assert_eq!(request.remote_addr, remote_addr);
        assert_eq!(
            request.bind,
            UdpBindOptions {
                local_addr: Some(bind_addr),
                purpose: UdpSocketPurpose::PortBoundListener,
            }
        );
    }

    #[test]
    fn session_listen_request_keeps_bind_options() {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let bind = UdpBindOptions::port_bound_listener(bind_addr);

        assert_eq!(UdpSessionListenRequest::new(bind).bind, bind);
    }

    struct MockUdpSessionSocket {
        kind: UdpSessionKind,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        incoming: Mutex<Vec<u8>>,
        sent: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl UdpSessionSocket for MockUdpSessionSocket {
        fn kind(&self) -> UdpSessionKind {
            self.kind
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }

        async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let incoming = self.incoming.lock().unwrap();
            let len = incoming.len().min(buf.len());
            buf[..len].copy_from_slice(&incoming[..len]);
            Ok(len)
        }
    }

    #[tokio::test]
    async fn udp_session_socket_is_peer_scoped() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 10000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 10001));
        let socket = MockUdpSessionSocket {
            kind: UdpSessionKind::Direct,
            local_addr,
            peer_addr,
            incoming: Mutex::new(b"pong".to_vec()),
            sent: Mutex::new(Vec::new()),
        };

        assert_eq!(socket.kind(), UdpSessionKind::Direct);
        assert_eq!(socket.local_addr().unwrap(), local_addr);
        assert_eq!(socket.peer_addr().unwrap(), peer_addr);
        assert_eq!(socket.send(b"ping").await.unwrap(), 4);

        let mut buf = [0; 8];
        let len = socket.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], b"pong");
        assert_eq!(&*socket.sent.lock().unwrap(), b"ping");
    }

    struct MockUdpSessionListener {
        local_addr: SocketAddr,
        accepted: Option<MockUdpSessionSocket>,
    }

    #[async_trait]
    impl UdpSessionListener for MockUdpSessionListener {
        type Session = MockUdpSessionSocket;

        async fn listen(&mut self, request: UdpSessionListenRequest) -> anyhow::Result<()> {
            if let Some(local_addr) = request.bind.local_addr {
                self.local_addr = local_addr;
            }
            Ok(())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Session> {
            self.accepted
                .take()
                .ok_or_else(|| anyhow::anyhow!("no accepted session"))
        }
    }

    #[tokio::test]
    async fn udp_session_listener_reports_bound_local_addr_before_accept() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 10000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 10001));
        let mut listener = MockUdpSessionListener {
            local_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            accepted: Some(MockUdpSessionSocket {
                kind: UdpSessionKind::EasyTierMux,
                local_addr,
                peer_addr,
                incoming: Mutex::new(Vec::new()),
                sent: Mutex::new(Vec::new()),
            }),
        };

        listener
            .listen(UdpSessionListenRequest::new(
                UdpBindOptions::port_bound_listener(local_addr),
            ))
            .await
            .unwrap();

        assert_eq!(listener.local_addr().unwrap(), local_addr);
        assert_eq!(
            listener.accept().await.unwrap().peer_addr().unwrap(),
            peer_addr
        );
    }

    struct MockVirtualUdpSocket {
        local_addr: SocketAddr,
        incoming: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl MockVirtualUdpSocket {
        fn new(local_addr: SocketAddr, incoming: Vec<(Vec<u8>, SocketAddr)>) -> Self {
            Self {
                local_addr,
                incoming: Mutex::new(incoming.into()),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for MockVirtualUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sent.lock().unwrap().push((data.to_vec(), addr));
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let (data, remote_addr) =
                self.incoming.lock().unwrap().pop_front().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "no incoming datagram")
                })?;
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, remote_addr))
        }
    }

    struct FailingSendVirtualUdpSocket {
        local_addr: SocketAddr,
    }

    #[async_trait]
    impl VirtualUdpSocket for FailingSendVirtualUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "injected send failure",
            ))
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug, Default)]
    struct RecordingUdpSessionControlHandler {
        stun_responses: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        v4_hole_punches: Mutex<Vec<SocketAddrV4>>,
        v6_hole_punches: Mutex<Vec<(SocketAddrV6, Option<PreferredIpv6Source>)>>,
    }

    impl RecordingUdpSessionControlHandler {
        fn stun_responses(&self) -> Vec<(Vec<u8>, SocketAddr)> {
            self.stun_responses.lock().unwrap().clone()
        }

        fn v4_hole_punches(&self) -> Vec<SocketAddrV4> {
            self.v4_hole_punches.lock().unwrap().clone()
        }

        fn v6_hole_punches(&self) -> Vec<(SocketAddrV6, Option<PreferredIpv6Source>)> {
            self.v6_hole_punches.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UdpSessionControlHandler<MockVirtualUdpSocket> for RecordingUdpSessionControlHandler {
        async fn respond_stun(
            &self,
            _socket: Arc<MockVirtualUdpSocket>,
            datagram: &[u8],
            remote_addr: SocketAddr,
        ) -> io::Result<()> {
            self.stun_responses
                .lock()
                .unwrap()
                .push((datagram.to_vec(), remote_addr));
            Ok(())
        }

        async fn send_v4_hole_punch(
            &self,
            _socket: Arc<MockVirtualUdpSocket>,
            dst_addr: SocketAddrV4,
        ) -> io::Result<usize> {
            self.v4_hole_punches.lock().unwrap().push(dst_addr);
            Ok(1)
        }

        async fn send_v6_hole_punch(
            &self,
            _socket: Arc<MockVirtualUdpSocket>,
            dst_addr: SocketAddrV6,
            preferred_src: Option<PreferredIpv6Source>,
        ) -> io::Result<usize> {
            self.v6_hole_punches
                .lock()
                .unwrap()
                .push((dst_addr, preferred_src));
            Ok(1)
        }
    }

    #[derive(Debug, Default)]
    struct BlockingUdpSessionControlHandler {
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl UdpSessionControlHandler<MockVirtualUdpSocket> for BlockingUdpSessionControlHandler {
        async fn respond_stun(
            &self,
            _socket: Arc<MockVirtualUdpSocket>,
            _datagram: &[u8],
            _remote_addr: SocketAddr,
        ) -> io::Result<()> {
            self.started.notify_waiters();
            self.release.notified().await;
            Ok(())
        }
    }

    struct AutoSackVirtualUdpSocket {
        local_addr: SocketAddr,
        incoming: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        incoming_notify: tokio::sync::Notify,
    }

    impl AutoSackVirtualUdpSocket {
        fn new(local_addr: SocketAddr) -> Self {
            Self {
                local_addr,
                incoming: Mutex::new(VecDeque::new()),
                sent: Mutex::new(Vec::new()),
                incoming_notify: tokio::sync::Notify::new(),
            }
        }

        fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for AutoSackVirtualUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sent.lock().unwrap().push((data.to_vec(), addr));
            if let Ok(packet) = parse_udp_session_datagram(BytesMut::from(data), false) {
                let header = packet.udp_tunnel_header().unwrap();
                if header.msg_type == UdpPacketType::Syn as u8 && packet.udp_payload().len() == 8 {
                    let conn_id = header.conn_id.get();
                    let magic = u64::from_le_bytes(packet.udp_payload()[..8].try_into().unwrap());
                    self.incoming
                        .lock()
                        .unwrap()
                        .push_back((new_sack_packet(conn_id, magic).into_bytes().to_vec(), addr));
                    self.incoming_notify.notify_one();
                }
            }
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            loop {
                if let Some((data, remote_addr)) = self.incoming.lock().unwrap().pop_front() {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    return Ok((len, remote_addr));
                }
                self.incoming_notify.notified().await;
            }
        }
    }

    #[async_trait]
    impl UdpSessionControlHandler<AutoSackVirtualUdpSocket> for BlockingUdpSessionControlHandler {
        async fn respond_stun(
            &self,
            _socket: Arc<AutoSackVirtualUdpSocket>,
            _datagram: &[u8],
            _remote_addr: SocketAddr,
        ) -> io::Result<()> {
            self.started.notify_waiters();
            self.release.notified().await;
            Ok(())
        }
    }

    fn create_test_easy_tier_mux_session<S>(
        socket: Arc<S>,
        key: UdpSessionKey,
        sessions: Arc<UdpSessionRegistry>,
    ) -> (UdpSession, watch::Sender<bool>)
    where
        S: VirtualUdpSocket,
    {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        (
            create_test_easy_tier_mux_session_with_shutdown(socket, key, sessions, shutdown_rx),
            shutdown_tx,
        )
    }

    fn create_test_easy_tier_mux_session_with_shutdown<S>(
        socket: Arc<S>,
        key: UdpSessionKey,
        sessions: Arc<UdpSessionRegistry>,
        shutdown: watch::Receiver<bool>,
    ) -> UdpSession
    where
        S: VirtualUdpSocket,
    {
        let local_addr = socket.local_addr().unwrap();
        let rings = create_udp_session_rings();
        sessions.insert(key, udp_session_registry_entry(&rings));
        UdpSession::easy_tier_mux(socket, local_addr, key, rings, sessions, shutdown)
    }

    async fn wait_for_sent<F>(mut sent: F, min_len: usize) -> Vec<(Vec<u8>, SocketAddr)>
    where
        F: FnMut() -> Vec<(Vec<u8>, SocketAddr)>,
    {
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                let packets = sent();
                if packets.len() >= min_len {
                    return packets;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn direct_udp_session_sends_to_peer_addr() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let session = UdpSession::direct_standalone(socket.clone(), peer_addr).unwrap();

        assert_eq!(session.kind(), UdpSessionKind::Direct);
        assert_eq!(session.local_addr().unwrap(), local_addr);
        assert_eq!(session.peer_addr().unwrap(), peer_addr);
        assert_eq!(session.send(b"hello").await.unwrap(), 5);

        let sent = wait_for_sent(|| socket.sent(), 1).await;
        assert_eq!(sent, vec![(b"hello".to_vec(), peer_addr)]);
    }

    #[tokio::test]
    async fn direct_udp_session_receives_only_from_peer_addr() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let unexpected_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        socket.incoming.lock().unwrap().extend([
            (b"noise".to_vec(), unexpected_addr),
            (b"payload".to_vec(), peer_addr),
        ]);
        socket.incoming_notify.notify_one();
        let session = UdpSession::direct_standalone(socket, peer_addr).unwrap();

        let mut buf = [0; 16];
        let len = session.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], b"payload");
    }

    #[tokio::test]
    async fn direct_udp_session_send_failure_closes_recv() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(FailingSendVirtualUdpSocket { local_addr });
        let session = UdpSession::direct_standalone(socket, peer_addr).unwrap();

        let err = tokio::time::timeout(Duration::from_secs(1), session.send(b"payload"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);

        let mut buf = [0; 16];
        let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn udp_layer_routes_raw_datagrams_to_registered_direct_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = EasyTierUdpSessionLayer::new(socket.clone());
        let session = layer.open_direct_session(peer_addr).unwrap();

        assert_eq!(session.kind(), UdpSessionKind::Direct);
        assert_eq!(session.send(b"outbound").await.unwrap(), 8);
        let sent = wait_for_sent(|| socket.sent(), 1).await;
        assert_eq!(sent, vec![(b"outbound".to_vec(), peer_addr)]);

        socket
            .incoming
            .lock()
            .unwrap()
            .push_back((b"inbound".to_vec(), peer_addr));
        socket.incoming_notify.notify_one();

        let mut buf = [0; 16];
        let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&buf[..len], b"inbound");
    }

    #[tokio::test]
    async fn udp_layer_accepts_direct_session_from_unknown_raw_datagram_when_enabled() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = Arc::new(EasyTierUdpSessionLayer::new(socket.clone()));
        let accept_task = tokio::spawn({
            let layer = layer.clone();
            async move { layer.accept_direct().await }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !layer.direct_accept_enabled.load(Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        socket
            .incoming
            .lock()
            .unwrap()
            .push_back((b"first".to_vec(), peer_addr));
        socket.incoming_notify.notify_one();

        let accepted = tokio::time::timeout(Duration::from_secs(1), accept_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(accepted.kind(), UdpSessionKind::Direct);
        assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
        assert_eq!(layer.active_direct_session_count(), 1);

        let mut buf = [0; 16];
        let len = accepted.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"first");
    }

    #[tokio::test]
    async fn udp_layer_keeps_easy_tier_syn_out_of_direct_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = EasyTierUdpSessionLayer::new(socket.clone());
        let session = layer.open_direct_session(peer_addr).unwrap();
        let syn = new_syn_packet(0x1122_3344, 0x5566_7788).into_bytes();

        socket
            .incoming
            .lock()
            .unwrap()
            .push_back((syn.to_vec(), peer_addr));
        socket.incoming_notify.notify_one();

        tokio::time::timeout(Duration::from_secs(1), async {
            while layer.active_session_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let mut buf = [0; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), session.recv(&mut buf))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn easy_tier_mux_udp_session_wraps_sent_payloads() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let sessions = Arc::new(DashMap::new());
        let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
            socket.clone(),
            UdpSessionKey::new(peer_addr, conn_id),
            sessions,
        );

        assert_eq!(session.kind(), UdpSessionKind::EasyTierMux);
        assert_eq!(session.send(b"payload").await.unwrap(), 7);

        let sent = wait_for_sent(|| socket.sent(), 1).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, peer_addr);

        let packet = parse_udp_session_datagram(BytesMut::from(sent[0].0.as_slice()), false)
            .expect("sent datagram should keep EasyTier UDP packet shape");
        let header = packet.udp_tunnel_header().unwrap();
        assert_eq!(header.conn_id.get(), conn_id);
        assert_eq!(header.msg_type, UdpPacketType::Data as u8);
        assert_eq!(header.len.get(), 7);
        assert_eq!(packet.udp_payload(), b"payload");
    }

    #[tokio::test]
    async fn easy_tier_mux_udp_session_rejects_oversized_payload_before_enqueue() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let sessions = Arc::new(DashMap::new());
        let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
            socket.clone(),
            UdpSessionKey::new(peer_addr, conn_id),
            sessions,
        );

        let payload = vec![0; u16::MAX as usize + 1];
        let err = session.send(&payload).await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(socket.sent().is_empty());
    }

    #[tokio::test]
    async fn easy_tier_mux_udp_session_send_failure_closes_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let key = UdpSessionKey::new(peer_addr, conn_id);
        let socket = Arc::new(FailingSendVirtualUdpSocket { local_addr });
        let sessions = Arc::new(DashMap::new());
        let (session, _shutdown_tx) =
            create_test_easy_tier_mux_session(socket, key, sessions.clone());

        let err = tokio::time::timeout(Duration::from_secs(1), session.send(b"payload"))
            .await
            .unwrap()
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        tokio::time::timeout(Duration::from_secs(1), async {
            while sessions.contains_key(&key) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let mut buf = [0; 16];
        let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn easy_tier_mux_udp_session_receives_only_peer_data_payloads() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let unexpected_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let conn_id = 0x1122_3344;
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let sessions = Arc::new(DashMap::new());
        let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
            socket,
            UdpSessionKey::new(peer_addr, conn_id),
            sessions.clone(),
        );

        dispatch_data_packet(
            &sessions,
            unexpected_addr,
            conn_id,
            new_data_packet(conn_id, b"wrong-peer").unwrap(),
        );
        dispatch_data_packet(
            &sessions,
            peer_addr,
            conn_id + 1,
            new_data_packet(conn_id + 1, b"wrong-conn").unwrap(),
        );
        dispatch_data_packet(
            &sessions,
            peer_addr,
            conn_id,
            new_data_packet(conn_id, b"payload").unwrap(),
        );

        let mut buf = [0; 16];
        let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&buf[..len], b"payload");
    }

    #[tokio::test]
    async fn easy_tier_udp_session_layer_connects_with_shared_recv_loop() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = EasyTierUdpSessionLayer::new(socket.clone());

        let session = tokio::time::timeout(Duration::from_secs(1), layer.connect(peer_addr))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(layer.local_addr().unwrap(), local_addr);
        assert_eq!(session.kind(), UdpSessionKind::EasyTierMux);
        assert_eq!(session.peer_addr().unwrap(), peer_addr);

        let sent = socket.sent();
        assert!(!sent.is_empty());
        let packet = parse_udp_session_datagram(BytesMut::from(sent[0].0.as_slice()), false)
            .expect("first sent datagram should be syn");
        assert_eq!(
            packet.udp_tunnel_header().unwrap().msg_type,
            UdpPacketType::Syn as u8
        );
    }

    #[tokio::test]
    async fn cancelled_easy_tier_udp_session_connect_cleans_registered_state() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let layer = EasyTierUdpSessionLayer::new(socket);

        let result =
            tokio::time::timeout(Duration::from_millis(50), layer.connect(peer_addr)).await;

        assert!(result.is_err());
        assert!(layer.pending_connects.is_empty());
        assert!(layer.sessions.is_empty());
    }

    #[tokio::test]
    async fn dropping_easy_tier_udp_session_layer_closes_session_recv() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = EasyTierUdpSessionLayer::new(socket.clone());
        let session = layer.connect(peer_addr).await.unwrap();
        drop(layer);

        let mut buf = [0; 16];
        let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn udp_session_recv_loop_error_closes_registered_sessions() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let sessions = Arc::new(DashMap::new());
        let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
        let session = create_test_easy_tier_mux_session_with_shutdown(
            socket.clone(),
            UdpSessionKey::new(peer_addr, conn_id),
            sessions.clone(),
            session_shutdown_rx,
        );
        let pending_connects = Arc::new(DashMap::new());
        let direct_sessions = Arc::new(DashMap::new());
        let (accepted_tx, _accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (direct_accepted_tx, _direct_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let direct_accept_enabled = Arc::new(AtomicBool::new(false));
        let (priority_control_tx, _priority_control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);

        easy_tier_mux_layer_recv_task(
            socket,
            sessions.clone(),
            direct_sessions.clone(),
            pending_connects.clone(),
            accepted_tx,
            direct_accepted_tx,
            direct_accept_enabled,
            priority_control_tx,
            control_tx,
            Arc::new(NoopUdpSessionControlHandler),
            session_shutdown_tx,
        )
        .await;

        assert!(sessions.is_empty());
        assert!(direct_sessions.is_empty());
        assert!(pending_connects.is_empty());

        let mut buf = [0; 16];
        let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let err = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Err(err) = session.send(b"payload").await {
                    return err;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn easy_tier_udp_session_layer_accepts_syn_and_sends_sack() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let sessions = Arc::new(DashMap::new());
        let (accepted_tx, mut accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        handle_new_easy_tier_mux_connect(
            socket.clone(),
            sessions.clone(),
            accepted_tx,
            peer_addr,
            conn_id,
            new_syn_packet(conn_id, magic),
            shutdown_rx,
        );

        let accepted = tokio::time::timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.kind(), UdpSessionKind::EasyTierMux);
        assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
        assert!(sessions.contains_key(&UdpSessionKey::new(peer_addr, conn_id)));

        let sent = wait_for_sent(|| socket.sent(), 1).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, peer_addr);
        let packet = parse_udp_session_datagram(BytesMut::from(sent[0].0.as_slice()), false)
            .expect("sent datagram should be sack");
        let header = packet.udp_tunnel_header().unwrap();
        assert_eq!(header.conn_id.get(), conn_id);
        assert_eq!(header.msg_type, UdpPacketType::Sack as u8);
        assert_eq!(packet.udp_payload(), magic.to_le_bytes());
    }

    #[tokio::test]
    async fn duplicate_syn_sack_send_failure_closes_existing_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let key = UdpSessionKey::new(peer_addr, conn_id);
        let socket = Arc::new(FailingSendVirtualUdpSocket { local_addr });
        let sessions = Arc::new(DashMap::new());
        let (session, _shutdown_tx) =
            create_test_easy_tier_mux_session(socket.clone(), key, sessions.clone());
        let (accepted_tx, _accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (_session_shutdown_tx, session_shutdown_rx) = watch::channel(false);

        handle_new_easy_tier_mux_connect(
            socket,
            sessions.clone(),
            accepted_tx,
            peer_addr,
            conn_id,
            new_syn_packet(conn_id, magic),
            session_shutdown_rx,
        );

        let mut buf = [0; 16];
        let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(!sessions.contains_key(&key));
    }

    #[tokio::test]
    async fn full_accept_queue_does_not_block_udp_session_recv_loop() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let sessions = Arc::new(DashMap::new());
        let full_sessions = Arc::new(DashMap::new());
        let (accepted_tx, mut accepted_rx) = mpsc::channel(1);
        let (queued_session, _queued_shutdown_tx) = create_test_easy_tier_mux_session(
            socket.clone(),
            UdpSessionKey::new(SocketAddr::from(([127, 0, 0, 1], 12002)), 7),
            full_sessions,
        );
        accepted_tx.try_send(queued_session).unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        handle_new_easy_tier_mux_connect(
            socket.clone(),
            sessions.clone(),
            accepted_tx,
            peer_addr,
            conn_id,
            new_syn_packet(conn_id, magic),
            shutdown_rx,
        );

        assert!(accepted_rx.try_recv().is_ok());
        assert!(!sessions.contains_key(&UdpSessionKey::new(peer_addr, conn_id)));
        assert!(socket.sent().is_empty());
    }

    #[tokio::test]
    async fn easy_tier_udp_session_layer_routes_stun_and_hole_punch_control_packets() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let stun_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let rejected_remote_addr = SocketAddr::from(([192, 0, 2, 1], 12001));
        let v4_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let v6_remote_addr = "[::1]:12003".parse::<SocketAddr>().unwrap();
        let dst_v4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 1234);
        let dst_v6 = "[2001:db8::1]:2345".parse::<SocketAddrV6>().unwrap();
        let preferred_src = PreferredIpv6Source {
            ip: "2001:db8::2".parse().unwrap(),
            ifindex: 42,
        };
        let mut stun = vec![0; UDP_TUNNEL_HEADER_SIZE];
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let socket = Arc::new(MockVirtualUdpSocket::new(
            local_addr,
            vec![
                (stun.clone(), stun_remote_addr),
                (
                    new_v4_hole_punch_packet(&dst_v4).into_bytes().to_vec(),
                    rejected_remote_addr,
                ),
                (
                    new_v4_hole_punch_packet(&dst_v4).into_bytes().to_vec(),
                    v4_remote_addr,
                ),
                (
                    new_v6_hole_punch_packet(&dst_v6, Some(preferred_src))
                        .into_bytes()
                        .to_vec(),
                    v6_remote_addr,
                ),
            ],
        ));
        let control_handler = Arc::new(RecordingUdpSessionControlHandler::default());
        let layer =
            EasyTierUdpSessionLayer::new_with_control_handler(socket, control_handler.clone());

        let mut events = Vec::new();
        for _ in 0..3 {
            events.push(
                tokio::time::timeout(Duration::from_secs(1), layer.recv_control())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert!(events.contains(&UdpSessionLayerControl::Stun {
            remote_addr: stun_remote_addr,
            datagram: BytesMut::from(stun.as_slice()),
        }));
        assert!(events.contains(&UdpSessionLayerControl::V4HolePunch {
            remote_addr: v4_remote_addr,
            dst_addr: dst_v4,
        }));
        assert!(events.contains(&UdpSessionLayerControl::V6HolePunch {
            remote_addr: v6_remote_addr,
            dst_addr: dst_v6,
            preferred_src: Some(preferred_src),
        }));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if control_handler
                    .stun_responses()
                    .contains(&(stun.clone(), stun_remote_addr))
                    && control_handler.v4_hole_punches().contains(&dst_v4)
                    && control_handler
                        .v6_hole_punches()
                        .contains(&(dst_v6, Some(preferred_src)))
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            control_handler
                .stun_responses()
                .contains(&(stun, stun_remote_addr))
        );
        assert!(control_handler.v4_hole_punches().contains(&dst_v4));
        assert!(
            control_handler
                .v6_hole_punches()
                .contains(&(dst_v6, Some(preferred_src)))
        );
    }

    #[tokio::test]
    async fn udp_session_recv_loop_does_not_wait_for_control_handler() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let stun_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let conn_id = 0x1122_3344;
        let mut stun = vec![0; UDP_TUNNEL_HEADER_SIZE];
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        socket.incoming.lock().unwrap().extend([
            (stun, stun_remote_addr),
            (
                new_data_packet(conn_id, b"payload")
                    .unwrap()
                    .into_bytes()
                    .to_vec(),
                peer_addr,
            ),
        ]);
        socket.incoming_notify.notify_one();
        let sessions = Arc::new(DashMap::new());
        let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
            socket.clone(),
            UdpSessionKey::new(peer_addr, conn_id),
            sessions.clone(),
        );
        let pending_connects = Arc::new(DashMap::new());
        let direct_sessions = Arc::new(DashMap::new());
        let (accepted_tx, _accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (direct_accepted_tx, _direct_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let direct_accept_enabled = Arc::new(AtomicBool::new(false));
        let (priority_control_tx, _priority_control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let control_handler = Arc::new(BlockingUdpSessionControlHandler::default());
        let (session_shutdown_tx, _) = watch::channel(false);
        let recv_task = tokio::spawn(easy_tier_mux_layer_recv_task(
            socket,
            sessions,
            direct_sessions,
            pending_connects,
            accepted_tx,
            direct_accepted_tx,
            direct_accept_enabled,
            priority_control_tx,
            control_tx,
            control_handler.clone(),
            session_shutdown_tx,
        ));

        tokio::time::timeout(Duration::from_secs(1), control_handler.started.notified())
            .await
            .unwrap();

        let mut buf = [0; 16];
        let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"payload");

        control_handler.release.notify_waiters();
        recv_task.abort();
        let _ = recv_task.await;
    }

    #[tokio::test]
    async fn local_hole_punch_control_uses_priority_queue_over_stun_backlog() {
        let remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let dst_addr = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 1234);
        let (normal_tx, _normal_rx) = mpsc::channel(1);
        let (priority_tx, mut priority_rx) = mpsc::channel(1);
        normal_tx
            .try_send(UdpSessionLayerControl::Stun {
                remote_addr,
                datagram: BytesMut::from(&b"stun"[..]),
            })
            .unwrap();
        let socket = Arc::new(MockVirtualUdpSocket::new(remote_addr, vec![]));
        let control_handler = Arc::new(RecordingUdpSessionControlHandler::default());

        dispatch_v4_hole_punch_control(
            socket,
            control_handler,
            Arc::new(Semaphore::new(UDP_SESSION_QUEUE_CAPACITY)),
            &priority_tx,
            remote_addr,
            new_v4_hole_punch_packet(&dst_addr),
        );

        assert_eq!(
            priority_rx.recv().await.unwrap(),
            UdpSessionLayerControl::V4HolePunch {
                remote_addr,
                dst_addr,
            }
        );
    }

    #[tokio::test]
    async fn sack_from_actual_remote_rekeys_pending_session_before_data_dispatch() {
        let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let sessions = DashMap::new();
        let pending_connects = DashMap::new();
        let expected_key = UdpSessionKey::new(expected_addr, conn_id);
        let actual_key = UdpSessionKey::new(actual_addr, conn_id);
        let session_key = Arc::new(StdMutex::new(None));
        let rings = create_udp_session_rings();
        let entry = udp_session_registry_entry(&rings);
        let mut incoming_rx = rings.session_incoming;
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (sack_tx, mut sack_rx) = watch::channel(None);
        control_tx
            .try_send(UdpConnectControl::HolePunch {
                recv_addr: expected_addr,
            })
            .unwrap();
        pending_connects.insert(
            conn_id,
            PendingUdpSessionConnect {
                expected_addr,
                magic,
                session_key: session_key.clone(),
                entry,
                control: control_tx,
                sack: sack_tx,
            },
        );

        dispatch_data_packet(
            &sessions,
            expected_addr,
            conn_id,
            new_data_packet(conn_id, b"pre-sack").unwrap(),
        );
        dispatch_sack_packet(
            &sessions,
            &pending_connects,
            actual_addr,
            conn_id,
            new_sack_packet(conn_id, magic),
        );
        dispatch_data_packet(
            &sessions,
            actual_addr,
            conn_id,
            new_data_packet(conn_id, b"payload").unwrap(),
        );

        assert!(sessions.contains_key(&actual_key));
        assert!(!sessions.contains_key(&expected_key));
        assert!(pending_connects.is_empty());
        assert_eq!(*session_key.lock().unwrap(), Some(actual_key));
        sack_rx.changed().await.unwrap();
        assert_eq!(*sack_rx.borrow_and_update(), Some(actual_addr));

        let payload = futures::StreamExt::next(&mut incoming_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, BytesMut::from(&b"payload"[..]));
    }

    #[tokio::test]
    async fn replayed_sack_cannot_rekey_pending_session_after_first_success() {
        let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let first_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let replay_addr = SocketAddr::from(([127, 0, 0, 1], 12003));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let sessions = DashMap::new();
        let pending_connects = DashMap::new();
        let expected_key = UdpSessionKey::new(expected_addr, conn_id);
        let first_key = UdpSessionKey::new(first_addr, conn_id);
        let replay_key = UdpSessionKey::new(replay_addr, conn_id);
        let session_key = Arc::new(StdMutex::new(None));
        let rings = create_udp_session_rings();
        let entry = udp_session_registry_entry(&rings);
        let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (sack_tx, mut sack_rx) = watch::channel(None);
        pending_connects.insert(
            conn_id,
            PendingUdpSessionConnect {
                expected_addr,
                magic,
                session_key: session_key.clone(),
                entry,
                control: control_tx,
                sack: sack_tx,
            },
        );

        dispatch_sack_packet(
            &sessions,
            &pending_connects,
            first_addr,
            conn_id,
            new_sack_packet(conn_id, magic),
        );
        dispatch_sack_packet(
            &sessions,
            &pending_connects,
            replay_addr,
            conn_id,
            new_sack_packet(conn_id, magic),
        );

        assert!(sessions.contains_key(&first_key));
        assert!(!sessions.contains_key(&expected_key));
        assert!(!sessions.contains_key(&replay_key));
        assert_eq!(*session_key.lock().unwrap(), Some(first_key));
        sack_rx.changed().await.unwrap();
        assert_eq!(*sack_rx.borrow_and_update(), Some(first_addr));
    }

    #[tokio::test]
    async fn stale_sack_after_pending_removal_does_not_register_session() {
        let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let sessions = DashMap::new();
        let pending_connects = DashMap::new();
        let rings = create_udp_session_rings();
        let entry = udp_session_registry_entry(&rings);
        let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (sack_tx, sack_rx) = watch::channel(None);
        pending_connects.insert(
            conn_id,
            PendingUdpSessionConnect {
                expected_addr,
                magic,
                session_key: Arc::new(StdMutex::new(None)),
                entry,
                control: control_tx,
                sack: sack_tx,
            },
        );
        pending_connects.remove(&conn_id);

        dispatch_sack_packet(
            &sessions,
            &pending_connects,
            actual_addr,
            conn_id,
            new_sack_packet(conn_id, magic),
        );

        assert!(sessions.is_empty());
        assert_eq!(*sack_rx.borrow(), None);
    }

    #[tokio::test]
    async fn sack_after_connect_receiver_drop_removes_registered_session() {
        let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let sessions = DashMap::new();
        let pending_connects = DashMap::new();
        let rings = create_udp_session_rings();
        let entry = udp_session_registry_entry(&rings);
        let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (sack_tx, sack_rx) = watch::channel(None);
        drop(sack_rx);
        pending_connects.insert(
            conn_id,
            PendingUdpSessionConnect {
                expected_addr,
                magic,
                session_key: Arc::new(StdMutex::new(None)),
                entry,
                control: control_tx,
                sack: sack_tx,
            },
        );

        dispatch_sack_packet(
            &sessions,
            &pending_connects,
            actual_addr,
            conn_id,
            new_sack_packet(conn_id, magic),
        );

        assert!(sessions.is_empty());
    }

    struct MockVirtualUdpSocketFactory {
        next_port: AtomicU16,
        bind_options: Mutex<Vec<UdpBindOptions>>,
    }

    impl MockVirtualUdpSocketFactory {
        fn new(next_port: u16) -> Self {
            Self {
                next_port: AtomicU16::new(next_port),
                bind_options: Mutex::new(Vec::new()),
            }
        }

        fn bind_options(&self) -> Vec<UdpBindOptions> {
            self.bind_options.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for MockVirtualUdpSocketFactory {
        type Socket = MockVirtualUdpSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.bind_options.lock().unwrap().push(options);
            let local_addr = options.local_addr.unwrap_or_else(|| {
                SocketAddr::from((
                    [127, 0, 0, 1],
                    self.next_port.fetch_add(1, Ordering::Relaxed),
                ))
            });
            Ok(Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new())))
        }
    }

    #[tokio::test]
    async fn udp_session_dialer_binds_socket_and_returns_direct_session() {
        let factory = Arc::new(MockVirtualUdpSocketFactory::new(13000));
        let mut dialer = UdpSessionDialer::new(factory.clone());
        let remote_addr = SocketAddr::from(([192, 0, 2, 10], 11010));
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 14000));
        let request = UdpSessionConnectRequest::direct(remote_addr)
            .with_bind(UdpBindOptions::port_bound_listener(bind_addr));

        let session = dialer.connect(request).await.unwrap();

        assert_eq!(factory.bind_options(), vec![request.bind]);
        assert_eq!(session.kind(), UdpSessionKind::Direct);
        assert_eq!(session.local_addr().unwrap(), bind_addr);
        assert_eq!(session.peer_addr().unwrap(), remote_addr);
    }

    #[test]
    fn builds_syn_and_sack_packets_without_changing_wire_shape() {
        let conn_id = 0x1234_5678;
        let magic = 0x0102_0304_0506_0708;

        for (packet, msg_type) in [
            (new_syn_packet(conn_id, magic), UdpPacketType::Syn as u8),
            (new_sack_packet(conn_id, magic), UdpPacketType::Sack as u8),
        ] {
            let header = packet.udp_tunnel_header().unwrap();
            assert_eq!(header.conn_id.get(), conn_id);
            assert_eq!(header.msg_type, msg_type);
            assert_eq!(header.len.get(), 8);
            assert_eq!(packet.udp_payload(), magic.to_le_bytes());
        }
    }

    #[test]
    fn v6_hole_punch_packet_preserves_preferred_source() {
        let dst_addr = "[2001:db8::1]:10001".parse::<SocketAddrV6>().unwrap();
        let preferred_src = PreferredIpv6Source {
            ip: "2001:db8::2".parse().unwrap(),
            ifindex: 42,
        };

        let packet = new_v6_hole_punch_packet(&dst_addr, Some(preferred_src));
        let (parsed_dst_addr, parsed_preferred_src) =
            extract_v6_hole_punch_packet(packet.udp_payload()).unwrap();

        assert_eq!(parsed_dst_addr, dst_addr);
        assert_eq!(parsed_preferred_src, Some(preferred_src));
    }

    #[test]
    fn parses_udp_session_datagram_and_rejects_bad_payload_len() {
        let packet = new_syn_packet(7, 42).into_bytes();
        let parsed = parse_udp_session_datagram(packet.clone().into(), false).unwrap();
        assert_eq!(parsed.udp_tunnel_header().unwrap().conn_id.get(), 7);

        let mut bad_packet = packet.to_vec();
        bad_packet.pop();

        assert!(matches!(
            parse_udp_session_datagram(BytesMut::from(bad_packet.as_slice()), false),
            Err(UdpSessionPacketError::PayloadLenMismatch { .. })
        ));
    }

    #[test]
    fn stun_classifier_requires_cookie_and_stun_bits() {
        let mut stun = [0; UDP_TUNNEL_HEADER_SIZE];
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);

        assert!(is_stun_packet(&stun));

        stun[0] = 0xC0;
        assert!(!is_stun_packet(&stun));
        assert!(!is_stun_packet(&stun[..UDP_TUNNEL_HEADER_SIZE - 1]));
    }
}
