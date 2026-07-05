use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex as StdMutex, atomic::Ordering},
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpBindOptions {
    pub local_addr: Option<SocketAddr>,
    pub socket_mark: Option<u32>,
    pub bind_device: Option<String>,
    pub reuse_addr: bool,
    pub reuse_port: bool,
    pub only_v6: bool,
    pub purpose: UdpSocketPurpose,
}

impl UdpBindOptions {
    fn for_purpose(purpose: UdpSocketPurpose) -> Self {
        Self {
            local_addr: None,
            socket_mark: None,
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose,
        }
    }

    pub fn hole_punch_control() -> Self {
        Self::for_purpose(UdpSocketPurpose::HolePunchControl)
    }

    pub fn hole_punch_candidate() -> Self {
        Self::for_purpose(UdpSocketPurpose::HolePunchCandidate)
    }

    pub fn direct_connect() -> Self {
        Self::for_purpose(UdpSocketPurpose::DirectConnect)
    }

    pub fn port_bound_listener(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: Some(local_addr),
            ..Self::for_purpose(UdpSocketPurpose::PortBoundListener)
        }
    }

    pub fn with_socket_mark(mut self, socket_mark: Option<u32>) -> Self {
        self.socket_mark = socket_mark;
        self
    }

    pub fn with_bind_device(mut self, bind_device: Option<String>) -> Self {
        self.bind_device = bind_device;
        self
    }

    pub fn with_reuse_addr(mut self, reuse_addr: bool) -> Self {
        self.reuse_addr = reuse_addr;
        self
    }

    pub fn with_reuse_port(mut self, reuse_port: bool) -> Self {
        self.reuse_port = reuse_port;
        self
    }

    pub fn with_only_v6(mut self, only_v6: bool) -> Self {
        self.only_v6 = only_v6;
        self
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

#[derive(Debug)]
enum UdpDatagramClassification {
    Stun(BytesMut),
    EasyTier {
        kind: EasyTierUdpPacketKind,
        conn_id: u32,
        packet: ZCPacket,
        fallback: UdpSessionPacketKind,
    },
    SessionPacket {
        kind: UdpSessionPacketKind,
        datagram: BytesMut,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpSessionPacketKind {
    Classified(UdpSessionProtocol),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EasyTierUdpPacketKind {
    Data,
    Syn,
    Sack,
    HolePunch,
    V4HolePunch,
    V6HolePunch,
}

impl EasyTierUdpPacketKind {
    fn from_msg_type(msg_type: u8) -> Option<Self> {
        match msg_type {
            msg_type if msg_type == UdpPacketType::Data as u8 => Some(Self::Data),
            msg_type if msg_type == UdpPacketType::Syn as u8 => Some(Self::Syn),
            msg_type if msg_type == UdpPacketType::Sack as u8 => Some(Self::Sack),
            msg_type if msg_type == UdpPacketType::HolePunch as u8 => Some(Self::HolePunch),
            msg_type if msg_type == UdpPacketType::V4HolePunch as u8 => Some(Self::V4HolePunch),
            msg_type if msg_type == UdpPacketType::V6HolePunch as u8 => Some(Self::V6HolePunch),
            _ => None,
        }
    }
}

fn classify_session_udp_datagram(data: &[u8]) -> UdpSessionPacketKind {
    if is_wireguard_packet(data) {
        UdpSessionPacketKind::Classified(UdpSessionProtocol::WireGuard)
    } else if is_quic_packet(data) {
        UdpSessionPacketKind::Classified(UdpSessionProtocol::Quic)
    } else {
        UdpSessionPacketKind::Unknown
    }
}

fn is_wireguard_packet(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let msg_type = u32::from_le_bytes(data[..4].try_into().unwrap());
    match msg_type {
        1 => data.len() == 148,
        2 => data.len() == 92,
        3 => data.len() == 64,
        4 => data.len() >= 32,
        _ => false,
    }
}

fn is_quic_packet(data: &[u8]) -> bool {
    data.first().is_some_and(|first| first & 0x40 != 0)
}

fn classify_udp_datagram(datagram: BytesMut) -> UdpDatagramClassification {
    if is_stun_packet(&datagram) {
        return UdpDatagramClassification::Stun(datagram);
    }

    let fallback = classify_session_udp_datagram(&datagram);
    let packet = match parse_udp_session_datagram(datagram.clone(), false) {
        Ok(packet) => packet,
        Err(err) => {
            tracing::debug!(?err, "udp session packet parse error");
            return UdpDatagramClassification::SessionPacket {
                kind: fallback,
                datagram,
            };
        }
    };
    let header = packet.udp_tunnel_header().unwrap();
    let conn_id = header.conn_id.get();
    let Some(kind) = EasyTierUdpPacketKind::from_msg_type(header.msg_type) else {
        return UdpDatagramClassification::SessionPacket {
            kind: fallback,
            datagram: packet.into_bytes().into(),
        };
    };

    UdpDatagramClassification::EasyTier {
        kind,
        conn_id,
        packet,
        fallback,
    }
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
    EasyTierMux,
    WireGuard,
    Quic,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpSessionProtocol {
    WireGuard,
    Quic,
}

impl UdpSessionProtocol {
    fn session_kind(self) -> UdpSessionKind {
        match self {
            Self::WireGuard => UdpSessionKind::WireGuard,
            Self::Quic => UdpSessionKind::Quic,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpSessionConnectRequest {
    pub remote_addr: SocketAddr,
    pub bind: UdpBindOptions,
    pub protocol: UdpSessionProtocol,
}

impl UdpSessionConnectRequest {
    pub fn wireguard(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: UdpBindOptions::direct_connect(),
            protocol: UdpSessionProtocol::WireGuard,
        }
    }

    pub fn with_bind(mut self, bind: UdpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
type ClassifiedUdpSessionRegistry = DashMap<ClassifiedUdpSessionKey, UdpSessionRegistryEntry>;
type ClassifiedUdpSessionAccepts = DashMap<UdpSessionProtocol, Arc<ClassifiedUdpSessionAccept>>;
type PendingUdpSessionConnects = DashMap<u32, PendingUdpSessionConnect>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClassifiedUdpSessionKey {
    protocol: UdpSessionProtocol,
    peer_addr: SocketAddr,
}

impl ClassifiedUdpSessionKey {
    fn new(protocol: UdpSessionProtocol, peer_addr: SocketAddr) -> Self {
        Self {
            protocol,
            peer_addr,
        }
    }
}

#[derive(Debug)]
struct ClassifiedUdpSessionAccept {
    accepted: mpsc::Sender<UdpSession>,
    accepted_rx: TokioMutex<mpsc::Receiver<UdpSession>>,
    accept_enabled: std::sync::atomic::AtomicBool,
}

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
    codec: UdpSessionCodec,
    incoming: TokioMutex<RingSocketReceiver<BytesMut>>,
    outgoing: TokioMutex<RingSocketSender<UdpSessionOutbound>>,
    closed: watch::Receiver<bool>,
    _cleanup: UdpSessionCleanup,
}

struct UdpSessionOutbound {
    payload: BytesMut,
    completion: oneshot::Sender<io::Result<usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpSessionCodec {
    EasyTierData { conn_id: u32 },
    Identity,
}

impl UdpSessionCodec {
    fn validate_payload(&self, payload: &[u8]) -> io::Result<()> {
        if matches!(self, Self::EasyTierData { .. }) {
            udp_session_payload_len(payload)?;
        }
        Ok(())
    }

    fn encode(&self, payload: &[u8]) -> io::Result<BytesMut> {
        match self {
            Self::EasyTierData { conn_id } => {
                Ok(new_data_packet(*conn_id, payload)?.into_bytes().into())
            }
            Self::Identity => Ok(BytesMut::from(payload)),
        }
    }
}

#[derive(Clone)]
enum UdpSessionCloseTarget {
    #[cfg(test)]
    SignalOnly,
    EasyTier {
        key: UdpSessionKey,
        sessions: Arc<UdpSessionRegistry>,
    },
    Classified {
        key: ClassifiedUdpSessionKey,
        sessions: Arc<ClassifiedUdpSessionRegistry>,
    },
}

#[derive(Clone)]
struct UdpSessionClose {
    close: watch::Sender<bool>,
    target: UdpSessionCloseTarget,
}

impl UdpSessionClose {
    #[cfg(test)]
    fn signal_only(close: watch::Sender<bool>) -> Self {
        Self {
            close,
            target: UdpSessionCloseTarget::SignalOnly,
        }
    }

    fn easy_tier(
        key: UdpSessionKey,
        close: watch::Sender<bool>,
        sessions: Arc<UdpSessionRegistry>,
    ) -> Self {
        Self {
            close,
            target: UdpSessionCloseTarget::EasyTier { key, sessions },
        }
    }

    fn classified(
        key: ClassifiedUdpSessionKey,
        close: watch::Sender<bool>,
        sessions: Arc<ClassifiedUdpSessionRegistry>,
    ) -> Self {
        Self {
            close,
            target: UdpSessionCloseTarget::Classified { key, sessions },
        }
    }

    fn close(&self) {
        match &self.target {
            #[cfg(test)]
            UdpSessionCloseTarget::SignalOnly => {}
            UdpSessionCloseTarget::EasyTier { key, sessions } => {
                close_udp_session(sessions, *key);
            }
            UdpSessionCloseTarget::Classified { key, sessions } => {
                close_classified_udp_session(sessions, *key);
            }
        }
        let _ = self.close.send(true);
    }
}

struct UdpSessionCleanup {
    session_close: Option<UdpSessionClose>,
    shutdown: Option<watch::Sender<bool>>,
    tasks: Vec<JoinHandle<()>>,
    layer_guard: Option<Box<dyn Send + Sync>>,
}

impl std::fmt::Debug for UdpSessionCleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSessionCleanup")
            .field("has_session_close", &self.session_close.is_some())
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
        if let Some(close) = &self.session_close {
            close.close();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl UdpSession {
    #[cfg(test)]
    fn identity_standalone<S>(
        socket: Arc<S>,
        peer_addr: SocketAddr,
        kind: UdpSessionKind,
    ) -> io::Result<Self>
    where
        S: VirtualUdpSocket,
    {
        let local_addr = socket.local_addr()?;
        let rings = create_udp_session_rings();
        let (shutdown_tx, _) = watch::channel(false);
        let close = UdpSessionClose::signal_only(rings.close_tx.clone());
        let recv_socket = socket.clone();
        let recv_task = tokio::spawn(forward_identity_socket_to_udp_session(
            recv_socket,
            peer_addr,
            rings.core_incoming.clone(),
            shutdown_tx.subscribe(),
            close.clone(),
        ));
        let mut session = Self::new(
            socket.clone(),
            local_addr,
            peer_addr,
            kind,
            UdpSessionCodec::Identity,
            rings,
            close,
            shutdown_tx.subscribe(),
        );
        session._cleanup.shutdown = Some(shutdown_tx);
        session._cleanup.tasks.push(recv_task);
        Ok(session)
    }

    fn new<S>(
        socket: Arc<S>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        kind: UdpSessionKind,
        codec: UdpSessionCodec,
        rings: UdpSessionRingParts,
        close: UdpSessionClose,
        shutdown: watch::Receiver<bool>,
    ) -> Self
    where
        S: VirtualUdpSocket,
    {
        if *shutdown.borrow() {
            let _ = rings.close_tx.send(true);
        }
        let send_task = tokio::spawn(forward_udp_session_to_socket(
            socket,
            peer_addr,
            codec,
            rings.core_outgoing,
            shutdown,
            close.clone(),
        ));

        Self {
            local_addr,
            peer_addr,
            kind,
            codec,
            incoming: TokioMutex::new(rings.session_incoming),
            outgoing: TokioMutex::new(rings.session_outgoing),
            closed: rings.close_rx,
            _cleanup: UdpSessionCleanup {
                session_close: Some(close),
                shutdown: None,
                tasks: vec![send_task],
                layer_guard: None,
            },
        }
    }
}

#[derive(Debug)]
pub struct UdpSessionLayer<S, H = NoopUdpSessionControlHandler> {
    socket: Arc<S>,
    _control_handler: Arc<H>,
    sessions: Arc<UdpSessionRegistry>,
    classified_sessions: Arc<ClassifiedUdpSessionRegistry>,
    classified_accepts: Arc<ClassifiedUdpSessionAccepts>,
    pending_connects: Arc<PendingUdpSessionConnects>,
    mux_accepted_rx: TokioMutex<mpsc::Receiver<UdpSession>>,
    control_rx: TokioMutex<mpsc::Receiver<UdpSessionLayerControl>>,
    session_shutdown_tx: watch::Sender<bool>,
    recv_task: JoinHandle<()>,
}

fn create_classified_udp_session_accepts() -> Arc<ClassifiedUdpSessionAccepts> {
    let accepts = Arc::new(DashMap::new());
    for protocol in [UdpSessionProtocol::WireGuard, UdpSessionProtocol::Quic] {
        let (accepted, accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        accepts.insert(
            protocol,
            Arc::new(ClassifiedUdpSessionAccept {
                accepted,
                accepted_rx: TokioMutex::new(accepted_rx),
                accept_enabled: std::sync::atomic::AtomicBool::new(false),
            }),
        );
    }
    accepts
}

impl<S> UdpSessionLayer<S>
where
    S: VirtualUdpSocket,
{
    pub fn new(socket: Arc<S>) -> Self {
        Self::new_with_control_handler(socket, Arc::new(NoopUdpSessionControlHandler))
    }
}

impl<S, H> UdpSessionLayer<S, H>
where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    pub fn new_with_control_handler(socket: Arc<S>, control_handler: Arc<H>) -> Self {
        let sessions = Arc::new(DashMap::new());
        let classified_sessions = Arc::new(DashMap::new());
        let classified_accepts = create_classified_udp_session_accepts();
        let pending_connects = Arc::new(DashMap::new());
        let (mux_accepted_tx, mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (session_shutdown_tx, _) = watch::channel(false);
        let recv_task = tokio::spawn(udp_session_layer_recv_task(
            socket.clone(),
            sessions.clone(),
            classified_sessions.clone(),
            classified_accepts.clone(),
            pending_connects.clone(),
            mux_accepted_tx,
            control_tx,
            control_handler.clone(),
            session_shutdown_tx.clone(),
        ));

        Self {
            socket,
            _control_handler: control_handler,
            sessions,
            classified_sessions,
            classified_accepts,
            pending_connects,
            mux_accepted_rx: TokioMutex::new(mux_accepted_rx),
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

    pub fn active_classified_session_count(&self) -> usize {
        self.classified_sessions.len()
    }

    pub fn open_classified_session(
        &self,
        protocol: UdpSessionProtocol,
        remote_addr: SocketAddr,
    ) -> io::Result<UdpSession> {
        let local_addr = self.socket.local_addr()?;
        let key = ClassifiedUdpSessionKey::new(protocol, remote_addr);
        let rings = create_udp_session_rings();
        match self.classified_sessions.entry(key) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(udp_session_registry_entry(&rings));
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{protocol:?} udp session already exists for {remote_addr}"),
                ));
            }
        }

        let close = UdpSessionClose::classified(
            key,
            rings.close_tx.clone(),
            self.classified_sessions.clone(),
        );
        Ok(UdpSession::new(
            self.socket.clone(),
            local_addr,
            remote_addr,
            protocol.session_kind(),
            UdpSessionCodec::Identity,
            rings,
            close,
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

                let close =
                    UdpSessionClose::easy_tier(key, rings.close_tx.clone(), self.sessions.clone());
                Ok(UdpSession::new(
                    self.socket.clone(),
                    local_addr,
                    key.peer_addr,
                    UdpSessionKind::EasyTierMux,
                    UdpSessionCodec::EasyTierData { conn_id },
                    rings,
                    close,
                    self.session_shutdown_tx.subscribe(),
                ))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn accept(&self) -> io::Result<UdpSession> {
        let mut mux_accepted_rx = self.mux_accepted_rx.lock().await;
        mux_accepted_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "udp listener closed"))
    }

    pub async fn accept_classified_session(
        &self,
        protocol: UdpSessionProtocol,
    ) -> io::Result<UdpSession> {
        let accept = self
            .classified_accepts
            .get(&protocol)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{protocol:?} udp listener is not registered"),
                )
            })?;
        accept.accept_enabled.store(true, Ordering::Relaxed);
        let mut accepted_rx = accept.accepted_rx.lock().await;
        accepted_rx.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{protocol:?} udp listener closed"),
            )
        })
    }

    pub async fn recv_control(&self) -> io::Result<UdpSessionLayerControl> {
        let mut control_rx = self.control_rx.lock().await;
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

impl<S, H> Drop for UdpSessionLayer<S, H> {
    fn drop(&mut self) {
        let _ = self.session_shutdown_tx.send(true);
        self.pending_connects.clear();
        close_all_udp_sessions(&self.sessions);
        close_all_classified_udp_sessions(&self.classified_sessions);
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
        self.codec.validate_payload(data)?;
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

fn close_classified_udp_session(
    classified_sessions: &ClassifiedUdpSessionRegistry,
    key: ClassifiedUdpSessionKey,
) {
    if let Some((_, entry)) = classified_sessions.remove(&key) {
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

fn close_all_classified_udp_sessions(classified_sessions: &ClassifiedUdpSessionRegistry) {
    let close_senders = classified_sessions
        .iter()
        .map(|entry| entry.value().close.clone())
        .collect::<Vec<_>>();
    for close in close_senders {
        let _ = close.send(true);
    }
    classified_sessions.clear();
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

async fn forward_udp_session_to_socket<S>(
    socket: Arc<S>,
    peer_addr: SocketAddr,
    codec: UdpSessionCodec,
    mut outgoing: RingSocketReceiver<UdpSessionOutbound>,
    mut shutdown: watch::Receiver<bool>,
    close: UdpSessionClose,
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
                        tracing::debug!(?err, ?peer_addr, "udp session outgoing ring closed");
                        close.close();
                        break;
                    }
                };
                let payload_len = outbound.payload.len();
                let datagram = match codec.encode(&outbound.payload) {
                    Ok(datagram) => datagram,
                    Err(err) => {
                        tracing::debug!(?err, ?peer_addr, ?codec, "udp session datagram encode error");
                        let _ = outbound.completion.send(Err(err));
                        close.close();
                        break;
                    }
                };
                match socket.send_to(&datagram, peer_addr).await {
                    Ok(_) => {
                        let _ = outbound.completion.send(Ok(payload_len));
                    }
                    Err(err) => {
                        tracing::debug!(?err, ?peer_addr, "udp session send error");
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
async fn forward_identity_socket_to_udp_session<S>(
    socket: Arc<S>,
    peer_addr: SocketAddr,
    incoming: Arc<StdMutex<RingSocketSender<BytesMut>>>,
    mut shutdown: watch::Receiver<bool>,
    close: UdpSessionClose,
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
                        tracing::debug!(?err, ?peer_addr, "identity udp session recv error");
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

async fn udp_session_layer_recv_task<S, H>(
    socket: Arc<S>,
    sessions: Arc<UdpSessionRegistry>,
    classified_sessions: Arc<ClassifiedUdpSessionRegistry>,
    classified_accepts: Arc<ClassifiedUdpSessionAccepts>,
    pending_connects: Arc<PendingUdpSessionConnects>,
    mux_accepted: mpsc::Sender<UdpSession>,
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
                close_all_classified_udp_sessions(&classified_sessions);
                break;
            }
        };

        let datagram = BytesMut::from(&buf[..len]);
        match classify_udp_datagram(datagram) {
            UdpDatagramClassification::Stun(datagram) => {
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
            }
            UdpDatagramClassification::SessionPacket { kind, datagram } => {
                dispatch_session_udp_datagram(
                    socket.clone(),
                    &classified_sessions,
                    &classified_accepts,
                    session_shutdown_tx.subscribe(),
                    remote_addr,
                    kind,
                    datagram,
                );
            }
            UdpDatagramClassification::EasyTier {
                kind,
                conn_id,
                packet,
                fallback,
            } => {
                let consumed = dispatch_easy_tier_udp_datagram(
                    socket.clone(),
                    &sessions,
                    &pending_connects,
                    &mux_accepted,
                    &control,
                    control_handler.clone(),
                    control_handler_permits.clone(),
                    remote_addr,
                    kind,
                    conn_id,
                    &packet,
                    session_shutdown_tx.subscribe(),
                );
                if !consumed {
                    dispatch_session_udp_datagram(
                        socket.clone(),
                        &classified_sessions,
                        &classified_accepts,
                        session_shutdown_tx.subscribe(),
                        remote_addr,
                        fallback,
                        packet.into_bytes().into(),
                    );
                }
            }
        }
    }
}

fn dispatch_easy_tier_udp_datagram<S, H>(
    socket: Arc<S>,
    sessions: &Arc<UdpSessionRegistry>,
    pending_connects: &Arc<PendingUdpSessionConnects>,
    mux_accepted: &mpsc::Sender<UdpSession>,
    control: &mpsc::Sender<UdpSessionLayerControl>,
    control_handler: Arc<H>,
    control_handler_permits: Arc<Semaphore>,
    remote_addr: SocketAddr,
    kind: EasyTierUdpPacketKind,
    conn_id: u32,
    packet: &ZCPacket,
    session_shutdown: watch::Receiver<bool>,
) -> bool
where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    match kind {
        EasyTierUdpPacketKind::Data => dispatch_data_packet(sessions, remote_addr, conn_id, packet),
        EasyTierUdpPacketKind::Syn => handle_new_easy_tier_mux_connect(
            socket,
            sessions.clone(),
            mux_accepted.clone(),
            remote_addr,
            conn_id,
            packet,
            session_shutdown,
        ),
        EasyTierUdpPacketKind::Sack => {
            dispatch_sack_packet(sessions, pending_connects, remote_addr, conn_id, packet)
        }
        EasyTierUdpPacketKind::HolePunch => {
            dispatch_hole_punch_packet(pending_connects, remote_addr)
        }
        EasyTierUdpPacketKind::V4HolePunch => dispatch_v4_hole_punch_control(
            socket,
            control_handler,
            control_handler_permits,
            control,
            remote_addr,
            packet,
        ),
        EasyTierUdpPacketKind::V6HolePunch => dispatch_v6_hole_punch_control(
            socket,
            control_handler,
            control_handler_permits,
            control,
            remote_addr,
            packet,
        ),
    }
}

fn dispatch_data_packet(
    sessions: &UdpSessionRegistry,
    peer_addr: SocketAddr,
    conn_id: u32,
    packet: &ZCPacket,
) -> bool {
    let key = UdpSessionKey::new(peer_addr, conn_id);
    let Some(entry) = sessions.get(&key).map(|entry| entry.value().clone()) else {
        return false;
    };

    let payload = BytesMut::from(packet.udp_payload());
    if !dispatch_payload_to_session(&entry.incoming, payload) {
        close_udp_session(sessions, key);
        tracing::debug!(?key, "udp session data queue closed");
    }
    true
}

fn dispatch_session_udp_datagram<S>(
    socket: Arc<S>,
    classified_sessions: &Arc<ClassifiedUdpSessionRegistry>,
    classified_accepts: &Arc<ClassifiedUdpSessionAccepts>,
    session_shutdown: watch::Receiver<bool>,
    remote_addr: SocketAddr,
    kind: UdpSessionPacketKind,
    datagram: BytesMut,
) where
    S: VirtualUdpSocket,
{
    match kind {
        UdpSessionPacketKind::Classified(protocol) => dispatch_classified_udp_datagram(
            socket,
            classified_sessions,
            classified_accepts,
            protocol,
            session_shutdown,
            remote_addr,
            datagram,
        ),
        UdpSessionPacketKind::Unknown => {
            tracing::trace!(?remote_addr, "unknown udp packet has no session route");
        }
    }
}

fn dispatch_classified_udp_datagram<S>(
    socket: Arc<S>,
    classified_sessions: &Arc<ClassifiedUdpSessionRegistry>,
    classified_accepts: &Arc<ClassifiedUdpSessionAccepts>,
    protocol: UdpSessionProtocol,
    session_shutdown: watch::Receiver<bool>,
    remote_addr: SocketAddr,
    datagram: BytesMut,
) where
    S: VirtualUdpSocket,
{
    let key = ClassifiedUdpSessionKey::new(protocol, remote_addr);
    if let Some(entry) = classified_sessions
        .get(&key)
        .map(|entry| entry.value().clone())
    {
        if !dispatch_payload_to_session(&entry.incoming, datagram) {
            close_classified_udp_session(classified_sessions, key);
            tracing::debug!(?key, "classified udp session data queue closed");
        }
        return;
    }

    let Some(accept) = classified_accepts
        .get(&protocol)
        .map(|entry| entry.value().clone())
    else {
        tracing::trace!(
            ?protocol,
            ?remote_addr,
            "classified udp accept is not registered"
        );
        return;
    };

    if !accept.accept_enabled.load(Ordering::Relaxed) {
        return;
    }

    let accept_permit = match accept.accepted.clone().try_reserve_owned() {
        Ok(permit) => permit,
        Err(err) => {
            tracing::debug!(?err, ?key, "classified udp accept queue unavailable");
            return;
        }
    };
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::debug!(?err, ?key, "classified udp get local addr error");
            return;
        }
    };
    let rings = create_udp_session_rings();
    match classified_sessions.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(udp_session_registry_entry(&rings));
        }
        dashmap::mapref::entry::Entry::Occupied(entry) => {
            let entry = entry.get().clone();
            if !dispatch_payload_to_session(&entry.incoming, datagram) {
                close_classified_udp_session(classified_sessions, key);
                tracing::debug!(?key, "classified udp session data queue closed");
            }
            return;
        }
    }
    if !dispatch_payload_to_session(&rings.core_incoming, datagram) {
        close_classified_udp_session(classified_sessions, key);
        tracing::debug!(?key, "classified udp session data queue closed");
        return;
    }
    let close =
        UdpSessionClose::classified(key, rings.close_tx.clone(), classified_sessions.clone());
    let session = UdpSession::new(
        socket,
        local_addr,
        remote_addr,
        protocol.session_kind(),
        UdpSessionCodec::Identity,
        rings,
        close,
        session_shutdown,
    );
    accept_permit.send(session);
}

fn handle_new_easy_tier_mux_connect<S>(
    socket: Arc<S>,
    sessions: Arc<UdpSessionRegistry>,
    mux_accepted: mpsc::Sender<UdpSession>,
    remote_addr: SocketAddr,
    conn_id: u32,
    packet: &ZCPacket,
    session_shutdown: watch::Receiver<bool>,
) -> bool
where
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
        return false;
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
        return true;
    }

    let accept_permit = match mux_accepted.clone().try_reserve_owned() {
        Ok(permit) => permit,
        Err(err) => {
            tracing::debug!(?err, ?key, "udp accept queue unavailable");
            return true;
        }
    };
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::debug!(?err, ?key, "udp get local addr for accepted session error");
            return true;
        }
    };
    let rings = create_udp_session_rings();
    sessions.insert(key, udp_session_registry_entry(&rings));
    let close = UdpSessionClose::easy_tier(key, rings.close_tx.clone(), sessions.clone());
    let session = UdpSession::new(
        socket.clone(),
        local_addr,
        key.peer_addr,
        UdpSessionKind::EasyTierMux,
        UdpSessionCodec::EasyTierData { conn_id },
        rings,
        close,
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
    true
}

fn dispatch_sack_packet(
    sessions: &UdpSessionRegistry,
    pending_connects: &PendingUdpSessionConnects,
    recv_addr: SocketAddr,
    conn_id: u32,
    packet: &ZCPacket,
) -> bool {
    let payload = packet.udp_payload();
    if payload.len() != 8 {
        if let Some(pending) = pending_connects
            .get(&conn_id)
            .map(|entry| entry.value().control.clone())
        {
            let _ = pending.try_send(UdpConnectControl::InvalidPacket(
                "udp sack packet payload len not match".to_owned(),
            ));
            return true;
        }
        return false;
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
            return true;
        }
        return false;
    };

    let new_key = UdpSessionKey::new(recv_addr, conn_id);
    if !move_pending_udp_session_sender(sessions, &pending, new_key) {
        let _ = pending.control.try_send(UdpConnectControl::InvalidPacket(
            "udp session already exists".to_owned(),
        ));
        return true;
    }
    if pending.sack.send(Some(recv_addr)).is_err() {
        close_udp_session(sessions, new_key);
    }
    true
}

fn dispatch_hole_punch_packet(
    pending_connects: &PendingUdpSessionConnects,
    recv_addr: SocketAddr,
) -> bool {
    let controls = pending_connects
        .iter()
        .filter(|entry| entry.value().expected_addr == recv_addr)
        .map(|entry| entry.value().control.clone())
        .collect::<Vec<_>>();
    if controls.is_empty() {
        return false;
    }

    for control in controls {
        let _ = control.try_send(UdpConnectControl::HolePunch { recv_addr });
    }
    true
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
    packet: &ZCPacket,
) -> bool
where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    if !remote_addr.ip().is_loopback() {
        tracing::warn!(?remote_addr, "v4 hole punch packet should be from loopback");
        return false;
    }
    if !remote_addr.ip().is_ipv4() {
        tracing::warn!(
            ?remote_addr,
            "v4 hole punch packet should be sent from ipv4"
        );
        return false;
    }
    let Some(dst_addr) = extract_dst_addr_from_v4_hole_punch_packet(packet.udp_payload()) else {
        tracing::debug!(?remote_addr, "invalid v4 hole punch packet");
        return false;
    };
    spawn_v4_hole_punch_control_handler(socket, control_handler, permits, remote_addr, dst_addr);
    dispatch_control_packet(
        control,
        UdpSessionLayerControl::V4HolePunch {
            remote_addr,
            dst_addr,
        },
    );
    true
}

fn dispatch_v6_hole_punch_control<S, H>(
    socket: Arc<S>,
    control_handler: Arc<H>,
    permits: Arc<Semaphore>,
    control: &mpsc::Sender<UdpSessionLayerControl>,
    remote_addr: SocketAddr,
    packet: &ZCPacket,
) -> bool
where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
{
    if !remote_addr.ip().is_loopback() {
        tracing::warn!(?remote_addr, "v6 hole punch packet should be from loopback");
        return false;
    }
    if !remote_addr.ip().is_ipv6() {
        tracing::warn!(
            ?remote_addr,
            "v6 hole punch packet should be sent from ipv6"
        );
        return false;
    }
    let Some((dst_addr, preferred_src)) = extract_v6_hole_punch_packet(packet.udp_payload()) else {
        tracing::debug!(?remote_addr, "invalid v6 hole punch packet");
        return false;
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
    true
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
        let layer = Arc::new(UdpSessionLayer::new(socket));
        let mut session = layer.open_classified_session(request.protocol, request.remote_addr)?;
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
                socket_mark: None,
                bind_device: None,
                reuse_addr: false,
                reuse_port: false,
                only_v6: false,
                purpose: UdpSocketPurpose::HolePunchControl,
            }
        );
        assert_eq!(
            UdpBindOptions::hole_punch_candidate(),
            UdpBindOptions {
                local_addr: None,
                socket_mark: None,
                bind_device: None,
                reuse_addr: false,
                reuse_port: false,
                only_v6: false,
                purpose: UdpSocketPurpose::HolePunchCandidate,
            }
        );
        assert_eq!(
            UdpBindOptions::direct_connect(),
            UdpBindOptions {
                local_addr: None,
                socket_mark: None,
                bind_device: None,
                reuse_addr: false,
                reuse_port: false,
                only_v6: false,
                purpose: UdpSocketPurpose::DirectConnect,
            }
        );
        assert_eq!(
            UdpBindOptions::port_bound_listener(listener_addr),
            UdpBindOptions {
                local_addr: Some(listener_addr),
                socket_mark: None,
                bind_device: None,
                reuse_addr: false,
                reuse_port: false,
                only_v6: false,
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

        let request = UdpSessionConnectRequest::wireguard(remote_addr)
            .with_bind(UdpBindOptions::port_bound_listener(bind_addr));

        assert_eq!(request.remote_addr, remote_addr);
        assert_eq!(request.protocol, UdpSessionProtocol::WireGuard);
        assert_eq!(
            request.bind,
            UdpBindOptions {
                local_addr: Some(bind_addr),
                socket_mark: None,
                bind_device: None,
                reuse_addr: false,
                reuse_port: false,
                only_v6: false,
                purpose: UdpSocketPurpose::PortBoundListener,
            }
        );
    }

    #[test]
    fn session_listen_request_keeps_bind_options() {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let bind = UdpBindOptions::port_bound_listener(bind_addr);

        assert_eq!(UdpSessionListenRequest::new(bind.clone()).bind, bind);
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
            kind: UdpSessionKind::WireGuard,
            local_addr,
            peer_addr,
            incoming: Mutex::new(b"pong".to_vec()),
            sent: Mutex::new(Vec::new()),
        };

        assert_eq!(socket.kind(), UdpSessionKind::WireGuard);
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
        let close = UdpSessionClose::easy_tier(key, rings.close_tx.clone(), sessions);
        UdpSession::new(
            socket,
            local_addr,
            key.peer_addr,
            UdpSessionKind::EasyTierMux,
            UdpSessionCodec::EasyTierData {
                conn_id: key.conn_id,
            },
            rings,
            close,
            shutdown,
        )
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

    fn wireguard_transport_packet(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 32.max(4 + payload.len())];
        packet[..4].copy_from_slice(&4u32.to_le_bytes());
        packet[4..4 + payload.len()].copy_from_slice(payload);
        packet
    }

    fn wireguard_packet_with_easy_tier_data_header(payload: &[u8]) -> Vec<u8> {
        let payload_len = 24.max(payload.len());
        let mut packet = vec![0; UDP_TUNNEL_HEADER_SIZE + payload_len];
        packet[..4].copy_from_slice(&4u32.to_le_bytes());
        packet[4] = UdpPacketType::Data as u8;
        packet[6..8].copy_from_slice(&(payload_len as u16).to_le_bytes());
        packet[UDP_TUNNEL_HEADER_SIZE..UDP_TUNNEL_HEADER_SIZE + payload.len()]
            .copy_from_slice(payload);
        packet
    }

    #[tokio::test]
    async fn wireguard_udp_session_sends_to_peer_addr() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let session =
            UdpSession::identity_standalone(socket.clone(), peer_addr, UdpSessionKind::WireGuard)
                .unwrap();

        assert_eq!(session.kind(), UdpSessionKind::WireGuard);
        assert_eq!(session.local_addr().unwrap(), local_addr);
        assert_eq!(session.peer_addr().unwrap(), peer_addr);
        assert_eq!(session.send(b"hello").await.unwrap(), 5);

        let sent = wait_for_sent(|| socket.sent(), 1).await;
        assert_eq!(sent, vec![(b"hello".to_vec(), peer_addr)]);
    }

    #[tokio::test]
    async fn wireguard_udp_session_receives_only_from_peer_addr() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let unexpected_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        socket.incoming.lock().unwrap().extend([
            (b"noise".to_vec(), unexpected_addr),
            (b"payload".to_vec(), peer_addr),
        ]);
        socket.incoming_notify.notify_one();
        let session =
            UdpSession::identity_standalone(socket, peer_addr, UdpSessionKind::WireGuard).unwrap();

        let mut buf = [0; 16];
        let len = session.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], b"payload");
    }

    #[tokio::test]
    async fn wireguard_udp_session_send_failure_closes_recv() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(FailingSendVirtualUdpSocket { local_addr });
        let session =
            UdpSession::identity_standalone(socket, peer_addr, UdpSessionKind::WireGuard).unwrap();

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
    async fn udp_layer_routes_wireguard_packets_to_registered_wireguard_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = UdpSessionLayer::new(socket.clone());
        let session = layer
            .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
            .unwrap();

        assert_eq!(session.kind(), UdpSessionKind::WireGuard);
        assert_eq!(session.send(b"outbound").await.unwrap(), 8);
        let sent = wait_for_sent(|| socket.sent(), 1).await;
        assert_eq!(sent, vec![(b"outbound".to_vec(), peer_addr)]);

        let inbound = wireguard_transport_packet(b"inbound");
        socket
            .incoming
            .lock()
            .unwrap()
            .push_back((inbound.clone(), peer_addr));
        socket.incoming_notify.notify_one();

        let mut buf = [0; 64];
        let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&buf[..len], inbound.as_slice());
    }

    #[tokio::test]
    async fn udp_layer_routes_unclaimed_easy_tier_shaped_wireguard_packet_to_wireguard_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = UdpSessionLayer::new(socket.clone());
        let session = layer
            .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
            .unwrap();
        let packet = wireguard_packet_with_easy_tier_data_header(b"wireguard-collision");

        socket
            .incoming
            .lock()
            .unwrap()
            .push_back((packet.clone(), peer_addr));
        socket.incoming_notify.notify_one();

        let mut buf = [0; 64];
        let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&buf[..len], packet.as_slice());
        assert_eq!(layer.active_session_count(), 0);
    }

    #[tokio::test]
    async fn udp_layer_routes_claimed_easy_tier_data_to_mux_before_wireguard_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = UdpSessionLayer::new(socket.clone());
        let wireguard_session = layer
            .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
            .unwrap();
        let key = UdpSessionKey::new(peer_addr, 4);
        let (mux_session, _shutdown_tx) =
            create_test_easy_tier_mux_session(socket.clone(), key, layer.sessions.clone());
        let packet = wireguard_packet_with_easy_tier_data_header(b"mux-payload");
        let mux_payload = packet[UDP_TUNNEL_HEADER_SIZE..].to_vec();

        socket
            .incoming
            .lock()
            .unwrap()
            .push_back((packet, peer_addr));
        socket.incoming_notify.notify_one();

        let mut mux_buf = [0; 32];
        let len = tokio::time::timeout(Duration::from_secs(1), mux_session.recv(&mut mux_buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&mux_buf[..len], mux_payload.as_slice());

        let mut wireguard_buf = [0; 64];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                wireguard_session.recv(&mut wireguard_buf)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn udp_layer_drops_unknown_datagram_instead_of_creating_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = Arc::new(UdpSessionLayer::new(socket.clone()));
        let mut accept_task = tokio::spawn({
            let layer = layer.clone();
            async move {
                layer
                    .accept_classified_session(UdpSessionProtocol::WireGuard)
                    .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !layer
                .classified_accepts
                .get(&UdpSessionProtocol::WireGuard)
                .unwrap()
                .accept_enabled
                .load(Ordering::Relaxed)
            {
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

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut accept_task)
                .await
                .is_err()
        );
        accept_task.abort();
        assert_eq!(layer.active_classified_session_count(), 0);
    }

    #[tokio::test]
    async fn udp_layer_accepts_unclaimed_easy_tier_shaped_wireguard_packet_when_enabled() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = Arc::new(UdpSessionLayer::new(socket.clone()));
        let accept_task = tokio::spawn({
            let layer = layer.clone();
            async move {
                layer
                    .accept_classified_session(UdpSessionProtocol::WireGuard)
                    .await
            }
        });
        let packet = wireguard_packet_with_easy_tier_data_header(b"accepted-wireguard");

        tokio::time::timeout(Duration::from_secs(1), async {
            while !layer
                .classified_accepts
                .get(&UdpSessionProtocol::WireGuard)
                .unwrap()
                .accept_enabled
                .load(Ordering::Relaxed)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        socket
            .incoming
            .lock()
            .unwrap()
            .push_back((packet.clone(), peer_addr));
        socket.incoming_notify.notify_one();

        let accepted = tokio::time::timeout(Duration::from_secs(1), accept_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut buf = [0; 192];
        let len = accepted.recv(&mut buf).await.unwrap();

        assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
        assert_eq!(&buf[..len], packet.as_slice());
        assert_eq!(layer.active_session_count(), 0);
        assert_eq!(layer.active_classified_session_count(), 1);
    }

    #[tokio::test]
    async fn udp_layer_keeps_easy_tier_syn_out_of_wireguard_session() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = UdpSessionLayer::new(socket.clone());
        let session = layer
            .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
            .unwrap();
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
            &new_data_packet(conn_id, b"wrong-peer").unwrap(),
        );
        dispatch_data_packet(
            &sessions,
            peer_addr,
            conn_id + 1,
            &new_data_packet(conn_id + 1, b"wrong-conn").unwrap(),
        );
        dispatch_data_packet(
            &sessions,
            peer_addr,
            conn_id,
            &new_data_packet(conn_id, b"payload").unwrap(),
        );

        let mut buf = [0; 16];
        let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&buf[..len], b"payload");
    }

    #[tokio::test]
    async fn udp_session_layer_connects_with_shared_recv_loop() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = UdpSessionLayer::new(socket.clone());

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
    async fn cancelled_udp_session_connect_cleans_registered_state() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let layer = UdpSessionLayer::new(socket);

        let result =
            tokio::time::timeout(Duration::from_millis(50), layer.connect(peer_addr)).await;

        assert!(result.is_err());
        assert!(layer.pending_connects.is_empty());
        assert!(layer.sessions.is_empty());
    }

    #[tokio::test]
    async fn dropping_udp_session_layer_closes_session_recv() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
        let layer = UdpSessionLayer::new(socket.clone());
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
        let classified_sessions = Arc::new(DashMap::new());
        let classified_accepts = create_classified_udp_session_accepts();
        let (mux_accepted_tx, _mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);

        udp_session_layer_recv_task(
            socket,
            sessions.clone(),
            classified_sessions.clone(),
            classified_accepts,
            pending_connects.clone(),
            mux_accepted_tx,
            control_tx,
            Arc::new(NoopUdpSessionControlHandler),
            session_shutdown_tx,
        )
        .await;

        assert!(sessions.is_empty());
        assert!(classified_sessions.is_empty());
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
    async fn udp_session_layer_accepts_syn_and_sends_sack() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let conn_id = 0x1122_3344;
        let magic = 0x0102_0304_0506_0708;
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let sessions = Arc::new(DashMap::new());
        let (mux_accepted_tx, mut mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        handle_new_easy_tier_mux_connect(
            socket.clone(),
            sessions.clone(),
            mux_accepted_tx,
            peer_addr,
            conn_id,
            &new_syn_packet(conn_id, magic),
            shutdown_rx,
        );

        let accepted = tokio::time::timeout(Duration::from_secs(1), mux_accepted_rx.recv())
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
        let (mux_accepted_tx, _mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (_session_shutdown_tx, session_shutdown_rx) = watch::channel(false);

        handle_new_easy_tier_mux_connect(
            socket,
            sessions.clone(),
            mux_accepted_tx,
            peer_addr,
            conn_id,
            &new_syn_packet(conn_id, magic),
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
        let (mux_accepted_tx, mut mux_accepted_rx) = mpsc::channel(1);
        let (queued_session, _queued_shutdown_tx) = create_test_easy_tier_mux_session(
            socket.clone(),
            UdpSessionKey::new(SocketAddr::from(([127, 0, 0, 1], 12002)), 7),
            full_sessions,
        );
        mux_accepted_tx.try_send(queued_session).unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        handle_new_easy_tier_mux_connect(
            socket.clone(),
            sessions.clone(),
            mux_accepted_tx,
            peer_addr,
            conn_id,
            &new_syn_packet(conn_id, magic),
            shutdown_rx,
        );

        assert!(mux_accepted_rx.try_recv().is_ok());
        assert!(!sessions.contains_key(&UdpSessionKey::new(peer_addr, conn_id)));
        assert!(socket.sent().is_empty());
    }

    #[tokio::test]
    async fn udp_session_layer_routes_stun_and_hole_punch_control_packets() {
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
        let layer = UdpSessionLayer::new_with_control_handler(socket, control_handler.clone());

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
        let classified_sessions = Arc::new(DashMap::new());
        let classified_accepts = create_classified_udp_session_accepts();
        let (mux_accepted_tx, _mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        let control_handler = Arc::new(BlockingUdpSessionControlHandler::default());
        let (session_shutdown_tx, _) = watch::channel(false);
        let recv_task = tokio::spawn(udp_session_layer_recv_task(
            socket,
            sessions,
            classified_sessions,
            classified_accepts,
            pending_connects,
            mux_accepted_tx,
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
    async fn local_hole_punch_control_is_dispatched_to_control_queue() {
        let remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let dst_addr = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 1234);
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let socket = Arc::new(MockVirtualUdpSocket::new(remote_addr, vec![]));
        let control_handler = Arc::new(RecordingUdpSessionControlHandler::default());

        dispatch_v4_hole_punch_control(
            socket,
            control_handler,
            Arc::new(Semaphore::new(UDP_SESSION_QUEUE_CAPACITY)),
            &control_tx,
            remote_addr,
            &new_v4_hole_punch_packet(&dst_addr),
        );

        assert_eq!(
            control_rx.recv().await.unwrap(),
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
            &new_data_packet(conn_id, b"pre-sack").unwrap(),
        );
        dispatch_sack_packet(
            &sessions,
            &pending_connects,
            actual_addr,
            conn_id,
            &new_sack_packet(conn_id, magic),
        );
        dispatch_data_packet(
            &sessions,
            actual_addr,
            conn_id,
            &new_data_packet(conn_id, b"payload").unwrap(),
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
            &new_sack_packet(conn_id, magic),
        );
        dispatch_sack_packet(
            &sessions,
            &pending_connects,
            replay_addr,
            conn_id,
            &new_sack_packet(conn_id, magic),
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
            &new_sack_packet(conn_id, magic),
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
            &new_sack_packet(conn_id, magic),
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
            self.bind_options.lock().unwrap().push(options.clone());
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
    async fn udp_session_dialer_binds_socket_and_returns_wireguard_session() {
        let factory = Arc::new(MockVirtualUdpSocketFactory::new(13000));
        let mut dialer = UdpSessionDialer::new(factory.clone());
        let remote_addr = SocketAddr::from(([192, 0, 2, 10], 11010));
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 14000));
        let request = UdpSessionConnectRequest::wireguard(remote_addr)
            .with_bind(UdpBindOptions::port_bound_listener(bind_addr));
        let expected_bind = request.bind.clone();

        let session = dialer.connect(request).await.unwrap();

        assert_eq!(factory.bind_options(), vec![expected_bind]);
        assert_eq!(session.kind(), UdpSessionKind::WireGuard);
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
