use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex as TokioMutex, mpsc, oneshot, watch},
    task::JoinHandle,
};

use crate::socket::ring::{RingSocket, RingSocketReceiver, RingSocketSendError, RingSocketSender};

use super::{
    UDP_SESSION_QUEUE_CAPACITY,
    packet::{new_data_packet, udp_session_payload_len},
    virtual_socket::{PreferredIpv6Source, UdpBindOptions, UdpSocketRecvMeta, VirtualUdpSocket},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UdpSessionDatagram {
    pub(crate) payload: BytesMut,
    pub(crate) dst_ip: Option<IpAddr>,
}

impl UdpSessionDatagram {
    pub(crate) fn new(payload: BytesMut, meta: UdpSocketRecvMeta) -> Self {
        Self {
            payload,
            dst_ip: meta.dst_ip,
        }
    }
}

impl From<BytesMut> for UdpSessionDatagram {
    fn from(payload: BytesMut) -> Self {
        Self {
            payload,
            dst_ip: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionRecvMeta {
    pub dst_ip: Option<IpAddr>,
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

    async fn recv_with_meta(&self, buf: &mut [u8]) -> std::io::Result<(usize, UdpSessionRecvMeta)> {
        let len = self.recv(buf).await?;
        Ok((len, UdpSessionRecvMeta::default()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UdpSessionProtocol {
    WireGuard,
    Quic,
}

impl UdpSessionProtocol {
    pub(super) fn session_kind(self) -> UdpSessionKind {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub(super) struct UdpSessionKey {
    pub(super) peer_addr: SocketAddr,
    pub(super) conn_id: u32,
}

impl UdpSessionKey {
    pub(super) fn new(peer_addr: SocketAddr, conn_id: u32) -> Self {
        Self { peer_addr, conn_id }
    }
}

pub(super) type UdpSessionRegistry = DashMap<UdpSessionKey, UdpSessionRegistryEntry>;
pub(super) type ClassifiedUdpSessionRegistry =
    DashMap<ClassifiedUdpSessionKey, UdpSessionRegistryEntry>;
pub(super) type ClassifiedUdpSessionAccepts =
    DashMap<UdpSessionProtocol, Arc<ClassifiedUdpSessionAccept>>;
pub(super) type PendingUdpSessionConnects = DashMap<u32, PendingUdpSessionConnect>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ClassifiedUdpSessionKey {
    pub(super) protocol: UdpSessionProtocol,
    pub(super) peer_addr: SocketAddr,
}

impl ClassifiedUdpSessionKey {
    pub(super) fn new(protocol: UdpSessionProtocol, peer_addr: SocketAddr) -> Self {
        Self {
            protocol,
            peer_addr,
        }
    }
}

#[derive(Debug)]
pub(super) struct ClassifiedUdpSessionAccept {
    pub(super) accepted: mpsc::Sender<UdpSession>,
    pub(super) accepted_rx: TokioMutex<mpsc::Receiver<UdpSession>>,
    pub(super) accept_enabled: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Clone)]
pub(super) struct UdpSessionRegistryEntry {
    pub(super) incoming: Arc<StdMutex<RingSocketSender<UdpSessionDatagram>>>,
    pub(super) close: watch::Sender<bool>,
}

#[derive(Debug, Clone)]
pub(super) struct PendingUdpSessionConnect {
    pub(super) expected_addr: SocketAddr,
    pub(super) magic: u64,
    pub(super) session_key: Arc<StdMutex<Option<UdpSessionKey>>>,
    pub(super) entry: UdpSessionRegistryEntry,
    pub(super) control: mpsc::Sender<UdpConnectControl>,
    pub(super) sack: watch::Sender<Option<SocketAddr>>,
}

#[derive(Debug)]
pub(super) enum UdpConnectControl {
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
    incoming: TokioMutex<RingSocketReceiver<UdpSessionDatagram>>,
    outgoing: TokioMutex<RingSocketSender<UdpSessionOutbound>>,
    closed: watch::Receiver<bool>,
    pub(super) _cleanup: UdpSessionCleanup,
}

pub(crate) struct UdpSessionOutbound {
    pub(crate) payload: BytesMut,
    pub(crate) completion: oneshot::Sender<io::Result<usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpSessionCodec {
    EasyTierData { conn_id: u32 },
    Identity,
}

impl UdpSessionCodec {
    pub(crate) fn validate_payload(&self, payload: &[u8]) -> io::Result<()> {
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
pub(super) struct UdpSessionClose {
    close: watch::Sender<bool>,
    target: UdpSessionCloseTarget,
}

impl UdpSessionClose {
    pub(super) fn easy_tier(
        key: UdpSessionKey,
        close: watch::Sender<bool>,
        sessions: Arc<UdpSessionRegistry>,
    ) -> Self {
        Self {
            close,
            target: UdpSessionCloseTarget::EasyTier { key, sessions },
        }
    }

    pub(super) fn classified(
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

pub(crate) struct UdpSessionCleanup {
    session_close: Option<UdpSessionClose>,
    shutdown: Option<watch::Sender<bool>>,
    tasks: Vec<JoinHandle<()>>,
    pub(super) layer_guard: Option<Box<dyn Send + Sync>>,
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
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new<S>(
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
            rings.session_send_rx,
            shutdown,
            close.clone(),
        ));

        Self {
            local_addr,
            peer_addr,
            kind,
            codec,
            incoming: TokioMutex::new(rings.session_recv_rx),
            outgoing: TokioMutex::new(rings.session_send_tx),
            closed: rings.close_rx,
            _cleanup: UdpSessionCleanup {
                session_close: Some(close),
                shutdown: None,
                tasks: vec![send_task],
                layer_guard: None,
            },
        }
    }

    pub(super) fn keep_layer_alive<T>(&mut self, layer_guard: T)
    where
        T: Send + Sync + 'static,
    {
        self._cleanup.layer_guard = Some(Box::new(layer_guard));
    }

    pub(crate) fn into_tunnel_parts(self) -> UdpSessionTunnelParts {
        let Self {
            local_addr,
            peer_addr,
            kind,
            codec,
            incoming,
            outgoing,
            closed,
            _cleanup,
        } = self;
        UdpSessionTunnelParts {
            local_addr,
            peer_addr,
            kind,
            codec,
            session_recv_rx: incoming.into_inner(),
            session_send_tx: outgoing.into_inner(),
            closed,
            cleanup: _cleanup,
        }
    }
}

pub(crate) struct UdpSessionTunnelParts {
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) kind: UdpSessionKind,
    pub(crate) codec: UdpSessionCodec,
    pub(crate) session_recv_rx: RingSocketReceiver<UdpSessionDatagram>,
    pub(crate) session_send_tx: RingSocketSender<UdpSessionOutbound>,
    pub(crate) closed: watch::Receiver<bool>,
    pub(crate) cleanup: UdpSessionCleanup,
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
        self.recv_with_meta(buf).await.map(|(len, _meta)| len)
    }

    async fn recv_with_meta(&self, buf: &mut [u8]) -> std::io::Result<(usize, UdpSessionRecvMeta)> {
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
        let len = payload.payload.len().min(buf.len());
        buf[..len].copy_from_slice(&payload.payload[..len]);
        Ok((
            len,
            UdpSessionRecvMeta {
                dst_ip: payload.dst_ip,
            },
        ))
    }
}

pub(super) struct UdpSessionRingParts {
    pub(super) session_recv_rx: RingSocketReceiver<UdpSessionDatagram>,
    pub(super) session_recv_tx: Arc<StdMutex<RingSocketSender<UdpSessionDatagram>>>,
    pub(super) session_send_tx: RingSocketSender<UdpSessionOutbound>,
    pub(super) session_send_rx: RingSocketReceiver<UdpSessionOutbound>,
    pub(super) close_tx: watch::Sender<bool>,
    pub(super) close_rx: watch::Receiver<bool>,
}

pub(super) fn create_udp_session_rings() -> UdpSessionRingParts {
    let (session_recv_rx_socket, session_recv_tx_socket) =
        RingSocket::pair(UDP_SESSION_QUEUE_CAPACITY);
    let (session_send_rx_socket, session_send_tx_socket) =
        RingSocket::pair(UDP_SESSION_QUEUE_CAPACITY);
    let (session_recv_rx, _unused_session_recv_tx) = session_recv_rx_socket.split();
    let (_unused_session_recv_peer_rx, session_recv_tx) = session_recv_tx_socket.split();
    let (session_send_rx, _unused_session_send_peer_tx) = session_send_rx_socket.split();
    let (_unused_session_send_rx, session_send_tx) = session_send_tx_socket.split();
    let (close_tx, close_rx) = watch::channel(false);
    UdpSessionRingParts {
        session_recv_rx,
        session_recv_tx: Arc::new(StdMutex::new(session_recv_tx)),
        session_send_tx,
        session_send_rx,
        close_tx,
        close_rx,
    }
}

pub(super) fn udp_session_registry_entry(rings: &UdpSessionRingParts) -> UdpSessionRegistryEntry {
    UdpSessionRegistryEntry {
        incoming: rings.session_recv_tx.clone(),
        close: rings.close_tx.clone(),
    }
}

pub(super) fn close_udp_session(sessions: &UdpSessionRegistry, key: UdpSessionKey) {
    if let Some((_, entry)) = sessions.remove(&key) {
        let _ = entry.close.send(true);
    }
}

pub(super) fn close_classified_udp_session(
    classified_sessions: &ClassifiedUdpSessionRegistry,
    key: ClassifiedUdpSessionKey,
) {
    if let Some((_, entry)) = classified_sessions.remove(&key) {
        let _ = entry.close.send(true);
    }
}

pub(super) fn close_all_udp_sessions(sessions: &UdpSessionRegistry) {
    let close_senders = sessions
        .iter()
        .map(|entry| entry.value().close.clone())
        .collect::<Vec<_>>();
    for close in close_senders {
        let _ = close.send(true);
    }
    sessions.clear();
}

pub(super) fn close_all_classified_udp_sessions(
    classified_sessions: &ClassifiedUdpSessionRegistry,
) {
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

#[derive(Debug, Clone, Copy)]
pub(super) enum UdpSessionEnqueuePolicy {
    Lossy,
    Reliable,
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

pub(super) fn dispatch_payload_to_session(
    incoming: &Arc<StdMutex<RingSocketSender<UdpSessionDatagram>>>,
    payload: impl Into<UdpSessionDatagram>,
    policy: UdpSessionEnqueuePolicy,
) -> bool {
    let payload = payload.into();
    let result = {
        let mut incoming = incoming.lock().unwrap();
        match policy {
            UdpSessionEnqueuePolicy::Lossy => incoming.try_send(payload),
            UdpSessionEnqueuePolicy::Reliable => incoming.force_send(payload),
        }
    };
    match result {
        Ok(()) => true,
        Err(RingSocketSendError::Full(_)) => {
            tracing::trace!(?policy, "udp session data queue full");
            true
        }
        Err(RingSocketSendError::Closed(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl UdpSessionClose {
        fn signal_only(close: watch::Sender<bool>) -> Self {
            Self {
                close,
                target: UdpSessionCloseTarget::SignalOnly,
            }
        }
    }

    impl UdpSession {
        pub(crate) fn identity_standalone<S>(
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
                rings.session_recv_tx.clone(),
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
    }

    async fn forward_identity_socket_to_udp_session<S>(
        socket: Arc<S>,
        peer_addr: SocketAddr,
        incoming: Arc<StdMutex<RingSocketSender<UdpSessionDatagram>>>,
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
                    if !dispatch_payload_to_session(
                        &incoming,
                        BytesMut::from(&buf[..len]),
                        UdpSessionEnqueuePolicy::Reliable,
                    ) {
                        close.close();
                        break;
                    }
                }
            }
        }
    }
}
