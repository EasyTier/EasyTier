use std::{
    io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex as StdMutex, atomic::Ordering},
};

use async_trait::async_trait;
use bytes::BytesMut;
use dashmap::DashMap;
use tokio::{
    sync::{Mutex as TokioMutex, Semaphore, mpsc, watch},
    task::JoinHandle,
};

use crate::{connectivity::hole_punch::udp::new_hole_punch_packet, packet::ZCPacket};

use super::{
    UDP_SESSION_CONNECT_TIMEOUT, UDP_SESSION_QUEUE_CAPACITY, UDP_SESSION_RESEND_INTERVAL,
    packet::{
        EasyTierUdpPacketKind, UdpDatagramClassification, UdpSessionPacketKind,
        classify_udp_datagram, extract_dst_addr_from_v4_hole_punch_packet,
        extract_v6_hole_punch_packet, new_sack_packet, new_syn_packet,
    },
    session::{
        ClassifiedUdpSessionAccept, ClassifiedUdpSessionAccepts, ClassifiedUdpSessionKey,
        ClassifiedUdpSessionRegistry, PendingUdpSessionConnect, PendingUdpSessionConnects,
        UdpConnectControl, UdpSession, UdpSessionClose, UdpSessionCodec, UdpSessionConnectError,
        UdpSessionConnectRequest, UdpSessionConnector, UdpSessionDatagram, UdpSessionEnqueuePolicy,
        UdpSessionKey, UdpSessionKind, UdpSessionLayerControl, UdpSessionProtocol,
        UdpSessionRegistry, close_all_classified_udp_sessions, close_all_udp_sessions,
        close_classified_udp_session, close_udp_session, create_udp_session_rings,
        dispatch_payload_to_session, udp_session_registry_entry,
    },
    virtual_socket::{
        NoopUdpSessionStunResponder, PreferredIpv6Source, UdpSessionStunResponder,
        UdpSocketRecvMeta, UdpSocketSendMeta, VirtualUdpSocket, VirtualUdpSocketFactory,
    },
};

pub(super) const UDP_SESSION_HOLE_PUNCH_PACKET_BODY_LEN: u16 = 32;

#[derive(Debug)]
pub struct UdpSessionLayer<S, R = NoopUdpSessionStunResponder> {
    socket: Arc<S>,
    _stun_responder: Arc<R>,
    pub(super) sessions: Arc<UdpSessionRegistry>,
    classified_sessions: Arc<ClassifiedUdpSessionRegistry>,
    pub(super) classified_accepts: Arc<ClassifiedUdpSessionAccepts>,
    pub(super) pending_connects: Arc<PendingUdpSessionConnects>,
    mux_accepted_rx: TokioMutex<mpsc::Receiver<UdpSession>>,
    _control_rx: TokioMutex<mpsc::Receiver<UdpSessionLayerControl>>,
    session_shutdown_tx: watch::Sender<bool>,
    recv_task: JoinHandle<()>,
}

pub(super) fn create_classified_udp_session_accepts() -> Arc<ClassifiedUdpSessionAccepts> {
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
        Self::new_with_stun_responder(socket, Arc::new(NoopUdpSessionStunResponder))
    }
}

impl<S, R> UdpSessionLayer<S, R>
where
    S: VirtualUdpSocket,
    R: UdpSessionStunResponder<S>,
{
    pub fn new_with_stun_responder(socket: Arc<S>, stun_responder: Arc<R>) -> Self {
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
            stun_responder.clone(),
            session_shutdown_tx.clone(),
        ));

        Self {
            socket,
            _stun_responder: stun_responder,
            sessions,
            classified_sessions,
            classified_accepts,
            pending_connects,
            mux_accepted_rx: TokioMutex::new(mux_accepted_rx),
            _control_rx: TokioMutex::new(control_rx),
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

    fn classified_accept(
        &self,
        protocol: UdpSessionProtocol,
    ) -> io::Result<Arc<ClassifiedUdpSessionAccept>> {
        self.classified_accepts
            .get(&protocol)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{protocol:?} udp listener is not registered"),
                )
            })
    }

    pub fn enable_classified_accept(&self, protocol: UdpSessionProtocol) -> io::Result<()> {
        let accept = self.classified_accept(protocol)?;
        accept.accept_enabled.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub async fn accept_classified_session(
        &self,
        protocol: UdpSessionProtocol,
    ) -> io::Result<UdpSession> {
        let accept = self.classified_accept(protocol)?;
        accept.accept_enabled.store(true, Ordering::Relaxed);
        let mut accepted_rx = accept.accepted_rx.lock().await;
        accepted_rx.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{protocol:?} udp listener closed"),
            )
        })
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

        let timeout = crate::foundation::time::sleep(UDP_SESSION_CONNECT_TIMEOUT);
        let resend_sleep = crate::foundation::time::sleep(UDP_SESSION_RESEND_INTERVAL);
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
                        .reset(crate::foundation::time::Instant::now() + UDP_SESSION_RESEND_INTERVAL);
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

impl<S, R> Drop for UdpSessionLayer<S, R> {
    fn drop(&mut self) {
        let _ = self.session_shutdown_tx.send(true);
        self.pending_connects.clear();
        close_all_udp_sessions(&self.sessions);
        close_all_classified_udp_sessions(&self.classified_sessions);
        self.recv_task.abort();
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

pub(super) async fn udp_session_layer_recv_task<S, R>(
    socket: Arc<S>,
    sessions: Arc<UdpSessionRegistry>,
    classified_sessions: Arc<ClassifiedUdpSessionRegistry>,
    classified_accepts: Arc<ClassifiedUdpSessionAccepts>,
    pending_connects: Arc<PendingUdpSessionConnects>,
    mux_accepted: mpsc::Sender<UdpSession>,
    control: mpsc::Sender<UdpSessionLayerControl>,
    stun_responder: Arc<R>,
    session_shutdown_tx: watch::Sender<bool>,
) where
    S: VirtualUdpSocket,
    R: UdpSessionStunResponder<S>,
{
    let mut buf = [0u8; 65535];
    let control_permits = Arc::new(Semaphore::new(UDP_SESSION_QUEUE_CAPACITY));
    loop {
        let (len, remote_addr, recv_meta) = match socket.recv_from_with_meta(&mut buf).await {
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

        let payload = BytesMut::from(&buf[..len]);
        let datagram = UdpSessionDatagram::new(payload.clone(), recv_meta);
        let quic_key = ClassifiedUdpSessionKey::new(UdpSessionProtocol::Quic, remote_addr);
        if classified_sessions.contains_key(&quic_key) {
            dispatch_existing_classified_udp_datagram(&classified_sessions, quic_key, datagram);
            continue;
        }
        match classify_udp_datagram(payload) {
            UdpDatagramClassification::Stun(datagram_payload) => {
                spawn_stun_control_handler(
                    socket.clone(),
                    stun_responder.clone(),
                    control_permits.clone(),
                    datagram_payload.clone(),
                    remote_addr,
                );
                dispatch_control_packet(
                    &control,
                    UdpSessionLayerControl::Stun {
                        remote_addr,
                        datagram: datagram_payload,
                    },
                );
            }
            UdpDatagramClassification::SessionPacket {
                kind,
                datagram: datagram_payload,
            } => {
                dispatch_session_udp_datagram(
                    socket.clone(),
                    &classified_sessions,
                    &classified_accepts,
                    session_shutdown_tx.subscribe(),
                    remote_addr,
                    kind,
                    UdpSessionDatagram::new(datagram_payload, recv_meta),
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
                    control_permits.clone(),
                    remote_addr,
                    kind,
                    conn_id,
                    &packet,
                    recv_meta,
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
                        UdpSessionDatagram::new(packet.into_bytes().into(), recv_meta),
                    );
                }
            }
        }
    }
}

fn dispatch_existing_classified_udp_datagram(
    classified_sessions: &Arc<ClassifiedUdpSessionRegistry>,
    key: ClassifiedUdpSessionKey,
    datagram: UdpSessionDatagram,
) {
    let Some(entry) = classified_sessions
        .get(&key)
        .map(|entry| entry.value().clone())
    else {
        return;
    };

    if !dispatch_payload_to_session(&entry.incoming, datagram, UdpSessionEnqueuePolicy::Reliable) {
        close_classified_udp_session(classified_sessions, key);
        tracing::debug!(?key, "classified udp session data queue closed");
    }
}

fn dispatch_easy_tier_udp_datagram<S>(
    socket: Arc<S>,
    sessions: &Arc<UdpSessionRegistry>,
    pending_connects: &Arc<PendingUdpSessionConnects>,
    mux_accepted: &mpsc::Sender<UdpSession>,
    control: &mpsc::Sender<UdpSessionLayerControl>,
    control_permits: Arc<Semaphore>,
    remote_addr: SocketAddr,
    kind: EasyTierUdpPacketKind,
    conn_id: u32,
    packet: &ZCPacket,
    recv_meta: UdpSocketRecvMeta,
    session_shutdown: watch::Receiver<bool>,
) -> bool
where
    S: VirtualUdpSocket,
{
    match kind {
        EasyTierUdpPacketKind::Data => {
            dispatch_data_packet(sessions, remote_addr, conn_id, packet, recv_meta)
        }
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
        EasyTierUdpPacketKind::V4HolePunch => {
            dispatch_v4_hole_punch_control(socket, control_permits, control, remote_addr, packet)
        }
        EasyTierUdpPacketKind::V6HolePunch => {
            dispatch_v6_hole_punch_control(socket, control_permits, control, remote_addr, packet)
        }
    }
}

pub(super) fn dispatch_data_packet(
    sessions: &UdpSessionRegistry,
    peer_addr: SocketAddr,
    conn_id: u32,
    packet: &ZCPacket,
    recv_meta: UdpSocketRecvMeta,
) -> bool {
    let key = UdpSessionKey::new(peer_addr, conn_id);
    let Some(entry) = sessions.get(&key).map(|entry| entry.value().clone()) else {
        return false;
    };

    let payload = UdpSessionDatagram::new(BytesMut::from(packet.udp_payload()), recv_meta);
    let policy = if packet.is_lossy() {
        UdpSessionEnqueuePolicy::Lossy
    } else {
        UdpSessionEnqueuePolicy::Reliable
    };
    if !dispatch_payload_to_session(&entry.incoming, payload, policy) {
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
    datagram: UdpSessionDatagram,
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
    datagram: UdpSessionDatagram,
) where
    S: VirtualUdpSocket,
{
    let key = ClassifiedUdpSessionKey::new(protocol, remote_addr);
    if let Some(entry) = classified_sessions
        .get(&key)
        .map(|entry| entry.value().clone())
    {
        if !dispatch_payload_to_session(
            &entry.incoming,
            datagram,
            UdpSessionEnqueuePolicy::Reliable,
        ) {
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
            if !dispatch_payload_to_session(
                &entry.incoming,
                datagram,
                UdpSessionEnqueuePolicy::Reliable,
            ) {
                close_classified_udp_session(classified_sessions, key);
                tracing::debug!(?key, "classified udp session data queue closed");
            }
            return;
        }
    }
    if !dispatch_payload_to_session(
        &rings.session_recv_tx,
        datagram,
        UdpSessionEnqueuePolicy::Reliable,
    ) {
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

pub(super) fn handle_new_easy_tier_mux_connect<S>(
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

pub(super) fn dispatch_sack_packet(
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
    stun_responder: Arc<H>,
    permits: Arc<Semaphore>,
    datagram: BytesMut,
    remote_addr: SocketAddr,
) where
    S: VirtualUdpSocket,
    H: UdpSessionStunResponder<S>,
{
    let Ok(permit) = permits.try_acquire_owned() else {
        tracing::debug!(?remote_addr, "udp stun responder queue full");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(err) = stun_responder
            .respond_stun(socket, &datagram, remote_addr)
            .await
        {
            tracing::debug!(?err, ?remote_addr, "udp respond stun packet error");
        }
    });
}

fn spawn_v4_hole_punch_control_handler<S>(
    socket: Arc<S>,
    permits: Arc<Semaphore>,
    remote_addr: SocketAddr,
    dst_addr: SocketAddrV4,
) where
    S: VirtualUdpSocket,
{
    let Ok(permit) = permits.try_acquire_owned() else {
        tracing::debug!(?remote_addr, ?dst_addr, "udp control handler queue full");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        let packet = new_hole_punch_packet(1, UDP_SESSION_HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        if let Err(err) = socket
            .send_to_with_meta(
                &packet,
                SocketAddr::V4(dst_addr),
                UdpSocketSendMeta::default(),
            )
            .await
        {
            tracing::debug!(
                ?err,
                ?remote_addr,
                ?dst_addr,
                "udp send v4 hole punch packet error"
            );
        }
    });
}

fn spawn_v6_hole_punch_control_handler<S>(
    socket: Arc<S>,
    permits: Arc<Semaphore>,
    remote_addr: SocketAddr,
    dst_addr: SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) where
    S: VirtualUdpSocket,
{
    let Ok(permit) = permits.try_acquire_owned() else {
        tracing::debug!(?remote_addr, ?dst_addr, "udp control handler queue full");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        let packet = new_hole_punch_packet(1, UDP_SESSION_HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        if let Some(source) = preferred_src {
            match socket
                .send_to_with_meta(
                    &packet,
                    SocketAddr::V6(dst_addr),
                    UdpSocketSendMeta {
                        src_ip: Some(source.ip.into()),
                        src_ifindex: Some(source.ifindex),
                    },
                )
                .await
            {
                Ok(_) => return,
                Err(error) => tracing::debug!(
                    ?source,
                    ?dst_addr,
                    ?error,
                    "udp preferred v6 source failed, falling back"
                ),
            }
        }
        if let Err(err) = socket
            .send_to_with_meta(
                &packet,
                SocketAddr::V6(dst_addr),
                UdpSocketSendMeta::default(),
            )
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

pub(super) fn dispatch_v4_hole_punch_control<S>(
    socket: Arc<S>,
    permits: Arc<Semaphore>,
    control: &mpsc::Sender<UdpSessionLayerControl>,
    remote_addr: SocketAddr,
    packet: &ZCPacket,
) -> bool
where
    S: VirtualUdpSocket,
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
    spawn_v4_hole_punch_control_handler(socket, permits, remote_addr, dst_addr);
    dispatch_control_packet(
        control,
        UdpSessionLayerControl::V4HolePunch {
            remote_addr,
            dst_addr,
        },
    );
    true
}

fn dispatch_v6_hole_punch_control<S>(
    socket: Arc<S>,
    permits: Arc<Semaphore>,
    control: &mpsc::Sender<UdpSessionLayerControl>,
    remote_addr: SocketAddr,
    packet: &ZCPacket,
) -> bool
where
    S: VirtualUdpSocket,
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
    spawn_v6_hole_punch_control_handler(socket, permits, remote_addr, dst_addr, preferred_src);
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
        let layer = Arc::new(UdpSessionLayer::new_with_stun_responder(
            socket,
            self.factory.clone(),
        ));
        let mut session = layer.open_classified_session(request.protocol, request.remote_addr)?;
        session._cleanup.layer_guard = Some(Box::new(layer));
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<S, R> UdpSessionLayer<S, R>
    where
        S: VirtualUdpSocket,
        R: UdpSessionStunResponder<S>,
    {
        pub(crate) async fn recv_control(&self) -> io::Result<UdpSessionLayerControl> {
            let mut control_rx = self._control_rx.lock().await;
            control_rx
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "udp listener closed"))
        }
    }
}
