use std::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use quanta::Instant;

use super::{FromUrl, common::wait_for_connect_futures};
use crate::tunnel::common::{BindDev, bind};
use crate::{
    common::{netns::NetNS, shrink_dashmap},
    proto::common::TunnelInfo,
    socket::udp::{
        RuntimeUdpSessionSocketListener, RuntimeUdpSocket, new_runtime_udp_session_listener,
    },
    tunnel::{TunnelUrl, build_url_from_socket_addr},
};
use anyhow::Context;
use async_recursion::async_recursion;
use async_trait::async_trait;
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};
use bytes::BytesMut;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use easytier_core::tunnel::ring::create_ring_tunnel_pair;
use easytier_core::tunnel::{IpVersion, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream};
use easytier_core::{
    connectivity::{protocol::wireguard::WgConfig, transport::ConnectedUdpSession},
    packet::{PEER_MANAGER_HEADER_SIZE, WG_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType},
    socket::{
        SocketContext,
        udp::{
            UdpBindOptions, UdpSession, UdpSessionAcceptKind, UdpSessionListenRequest,
            UdpSessionProtocol, UdpSessionSocket,
        },
    },
    tunnel::wrapper::TunnelWrapper,
};
use futures::{SinkExt, StreamExt, stream::FuturesUnordered};
use rand::RngCore;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc::unbounded_channel},
    task::JoinSet,
};

const MAX_PACKET: usize = 2048;

#[derive(Clone)]
struct WgPeerData {
    session: Arc<dyn UdpSessionSocket>,
    endpoint: SocketAddr,
    tunn: Arc<Mutex<Tunn>>,
    internal_use: bool,
    access_time: Arc<AtomicCell<Instant>>,
    stopped: Arc<AtomicBool>,
}

impl Debug for WgPeerData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeerData")
            .field("endpoint", &self.endpoint)
            .field("local", &self.session.local_addr())
            .finish()
    }
}

impl WgPeerData {
    #[tracing::instrument]
    async fn handle_one_packet_from_me(&self, zc_packet: ZCPacket) -> Result<(), anyhow::Error> {
        let mut send_buf = vec![0u8; MAX_PACKET];

        let packet = if self.internal_use {
            let mut zc_packet = zc_packet.convert_type(ZCPacketType::WG);
            Self::fill_ip_header(&mut zc_packet);
            zc_packet.into_bytes()
        } else {
            zc_packet.convert_type(ZCPacketType::WG).into_bytes()
        };
        tracing::trace!(?packet, "Sending packet to peer");

        let encapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.encapsulate(&packet, &mut send_buf)
        };

        tracing::trace!(
            ?encapsulate_result,
            "Received {} bytes from me",
            packet.len()
        );

        match encapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                self.session
                    .send(packet)
                    .await
                    .context("Failed to send encrypted IP packet to WireGuard endpoint.")?;
                tracing::debug!(
                    "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                    packet.len()
                );
            }
            TunnResult::Err(e) => {
                tracing::error!("Failed to encapsulate IP packet: {:?}", e);
            }
            TunnResult::Done => {
                // Ignored
            }
            other => {
                tracing::error!(
                    "Unexpected WireGuard state during encapsulation: {:?}",
                    other
                );
            }
        };
        Ok(())
    }

    /// WireGuard consumption task. Receives encrypted packets from the WireGuard endpoint,
    /// decapsulates them, and dispatches newly received IP packets.
    #[tracing::instrument(skip(sink))]
    pub async fn handle_one_packet_from_peer<S: ZCPacketSink + Unpin>(
        &self,
        mut sink: S,
        recv_buf: &[u8],
    ) {
        self.access_time.store(Instant::now());
        let mut send_buf = vec![0u8; MAX_PACKET];
        let data = recv_buf;
        let decapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.decapsulate(None, data, &mut send_buf)
        };

        tracing::debug!("Decapsulation result: {:?}", decapsulate_result);

        match decapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                match self.session.send(packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            "Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}",
                            e
                        );
                        return;
                    }
                };
                let mut peer = self.tunn.lock().await;
                loop {
                    let mut send_buf = vec![0u8; MAX_PACKET];
                    match peer.decapsulate(None, &[], &mut send_buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            match self.session.send(packet).await {
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}",
                                        e
                                    );
                                    break;
                                }
                            };
                        }
                        _ => {
                            break;
                        }
                    }
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                tracing::debug!(
                    ?packet,
                    "receive IP packet from peer: {} bytes",
                    packet.len()
                );
                let mut b = BytesMut::new();
                if self.internal_use {
                    b.resize(WG_TUNNEL_HEADER_SIZE, 0);
                    b.extend_from_slice(self.remove_ip_header(packet, packet[0] >> 4 == 4));
                } else {
                    b.extend_from_slice(packet);
                };
                let zc_packet = ZCPacket::new_from_buf(b, ZCPacketType::WG);
                tracing::trace!(?zc_packet, "forward zc_packet to sink");
                let ret = sink.send(zc_packet).await;
                if ret.is_err() {
                    tracing::error!("Failed to send packet to tunnel: {:?}", ret);
                }
            }
            _ => {
                tracing::debug!(
                    "Unexpected WireGuard state during decapsulation: {:?}",
                    decapsulate_result
                );
            }
        }
    }

    #[tracing::instrument]
    #[async_recursion]
    async fn handle_routine_tun_result<'a: 'async_recursion>(&self, result: TunnResult<'a>) -> () {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                tracing::debug!(
                    "Sending routine packet of {} bytes to WireGuard endpoint",
                    packet.len()
                );
                match self.session.send(packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            "Failed to send routine packet to WireGuard endpoint: {:?}",
                            e
                        );
                    }
                };
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                tracing::warn!("Wireguard handshake has expired!");

                let mut buf = vec![0u8; MAX_PACKET];
                let result = self
                    .tunn
                    .lock()
                    .await
                    .format_handshake_initiation(&mut buf[..], false);

                self.handle_routine_tun_result(result).await
            }
            TunnResult::Err(e) => {
                tracing::error!(
                    "Failed to prepare routine packet for WireGuard endpoint: {:?}",
                    e
                );
            }
            TunnResult::Done => {
                // Sleep for a bit
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            other => {
                tracing::warn!("Unexpected WireGuard routine task state: {:?}", other);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
    }

    /// WireGuard Routine task. Handles Handshake, keep-alive, etc.
    pub async fn routine_task(self) {
        loop {
            let mut send_buf = vec![0u8; MAX_PACKET];
            let tun_result = { self.tunn.lock().await.update_timers(&mut send_buf) };
            self.handle_routine_tun_result(tun_result).await;
        }
    }

    fn fill_ip_header(zc_packet: &mut ZCPacket) {
        let len = zc_packet.payload_len() + PEER_MANAGER_HEADER_SIZE;
        let ip_header = &mut zc_packet.mut_wg_tunnel_header().unwrap().ipv4_header;
        ip_header[0] = 0x45;
        ip_header[1] = 0;
        ip_header[2..4].copy_from_slice(&((len + 20) as u16).to_be_bytes());
        ip_header[4..6].copy_from_slice(&0u16.to_be_bytes());
        ip_header[6..8].copy_from_slice(&0u16.to_be_bytes());
        ip_header[8] = 64;
        ip_header[9] = 0;
        ip_header[10..12].copy_from_slice(&0u16.to_be_bytes());
        ip_header[12..16].copy_from_slice(&0u32.to_be_bytes());
        ip_header[16..20].copy_from_slice(&0u32.to_be_bytes());
    }

    fn remove_ip_header<'a>(&self, packet: &'a [u8], is_v4: bool) -> &'a [u8] {
        if is_v4 { &packet[20..] } else { &packet[40..] }
    }
}

struct WgPeer {
    tunn: Option<Mutex<Tunn>>,
    _session_guard: Box<dyn Send + Sync>,
    session: Arc<dyn UdpSessionSocket>,
    config: WgConfig,
    endpoint: SocketAddr,

    sink: std::sync::Mutex<Option<Pin<Box<dyn ZCPacketSink>>>>,

    data: Option<WgPeerData>,
    tasks: JoinSet<()>,

    access_time: Arc<AtomicCell<Instant>>,
}

impl WgPeer {
    fn new(
        session_guard: Box<dyn Send + Sync>,
        session: Arc<dyn UdpSessionSocket>,
        config: WgConfig,
        endpoint: SocketAddr,
    ) -> Self {
        WgPeer {
            tunn: Some(Mutex::new(Tunn::new(
                StaticSecret::from(<[u8; 32]>::try_from(config.my_secret_key()).unwrap()),
                PublicKey::from(<[u8; 32]>::try_from(config.peer_public_key()).unwrap()),
                None,
                None,
                rand::thread_rng().next_u32(),
                None,
            ))),

            _session_guard: session_guard,
            session,
            config,
            endpoint,
            sink: std::sync::Mutex::new(None),

            data: None,
            tasks: JoinSet::new(),

            access_time: Arc::new(AtomicCell::new(Instant::now())),
        }
    }

    async fn handle_packet_from_me<S: ZCPacketStream + Unpin>(mut stream: S, data: WgPeerData) {
        while let Some(Ok(packet)) = stream.next().await {
            let ret = data.handle_one_packet_from_me(packet).await;
            if let Err(e) = ret {
                tracing::error!("Failed to handle packet from me: {}", e);
            }
        }
        data.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn start_and_get_tunnel(&mut self) -> Box<dyn Tunnel> {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();

        let (stream, sink) = stunnel.split();

        let data = WgPeerData {
            session: self.session.clone(),
            endpoint: self.endpoint,
            tunn: Arc::new(self.tunn.take().unwrap()),
            internal_use: self.config.is_internal(),
            access_time: self.access_time.clone(),
            stopped: Arc::new(AtomicBool::new(false)),
        };

        self.data = Some(data.clone());
        self.sink.lock().unwrap().replace(sink);

        self.tasks
            .spawn(Self::handle_packet_from_me(stream, data.clone()));
        self.tasks.spawn(data.routine_task());

        ctunnel
    }

    fn stopped(&self) -> bool {
        self.data
            .as_ref()
            .unwrap()
            .stopped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn create_handshake_init(&self) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = self
            .tunn
            .as_ref()
            .unwrap()
            .lock()
            .await
            .format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn spawn_session_recv_task(&mut self, first_packet: Option<Vec<u8>>) {
        let session = self.session.clone();
        let data = self.data.as_ref().unwrap().clone();
        let mut sink = self.sink.lock().unwrap().take().unwrap();
        self.tasks.spawn(async move {
            if let Some(packet) = first_packet {
                data.handle_one_packet_from_peer(&mut sink, &packet).await;
            }

            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let n = match session.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!("Failed to receive wg packet: {}", e);
                        data.stopped
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                };
                data.handle_one_packet_from_peer(&mut sink, &buf[..n]).await;
            }
        });
    }
}

type ConnSender = tokio::sync::mpsc::UnboundedSender<Box<dyn Tunnel>>;
type ConnReceiver = tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>;

pub struct WgTunnelListener {
    addr: url::Url,
    session_listener: Option<Arc<RuntimeUdpSessionSocketListener>>,
    socket_mark: Option<u32>,
    config: WgConfig,

    conn_recv: ConnReceiver,
    conn_send: Option<ConnSender>,

    wg_peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,

    tasks: JoinSet<()>,
}

impl Debug for WgTunnelListener {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WgTunnelListener")
            .field("addr", &self.addr)
            .field("listening", &self.session_listener.is_some())
            .finish()
    }
}

impl WgTunnelListener {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        let (conn_send, conn_recv) = unbounded_channel();
        WgTunnelListener {
            addr,
            session_listener: None,
            socket_mark: None,
            config,

            conn_recv,
            conn_send: Some(conn_send),

            wg_peer_map: Arc::new(DashMap::new()),

            tasks: JoinSet::new(),
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn accept_udp_sessions(
        session_listener: Arc<RuntimeUdpSessionSocketListener>,
        config: WgConfig,
        conn_sender: ConnSender,
        peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,
    ) {
        let mut tasks = JoinSet::new();

        let peer_map_clone: Arc<DashMap<SocketAddr, Arc<WgPeer>>> = peer_map.clone();
        tasks.spawn(async move {
            loop {
                peer_map_clone.retain(|_, peer| {
                    peer.access_time.load().elapsed().as_secs() < 61 && !peer.stopped()
                });
                shrink_dashmap(&peer_map_clone, None);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        loop {
            let session = match session_listener.accept_session().await {
                Ok(session) => Arc::new(session) as Arc<dyn UdpSessionSocket>,
                Err(e) => {
                    tracing::error!("Failed to accept wg udp session: {}", e);
                    break;
                }
            };
            let addr = match session.peer_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!("Failed to get wg session peer addr: {}", e);
                    continue;
                }
            };
            if peer_map.contains_key(&addr) {
                continue;
            }
            let local_addr = match session.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!("Failed to get wg session local addr: {}", e);
                    continue;
                }
            };

            tracing::info!("New peer: {}", addr);
            let mut wg = WgPeer::new(
                Box::new(session_listener.clone()),
                session,
                config.clone(),
                addr,
            );
            let (stream, sink) = wg.start_and_get_tunnel().split();
            wg.spawn_session_recv_task(None);
            let tunnel = Box::new(TunnelWrapper::new(
                stream,
                sink,
                Some(TunnelInfo {
                    tunnel_type: "wg".to_owned(),
                    local_addr: Some(
                        build_url_from_socket_addr(&local_addr.to_string(), "wg").into(),
                    ),
                    remote_addr: Some(build_url_from_socket_addr(&addr.to_string(), "wg").into()),
                    resolved_remote_addr: Some(
                        build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                    ),
                }),
            ));
            if let Err(e) = conn_sender.send(tunnel) {
                tracing::error!("Failed to send tunnel to conn_sender: {}", e);
                break;
            }
            peer_map.insert(addr, Arc::new(wg));
        }
    }

    async fn listen_tunnel(&mut self) -> Result<(), TunnelError> {
        if self.session_listener.is_some() {
            return Ok(());
        }

        let local_addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let bind = UdpBindOptions::port_bound_listener(local_addr)
            .with_socket_mark(self.socket_mark)
            .with_bind_device(TunnelUrl::from(self.addr.clone()).bind_dev())
            .with_only_v6(true);
        let mut session_listener = new_runtime_udp_session_listener(
            self.addr.clone(),
            UdpSessionListenRequest::new(bind),
            UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
            NetNS::new(None),
        );
        easytier_core::listener::SocketListener::listen(&mut session_listener).await?;
        let session_listener = Arc::new(session_listener);

        self.tasks.spawn(Self::accept_udp_sessions(
            session_listener.clone(),
            self.config.clone(),
            self.conn_send.take().unwrap(),
            self.wg_peer_map.clone(),
        ));
        self.session_listener = Some(session_listener);

        Ok(())
    }

    async fn accept_tunnel(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        if let Some(tunnel) = self.conn_recv.recv().await {
            tracing::info!(?tunnel, "Accepted tunnel");
            return Ok(tunnel);
        }
        Err(TunnelError::Shutdown)
    }
}

#[async_trait]
impl easytier_core::listener::SocketListener for WgTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_tunnel().await?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_tunnel().await?)
    }

    fn local_url(&self) -> url::Url {
        self.session_listener
            .as_ref()
            .map(|listener| easytier_core::listener::SocketListener::local_url(listener.as_ref()))
            .unwrap_or_else(|| self.addr.clone())
    }
}

#[derive(Clone)]
pub struct WgTunnelConnector {
    addr: url::Url,
    config: WgConfig,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
}

impl Debug for WgTunnelConnector {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgTunnelConnector")
            .field("addr", &self.addr)
            .finish()
    }
}

impl WgTunnelConnector {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        WgTunnelConnector {
            addr,
            config,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
        }
    }

    pub fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    pub fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    pub fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    #[tracing::instrument(skip(config))]
    async fn connect_with_socket(
        addr_url: url::Url,
        config: WgConfig,
        udp: UdpSocket,
        context: SocketContext,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::warn!("wg connect: {:?}", addr);
        let runtime_socket = Arc::new(RuntimeUdpSocket::new_with_context(Arc::new(udp), context));
        let layer = runtime_socket.udp_session_layer();
        let session = layer.open_classified_session(UdpSessionProtocol::WireGuard, addr)?;
        upgrade_connected(ConnectedUdpSession::new(session, layer), addr_url, config).await
    }
}

pub(crate) async fn upgrade_connected(
    connected: ConnectedUdpSession,
    addr_url: url::Url,
    config: WgConfig,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let (session, session_guard) = connected.into_parts();
    let session = Arc::new(session) as Arc<dyn UdpSessionSocket>;
    let addr = session.peer_addr()?;
    let local_addr = session
        .local_addr()
        .with_context(|| "Failed to get local addr")?
        .to_string();

    let mut wg_peer = WgPeer::new(session_guard, session.clone(), config.clone(), addr);

    // do handshake here so we will return after receive first packet
    let handshake = wg_peer.create_handshake_init().await;
    session.send(&handshake).await?;
    let mut buf = [0u8; MAX_PACKET];
    let n = match session.recv(&mut buf).await {
        Ok(ret) => ret,
        Err(e) => {
            tracing::error!("Failed to receive handshake response: {}", e);
            return Err(TunnelError::IOError(e));
        }
    };

    let tunnel = wg_peer.start_and_get_tunnel();
    wg_peer.spawn_session_recv_task(Some(buf[..n].to_vec()));

    let (stream, sink) = tunnel.split();
    let ret = Box::new(TunnelWrapper::new_with_associate_data(
        stream,
        sink,
        Some(TunnelInfo {
            tunnel_type: "wg".to_owned(),
            local_addr: Some(super::build_url_from_socket_addr(&local_addr, "wg").into()),
            remote_addr: Some(addr_url.into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&addr.to_string(), "wg").into(),
            ),
        }),
        Some(Box::new(wg_peer)),
    ));

    Ok(ret)
}

pub(crate) fn upgrade_accepted(
    session: UdpSession,
    config: WgConfig,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let session = Arc::new(session) as Arc<dyn UdpSessionSocket>;
    let remote_addr = session.peer_addr()?;
    let local_addr = session.local_addr()?;
    let mut wg_peer = WgPeer::new(Box::new(()), session, config, remote_addr);
    let tunnel = wg_peer.start_and_get_tunnel();
    wg_peer.spawn_session_recv_task(None);

    let (stream, sink) = tunnel.split();
    let remote_url = build_url_from_socket_addr(&remote_addr.to_string(), "wg");
    Ok(Box::new(TunnelWrapper::new_with_associate_data(
        stream,
        sink,
        Some(TunnelInfo {
            tunnel_type: "wg".to_owned(),
            local_addr: Some(build_url_from_socket_addr(&local_addr.to_string(), "wg").into()),
            remote_addr: Some(remote_url.clone().into()),
            resolved_remote_addr: Some(remote_url.into()),
        }),
        Some(Box::new(wg_peer)),
    )))
}

impl WgTunnelConnector {
    async fn connect_with_ipv6(&self, addr: SocketAddr) -> Result<Box<dyn Tunnel>, TunnelError> {
        let socket = bind()
            .addr("[::]:0".parse().unwrap())
            .dev(BindDev::Disabled)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;
        let context = SocketContext::default()
            .with_ip_version(IpVersion::V6)
            .with_socket_mark(self.socket_mark);
        Self::connect_with_socket(
            self.addr.clone(),
            self.config.clone(),
            socket,
            context,
            addr,
        )
        .await
    }

    async fn connect_tunnel(&self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };

        if addr.is_ipv6() {
            return self.connect_with_ipv6(addr).await;
        }

        let bind_addrs = if self.bind_addrs.is_empty() {
            vec!["0.0.0.0:0".parse().unwrap()]
        } else {
            self.bind_addrs.clone()
        };
        let futures = FuturesUnordered::new();
        for bind_addr in bind_addrs {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind()
                .addr(bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => futures.push(Self::connect_with_socket(
                    self.addr.clone(),
                    self.config.clone(),
                    socket,
                    SocketContext::default()
                        .with_ip_version(IpVersion::V4)
                        .with_socket_mark(self.socket_mark),
                    addr,
                )),
                Err(error) => {
                    tracing::error!(?error, ?bind_addr, ?addr, "bind addr fail");
                    continue;
                }
            }
        }

        wait_for_connect_futures(futures).await
    }
}

#[async_trait]
impl easytier_core::connectivity::protocol::raw::TunnelDialer for WgTunnelConnector {
    #[tracing::instrument]
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        Ok(self.connect_tunnel().await?)
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};
    use boringtun::*;
    use easytier_core::{connectivity::protocol::raw::TunnelDialer, listener::SocketListener};

    pub fn create_wg_config() -> (WgConfig, WgConfig) {
        let my_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());

        let their_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());

        let server_cfg =
            WgConfig::new_internal(*my_secret_key.as_bytes(), *their_secret_key.as_bytes());
        let client_cfg =
            WgConfig::new_internal(*their_secret_key.as_bytes(), *my_secret_key.as_bytes());

        (server_cfg, client_cfg)
    }

    #[tokio::test]
    async fn wg_pingpong() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://0.0.0.0:5599".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://127.0.0.1:5599".parse().unwrap(), client_cfg);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn wg_bench() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://0.0.0.0:5598".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://127.0.0.1:5598".parse().unwrap(), client_cfg);
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn wg_bench_with_bind() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://127.0.0.1:5597".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://127.0.0.1:5597".parse().unwrap(), client_cfg);
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn wg_bench_with_bind_fail() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://127.0.0.1:5596".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://127.0.0.1:5596".parse().unwrap(), client_cfg);
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn wg_server_erase_from_map_after_close() {
        let (server_cfg, client_cfg) = create_wg_config();
        let mut listener =
            WgTunnelListener::new("wg://127.0.0.1:5595".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();

        const CONN_COUNT: usize = 10;

        tokio::spawn(async move {
            let mut tunnels = vec![];
            for _ in 0..CONN_COUNT {
                let connector = WgTunnelConnector::new(
                    "wg://127.0.0.1:5595".parse().unwrap(),
                    client_cfg.clone(),
                );
                let ret = connector.connect().await;
                assert!(ret.is_ok());
                let t = ret.unwrap();
                let (_stream, mut sink) = t.split();
                sink.send(ZCPacket::new_with_payload("payload".as_bytes()))
                    .await
                    .unwrap();
                tunnels.push(t);
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        });

        for _ in 0..CONN_COUNT {
            println!("accepting");
            let conn = listener.accept().await;
            let (mut stream, _sink) = conn.unwrap().split();
            let packet = stream.next().await.unwrap().unwrap();
            assert_eq!("payload".as_bytes(), packet.payload());
            println!("accepting drop");
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        assert_eq!(0, listener.wg_peer_map.len());
    }

    #[tokio::test]
    async fn bind_same_port() {
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener2 = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://[::1]:31015".parse().unwrap(), client_cfg);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://[::1]:31016".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://test.easytier.top:31016".parse().unwrap(), client_cfg);
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://127.0.0.1:31016".parse().unwrap(), server_cfg);
        let mut connector =
            WgTunnelConnector::new("wg://test.easytier.top:31016".parse().unwrap(), client_cfg);
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener = WgTunnelListener::new("wg://0.0.0.0:0".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let (server_cfg, _client_cfg) = create_wg_config();
        let mut listener = WgTunnelListener::new("wg://[::]:0".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}
