use std::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use super::{
    FromUrl, IpVersion, Tunnel, TunnelError, TunnelInfo, TunnelListener, TunnelUrl, ZCPacketSink,
    ZCPacketStream,
    common::wait_for_connect_futures,
    generate_digest_from_str,
    packet_def::{PEER_MANAGER_HEADER_SIZE, ZCPacketType},
    ring::create_ring_tunnel_pair,
};
use crate::tunnel::common::{BindDev, bind};
use crate::{
    common::shrink_dashmap,
    tunnel::{
        build_url_from_socket_addr,
        common::TunnelWrapper,
        packet_def::{WG_TUNNEL_HEADER_SIZE, ZCPacket},
    },
};
use anyhow::Context;
use async_recursion::async_recursion;
use async_trait::async_trait;
use boringtun::{
    noise::{Packet, Tunn, TunnResult, errors::WireGuardError, handshake::parse_handshake_anon},
    x25519::{PublicKey, StaticSecret},
};
use bytes::BytesMut;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, stream::FuturesUnordered};
use rand::RngCore;
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};

const MAX_PACKET: usize = 2048;

#[derive(Debug, Clone)]
enum WgType {
    // used by easytier peer, need remove/add ip header for in/out wg msg
    InternalUse,
    // used by wireguard peer, keep original ip header
    ExternalUse,
}

#[derive(Clone)]
pub struct WgConfig {
    my_secret_key: StaticSecret,
    my_public_key: PublicKey,

    peer_secret_key: StaticSecret,
    peer_public_key: PublicKey,

    wg_type: WgType,
}

impl WgConfig {
    pub fn new_from_network_identity(network_name: &str, network_secret: &str) -> Self {
        let mut my_sec = [0u8; 32];
        generate_digest_from_str(network_name, network_secret, &mut my_sec);

        let my_secret_key = StaticSecret::from(my_sec);
        let my_public_key = PublicKey::from(&my_secret_key);
        let peer_secret_key = StaticSecret::from(my_sec);
        let peer_public_key = my_public_key;

        WgConfig {
            my_secret_key,
            my_public_key,
            peer_secret_key,
            peer_public_key,

            wg_type: WgType::InternalUse,
        }
    }

    pub fn new_for_portal(server_key_seed: &str, client_key_seed: &str) -> Self {
        let server_cfg = Self::new_from_network_identity("server", server_key_seed);
        let client_cfg = Self::new_from_network_identity("client", client_key_seed);
        Self {
            my_secret_key: server_cfg.my_secret_key,
            my_public_key: server_cfg.my_public_key,
            peer_secret_key: client_cfg.my_secret_key,
            peer_public_key: client_cfg.my_public_key,

            wg_type: WgType::ExternalUse,
        }
    }

    pub fn new_for_portal_server(
        server_secret_key: StaticSecret,
        server_public_key: PublicKey,
        peer_public_key: PublicKey,
    ) -> Self {
        Self {
            my_secret_key: server_secret_key,
            my_public_key: server_public_key,
            peer_secret_key: StaticSecret::from([0u8; 32]),
            peer_public_key,
            wg_type: WgType::ExternalUse,
        }
    }

    pub fn my_secret_key(&self) -> &[u8] {
        self.my_secret_key.as_bytes()
    }

    pub fn peer_secret_key(&self) -> &[u8] {
        self.peer_secret_key.as_bytes()
    }

    pub fn my_public_key(&self) -> &[u8] {
        self.my_public_key.as_bytes()
    }

    pub fn peer_public_key(&self) -> &[u8] {
        self.peer_public_key.as_bytes()
    }
}

#[derive(Clone)]
struct WgPeerData {
    udp: Arc<UdpSocket>, // only for send
    endpoint: SocketAddr,
    tunn: Arc<Mutex<Tunn>>,
    wg_type: WgType,
    stopped: Arc<AtomicBool>,
}

impl Debug for WgPeerData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeerData")
            .field("endpoint", &self.endpoint)
            .field("local", &self.udp.local_addr())
            .finish()
    }
}

impl WgPeerData {
    #[tracing::instrument]
    async fn handle_one_packet_from_me(&self, zc_packet: ZCPacket) -> Result<(), anyhow::Error> {
        let mut send_buf = vec![0u8; MAX_PACKET];

        let packet = if matches!(self.wg_type, WgType::InternalUse) {
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
                self.udp
                    .send_to(packet, self.endpoint)
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
        let mut send_buf = vec![0u8; MAX_PACKET];
        let data = recv_buf;
        let decapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.decapsulate(None, data, &mut send_buf)
        };

        tracing::debug!("Decapsulation result: {:?}", decapsulate_result);

        match decapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                match self.udp.send_to(packet, self.endpoint).await {
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
                            match self.udp.send_to(packet, self.endpoint).await {
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
                if matches!(self.wg_type, WgType::InternalUse) {
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
                match self.udp.send_to(packet, self.endpoint).await {
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
    udp: Arc<UdpSocket>, // only for send
    config: WgConfig,
    endpoint: SocketAddr,

    sink: std::sync::Mutex<Option<Pin<Box<dyn ZCPacketSink>>>>,

    data: Option<WgPeerData>,
    tasks: JoinSet<()>,

    access_time: AtomicCell<std::time::Instant>,
    tunn_index: u32,
}

impl WgPeer {
    fn new(udp: Arc<UdpSocket>, config: WgConfig, endpoint: SocketAddr) -> Self {
        Self::new_with_index(udp, config, endpoint, rand::thread_rng().next_u32())
    }

    fn new_with_index(
        udp: Arc<UdpSocket>,
        config: WgConfig,
        endpoint: SocketAddr,
        tunn_index: u32,
    ) -> Self {
        WgPeer {
            tunn: Some(Mutex::new(Tunn::new(
                config.my_secret_key.clone(),
                config.peer_public_key,
                None,
                None,
                tunn_index,
                None,
            ))),

            udp,
            config,
            endpoint,
            sink: std::sync::Mutex::new(None),

            data: None,
            tasks: JoinSet::new(),

            access_time: AtomicCell::new(std::time::Instant::now()),
            tunn_index,
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

    async fn handle_packet_from_peer(&self, packet: &[u8]) {
        self.access_time.store(std::time::Instant::now());
        tracing::trace!("Received {} bytes from peer", packet.len());
        let data = self.data.as_ref().unwrap();
        // TODO: improve this
        let mut sink = self.sink.lock().unwrap().take().unwrap();
        data.handle_one_packet_from_peer(&mut sink, packet).await;
        self.sink.lock().unwrap().replace(sink);
    }

    fn start_and_get_tunnel(&mut self) -> Box<dyn Tunnel> {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();

        let (stream, sink) = stunnel.split();

        let data = WgPeerData {
            udp: self.udp.clone(),
            endpoint: self.endpoint,
            tunn: Arc::new(self.tunn.take().unwrap()),
            wg_type: self.config.wg_type.clone(),
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

    fn udp_socket(&self) -> Arc<UdpSocket> {
        self.udp.clone()
    }
}

type ConnSender = tokio::sync::mpsc::UnboundedSender<Box<dyn Tunnel>>;
type ConnReceiver = tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>;

#[derive(Clone)]
pub struct WgPortalServerConfig {
    pub server_secret_key: StaticSecret,
    pub server_public_key: PublicKey,
    pub clients: Arc<DashMap<PublicKey, String>>, // pubkey -> client name
    pub next_index: Arc<std::sync::atomic::AtomicU32>,
}

#[derive(Clone, Debug)]
pub struct WgClientInfo {
    pub name: String,
    pub pubkey: [u8; 32],
}

pub struct WgTunnelListener {
    addr: url::Url,
    config: Option<WgConfig>,
    server_config: Option<WgPortalServerConfig>,

    udp: Option<Arc<UdpSocket>>,
    conn_recv: ConnReceiver,
    conn_send: Option<ConnSender>,

    wg_peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,
    wg_peer_by_idx: Arc<DashMap<u32, Arc<WgPeer>>>,

    tasks: JoinSet<()>,
}

impl WgTunnelListener {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        let (conn_send, conn_recv) = tokio::sync::mpsc::unbounded_channel();
        WgTunnelListener {
            addr,
            config: Some(config),
            server_config: None,

            udp: None,
            conn_recv,
            conn_send: Some(conn_send),

            wg_peer_map: Arc::new(DashMap::new()),
            wg_peer_by_idx: Arc::new(DashMap::new()),

            tasks: JoinSet::new(),
        }
    }

    pub fn new_for_portal(addr: url::Url, server_config: WgPortalServerConfig) -> Self {
        let (conn_send, conn_recv) = tokio::sync::mpsc::unbounded_channel();
        WgTunnelListener {
            addr,
            config: None,
            server_config: Some(server_config),

            udp: None,
            conn_recv,
            conn_send: Some(conn_send),

            wg_peer_map: Arc::new(DashMap::new()),
            wg_peer_by_idx: Arc::new(DashMap::new()),

            tasks: JoinSet::new(),
        }
    }

    fn get_udp_socket(&self) -> Arc<UdpSocket> {
        self.udp.as_ref().unwrap().clone()
    }

    async fn handle_udp_incoming(
        socket: Arc<UdpSocket>,
        config: Option<WgConfig>,
        server_config: Option<WgPortalServerConfig>,
        conn_sender: ConnSender,
        peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,
        peer_by_idx: Arc<DashMap<u32, Arc<WgPeer>>>,
    ) {
        let mut tasks = JoinSet::new();

        let peer_map_clone: Arc<DashMap<SocketAddr, Arc<WgPeer>>> = peer_map.clone();
        let peer_by_idx_clone = peer_by_idx.clone();
        tasks.spawn(async move {
            loop {
                peer_map_clone.retain(|_, peer| {
                    peer.access_time.load().elapsed().as_secs() < 61 && !peer.stopped()
                });
                shrink_dashmap(&peer_map_clone, None);
                peer_by_idx_clone.retain(|_, peer| {
                    peer.access_time.load().elapsed().as_secs() < 61 && !peer.stopped()
                });
                shrink_dashmap(&peer_by_idx_clone, None);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                tracing::error!("Failed to receive from UDP socket");
                break;
            };

            let data = &buf[..n];
            tracing::trace!(?n, ?addr, "Received bytes from peer");

            if let Some(ref srv_cfg) = server_config {
                // Multi-client portal mode
                match Tunn::parse_incoming_packet(data) {
                    Ok(Packet::HandshakeInit(p)) => {
                        if !peer_map.contains_key(&addr) {
                            if let Ok(hh) = parse_handshake_anon(
                                &srv_cfg.server_secret_key,
                                &srv_cfg.server_public_key,
                                &p,
                            ) {
                                let client_pubkey = PublicKey::from(hh.peer_static_public);
                                if let Some(client_name) = srv_cfg.clients.get(&client_pubkey) {
                                    tracing::info!(
                                        "New wireguard peer: {}, client: {}, pubkey: {:?}",
                                        addr,
                                        client_name.value(),
                                        client_pubkey
                                    );
                                    let idx = srv_cfg
                                        .next_index
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    let client_config = WgConfig::new_for_portal_server(
                                        srv_cfg.server_secret_key.clone(),
                                        srv_cfg.server_public_key.clone(),
                                        client_pubkey,
                                    );
                                    let mut wg = WgPeer::new_with_index(
                                        socket.clone(),
                                        client_config,
                                        addr,
                                        idx,
                                    );
                                    let (stream, sink) = wg.start_and_get_tunnel().split();
                                    let client_info = WgClientInfo {
                                        name: client_name.value().clone(),
                                        pubkey: hh.peer_static_public,
                                    };
                                    let tunnel = Box::new(TunnelWrapper::new_with_associate_data(
                                        stream,
                                        sink,
                                        Some(TunnelInfo {
                                            tunnel_type: "wg".to_owned(),
                                            local_addr: Some(
                                                build_url_from_socket_addr(
                                                    &socket.local_addr().unwrap().to_string(),
                                                    "wg",
                                                )
                                                .into(),
                                            ),
                                            remote_addr: Some(
                                                build_url_from_socket_addr(&addr.to_string(), "wg")
                                                    .into(),
                                            ),
                                            resolved_remote_addr: Some(
                                                build_url_from_socket_addr(&addr.to_string(), "wg")
                                                    .into(),
                                            ),
                                        }),
                                        Some(Box::new(client_info)),
                                    ));
                                    if let Err(e) = conn_sender.send(tunnel) {
                                        tracing::error!(
                                            "Failed to send tunnel to conn_sender: {}",
                                            e
                                        );
                                    }
                                    let wg = Arc::new(wg);
                                    peer_map.insert(addr, wg.clone());
                                    peer_by_idx.insert(idx, wg);
                                } else {
                                    tracing::debug!(
                                        ?client_pubkey,
                                        "Unknown wireguard client pubkey"
                                    );
                                }
                            }
                        }
                        if let Some(peer) = peer_map.get(&addr) {
                            peer.handle_packet_from_peer(data).await;
                        }
                    }
                    Ok(Packet::HandshakeResponse(p)) => {
                        let idx = p.receiver_idx >> 8;
                        if let Some(peer) = peer_by_idx.get(&idx) {
                            peer.handle_packet_from_peer(data).await;
                        } else {
                            tracing::trace!(?idx, "No peer found for receiver_idx");
                        }
                    }
                    Ok(Packet::PacketCookieReply(p)) => {
                        let idx = p.receiver_idx >> 8;
                        if let Some(peer) = peer_by_idx.get(&idx) {
                            peer.handle_packet_from_peer(data).await;
                        } else {
                            tracing::trace!(?idx, "No peer found for receiver_idx");
                        }
                    }
                    Ok(Packet::PacketData(p)) => {
                        let idx = p.receiver_idx >> 8;
                        if let Some(peer) = peer_by_idx.get(&idx) {
                            peer.handle_packet_from_peer(data).await;
                        } else {
                            tracing::trace!(?idx, "No peer found for receiver_idx");
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to parse wireguard packet: {:?}", e);
                    }
                }
            } else if let Some(ref cfg) = config {
                // Single-peer legacy mode
                if !peer_map.contains_key(&addr) {
                    tracing::info!("New peer: {}", addr);
                    let mut wg = WgPeer::new(socket.clone(), cfg.clone(), addr);
                    let (stream, sink) = wg.start_and_get_tunnel().split();
                    let tunnel = Box::new(TunnelWrapper::new(
                        stream,
                        sink,
                        Some(TunnelInfo {
                            tunnel_type: "wg".to_owned(),
                            local_addr: Some(
                                build_url_from_socket_addr(
                                    &socket.local_addr().unwrap().to_string(),
                                    "wg",
                                )
                                .into(),
                            ),
                            remote_addr: Some(
                                build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                            ),
                            resolved_remote_addr: Some(
                                build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                            ),
                        }),
                    ));
                    if let Err(e) = conn_sender.send(tunnel) {
                        tracing::error!("Failed to send tunnel to conn_sender: {}", e);
                    }
                    peer_map.insert(addr, Arc::new(wg));
                }

                let peer = peer_map.get(&addr).unwrap().clone();
                peer.handle_packet_from_peer(data).await;
            }
        }
    }
}

#[async_trait]
impl TunnelListener for WgTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let tunnel_url: TunnelUrl = self.addr.clone().into();
        self.udp = Some(Arc::new(
            bind()
                .addr(addr)
                .only_v6(true)
                .maybe_dev(tunnel_url.bind_dev())
                .call()?,
        ));
        self.addr
            .set_port(Some(self.udp.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

        self.tasks.spawn(Self::handle_udp_incoming(
            self.get_udp_socket(),
            self.config.clone(),
            self.server_config.clone(),
            self.conn_send.take().unwrap(),
            self.wg_peer_map.clone(),
            self.wg_peer_by_idx.clone(),
        ));

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        if let Some(tunnel) = self.conn_recv.recv().await {
            tracing::info!(?tunnel, "Accepted tunnel");
            return Ok(tunnel);
        }
        Err(TunnelError::Shutdown)
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[derive(Clone)]
pub struct WgTunnelConnector {
    addr: url::Url,
    config: WgConfig,
    udp: Option<Arc<UdpSocket>>,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
}

impl Debug for WgTunnelConnector {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgTunnelConnector")
            .field("addr", &self.addr)
            .field("udp", &self.udp)
            .finish()
    }
}

impl WgTunnelConnector {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        WgTunnelConnector {
            addr,
            config,
            udp: None,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
        }
    }

    #[tracing::instrument(skip(config))]
    async fn connect_with_socket(
        addr_url: url::Url,
        config: WgConfig,
        udp: UdpSocket,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::warn!("wg connect: {:?}", addr);
        let local_addr = udp
            .local_addr()
            .with_context(|| "Failed to get local addr")?
            .to_string();

        let mut wg_peer = WgPeer::new(Arc::new(udp), config.clone(), addr);
        let udp = wg_peer.udp_socket();

        // do handshake here so we will return after receive first packet
        let handshake = wg_peer.create_handshake_init().await;
        udp.send_to(&handshake, addr).await?;
        let mut buf = [0u8; MAX_PACKET];
        let (n, recv_addr) = match udp.recv_from(&mut buf).await {
            Ok(ret) => ret,
            Err(e) => {
                tracing::error!("Failed to receive handshake response: {}", e);
                return Err(TunnelError::IOError(e));
            }
        };

        if recv_addr != addr {
            tracing::warn!(?recv_addr, "Received packet from changed address");
        }

        let tunnel = wg_peer.start_and_get_tunnel();
        let data = wg_peer.data.as_ref().unwrap().clone();
        let mut sink = wg_peer.sink.lock().unwrap().take().unwrap();
        wg_peer.tasks.spawn(async move {
            data.handle_one_packet_from_peer(&mut sink, &buf[..n]).await;
            loop {
                let mut buf = vec![0u8; MAX_PACKET];
                let (n, _) = match udp.recv_from(&mut buf).await {
                    Ok(ret) => ret,
                    Err(e) => {
                        tracing::error!("Failed to receive wg packet: {}", e);
                        break;
                    }
                };
                data.handle_one_packet_from_peer(&mut sink, &buf[..n]).await;
            }
        });

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

    async fn connect_with_ipv6(&self, addr: SocketAddr) -> Result<Box<dyn Tunnel>, TunnelError> {
        let socket = bind()
            .addr("[::]:0".parse().unwrap())
            .dev(BindDev::Disabled)
            .only_v6(true)
            .call()?;
        Self::connect_with_socket(self.addr.clone(), self.config.clone(), socket, addr).await
    }
}

#[async_trait]
impl super::TunnelConnector for WgTunnelConnector {
    #[tracing::instrument]
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
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
        for bind_addr in bind_addrs.into_iter() {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind().addr(bind_addr).only_v6(true).call() {
                Ok(socket) => futures.push(Self::connect_with_socket(
                    self.addr.clone(),
                    self.config.clone(),
                    socket,
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

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tunnel::{
        TunnelConnector,
        common::tests::{_tunnel_bench, _tunnel_pingpong},
    };
    use boringtun::*;

    pub fn create_wg_config() -> (WgConfig, WgConfig) {
        let my_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let my_public_key = x25519::PublicKey::from(&my_secret_key);

        let their_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let their_public_key = x25519::PublicKey::from(&their_secret_key);

        let server_cfg = WgConfig {
            my_secret_key: my_secret_key.clone(),
            my_public_key,
            peer_secret_key: their_secret_key.clone(),
            peer_public_key: their_public_key,
            wg_type: WgType::InternalUse,
        };

        let client_cfg = WgConfig {
            my_secret_key: their_secret_key,
            my_public_key: their_public_key,
            peer_secret_key: my_secret_key,
            peer_public_key: my_public_key,
            wg_type: WgType::InternalUse,
        };

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
                let mut connector = WgTunnelConnector::new(
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

    #[tokio::test]
    async fn wg_multi_client_portal() {
        use std::sync::atomic::AtomicU32;

        let server_secret = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = x25519::PublicKey::from(&server_secret);

        let client1_secret = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let client1_public = x25519::PublicKey::from(&client1_secret);

        let client2_secret = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let client2_public = x25519::PublicKey::from(&client2_secret);

        let clients = Arc::new(DashMap::new());
        clients.insert(client1_public, "client1".to_string());
        clients.insert(client2_public, "client2".to_string());

        let server_config = WgPortalServerConfig {
            server_secret_key: server_secret.clone(),
            server_public_key: server_public.clone(),
            clients,
            next_index: Arc::new(AtomicU32::new(1)),
        };

        let mut listener =
            WgTunnelListener::new_for_portal("wg://127.0.0.1:5588".parse().unwrap(), server_config);
        listener.listen().await.unwrap();

        let client1_wg_cfg = WgConfig {
            my_secret_key: client1_secret,
            my_public_key: client1_public,
            peer_secret_key: server_secret.clone(),
            peer_public_key: server_public.clone(),
            wg_type: WgType::ExternalUse,
        };

        let client2_wg_cfg = WgConfig {
            my_secret_key: client2_secret,
            my_public_key: client2_public,
            peer_secret_key: server_secret.clone(),
            peer_public_key: server_public.clone(),
            wg_type: WgType::ExternalUse,
        };

        // Client 1 connects
        let mut connector1 =
            WgTunnelConnector::new("wg://127.0.0.1:5588".parse().unwrap(), client1_wg_cfg);
        let t1 = connector1.connect().await;
        assert!(t1.is_ok(), "client1 should connect");

        // Client 2 connects
        let mut connector2 =
            WgTunnelConnector::new("wg://127.0.0.1:5588".parse().unwrap(), client2_wg_cfg);
        let t2 = connector2.connect().await;
        assert!(t2.is_ok(), "client2 should connect");

        // Verify listener accepted both
        let accepted1 = listener.accept().await;
        assert!(accepted1.is_ok());

        let accepted2 = listener.accept().await;
        assert!(accepted2.is_ok());

        // Verify peer_by_idx has both peers
        assert_eq!(listener.wg_peer_by_idx.len(), 2);

        // Unregistered client should fail to connect (timeout)
        let unreg_secret = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let unreg_public = x25519::PublicKey::from(&unreg_secret);
        let unreg_cfg = WgConfig {
            my_secret_key: unreg_secret,
            my_public_key: unreg_public,
            peer_secret_key: server_secret.clone(),
            peer_public_key: server_public.clone(),
            wg_type: WgType::ExternalUse,
        };
        let mut unreg_connector =
            WgTunnelConnector::new("wg://127.0.0.1:5588".parse().unwrap(), unreg_cfg);
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), unreg_connector.connect())
                .await;
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "unregistered client should fail"
        );
    }
}
