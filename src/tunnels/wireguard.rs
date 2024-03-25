use std::{
    collections::hash_map::DefaultHasher,
    fmt::{Debug, Formatter},
    hash::Hasher,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use async_recursion::async_recursion;
use async_trait::async_trait;
use boringtun::{
    noise::{errors::WireGuardError, Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};

use crate::{
    rpc::TunnelInfo,
    tunnels::{build_url_from_socket_addr, common::TunnelWithCustomInfo},
};

use super::{
    check_scheme_and_get_socket_addr, common::setup_sokcet2, ring_tunnel::create_ring_tunnel_pair,
    DatagramSink, DatagramStream, Tunnel, TunnelError, TunnelListener,
};

const MAX_PACKET: usize = 4096;

#[derive(Clone)]
pub struct WgConfig {
    my_secret_key: StaticSecret,
    my_public_key: PublicKey,

    peer_public_key: PublicKey,
}

impl WgConfig {
    pub fn new_from_network_identity(network_name: &str, network_secret: &str) -> Self {
        let mut my_sec = [0u8; 32];
        let mut hasher = DefaultHasher::new();
        hasher.write(network_name.as_bytes());
        hasher.write(network_secret.as_bytes());
        my_sec[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&my_sec[0..8]);
        my_sec[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&my_sec[0..16]);
        my_sec[16..24].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&my_sec[0..24]);
        my_sec[24..32].copy_from_slice(&hasher.finish().to_be_bytes());

        let my_secret_key = StaticSecret::from(my_sec);
        let my_public_key = PublicKey::from(&my_secret_key);
        let peer_public_key = my_public_key.clone();

        WgConfig {
            my_secret_key,
            my_public_key,
            peer_public_key,
        }
    }
}

#[derive(Clone)]
struct WgPeerData {
    udp: Arc<UdpSocket>, // only for send
    endpoint: SocketAddr,
    tunn: Arc<Mutex<Tunn>>,
    sink: Arc<Mutex<Pin<Box<dyn DatagramSink>>>>,
    stream: Arc<Mutex<Pin<Box<dyn DatagramStream>>>>,
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
    async fn handle_one_packet_from_me(&self, packet: &[u8]) -> Result<(), anyhow::Error> {
        let mut send_buf = [0u8; MAX_PACKET];
        let encapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.encapsulate(&packet, &mut send_buf)
        };

        tracing::info!(
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
    #[tracing::instrument]
    pub async fn handle_one_packet_from_peer(&self, recv_buf: &[u8]) {
        let mut send_buf = [0u8; MAX_PACKET];
        let data = &recv_buf[..];
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
                        tracing::error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                        return;
                    }
                };
                let mut peer = self.tunn.lock().await;
                loop {
                    let mut send_buf = [0u8; MAX_PACKET];
                    match peer.decapsulate(None, &[], &mut send_buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            match self.udp.send_to(packet, self.endpoint).await {
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
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
                    "WireGuard endpoint sent IP packet of {} bytes",
                    packet.len()
                );
                let ret = self
                    .sink
                    .lock()
                    .await
                    .send(
                        WgPeer::remove_ip_header(packet, packet[0] >> 4 == 4)
                            .to_vec()
                            .into(),
                    )
                    .await;
                if ret.is_err() {
                    tracing::error!("Failed to send packet to tunnel: {:?}", ret);
                }
            }
            _ => {
                tracing::warn!(
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
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            other => {
                tracing::warn!("Unexpected WireGuard routine task state: {:?}", other);
            }
        };
    }

    /// WireGuard Routine task. Handles Handshake, keep-alive, etc.
    pub async fn routine_task(self) {
        loop {
            let mut send_buf = [0u8; MAX_PACKET];
            let tun_result = { self.tunn.lock().await.update_timers(&mut send_buf) };
            self.handle_routine_tun_result(tun_result).await;
        }
    }
}

struct WgPeer {
    udp: Arc<UdpSocket>, // only for send
    config: WgConfig,
    endpoint: SocketAddr,

    data: Option<WgPeerData>,
    tasks: JoinSet<()>,

    access_time: std::time::Instant,
}

impl WgPeer {
    fn new(udp: Arc<UdpSocket>, config: WgConfig, endpoint: SocketAddr) -> Self {
        WgPeer {
            udp,
            config,
            endpoint,

            data: None,
            tasks: JoinSet::new(),

            access_time: std::time::Instant::now(),
        }
    }

    fn add_ip_header(packet: &[u8]) -> Vec<u8> {
        let mut ret = vec![0u8; packet.len() + 20];
        let ip_header = ret.as_mut_slice();
        ip_header[0] = 0x45;
        ip_header[1] = 0;
        ip_header[2..4].copy_from_slice(&((packet.len() + 20) as u16).to_be_bytes());
        ip_header[4..6].copy_from_slice(&0u16.to_be_bytes());
        ip_header[6..8].copy_from_slice(&0u16.to_be_bytes());
        ip_header[8] = 64;
        ip_header[9] = 0;
        ip_header[10..12].copy_from_slice(&0u16.to_be_bytes());
        ip_header[12..16].copy_from_slice(&0u32.to_be_bytes());
        ip_header[16..20].copy_from_slice(&0u32.to_be_bytes());
        ip_header[20..].copy_from_slice(packet);
        ret
    }

    fn remove_ip_header(packet: &[u8], is_v4: bool) -> &[u8] {
        if is_v4 {
            return &packet[20..];
        } else {
            return &packet[40..];
        }
    }

    async fn handle_packet_from_me(data: WgPeerData) {
        while let Some(Ok(packet)) = data.stream.lock().await.next().await {
            let ret = data
                .handle_one_packet_from_me(&Self::add_ip_header(&packet))
                .await;
            if let Err(e) = ret {
                tracing::error!("Failed to handle packet from me: {}", e);
            }
        }
    }

    async fn handle_packet_from_peer(&mut self, packet: &[u8]) {
        self.access_time = std::time::Instant::now();
        tracing::info!("Received {} bytes from peer", packet.len());
        let data = self.data.as_ref().unwrap();
        data.handle_one_packet_from_peer(packet).await;
    }

    fn start_and_get_tunnel(&mut self) -> Box<dyn Tunnel> {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();

        let data = WgPeerData {
            udp: self.udp.clone(),
            endpoint: self.endpoint,
            tunn: Arc::new(Mutex::new(
                Tunn::new(
                    self.config.my_secret_key.clone(),
                    self.config.peer_public_key.clone(),
                    None,
                    None,
                    rand::thread_rng().next_u32(),
                    None,
                )
                .unwrap(),
            )),
            sink: Arc::new(Mutex::new(stunnel.pin_sink())),
            stream: Arc::new(Mutex::new(stunnel.pin_stream())),
        };

        self.data = Some(data.clone());
        self.tasks.spawn(Self::handle_packet_from_me(data.clone()));
        self.tasks.spawn(data.routine_task());

        ctunnel
    }
}

type ConnSender = tokio::sync::mpsc::UnboundedSender<Box<dyn Tunnel>>;
type ConnReceiver = tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>;

pub struct WgTunnelListener {
    addr: url::Url,
    config: WgConfig,

    udp: Option<Arc<UdpSocket>>,
    conn_recv: ConnReceiver,
    conn_send: Option<ConnSender>,

    tasks: JoinSet<()>,
}

impl WgTunnelListener {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        let (conn_send, conn_recv) = tokio::sync::mpsc::unbounded_channel();
        WgTunnelListener {
            addr,
            config,

            udp: None,
            conn_recv,
            conn_send: Some(conn_send),

            tasks: JoinSet::new(),
        }
    }

    fn get_udp_socket(&self) -> Arc<UdpSocket> {
        self.udp.as_ref().unwrap().clone()
    }

    async fn handle_udp_incoming(
        socket: Arc<UdpSocket>,
        config: WgConfig,
        conn_sender: ConnSender,
    ) {
        let mut tasks = JoinSet::new();
        let peer_map: Arc<DashMap<SocketAddr, WgPeer>> = Arc::new(DashMap::new());

        let peer_map_clone = peer_map.clone();
        tasks.spawn(async move {
            loop {
                peer_map_clone.retain(|_, peer| peer.access_time.elapsed().as_secs() < 600);
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                tracing::error!("Failed to receive from UDP socket");
                break;
            };

            let data = &buf[..n];
            tracing::info!("Received {} bytes from {}", n, addr);

            if !peer_map.contains_key(&addr) {
                tracing::info!("New peer: {}", addr);
                let mut wg = WgPeer::new(socket.clone(), config.clone(), addr.clone());
                let tunnel = Box::new(TunnelWithCustomInfo::new(
                    wg.start_and_get_tunnel(),
                    TunnelInfo {
                        tunnel_type: "wg".to_owned(),
                        local_addr: build_url_from_socket_addr(
                            &socket.local_addr().unwrap().to_string(),
                            "wg",
                        )
                        .into(),
                        remote_addr: build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                    },
                ));
                if let Err(e) = conn_sender.send(tunnel) {
                    tracing::error!("Failed to send tunnel to conn_sender: {}", e);
                }
                peer_map.insert(addr, wg);
            }

            let mut peer = peer_map.get_mut(&addr).unwrap();
            peer.handle_packet_from_peer(data).await;
        }
    }
}

#[async_trait]
impl TunnelListener for WgTunnelListener {
    async fn listen(&mut self) -> Result<(), super::TunnelError> {
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "wg")?;
        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        setup_sokcet2(&socket2_socket, &addr)?;
        self.udp = Some(Arc::new(UdpSocket::from_std(socket2_socket.into())?));
        self.tasks.spawn(Self::handle_udp_incoming(
            self.get_udp_socket(),
            self.config.clone(),
            self.conn_send.take().unwrap(),
        ));

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        while let Some(tunnel) = self.conn_recv.recv().await {
            tracing::info!(?tunnel, "Accepted tunnel");
            return Ok(tunnel);
        }
        Err(TunnelError::CommonError(
            "Failed to accept tunnel".to_string(),
        ))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct WgClientTunnel {
    wg_peer: WgPeer,
    tunnel: Box<dyn Tunnel>,
    info: TunnelInfo,
}

impl Tunnel for WgClientTunnel {
    fn stream(&self) -> Box<dyn DatagramStream> {
        self.tunnel.stream()
    }

    fn sink(&self) -> Box<dyn DatagramSink> {
        self.tunnel.sink()
    }

    fn info(&self) -> Option<TunnelInfo> {
        Some(self.info.clone())
    }
}

#[derive(Clone)]
pub struct WgTunnelConnector {
    addr: url::Url,
    config: WgConfig,
    udp: Option<Arc<UdpSocket>>,
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
        }
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(
            matches!(keepalive, TunnResult::WriteToNetwork(_)),
            "Failed to parse handshake response, {:?}",
            keepalive
        );

        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };

        keepalive.into()
    }
}

#[async_trait]
impl super::TunnelConnector for WgTunnelConnector {
    #[tracing::instrument]
    async fn connect(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let addr = super::check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "wg")?;
        tracing::warn!("wg connect: {:?}", self.addr);
        let udp = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = udp.local_addr().unwrap().to_string();

        let mut my_tun = Tunn::new(
            self.config.my_secret_key.clone(),
            self.config.peer_public_key.clone(),
            None,
            None,
            rand::thread_rng().next_u32(),
            None,
        )
        .unwrap();

        let init = Self::create_handshake_init(&mut my_tun);
        udp.send_to(&init, addr).await?;

        let mut buf = [0u8; MAX_PACKET];
        let (n, _) = udp.recv_from(&mut buf).await.unwrap();
        let keepalive = Self::parse_handshake_resp(&mut my_tun, &buf[..n]);
        udp.send_to(&keepalive, addr).await?;

        let mut wg_peer = WgPeer::new(Arc::new(udp), self.config.clone(), addr);
        let tunnel = wg_peer.start_and_get_tunnel();

        let data = wg_peer.data.as_ref().unwrap().clone();
        wg_peer.tasks.spawn(async move {
            loop {
                let mut buf = [0u8; MAX_PACKET];
                let (n, recv_addr) = data.udp.recv_from(&mut buf).await.unwrap();
                if recv_addr != addr {
                    continue;
                }
                data.handle_one_packet_from_peer(&buf[..n]).await;
            }
        });

        let ret = Box::new(WgClientTunnel {
            wg_peer,
            tunnel,
            info: TunnelInfo {
                tunnel_type: "wg".to_owned(),
                local_addr: super::build_url_from_socket_addr(&local_addr, "wg").into(),
                remote_addr: self.remote_url().into(),
            },
        });

        Ok(ret)
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use boringtun::*;

    use crate::tunnels::common::tests::{_tunnel_bench, _tunnel_pingpong};
    use crate::tunnels::wireguard::*;

    pub fn enable_log() {
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::DEBUG.into())
            .from_env()
            .unwrap()
            .add_directive("tarpc=error".parse().unwrap());
        tracing_subscriber::fmt::fmt()
            .pretty()
            .with_env_filter(filter)
            .init();
    }

    pub fn create_wg_config() -> (WgConfig, WgConfig) {
        let my_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let my_public_key = x25519::PublicKey::from(&my_secret_key);

        let their_secret_key = x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let their_public_key = x25519::PublicKey::from(&their_secret_key);

        let server_cfg = WgConfig {
            my_secret_key: my_secret_key.clone(),
            my_public_key,
            peer_public_key: their_public_key.clone(),
        };

        let client_cfg = WgConfig {
            my_secret_key: their_secret_key,
            my_public_key: their_public_key,
            peer_public_key: my_public_key,
        };

        (server_cfg, client_cfg)
    }

    #[tokio::test]
    async fn test_wg() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://0.0.0.0:5599".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://127.0.0.1:5599".parse().unwrap(), client_cfg);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn udp_bench() {
        let (server_cfg, client_cfg) = create_wg_config();
        let listener = WgTunnelListener::new("wg://0.0.0.0:5598".parse().unwrap(), server_cfg);
        let connector = WgTunnelConnector::new("wg://127.0.0.1:5598".parse().unwrap(), client_cfg);
        _tunnel_bench(listener, connector).await
    }
}
