use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Context;
use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use rand::{seq::SliceRandom, Rng};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tracing::{instrument, Instrument, Level};
use zerocopy::FromBytes;

use crate::{
    common::{
        constants, error::Error, global_ctx::ArcGlobalCtx, join_joinset_background, netns::NetNS,
        stun::StunInfoCollectorTrait, PeerId,
    },
    defer,
    peers::peer_manager::PeerManager,
    rpc::NatType,
    tunnel::{
        common::setup_sokcet2,
        packet_def::{UDPTunnelHeader, UdpPacketType, UDP_TUNNEL_HEADER_SIZE},
        udp::{new_hole_punch_packet, UdpTunnelConnector, UdpTunnelListener},
        Tunnel, TunnelConnCounter, TunnelListener,
    },
};

use super::direct::PeerManagerForDirectConnector;

const HOLE_PUNCH_PACKET_BODY_LEN: u16 = 16;

fn generate_shuffled_port_vec() -> Vec<u16> {
    let mut rng = rand::thread_rng();
    let mut port_vec: Vec<u16> = (1..=65535).collect();
    port_vec.shuffle(&mut rng);
    port_vec
}

// used for symmetric hole punching, binding to multiple ports to increase the chance of success
struct UdpSocketArray {
    sockets: Arc<DashMap<SocketAddr, Arc<UdpSocket>>>,
    max_socket_count: usize,
    net_ns: NetNS,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    intreast_tids: Arc<DashSet<u32>>,
    tid_to_socket: Arc<DashMap<u32, Vec<Arc<UdpSocket>>>>,
}

impl UdpSocketArray {
    pub fn new(max_socket_count: usize, net_ns: NetNS) -> Self {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "UdpSocketArray".to_owned());

        Self {
            sockets: Arc::new(DashMap::new()),
            max_socket_count,
            net_ns,
            tasks,

            intreast_tids: Arc::new(DashSet::new()),
            tid_to_socket: Arc::new(DashMap::new()),
        }
    }

    pub fn started(&self) -> bool {
        !self.sockets.is_empty()
    }

    async fn add_new_socket(&self) -> Result<(), anyhow::Error> {
        let socket = {
            let _g = self.net_ns.guard();
            Arc::new(UdpSocket::bind("0.0.0.0:0").await?)
        };
        let local_addr = socket.local_addr()?;
        self.sockets.insert(local_addr, socket.clone());

        let intreast_tids = self.intreast_tids.clone();
        let tid_to_socket = self.tid_to_socket.clone();
        self.tasks.lock().unwrap().spawn(
            async move {
                let mut buf = [0u8; UDP_TUNNEL_HEADER_SIZE + HOLE_PUNCH_PACKET_BODY_LEN as usize];
                tracing::trace!(?local_addr, "udp socket added");
                loop {
                    let Ok((len, addr)) = socket.recv_from(&mut buf).await else {
                        break;
                    };

                    tracing::debug!(?len, ?addr, "got raw packet");

                    if len != UDP_TUNNEL_HEADER_SIZE + HOLE_PUNCH_PACKET_BODY_LEN as usize {
                        continue;
                    }

                    let Some(p) = UDPTunnelHeader::ref_from_prefix(&buf) else {
                        continue;
                    };

                    tracing::debug!(?p, ?addr, "got udp hole punch packet");

                    if p.msg_type != UdpPacketType::HolePunch as u8
                        || p.len.get() != HOLE_PUNCH_PACKET_BODY_LEN
                    {
                        continue;
                    }

                    let tid = p.conn_id.get();
                    if intreast_tids.contains(&tid) {
                        tracing::info!(?addr, "got hole punching packet with intreast tid");
                        tid_to_socket
                            .entry(tid)
                            .or_insert_with(Vec::new)
                            .push(socket);
                        break;
                    }
                }
                tracing::debug!(?local_addr, "udp socket recv loop end");
            }
            .instrument(tracing::info_span!("udp array socket recv loop")),
        );
        Ok(())
    }

    #[instrument(err)]
    pub async fn start(&self) -> Result<(), anyhow::Error> {
        if self.started() {
            return Ok(());
        }

        tracing::info!("starting udp socket array");

        while self.sockets.len() < self.max_socket_count {
            self.add_new_socket().await?;
        }

        Ok(())
    }

    #[instrument(err)]
    pub async fn send_with_all(&self, data: &[u8], addr: SocketAddr) -> Result<(), anyhow::Error> {
        tracing::info!(?addr, "sending hole punching packet");

        for socket in self.sockets.iter() {
            let socket = socket.value();
            socket.send_to(data, addr).await?;
        }

        Ok(())
    }

    #[instrument(ret(level = Level::DEBUG))]
    pub fn try_fetch_punched_socket(&self, tid: u32) -> Option<Arc<UdpSocket>> {
        tracing::debug!(?tid, "try fetch punched socket");
        self.tid_to_socket.get_mut(&tid)?.value_mut().pop()
    }

    pub fn add_intreast_tid(&self, tid: u32) {
        self.intreast_tids.insert(tid);
    }

    pub fn remove_intreast_tid(&self, tid: u32) {
        self.intreast_tids.remove(&tid);
        self.tid_to_socket.remove(&tid);
    }
}

impl std::fmt::Debug for UdpSocketArray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocketArray")
            .field("sockets", &self.sockets.len())
            .field("max_socket_count", &self.max_socket_count)
            .field("started", &self.started())
            .field("intreast_tids", &self.intreast_tids.len())
            .field("tid_to_socket", &self.tid_to_socket.len())
            .finish()
    }
}

#[tarpc::service]
pub trait UdpHolePunchService {
    async fn try_punch_hole(local_mapped_addr: SocketAddr) -> Option<SocketAddr>;
    async fn try_punch_symmetric(
        listener_addr: SocketAddr,
        port: u16,
        public_ips: Vec<Ipv4Addr>,
        min_port: u16,
        max_port: u16,
        transaction_id: u32,
        round: u32,
        last_port_index: usize,
    ) -> Option<usize>;
}

#[derive(Debug)]
struct UdpHolePunchListener {
    socket: Arc<UdpSocket>,
    tasks: JoinSet<()>,
    running: Arc<AtomicCell<bool>>,
    mapped_addr: SocketAddr,
    conn_counter: Arc<Box<dyn TunnelConnCounter>>,

    listen_time: std::time::Instant,
    last_select_time: AtomicCell<std::time::Instant>,
    last_active_time: Arc<AtomicCell<std::time::Instant>>,
}

impl UdpHolePunchListener {
    async fn get_avail_port() -> Result<u16, Error> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(socket.local_addr()?.port())
    }

    #[instrument(err)]
    pub async fn new(peer_mgr: Arc<PeerManager>) -> Result<Self, Error> {
        let port = Self::get_avail_port().await?;
        let listen_url = format!("udp://0.0.0.0:{}", port);

        let gctx = peer_mgr.get_global_ctx();
        let stun_info_collect = gctx.get_stun_info_collector();
        let mapped_addr = stun_info_collect.get_udp_port_mapping(port).await?;

        let mut listener = UdpTunnelListener::new(listen_url.parse().unwrap());

        {
            let _g = peer_mgr.get_global_ctx().net_ns.guard();
            listener.listen().await?;
        }
        let socket = listener.get_socket().unwrap();

        let running = Arc::new(AtomicCell::new(true));
        let running_clone = running.clone();

        let conn_counter = listener.get_conn_counter();
        let mut tasks = JoinSet::new();

        tasks.spawn(async move {
            while let Ok(conn) = listener.accept().await {
                tracing::warn!(?conn, "udp hole punching listener got peer connection");
                let peer_mgr = peer_mgr.clone();
                tokio::spawn(async move {
                    if let Err(e) = peer_mgr.add_tunnel_as_server(conn).await {
                        tracing::error!(
                            ?e,
                            "failed to add tunnel as server in hole punch listener"
                        );
                    }
                });
            }

            running_clone.store(false);
        });

        let last_active_time = Arc::new(AtomicCell::new(std::time::Instant::now()));
        let conn_counter_clone = conn_counter.clone();
        let last_active_time_clone = last_active_time.clone();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if conn_counter_clone.get() != 0 {
                    last_active_time_clone.store(std::time::Instant::now());
                }
            }
        });

        tracing::warn!(?mapped_addr, ?socket, "udp hole punching listener started");

        Ok(Self {
            tasks,
            socket,
            running,
            mapped_addr,
            conn_counter,

            listen_time: std::time::Instant::now(),
            last_select_time: AtomicCell::new(std::time::Instant::now()),
            last_active_time,
        })
    }

    pub async fn get_socket(&self) -> Arc<UdpSocket> {
        self.last_select_time.store(std::time::Instant::now());
        self.socket.clone()
    }
}

struct UdpHolePunchConnectorData {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Arc<PeerManager>,
    listeners: Arc<Mutex<Vec<UdpHolePunchListener>>>,
    shuffled_port_vec: Arc<Vec<u16>>,

    udp_array: Arc<Mutex<Option<Arc<UdpSocketArray>>>>,
    try_direct_connect: AtomicBool,
    punch_predicablely: AtomicBool,
    punch_randomly: AtomicBool,
    udp_array_size: AtomicUsize,
}

impl std::fmt::Debug for UdpHolePunchConnectorData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // print peer id listener count
        let peer_id = self.peer_mgr.my_peer_id();
        f.debug_struct("UdpHolePunchConnectorData")
            .field("peer_id", &peer_id)
            .finish()
    }
}

impl UdpHolePunchConnectorData {
    fn my_nat_type(&self) -> NatType {
        let stun_info = self.global_ctx.get_stun_info_collector().get_stun_info();
        NatType::try_from(stun_info.udp_nat_type).unwrap()
    }
}

#[derive(Clone)]
struct UdpHolePunchRpcServer {
    data: Arc<UdpHolePunchConnectorData>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

#[tarpc::server]
impl UdpHolePunchService for UdpHolePunchRpcServer {
    #[tracing::instrument(skip(self))]
    async fn try_punch_hole(
        self,
        _: tarpc::context::Context,
        local_mapped_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        // local mapped addr will be unspecified if peer is symmetric
        let peer_is_symmetric = local_mapped_addr.ip().is_unspecified();
        let (socket, mapped_addr) = self.select_listener(peer_is_symmetric).await?;
        tracing::warn!(?local_mapped_addr, ?mapped_addr, "start hole punching");

        if !peer_is_symmetric {
            let my_udp_nat_type = self
                .data
                .global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .udp_nat_type;

            // if we are cone, we need to send hole punching resp to client
            if my_udp_nat_type == NatType::PortRestricted as i32
                || my_udp_nat_type == NatType::Restricted as i32
                || my_udp_nat_type == NatType::FullCone as i32
            {
                let notifier = Arc::new(Notify::new());

                let n = notifier.clone();
                // send punch msg to local_mapped_addr for 3 seconds, 3.3 packet per second
                self.tasks.lock().unwrap().spawn(async move {
                    for i in 0..10 {
                        tracing::info!(?local_mapped_addr, "sending hole punching packet");

                        let udp_packet = new_hole_punch_packet(100, HOLE_PUNCH_PACKET_BODY_LEN);
                        let _ = socket
                            .send_to(&udp_packet.into_bytes(), local_mapped_addr)
                            .await;
                        let sleep_ms = if i < 4 { 10 } else { 500 };
                        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
                        if i == 3 {
                            n.notify_one();
                        }
                    }
                });

                notifier.notified().await;
            }
        }

        Some(mapped_addr)
    }

    #[instrument(skip(self))]
    async fn try_punch_symmetric(
        self,
        _: tarpc::context::Context,
        listener_addr: SocketAddr,
        port: u16,
        public_ips: Vec<Ipv4Addr>,
        mut min_port: u16,
        mut max_port: u16,
        transaction_id: u32,
        round: u32,
        last_port_index: usize,
    ) -> Option<usize> {
        tracing::info!("try_punch_symmetric start");

        let punch_predictablely = self.data.punch_predicablely.load(Ordering::Relaxed);
        let punch_randomly = self.data.punch_randomly.load(Ordering::Relaxed);
        let total_port_count = self.data.shuffled_port_vec.len();
        let listener = self.find_listener(&listener_addr).await?;
        let ip_count = public_ips.len();
        if ip_count == 0 {
            tracing::warn!("try_punch_symmetric got zero len public ip");
            return None;
        }

        min_port = std::cmp::max(1, min_port);
        if max_port == 0 {
            max_port = u16::MAX;
        }
        if max_port < min_port {
            std::mem::swap(&mut min_port, &mut max_port);
        }

        // send max k1 packets if we are predicting the dst port
        let max_k1 = 180;
        // send max k2 packets if we are sending to random port
        let max_k2 = rand::thread_rng().gen_range(600..800);

        // this means the NAT is allocating port in a predictable way
        if max_port.abs_diff(min_port) <= max_k1 && round <= 6 && punch_predictablely {
            let (min_port, max_port) = {
                // round begin from 0. if round is even, we guess port in increasing order
                let port_delta = (max_k1 as u32) / ip_count as u32;
                let port_diff_for_min = std::cmp::min((round / 2) * port_delta, u16::MAX as u32);
                if round % 2 == 0 {
                    let lower = std::cmp::max(1, port.saturating_add(port_diff_for_min as u16));
                    let upper = lower.saturating_add(port_delta as u16);
                    (lower, upper)
                } else {
                    let upper = std::cmp::max(1, port.saturating_sub(port_diff_for_min as u16));
                    let lower = std::cmp::max(1, upper.saturating_sub(port_delta as u16));
                    (lower, upper)
                }
            };
            let mut ports = (min_port..=max_port).collect::<Vec<_>>();
            ports.push(max_port);
            ports.shuffle(&mut rand::thread_rng());
            self.send_symmetric_hole_punch_packet(
                listener.clone(),
                transaction_id,
                &public_ips,
                &ports,
            )
            .await
            .ok()?;
        }

        if punch_randomly {
            let start = last_port_index % total_port_count;
            let diff = std::cmp::max(10, max_k2 / ip_count);
            let end = std::cmp::min(start + diff, self.data.shuffled_port_vec.len());
            self.send_symmetric_hole_punch_packet(
                listener.clone(),
                transaction_id,
                &public_ips,
                &self.data.shuffled_port_vec[start..end],
            )
            .await
            .ok()?;

            return if end >= self.data.shuffled_port_vec.len() {
                Some(1)
            } else {
                Some(end)
            };
        }

        return Some(1);
    }
}

impl UdpHolePunchRpcServer {
    pub fn new(data: Arc<UdpHolePunchConnectorData>) -> Self {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "UdpHolePunchRpcServer".to_owned());
        Self { data, tasks }
    }

    async fn find_listener(&self, addr: &SocketAddr) -> Option<Arc<UdpSocket>> {
        let all_listener_sockets = self.data.listeners.lock().await;

        let listener = all_listener_sockets
            .iter()
            .find(|listener| listener.mapped_addr == *addr && listener.running.load())?;

        Some(listener.get_socket().await)
    }

    async fn select_listener(
        &self,
        use_new_listener: bool,
    ) -> Option<(Arc<UdpSocket>, SocketAddr)> {
        let all_listener_sockets = &self.data.listeners;

        // remove listener that is not active for 40 seconds but keep listeners that are selected less than 30 seconds
        all_listener_sockets.lock().await.retain(|listener| {
            listener.last_active_time.load().elapsed().as_secs() < 40
                || listener.last_select_time.load().elapsed().as_secs() < 30
        });

        let mut use_last = false;
        if all_listener_sockets.lock().await.len() < 4 || use_new_listener {
            tracing::warn!("creating new udp hole punching listener");
            all_listener_sockets.lock().await.push(
                UdpHolePunchListener::new(self.data.peer_mgr.clone())
                    .await
                    .ok()?,
            );
            use_last = true;
        }

        let locked = all_listener_sockets.lock().await;

        let listener = if use_last {
            locked.last()?
        } else {
            // use the listener that is active most recently
            locked
                .iter()
                .max_by_key(|listener| listener.last_active_time.load())?
        };

        Some((listener.get_socket().await, listener.mapped_addr))
    }

    #[tracing::instrument(err, ret(level=Level::DEBUG), skip(self, ports))]
    async fn send_symmetric_hole_punch_packet(
        &self,
        udp: Arc<UdpSocket>,
        transaction_id: u32,
        public_ips: &Vec<Ipv4Addr>,
        ports: &[u16],
    ) -> Result<(), Error> {
        tracing::debug!(
            ?public_ips,
            "sending symmetric hole punching packet, ports len: {}",
            ports.len(),
        );
        for port in ports {
            for pub_ip in public_ips {
                let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, *port));
                let packet = new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
                udp.send_to(&packet.into_bytes(), addr).await?;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        Ok(())
    }
}

pub struct UdpHolePunchConnector {
    data: Arc<UdpHolePunchConnectorData>,
    tasks: JoinSet<()>,
}

// Currently support:
// Symmetric -> Full Cone
// Any Type of Full Cone -> Any Type of Full Cone

// if same level of full cone, node with smaller peer_id will be the initiator
// if different level of full cone, node with more strict level will be the initiator

impl UdpHolePunchConnector {
    pub fn new(global_ctx: ArcGlobalCtx, peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            data: Arc::new(UdpHolePunchConnectorData {
                global_ctx,
                peer_mgr,
                listeners: Arc::new(Mutex::new(Vec::new())),
                shuffled_port_vec: Arc::new(generate_shuffled_port_vec()),
                udp_array: Arc::new(Mutex::new(None)),
                try_direct_connect: AtomicBool::new(true),
                punch_predicablely: AtomicBool::new(true),
                punch_randomly: AtomicBool::new(true),
                udp_array_size: AtomicUsize::new(80),
            }),
            tasks: JoinSet::new(),
        }
    }

    pub async fn run_as_client(&mut self) -> Result<(), Error> {
        let data = self.data.clone();
        self.tasks.spawn(async move {
            Self::main_loop(data).await;
        });

        Ok(())
    }

    pub async fn run_as_server(&mut self) -> Result<(), Error> {
        self.data.peer_mgr.get_peer_rpc_mgr().run_service(
            constants::UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID,
            UdpHolePunchRpcServer::new(self.data.clone()).serve(),
        );

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.run_as_client().await?;
        self.run_as_server().await?;

        Ok(())
    }

    async fn collect_peer_to_connect(
        data: Arc<UdpHolePunchConnectorData>,
    ) -> Vec<(PeerId, NatType)> {
        let mut peers_to_connect = Vec::new();

        // do not do anything if:
        // 1. our stun test has not finished
        // 2. our nat type is OpenInternet or NoPat, which means we can wait other peers to connect us
        let my_nat_type = data.my_nat_type();
        if my_nat_type == NatType::Unknown
            || my_nat_type == NatType::OpenInternet
            || my_nat_type == NatType::NoPat
        {
            return peers_to_connect;
        }

        // collect peer list from peer manager and do some filter:
        // 1. peers without direct conns;
        // 2. peers is full cone (any restricted type);
        for route in data.peer_mgr.list_routes().await.iter() {
            let Some(peer_stun_info) = route.stun_info.as_ref() else {
                continue;
            };
            let Ok(peer_nat_type) = NatType::try_from(peer_stun_info.udp_nat_type) else {
                continue;
            };

            let peer_id: PeerId = route.peer_id;
            let conns = data.peer_mgr.list_peer_conns(peer_id).await;
            if conns.is_some() && conns.unwrap().len() > 0 {
                continue;
            }

            // if peer is symmetric ignore it because we cannot connect to it
            // if peer is open internet or no pat, direct connector will connecto to it
            if peer_nat_type == NatType::Unknown
                || peer_nat_type == NatType::OpenInternet
                || peer_nat_type == NatType::NoPat
                || peer_nat_type == NatType::Symmetric
                || peer_nat_type == NatType::SymUdpFirewall
            {
                continue;
            }

            // if we are symmetric, we can only connect to cone peer
            if (my_nat_type == NatType::Symmetric || my_nat_type == NatType::SymUdpFirewall)
                && (peer_nat_type == NatType::Symmetric || peer_nat_type == NatType::SymUdpFirewall)
            {
                continue;
            }

            // if we have smae level of full cone, node with smaller peer_id will be the initiator
            if my_nat_type == peer_nat_type {
                if data.peer_mgr.my_peer_id() > peer_id {
                    continue;
                }
            } else {
                // if we have different level of full cone
                // we will be the initiator if we have more strict level
                if my_nat_type < peer_nat_type {
                    continue;
                }
            }

            tracing::info!(
                ?peer_id,
                ?peer_nat_type,
                ?my_nat_type,
                ?data.global_ctx.id,
                "found peer to do hole punching"
            );

            peers_to_connect.push((peer_id, peer_nat_type));
        }

        peers_to_connect
    }

    async fn try_connect_with_socket(
        socket: Arc<UdpSocket>,
        remote_mapped_addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let connector = UdpTunnelConnector::new(
            format!(
                "udp://{}:{}",
                remote_mapped_addr.ip(),
                remote_mapped_addr.port()
            )
            .to_string()
            .parse()
            .unwrap(),
        );
        connector
            .try_connect_with_socket(socket, remote_mapped_addr)
            .await
            .map_err(|e| Error::from(e))
    }

    #[tracing::instrument(err)]
    async fn do_hole_punching_cone(
        data: Arc<UdpHolePunchConnectorData>,
        dst_peer_id: PeerId,
    ) -> Result<Box<dyn Tunnel>, anyhow::Error> {
        tracing::info!(?dst_peer_id, "start hole punching");
        // client: choose a local udp port, and get the pubic mapped port from stun server
        let socket = {
            let _g = data.global_ctx.net_ns.guard();
            UdpSocket::bind("0.0.0.0:0").await.with_context(|| "")?
        };
        let local_socket_addr = socket.local_addr()?;
        let local_port = socket.local_addr()?.port();
        drop(socket); // drop the socket to release the port

        let local_mapped_addr = data
            .global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(local_port)
            .await
            .with_context(|| "failed to get udp port mapping")?;

        // client -> server: tell server the mapped port, server will return the mapped address of listening port.
        let Some(remote_mapped_addr) = data
            .peer_mgr
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(
                constants::UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID,
                dst_peer_id,
                |c| async {
                    let client =
                        UdpHolePunchServiceClient::new(tarpc::client::Config::default(), c).spawn();
                    let remote_mapped_addr = client
                        .try_punch_hole(tarpc::context::current(), local_mapped_addr)
                        .await;
                    tracing::info!(?remote_mapped_addr, ?dst_peer_id, "got remote mapped addr");
                    remote_mapped_addr
                },
            )
            .await?
        else {
            return Err(anyhow::anyhow!("failed to get remote mapped addr"));
        };

        // server: will send some punching resps, total 10 packets.
        // client: use the socket to create UdpTunnel with UdpTunnelConnector
        // NOTICE: UdpTunnelConnector will ignore the punching resp packet sent by remote.
        let _g = data.global_ctx.net_ns.guard();
        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(local_socket_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        setup_sokcet2(&socket2_socket, &local_socket_addr)?;
        let socket = Arc::new(UdpSocket::from_std(socket2_socket.into())?);

        Ok(Self::try_connect_with_socket(socket, remote_mapped_addr)
            .await
            .with_context(|| "UdpTunnelConnector failed to connect remote")?)
    }

    #[tracing::instrument(err(level = Level::ERROR))]
    async fn do_hole_punching_symmetric(
        data: Arc<UdpHolePunchConnectorData>,
        dst_peer_id: PeerId,
    ) -> Result<Box<dyn Tunnel>, anyhow::Error> {
        let Some(udp_array) = data.udp_array.lock().await.clone() else {
            return Err(anyhow::anyhow!("udp array not started"));
        };

        let Some(remote_mapped_addr) = data
            .peer_mgr
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(
                constants::UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID,
                dst_peer_id,
                |c| async {
                    let client =
                        UdpHolePunchServiceClient::new(tarpc::client::Config::default(), c).spawn();
                    let remote_mapped_addr = client
                        .try_punch_hole(tarpc::context::current(), "0.0.0.0:0".parse().unwrap())
                        .await;
                    tracing::debug!(
                        ?remote_mapped_addr,
                        ?dst_peer_id,
                        "hole punching symmetric got remote mapped addr"
                    );
                    remote_mapped_addr
                },
            )
            .await?
        else {
            return Err(anyhow::anyhow!("failed to get remote mapped addr"));
        };

        // try direct connect first
        if data.try_direct_connect.load(Ordering::Relaxed) {
            if let Ok(tunnel) = Self::try_connect_with_socket(
                Arc::new(UdpSocket::bind("0.0.0.0:0").await?),
                remote_mapped_addr,
            )
            .await
            {
                return Ok(tunnel);
            }
        }

        let tid = rand::thread_rng().gen();
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        udp_array.add_intreast_tid(tid);
        defer! { udp_array.remove_intreast_tid(tid);}
        udp_array.send_with_all(&packet, remote_mapped_addr).await?;

        // get latest port mapping
        let local_mapped_addr = data
            .global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(0)
            .await?;
        let port = local_mapped_addr.port();
        let IpAddr::V4(ipv4) = local_mapped_addr.ip() else {
            return Err(anyhow::anyhow!("failed to get local mapped addr"));
        };
        let stun_info = data.global_ctx.get_stun_info_collector().get_stun_info();
        let mut public_ips: Vec<Ipv4Addr> = stun_info
            .public_ip
            .iter()
            .map(|x| x.parse().unwrap())
            .collect();
        if !public_ips.contains(&ipv4) {
            public_ips.push(ipv4);
        }
        if public_ips.is_empty() {
            return Err(anyhow::anyhow!("failed to get public ips"));
        }

        let mut last_port_idx = 0;

        for round in 0..30 {
            let Some(next_last_port_idx) = data
                .peer_mgr
                .get_peer_rpc_mgr()
                .do_client_rpc_scoped(
                    constants::UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID,
                    dst_peer_id,
                    |c| async {
                        let client =
                            UdpHolePunchServiceClient::new(tarpc::client::Config::default(), c)
                                .spawn();
                        let last_port_idx = client
                            .try_punch_symmetric(
                                tarpc::context::current(),
                                remote_mapped_addr,
                                port,
                                public_ips.clone(),
                                stun_info.min_port as u16,
                                stun_info.max_port as u16,
                                tid,
                                round,
                                last_port_idx,
                            )
                            .await;
                        tracing::info!(?last_port_idx, ?dst_peer_id, "punch symmetric return");
                        last_port_idx
                    },
                )
                .await?
            else {
                return Err(anyhow::anyhow!("failed to get remote mapped addr"));
            };

            while let Some(socket) = udp_array.try_fetch_punched_socket(tid) {
                if let Ok(tunnel) = Self::try_connect_with_socket(socket, remote_mapped_addr).await
                {
                    return Ok(tunnel);
                }
            }

            last_port_idx = next_last_port_idx;
        }

        return Err(anyhow::anyhow!("udp array not started"));
    }

    async fn peer_punching_task(
        data: Arc<UdpHolePunchConnectorData>,
        peer_id: PeerId,
    ) -> Result<(), anyhow::Error> {
        const MAX_BACKOFF_TIME: u64 = 600;
        let mut backoff_time = vec![15, 15, 30, 30, 60, 120, 300, MAX_BACKOFF_TIME];
        let my_nat_type = data.my_nat_type();

        loop {
            let ret = if my_nat_type == NatType::FullCone
                || my_nat_type == NatType::Restricted
                || my_nat_type == NatType::PortRestricted
            {
                Self::do_hole_punching_cone(data.clone(), peer_id).await
            } else {
                Self::do_hole_punching_symmetric(data.clone(), peer_id).await
            };

            match ret {
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(
                        backoff_time.pop().unwrap_or(MAX_BACKOFF_TIME),
                    ))
                    .await;
                    continue;
                }

                Ok(tunnel) => {
                    let _ = data
                        .peer_mgr
                        .add_client_tunnel(tunnel)
                        .await
                        .with_context(|| {
                            "failed to add tunnel as client in hole punch connector"
                        })?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn main_loop(data: Arc<UdpHolePunchConnectorData>) {
        type JoinTaskRet = Result<(), anyhow::Error>;
        type JoinTask = tokio::task::JoinHandle<JoinTaskRet>;
        let punching_task = Arc::new(DashMap::<(PeerId, NatType), JoinTask>::new());
        let mut last_my_nat_type = NatType::Unknown;

        loop {
            let my_nat_type = data.my_nat_type();
            let peers_to_connect = Self::collect_peer_to_connect(data.clone()).await;

            // remove task not in peers_to_connect
            let mut to_remove = vec![];
            for item in punching_task.iter() {
                if !peers_to_connect.contains(item.key())
                    || item.value().is_finished()
                    || my_nat_type != last_my_nat_type
                {
                    to_remove.push(item.key().clone());
                }
            }
            for key in to_remove {
                if let Some((_, task)) = punching_task.remove(&key) {
                    task.abort();
                    match task.await {
                        Ok(Ok(_)) => {}
                        Ok(Err(task_ret)) => {
                            tracing::error!(?task_ret, "hole punching task failed");
                        }
                        Err(e) => {
                            tracing::error!(?e, "hole punching task aborted");
                        }
                    }
                }
            }

            last_my_nat_type = my_nat_type;

            if !peers_to_connect.is_empty() {
                let my_nat_type = data.my_nat_type();
                if my_nat_type == NatType::Symmetric || my_nat_type == NatType::SymUdpFirewall {
                    let mut udp_array = data.udp_array.lock().await;
                    if udp_array.is_none() {
                        *udp_array = Some(Arc::new(UdpSocketArray::new(
                            data.udp_array_size.load(Ordering::Relaxed),
                            data.global_ctx.net_ns.clone(),
                        )));
                    }
                    let udp_array = udp_array.as_ref().unwrap();
                    udp_array.start().await.unwrap();
                }

                for item in peers_to_connect {
                    punching_task.insert(
                        item,
                        tokio::spawn(Self::peer_punching_task(data.clone(), item.0)),
                    );
                }
            } else if punching_task.is_empty() {
                data.udp_array.lock().await.take();
            }

            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use crate::connector::udp_hole_punch::UdpHolePunchListener;
    use crate::rpc::{NatType, StunInfo};
    use crate::tunnel::common::tests::wait_for_condition;

    use crate::{
        common::{error::Error, stun::StunInfoCollectorTrait},
        connector::udp_hole_punch::UdpHolePunchConnector,
        peers::{
            peer_manager::PeerManager,
            tests::{
                connect_peer_manager, create_mock_peer_manager, wait_route_appear,
                wait_route_appear_with_cost,
            },
        },
    };

    struct MockStunInfoCollector {
        udp_nat_type: NatType,
    }

    #[async_trait::async_trait]
    impl StunInfoCollectorTrait for MockStunInfoCollector {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                udp_nat_type: self.udp_nat_type as i32,
                tcp_nat_type: NatType::Unknown as i32,
                last_update_time: std::time::Instant::now().elapsed().as_secs() as i64,
                min_port: 100,
                max_port: 200,
                ..Default::default()
            }
        }

        async fn get_udp_port_mapping(&self, mut port: u16) -> Result<std::net::SocketAddr, Error> {
            if port == 0 {
                port = 40144;
            }
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }
    }

    pub fn replace_stun_info_collector(peer_mgr: Arc<PeerManager>, udp_nat_type: NatType) {
        let collector = Box::new(MockStunInfoCollector { udp_nat_type });
        peer_mgr
            .get_global_ctx()
            .replace_stun_info_collector(collector);
    }

    pub async fn create_mock_peer_manager_with_mock_stun(
        udp_nat_type: NatType,
    ) -> Arc<PeerManager> {
        let p_a = create_mock_peer_manager().await;
        replace_stun_info_collector(p_a.clone(), udp_nat_type);
        p_a
    }

    #[tokio::test]
    async fn hole_punching_cone() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        println!("{:?}", p_a.list_routes().await);

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.get_global_ctx(), p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.get_global_ctx(), p_c.clone());

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
        println!("{:?}", p_a.list_routes().await);
    }

    #[tokio::test]
    async fn hole_punching_symmetric_only_random() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Symmetric).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.get_global_ctx(), p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.get_global_ctx(), p_c.clone());

        hole_punching_a
            .data
            .try_direct_connect
            .store(false, std::sync::atomic::Ordering::Relaxed);

        hole_punching_c
            .data
            .punch_predicablely
            .store(false, std::sync::atomic::Ordering::Relaxed);

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        wait_for_condition(
            || async { hole_punching_a.data.udp_array.lock().await.is_some() },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || async {
                wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
                    .await
                    .is_ok()
            },
            Duration::from_secs(30),
        )
        .await;
        println!("{:?}", p_a.list_routes().await);

        wait_for_condition(
            || async { hole_punching_a.data.udp_array.lock().await.is_none() },
            Duration::from_secs(20),
        )
        .await;
    }

    #[tokio::test]
    async fn hole_punching_symmetric_only_predict() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Symmetric).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.get_global_ctx(), p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.get_global_ctx(), p_c.clone());

        hole_punching_a
            .data
            .try_direct_connect
            .store(false, std::sync::atomic::Ordering::Relaxed);
        hole_punching_a
            .data
            .udp_array_size
            .store(0, std::sync::atomic::Ordering::Relaxed);

        hole_punching_c
            .data
            .punch_randomly
            .store(false, std::sync::atomic::Ordering::Relaxed);

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        let udp_self = Arc::new(UdpSocket::bind("0.0.0.0:40144").await.unwrap());
        let udp_inc = Arc::new(UdpSocket::bind("0.0.0.0:40147").await.unwrap());
        let udp_inc2 = Arc::new(UdpSocket::bind("0.0.0.0:40400").await.unwrap());
        let udp_dec = Arc::new(UdpSocket::bind("0.0.0.0:40140").await.unwrap());
        let udp_dec2 = Arc::new(UdpSocket::bind("0.0.0.0:40350").await.unwrap());
        let udps = vec![udp_self, udp_inc, udp_inc2, udp_dec, udp_dec2];

        let counter = Arc::new(AtomicU32::new(0));

        // all these sockets should receive hole punching packet
        for udp in udps.iter().map(Arc::clone) {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (len, addr) = udp.recv_from(&mut buf).await.unwrap();
                println!("{:?} {:?}", len, addr);
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
        }

        let udp_len = udps.len();
        wait_for_condition(
            || async { counter.load(std::sync::atomic::Ordering::Relaxed) == udp_len as u32 },
            Duration::from_secs(30),
        )
        .await;
    }
}
