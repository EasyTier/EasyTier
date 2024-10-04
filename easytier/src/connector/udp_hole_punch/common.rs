use std::{net::SocketAddr, sync::Arc};

use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use rand::seq::SliceRandom as _;
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};
use tracing::{instrument, Instrument, Level};
use zerocopy::FromBytes as _;

use crate::{
    common::{
        error::Error, global_ctx::ArcGlobalCtx, join_joinset_background, netns::NetNS,
        stun::StunInfoCollectorTrait as _,
    },
    peers::peer_manager::PeerManager,
    tunnel::{
        packet_def::{UDPTunnelHeader, UdpPacketType, UDP_TUNNEL_HEADER_SIZE},
        udp::UdpTunnelListener,
        TunnelConnCounter, TunnelListener as _,
    },
};

pub(crate) const HOLE_PUNCH_PACKET_BODY_LEN: u16 = 16;

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

pub(crate) struct PunchHoleServerCommon {
    peer_mgr: Arc<PeerManager>,

    listeners: Arc<Mutex<Vec<UdpHolePunchListener>>>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl PunchHoleServerCommon {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "PunchHoleServerCommon".to_owned());
        Arc::new(Self {
            peer_mgr,

            listeners: Arc::new(Mutex::new(Vec::new())),
            tasks,
        })
    }

    async fn find_listener(&self, addr: &SocketAddr) -> Option<Arc<UdpSocket>> {
        let all_listener_sockets = self.listeners.lock().await;

        let listener = all_listener_sockets
            .iter()
            .find(|listener| listener.mapped_addr == *addr && listener.running.load())?;

        Some(listener.get_socket().await)
    }

    async fn select_listener(
        &self,
        use_new_listener: bool,
    ) -> Option<(Arc<UdpSocket>, SocketAddr)> {
        let all_listener_sockets = &self.listeners;

        // remove listener that is not active for 40 seconds but keep listeners that are selected less than 30 seconds
        all_listener_sockets.lock().await.retain(|listener| {
            listener.last_active_time.load().elapsed().as_secs() < 40
                || listener.last_select_time.load().elapsed().as_secs() < 30
        });

        let mut use_last = false;
        if all_listener_sockets.lock().await.len() < 4 || use_new_listener {
            tracing::warn!("creating new udp hole punching listener");
            all_listener_sockets.lock().await.push(
                UdpHolePunchListener::new(self.peer_mgr.clone())
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
}
