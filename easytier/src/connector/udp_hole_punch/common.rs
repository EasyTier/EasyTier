use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use guarden::defer;
use rand::seq::SliceRandom as _;
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};
use tracing::{Instrument, Level, instrument};
use zerocopy::FromBytes as _;

use crate::{
    common::{
        PeerId, error::Error, global_ctx::ArcGlobalCtx, join_joinset_background, netns::NetNS, upnp,
    },
    peers::peer_manager::PeerManager,
    proto::common::NatType,
    tunnel::{
        Tunnel, TunnelConnCounter, TunnelListener as _,
        packet_def::{UDP_TUNNEL_HEADER_SIZE, UDPTunnelHeader, UdpPacketType},
        udp::{UdpTunnelConnector, UdpTunnelListener, new_hole_punch_packet},
    },
};

pub(crate) const HOLE_PUNCH_PACKET_BODY_LEN: u16 = 16;
const MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS: usize = 4;

fn generate_shuffled_port_vec() -> Vec<u16> {
    let mut rng = rand::thread_rng();
    let mut port_vec: Vec<u16> = (1..=65535).collect();
    port_vec.shuffle(&mut rng);
    port_vec
}

pub(crate) enum UdpPunchClientMethod {
    None,
    ConeToCone,
    SymToCone,
    EasySymToEasySym,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum UdpNatType {
    Unknown,
    Open(NatType),
    Cone(NatType),
    // bool means if it is incremental
    EasySymmetric(NatType, bool),
    HardSymmetric(NatType),
}

impl From<NatType> for UdpNatType {
    fn from(nat_type: NatType) -> Self {
        match nat_type {
            NatType::Unknown => UdpNatType::Unknown,
            NatType::OpenInternet => UdpNatType::Open(nat_type),
            NatType::NoPat | NatType::FullCone | NatType::Restricted | NatType::PortRestricted => {
                UdpNatType::Cone(nat_type)
            }
            NatType::Symmetric | NatType::SymUdpFirewall => UdpNatType::HardSymmetric(nat_type),
            NatType::SymmetricEasyInc => UdpNatType::EasySymmetric(nat_type, true),
            NatType::SymmetricEasyDec => UdpNatType::EasySymmetric(nat_type, false),
        }
    }
}

impl From<UdpNatType> for NatType {
    fn from(val: UdpNatType) -> Self {
        match val {
            UdpNatType::Unknown => NatType::Unknown,
            UdpNatType::Open(nat_type) => nat_type,
            UdpNatType::Cone(nat_type) => nat_type,
            UdpNatType::EasySymmetric(nat_type, _) => nat_type,
            UdpNatType::HardSymmetric(nat_type) => nat_type,
        }
    }
}

impl UdpNatType {
    pub(crate) fn is_open(&self) -> bool {
        matches!(self, UdpNatType::Open(_))
    }

    pub(crate) fn is_unknown(&self) -> bool {
        matches!(self, UdpNatType::Unknown)
    }

    pub(crate) fn is_sym(&self) -> bool {
        self.is_hard_sym() || self.is_easy_sym()
    }

    pub(crate) fn is_hard_sym(&self) -> bool {
        matches!(self, UdpNatType::HardSymmetric(_))
    }

    pub(crate) fn is_easy_sym(&self) -> bool {
        matches!(self, UdpNatType::EasySymmetric(_, _))
    }

    pub(crate) fn is_cone(&self) -> bool {
        matches!(self, UdpNatType::Cone(_))
    }

    pub(crate) fn get_inc_of_easy_sym(&self) -> Option<bool> {
        match self {
            UdpNatType::EasySymmetric(_, inc) => Some(*inc),
            _ => None,
        }
    }

    pub(crate) fn get_punch_hole_method(
        &self,
        other: Self,
        global_ctx: ArcGlobalCtx,
    ) -> UdpPunchClientMethod {
        // Check if symmetric NAT hole punching is disabled
        let disable_sym_hole_punching = global_ctx.get_flags().disable_sym_hole_punching;

        // If symmetric NAT hole punching is disabled, treat symmetric as cone
        if disable_sym_hole_punching && self.is_sym() {
            // Convert symmetric to cone type for hole punching logic
            if other.is_sym() {
                return UdpPunchClientMethod::None;
            } else {
                return UdpPunchClientMethod::ConeToCone;
            }
        }

        if other.is_unknown() {
            if self.is_sym() {
                return UdpPunchClientMethod::SymToCone;
            } else {
                return UdpPunchClientMethod::ConeToCone;
            }
        }

        if self.is_unknown() {
            if other.is_sym() {
                return UdpPunchClientMethod::None;
            } else {
                return UdpPunchClientMethod::ConeToCone;
            }
        }

        if self.is_open() || other.is_open() {
            // open nat does not need to punch hole
            return UdpPunchClientMethod::None;
        }

        if self.is_cone() {
            if other.is_sym() {
                return UdpPunchClientMethod::None;
            } else {
                return UdpPunchClientMethod::ConeToCone;
            }
        } else if self.is_easy_sym() {
            if other.is_hard_sym() {
                return UdpPunchClientMethod::None;
            } else if other.is_easy_sym() {
                return UdpPunchClientMethod::EasySymToEasySym;
            } else {
                return UdpPunchClientMethod::SymToCone;
            }
        } else if self.is_hard_sym() {
            if other.is_sym() {
                return UdpPunchClientMethod::None;
            } else {
                return UdpPunchClientMethod::SymToCone;
            }
        }

        unreachable!("invalid nat type");
    }

    pub(crate) fn can_punch_hole_as_client(
        &self,
        other: Self,
        my_peer_id: PeerId,
        dst_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
    ) -> bool {
        match self.get_punch_hole_method(other, global_ctx) {
            UdpPunchClientMethod::None => false,
            UdpPunchClientMethod::ConeToCone | UdpPunchClientMethod::SymToCone => true,
            UdpPunchClientMethod::EasySymToEasySym => my_peer_id < dst_peer_id,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PunchedUdpSocket {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) tid: u32,
    pub(crate) remote_addr: SocketAddr,
}

// used for symmetric hole punching, binding to multiple ports to increase the chance of success
pub(crate) struct UdpSocketArray {
    sockets: Arc<DashMap<SocketAddr, Arc<UdpSocket>>>,
    max_socket_count: usize,
    net_ns: NetNS,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    intreast_tids: Arc<DashSet<u32>>,
    tid_to_socket: Arc<DashMap<u32, Vec<PunchedUdpSocket>>>,
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

    pub async fn add_new_socket(&self, socket: Arc<UdpSocket>) -> Result<(), anyhow::Error> {
        let socket_map = self.sockets.clone();
        let local_addr = socket.local_addr()?;
        let intreast_tids = self.intreast_tids.clone();
        let tid_to_socket = self.tid_to_socket.clone();
        socket_map.insert(local_addr, socket.clone());
        self.tasks.lock().unwrap().spawn(
            async move {
                defer!(socket_map.remove(&local_addr););
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

                    let tid = p.conn_id.get();
                    let valid = p.msg_type == UdpPacketType::HolePunch as u8
                        && p.len.get() == HOLE_PUNCH_PACKET_BODY_LEN;
                    tracing::debug!(?p, ?addr, ?tid, ?valid, ?p, "got udp hole punch packet");

                    if !valid {
                        continue;
                    }

                    if intreast_tids.contains(&tid) {
                        tracing::info!(?addr, ?tid, "got hole punching packet with intreast tid");
                        tid_to_socket
                            .entry(tid)
                            .or_default()
                            .push(PunchedUdpSocket {
                                socket: socket.clone(),
                                tid,
                                remote_addr: addr,
                            });
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
        tracing::info!("starting udp socket array");

        while self.sockets.len() < self.max_socket_count {
            let socket = {
                let _g = self.net_ns.guard();
                Arc::new(UdpSocket::bind("0.0.0.0:0").await?)
            };

            self.add_new_socket(socket).await?;
        }

        Ok(())
    }

    #[instrument(err)]
    pub async fn send_with_all(&self, data: &[u8], addr: SocketAddr) -> Result<(), anyhow::Error> {
        tracing::info!(?addr, "sending hole punching packet");

        let sockets = self
            .sockets
            .iter()
            .map(|s| s.value().clone())
            .collect::<Vec<_>>();

        for socket in sockets.iter() {
            for _ in 0..3 {
                socket.send_to(data, addr).await?;
            }
        }

        Ok(())
    }

    #[instrument(ret(level = Level::DEBUG))]
    pub fn try_fetch_punched_socket(&self, tid: u32) -> Option<PunchedUdpSocket> {
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
pub(crate) struct UdpHolePunchListener {
    socket: Arc<UdpSocket>,
    tasks: JoinSet<()>,
    running: Arc<AtomicCell<bool>>,
    mapped_addr: SocketAddr,
    has_port_mapping_lease: bool,
    _port_mapping_lease: Option<upnp::UdpPortMappingLease>,
    conn_counter: Arc<Box<dyn TunnelConnCounter>>,

    listen_time: std::time::Instant,
    last_select_time: AtomicCell<std::time::Instant>,
    last_active_time: Arc<AtomicCell<std::time::Instant>>,
}

impl UdpHolePunchListener {
    #[instrument(err)]
    pub async fn new(peer_mgr: Arc<PeerManager>) -> Result<Self, Error> {
        Self::new_ext(peer_mgr, true, None).await
    }

    #[instrument(err)]
    pub async fn new_ext(
        peer_mgr: Arc<PeerManager>,
        with_mapped_addr: bool,
        port: Option<u16>,
    ) -> Result<Self, Error> {
        let socket = {
            let _g = peer_mgr.get_global_ctx().net_ns.guard();
            Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port.unwrap_or(0))).await?)
        };
        let local_port = socket.local_addr()?.port();
        let listen_url: url::Url = format!("udp://0.0.0.0:{local_port}").parse().unwrap();

        let (mapped_addr, port_mapping_lease) = if with_mapped_addr {
            upnp::resolve_udp_public_addr(peer_mgr.get_global_ctx(), &listen_url, socket.clone())
                .await?
        } else {
            (
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port)),
                None,
            )
        };

        let mut listener = UdpTunnelListener::new_with_socket(listen_url, socket.clone());

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
                    if let Err(e) = peer_mgr.add_tunnel_as_server(conn, false).await {
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
                if conn_counter_clone.get().unwrap_or(0) != 0 {
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
            has_port_mapping_lease: port_mapping_lease.is_some(),
            _port_mapping_lease: port_mapping_lease,
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

    pub async fn get_conn_count(&self) -> usize {
        self.conn_counter.get().unwrap_or(0) as usize
    }
}

pub(crate) struct PunchHoleServerCommon {
    peer_mgr: Arc<PeerManager>,

    listeners: Arc<Mutex<Vec<UdpHolePunchListener>>>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl PunchHoleServerCommon {
    pub(crate) fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "PunchHoleServerCommon".to_owned());

        let listeners = Arc::new(Mutex::new(Vec::<UdpHolePunchListener>::new()));

        let l = listeners.clone();
        tasks.lock().unwrap().spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                {
                    // remove listener that is not active for 40 seconds but keep listeners that are selected less than 30 seconds
                    l.lock().await.retain(|listener| {
                        listener.last_active_time.load().elapsed().as_secs() < 40
                            || listener.last_select_time.load().elapsed().as_secs() < 30
                    });
                }
            }
        });

        Self {
            peer_mgr,

            listeners,
            tasks,
        }
    }

    pub(crate) async fn add_listener(&self, listener: UdpHolePunchListener) {
        self.listeners.lock().await.push(listener);
    }

    pub(crate) async fn find_listener(&self, addr: &SocketAddr) -> Option<Arc<UdpSocket>> {
        let all_listener_sockets = self.listeners.lock().await;

        let listener = all_listener_sockets
            .iter()
            .find(|listener| listener.mapped_addr == *addr && listener.running.load())?;

        Some(listener.get_socket().await)
    }

    pub(crate) async fn my_udp_nat_type(&self) -> i32 {
        self.peer_mgr
            .get_global_ctx()
            .get_stun_info_collector()
            .get_stun_info()
            .udp_nat_type
    }

    #[async_recursion::async_recursion]
    pub(crate) async fn select_listener(
        &self,
        use_new_listener: bool,
        prefer_port_mapping: bool,
    ) -> Option<(Arc<UdpSocket>, SocketAddr)> {
        let (listener_count, has_reusable_listener, has_port_mapping_listener) = {
            let locked = self.listeners.lock().await;
            (
                locked.len(),
                locked.iter().any(can_reuse_public_listener),
                locked.iter().any(can_reuse_port_mapping_listener),
            )
        };
        let should_create = should_create_public_listener(
            listener_count,
            has_reusable_listener,
            has_port_mapping_listener,
            use_new_listener,
            prefer_port_mapping,
        );

        if should_create {
            tracing::warn!(
                max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                "creating udp hole punching listener"
            );
            match UdpHolePunchListener::new(self.peer_mgr.clone()).await {
                Ok(listener) => self.listeners.lock().await.push(listener),
                Err(err) => {
                    tracing::warn!(?err, "failed to create udp hole punching listener");
                }
            }
        }

        let mut locked = self.listeners.lock().await;
        let listener_count = locked.len();
        let listener_idx = if prefer_port_mapping {
            select_reusable_port_mapping_listener_idx(locked.as_slice())
                .or_else(|| {
                    if should_create && locked.last().is_some_and(can_reuse_public_listener) {
                        Some(locked.len() - 1)
                    } else {
                        None
                    }
                })
                .or_else(|| select_reusable_public_listener_idx(locked.as_slice()))
        } else if should_create {
            locked.len().checked_sub(1)
        } else {
            select_reusable_public_listener_idx(locked.as_slice())
        };

        let Some(listener_idx) = listener_idx else {
            tracing::warn!(
                ?use_new_listener,
                ?prefer_port_mapping,
                listener_count,
                max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                "no available udp hole punching listener with mapped address"
            );
            if should_retry_public_listener_selection(
                use_new_listener,
                listener_count,
                prefer_port_mapping,
                has_port_mapping_listener,
            ) {
                drop(locked);
                return self.select_listener(true, prefer_port_mapping).await;
            }
            return None;
        };

        let listener = &mut locked[listener_idx];
        if !can_reuse_public_listener(listener) {
            tracing::warn!(
                ?use_new_listener,
                ?prefer_port_mapping,
                listener_count,
                max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                "selected udp hole punching listener is not reusable"
            );
            return None;
        }

        Some((listener.get_socket().await, listener.mapped_addr))
    }

    pub(crate) fn get_joinset(&self) -> Arc<std::sync::Mutex<JoinSet<()>>> {
        self.tasks.clone()
    }

    pub(crate) fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.peer_mgr.get_global_ctx()
    }

    pub(crate) fn get_peer_mgr(&self) -> Arc<PeerManager> {
        self.peer_mgr.clone()
    }
}

fn can_reuse_public_listener(listener: &UdpHolePunchListener) -> bool {
    listener.running.load() && !listener.mapped_addr.ip().is_unspecified()
}

fn can_reuse_port_mapping_listener(listener: &UdpHolePunchListener) -> bool {
    can_reuse_public_listener(listener) && listener.has_port_mapping_lease
}

fn select_reusable_public_listener_idx(listeners: &[UdpHolePunchListener]) -> Option<usize> {
    // Reuse the listener that was active most recently.
    listeners
        .iter()
        .enumerate()
        .filter(|(_, listener)| can_reuse_public_listener(listener))
        .max_by_key(|(_, listener)| listener.last_active_time.load())
        .map(|(idx, _)| idx)
}

fn select_reusable_port_mapping_listener_idx(listeners: &[UdpHolePunchListener]) -> Option<usize> {
    listeners
        .iter()
        .enumerate()
        .filter(|(_, listener)| can_reuse_port_mapping_listener(listener))
        .max_by_key(|(_, listener)| listener.last_active_time.load())
        .map(|(idx, _)| idx)
}

fn should_create_public_listener(
    current_listener_count: usize,
    has_reusable_listener: bool,
    has_port_mapping_listener: bool,
    force_new_listener: bool,
    prefer_port_mapping: bool,
) -> bool {
    if current_listener_count >= MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS {
        return false;
    }

    if current_listener_count == 0 {
        return true;
    }

    if force_new_listener {
        return true;
    }

    if prefer_port_mapping && !has_port_mapping_listener {
        return true;
    }

    !has_reusable_listener
}

fn should_retry_public_listener_selection(
    force_new_listener: bool,
    current_listener_count: usize,
    prefer_port_mapping: bool,
    has_port_mapping_listener: bool,
) -> bool {
    if prefer_port_mapping && has_port_mapping_listener {
        return false;
    }

    !force_new_listener && current_listener_count < MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS
}

#[tracing::instrument(err, ret(level=Level::DEBUG))]
pub(crate) async fn send_symmetric_hole_punch_packet(
    ports: &[u16],
    udp: Arc<UdpSocket>,
    transaction_id: u32,
    public_ips: &Vec<Ipv4Addr>,
    port_start_idx: usize,
    max_packets: usize,
) -> Result<usize, Error> {
    tracing::debug!("sending hard symmetric hole punching packet");
    let mut sent_packets = 0;
    let mut cur_port_idx = port_start_idx;
    while sent_packets < max_packets {
        let port = ports[cur_port_idx % ports.len()];
        for pub_ip in public_ips {
            let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, port));
            for _ in 0..3 {
                let packet = new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
                udp.send_to(&packet.into_bytes(), addr).await?;
            }
            sent_packets += 1;
        }
        cur_port_idx = cur_port_idx.wrapping_add(1);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(cur_port_idx % ports.len())
}

async fn check_udp_socket_local_addr(
    global_ctx: ArcGlobalCtx,
    remote_mapped_addr: SocketAddr,
) -> Result<(), Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(remote_mapped_addr).await?;
    if let Ok(local_addr) = socket.local_addr()
        && let Some(err) = easytier_managed_local_addr_error(&global_ctx, local_addr) {
            return Err(anyhow::anyhow!(err).into());
        }

    Ok(())
}

fn easytier_managed_local_addr_error(
    global_ctx: &ArcGlobalCtx,
    local_addr: SocketAddr,
) -> Option<&'static str> {
    // local_addr should not be equal to an EasyTier-managed virtual/public address.
    match local_addr.ip() {
        IpAddr::V4(ip) if global_ctx.get_ipv4().map(|ip| ip.address()) == Some(ip) => {
            Some("local address is virtual ipv4")
        }
        IpAddr::V6(ip) if global_ctx.is_ip_easytier_managed_ipv6(&ip) => {
            Some("local address is easytier-managed ipv6")
        }
        _ => None,
    }
}

pub(crate) async fn try_connect_with_socket(
    global_ctx: ArcGlobalCtx,
    socket: Arc<UdpSocket>,
    remote_mapped_addr: SocketAddr,
) -> Result<Box<dyn Tunnel>, Error> {
    let connector = UdpTunnelConnector::new(
        format!(
            "udp://{}:{}",
            remote_mapped_addr.ip(),
            remote_mapped_addr.port()
        )
        .parse()
        .unwrap(),
    );

    check_udp_socket_local_addr(global_ctx, remote_mapped_addr).await?;

    connector
        .try_connect_with_socket(socket, remote_mapped_addr)
        .await
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddr};

    use crate::common::global_ctx::tests::get_mock_global_ctx;

    use super::{
        MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS, easytier_managed_local_addr_error,
        should_create_public_listener, should_retry_public_listener_selection,
    };

    #[tokio::test]
    async fn local_addr_check_rejects_easytier_public_ipv6_route() {
        let global_ctx = get_mock_global_ctx();
        let public_route: cidr::Ipv6Inet = "2001:db8::4/128".parse().unwrap();
        global_ctx.set_public_ipv6_routes(BTreeSet::from([public_route]));

        let local_addr: SocketAddr = "[2001:db8::4]:1234".parse().unwrap();

        assert_eq!(
            easytier_managed_local_addr_error(&global_ctx, local_addr),
            Some("local address is easytier-managed ipv6")
        );
    }

    #[test]
    fn listener_selection_prefers_reuse_before_cap() {
        assert!(!should_create_public_listener(1, true, true, false, false));
        assert!(!should_create_public_listener(
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            false,
            false
        ));
    }

    #[test]
    fn listener_selection_creates_when_empty_or_no_reusable_listener() {
        assert!(should_create_public_listener(0, false, false, false, false));
        assert!(should_create_public_listener(1, false, false, false, false));
    }

    #[test]
    fn listener_selection_force_new_respects_cap() {
        assert!(should_create_public_listener(1, true, true, true, false));
        assert!(!should_create_public_listener(
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            true,
            false
        ));
    }

    #[test]
    fn listener_selection_prefers_port_mapping_until_available() {
        assert!(should_create_public_listener(1, true, false, false, true));
        assert!(!should_create_public_listener(1, true, true, false, true));
    }

    #[test]
    fn listener_selection_retry_respects_cap() {
        assert!(should_retry_public_listener_selection(
            false, 1, false, false
        ));
        assert!(!should_retry_public_listener_selection(
            false,
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            false,
            false
        ));
        assert!(!should_retry_public_listener_selection(
            true, 1, false, false
        ));
        assert!(!should_retry_public_listener_selection(
            false, 1, true, true
        ));
    }
}
