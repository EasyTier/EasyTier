use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use crossbeam::atomic::AtomicCell;
use easytier_core::hole_punch::udp::{self as core_udp_hole_punch, ReusableUdpPunchListener};
use quanta::Instant;
use rand::seq::SliceRandom as _;
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};
use tracing::{Level, instrument};

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, join_joinset_background, netns::NetNS, upnp},
    peers::peer_manager::PeerManager,
    tunnel::{
        Tunnel, TunnelConnCounter, TunnelListener as _,
        udp::{UdpTunnelConnector, UdpTunnelListener, new_hole_punch_packet},
    },
};

pub(crate) use easytier_core::hole_punch::udp::{
    HOLE_PUNCH_PACKET_BODY_LEN, MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS, UdpNatType,
    UdpPunchClientMethod,
};

fn generate_shuffled_port_vec() -> Vec<u16> {
    let mut rng = rand::thread_rng();
    let mut port_vec: Vec<u16> = (1..=65535).collect();
    port_vec.shuffle(&mut rng);
    port_vec
}

#[derive(Debug)]
pub(crate) struct PunchedUdpSocket {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) tid: u32,
    pub(crate) remote_addr: SocketAddr,
}

struct RuntimeUdpPunchSocket {
    socket: Arc<UdpSocket>,
}

impl RuntimeUdpPunchSocket {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }
}

#[async_trait]
impl core_udp_hole_punch::UdpPunchSocket for RuntimeUdpPunchSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

struct RuntimeUdpPunchSocketFactory {
    net_ns: NetNS,
}

#[async_trait]
impl core_udp_hole_punch::UdpPunchSocketFactory for RuntimeUdpPunchSocketFactory {
    type Socket = RuntimeUdpPunchSocket;

    async fn bind_udp(&self, port: Option<u16>) -> anyhow::Result<Arc<Self::Socket>> {
        let socket = {
            let _g = self.net_ns.guard();
            Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port.unwrap_or(0))).await?)
        };

        Ok(Arc::new(RuntimeUdpPunchSocket::new(socket)))
    }
}

// used for symmetric hole punching, binding to multiple ports to increase the chance of success
pub(crate) struct UdpSocketArray {
    inner: core_udp_hole_punch::UdpSocketArray<RuntimeUdpPunchSocketFactory>,
}

impl UdpSocketArray {
    pub fn new(max_socket_count: usize, net_ns: NetNS) -> Self {
        let runtime = Arc::new(RuntimeUdpPunchSocketFactory { net_ns });
        Self {
            inner: core_udp_hole_punch::UdpSocketArray::new(max_socket_count, runtime),
        }
    }

    pub fn started(&self) -> bool {
        self.inner.started()
    }

    pub async fn add_new_socket(&self, socket: Arc<UdpSocket>) -> Result<(), anyhow::Error> {
        self.inner
            .add_new_socket(Arc::new(RuntimeUdpPunchSocket::new(socket)))
            .await
    }

    #[instrument(err)]
    pub async fn start(&self) -> Result<(), anyhow::Error> {
        self.inner.start().await
    }

    #[instrument(err)]
    pub async fn send_with_all(&self, data: &[u8], addr: SocketAddr) -> Result<(), anyhow::Error> {
        self.inner.send_with_all(data, addr).await
    }

    pub fn try_fetch_punched_socket(&self, tid: u32) -> Option<PunchedUdpSocket> {
        self.inner
            .try_fetch_punched_socket(tid)
            .map(|socket| PunchedUdpSocket {
                socket: socket.socket.socket.clone(),
                tid: socket.tid,
                remote_addr: socket.remote_addr,
            })
    }

    pub fn add_intreast_tid(&self, tid: u32) {
        self.inner.add_intreast_tid(tid);
    }

    pub fn remove_intreast_tid(&self, tid: u32) {
        self.inner.remove_intreast_tid(tid);
    }
}

impl std::fmt::Debug for UdpSocketArray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
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

    listen_time: Instant,
    last_select_time: AtomicCell<Instant>,
    last_active_time: Arc<AtomicCell<Instant>>,
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

        let last_active_time = Arc::new(AtomicCell::new(Instant::now()));
        let conn_counter_clone = conn_counter.clone();
        let last_active_time_clone = last_active_time.clone();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if conn_counter_clone.get().unwrap_or(0) != 0 {
                    last_active_time_clone.store(Instant::now());
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

            listen_time: Instant::now(),
            last_select_time: AtomicCell::new(Instant::now()),
            last_active_time,
        })
    }

    pub async fn get_socket(&self) -> Arc<UdpSocket> {
        self.last_select_time.store(Instant::now());
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
    core_udp_hole_punch::can_reuse_public_listener(&listener_reuse_state(listener))
}

fn can_reuse_port_mapping_listener(listener: &UdpHolePunchListener) -> bool {
    core_udp_hole_punch::can_reuse_port_mapping_listener(&listener_reuse_state(listener))
}

fn select_reusable_public_listener_idx(listeners: &[UdpHolePunchListener]) -> Option<usize> {
    let states = listener_reuse_states(listeners);
    core_udp_hole_punch::select_reusable_public_listener_idx(&states)
}

fn select_reusable_port_mapping_listener_idx(listeners: &[UdpHolePunchListener]) -> Option<usize> {
    let states = listener_reuse_states(listeners);
    core_udp_hole_punch::select_reusable_port_mapping_listener_idx(&states)
}

fn should_create_public_listener(
    current_listener_count: usize,
    has_reusable_listener: bool,
    has_port_mapping_listener: bool,
    force_new_listener: bool,
    prefer_port_mapping: bool,
) -> bool {
    core_udp_hole_punch::should_create_public_listener(
        current_listener_count,
        has_reusable_listener,
        has_port_mapping_listener,
        force_new_listener,
        prefer_port_mapping,
    )
}

fn should_retry_public_listener_selection(
    force_new_listener: bool,
    current_listener_count: usize,
    prefer_port_mapping: bool,
    has_port_mapping_listener: bool,
) -> bool {
    core_udp_hole_punch::should_retry_public_listener_selection(
        force_new_listener,
        current_listener_count,
        prefer_port_mapping,
        has_port_mapping_listener,
    )
}

fn listener_reuse_state(listener: &UdpHolePunchListener) -> ReusableUdpPunchListener {
    ReusableUdpPunchListener {
        running: listener.running.load(),
        mapped_addr: listener.mapped_addr,
        has_port_mapping_lease: listener.has_port_mapping_lease,
        last_active_time: listener.last_active_time.load(),
    }
}

fn listener_reuse_states(listeners: &[UdpHolePunchListener]) -> Vec<ReusableUdpPunchListener> {
    listeners.iter().map(listener_reuse_state).collect()
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
        && let Some(err) = easytier_managed_local_addr_error(&global_ctx, local_addr)
    {
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
