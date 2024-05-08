use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicU32, Arc},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
use tracing::Instrument;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, stun::StunInfoCollectorTrait, PeerId},
    peers::route_trait::{Route, RouteInterfaceBox},
    rpc::{NatType, StunInfo},
    tunnel::packet_def::{PacketType, ZCPacket},
};

use super::PeerPacketFilter;

const SEND_ROUTE_PERIOD_SEC: u64 = 60;
const SEND_ROUTE_FAST_REPLY_SEC: u64 = 5;
const ROUTE_EXPIRED_SEC: u64 = 70;

type Version = u32;

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
// Derives can be passed through to the generated type:
pub struct SyncPeerInfo {
    // means next hop in route table.
    pub peer_id: PeerId,
    pub cost: u32,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub proxy_cidrs: Vec<String>,
    pub hostname: String,
    pub udp_stun_info: i8,
}

impl SyncPeerInfo {
    pub fn new_self(from_peer: PeerId, global_ctx: &ArcGlobalCtx) -> Self {
        SyncPeerInfo {
            peer_id: from_peer,
            cost: 0,
            ipv4_addr: global_ctx.get_ipv4(),
            proxy_cidrs: global_ctx
                .get_proxy_cidrs()
                .iter()
                .map(|x| x.to_string())
                .chain(global_ctx.get_vpn_portal_cidr().map(|x| x.to_string()))
                .collect(),
            hostname: global_ctx.get_hostname(),
            udp_stun_info: global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .udp_nat_type as i8,
        }
    }

    pub fn clone_for_route_table(&self, next_hop: PeerId, cost: u32, from: &Self) -> Self {
        SyncPeerInfo {
            peer_id: next_hop,
            cost,
            ipv4_addr: from.ipv4_addr.clone(),
            proxy_cidrs: from.proxy_cidrs.clone(),
            hostname: from.hostname.clone(),
            udp_stun_info: from.udp_stun_info,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct SyncPeer {
    pub myself: SyncPeerInfo,
    pub neighbors: Vec<SyncPeerInfo>,
    // the route table version of myself
    pub version: Version,
    // the route table version of peer that we have received last time
    pub peer_version: Option<Version>,
    // if we do not have latest peer version, need_reply is true
    pub need_reply: bool,
}

impl SyncPeer {
    pub fn new(
        from_peer: PeerId,
        _to_peer: PeerId,
        neighbors: Vec<SyncPeerInfo>,
        global_ctx: ArcGlobalCtx,
        version: Version,
        peer_version: Option<Version>,
        need_reply: bool,
    ) -> Self {
        SyncPeer {
            myself: SyncPeerInfo::new_self(from_peer, &global_ctx),
            neighbors,
            version,
            peer_version,
            need_reply,
        }
    }
}

#[derive(Debug)]
struct SyncPeerFromRemote {
    packet: SyncPeer,
    last_update: std::time::Instant,
}

type SyncPeerFromRemoteMap = Arc<DashMap<PeerId, SyncPeerFromRemote>>;

#[derive(Debug)]
struct RouteTable {
    route_info: DashMap<PeerId, SyncPeerInfo>,
    ipv4_peer_id_map: DashMap<Ipv4Addr, PeerId>,
    cidr_peer_id_map: DashMap<cidr::IpCidr, PeerId>,
}

impl RouteTable {
    fn new() -> Self {
        RouteTable {
            route_info: DashMap::new(),
            ipv4_peer_id_map: DashMap::new(),
            cidr_peer_id_map: DashMap::new(),
        }
    }

    fn copy_from(&self, other: &Self) {
        self.route_info.clear();
        for item in other.route_info.iter() {
            let (k, v) = item.pair();
            self.route_info.insert(*k, v.clone());
        }

        self.ipv4_peer_id_map.clear();
        for item in other.ipv4_peer_id_map.iter() {
            let (k, v) = item.pair();
            self.ipv4_peer_id_map.insert(*k, *v);
        }

        self.cidr_peer_id_map.clear();
        for item in other.cidr_peer_id_map.iter() {
            let (k, v) = item.pair();
            self.cidr_peer_id_map.insert(*k, *v);
        }
    }
}

#[derive(Debug, Clone)]
struct RouteVersion(Arc<AtomicU32>);

impl RouteVersion {
    fn new() -> Self {
        // RouteVersion(Arc::new(AtomicU32::new(rand::random())))
        RouteVersion(Arc::new(AtomicU32::new(0)))
    }

    fn get(&self) -> Version {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn inc(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub struct BasicRoute {
    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,
    interface: Arc<Mutex<Option<RouteInterfaceBox>>>,

    route_table: Arc<RouteTable>,

    sync_peer_from_remote: SyncPeerFromRemoteMap,

    tasks: Mutex<JoinSet<()>>,

    need_sync_notifier: Arc<tokio::sync::Notify>,

    version: RouteVersion,
    myself: Arc<RwLock<SyncPeerInfo>>,
    last_send_time_map: Arc<DashMap<PeerId, (Version, Option<Version>, Instant)>>,
}

impl BasicRoute {
    pub fn new(my_peer_id: PeerId, global_ctx: ArcGlobalCtx) -> Self {
        BasicRoute {
            my_peer_id,
            global_ctx: global_ctx.clone(),
            interface: Arc::new(Mutex::new(None)),

            route_table: Arc::new(RouteTable::new()),

            sync_peer_from_remote: Arc::new(DashMap::new()),
            tasks: Mutex::new(JoinSet::new()),

            need_sync_notifier: Arc::new(tokio::sync::Notify::new()),

            version: RouteVersion::new(),
            myself: Arc::new(RwLock::new(SyncPeerInfo::new_self(
                my_peer_id.into(),
                &global_ctx,
            ))),
            last_send_time_map: Arc::new(DashMap::new()),
        }
    }

    fn update_route_table(
        my_id: PeerId,
        sync_peer_reqs: SyncPeerFromRemoteMap,
        route_table: Arc<RouteTable>,
    ) {
        tracing::trace!(my_id = ?my_id, route_table = ?route_table, "update route table");

        let new_route_table = Arc::new(RouteTable::new());
        for item in sync_peer_reqs.iter() {
            Self::update_route_table_with_req(my_id, &item.value().packet, new_route_table.clone());
        }

        route_table.copy_from(&new_route_table);
    }

    async fn update_myself(
        my_peer_id: PeerId,
        myself: &Arc<RwLock<SyncPeerInfo>>,
        global_ctx: &ArcGlobalCtx,
    ) -> bool {
        let new_myself = SyncPeerInfo::new_self(my_peer_id, &global_ctx);
        if *myself.read().await != new_myself {
            *myself.write().await = new_myself;
            true
        } else {
            false
        }
    }

    fn update_route_table_with_req(my_id: PeerId, packet: &SyncPeer, route_table: Arc<RouteTable>) {
        let peer_id = packet.myself.peer_id.clone();
        let update = |cost: u32, peer_info: &SyncPeerInfo| {
            let node_id: PeerId = peer_info.peer_id.into();
            let ret = route_table
                .route_info
                .entry(node_id.clone().into())
                .and_modify(|info| {
                    if info.cost > cost {
                        *info = info.clone_for_route_table(peer_id, cost, &peer_info);
                    }
                })
                .or_insert(
                    peer_info
                        .clone()
                        .clone_for_route_table(peer_id, cost, &peer_info),
                )
                .value()
                .clone();

            if ret.cost > 6 {
                log::error!(
                    "cost too large: {}, may lost connection, remove it",
                    ret.cost
                );
                route_table.route_info.remove(&node_id);
            }

            log::trace!(
                "update route info, to: {:?}, gateway: {:?}, cost: {}, peer: {:?}",
                node_id,
                peer_id,
                cost,
                &peer_info
            );

            if let Some(ipv4) = peer_info.ipv4_addr {
                route_table
                    .ipv4_peer_id_map
                    .insert(ipv4.clone(), node_id.clone().into());
            }

            for cidr in peer_info.proxy_cidrs.iter() {
                let cidr: cidr::IpCidr = cidr.parse().unwrap();
                route_table
                    .cidr_peer_id_map
                    .insert(cidr, node_id.clone().into());
            }
        };

        for neighbor in packet.neighbors.iter() {
            if neighbor.peer_id == my_id {
                continue;
            }
            update(neighbor.cost + 1, &neighbor);
            log::trace!("route info: {:?}", neighbor);
        }

        // add the sender peer to route info
        update(1, &packet.myself);

        log::trace!("my_id: {:?}, current route table: {:?}", my_id, route_table);
    }

    async fn send_sync_peer_request(
        interface: &RouteInterfaceBox,
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        peer_id: PeerId,
        route_table: Arc<RouteTable>,
        my_version: Version,
        peer_version: Option<Version>,
        need_reply: bool,
    ) -> Result<(), Error> {
        let mut route_info_copy: Vec<SyncPeerInfo> = Vec::new();
        // copy the route info
        for item in route_table.route_info.iter() {
            let (k, v) = item.pair();
            route_info_copy.push(v.clone().clone_for_route_table(*k, v.cost, &v));
        }
        let msg = SyncPeer::new(
            my_peer_id,
            peer_id,
            route_info_copy,
            global_ctx,
            my_version,
            peer_version,
            need_reply,
        );
        // TODO: this may exceed the MTU of the tunnel
        interface
            .send_route_packet(postcard::to_allocvec(&msg).unwrap().into(), 1, peer_id)
            .await
    }

    async fn sync_peer_periodically(&self) {
        let route_table = self.route_table.clone();
        let global_ctx = self.global_ctx.clone();
        let my_peer_id = self.my_peer_id.clone();
        let interface = self.interface.clone();
        let notifier = self.need_sync_notifier.clone();
        let sync_peer_from_remote = self.sync_peer_from_remote.clone();
        let myself = self.myself.clone();
        let version = self.version.clone();
        let last_send_time_map = self.last_send_time_map.clone();
        self.tasks.lock().await.spawn(
            async move {
                loop {
                    if Self::update_myself(my_peer_id,&myself, &global_ctx).await {
                        version.inc();
                        tracing::info!(
                            my_id = ?my_peer_id,
                            version = version.get(),
                            "update route table version when myself changed"
                        );
                    }

                    let lockd_interface = interface.lock().await;
                    let interface = lockd_interface.as_ref().unwrap();
                    let last_send_time_map_new = DashMap::new();
                    let peers = interface.list_peers().await;
                    for peer in peers.iter() {
                        let last_send_time = last_send_time_map.get(peer).map(|v| *v).unwrap_or((0, None, Instant::now() - Duration::from_secs(3600)));
                        let my_version_peer_saved = sync_peer_from_remote.get(peer).and_then(|v| v.packet.peer_version);
                        let peer_have_latest_version = my_version_peer_saved == Some(version.get());
                        if peer_have_latest_version && last_send_time.2.elapsed().as_secs() < SEND_ROUTE_PERIOD_SEC {
                            last_send_time_map_new.insert(*peer, last_send_time);
                            continue;
                        }

                        tracing::trace!(
                            my_id = ?my_peer_id,
                            dst_peer_id = ?peer,
                            version = version.get(),
                            ?my_version_peer_saved,
                            last_send_version = ?last_send_time.0,
                            last_send_peer_version = ?last_send_time.1,
                            last_send_elapse = ?last_send_time.2.elapsed().as_secs(),
                            "need send route info"
                        );
                        let peer_version_we_saved = sync_peer_from_remote.get(&peer).and_then(|v| Some(v.packet.version));
                        last_send_time_map_new.insert(*peer, (version.get(), peer_version_we_saved, Instant::now()));
                        let ret = Self::send_sync_peer_request(
                            interface,
                            my_peer_id.clone(),
                            global_ctx.clone(),
                            *peer,
                            route_table.clone(),
                            version.get(),
                            peer_version_we_saved,
                            !peer_have_latest_version,
                        )
                        .await;

                        match &ret {
                            Ok(_) => {
                                log::trace!("send sync peer request to peer: {}", peer);
                            }
                            Err(Error::PeerNoConnectionError(_)) => {
                                log::trace!("peer {} no connection", peer);
                            }
                            Err(e) => {
                                log::error!(
                                    "send sync peer request to peer: {} error: {:?}",
                                    peer,
                                    e
                                );
                            }
                        };
                    }

                    last_send_time_map.clear();
                    for item in last_send_time_map_new.iter() {
                        let (k, v) = item.pair();
                        last_send_time_map.insert(*k, *v);
                    }

                    tokio::select! {
                        _ = notifier.notified() => {
                            log::trace!("sync peer request triggered by notifier");
                        }
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {
                            log::trace!("sync peer request triggered by timeout");
                        }
                    }
                }
            }
            .instrument(
                tracing::info_span!("sync_peer_periodically", my_id = ?self.my_peer_id, global_ctx = ?self.global_ctx),
            ),
        );
    }

    async fn check_expired_sync_peer_from_remote(&self) {
        let route_table = self.route_table.clone();
        let my_peer_id = self.my_peer_id.clone();
        let sync_peer_from_remote = self.sync_peer_from_remote.clone();
        let notifier = self.need_sync_notifier.clone();
        let interface = self.interface.clone();
        let version = self.version.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                let mut need_update_route = false;
                let now = std::time::Instant::now();
                let mut need_remove = Vec::new();
                let connected_peers = interface.lock().await.as_ref().unwrap().list_peers().await;
                for item in sync_peer_from_remote.iter() {
                    let (k, v) = item.pair();
                    if now.duration_since(v.last_update).as_secs() > ROUTE_EXPIRED_SEC
                        || !connected_peers.contains(k)
                    {
                        need_update_route = true;
                        need_remove.insert(0, k.clone());
                    }
                }

                for k in need_remove.iter() {
                    log::warn!("remove expired sync peer: {:?}", k);
                    sync_peer_from_remote.remove(k);
                }

                if need_update_route {
                    Self::update_route_table(
                        my_peer_id,
                        sync_peer_from_remote.clone(),
                        route_table.clone(),
                    );
                    version.inc();
                    tracing::info!(
                        my_id = ?my_peer_id,
                        version = version.get(),
                        "update route table when check expired peer"
                    );
                    notifier.notify_one();
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    fn get_peer_id_for_proxy(&self, ipv4: &Ipv4Addr) -> Option<PeerId> {
        let ipv4 = std::net::IpAddr::V4(*ipv4);
        for item in self.route_table.cidr_peer_id_map.iter() {
            let (k, v) = item.pair();
            if k.contains(&ipv4) {
                return Some(*v);
            }
        }
        None
    }

    #[tracing::instrument(skip(self, packet), fields(my_id = ?self.my_peer_id, ctx = ?self.global_ctx))]
    async fn handle_route_packet(&self, src_peer_id: PeerId, packet: Bytes) {
        let packet = postcard::from_bytes::<SyncPeer>(&packet).unwrap();
        let p = &packet;
        let mut updated = true;
        assert_eq!(packet.myself.peer_id, src_peer_id);
        self.sync_peer_from_remote
            .entry(packet.myself.peer_id.into())
            .and_modify(|v| {
                if v.packet.myself == p.myself && v.packet.neighbors == p.neighbors {
                    updated = false;
                } else {
                    v.packet = p.clone();
                }
                v.packet.version = p.version;
                v.packet.peer_version = p.peer_version;
                v.last_update = std::time::Instant::now();
            })
            .or_insert(SyncPeerFromRemote {
                packet: p.clone(),
                last_update: std::time::Instant::now(),
            });

        if updated {
            Self::update_route_table(
                self.my_peer_id.clone(),
                self.sync_peer_from_remote.clone(),
                self.route_table.clone(),
            );
            self.version.inc();
            tracing::info!(
                my_id = ?self.my_peer_id,
                ?p,
                version = self.version.get(),
                "update route table when receive route packet"
            );
        }

        if packet.need_reply {
            self.last_send_time_map
                .entry(packet.myself.peer_id.into())
                .and_modify(|v| {
                    const FAST_REPLY_DURATION: u64 =
                        SEND_ROUTE_PERIOD_SEC - SEND_ROUTE_FAST_REPLY_SEC;
                    if v.0 != self.version.get() || v.1 != Some(p.version) {
                        v.2 = Instant::now() - Duration::from_secs(3600);
                    } else if v.2.elapsed().as_secs() < FAST_REPLY_DURATION {
                        // do not send same version route info too frequently
                        v.2 = Instant::now() - Duration::from_secs(FAST_REPLY_DURATION);
                    }
                });
        }

        if updated || packet.need_reply {
            self.need_sync_notifier.notify_one();
        }
    }
}

#[async_trait]
impl Route for BasicRoute {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()> {
        *self.interface.lock().await = Some(interface);
        self.sync_peer_periodically().await;
        self.check_expired_sync_peer_from_remote().await;
        Ok(1)
    }

    async fn close(&self) {}

    async fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<PeerId> {
        match self.route_table.route_info.get(&dst_peer_id) {
            Some(info) => {
                return Some(info.peer_id.clone().into());
            }
            None => {
                log::error!("no route info for dst_peer_id: {}", dst_peer_id);
                return None;
            }
        }
    }

    async fn list_routes(&self) -> Vec<crate::rpc::Route> {
        let mut routes = Vec::new();

        let parse_route_info = |real_peer_id: PeerId, route_info: &SyncPeerInfo| {
            let mut route = crate::rpc::Route::default();
            route.ipv4_addr = if let Some(ipv4_addr) = route_info.ipv4_addr {
                ipv4_addr.to_string()
            } else {
                "".to_string()
            };
            route.peer_id = real_peer_id;
            route.next_hop_peer_id = route_info.peer_id;
            route.cost = route_info.cost as i32;
            route.proxy_cidrs = route_info.proxy_cidrs.clone();
            route.hostname = route_info.hostname.clone();

            let mut stun_info = StunInfo::default();
            if let Ok(udp_nat_type) = NatType::try_from(route_info.udp_stun_info as i32) {
                stun_info.set_udp_nat_type(udp_nat_type);
            }
            route.stun_info = Some(stun_info);

            route
        };

        self.route_table.route_info.iter().for_each(|item| {
            routes.push(parse_route_info(*item.key(), item.value()));
        });

        routes
    }

    async fn get_peer_id_by_ipv4(&self, ipv4_addr: &Ipv4Addr) -> Option<PeerId> {
        if let Some(peer_id) = self.route_table.ipv4_peer_id_map.get(ipv4_addr) {
            return Some(*peer_id);
        }

        if let Some(peer_id) = self.get_peer_id_for_proxy(ipv4_addr) {
            return Some(peer_id);
        }

        log::info!("no peer id for ipv4: {}", ipv4_addr);
        return None;
    }
}

#[async_trait::async_trait]
impl PeerPacketFilter for BasicRoute {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let hdr = packet.peer_manager_header().unwrap();
        if hdr.packet_type == PacketType::Route as u8 {
            let b = packet.payload().to_vec();
            self.handle_route_packet(hdr.from_peer_id.get(), b.into())
                .await;
            None
        } else {
            Some(packet)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        common::{global_ctx::tests::get_mock_global_ctx, PeerId},
        connector::udp_hole_punch::tests::replace_stun_info_collector,
        peers::{
            peer_manager::{PeerManager, RouteAlgoType},
            peer_rip_route::Version,
            tests::{connect_peer_manager, wait_route_appear},
        },
        rpc::NatType,
    };

    async fn create_mock_pmgr() -> Arc<PeerManager> {
        let (s, _r) = tokio::sync::mpsc::channel(1000);
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::Rip,
            get_mock_global_ctx(),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.run().await.unwrap();
        peer_mgr
    }

    #[tokio::test]
    async fn test_rip_route() {
        let peer_mgr_a = create_mock_pmgr().await;
        let peer_mgr_b = create_mock_pmgr().await;
        let peer_mgr_c = create_mock_pmgr().await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let mgrs = vec![peer_mgr_a.clone(), peer_mgr_b.clone(), peer_mgr_c.clone()];

        tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;

        let check_version = |version: Version, peer_id: PeerId, mgrs: &Vec<Arc<PeerManager>>| {
            for mgr in mgrs.iter() {
                tracing::warn!(
                    "check version: {:?}, {:?}, {:?}, {:?}",
                    version,
                    peer_id,
                    mgr,
                    mgr.get_basic_route().sync_peer_from_remote
                );
                assert_eq!(
                    version,
                    mgr.get_basic_route()
                        .sync_peer_from_remote
                        .get(&peer_id)
                        .unwrap()
                        .packet
                        .version,
                );
                assert_eq!(
                    mgr.get_basic_route()
                        .sync_peer_from_remote
                        .get(&peer_id)
                        .unwrap()
                        .packet
                        .peer_version
                        .unwrap(),
                    mgr.get_basic_route().version.get()
                );
            }
        };

        let check_sanity = || {
            // check peer version in other peer mgr are correct.
            check_version(
                peer_mgr_b.get_basic_route().version.get(),
                peer_mgr_b.my_peer_id(),
                &vec![peer_mgr_a.clone(), peer_mgr_c.clone()],
            );

            check_version(
                peer_mgr_a.get_basic_route().version.get(),
                peer_mgr_a.my_peer_id(),
                &vec![peer_mgr_b.clone()],
            );

            check_version(
                peer_mgr_c.get_basic_route().version.get(),
                peer_mgr_c.my_peer_id(),
                &vec![peer_mgr_b.clone()],
            );
        };

        check_sanity();

        let versions = mgrs
            .iter()
            .map(|x| x.get_basic_route().version.get())
            .collect::<Vec<_>>();

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let versions2 = mgrs
            .iter()
            .map(|x| x.get_basic_route().version.get())
            .collect::<Vec<_>>();

        assert_eq!(versions, versions2);
        check_sanity();

        assert!(peer_mgr_a.get_basic_route().version.get() <= 3);
        assert!(peer_mgr_b.get_basic_route().version.get() <= 6);
        assert!(peer_mgr_c.get_basic_route().version.get() <= 3);
    }
}
