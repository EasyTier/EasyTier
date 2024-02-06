use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
use easytier_rpc::{NatType, StunInfo};
use rkyv::{Archive, Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::bytes::Bytes;
use tracing::Instrument;
use uuid::Uuid;

use crate::{
    common::{
        error::Error,
        global_ctx::ArcGlobalCtx,
        rkyv_util::{decode_from_bytes, encode_to_bytes, extract_bytes_from_archived_vec},
        stun::StunInfoCollectorTrait,
    },
    peers::{
        packet::{self, UUID},
        route_trait::{Route, RouteInterfaceBox},
        PeerId,
    },
};

use super::{packet::ArchivedPacketBody, peer_manager::PeerPacketFilter};

#[derive(Archive, Deserialize, Serialize, Clone, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub struct SyncPeerInfo {
    // means next hop in route table.
    pub peer_id: UUID,
    pub cost: u32,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub proxy_cidrs: Vec<String>,
    pub hostname: Option<String>,
    pub udp_stun_info: i8,
}

impl SyncPeerInfo {
    pub fn new_self(from_peer: UUID, global_ctx: &ArcGlobalCtx) -> Self {
        SyncPeerInfo {
            peer_id: from_peer,
            cost: 0,
            ipv4_addr: global_ctx.get_ipv4(),
            proxy_cidrs: global_ctx
                .get_proxy_cidrs()
                .iter()
                .map(|x| x.to_string())
                .collect(),
            hostname: global_ctx.get_hostname(),
            udp_stun_info: global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .udp_nat_type as i8,
        }
    }

    pub fn clone_for_route_table(&self, next_hop: &UUID, cost: u32, from: &Self) -> Self {
        SyncPeerInfo {
            peer_id: next_hop.clone(),
            cost,
            ipv4_addr: from.ipv4_addr.clone(),
            proxy_cidrs: from.proxy_cidrs.clone(),
            hostname: from.hostname.clone(),
            udp_stun_info: from.udp_stun_info,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Clone, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub struct SyncPeer {
    pub myself: SyncPeerInfo,
    pub neighbors: Vec<SyncPeerInfo>,
}

impl SyncPeer {
    pub fn new(
        from_peer: UUID,
        _to_peer: UUID,
        neighbors: Vec<SyncPeerInfo>,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        SyncPeer {
            myself: SyncPeerInfo::new_self(from_peer, &global_ctx),
            neighbors,
        }
    }
}

struct SyncPeerFromRemote {
    packet: SyncPeer,
    last_update: std::time::Instant,
}

type SyncPeerFromRemoteMap = Arc<DashMap<uuid::Uuid, SyncPeerFromRemote>>;

#[derive(Clone, Debug)]
struct RouteTable {
    route_info: DashMap<uuid::Uuid, SyncPeerInfo>,
    ipv4_peer_id_map: DashMap<Ipv4Addr, uuid::Uuid>,
    cidr_peer_id_map: DashMap<cidr::IpCidr, uuid::Uuid>,
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

pub struct BasicRoute {
    my_peer_id: packet::UUID,
    global_ctx: ArcGlobalCtx,
    interface: Arc<Mutex<Option<RouteInterfaceBox>>>,

    route_table: Arc<RouteTable>,

    sync_peer_from_remote: SyncPeerFromRemoteMap,

    tasks: Mutex<JoinSet<()>>,

    need_sync_notifier: Arc<tokio::sync::Notify>,
}

impl BasicRoute {
    pub fn new(my_peer_id: Uuid, global_ctx: ArcGlobalCtx) -> Self {
        BasicRoute {
            my_peer_id: my_peer_id.into(),
            global_ctx,
            interface: Arc::new(Mutex::new(None)),

            route_table: Arc::new(RouteTable::new()),

            sync_peer_from_remote: Arc::new(DashMap::new()),
            tasks: Mutex::new(JoinSet::new()),

            need_sync_notifier: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn update_route_table(
        my_id: packet::UUID,
        sync_peer_reqs: SyncPeerFromRemoteMap,
        route_table: Arc<RouteTable>,
    ) {
        tracing::trace!(my_id = ?my_id, route_table = ?route_table, "update route table");

        let new_route_table = Arc::new(RouteTable::new());
        for item in sync_peer_reqs.iter() {
            Self::update_route_table_with_req(
                my_id.clone(),
                &item.value().packet,
                new_route_table.clone(),
            );
        }

        route_table.copy_from(&new_route_table);
    }

    fn update_route_table_with_req(
        my_id: packet::UUID,
        packet: &SyncPeer,
        route_table: Arc<RouteTable>,
    ) {
        let peer_id = packet.myself.peer_id.clone();
        let update = |cost: u32, peer_info: &SyncPeerInfo| {
            let node_id: uuid::Uuid = peer_info.peer_id.clone().into();
            let ret = route_table
                .route_info
                .entry(node_id.clone().into())
                .and_modify(|info| {
                    if info.cost > cost {
                        *info = info.clone_for_route_table(&peer_id, cost, &peer_info);
                    }
                })
                .or_insert(
                    peer_info
                        .clone()
                        .clone_for_route_table(&peer_id, cost, &peer_info),
                )
                .value()
                .clone();

            if ret.cost > 32 {
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
        my_peer_id: packet::UUID,
        global_ctx: ArcGlobalCtx,
        peer_id: PeerId,
        route_table: Arc<RouteTable>,
    ) -> Result<(), Error> {
        let mut route_info_copy: Vec<SyncPeerInfo> = Vec::new();
        // copy the route info
        for item in route_table.route_info.iter() {
            let (k, v) = item.pair();
            route_info_copy.push(v.clone().clone_for_route_table(&(*k).into(), v.cost, &v));
        }
        let msg = SyncPeer::new(my_peer_id, peer_id.into(), route_info_copy, global_ctx);
        // TODO: this may exceed the MTU of the tunnel
        interface
            .send_route_packet(encode_to_bytes::<_, 4096>(&msg), 1, &peer_id)
            .await
    }

    async fn sync_peer_periodically(&self) {
        let route_table = self.route_table.clone();
        let global_ctx = self.global_ctx.clone();
        let my_peer_id = self.my_peer_id.clone();
        let interface = self.interface.clone();
        let notifier = self.need_sync_notifier.clone();
        self.tasks.lock().await.spawn(
            async move {
                loop {
                    let lockd_interface = interface.lock().await;
                    let interface = lockd_interface.as_ref().unwrap();
                    let peers = interface.list_peers().await;
                    for peer in peers.iter() {
                        let ret = Self::send_sync_peer_request(
                            interface,
                            my_peer_id.clone(),
                            global_ctx.clone(),
                            *peer,
                            route_table.clone(),
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
        self.tasks.lock().await.spawn(async move {
            loop {
                let mut need_update_route = false;
                let now = std::time::Instant::now();
                let mut need_remove = Vec::new();
                for item in sync_peer_from_remote.iter() {
                    let (k, v) = item.pair();
                    if now.duration_since(v.last_update).as_secs() > 5 {
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
                        my_peer_id.clone(),
                        sync_peer_from_remote.clone(),
                        route_table.clone(),
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
    async fn handle_route_packet(&self, src_peer_id: uuid::Uuid, packet: Bytes) {
        let packet = decode_from_bytes::<SyncPeer>(&packet).unwrap();
        let p: SyncPeer = packet.deserialize(&mut rkyv::Infallible).unwrap();
        let mut updated = true;
        assert_eq!(packet.myself.peer_id.to_uuid(), src_peer_id);
        self.sync_peer_from_remote
            .entry(packet.myself.peer_id.to_uuid())
            .and_modify(|v| {
                if v.packet == *packet {
                    updated = false;
                } else {
                    v.packet = p.clone();
                }
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

    async fn get_next_hop(&self, dst_peer_id: &PeerId) -> Option<PeerId> {
        match self.route_table.route_info.get(dst_peer_id) {
            Some(info) => {
                return Some(info.peer_id.clone().into());
            }
            None => {
                log::error!("no route info for dst_peer_id: {}", dst_peer_id);
                return None;
            }
        }
    }

    async fn list_routes(&self) -> Vec<easytier_rpc::Route> {
        let mut routes = Vec::new();

        let parse_route_info = |real_peer_id: &Uuid, route_info: &SyncPeerInfo| {
            let mut route = easytier_rpc::Route::default();
            route.ipv4_addr = if let Some(ipv4_addr) = route_info.ipv4_addr {
                ipv4_addr.to_string()
            } else {
                "".to_string()
            };
            route.peer_id = real_peer_id.to_string();
            route.next_hop_peer_id = Uuid::from(route_info.peer_id.clone()).to_string();
            route.cost = route_info.cost as i32;
            route.proxy_cidrs = route_info.proxy_cidrs.clone();
            route.hostname = if let Some(hostname) = &route_info.hostname {
                hostname.clone()
            } else {
                "".to_string()
            };

            let mut stun_info = StunInfo::default();
            if let Ok(udp_nat_type) = NatType::try_from(route_info.udp_stun_info as i32) {
                stun_info.set_udp_nat_type(udp_nat_type);
            }
            route.stun_info = Some(stun_info);

            route
        };

        self.route_table.route_info.iter().for_each(|item| {
            routes.push(parse_route_info(item.key(), item.value()));
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
    async fn try_process_packet_from_peer(
        &self,
        packet: &packet::ArchivedPacket,
        data: &Bytes,
    ) -> Option<()> {
        if let ArchivedPacketBody::Ctrl(packet::ArchivedCtrlPacketBody::RoutePacket(route_packet)) =
            &packet.body
        {
            self.handle_route_packet(
                packet.from_peer.to_uuid(),
                extract_bytes_from_archived_vec(&data, &route_packet.body),
            )
            .await;
            Some(())
        } else {
            None
        }
    }
}
