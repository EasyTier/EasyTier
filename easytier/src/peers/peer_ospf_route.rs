use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Weak,
    },
    time::{Duration, Instant, SystemTime},
};

use arc_swap::ArcSwap;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use ordered_hash_map::OrderedHashMap;
use parking_lot::{lock_api::RwLockUpgradableReadGuard, RwLock};
use petgraph::{
    algo::dijkstra,
    graph::{Graph, NodeIndex},
    visit::{EdgeRef, IntoNodeReferences},
    Directed,
};
use prefix_trie::PrefixMap;
use prost::Message;
use prost_reflect::{DynamicMessage, ReflectMessage};
use tokio::{
    select,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};

use crate::{
    common::{
        config::NetworkIdentity, constants::EASYTIER_VERSION, global_ctx::ArcGlobalCtx,
        shrink_dashmap, stun::StunInfoCollectorTrait, PeerId,
    },
    peers::route_trait::{Route, RouteInterfaceBox},
    proto::{
        acl::GroupIdentity,
        common::{Ipv4Inet, NatType, StunInfo},
        peer_rpc::{
            route_foreign_network_infos, route_foreign_network_summary,
            sync_route_info_request::ConnInfo, ForeignNetworkRouteInfoEntry,
            ForeignNetworkRouteInfoKey, OspfRouteRpc, OspfRouteRpcClientFactory,
            OspfRouteRpcServer, PeerGroupInfo, PeerIdVersion, RouteForeignNetworkInfos,
            RouteForeignNetworkSummary, RoutePeerInfo, RoutePeerInfos, SyncRouteInfoError,
            SyncRouteInfoRequest, SyncRouteInfoResponse,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
    use_global_var,
};

use super::{
    graph_algo::dijkstra_with_first_hop,
    peer_rpc::PeerRpcManager,
    route_trait::{
        DefaultRouteCostCalculator, ForeignNetworkRouteInfoMap, NextHopPolicy, RouteCostCalculator,
        RouteCostCalculatorInterface,
    },
    PeerPacketFilter,
};

static SERVICE_ID: u32 = 7;
static UPDATE_PEER_INFO_PERIOD: Duration = Duration::from_secs(3600);
static REMOVE_DEAD_PEER_INFO_AFTER: Duration = Duration::from_secs(3660);
// the cost (latency between two peers) is i32, i32::MAX is large enough.
static AVOID_RELAY_COST: usize = i32::MAX as usize;
static FORCE_USE_CONN_LIST: AtomicBool = AtomicBool::new(false);

// if a peer is unreachable for `REMOVE_UNREACHABLE_PEER_INFO_AFTER` time, we can remove it because
// 1. all the ospf sessions between two zone are already destroy, new created session will resend the peer info.
// 2. all the dst_saved_peer_info_version in all sessions already remove the peer info, the peer info will be propagated
//    in another zone when two zone restore the conneciton.
static REMOVE_UNREACHABLE_PEER_INFO_AFTER: Duration = Duration::from_secs(90);

type Version = u32;

#[derive(Debug, Clone)]
struct AtomicVersion(Arc<AtomicU32>);

impl AtomicVersion {
    fn new() -> Self {
        AtomicVersion(Arc::new(AtomicU32::new(0)))
    }

    fn get(&self) -> Version {
        self.0.load(Ordering::Relaxed)
    }

    fn set(&self, version: Version) {
        self.0.store(version, Ordering::Relaxed);
    }

    fn inc(&self) -> Version {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn set_if_larger(&self, version: Version) -> bool {
        // return true if the version is set.
        self.0.fetch_max(version, Ordering::Relaxed) < version
    }
}

impl From<Version> for AtomicVersion {
    fn from(version: Version) -> Self {
        AtomicVersion(Arc::new(AtomicU32::new(version)))
    }
}

fn is_foreign_network_info_newer(
    next: &ForeignNetworkRouteInfoEntry,
    prev: &ForeignNetworkRouteInfoEntry,
) -> Option<bool> {
    Some(
        SystemTime::try_from(next.last_update?).ok()?
            > SystemTime::try_from(prev.last_update?).ok()?,
    )
}

impl RoutePeerInfo {
    pub fn new() -> Self {
        Self {
            peer_id: 0,
            inst_id: Some(uuid::Uuid::nil().into()),
            cost: 0,
            ipv4_addr: None,
            proxy_cidrs: Vec::new(),
            hostname: None,
            udp_nat_type: 0,
            tcp_nat_type: 0,
            // ensure this is updated when the peer_infos/conn_info/foreign_network lock is acquired.
            // else we may assign a older timestamp than iterate time.
            last_update: None,
            version: 0,
            easytier_version: EASYTIER_VERSION.to_string(),
            feature_flag: None,
            peer_route_id: 0,
            network_length: 24,
            quic_port: None,
            ipv6_addr: None,
            groups: Vec::new(),
        }
    }

    /// Creates a new `RoutePeerInfo` instance with updated information from the given context.
    ///
    /// # Parameters
    /// - `my_peer_id`: The unique identifier for the peer.
    /// - `peer_route_id`: The route identifier associated with the peer.
    /// - `global_ctx`: Reference to the global context containing configuration and state.
    ///
    /// # Returns
    /// A new `RoutePeerInfo` instance initialized with values from the provided context and parameters.
    pub fn new_updated_self(
        my_peer_id: PeerId,
        peer_route_id: u64,
        global_ctx: &ArcGlobalCtx,
    ) -> Self {
        let stun_info = global_ctx.get_stun_info_collector().get_stun_info();
        Self {
            peer_id: my_peer_id,
            inst_id: Some(global_ctx.get_id().into()),
            cost: 0,
            ipv4_addr: global_ctx.get_ipv4().map(|x| x.address().into()),
            proxy_cidrs: global_ctx
                .config
                .get_proxy_cidrs()
                .iter()
                .map(|x| x.mapped_cidr.unwrap_or(x.cidr))
                .chain(global_ctx.get_vpn_portal_cidr())
                .map(|x| x.to_string())
                .collect(),
            hostname: Some(global_ctx.get_hostname()),
            udp_nat_type: stun_info.udp_nat_type,
            tcp_nat_type: stun_info.tcp_nat_type,

            // these two fields should not participate in comparison.
            last_update: None,
            version: 0,

            easytier_version: EASYTIER_VERSION.to_string(),
            feature_flag: Some(global_ctx.get_feature_flags()),
            peer_route_id,
            network_length: global_ctx
                .get_ipv4()
                .map(|x| x.network_length() as u32)
                .unwrap_or(24),

            quic_port: global_ctx.get_quic_proxy_port().map(|x| x as u32),
            ipv6_addr: global_ctx.get_ipv6().map(|x| x.into()),

            groups: global_ctx.get_acl_groups(my_peer_id),
        }
    }

    /// Attempts to update the `new` RoutePeerInfo based on the `old` RoutePeerInfo.
    ///
    /// An update is triggered if any fields in `new` differ from `old`, or if the time since
    /// `old.last_update` exceeds the `UPDATE_PEER_INFO_PERIOD`.
    ///
    /// If an update occurs, `new.last_update` is set to the current time and `new.version` is incremented.
    /// Otherwise, `new.last_update` and `new.version` are copied from `old` without modification.
    ///
    /// Returns `true` if an update was performed (fields changed or periodic update required),
    /// or `false` if no update was necessary.
    pub fn try_update_new_peer_info(old: &RoutePeerInfo, new: &mut RoutePeerInfo) -> bool {
        let need_update_periodically = if let Ok(Ok(d)) =
            SystemTime::try_from(old.last_update.unwrap_or_default()).map(|x| x.elapsed())
        {
            d > UPDATE_PEER_INFO_PERIOD
        } else {
            true
        };

        // these two fields should not participate in comparison.
        new.version = old.version;
        new.last_update = old.last_update;

        if *new != *old || need_update_periodically {
            new.version += 1;
            true
        } else {
            false
        }
    }
}

impl From<RoutePeerInfo> for crate::proto::api::instance::Route {
    fn from(val: RoutePeerInfo) -> Self {
        let network_length = if val.network_length == 0 {
            24
        } else {
            val.network_length
        };

        crate::proto::api::instance::Route {
            peer_id: val.peer_id,
            ipv4_addr: val.ipv4_addr.map(|ipv4_addr| Ipv4Inet {
                address: Some(ipv4_addr),
                network_length,
            }),
            next_hop_peer_id: 0, // next_hop_peer_id is calculated in RouteTable.
            cost: 0,             // cost is calculated in RouteTable.
            path_latency: 0,     // path_latency is calculated in RouteTable.
            proxy_cidrs: val.proxy_cidrs.clone(),
            hostname: val.hostname.unwrap_or_default(),
            stun_info: {
                let mut stun_info = StunInfo::default();
                if let Ok(udp_nat_type) = NatType::try_from(val.udp_nat_type) {
                    stun_info.set_udp_nat_type(udp_nat_type);
                }
                if let Ok(tcp_nat_type) = NatType::try_from(val.tcp_nat_type) {
                    stun_info.set_tcp_nat_type(tcp_nat_type);
                }
                Some(stun_info)
            },
            inst_id: val.inst_id.map(|x| x.to_string()).unwrap_or_default(),
            version: val.easytier_version,
            feature_flag: val.feature_flag,

            next_hop_peer_id_latency_first: None,
            cost_latency_first: None,
            path_latency_latency_first: None,

            ipv6_addr: val.ipv6_addr,
        }
    }
}

type RouteConnBitmap = crate::proto::peer_rpc::RouteConnBitmap;
type RouteConnPeerList = crate::proto::peer_rpc::RouteConnPeerList;
type PeerConnInfo = crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo;

impl RouteConnBitmap {
    fn get_bit(&self, idx: usize) -> bool {
        let byte_idx = idx / 8;
        let bit_idx = idx % 8;
        let byte = self.bitmap[byte_idx];
        (byte >> bit_idx) & 1 == 1
    }

    fn get_connected_peers(&self, peer_idx: usize) -> BTreeSet<PeerId> {
        let mut connected_peers = BTreeSet::new();
        for (idx, peer_id_version) in self.peer_ids.iter().enumerate() {
            if self.get_bit(peer_idx * self.peer_ids.len() + idx) {
                connected_peers.insert(peer_id_version.peer_id);
            }
        }
        connected_peers
    }
}

type Error = SyncRouteInfoError;

#[derive(Debug, Clone)]
struct RouteConnInfo {
    connected_peers: BTreeSet<PeerId>,
    version: AtomicVersion,
    last_update: SystemTime,
}

impl Default for RouteConnInfo {
    fn default() -> Self {
        Self {
            connected_peers: BTreeSet::new(),
            version: AtomicVersion::new(),
            last_update: SystemTime::now(),
        }
    }
}

// constructed with all infos synced from all peers.
struct SyncedRouteInfo {
    peer_infos: RwLock<OrderedHashMap<PeerId, RoutePeerInfo>>,
    // prost doesn't support unknown fields, so we use DynamicMessage to store raw infos and propagate them to other peers.
    raw_peer_infos: DashMap<PeerId, DynamicMessage>,
    conn_map: RwLock<OrderedHashMap<PeerId, RouteConnInfo>>,
    foreign_network: DashMap<ForeignNetworkRouteInfoKey, ForeignNetworkRouteInfoEntry>,
    group_trust_map: DashMap<PeerId, HashMap<String, Vec<u8>>>,
    group_trust_map_cache: DashMap<PeerId, Arc<Vec<String>>>, // cache for group trust map, should sync with group_trust_map

    version: AtomicVersion,
}

impl Debug for SyncedRouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncedRouteInfo")
            .field("peer_infos", &self.peer_infos)
            .field("conn_map", &self.conn_map)
            .field("foreign_network", &self.foreign_network)
            .field("group_trust_map", &self.group_trust_map)
            .field("version", &self.version.get())
            .finish()
    }
}

impl SyncedRouteInfo {
    fn get_connected_peers<T: FromIterator<PeerId>>(&self, peer_id: PeerId) -> Option<T> {
        self.conn_map
            .read()
            .get(&peer_id)
            .map(|x| x.connected_peers.iter().copied().collect())
    }

    fn remove_peer(&self, peer_id: PeerId) {
        tracing::warn!(?peer_id, "remove_peer from synced_route_info");
        self.peer_infos.write().remove(&peer_id);
        self.raw_peer_infos.remove(&peer_id);
        self.conn_map.write().remove(&peer_id);
        self.foreign_network.retain(|k, _| k.peer_id != peer_id);
        self.group_trust_map.remove(&peer_id);
        self.group_trust_map_cache.remove(&peer_id);

        shrink_dashmap(&self.raw_peer_infos, None);
        shrink_dashmap(&self.foreign_network, None);
        shrink_dashmap(&self.group_trust_map, None);
        shrink_dashmap(&self.group_trust_map_cache, None);

        self.version.inc();
    }

    fn fill_empty_peer_info(&self, peer_ids: &BTreeSet<PeerId>) {
        let mut need_inc_version = false;
        for peer_id in peer_ids {
            let guard = self.peer_infos.upgradable_read();
            if !guard.contains_key(peer_id) {
                let mut peer_info = RoutePeerInfo::new();
                let mut guard = RwLockUpgradableReadGuard::upgrade(guard);
                peer_info.last_update = Some(SystemTime::now().into());
                guard.insert(*peer_id, peer_info);
                need_inc_version = true;
            } else {
                drop(guard);
            }

            let guard = self.conn_map.upgradable_read();
            if !guard.contains_key(peer_id) {
                let mut guard = RwLockUpgradableReadGuard::upgrade(guard);
                guard.insert(*peer_id, RouteConnInfo::default());
                need_inc_version = true;
            } else {
                drop(guard);
            }
        }
        if need_inc_version {
            self.version.inc();
        }
    }

    fn get_peer_info_version_with_default(&self, peer_id: PeerId) -> Version {
        self.peer_infos
            .read()
            .get(&peer_id)
            .map(|x| x.version)
            .unwrap_or(0)
    }

    fn get_avoid_relay_data(&self, peer_id: PeerId) -> bool {
        // if avoid relay, just set all outgoing edges to a large value: AVOID_RELAY_COST.
        self.peer_infos
            .read()
            .get(&peer_id)
            .and_then(|x| x.feature_flag)
            .map(|x| x.avoid_relay_data)
            .unwrap_or_default()
    }

    fn check_duplicate_peer_id(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        dst_peer_id: PeerId,
        dst_peer_route_id: Option<u64>,
        info: &RoutePeerInfo,
    ) -> Result<(), Error> {
        // 1. check if we are duplicated.
        if info.peer_id == my_peer_id {
            if info.peer_route_id != my_peer_route_id
                && info.version > self.get_peer_info_version_with_default(info.peer_id)
            {
                // if dst peer send to us with higher version info of my peer, our peer id is duplicated
                // TODO: handle this better. restart peer manager?
                panic!("my peer id is duplicated");
                // return Err(Error::DuplicatePeerId);
            }
        } else if info.peer_id == dst_peer_id {
            let Some(dst_peer_route_id) = dst_peer_route_id else {
                return Ok(());
            };

            if dst_peer_route_id != info.peer_route_id
                && info.version < self.get_peer_info_version_with_default(info.peer_id)
            {
                // if dst peer send to us with lower version info of dst peer, dst peer id is duplicated
                return Err(Error::DuplicatePeerId);
            }
        }

        Ok(())
    }

    fn update_peer_infos(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        dst_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
    ) -> Result<(), Error> {
        let mut need_inc_version = false;
        for (idx, route_info) in peer_infos.iter().enumerate() {
            let mut route_info = route_info.clone();
            let raw_route_info = &raw_peer_infos[idx];
            self.check_duplicate_peer_id(
                my_peer_id,
                my_peer_route_id,
                dst_peer_id,
                if route_info.peer_id == dst_peer_id {
                    self.peer_infos
                        .read()
                        .get(&dst_peer_id)
                        .map(|x| x.peer_route_id)
                } else {
                    None
                },
                &route_info,
            )?;

            let peer_id_raw = raw_route_info
                .get_field_by_name("peer_id")
                .unwrap()
                .as_u32()
                .unwrap();
            assert_eq!(peer_id_raw, route_info.peer_id);

            let mut guard = self.peer_infos.write();
            // time between peers may not be synchronized, so update last_update to local now.
            // note only last_update with larger version will be updated to local saved peer info.
            route_info.last_update = Some(SystemTime::now().into());
            if guard
                .get_mut(&route_info.peer_id)
                .is_none_or(|old| route_info.version > old.version)
            {
                self.raw_peer_infos
                    .insert(route_info.peer_id, raw_route_info.clone());
                guard.insert(route_info.peer_id, route_info);
                need_inc_version = true;
            }
        }
        if need_inc_version {
            self.version.inc();
        }
        Ok(())
    }

    fn update_conn_info_one_peer(
        &self,
        peer_id_version: &PeerIdVersion,
        connected_peers: BTreeSet<PeerId>,
    ) -> bool {
        let mut guard = self.conn_map.write();
        if guard
            .get_mut(&peer_id_version.peer_id)
            .is_none_or(|old| peer_id_version.version > old.version.get())
        {
            guard.insert(
                peer_id_version.peer_id,
                RouteConnInfo {
                    connected_peers,
                    version: peer_id_version.version.into(),
                    last_update: SystemTime::now(),
                },
            );
            return true;
        }

        false
    }

    fn update_conn_info_with_bitmap(&self, conn_bitmap: &RouteConnBitmap) {
        self.fill_empty_peer_info(&conn_bitmap.peer_ids.iter().map(|x| x.peer_id).collect());

        let mut need_inc_version = false;

        for (peer_idx, peer_id_version) in conn_bitmap.peer_ids.iter().enumerate() {
            let connceted_peers = conn_bitmap.get_connected_peers(peer_idx);
            self.fill_empty_peer_info(&connceted_peers);
            need_inc_version = self.update_conn_info_one_peer(peer_id_version, connceted_peers);
        }
        if need_inc_version {
            self.version.inc();
        }
    }

    fn update_conn_info_with_list(&self, conn_peer_list: &RouteConnPeerList) {
        let mut need_inc_version = false;

        for peer_conn_info in &conn_peer_list.peer_conn_infos {
            let Some(peer_id_version) = peer_conn_info.peer_id else {
                continue;
            };
            let connected_peers: BTreeSet<PeerId> =
                peer_conn_info.connected_peer_ids.iter().copied().collect();

            self.fill_empty_peer_info(&connected_peers);
            need_inc_version = self.update_conn_info_one_peer(&peer_id_version, connected_peers);
        }
        if need_inc_version {
            self.version.inc();
        }
    }

    fn update_conn_info(&self, conn_info: &ConnInfo) {
        match conn_info {
            ConnInfo::ConnBitmap(conn_bitmap) => {
                self.update_conn_info_with_bitmap(conn_bitmap);
            }
            ConnInfo::ConnPeerList(conn_peer_list) => {
                self.update_conn_info_with_list(conn_peer_list);
            }
        }
    }

    fn update_foreign_network(&self, foreign_network: &RouteForeignNetworkInfos) {
        for item in foreign_network.infos.iter().map(Clone::clone) {
            let Some(key) = item.key else {
                continue;
            };
            let Some(mut entry) = item.value else {
                continue;
            };

            entry.last_update = Some(SystemTime::now().into());

            self.foreign_network
                .entry(key.clone())
                .and_modify(|old_entry| {
                    if entry.version > old_entry.version {
                        *old_entry = entry.clone();
                    }
                })
                .or_insert_with(|| entry.clone());
        }
    }

    fn update_my_peer_info(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        global_ctx: &ArcGlobalCtx,
    ) -> bool {
        let mut new = RoutePeerInfo::new_updated_self(my_peer_id, my_peer_route_id, global_ctx);
        let mut guard = self.peer_infos.upgradable_read();
        let old = guard.get(&my_peer_id);
        let new_version = old.map(|x| x.version).unwrap_or(0) + 1;
        let need_insert_new = if let Some(old) = old {
            RoutePeerInfo::try_update_new_peer_info(old, &mut new)
        } else {
            true
        };

        if need_insert_new {
            let acl_groups = if old.map(|x| x.groups != new.groups).unwrap_or(true) {
                Some(new.groups.clone())
            } else {
                None
            };

            guard.with_upgraded(|peer_infos| {
                new.last_update = Some(SystemTime::now().into());
                new.version = new_version;
                peer_infos.insert(my_peer_id, new)
            });
            drop(guard);

            if let Some(acl_groups) = acl_groups {
                self.update_my_group_trusts(my_peer_id, &acl_groups);
            }

            self.version.inc();
            true
        } else {
            false
        }
    }

    fn update_my_conn_info(&self, my_peer_id: PeerId, connected_peers: BTreeSet<PeerId>) -> bool {
        self.fill_empty_peer_info(&connected_peers);

        let guard = self.conn_map.upgradable_read();
        let my_conn_info = guard.get(&my_peer_id);
        let new_version = my_conn_info.map(|x| x.version.get()).unwrap_or(0) + 1;

        if my_conn_info.is_none_or(|old| old.connected_peers != connected_peers) {
            let mut guard = RwLockUpgradableReadGuard::upgrade(guard);
            guard.insert(
                my_peer_id,
                RouteConnInfo {
                    connected_peers,
                    version: new_version.into(),
                    last_update: SystemTime::now(),
                },
            );
            self.version.inc();
            true
        } else {
            false
        }
    }

    fn update_my_foreign_network(
        &self,
        my_peer_id: PeerId,
        foreign_networks: ForeignNetworkRouteInfoMap,
    ) -> bool {
        let now = SystemTime::now();
        let now_version = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as Version;
        let mut updated = false;
        for mut item in self
            .foreign_network
            .iter_mut()
            .filter(|x| x.key().peer_id == my_peer_id)
        {
            let (key, entry) = item.pair_mut();
            if let Some(mut new_entry) = foreign_networks.get_mut(key) {
                assert!(!new_entry.foreign_peer_ids.is_empty());
                if let Some(is_newer) = is_foreign_network_info_newer(&new_entry, entry) {
                    let need_renew = is_newer
                        || now
                            .duration_since(entry.last_update.unwrap().try_into().unwrap())
                            .unwrap_or(Duration::from_secs(0))
                            > UPDATE_PEER_INFO_PERIOD;
                    if need_renew {
                        new_entry.version = std::cmp::max(new_entry.version + 1, now_version);
                        *entry = new_entry.clone();
                        updated = true;
                    }
                }
                drop(new_entry);
                foreign_networks.remove(key).unwrap();
            } else if !item.foreign_peer_ids.is_empty() {
                item.foreign_peer_ids.clear();
                item.last_update = Some(SystemTime::now().into());
                item.version = std::cmp::max(item.version + 1, now_version);
                updated = true;
            }
        }

        for item in foreign_networks.iter() {
            assert!(!item.value().foreign_peer_ids.is_empty());
            self.foreign_network
                .entry(item.key().clone())
                .and_modify(|old_entry| {
                    if item.value().version > old_entry.version {
                        *old_entry = item.value().clone();
                    }
                })
                .or_insert_with(|| {
                    let mut v = item.value().clone();
                    v.version = now_version;
                    v
                });
            updated = true;
        }

        if updated {
            self.version.inc();
        }

        updated
    }

    fn get_next_last_sync_succ_timestamp(&self) -> SystemTime {
        let _peer_info_lock = self.peer_infos.read();
        let _conn_info_lock = self.conn_map.read();
        // TODO: add conn and foreign network lock

        SystemTime::now()
    }

    fn verify_and_update_group_trusts(
        &self,
        peer_infos: &[RoutePeerInfo],
        local_group_declarations: &[GroupIdentity],
    ) {
        let local_group_declarations = local_group_declarations
            .iter()
            .map(|g| (g.group_name.as_str(), g.group_secret.as_str()))
            .collect::<std::collections::HashMap<&str, &str>>();

        let verify_groups = |old_trusted_groups: Option<&HashMap<String, Vec<u8>>>,
                             info: &RoutePeerInfo|
         -> HashMap<String, Vec<u8>> {
            let mut trusted_groups_for_peer: HashMap<String, Vec<u8>> = HashMap::new();

            for group_proof in &info.groups {
                let name = &group_proof.group_name;
                let proof_bytes = group_proof.group_proof.clone();

                // If we already trusted this group and the proof hasn't changed, reuse it.
                if old_trusted_groups
                    .and_then(|g| g.get(name))
                    .map(|old| old == &proof_bytes)
                    .unwrap_or(false)
                {
                    trusted_groups_for_peer.insert(name.clone(), proof_bytes);
                    continue;
                }

                if let Some(&local_secret) =
                    local_group_declarations.get(group_proof.group_name.as_str())
                {
                    if group_proof.verify(local_secret, info.peer_id) {
                        trusted_groups_for_peer.insert(name.clone(), proof_bytes);
                    } else {
                        tracing::warn!(
                            peer_id = info.peer_id,
                            group = %group_proof.group_name,
                            "Group proof verification failed"
                        );
                    }
                }
            }

            trusted_groups_for_peer
        };

        for info in peer_infos {
            match self.group_trust_map.entry(info.peer_id) {
                dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                    let old_trusted_groups = entry.get().clone();
                    let trusted_groups_for_peer = verify_groups(Some(&old_trusted_groups), info);

                    if trusted_groups_for_peer.is_empty() {
                        entry.remove();
                        self.group_trust_map_cache.remove(&info.peer_id);
                    } else {
                        self.group_trust_map_cache.insert(
                            info.peer_id,
                            Arc::new(trusted_groups_for_peer.keys().cloned().collect()),
                        );
                        *entry.get_mut() = trusted_groups_for_peer;
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    let trusted_groups_for_peer = verify_groups(None, info);

                    if !trusted_groups_for_peer.is_empty() {
                        self.group_trust_map_cache.insert(
                            info.peer_id,
                            Arc::new(trusted_groups_for_peer.keys().cloned().collect()),
                        );
                        entry.insert(trusted_groups_for_peer);
                    }
                }
            }
        }
    }

    fn update_my_group_trusts(&self, my_peer_id: PeerId, groups: &[PeerGroupInfo]) {
        let mut my_group_map = HashMap::new();
        let mut my_group_names = Vec::new();

        for group in groups.iter() {
            my_group_map.insert(group.group_name.clone(), group.group_proof.clone());
            my_group_names.push(group.group_name.clone());
        }

        self.group_trust_map.insert(my_peer_id, my_group_map);
        self.group_trust_map_cache
            .insert(my_peer_id, Arc::new(my_group_names));
    }
}

type PeerGraph = Graph<PeerId, usize, Directed>;
type PeerIdToNodexIdxMap = DashMap<PeerId, NodeIndex>;
#[derive(Debug, Clone, Copy)]
struct NextHopInfo {
    next_hop_peer_id: PeerId,
    path_latency: i32,
    path_len: usize, // path includes src and dst.
    version: Version,
}
// dst_peer_id -> (next_hop_peer_id, cost, path_len)
type NextHopMap = DashMap<PeerId, NextHopInfo>;

// computed with SyncedRouteInfo. used to get next hop.
#[derive(Debug)]
struct RouteTable {
    peer_infos: DashMap<PeerId, RoutePeerInfo>,
    next_hop_map: NextHopMap,
    ipv4_peer_id_map: DashMap<Ipv4Addr, PeerIdVersion>,
    ipv6_peer_id_map: DashMap<Ipv6Addr, PeerIdVersion>,
    cidr_peer_id_map: ArcSwap<PrefixMap<Ipv4Cidr, PeerIdVersion>>,
    cidr_v6_peer_id_map: ArcSwap<PrefixMap<Ipv6Cidr, PeerIdVersion>>,
    next_hop_map_version: AtomicVersion,
}

impl RouteTable {
    fn new() -> Self {
        RouteTable {
            peer_infos: DashMap::new(),
            next_hop_map: DashMap::new(),
            ipv4_peer_id_map: DashMap::new(),
            ipv6_peer_id_map: DashMap::new(),
            cidr_peer_id_map: ArcSwap::new(Arc::new(PrefixMap::new())),
            cidr_v6_peer_id_map: ArcSwap::new(Arc::new(PrefixMap::new())),
            next_hop_map_version: AtomicVersion::new(),
        }
    }

    fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<NextHopInfo> {
        let cur_version = self.next_hop_map_version.get();
        self.next_hop_map.get(&dst_peer_id).and_then(|x| {
            if x.version >= cur_version {
                Some(*x)
            } else {
                None
            }
        })
    }

    fn peer_reachable(&self, peer_id: PeerId) -> bool {
        self.get_next_hop(peer_id).is_some()
    }

    fn get_udp_nat_type(&self, peer_id: PeerId) -> Option<NatType> {
        self.peer_infos
            .get(&peer_id)
            .map(|x| NatType::try_from(x.udp_nat_type).unwrap_or_default())
    }

    // return graph and start node index (node of my peer id).
    fn build_peer_graph_from_synced_info<T: RouteCostCalculatorInterface>(
        my_peer_id: PeerId,
        synced_info: &SyncedRouteInfo,
        cost_calc: &T,
    ) -> (PeerGraph, NodeIndex) {
        let mut graph: PeerGraph = PeerGraph::new();

        let mut start_node_idx = None;
        let peer_id_to_node_index: PeerIdToNodexIdxMap = DashMap::new();
        for (peer_id, info) in synced_info.peer_infos.read().iter() {
            let peer_id = *peer_id;

            if info.version == 0 {
                continue;
            }

            let node_idx = graph.add_node(peer_id);

            peer_id_to_node_index.insert(peer_id, node_idx);
            if peer_id == my_peer_id {
                start_node_idx = Some(node_idx);
            }
        }

        if start_node_idx.is_none() {
            return (graph, NodeIndex::end());
        }

        for item in peer_id_to_node_index.iter() {
            let src_peer_id = item.key();
            let src_node_idx = item.value();
            let connected_peers: BTreeSet<_> = synced_info
                .get_connected_peers(*src_peer_id)
                .unwrap_or_default();

            // if avoid relay, just set all outgoing edges to a large value: AVOID_RELAY_COST.
            let peer_avoid_relay_data = synced_info.get_avoid_relay_data(*src_peer_id);

            for dst_peer_id in connected_peers.iter() {
                let Some(dst_node_idx) = peer_id_to_node_index.get(dst_peer_id) else {
                    continue;
                };

                let mut cost = cost_calc.calculate_cost(*src_peer_id, *dst_peer_id) as usize;
                if peer_avoid_relay_data {
                    cost += AVOID_RELAY_COST;
                }

                graph.add_edge(*src_node_idx, *dst_node_idx, cost);
            }
        }

        (graph, start_node_idx.unwrap())
    }

    fn clean_expired_route_info(&self) {
        let cur_version = self.next_hop_map_version.get();
        self.next_hop_map.retain(|_, v| {
            // remove next hop map for peers we cannot reach.
            v.version >= cur_version
        });
        self.peer_infos.retain(|k, _| {
            // remove peer info for peers we cannot reach.
            self.next_hop_map.contains_key(k)
        });
        self.ipv4_peer_id_map.retain(|_, v| {
            // remove ipv4 map for peers we cannot reach.
            self.next_hop_map.contains_key(&v.peer_id)
        });
        self.ipv6_peer_id_map.retain(|_, v| {
            // remove ipv6 map for peers we cannot reach.
            self.next_hop_map.contains_key(&v.peer_id)
        });

        shrink_dashmap(&self.peer_infos, None);
        shrink_dashmap(&self.next_hop_map, None);
        shrink_dashmap(&self.ipv4_peer_id_map, None);
        shrink_dashmap(&self.ipv6_peer_id_map, None);
    }

    fn gen_next_hop_map_with_least_hop(
        &self,
        graph: &PeerGraph,
        start_node: &NodeIndex,
        version: Version,
    ) {
        let normalize_edge_cost = |e: petgraph::graph::EdgeReference<usize>| {
            if *e.weight() >= AVOID_RELAY_COST {
                AVOID_RELAY_COST + 1
            } else {
                1
            }
        };
        // Step 1: 第一次 Dijkstra - 计算最短跳数
        let path_len_map = dijkstra(&graph, *start_node, None, normalize_edge_cost);

        // Step 2: 构建最短跳数子图（只保留属于最短路径和 AVOID RELAY 的边）
        let mut subgraph: PeerGraph = PeerGraph::new();
        let mut start_node_idx = None;
        for (node_idx, peer_id) in graph.node_references() {
            let new_node_idx = subgraph.add_node(*peer_id);
            if node_idx == *start_node {
                start_node_idx = Some(new_node_idx);
            }
        }

        for edge in graph.edge_references() {
            let (src, tgt) = graph.edge_endpoints(edge.id()).unwrap();
            let Some(src_path_len) = path_len_map.get(&src) else {
                continue;
            };
            let Some(tgt_path_len) = path_len_map.get(&tgt) else {
                continue;
            };
            if *src_path_len + normalize_edge_cost(edge) == *tgt_path_len {
                subgraph.add_edge(src, tgt, *edge.weight());
            }
        }

        // Step 3: 第二次 Dijkstra - 在子图上找代价最小的路径
        self.gen_next_hop_map_with_least_cost(&subgraph, &start_node_idx.unwrap(), version);
    }

    fn gen_next_hop_map_with_least_cost(
        &self,
        graph: &PeerGraph,
        start_node: &NodeIndex,
        version: Version,
    ) {
        let (costs, next_hops) = dijkstra_with_first_hop(&graph, *start_node, |e| *e.weight());

        for (dst, (next_hop, path_len)) in next_hops.iter() {
            let info = NextHopInfo {
                next_hop_peer_id: *graph.node_weight(*next_hop).unwrap(),
                path_latency: (*costs.get(dst).unwrap() % AVOID_RELAY_COST) as i32,
                path_len: { *path_len },
                version,
            };
            let dst_peer_id = *graph.node_weight(*dst).unwrap();
            self.next_hop_map
                .entry(dst_peer_id)
                .and_modify(|x| {
                    if x.version < version {
                        *x = info;
                    }
                })
                .or_insert(info);
        }

        self.next_hop_map_version.set_if_larger(version);
    }

    fn build_from_synced_info<T: RouteCostCalculatorInterface>(
        &self,
        my_peer_id: PeerId,
        synced_info: &SyncedRouteInfo,
        policy: NextHopPolicy,
        cost_calc: &T,
    ) {
        let version = synced_info.version.get();

        // build next hop map
        let (graph, start_node) =
            Self::build_peer_graph_from_synced_info(my_peer_id, synced_info, cost_calc);

        if graph.node_count() == 0 {
            tracing::warn!("no peer in graph, cannot build next hop map");
            return;
        }

        if matches!(policy, NextHopPolicy::LeastHop) {
            self.gen_next_hop_map_with_least_hop(&graph, &start_node, version);
        } else {
            self.gen_next_hop_map_with_least_cost(&graph, &start_node, version);
        };

        let mut new_cidr_prefix_trie = PrefixMap::new();
        let mut new_cidr_v6_prefix_trie = PrefixMap::new();

        // build peer_infos, ipv4_peer_id_map, cidr_peer_id_map
        // only set map for peers we can reach.
        for item in self.next_hop_map.iter() {
            if item.version < version {
                // skip if the next hop entry is outdated. (peer is unreachable)
                continue;
            }

            let peer_id = item.key();
            let Some(info) = synced_info.peer_infos.read().get(peer_id).cloned() else {
                continue;
            };

            self.peer_infos.insert(*peer_id, info.clone());

            let peer_id_and_version = PeerIdVersion {
                peer_id: *peer_id,
                version,
            };

            let is_new_peer_better = |old_peer: &PeerIdVersion| -> bool {
                if peer_id_and_version.version > old_peer.version {
                    return true;
                }
                if peer_id_and_version.peer_id == old_peer.peer_id {
                    return false;
                }
                let old_next_hop = self.get_next_hop(old_peer.peer_id);
                let new_next_hop = item.value();
                old_next_hop.is_none() || new_next_hop.path_len < old_next_hop.unwrap().path_len
            };

            if let Some(ipv4_addr) = info.ipv4_addr {
                self.ipv4_peer_id_map
                    .entry(ipv4_addr.into())
                    .and_modify(|v| {
                        if is_new_peer_better(v) {
                            *v = peer_id_and_version;
                        }
                    })
                    .or_insert(peer_id_and_version);
            }

            if let Some(ipv6_addr) = info.ipv6_addr.and_then(|x| x.address) {
                self.ipv6_peer_id_map
                    .entry(ipv6_addr.into())
                    .and_modify(|v| {
                        if is_new_peer_better(v) {
                            *v = peer_id_and_version;
                        }
                    })
                    .or_insert(peer_id_and_version);
            }

            for cidr in info.proxy_cidrs.iter() {
                let cidr = cidr.parse::<IpCidr>();
                match cidr {
                    Ok(IpCidr::V4(cidr)) => {
                        new_cidr_prefix_trie
                            .entry(cidr)
                            .and_modify(|e| {
                                // if ourself has same cidr, ensure here put my peer id, so we can know deadloop may happen.
                                if *peer_id == my_peer_id || is_new_peer_better(e) {
                                    *e = peer_id_and_version;
                                }
                            })
                            .or_insert(peer_id_and_version);
                    }

                    Ok(IpCidr::V6(cidr)) => {
                        new_cidr_v6_prefix_trie
                            .entry(cidr)
                            .and_modify(|e| {
                                // if ourself has same cidr, ensure here put my peer id, so we can know deadloop may happen.
                                if *peer_id == my_peer_id || is_new_peer_better(e) {
                                    *e = peer_id_and_version;
                                }
                            })
                            .or_insert(peer_id_and_version);
                    }

                    _ => {
                        tracing::warn!("invalid proxy cidr: {:?}, from peer: {:?}", cidr, peer_id);
                    }
                }
                tracing::debug!(
                    "add cidr: {:?} to peer: {:?}, my peer id: {:?}",
                    cidr,
                    peer_id,
                    my_peer_id
                );
            }
        }

        self.cidr_peer_id_map.store(Arc::new(new_cidr_prefix_trie));
        self.cidr_v6_peer_id_map
            .store(Arc::new(new_cidr_v6_prefix_trie));
        tracing::trace!(
            my_peer_id = my_peer_id,
            cidrs = ?self.cidr_peer_id_map.load(),
            cidrs_v6 = ?self.cidr_v6_peer_id_map.load(),
            "update peer cidr map"
        );
    }

    fn get_peer_id_for_proxy(&self, ip: &IpAddr) -> Option<PeerId> {
        match ip {
            IpAddr::V4(ipv4) => self
                .cidr_peer_id_map
                .load()
                .get_lpm(&Ipv4Cidr::new(*ipv4, 32).unwrap())
                .map(|x| x.1.peer_id),
            IpAddr::V6(ipv6) => self
                .cidr_v6_peer_id_map
                .load()
                .get_lpm(&Ipv6Cidr::new(*ipv6, 128).unwrap())
                .map(|x| x.1.peer_id),
        }
    }
}

type SessionId = u64;

type AtomicSessionId = atomic_shim::AtomicU64;

struct SessionTask {
    my_peer_id: PeerId,
    task: Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,
}

impl SessionTask {
    fn new(my_peer_id: PeerId) -> Self {
        SessionTask {
            my_peer_id,
            task: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn set_task(&self, task: JoinHandle<()>) {
        if let Some(old) = self.task.lock().unwrap().replace(task) {
            old.abort();
        }
    }

    fn is_running(&self) -> bool {
        if let Some(task) = self.task.lock().unwrap().as_ref() {
            !task.is_finished()
        } else {
            false
        }
    }
}

impl Drop for SessionTask {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        tracing::debug!(my_peer_id = self.my_peer_id, "drop SessionTask");
    }
}

impl Debug for SessionTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTask")
            .field("is_running", &self.is_running())
            .finish()
    }
}

#[derive(Debug)]
struct VersionAndTouchTime {
    version: AtomicVersion,
    touch_time: AtomicCell<Instant>,
}

impl Default for VersionAndTouchTime {
    fn default() -> Self {
        VersionAndTouchTime {
            version: AtomicVersion::new(),
            touch_time: AtomicCell::new(Instant::now()),
        }
    }
}

impl VersionAndTouchTime {
    fn touch(&self) {
        self.touch_time.store(Instant::now());
    }

    fn get(&self) -> Version {
        self.version.get()
    }

    fn set_if_larger(&self, version: Version) {
        self.version.set_if_larger(version);
    }

    fn is_expired(&self) -> bool {
        self.touch_time.load().elapsed() > Duration::from_secs(60)
    }
}

// if we need to sync route info with one peer, we create a SyncRouteSession with that peer.
#[derive(Debug)]
struct SyncRouteSession {
    my_peer_id: PeerId,
    dst_peer_id: PeerId,
    dst_saved_peer_info_versions: DashMap<PeerId, VersionAndTouchTime>,
    dst_saved_conn_info_version: DashMap<PeerId, VersionAndTouchTime>,
    dst_saved_foreign_network_versions: DashMap<ForeignNetworkRouteInfoKey, VersionAndTouchTime>,

    // we don't want to send unreachable peer infos / conn infos to peer, so we keep track of them.
    unreachable_peers_for_peer_info: parking_lot::Mutex<BTreeMap<PeerId, Version>>,
    unreachable_peers_for_conn_info: parking_lot::Mutex<BTreeMap<PeerId, Version>>,

    last_sync_succ_timestamp: AtomicCell<Option<SystemTime>>,

    my_session_id: AtomicSessionId,
    dst_session_id: AtomicSessionId,

    // every node should have exactly one initator session to one other non-initiator peer.
    we_are_initiator: AtomicBool,
    dst_is_initiator: AtomicBool,

    need_sync_initiator_info: AtomicBool,

    rpc_tx_count: AtomicU32,
    rpc_rx_count: AtomicU32,

    task: SessionTask,

    lock: parking_lot::Mutex<()>,
}

impl SyncRouteSession {
    fn new(my_peer_id: PeerId, dst_peer_id: PeerId) -> Self {
        SyncRouteSession {
            my_peer_id,
            dst_peer_id,
            dst_saved_peer_info_versions: DashMap::new(),
            dst_saved_conn_info_version: DashMap::new(),
            dst_saved_foreign_network_versions: DashMap::new(),

            unreachable_peers_for_peer_info: parking_lot::Mutex::new(BTreeMap::new()),
            unreachable_peers_for_conn_info: parking_lot::Mutex::new(BTreeMap::new()),

            last_sync_succ_timestamp: AtomicCell::new(None),

            my_session_id: AtomicSessionId::new(rand::random()),
            dst_session_id: AtomicSessionId::new(0),

            we_are_initiator: AtomicBool::new(false),
            dst_is_initiator: AtomicBool::new(false),

            need_sync_initiator_info: AtomicBool::new(false),

            rpc_tx_count: AtomicU32::new(0),
            rpc_rx_count: AtomicU32::new(0),

            task: SessionTask::new(my_peer_id),

            lock: parking_lot::Mutex::new(()),
        }
    }

    fn check_saved_peer_info_update_to_date(&self, peer_id: PeerId, version: Version) -> bool {
        if version == 0 || peer_id == self.dst_peer_id {
            // never send version 0 peer info to dst peer.
            return true;
        }
        self.dst_saved_peer_info_versions
            .get(&peer_id)
            .map(|v| {
                v.touch();
                v.get() >= version
            })
            .unwrap_or(false)
    }

    fn check_saved_conn_version_update_to_date(&self, peer_id: PeerId, version: Version) -> bool {
        if version == 0 || peer_id == self.dst_peer_id {
            // never send version 0 conn bitmap to dst peer.
            return true;
        }
        self.dst_saved_conn_info_version
            .get(&peer_id)
            .map(|v| {
                v.touch();
                v.get() >= version
            })
            .unwrap_or(false)
    }

    fn check_saved_foreign_network_version_update_to_date(
        &self,
        foreign_network_key: &ForeignNetworkRouteInfoKey,
        version: Version,
    ) -> bool {
        if version == 0 || foreign_network_key.peer_id == self.dst_peer_id {
            // never send version 0 foreign network to dst peer.
            return true;
        }

        self.dst_saved_foreign_network_versions
            .get(foreign_network_key)
            .map(|x| {
                x.touch();
                x.get() >= version
            })
            .unwrap_or(false)
    }

    fn update_dst_saved_peer_info_version(&self, infos: &[RoutePeerInfo], dst_peer_id: PeerId) {
        for info in infos.iter() {
            if info.peer_id == dst_peer_id {
                // we never send dst peer info to dst peer, so no need to store it.
                continue;
            }

            self.dst_saved_peer_info_versions
                .entry(info.peer_id)
                .or_default()
                .set_if_larger(info.version);
        }
    }

    fn update_dst_saved_conn_bitmap_version(
        &self,
        conn_bitmap: &RouteConnBitmap,
        dst_peer_id: PeerId,
    ) {
        for peer_id_version in conn_bitmap.peer_ids.iter() {
            if peer_id_version.peer_id == dst_peer_id {
                continue;
            }

            self.dst_saved_conn_info_version
                .entry(peer_id_version.peer_id)
                .or_default()
                .set_if_larger(peer_id_version.version);
        }
    }

    fn update_dst_saved_conn_peer_list_version(
        &self,
        conn_peer_list: &RouteConnPeerList,
        dst_peer_id: PeerId,
    ) {
        for peer_conn_info in &conn_peer_list.peer_conn_infos {
            let Some(peer_id_version) = peer_conn_info.peer_id else {
                continue;
            };
            if peer_id_version.peer_id == dst_peer_id {
                continue;
            }

            self.dst_saved_conn_info_version
                .entry(peer_id_version.peer_id)
                .or_default()
                .set_if_larger(peer_id_version.version);
        }
    }

    fn update_dst_saved_conn_info_version(&self, conn_info: &ConnInfo, dst_peer_id: PeerId) {
        match conn_info {
            ConnInfo::ConnBitmap(conn_bitmap) => {
                self.update_dst_saved_conn_bitmap_version(conn_bitmap, dst_peer_id);
            }
            ConnInfo::ConnPeerList(peer_list) => {
                self.update_dst_saved_conn_peer_list_version(peer_list, dst_peer_id);
            }
        }
    }

    fn update_dst_saved_foreign_network_version(
        &self,
        foreign_network: &RouteForeignNetworkInfos,
        dst_peer_id: PeerId,
    ) {
        for item in foreign_network.infos.iter() {
            if item.key.as_ref().unwrap().peer_id == dst_peer_id {
                continue;
            }
            self.dst_saved_foreign_network_versions
                .entry(item.key.clone().unwrap())
                .or_default()
                .set_if_larger(item.value.as_ref().unwrap().version);
        }
    }

    fn update_initiator_flag(&self, is_initiator: bool) {
        self.we_are_initiator.store(is_initiator, Ordering::Relaxed);
        self.need_sync_initiator_info.store(true, Ordering::Relaxed);
    }

    // return whether session id is updated
    fn update_dst_session_id(&self, session_id: SessionId) {
        if session_id != self.dst_session_id.load(Ordering::Relaxed) {
            tracing::warn!(?self, ?session_id, "session id mismatch, clear saved info.");
            self.dst_session_id.store(session_id, Ordering::Relaxed);
            self.dst_saved_conn_info_version.clear();
            self.dst_saved_peer_info_versions.clear();

            // update_dst_session_id is always called with session lock held, so clear
            // last_sync_succ_timestamp and unreachable_peers non-atomic is safe.
            self.last_sync_succ_timestamp.store(None);
            self.unreachable_peers_for_peer_info.lock().clear();
            self.unreachable_peers_for_conn_info.lock().clear();
        }
    }

    fn clean_dst_saved_map(&self) {
        self.dst_saved_peer_info_versions
            .retain(|_, v| !v.is_expired());
        self.dst_saved_peer_info_versions.shrink_to_fit();

        self.dst_saved_conn_info_version
            .retain(|_, v| !v.is_expired());
        self.dst_saved_conn_info_version.shrink_to_fit();

        self.dst_saved_foreign_network_versions
            .retain(|_, v| !v.is_expired());
        self.dst_saved_foreign_network_versions.shrink_to_fit();
    }

    fn update_last_sync_succ_timestamp(&self, next_last_sync_succ_timestamp: SystemTime) {
        let _ = self.last_sync_succ_timestamp.fetch_update(|x| {
            if x.is_none_or(|old| old < next_last_sync_succ_timestamp) {
                Some(Some(next_last_sync_succ_timestamp))
            } else {
                None
            }
        });
    }

    fn short_debug_string(&self) -> String {
        format!(
            "session_dst_peer: {:?}, my_session_id: {:?}, dst_session_id: {:?}, we_are_initiator: {:?}, dst_is_initiator: {:?}, rpc_tx_count: {:?}, rpc_rx_count: {:?}, task: {:?}",
            self.dst_peer_id,
            self.my_session_id,
            self.dst_session_id,
            self.we_are_initiator,
            self.dst_is_initiator,
            self.rpc_tx_count,
            self.rpc_rx_count,
            self.task
        )
    }
}

impl Drop for SyncRouteSession {
    fn drop(&mut self) {
        tracing::debug!(?self, "drop SyncRouteSession");
    }
}

struct PeerRouteServiceImpl {
    my_peer_id: PeerId,
    my_peer_route_id: u64,
    global_ctx: ArcGlobalCtx,
    sessions: DashMap<PeerId, Arc<SyncRouteSession>>,

    interface: Mutex<Option<RouteInterfaceBox>>,

    cost_calculator: std::sync::RwLock<Option<RouteCostCalculator>>,
    route_table: RouteTable,
    route_table_with_cost: RouteTable,
    foreign_network_owner_map: DashMap<NetworkIdentity, Vec<PeerId>>,
    foreign_network_my_peer_id_map: DashMap<(String, PeerId), PeerId>,
    synced_route_info: SyncedRouteInfo,
    cached_local_conn_map: std::sync::Mutex<RouteConnBitmap>,
    cached_local_conn_map_version: AtomicVersion,

    last_update_my_foreign_network: AtomicCell<Option<std::time::Instant>>,

    peer_info_last_update: AtomicCell<std::time::Instant>,
}

impl Debug for PeerRouteServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRouteServiceImpl")
            .field("my_peer_id", &self.my_peer_id)
            .field("my_peer_route_id", &self.my_peer_route_id)
            .field("network", &self.global_ctx.get_network_identity())
            .field("sessions", &self.sessions)
            .field("route_table", &self.route_table)
            .field("route_table_with_cost", &self.route_table_with_cost)
            .field("synced_route_info", &self.synced_route_info)
            .field("foreign_network_owner_map", &self.foreign_network_owner_map)
            .field(
                "foreign_network_my_peer_id_map",
                &self.foreign_network_my_peer_id_map,
            )
            .field(
                "cached_local_conn_map",
                &self.cached_local_conn_map.lock().unwrap(),
            )
            .finish()
    }
}

impl PeerRouteServiceImpl {
    fn new(my_peer_id: PeerId, global_ctx: ArcGlobalCtx) -> Self {
        PeerRouteServiceImpl {
            my_peer_id,
            my_peer_route_id: rand::random(),
            global_ctx,
            sessions: DashMap::new(),

            interface: Mutex::new(None),

            cost_calculator: std::sync::RwLock::new(Some(Box::new(DefaultRouteCostCalculator))),

            route_table: RouteTable::new(),
            route_table_with_cost: RouteTable::new(),
            foreign_network_owner_map: DashMap::new(),
            foreign_network_my_peer_id_map: DashMap::new(),

            synced_route_info: SyncedRouteInfo {
                peer_infos: RwLock::new(OrderedHashMap::new()),
                raw_peer_infos: DashMap::new(),
                conn_map: RwLock::new(OrderedHashMap::new()),
                foreign_network: DashMap::new(),
                group_trust_map: DashMap::new(),
                group_trust_map_cache: DashMap::new(),
                version: AtomicVersion::new(),
            },
            cached_local_conn_map: std::sync::Mutex::new(RouteConnBitmap::default()),
            cached_local_conn_map_version: AtomicVersion::new(),

            last_update_my_foreign_network: AtomicCell::new(None),

            peer_info_last_update: AtomicCell::new(std::time::Instant::now()),
        }
    }

    fn get_or_create_session(&self, dst_peer_id: PeerId) -> Arc<SyncRouteSession> {
        self.sessions
            .entry(dst_peer_id)
            .or_insert_with(|| Arc::new(SyncRouteSession::new(self.my_peer_id, dst_peer_id)))
            .value()
            .clone()
    }

    fn get_session(&self, dst_peer_id: PeerId) -> Option<Arc<SyncRouteSession>> {
        self.sessions.get(&dst_peer_id).map(|x| x.value().clone())
    }

    fn remove_session(&self, dst_peer_id: PeerId) {
        self.sessions.remove(&dst_peer_id);
        shrink_dashmap(&self.sessions, None);
    }

    fn list_session_peers(&self) -> Vec<PeerId> {
        self.sessions.iter().map(|x| *x.key()).collect()
    }

    async fn list_peers_from_interface<T: FromIterator<PeerId>>(&self) -> T {
        self.interface
            .lock()
            .await
            .as_ref()
            .unwrap()
            .list_peers()
            .await
            .into_iter()
            .collect()
    }

    fn update_my_peer_info(&self) -> bool {
        if self.synced_route_info.update_my_peer_info(
            self.my_peer_id,
            self.my_peer_route_id,
            &self.global_ctx,
        ) {
            self.update_route_table_and_cached_local_conn_bitmap();
            return true;
        }
        false
    }

    async fn update_my_conn_info(&self) -> bool {
        let connected_peers: BTreeSet<PeerId> = self.list_peers_from_interface().await;
        let updated = self
            .synced_route_info
            .update_my_conn_info(self.my_peer_id, connected_peers);

        if updated {
            self.update_route_table_and_cached_local_conn_bitmap();
        }

        updated
    }

    async fn update_my_foreign_network(&self) -> bool {
        let last_time = self.last_update_my_foreign_network.load();
        if last_time.is_some()
            && last_time.unwrap().elapsed().as_secs()
                < use_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC)
        {
            return false;
        }

        self.last_update_my_foreign_network
            .store(Some(std::time::Instant::now()));

        let foreign_networks = self
            .interface
            .lock()
            .await
            .as_ref()
            .unwrap()
            .list_foreign_networks()
            .await;

        // do not need update owner map because we always filter out my peer id.

        self.synced_route_info
            .update_my_foreign_network(self.my_peer_id, foreign_networks)
    }

    fn update_route_table(&self) {
        self.cost_calculator
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .begin_update();

        let calc_locked = self.cost_calculator.read().unwrap();

        self.route_table.build_from_synced_info(
            self.my_peer_id,
            &self.synced_route_info,
            NextHopPolicy::LeastHop,
            calc_locked.as_ref().unwrap(),
        );

        self.route_table_with_cost.build_from_synced_info(
            self.my_peer_id,
            &self.synced_route_info,
            NextHopPolicy::LeastCost,
            calc_locked.as_ref().unwrap(),
        );

        drop(calc_locked);

        self.cost_calculator
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .end_update();
    }

    fn update_foreign_network_owner_map(&self) {
        self.foreign_network_my_peer_id_map.clear();
        self.foreign_network_owner_map.clear();
        for item in self.synced_route_info.foreign_network.iter() {
            let key = item.key();
            let entry = item.value();
            if key.peer_id == self.my_peer_id
                || !self.route_table.peer_reachable(key.peer_id)
                || entry.foreign_peer_ids.is_empty()
            {
                continue;
            }
            let network_identity = NetworkIdentity {
                network_name: key.network_name.clone(),
                network_secret: None,
                network_secret_digest: Some(
                    entry
                        .network_secret_digest
                        .clone()
                        .try_into()
                        .unwrap_or_default(),
                ),
            };
            self.foreign_network_owner_map
                .entry(network_identity)
                .or_default()
                .push(entry.my_peer_id_for_this_network);

            self.foreign_network_my_peer_id_map.insert(
                (key.network_name.clone(), entry.my_peer_id_for_this_network),
                key.peer_id,
            );
        }
    }

    fn cost_calculator_need_update(&self) -> bool {
        self.cost_calculator
            .read()
            .unwrap()
            .as_ref()
            .map(|x| x.need_update())
            .unwrap_or(false)
    }

    fn update_route_table_and_cached_local_conn_bitmap(&self) {
        self.update_peer_info_last_update();

        // update route table first because we want to filter out unreachable peers.
        self.update_route_table();

        let synced_version = self.synced_route_info.version.get();

        // the conn_bitmap should contain complete list of directly connected peers.
        // use union of dst peers can preserve this property.
        let mut all_peer_ids: BTreeMap<PeerId, Version> = BTreeMap::new();
        let mut add_to_all_peer_ids = |peer_id: PeerId, version: Version| {
            all_peer_ids
                .entry(peer_id)
                .and_modify(|x| {
                    if *x < version {
                        *x = version;
                    }
                })
                .or_insert(version);
        };
        for item in self.synced_route_info.conn_map.read().iter() {
            let src_peer_id = *item.0;
            if !self.route_table.peer_reachable(src_peer_id) {
                continue;
            }
            add_to_all_peer_ids(src_peer_id, item.1.version.get());
            for dst_peer_id in item.1.connected_peers.iter() {
                add_to_all_peer_ids(*dst_peer_id, 0);
            }
        }

        let mut conn_bitmap = RouteConnBitmap {
            bitmap: vec![0; (all_peer_ids.len() * all_peer_ids.len()).div_ceil(8)],
            peer_ids: all_peer_ids
                .iter()
                .map(|x| PeerIdVersion {
                    peer_id: *x.0,
                    version: *x.1,
                })
                .collect(),
        };

        let locked_conn_map = self.synced_route_info.conn_map.read();
        let all_peer_ids = &conn_bitmap.peer_ids;
        for (peer_idx, peer_id_version) in all_peer_ids.iter().enumerate() {
            let Some(connected) = locked_conn_map.get(&peer_id_version.peer_id) else {
                continue;
            };

            for (idx, other_peer_id_version) in all_peer_ids.iter().enumerate() {
                if connected
                    .connected_peers
                    .contains(&other_peer_id_version.peer_id)
                {
                    let bit_idx = peer_idx * all_peer_ids.len() + idx;
                    conn_bitmap.bitmap[bit_idx / 8] |= 1 << (bit_idx % 8);
                }
            }
        }
        drop(locked_conn_map);

        let mut locked = self.cached_local_conn_map.lock().unwrap();
        if self
            .cached_local_conn_map_version
            .set_if_larger(synced_version)
        {
            *locked = conn_bitmap;
        }
    }

    fn build_route_info(&self, session: &SyncRouteSession) -> Option<Vec<RoutePeerInfo>> {
        let mut route_infos = Vec::new();
        let peer_infos = self.synced_route_info.peer_infos.read();
        let mut unreachable_peers_for_peer_info = session.unreachable_peers_for_peer_info.lock();
        let last_sync_succ_timestamp = session.last_sync_succ_timestamp.load();
        for (peer_id, peer_info) in peer_infos.iter().rev() {
            // stop iter if last_update of peer info is older than session.last_sync_succ_timestamp
            if let Some(last_update) = peer_info.last_update {
                let last_update = TryInto::<SystemTime>::try_into(last_update).unwrap();
                if last_sync_succ_timestamp.is_some_and(|t| last_update < t) {
                    tracing::debug!(
                        "ignore peer_info {:?} because last_update: {:?} is older than last_sync_succ_timestamp: {:?}, peer_infos_count: {}, my_peer_id: {:?}, session: {:?}",
                        peer_info,
                        last_update,
                        last_sync_succ_timestamp,
                        peer_infos.len(),
                        self.my_peer_id,
                        session
                    );
                    break;
                }
            }

            if session.check_saved_peer_info_update_to_date(peer_info.peer_id, peer_info.version) {
                continue;
            }

            // do not send unreachable peer info to dst peer.
            if !self.route_table.peer_reachable(*peer_id) {
                unreachable_peers_for_peer_info.insert(*peer_id, peer_info.version);
                continue;
            }

            route_infos.push(peer_info.clone());
        }

        unreachable_peers_for_peer_info.retain(|peer_id, version| {
            if session.check_saved_peer_info_update_to_date(*peer_id, *version) {
                // if saved peer info is up-to-date, forget this peer id.
                return false;
            }
            let Some(peer_info) = peer_infos.get(peer_id) else {
                // if not found in peer info map, forget this peer id.
                return false;
            };

            if self.route_table.peer_reachable(*peer_id) {
                route_infos.push(peer_info.clone());
            }

            // this round rpc may fail, so keep it and remove the id only when it's in dst_saved_map
            true
        });

        if route_infos.is_empty() {
            None
        } else {
            Some(route_infos)
        }
    }

    fn build_conn_peer_list(
        &self,
        session: &SyncRouteSession,
        estimated_size: &mut usize,
    ) -> Option<RouteConnPeerList> {
        let last_sync_succ_timestamp = session.last_sync_succ_timestamp.load();
        let mut peer_conn_infos = Vec::new();
        *estimated_size = 0;

        let conn_map = self.synced_route_info.conn_map.read();
        let mut unreachable_peers_for_conn_info = session.unreachable_peers_for_conn_info.lock();

        let mut add_to_conn_peer_list = |peer_id: PeerId, conn_info: &RouteConnInfo| {
            peer_conn_infos.push(PeerConnInfo {
                peer_id: Some(PeerIdVersion {
                    peer_id,
                    version: conn_info.version.get(),
                }),
                connected_peer_ids: conn_info.connected_peers.iter().copied().collect(),
            });
            *estimated_size += std::mem::size_of::<PeerIdVersion>()
                + conn_info.connected_peers.len() * std::mem::size_of::<PeerId>();
        };

        for (peer_id, conn_info) in conn_map.iter().rev() {
            // stop iter if last_update of conn info is older than session.last_sync_succ_timestamp
            let last_update = TryInto::<SystemTime>::try_into(conn_info.last_update).unwrap();
            if last_sync_succ_timestamp.is_some_and(|t| last_update < t) {
                tracing::debug!(
                        "ignore conn info {:?} because last_update: {:?} is older than last_sync_succ_timestamp: {:?}, conn_map count: {}, my_peer_id: {:?}, session: {:?}",
                        conn_info,
                        last_update,
                        last_sync_succ_timestamp,
                        conn_map.len(),
                        self.my_peer_id,
                        session
                    );
                break;
            }

            if session.check_saved_conn_version_update_to_date(*peer_id, conn_info.version.get()) {
                continue;
            }

            if !self.route_table.peer_reachable(*peer_id) {
                unreachable_peers_for_conn_info.insert(*peer_id, conn_info.version.get());
                continue;
            }

            add_to_conn_peer_list(*peer_id, conn_info);
        }

        unreachable_peers_for_conn_info.retain(|peer_id, version| {
            if session.check_saved_conn_version_update_to_date(*peer_id, *version) {
                // if saved conn info is up-to-date, forget this peer id.
                return false;
            }
            let Some(conn_info) = conn_map.get(peer_id) else {
                // if not found in peer info map, forget this peer id.
                return false;
            };

            if self.route_table.peer_reachable(*peer_id) {
                add_to_conn_peer_list(*peer_id, conn_info);
            }

            // this round rpc may fail, so keep it and remove the id only when it's in dst_saved_map
            true
        });

        if peer_conn_infos.is_empty() {
            return None;
        }

        Some(RouteConnPeerList { peer_conn_infos })
    }

    fn build_conn_bitmap(&self) -> RouteConnBitmap {
        self.cached_local_conn_map.lock().unwrap().clone()
    }

    fn estimate_conn_bitmap_size(&self) -> usize {
        let cached_conn_map = self.cached_local_conn_map.lock().unwrap();
        cached_conn_map.bitmap.len()
            + (cached_conn_map.peer_ids.len() * std::mem::size_of::<PeerIdVersion>())
    }

    fn build_foreign_network_info(
        &self,
        session: &SyncRouteSession,
    ) -> Option<RouteForeignNetworkInfos> {
        let mut foreign_networks = RouteForeignNetworkInfos::default();
        for item in self.synced_route_info.foreign_network.iter() {
            if session.check_saved_foreign_network_version_update_to_date(
                item.key(),
                item.value().version,
            ) {
                continue;
            }

            foreign_networks
                .infos
                .push(route_foreign_network_infos::Info {
                    key: Some(item.key().clone()),
                    value: Some(item.value().clone()),
                });
        }

        if foreign_networks.infos.is_empty() {
            None
        } else {
            Some(foreign_networks)
        }
    }

    async fn update_my_infos(&self) -> bool {
        let my_peer_info_updated = self.update_my_peer_info();
        let my_conn_info_updated = self.update_my_conn_info().await;
        let my_foreign_network_updated = self.update_my_foreign_network().await;
        if my_conn_info_updated || my_peer_info_updated {
            self.update_foreign_network_owner_map();
        }
        if my_peer_info_updated {
            self.update_peer_info_last_update();
        }
        my_peer_info_updated || my_conn_info_updated || my_foreign_network_updated
    }

    fn build_sync_request(
        &self,
        session: &SyncRouteSession,
        dst_peer_id: PeerId,
    ) -> (
        Option<Vec<RoutePeerInfo>>,
        Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo>,
        Option<RouteForeignNetworkInfos>,
    ) {
        let route_infos = self.build_route_info(session);
        let conn_info = self.build_conn_info(session, dst_peer_id);
        let foreign_network = self.build_foreign_network_info(session);

        (route_infos, conn_info, foreign_network)
    }

    fn build_conn_info(
        &self,
        session: &SyncRouteSession,
        dst_peer_id: PeerId,
    ) -> Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo> {
        // Check if destination peer supports selective peer list sync
        let dst_supports_peer_list = self
            .synced_route_info
            .peer_infos
            .read()
            .get(&dst_peer_id)
            .and_then(|p| p.feature_flag)
            .map(|x| x.support_conn_list_sync)
            .unwrap_or(false)
            || FORCE_USE_CONN_LIST.load(Ordering::Relaxed);

        // Both formats are supported, choose the more efficient one
        let mut conn_list_estimated_size = 0;
        let peer_list = self.build_conn_peer_list(session, &mut conn_list_estimated_size)?;
        let bitmap_size = self.estimate_conn_bitmap_size();

        if conn_list_estimated_size < bitmap_size && dst_supports_peer_list {
            Some(peer_list.into())
        } else {
            Some(self.build_conn_bitmap().into())
        }
    }

    fn clear_expired_peer(&self) {
        let now = SystemTime::now();
        let mut to_remove = Vec::new();
        for (peer_id, peer_info) in self.synced_route_info.peer_infos.read().iter() {
            if let Ok(d) = now.duration_since(peer_info.last_update.unwrap().try_into().unwrap()) {
                if d > REMOVE_DEAD_PEER_INFO_AFTER
                    || (d > REMOVE_UNREACHABLE_PEER_INFO_AFTER
                        && !self.route_table.peer_reachable(*peer_id))
                {
                    to_remove.push(*peer_id);
                }
            }
        }

        for p in to_remove.iter() {
            self.synced_route_info.remove_peer(*p);
        }

        // clear expired foreign network info
        let mut to_remove = Vec::new();
        for item in self.synced_route_info.foreign_network.iter() {
            let Some(since_last_update) = item
                .value()
                .last_update
                .and_then(|x| SystemTime::try_from(x).ok())
                .and_then(|x| now.duration_since(x).ok())
            else {
                to_remove.push(item.key().clone());
                continue;
            };

            if since_last_update > REMOVE_DEAD_PEER_INFO_AFTER {
                to_remove.push(item.key().clone());
            }
        }

        for p in to_remove.iter() {
            self.synced_route_info.foreign_network.remove(p);
        }

        self.route_table.clean_expired_route_info();
        self.route_table_with_cost.clean_expired_route_info();
    }

    fn build_sync_route_raw_req(
        req: &SyncRouteInfoRequest,
        raw_peer_infos: &DashMap<PeerId, DynamicMessage>,
    ) -> DynamicMessage {
        use prost_reflect::Value;

        let mut req_dynamic_msg = DynamicMessage::new(SyncRouteInfoRequest::default().descriptor());
        req_dynamic_msg.transcode_from(req).unwrap();

        let peer_infos = req.peer_infos.as_ref().map(|x| &x.items);
        if let Some(peer_infos) = peer_infos {
            let mut peer_info_raws = Vec::new();
            for peer_info in peer_infos.iter() {
                if let Some(info) = raw_peer_infos.get(&peer_info.peer_id) {
                    peer_info_raws.push(Value::Message(info.clone()));
                } else {
                    let mut p = DynamicMessage::new(RoutePeerInfo::default().descriptor());
                    p.transcode_from(peer_info).unwrap();
                    peer_info_raws.push(Value::Message(p));
                }
            }

            let mut peer_infos = DynamicMessage::new(RoutePeerInfos::default().descriptor());
            peer_infos.set_field_by_name("items", Value::List(peer_info_raws));

            req_dynamic_msg.set_field_by_name("peer_infos", Value::Message(peer_infos));
        }

        req_dynamic_msg
    }

    async fn sync_route_with_peer(
        &self,
        dst_peer_id: PeerId,
        peer_rpc: Arc<PeerRpcManager>,
        sync_as_initiator: bool,
    ) -> bool {
        let Some(session) = self.get_session(dst_peer_id) else {
            // if session not exist, exit the sync loop.
            return true;
        };

        let _session_lock = session.lock.lock();

        let my_peer_id = self.my_peer_id;

        let next_last_sync_succ_timestamp =
            self.synced_route_info.get_next_last_sync_succ_timestamp();
        let (peer_infos, conn_info, foreign_network) =
            self.build_sync_request(&session, dst_peer_id);
        if peer_infos.is_none()
            && conn_info.is_none()
            && foreign_network.is_none()
            && !session.need_sync_initiator_info.load(Ordering::Relaxed)
            && !(sync_as_initiator && session.we_are_initiator.load(Ordering::Relaxed))
        {
            return true;
        }

        tracing::debug!(?foreign_network, "sync_route request need send to peer. my_id {:?}, pper_id: {:?}, peer_infos: {:?}, conn_info: {:?}, synced_route_info: {:?} session: {:?}",
                       my_peer_id, dst_peer_id, peer_infos, conn_info, self.synced_route_info, session);

        session
            .need_sync_initiator_info
            .store(false, Ordering::Relaxed);

        let rpc_stub = peer_rpc
            .rpc_client()
            .scoped_client::<OspfRouteRpcClientFactory<BaseController>>(
                self.my_peer_id,
                dst_peer_id,
                self.global_ctx.get_network_name(),
            );

        let sync_route_info_req = SyncRouteInfoRequest {
            my_peer_id,
            my_session_id: session.my_session_id.load(Ordering::Relaxed),
            is_initiator: session.we_are_initiator.load(Ordering::Relaxed),
            peer_infos: peer_infos.clone().map(|x| RoutePeerInfos { items: x }),
            conn_info: conn_info.clone(),
            foreign_network_infos: foreign_network.clone(),
        };

        let mut ctrl = BaseController::default();
        ctrl.set_timeout_ms(3000);
        ctrl.set_raw_input(
            Self::build_sync_route_raw_req(
                &sync_route_info_req,
                &self.synced_route_info.raw_peer_infos,
            )
            .encode_to_vec()
            .into(),
        );

        drop(_session_lock);
        let ret = rpc_stub
            .sync_route_info(ctrl, SyncRouteInfoRequest::default())
            .await;
        let _session_lock = session.lock.lock();

        tracing::debug!(
            "sync_route_info resp: {:?}, req: {:?}, session: {:?}, my_info: {:?}, next_last_sync_succ_timestamp: {:?}",
            ret, sync_route_info_req, session, self.global_ctx.network, next_last_sync_succ_timestamp
        );

        if let Err(e) = &ret {
            tracing::error!(
                ?ret,
                ?my_peer_id,
                ?dst_peer_id,
                ?e,
                "sync_route_info failed"
            );
            session
                .need_sync_initiator_info
                .store(true, Ordering::Relaxed);
        } else {
            let resp = ret.as_ref().unwrap();
            if resp.error.is_some() {
                let err = resp.error.unwrap();
                if err == Error::DuplicatePeerId as i32 {
                    if !self.global_ctx.get_feature_flags().is_public_server {
                        panic!("duplicate peer id");
                    }
                } else {
                    tracing::error!(?ret, ?my_peer_id, ?dst_peer_id, "sync_route_info failed");
                    session
                        .need_sync_initiator_info
                        .store(true, Ordering::Relaxed);
                }
            } else {
                session.rpc_tx_count.fetch_add(1, Ordering::Relaxed);

                session
                    .dst_is_initiator
                    .store(resp.is_initiator, Ordering::Relaxed);

                session.update_dst_session_id(resp.session_id);

                if let Some(peer_infos) = &peer_infos {
                    session.update_dst_saved_peer_info_version(peer_infos, dst_peer_id);
                }

                // Update session saved versions based on the connection info format used
                if let Some(conn_info) = &conn_info {
                    session.update_dst_saved_conn_info_version(conn_info, dst_peer_id);
                }

                if let Some(foreign_network) = &foreign_network {
                    session.update_dst_saved_foreign_network_version(foreign_network, dst_peer_id);
                }

                session.update_last_sync_succ_timestamp(next_last_sync_succ_timestamp);
            }
        }
        false
    }

    fn update_peer_info_last_update(&self) {
        tracing::debug!(
            "update_peer_info_last_update, my_peer_id: {:?}, prev: {:?}, new: {:?}",
            self.my_peer_id,
            self.peer_info_last_update.load(),
            std::time::Instant::now()
        );
        self.peer_info_last_update.store(std::time::Instant::now());
    }

    fn get_peer_info_last_update(&self) -> std::time::Instant {
        self.peer_info_last_update.load()
    }

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>> {
        self.synced_route_info
            .group_trust_map_cache
            .get(&peer_id)
            .map(|groups| groups.value().clone())
            .unwrap_or_default()
    }

    fn clean_dst_saved_map(&self, dst_peer_id: PeerId) {
        let Some(session) = self.get_session(dst_peer_id) else {
            return;
        };

        session.clean_dst_saved_map();
    }
}

impl Drop for PeerRouteServiceImpl {
    fn drop(&mut self) {
        tracing::debug!(?self, "drop PeerRouteServiceImpl");
    }
}

#[derive(Clone)]
struct RouteSessionManager {
    service_impl: Weak<PeerRouteServiceImpl>,
    peer_rpc: Weak<PeerRpcManager>,

    sync_now_broadcast: tokio::sync::broadcast::Sender<()>,
}

impl Debug for RouteSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteSessionManager")
            .field("dump_sessions", &self.dump_sessions())
            .finish()
    }
}

fn get_raw_peer_infos(req_raw_input: &mut bytes::Bytes) -> Option<Vec<DynamicMessage>> {
    let sync_req_dynamic_msg =
        DynamicMessage::decode(SyncRouteInfoRequest::default().descriptor(), req_raw_input)
            .unwrap();

    let peer_infos = sync_req_dynamic_msg.get_field_by_name("peer_infos")?;

    let infos = peer_infos
        .as_message()?
        .get_field_by_name("items")?
        .as_list()?
        .iter()
        .map(|x| x.as_message().unwrap().clone())
        .collect();

    Some(infos)
}

#[async_trait::async_trait]
impl OspfRouteRpc for RouteSessionManager {
    type Controller = BaseController;
    async fn sync_route_info(
        &self,
        ctrl: BaseController,
        request: SyncRouteInfoRequest,
    ) -> Result<SyncRouteInfoResponse, rpc_types::error::Error> {
        let from_peer_id = request.my_peer_id;
        let from_session_id = request.my_session_id;
        let is_initiator = request.is_initiator;
        let peer_infos = request.peer_infos.map(|x| x.items);
        let conn_info = request.conn_info;
        let foreign_network = request.foreign_network_infos;
        let raw_peer_infos = if let Some(peer_infos_ref) = &peer_infos {
            let r = get_raw_peer_infos(&mut ctrl.get_raw_input().unwrap()).unwrap();
            assert_eq!(r.len(), peer_infos_ref.len());
            Some(r)
        } else {
            None
        };

        let ret = self
            .do_sync_route_info(
                from_peer_id,
                from_session_id,
                is_initiator,
                peer_infos,
                raw_peer_infos,
                conn_info,
                foreign_network,
            )
            .await;

        Ok(match ret {
            Ok(v) => v,
            Err(e) => SyncRouteInfoResponse {
                error: Some(e as i32),
                ..Default::default()
            },
        })
    }
}

impl RouteSessionManager {
    fn new(service_impl: Arc<PeerRouteServiceImpl>, peer_rpc: Arc<PeerRpcManager>) -> Self {
        RouteSessionManager {
            service_impl: Arc::downgrade(&service_impl),
            peer_rpc: Arc::downgrade(&peer_rpc),

            sync_now_broadcast: tokio::sync::broadcast::channel(100).0,
        }
    }

    async fn session_task(
        peer_rpc: Weak<PeerRpcManager>,
        service_impl: Weak<PeerRouteServiceImpl>,
        dst_peer_id: PeerId,
        mut sync_now: tokio::sync::broadcast::Receiver<()>,
    ) {
        let mut last_sync = Instant::now();
        let mut last_clean_dst_saved_map = Instant::now();
        loop {
            loop {
                let Some(service_impl) = service_impl.clone().upgrade() else {
                    return;
                };

                let Some(peer_rpc) = peer_rpc.clone().upgrade() else {
                    return;
                };

                // if we are initiator, we should ensure the dst has the session.
                let sync_as_initiator = if last_sync.elapsed().as_secs() > 10 {
                    last_sync = Instant::now();
                    true
                } else {
                    false
                };

                if service_impl
                    .sync_route_with_peer(dst_peer_id, peer_rpc.clone(), sync_as_initiator)
                    .await
                {
                    if last_clean_dst_saved_map.elapsed().as_secs() > 60 {
                        last_clean_dst_saved_map = Instant::now();
                        service_impl.clean_dst_saved_map(dst_peer_id);
                    }
                    break;
                }

                drop(service_impl);
                drop(peer_rpc);

                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            sync_now = sync_now.resubscribe();

            select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                ret = sync_now.recv() => if let Err(e) = ret {
                    tracing::debug!(?e, "session_task sync_now recv failed, ospf route may exit");
                    break;
                }
            }
        }
    }

    fn stop_session(&self, peer_id: PeerId) -> Result<(), Error> {
        tracing::warn!(?peer_id, "stop ospf sync session");
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };
        service_impl.remove_session(peer_id);
        Ok(())
    }

    fn start_session_task(&self, session: &SyncRouteSession) {
        if !session.task.is_running() {
            session.task.set_task(tokio::spawn(Self::session_task(
                self.peer_rpc.clone(),
                self.service_impl.clone(),
                session.dst_peer_id,
                self.sync_now_broadcast.subscribe(),
            )));
        }
    }

    fn get_or_start_session(&self, peer_id: PeerId) -> Result<Arc<SyncRouteSession>, Error> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };

        tracing::info!(?service_impl.my_peer_id, ?peer_id, "start ospf sync session");

        let session = service_impl.get_or_create_session(peer_id);
        self.start_session_task(&session);
        Ok(session)
    }

    async fn maintain_sessions(&self, service_impl: Arc<PeerRouteServiceImpl>) -> bool {
        let mut cur_dst_peer_id_to_initiate = None;
        let mut next_sleep_ms = 0;
        loop {
            let mut recv = self.sync_now_broadcast.subscribe();
            select! {
                _ = tokio::time::sleep(Duration::from_millis(next_sleep_ms)) => {}
                _ = recv.recv() => {}
            }

            let mut peers = service_impl.list_peers_from_interface::<Vec<_>>().await;
            peers.sort();

            let session_peers = self.list_session_peers();
            for peer_id in session_peers.iter() {
                if !peers.contains(peer_id) {
                    if Some(*peer_id) == cur_dst_peer_id_to_initiate {
                        cur_dst_peer_id_to_initiate = None;
                    }
                    let _ = self.stop_session(*peer_id);
                }
            }

            // find peer_ids that are not initiators.
            let initiator_candidates = peers
                .iter()
                .filter(|x| {
                    let Some(session) = service_impl.get_session(**x) else {
                        return true;
                    };
                    !session.dst_is_initiator.load(Ordering::Relaxed)
                })
                .copied()
                .collect::<Vec<_>>();

            if initiator_candidates.is_empty() {
                next_sleep_ms = 1000;
                continue;
            }

            let mut new_initiator_dst = None;
            // if any peer has NoPAT or OpenInternet stun type, we should use it.
            for peer_id in initiator_candidates.iter() {
                let Some(nat_type) = service_impl.route_table.get_udp_nat_type(*peer_id) else {
                    continue;
                };
                if nat_type == NatType::NoPat || nat_type == NatType::OpenInternet {
                    new_initiator_dst = Some(*peer_id);
                    break;
                }
            }
            if new_initiator_dst.is_none() {
                new_initiator_dst = Some(*initiator_candidates.first().unwrap());
            }

            if new_initiator_dst != cur_dst_peer_id_to_initiate {
                tracing::warn!(
                    "new_initiator: {:?}, prev: {:?}, my_id: {:?}",
                    new_initiator_dst,
                    cur_dst_peer_id_to_initiate,
                    service_impl.my_peer_id
                );
                // update initiator flag for previous session
                if let Some(cur_peer_id_to_initiate) = cur_dst_peer_id_to_initiate {
                    if let Some(session) = service_impl.get_session(cur_peer_id_to_initiate) {
                        session.update_initiator_flag(false);
                    }
                }

                cur_dst_peer_id_to_initiate = new_initiator_dst;
                // update initiator flag for new session
                let Ok(session) = self.get_or_start_session(new_initiator_dst.unwrap()) else {
                    tracing::warn!("get_or_start_session failed");
                    continue;
                };
                session.update_initiator_flag(true);
            }

            // clear sessions that are neither dst_initiator or we_are_initiator.
            for peer_id in session_peers.iter() {
                if let Some(session) = service_impl.get_session(*peer_id) {
                    if (session.dst_is_initiator.load(Ordering::Relaxed)
                        || session.we_are_initiator.load(Ordering::Relaxed)
                        || session.need_sync_initiator_info.load(Ordering::Relaxed))
                        && session.task.is_running()
                    {
                        continue;
                    }
                    let _ = self.stop_session(*peer_id);
                }
            }

            next_sleep_ms = 1000;
        }
    }

    fn list_session_peers(&self) -> Vec<PeerId> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return vec![];
        };

        service_impl.list_session_peers()
    }

    fn dump_sessions(&self) -> Result<String, Error> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };

        let mut ret = format!("my_peer_id: {:?}\n", service_impl.my_peer_id);
        for item in service_impl.sessions.iter() {
            ret += format!(
                "    session: {}, {}\n",
                item.key(),
                item.value().short_debug_string()
            )
            .as_str();
        }

        Ok(ret.to_string())
    }

    fn sync_now(&self, reason: &str) {
        let ret = self.sync_now_broadcast.send(());
        tracing::debug!(?ret, ?reason, "sync_now_broadcast.send");
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_sync_route_info(
        &self,
        from_peer_id: PeerId,
        from_session_id: SessionId,
        is_initiator: bool,
        peer_infos: Option<Vec<RoutePeerInfo>>,
        raw_peer_infos: Option<Vec<DynamicMessage>>,
        conn_info: Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo>,
        foreign_network: Option<RouteForeignNetworkInfos>,
    ) -> Result<SyncRouteInfoResponse, Error> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };

        let my_peer_id = service_impl.my_peer_id;
        let session = self.get_or_start_session(from_peer_id)?;

        let _session_lock = session.lock.lock();

        session.rpc_rx_count.fetch_add(1, Ordering::Relaxed);

        session.update_dst_session_id(from_session_id);

        let mut need_update_route_table = false;

        if let Some(peer_infos) = &peer_infos {
            service_impl.synced_route_info.update_peer_infos(
                my_peer_id,
                service_impl.my_peer_route_id,
                from_peer_id,
                peer_infos,
                raw_peer_infos.as_ref().unwrap(),
            )?;
            service_impl
                .synced_route_info
                .verify_and_update_group_trusts(
                    peer_infos,
                    &service_impl.global_ctx.get_acl_group_declarations(),
                );
            session.update_dst_saved_peer_info_version(peer_infos, from_peer_id);
            need_update_route_table = true;
        }

        if let Some(conn_info) = &conn_info {
            service_impl.synced_route_info.update_conn_info(conn_info);
            session.update_dst_saved_conn_info_version(conn_info, from_peer_id);
            need_update_route_table = true;
        }

        if need_update_route_table {
            service_impl.update_route_table_and_cached_local_conn_bitmap();
        }

        if let Some(foreign_network) = &foreign_network {
            service_impl
                .synced_route_info
                .update_foreign_network(foreign_network);
            session.update_dst_saved_foreign_network_version(foreign_network, from_peer_id);
        }

        if need_update_route_table || foreign_network.is_some() {
            service_impl.update_foreign_network_owner_map();
        }

        tracing::debug!(
            "handling sync_route_info rpc: from_peer_id: {:?}, is_initiator: {:?}, peer_infos: {:?}, conn_info: {:?}, synced_route_info: {:?} session: {:?}, new_route_table: {:?}",
            from_peer_id, is_initiator, peer_infos, conn_info, service_impl.synced_route_info, session, service_impl.route_table);

        session
            .dst_is_initiator
            .store(is_initiator, Ordering::Relaxed);
        let is_initiator = session.we_are_initiator.load(Ordering::Relaxed);
        let session_id = session.my_session_id.load(Ordering::Relaxed);

        self.sync_now("sync_route_info");

        Ok(SyncRouteInfoResponse {
            is_initiator,
            session_id,
            error: None,
        })
    }
}

pub struct PeerRoute {
    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,
    peer_rpc: Weak<PeerRpcManager>,

    service_impl: Arc<PeerRouteServiceImpl>,
    session_mgr: RouteSessionManager,

    tasks: std::sync::Mutex<JoinSet<()>>,
}

impl Debug for PeerRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRoute")
            .field("my_peer_id", &self.my_peer_id)
            .field("service_impl", &self.service_impl)
            .field("session_mgr", &self.session_mgr)
            .finish()
    }
}

impl PeerRoute {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        peer_rpc: Arc<PeerRpcManager>,
    ) -> Arc<Self> {
        let service_impl = Arc::new(PeerRouteServiceImpl::new(my_peer_id, global_ctx.clone()));
        let session_mgr = RouteSessionManager::new(service_impl.clone(), peer_rpc.clone());

        Arc::new(PeerRoute {
            my_peer_id,
            global_ctx,
            peer_rpc: Arc::downgrade(&peer_rpc),

            service_impl,
            session_mgr,

            tasks: std::sync::Mutex::new(JoinSet::new()),
        })
    }

    async fn clear_expired_peer(service_impl: Arc<PeerRouteServiceImpl>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            service_impl.clear_expired_peer();
            // TODO: use debug log level for this.
            tracing::debug!(?service_impl, "clear_expired_peer");
        }
    }

    async fn maintain_session_tasks(
        session_mgr: RouteSessionManager,
        service_impl: Arc<PeerRouteServiceImpl>,
    ) {
        session_mgr.maintain_sessions(service_impl).await;
    }

    async fn update_my_peer_info_routine(
        service_impl: Arc<PeerRouteServiceImpl>,
        session_mgr: RouteSessionManager,
    ) {
        let mut global_event_receiver = service_impl.global_ctx.subscribe();
        loop {
            if service_impl.update_my_infos().await {
                session_mgr.sync_now("update_my_infos");
            }

            if service_impl.cost_calculator_need_update() {
                tracing::debug!("cost_calculator_need_update");
                service_impl.synced_route_info.version.inc();
                service_impl.update_route_table();
            }

            select! {
                ev = global_event_receiver.recv() => {
                    tracing::info!(?ev, "global event received in update_my_peer_info_routine");
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }

    async fn start(&self) {
        let Some(peer_rpc) = self.peer_rpc.upgrade() else {
            return;
        };

        // make sure my_peer_id is in the peer_infos.
        self.service_impl.update_my_infos().await;

        peer_rpc.rpc_server().registry().register(
            OspfRouteRpcServer::new(self.session_mgr.clone()),
            &self.global_ctx.get_network_name(),
        );

        self.tasks
            .lock()
            .unwrap()
            .spawn(Self::update_my_peer_info_routine(
                self.service_impl.clone(),
                self.session_mgr.clone(),
            ));

        self.tasks
            .lock()
            .unwrap()
            .spawn(Self::maintain_session_tasks(
                self.session_mgr.clone(),
                self.service_impl.clone(),
            ));

        self.tasks
            .lock()
            .unwrap()
            .spawn(Self::clear_expired_peer(self.service_impl.clone()));
    }
}

impl Drop for PeerRoute {
    fn drop(&mut self) {
        tracing::debug!(
            self.my_peer_id,
            network = ?self.global_ctx.get_network_identity(),
            service = ?self.service_impl,
            "PeerRoute drop"
        );

        let Some(peer_rpc) = self.peer_rpc.upgrade() else {
            return;
        };

        peer_rpc.rpc_server().registry().unregister(
            OspfRouteRpcServer::new(self.session_mgr.clone()),
            &self.global_ctx.get_network_name(),
        );
    }
}

#[async_trait::async_trait]
impl Route for PeerRoute {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()> {
        *self.service_impl.interface.lock().await = Some(interface);
        self.start().await;
        Ok(1)
    }

    async fn close(&self) {}

    async fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<PeerId> {
        let route_table = &self.service_impl.route_table;
        route_table
            .get_next_hop(dst_peer_id)
            .map(|x| x.next_hop_peer_id)
    }

    async fn get_next_hop_with_policy(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        let route_table = if matches!(policy, NextHopPolicy::LeastCost) {
            &self.service_impl.route_table_with_cost
        } else {
            &self.service_impl.route_table
        };
        route_table
            .get_next_hop(dst_peer_id)
            .map(|x| x.next_hop_peer_id)
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        let route_table = &self.service_impl.route_table;
        let route_table_with_cost = &self.service_impl.route_table_with_cost;
        let mut routes = Vec::new();
        for item in route_table.peer_infos.iter() {
            if *item.key() == self.my_peer_id {
                continue;
            }
            let Some(next_hop_peer) = route_table.get_next_hop(*item.key()) else {
                continue;
            };
            let next_hop_peer_latency_first = route_table_with_cost.get_next_hop(*item.key());
            let mut route: crate::proto::api::instance::Route = item.value().clone().into();
            route.next_hop_peer_id = next_hop_peer.next_hop_peer_id;
            route.cost = next_hop_peer.path_len as i32;
            route.path_latency = next_hop_peer.path_latency;

            route.next_hop_peer_id_latency_first =
                next_hop_peer_latency_first.map(|x| x.next_hop_peer_id);
            route.cost_latency_first = next_hop_peer_latency_first.map(|x| x.path_len as i32);
            route.path_latency_latency_first = next_hop_peer_latency_first.map(|x| x.path_latency);

            route.feature_flag = item.feature_flag;

            routes.push(route);
        }
        routes
    }

    async fn get_peer_id_by_ipv4(&self, ipv4_addr: &Ipv4Addr) -> Option<PeerId> {
        let route_table = &self.service_impl.route_table;
        if let Some(p) = route_table.ipv4_peer_id_map.get(ipv4_addr) {
            return Some(p.peer_id);
        }

        // only get peer id for proxy when the dst ipv4 is not in same network with us
        if self
            .global_ctx
            .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
        {
            tracing::trace!(?ipv4_addr, "ipv4 addr is in same network with us");
            return None;
        }

        if let Some(peer_id) = route_table.get_peer_id_for_proxy(&IpAddr::V4(*ipv4_addr)) {
            return Some(peer_id);
        }

        tracing::debug!(?ipv4_addr, "no peer id for ipv4");
        None
    }

    async fn get_peer_id_by_ipv6(&self, ipv6_addr: &Ipv6Addr) -> Option<PeerId> {
        let route_table = &self.service_impl.route_table;
        if let Some(p) = route_table.ipv6_peer_id_map.get(ipv6_addr) {
            return Some(p.peer_id);
        }

        // only get peer id for proxy when the dst ipv4 is not in same network with us
        if self
            .global_ctx
            .is_ip_in_same_network(&std::net::IpAddr::V6(*ipv6_addr))
        {
            tracing::trace!(?ipv6_addr, "ipv6 addr is in same network with us");
            return None;
        }

        if let Some(peer_id) = route_table.get_peer_id_for_proxy(&IpAddr::V6(*ipv6_addr)) {
            return Some(peer_id);
        }

        tracing::debug!(?ipv6_addr, "no peer id for ipv6");
        None
    }

    async fn set_route_cost_fn(&self, _cost_fn: RouteCostCalculator) {
        *self.service_impl.cost_calculator.write().unwrap() = Some(_cost_fn);
        self.service_impl.synced_route_info.version.inc();
        self.service_impl.update_route_table();
    }

    async fn dump(&self) -> String {
        format!("{:#?}", self)
    }

    async fn list_foreign_network_info(&self) -> RouteForeignNetworkInfos {
        let route_table = &self.service_impl.route_table;
        let mut foreign_networks = RouteForeignNetworkInfos::default();
        for item in self
            .service_impl
            .synced_route_info
            .foreign_network
            .iter()
            .filter(|x| !x.value().foreign_peer_ids.is_empty())
            .filter(|x| route_table.peer_reachable(x.key().peer_id))
        {
            foreign_networks
                .infos
                .push(route_foreign_network_infos::Info {
                    key: Some(item.key().clone()),
                    value: Some(item.value().clone()),
                });
        }
        foreign_networks
    }

    async fn get_foreign_network_summary(&self) -> RouteForeignNetworkSummary {
        let mut info_map: BTreeMap<PeerId, route_foreign_network_summary::Info> = BTreeMap::new();
        for item in self.service_impl.synced_route_info.foreign_network.iter() {
            let entry = info_map.entry(item.key().peer_id).or_default();
            entry.network_count += 1;
            entry.peer_count += item.value().foreign_peer_ids.len() as u32;
        }
        RouteForeignNetworkSummary { info_map }
    }

    async fn list_peers_own_foreign_network(
        &self,
        network_identity: &NetworkIdentity,
    ) -> Vec<PeerId> {
        self.service_impl
            .foreign_network_owner_map
            .get(network_identity)
            .map(|x| x.clone())
            .unwrap_or_default()
    }

    async fn get_origin_my_peer_id(
        &self,
        network_name: &str,
        foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        self.service_impl
            .foreign_network_my_peer_id_map
            .get(&(network_name.to_string(), foreign_my_peer_id))
            .map(|x| *x)
    }

    async fn get_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        self.service_impl
            .route_table
            .peer_infos
            .get(&peer_id)
            .map(|x| x.clone())
    }

    async fn get_peer_info_last_update_time(&self) -> Instant {
        self.service_impl.get_peer_info_last_update()
    }

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>> {
        self.service_impl.get_peer_groups(peer_id)
    }
}

impl PeerPacketFilter for Arc<PeerRoute> {}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{atomic::Ordering, Arc},
        time::Duration,
    };

    use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Inet};
    use dashmap::DashMap;
    use prefix_trie::PrefixMap;
    use prost_reflect::{DynamicMessage, ReflectMessage};

    use crate::{
        common::{global_ctx::tests::get_mock_global_ctx, PeerId},
        connector::udp_hole_punch::tests::replace_stun_info_collector,
        peers::{
            create_packet_recv_chan,
            peer_manager::{PeerManager, RouteAlgoType},
            peer_ospf_route::{PeerIdVersion, PeerRouteServiceImpl, FORCE_USE_CONN_LIST},
            route_trait::{NextHopPolicy, Route, RouteCostCalculatorInterface},
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        proto::{
            common::NatType,
            peer_rpc::{RoutePeerInfo, RoutePeerInfos, SyncRouteInfoRequest},
        },
        tunnel::common::tests::wait_for_condition,
    };
    use prost::Message;

    use super::PeerRoute;

    async fn create_mock_route(peer_mgr: Arc<PeerManager>) -> Arc<PeerRoute> {
        let peer_route = PeerRoute::new(
            peer_mgr.my_peer_id(),
            peer_mgr.get_global_ctx(),
            peer_mgr.get_peer_rpc_mgr(),
        );
        peer_mgr.add_route(peer_route.clone()).await;
        peer_route
    }

    fn get_rpc_counter(route: &Arc<PeerRoute>, peer_id: PeerId) -> (u32, u32) {
        let session = route.service_impl.get_session(peer_id).unwrap();
        (
            session.rpc_tx_count.load(Ordering::Relaxed),
            session.rpc_rx_count.load(Ordering::Relaxed),
        )
    }

    fn get_is_initiator(route: &Arc<PeerRoute>, peer_id: PeerId) -> (bool, bool) {
        let session = route.service_impl.get_session(peer_id).unwrap();
        (
            session.we_are_initiator.load(Ordering::Relaxed),
            session.dst_is_initiator.load(Ordering::Relaxed),
        )
    }

    async fn create_mock_pmgr() -> Arc<PeerManager> {
        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            get_mock_global_ctx(),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.run().await.unwrap();
        peer_mgr
    }

    fn check_rpc_counter(route: &Arc<PeerRoute>, peer_id: PeerId, max_tx: u32, max_rx: u32) {
        let (tx1, rx1) = get_rpc_counter(route, peer_id);
        assert!(tx1 <= max_tx);
        assert!(rx1 <= max_rx);
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn ospf_route_2node(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);

        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;

        for r in [r_a.clone(), r_b.clone()].iter() {
            wait_for_condition(
                || async {
                    println!("route: {:?}", r.list_routes().await);
                    r.list_routes().await.len() == 1
                },
                Duration::from_secs(5),
            )
            .await;
        }

        tokio::time::sleep(Duration::from_secs(3)).await;

        assert_eq!(
            2,
            r_a.service_impl.synced_route_info.peer_infos.read().len()
        );
        assert_eq!(
            2,
            r_b.service_impl.synced_route_info.peer_infos.read().len()
        );

        for s in r_a.service_impl.sessions.iter() {
            assert!(s.value().task.is_running());
        }

        assert_eq!(
            r_a.service_impl
                .synced_route_info
                .peer_infos
                .read()
                .get(&p_a.my_peer_id())
                .unwrap()
                .version,
            r_a.service_impl
                .get_session(p_b.my_peer_id())
                .unwrap()
                .dst_saved_peer_info_versions
                .get(&p_a.my_peer_id())
                .unwrap()
                .value()
                .get()
        );

        assert_eq!((1, 1), get_rpc_counter(&r_a, p_b.my_peer_id()));
        assert_eq!((1, 1), get_rpc_counter(&r_b, p_a.my_peer_id()));

        let i_a = get_is_initiator(&r_a, p_b.my_peer_id());
        let i_b = get_is_initiator(&r_b, p_a.my_peer_id());
        assert_eq!(i_a.0, i_b.1);
        assert_eq!(i_b.0, i_a.1);

        println!("after drop p_b, r_b");

        drop(r_b);
        drop(p_b);

        wait_for_condition(
            || async { r_a.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || async { r_a.service_impl.sessions.is_empty() },
            Duration::from_secs(5),
        )
        .await;
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn ospf_route_multi_node(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);

        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_c.clone(), p_b.clone()).await;

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;
        let r_c = create_mock_route(p_c.clone()).await;

        for r in [r_a.clone(), r_b.clone(), r_c.clone()].iter() {
            wait_for_condition(
                || async { r.service_impl.synced_route_info.peer_infos.read().len() == 3 },
                Duration::from_secs(5),
            )
            .await;
        }

        connect_peer_manager(p_a.clone(), p_c.clone()).await;
        // for full-connected 3 nodes, the sessions between them may be a cycle or a line
        wait_for_condition(
            || async {
                let mut lens = vec![
                    r_a.service_impl.sessions.len(),
                    r_b.service_impl.sessions.len(),
                    r_c.service_impl.sessions.len(),
                ];
                lens.sort();

                lens == vec![1, 1, 2] || lens == vec![2, 2, 2]
            },
            Duration::from_secs(3),
        )
        .await;

        let p_d = create_mock_pmgr().await;
        let r_d = create_mock_route(p_d.clone()).await;
        connect_peer_manager(p_d.clone(), p_a.clone()).await;
        connect_peer_manager(p_d.clone(), p_b.clone()).await;
        connect_peer_manager(p_d.clone(), p_c.clone()).await;

        // find the smallest peer_id, which should be a center node
        let mut all_route = [r_a.clone(), r_b.clone(), r_c.clone(), r_d.clone()];
        all_route.sort_by(|a, b| a.my_peer_id.cmp(&b.my_peer_id));
        let mut all_peer_mgr = [p_a.clone(), p_b.clone(), p_c.clone(), p_d.clone()];
        all_peer_mgr.sort_by_key(|a| a.my_peer_id());

        wait_for_condition(
            || async { all_route[0].service_impl.sessions.len() == 3 },
            Duration::from_secs(3),
        )
        .await;

        for r in all_route.iter() {
            println!("session: {}", r.session_mgr.dump_sessions().unwrap());
        }

        let p_e = create_mock_pmgr().await;
        let r_e = create_mock_route(p_e.clone()).await;
        let last_p = all_peer_mgr.last().unwrap();
        connect_peer_manager(p_e.clone(), last_p.clone()).await;

        wait_for_condition(
            || async { r_e.session_mgr.list_session_peers().len() == 1 },
            Duration::from_secs(3),
        )
        .await;

        for s in r_e.service_impl.sessions.iter() {
            assert!(s.value().task.is_running());
        }

        tokio::time::sleep(Duration::from_secs(2)).await;

        check_rpc_counter(&r_e, last_p.my_peer_id(), 2, 2);

        for r in all_route.iter() {
            if r.my_peer_id != last_p.my_peer_id() {
                wait_for_condition(
                    || async {
                        r.get_next_hop(p_e.my_peer_id()).await == Some(last_p.my_peer_id())
                    },
                    Duration::from_secs(3),
                )
                .await;
            } else {
                wait_for_condition(
                    || async { r.get_next_hop(p_e.my_peer_id()).await == Some(p_e.my_peer_id()) },
                    Duration::from_secs(3),
                )
                .await;
            }
        }
    }

    async fn check_route_sanity(p: &Arc<PeerRoute>, routable_peers: Vec<Arc<PeerManager>>) {
        let synced_info = &p.service_impl.synced_route_info;
        for routable_peer in routable_peers.iter() {
            // check conn map
            let conns = {
                let guard = synced_info.conn_map.read();
                guard.get(&routable_peer.my_peer_id()).cloned().unwrap()
            };

            assert_eq!(
                conns.connected_peers,
                routable_peer
                    .get_peer_map()
                    .list_peers()
                    .await
                    .into_iter()
                    .collect::<BTreeSet<PeerId>>()
            );

            // check peer infos
            let peer_info = synced_info
                .peer_infos
                .read()
                .get(&routable_peer.my_peer_id())
                .cloned()
                .unwrap();
            assert_eq!(peer_info.peer_id, routable_peer.my_peer_id());
        }
    }

    async fn print_routes(peers: Vec<Arc<PeerRoute>>) {
        for p in peers.iter() {
            println!("p:{:?}, route: {:#?}", p.my_peer_id, p.list_routes().await);
        }
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn ospf_route_3node_disconnect(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_c.clone(), p_b.clone()).await;

        let mgrs = vec![p_a.clone(), p_b.clone(), p_c.clone()];

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;
        let r_c = create_mock_route(p_c.clone()).await;

        for r in [r_a.clone(), r_b.clone(), r_c.clone()].iter() {
            wait_for_condition(
                || async { r.service_impl.synced_route_info.peer_infos.read().len() == 3 },
                Duration::from_secs(5),
            )
            .await;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        print_routes(vec![r_a.clone(), r_b.clone(), r_c.clone()]).await;
        check_route_sanity(&r_a, mgrs.clone()).await;
        check_route_sanity(&r_b, mgrs.clone()).await;
        check_route_sanity(&r_c, mgrs.clone()).await;

        assert_eq!(2, r_a.list_routes().await.len());

        drop(mgrs);
        drop(r_c);
        drop(p_c);

        for r in [r_a.clone(), r_b.clone()].iter() {
            wait_for_condition(
                || async { r.list_routes().await.len() == 1 },
                Duration::from_secs(5),
            )
            .await;
        }
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn peer_reconnect(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;

        connect_peer_manager(p_a.clone(), p_b.clone()).await;

        wait_for_condition(
            || async { r_a.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(1, r_b.list_routes().await.len());

        check_rpc_counter(&r_a, p_b.my_peer_id(), 2, 2);

        p_a.get_peer_map()
            .close_peer(p_b.my_peer_id())
            .await
            .unwrap();
        wait_for_condition(
            || async { r_a.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;

        // reconnect
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        wait_for_condition(
            || async { r_a.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        // wait session init
        tokio::time::sleep(Duration::from_secs(1)).await;

        println!("session: {:?}", r_a.session_mgr.dump_sessions());
        check_rpc_counter(&r_a, p_b.my_peer_id(), 2, 2);
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn test_cost_calculator(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        let p_d = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_a.clone(), p_c.clone()).await;
        connect_peer_manager(p_d.clone(), p_b.clone()).await;
        connect_peer_manager(p_d.clone(), p_c.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        let _r_a = create_mock_route(p_a.clone()).await;
        let _r_b = create_mock_route(p_b.clone()).await;
        let _r_c = create_mock_route(p_c.clone()).await;
        let r_d = create_mock_route(p_d.clone()).await;

        // in normal mode, packet from p_c should directly forward to p_a
        wait_for_condition(
            || async { (r_d.get_next_hop(p_a.my_peer_id()).await).is_some() },
            Duration::from_secs(5),
        )
        .await;

        struct TestCostCalculator {
            p_a_peer_id: PeerId,
            p_b_peer_id: PeerId,
            p_c_peer_id: PeerId,
            p_d_peer_id: PeerId,
        }

        impl RouteCostCalculatorInterface for TestCostCalculator {
            fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
                if src == self.p_d_peer_id && dst == self.p_b_peer_id {
                    return 100;
                }

                if src == self.p_d_peer_id && dst == self.p_c_peer_id {
                    return 1;
                }

                if src == self.p_c_peer_id && dst == self.p_a_peer_id {
                    return 101;
                }

                if src == self.p_b_peer_id && dst == self.p_a_peer_id {
                    return 1;
                }

                if src == self.p_c_peer_id && dst == self.p_b_peer_id {
                    return 2;
                }

                1
            }
        }

        r_d.set_route_cost_fn(Box::new(TestCostCalculator {
            p_a_peer_id: p_a.my_peer_id(),
            p_b_peer_id: p_b.my_peer_id(),
            p_c_peer_id: p_c.my_peer_id(),
            p_d_peer_id: p_d.my_peer_id(),
        }))
        .await;

        // after set cost, packet from p_c should forward to p_b first
        wait_for_condition(
            || async {
                r_d.get_next_hop_with_policy(p_a.my_peer_id(), NextHopPolicy::LeastCost)
                    .await
                    == Some(p_c.my_peer_id())
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || async {
                r_d.get_next_hop_with_policy(p_a.my_peer_id(), NextHopPolicy::LeastHop)
                    .await
                    == Some(p_b.my_peer_id())
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn test_raw_peer_info(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let mut req = SyncRouteInfoRequest::default();
        let raw_info_map: DashMap<PeerId, DynamicMessage> = DashMap::new();

        req.peer_infos = Some(RoutePeerInfos {
            items: vec![RoutePeerInfo {
                peer_id: 1,
                ..Default::default()
            }],
        });

        let mut raw_req = DynamicMessage::new(RoutePeerInfo::default().descriptor());
        raw_req
            .transcode_from(&req.peer_infos.as_ref().unwrap().items[0])
            .unwrap();
        raw_info_map.insert(1, raw_req);

        let out = PeerRouteServiceImpl::build_sync_route_raw_req(&req, &raw_info_map);

        let out_bytes = out.encode_to_vec();

        let req2 = SyncRouteInfoRequest::decode(out_bytes.as_slice()).unwrap();

        assert_eq!(req, req2);
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn test_peer_id_map_override(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        let ip: Ipv4Inet = "10.0.0.1/24".parse().unwrap();
        let ipv6: Ipv6Inet = "2001:db8::1/64".parse().unwrap();
        let proxy: Ipv4Cidr = "10.3.0.0/24".parse().unwrap();
        let check_route_peer_id = async |p: Arc<PeerManager>| {
            let p = p.clone();
            wait_for_condition(
                || async {
                    p_a.get_route().get_peer_id_by_ipv4(&ip.address()).await == Some(p.my_peer_id())
                        && p_a.get_route().get_peer_id_by_ipv6(&ipv6.address()).await
                            == Some(p.my_peer_id())
                        && p_a
                            .get_route()
                            .get_peer_id_by_ipv4(&proxy.first_address())
                            .await
                            == Some(p.my_peer_id())
                },
                Duration::from_secs(5),
            )
            .await;
        };

        p_c.get_global_ctx().set_ipv4(Some(ip));
        p_c.get_global_ctx().set_ipv6(Some(ipv6));
        p_c.get_global_ctx()
            .config
            .add_proxy_cidr(proxy, None)
            .unwrap();
        check_route_peer_id(p_c.clone()).await;

        p_b.get_global_ctx().set_ipv4(Some(ip));
        p_b.get_global_ctx().set_ipv6(Some(ipv6));
        p_b.get_global_ctx()
            .config
            .add_proxy_cidr(proxy, None)
            .unwrap();
        check_route_peer_id(p_b.clone()).await;

        p_b.get_global_ctx()
            .set_ipv4(Some("10.0.0.2/24".parse().unwrap()));
        p_b.get_global_ctx()
            .set_ipv6(Some("2001:db8::2/64".parse().unwrap()));
        p_b.get_global_ctx().config.remove_proxy_cidr(proxy);
        check_route_peer_id(p_c.clone()).await;
    }
    #[rstest::rstest]
    #[tokio::test]
    async fn test_subnet_proxy_conflict(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        // Create three peer managers: A, B, C
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        // Connect A-B-C in a line topology
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        // Create routes for testing
        let route_a = p_a.get_route();
        let route_b = p_b.get_route();

        // Define the proxy CIDR that will be used by both A and B
        let proxy_cidr: Ipv4Cidr = "192.168.100.0/24".parse().unwrap();
        let test_ip = proxy_cidr.first_address();

        let mut cidr_peer_id_map: PrefixMap<Ipv4Cidr, PeerIdVersion> = PrefixMap::new();
        cidr_peer_id_map.insert(
            proxy_cidr,
            PeerIdVersion {
                peer_id: p_c.my_peer_id(),
                version: 0,
            },
        );
        assert_eq!(
            cidr_peer_id_map
                .get_lpm(&Ipv4Cidr::new(test_ip, 32).unwrap())
                .map(|v| v.1.peer_id)
                .unwrap_or(0),
            p_c.my_peer_id(),
        );

        // First, add proxy CIDR to node C to establish a baseline route
        p_c.get_global_ctx()
            .config
            .add_proxy_cidr(proxy_cidr, None)
            .unwrap();

        // Wait for route convergence - A should route to C for the proxy CIDR
        wait_for_condition(
            || async {
                let peer_id_for_proxy = route_a.get_peer_id_by_ipv4(&test_ip).await;
                peer_id_for_proxy == Some(p_c.my_peer_id())
            },
            Duration::from_secs(10),
        )
        .await;

        // Now add the same proxy CIDR to node A (creating a conflict)
        p_a.get_global_ctx()
            .config
            .add_proxy_cidr(proxy_cidr, None)
            .unwrap();

        // Wait for route convergence - A should now route to itself for the proxy CIDR
        wait_for_condition(
            || async { route_a.get_peer_id_by_ipv4(&test_ip).await == Some(p_a.my_peer_id()) },
            Duration::from_secs(10),
        )
        .await;

        // Also add the same proxy CIDR to node B (creating another conflict)
        p_b.get_global_ctx()
            .config
            .add_proxy_cidr(proxy_cidr, None)
            .unwrap();

        // Wait for route convergence - B should route to itself for the proxy CIDR
        wait_for_condition(
            || async { route_b.get_peer_id_by_ipv4(&test_ip).await == Some(p_b.my_peer_id()) },
            Duration::from_secs(5),
        )
        .await;

        // Final verification: A should still route to itself even with multiple conflicts
        assert_eq!(
            route_a.get_peer_id_by_ipv4(&test_ip).await,
            Some(p_a.my_peer_id())
        );

        // remove proxy on A, a should route to B
        p_a.get_global_ctx().config.remove_proxy_cidr(proxy_cidr);
        wait_for_condition(
            || async {
                let peer_id_for_proxy = route_a.get_peer_id_by_ipv4(&test_ip).await;
                peer_id_for_proxy == Some(p_b.my_peer_id())
            },
            Duration::from_secs(10),
        )
        .await;
    }
    #[rstest::rstest]
    #[tokio::test]
    async fn test_connect_at_different_time(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        // Create three peer managers: A, B, C
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        // Connect A-B-C in a line topology
        connect_peer_manager(p_a.clone(), p_b.clone()).await;

        wait_route_appear(p_a.clone(), p_b.clone()).await.unwrap();

        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
    }
}
