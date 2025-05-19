use std::{
    collections::BTreeSet,
    fmt::Debug,
    hash::RandomState,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Weak,
    },
    time::{Duration, Instant, SystemTime},
};

use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use petgraph::{
    algo::{all_simple_paths, astar, dijkstra},
    graph::NodeIndex,
    Directed, Graph,
};
use prost::Message;
use prost_reflect::{DynamicMessage, ReflectMessage};
use serde::{Deserialize, Serialize};
use tokio::{
    select,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};

use crate::{
    common::{
        config::NetworkIdentity, constants::EASYTIER_VERSION, global_ctx::ArcGlobalCtx,
        stun::StunInfoCollectorTrait, PeerId,
    },
    peers::route_trait::{Route, RouteInterfaceBox},
    proto::{
        common::{Ipv4Inet, NatType, PeerFeatureFlag, StunInfo},
        peer_rpc::{
            route_foreign_network_infos, ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey,
            OspfRouteRpc, OspfRouteRpcClientFactory, OspfRouteRpcServer, PeerIdVersion,
            RouteForeignNetworkInfos, RoutePeerInfo, RoutePeerInfos, SyncRouteInfoError,
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
static AVOID_RELAY_COST: i32 = i32::MAX / 512;

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

    fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn set_if_larger(&self, version: Version) {
        if self.get() < version {
            self.set(version);
        }
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
            udp_stun_info: 0,
            last_update: Some(SystemTime::now().into()),
            version: 0,
            easytier_version: EASYTIER_VERSION.to_string(),
            feature_flag: None,
            peer_route_id: 0,
            network_length: 24,
        }
    }

    pub fn update_self(
        &self,
        my_peer_id: PeerId,
        peer_route_id: u64,
        global_ctx: &ArcGlobalCtx,
    ) -> Self {
        let mut new = Self {
            peer_id: my_peer_id,
            inst_id: Some(global_ctx.get_id().into()),
            cost: 0,
            ipv4_addr: global_ctx.get_ipv4().map(|x| x.address().into()),
            proxy_cidrs: global_ctx
                .get_proxy_cidrs()
                .iter()
                .map(|x| x.to_string())
                .chain(global_ctx.get_vpn_portal_cidr().map(|x| x.to_string()))
                .collect(),
            hostname: Some(global_ctx.get_hostname()),
            udp_stun_info: global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .udp_nat_type,
            // following fields do not participate in comparison.
            last_update: self.last_update,
            version: self.version,

            easytier_version: EASYTIER_VERSION.to_string(),
            feature_flag: Some(global_ctx.get_feature_flags()),
            peer_route_id,
            network_length: global_ctx
                .get_ipv4()
                .map(|x| x.network_length() as u32)
                .unwrap_or(24),
        };

        let need_update_periodically = if let Ok(Ok(d)) =
            SystemTime::try_from(new.last_update.unwrap()).map(|x| x.elapsed())
        {
            d > UPDATE_PEER_INFO_PERIOD
        } else {
            true
        };

        if new != *self || need_update_periodically {
            new.last_update = Some(SystemTime::now().into());
            new.version += 1;
        }

        new
    }
}

impl Into<crate::proto::cli::Route> for RoutePeerInfo {
    fn into(self) -> crate::proto::cli::Route {
        let network_length = if self.network_length == 0 {
            24
        } else {
            self.network_length
        };

        crate::proto::cli::Route {
            peer_id: self.peer_id,
            ipv4_addr: if let Some(ipv4_addr) = self.ipv4_addr {
                Some(Ipv4Inet {
                    address: Some(ipv4_addr.into()),
                    network_length,
                })
            } else {
                None
            },
            next_hop_peer_id: 0, // next_hop_peer_id is calculated in RouteTable.
            cost: 0,             // cost is calculated in RouteTable.
            path_latency: 0,     // path_latency is calculated in RouteTable.
            proxy_cidrs: self.proxy_cidrs.clone(),
            hostname: self.hostname.unwrap_or_default(),
            stun_info: {
                let mut stun_info = StunInfo::default();
                if let Ok(udp_nat_type) = NatType::try_from(self.udp_stun_info as i32) {
                    stun_info.set_udp_nat_type(udp_nat_type);
                }
                Some(stun_info)
            },
            inst_id: self.inst_id.map(|x| x.to_string()).unwrap_or_default(),
            version: self.easytier_version,
            feature_flag: self.feature_flag,

            next_hop_peer_id_latency_first: None,
            cost_latency_first: None,
            path_latency_latency_first: None,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
struct RouteConnBitmap {
    peer_ids: Vec<(PeerId, Version)>,
    bitmap: Vec<u8>,
}

impl Into<crate::proto::peer_rpc::RouteConnBitmap> for RouteConnBitmap {
    fn into(self) -> crate::proto::peer_rpc::RouteConnBitmap {
        crate::proto::peer_rpc::RouteConnBitmap {
            peer_ids: self
                .peer_ids
                .into_iter()
                .map(|x| PeerIdVersion {
                    peer_id: x.0,
                    version: x.1,
                })
                .collect(),
            bitmap: self.bitmap,
        }
    }
}

impl From<crate::proto::peer_rpc::RouteConnBitmap> for RouteConnBitmap {
    fn from(v: crate::proto::peer_rpc::RouteConnBitmap) -> Self {
        RouteConnBitmap {
            peer_ids: v
                .peer_ids
                .into_iter()
                .map(|x| (x.peer_id, x.version))
                .collect(),
            bitmap: v.bitmap,
        }
    }
}

impl RouteConnBitmap {
    fn new() -> Self {
        RouteConnBitmap {
            peer_ids: Vec::new(),
            bitmap: Vec::new(),
        }
    }

    fn get_bit(&self, idx: usize) -> bool {
        let byte_idx = idx / 8;
        let bit_idx = idx % 8;
        let byte = self.bitmap[byte_idx];
        (byte >> bit_idx) & 1 == 1
    }

    fn get_connected_peers(&self, peer_idx: usize) -> BTreeSet<PeerId> {
        let mut connected_peers = BTreeSet::new();
        for (idx, (peer_id, _)) in self.peer_ids.iter().enumerate() {
            if self.get_bit(peer_idx * self.peer_ids.len() + idx) {
                connected_peers.insert(*peer_id);
            }
        }
        connected_peers
    }
}

type Error = SyncRouteInfoError;

// constructed with all infos synced from all peers.
#[derive(Debug)]
struct SyncedRouteInfo {
    peer_infos: DashMap<PeerId, RoutePeerInfo>,
    // prost doesn't support unknown fields, so we use DynamicMessage to store raw infos and progate them to other peers.
    raw_peer_infos: DashMap<PeerId, DynamicMessage>,
    conn_map: DashMap<PeerId, (BTreeSet<PeerId>, AtomicVersion)>,
    foreign_network: DashMap<ForeignNetworkRouteInfoKey, ForeignNetworkRouteInfoEntry>,
}

impl SyncedRouteInfo {
    fn get_connected_peers<T: FromIterator<PeerId>>(&self, peer_id: PeerId) -> Option<T> {
        self.conn_map
            .get(&peer_id)
            .map(|x| x.0.clone().iter().map(|x| *x).collect())
    }

    fn remove_peer(&self, peer_id: PeerId) {
        tracing::warn!(?peer_id, "remove_peer from synced_route_info");
        self.peer_infos.remove(&peer_id);
        self.raw_peer_infos.remove(&peer_id);
        self.conn_map.remove(&peer_id);
        self.foreign_network.retain(|k, _| k.peer_id != peer_id);
    }

    fn fill_empty_peer_info(&self, peer_ids: &BTreeSet<PeerId>) {
        for peer_id in peer_ids {
            self.peer_infos
                .entry(*peer_id)
                .or_insert_with(|| RoutePeerInfo::new());

            self.conn_map
                .entry(*peer_id)
                .or_insert_with(|| (BTreeSet::new(), AtomicVersion::new()));
        }
    }

    fn get_peer_info_version_with_default(&self, peer_id: PeerId) -> Version {
        self.peer_infos
            .get(&peer_id)
            .map(|x| x.version)
            .unwrap_or(0)
    }

    fn get_avoid_relay_data(&self, peer_id: PeerId) -> bool {
        // if avoid relay, just set all outgoing edges to a large value: AVOID_RELAY_COST.
        self.peer_infos
            .get(&peer_id)
            .and_then(|x| x.value().feature_flag)
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
        peer_infos: &Vec<RoutePeerInfo>,
        raw_peer_infos: &Vec<DynamicMessage>,
    ) -> Result<(), Error> {
        for (idx, route_info) in peer_infos.iter().enumerate() {
            let mut route_info = route_info.clone();
            let raw_route_info = &raw_peer_infos[idx];
            self.check_duplicate_peer_id(
                my_peer_id,
                my_peer_route_id,
                dst_peer_id,
                if route_info.peer_id == dst_peer_id {
                    self.peer_infos.get(&dst_peer_id).map(|x| x.peer_route_id)
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

            // time between peers may not be synchronized, so update last_update to local now.
            // note only last_update with larger version will be updated to local saved peer info.
            route_info.last_update = Some(SystemTime::now().into());

            self.peer_infos
                .entry(route_info.peer_id)
                .and_modify(|old_entry| {
                    if route_info.version > old_entry.version {
                        self.raw_peer_infos
                            .insert(route_info.peer_id, raw_route_info.clone());
                        *old_entry = route_info.clone();
                    }
                })
                .or_insert_with(|| {
                    self.raw_peer_infos
                        .insert(route_info.peer_id, raw_route_info.clone());
                    route_info.clone()
                });
        }
        Ok(())
    }

    fn update_conn_map(&self, conn_bitmap: &RouteConnBitmap) {
        self.fill_empty_peer_info(&conn_bitmap.peer_ids.iter().map(|x| x.0).collect());

        for (peer_idx, (peer_id, version)) in conn_bitmap.peer_ids.iter().enumerate() {
            assert!(self.peer_infos.contains_key(peer_id));
            let connceted_peers = conn_bitmap.get_connected_peers(peer_idx);
            self.fill_empty_peer_info(&connceted_peers);

            self.conn_map
                .entry(*peer_id)
                .and_modify(|(old_conn_bitmap, old_version)| {
                    if *version > old_version.get() {
                        *old_conn_bitmap = conn_bitmap.get_connected_peers(peer_idx);
                        old_version.set(*version);
                    }
                })
                .or_insert_with(|| {
                    (
                        conn_bitmap.get_connected_peers(peer_idx),
                        version.clone().into(),
                    )
                });
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
        let mut old = self
            .peer_infos
            .entry(my_peer_id)
            .or_insert(RoutePeerInfo::new());
        let new = old.update_self(my_peer_id, my_peer_route_id, &global_ctx);
        let new_version = new.version;
        let old_version = old.version;
        *old = new;

        new_version != old_version
    }

    fn update_my_conn_info(&self, my_peer_id: PeerId, connected_peers: BTreeSet<PeerId>) -> bool {
        self.fill_empty_peer_info(&connected_peers);

        let mut my_conn_info = self
            .conn_map
            .entry(my_peer_id)
            .or_insert((BTreeSet::new(), AtomicVersion::new()));

        if connected_peers == my_conn_info.value().0 {
            false
        } else {
            let _ = std::mem::replace(&mut my_conn_info.value_mut().0, connected_peers);
            my_conn_info.value().1.inc();
            true
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
                            .unwrap()
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
                .and_modify(|v| panic!("key should not exist, {:?}", v))
                .or_insert_with(|| {
                    let mut v = item.value().clone();
                    v.version = now_version;
                    v
                });
            updated = true;
        }

        updated
    }

    fn is_peer_bidirectly_connected(&self, src_peer_id: PeerId, dst_peer_id: PeerId) -> bool {
        self.conn_map
            .get(&src_peer_id)
            .map(|x| x.0.contains(&dst_peer_id))
            .unwrap_or(false)
    }

    fn is_peer_directly_connected(&self, src_peer_id: PeerId, dst_peer_id: PeerId) -> bool {
        return self.is_peer_bidirectly_connected(src_peer_id, dst_peer_id)
            || self.is_peer_bidirectly_connected(dst_peer_id, src_peer_id);
    }
}

type PeerGraph = Graph<PeerId, i32, Directed>;
type PeerIdToNodexIdxMap = DashMap<PeerId, NodeIndex>;
#[derive(Debug, Clone, Copy)]
struct NextHopInfo {
    next_hop_peer_id: PeerId,
    path_latency: i32,
    path_len: usize, // path includes src and dst.
}
// dst_peer_id -> (next_hop_peer_id, cost, path_len)
type NextHopMap = DashMap<PeerId, NextHopInfo>;

// computed with SyncedRouteInfo. used to get next hop.
#[derive(Debug)]
struct RouteTable {
    peer_infos: DashMap<PeerId, RoutePeerInfo>,
    next_hop_map: NextHopMap,
    ipv4_peer_id_map: DashMap<Ipv4Addr, PeerId>,
    cidr_peer_id_map: DashMap<cidr::IpCidr, PeerId>,
}

impl RouteTable {
    fn new() -> Self {
        RouteTable {
            peer_infos: DashMap::new(),
            next_hop_map: DashMap::new(),
            ipv4_peer_id_map: DashMap::new(),
            cidr_peer_id_map: DashMap::new(),
        }
    }

    fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<NextHopInfo> {
        self.next_hop_map.get(&dst_peer_id).map(|x| *x)
    }

    fn peer_reachable(&self, peer_id: PeerId) -> bool {
        self.next_hop_map.contains_key(&peer_id)
    }

    fn get_nat_type(&self, peer_id: PeerId) -> Option<NatType> {
        self.peer_infos
            .get(&peer_id)
            .map(|x| NatType::try_from(x.udp_stun_info as i32).unwrap_or_default())
    }

    fn build_peer_graph_from_synced_info<T: RouteCostCalculatorInterface>(
        peers: Vec<PeerId>,
        synced_info: &SyncedRouteInfo,
        cost_calc: &mut T,
    ) -> (PeerGraph, PeerIdToNodexIdxMap) {
        let mut graph: PeerGraph = Graph::new();
        let peer_id_to_node_index = PeerIdToNodexIdxMap::new();
        for peer_id in peers.iter() {
            peer_id_to_node_index.insert(*peer_id, graph.add_node(*peer_id));
        }

        for peer_id in peers.iter() {
            let connected_peers = synced_info
                .get_connected_peers(*peer_id)
                .unwrap_or(BTreeSet::new());

            // if avoid relay, just set all outgoing edges to a large value: AVOID_RELAY_COST.
            let peer_avoid_relay_data = synced_info.get_avoid_relay_data(*peer_id);

            for dst_peer_id in connected_peers.iter() {
                let Some(dst_idx) = peer_id_to_node_index.get(dst_peer_id) else {
                    continue;
                };

                graph.add_edge(
                    *peer_id_to_node_index.get(&peer_id).unwrap(),
                    *dst_idx,
                    if peer_avoid_relay_data {
                        AVOID_RELAY_COST
                    } else {
                        cost_calc.calculate_cost(*peer_id, *dst_peer_id)
                    },
                );
            }
        }

        (graph, peer_id_to_node_index)
    }

    fn gen_next_hop_map_with_least_hop<T: RouteCostCalculatorInterface>(
        my_peer_id: PeerId,
        graph: &PeerGraph,
        idx_map: &PeerIdToNodexIdxMap,
        cost_calc: &mut T,
    ) -> NextHopMap {
        let res = dijkstra(&graph, *idx_map.get(&my_peer_id).unwrap(), None, |_| 1);
        let next_hop_map = NextHopMap::new();
        for (node_idx, cost) in res.iter() {
            if *cost == 0 {
                continue;
            }
            let mut all_paths = all_simple_paths::<Vec<_>, _, RandomState>(
                graph,
                *idx_map.get(&my_peer_id).unwrap(),
                *node_idx,
                *cost - 1,
                Some(*cost + 1), // considering having avoid relay, the max cost could be a bit larger.
            )
            .collect::<Vec<_>>();

            assert!(!all_paths.is_empty());
            all_paths.sort_by(|a, b| a.len().cmp(&b.len()));

            // find a path with least cost.
            let mut min_cost = i32::MAX;
            let mut min_path_len = usize::MAX;
            let mut min_path = Vec::new();
            for path in all_paths.iter() {
                if min_path_len < path.len() && min_cost < AVOID_RELAY_COST {
                    // the min path does not contain avoid relay node.
                    break;
                }

                let mut cost = 0;
                for i in 0..path.len() - 1 {
                    let src_peer_id = *graph.node_weight(path[i]).unwrap();
                    let dst_peer_id = *graph.node_weight(path[i + 1]).unwrap();
                    let edge_weight = *graph
                        .edge_weight(graph.find_edge(path[i], path[i + 1]).unwrap())
                        .unwrap();
                    if edge_weight != 1 {
                        // means avoid relay.
                        cost += edge_weight;
                    } else {
                        cost += cost_calc.calculate_cost(src_peer_id, dst_peer_id);
                    }
                }

                if cost <= min_cost {
                    min_cost = cost;
                    min_path = path.clone();
                    min_path_len = path.len();
                }
            }
            next_hop_map.insert(
                *graph.node_weight(*node_idx).unwrap(),
                NextHopInfo {
                    next_hop_peer_id: *graph.node_weight(min_path[1]).unwrap(),
                    path_latency: min_cost,
                    path_len: min_path_len,
                },
            );
        }

        next_hop_map
    }

    fn gen_next_hop_map_with_least_cost(
        my_peer_id: PeerId,
        graph: &PeerGraph,
        idx_map: &PeerIdToNodexIdxMap,
    ) -> NextHopMap {
        let next_hop_map = NextHopMap::new();
        for item in idx_map.iter() {
            if *item.key() == my_peer_id {
                continue;
            }

            let dst_peer_node_idx = *item.value();

            let Some((cost, path)) = astar::astar(
                graph,
                *idx_map.get(&my_peer_id).unwrap(),
                |node_idx| node_idx == dst_peer_node_idx,
                |e| *e.weight(),
                |_| 0,
            ) else {
                continue;
            };

            next_hop_map.insert(
                *item.key(),
                NextHopInfo {
                    next_hop_peer_id: *graph.node_weight(path[1]).unwrap(),
                    path_latency: cost,
                    path_len: path.len(),
                },
            );
        }

        next_hop_map
    }

    fn build_from_synced_info<T: RouteCostCalculatorInterface>(
        &self,
        my_peer_id: PeerId,
        synced_info: &SyncedRouteInfo,
        policy: NextHopPolicy,
        mut cost_calc: T,
    ) {
        // build  peer_infos
        self.peer_infos.clear();
        for item in synced_info.peer_infos.iter() {
            let peer_id = item.key();
            let info = item.value();

            if info.version == 0 {
                continue;
            }

            self.peer_infos.insert(*peer_id, info.clone());
        }

        if self.peer_infos.is_empty() {
            return;
        }

        // build next hop map
        self.next_hop_map.clear();
        self.next_hop_map.insert(
            my_peer_id,
            NextHopInfo {
                next_hop_peer_id: my_peer_id,
                path_latency: 0,
                path_len: 1,
            },
        );
        let (graph, idx_map) = Self::build_peer_graph_from_synced_info(
            self.peer_infos.iter().map(|x| *x.key()).collect(),
            &synced_info,
            &mut cost_calc,
        );
        let next_hop_map = if matches!(policy, NextHopPolicy::LeastHop) {
            Self::gen_next_hop_map_with_least_hop(my_peer_id, &graph, &idx_map, &mut cost_calc)
        } else {
            Self::gen_next_hop_map_with_least_cost(my_peer_id, &graph, &idx_map)
        };
        for item in next_hop_map.iter() {
            self.next_hop_map.insert(*item.key(), *item.value());
        }
        // build graph

        // build ipv4_peer_id_map, cidr_peer_id_map
        self.ipv4_peer_id_map.clear();
        self.cidr_peer_id_map.clear();
        for item in self.peer_infos.iter() {
            // only set ipv4 map for peers we can reach.
            if !self.next_hop_map.contains_key(item.key()) {
                continue;
            }

            let peer_id = item.key();
            let info = item.value();

            if let Some(ipv4_addr) = info.ipv4_addr {
                self.ipv4_peer_id_map.insert(ipv4_addr.into(), *peer_id);
            }

            for cidr in info.proxy_cidrs.iter() {
                self.cidr_peer_id_map
                    .insert(cidr.parse().unwrap(), *peer_id);
            }
        }
    }

    fn get_peer_id_for_proxy(&self, ipv4: &Ipv4Addr) -> Option<PeerId> {
        let ipv4 = std::net::IpAddr::V4(*ipv4);
        for item in self.cidr_peer_id_map.iter() {
            let (k, v) = item.pair();
            if k.contains(&ipv4) {
                return Some(*v);
            }
        }
        None
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

// if we need to sync route info with one peer, we create a SyncRouteSession with that peer.
#[derive(Debug)]
struct SyncRouteSession {
    my_peer_id: PeerId,
    dst_peer_id: PeerId,
    dst_saved_peer_info_versions: DashMap<PeerId, AtomicVersion>,
    dst_saved_conn_bitmap_version: DashMap<PeerId, AtomicVersion>,
    dst_saved_foreign_network_versions: DashMap<ForeignNetworkRouteInfoKey, AtomicVersion>,

    my_session_id: AtomicSessionId,
    dst_session_id: AtomicSessionId,

    // every node should have exactly one initator session to one other non-initiator peer.
    we_are_initiator: AtomicBool,
    dst_is_initiator: AtomicBool,

    need_sync_initiator_info: AtomicBool,

    rpc_tx_count: AtomicU32,
    rpc_rx_count: AtomicU32,

    task: SessionTask,
}

impl SyncRouteSession {
    fn new(my_peer_id: PeerId, dst_peer_id: PeerId) -> Self {
        SyncRouteSession {
            my_peer_id,
            dst_peer_id,
            dst_saved_peer_info_versions: DashMap::new(),
            dst_saved_conn_bitmap_version: DashMap::new(),
            dst_saved_foreign_network_versions: DashMap::new(),

            my_session_id: AtomicSessionId::new(rand::random()),
            dst_session_id: AtomicSessionId::new(0),

            we_are_initiator: AtomicBool::new(false),
            dst_is_initiator: AtomicBool::new(false),

            need_sync_initiator_info: AtomicBool::new(false),

            rpc_tx_count: AtomicU32::new(0),
            rpc_rx_count: AtomicU32::new(0),

            task: SessionTask::new(my_peer_id),
        }
    }

    fn check_saved_peer_info_update_to_date(&self, peer_id: PeerId, version: Version) -> bool {
        if version == 0 || peer_id == self.dst_peer_id {
            // never send version 0 peer info to dst peer.
            return true;
        }
        self.dst_saved_peer_info_versions
            .get(&peer_id)
            .map(|v| v.get() >= version)
            .unwrap_or(false)
    }

    fn update_dst_saved_peer_info_version(&self, infos: &Vec<RoutePeerInfo>) {
        for info in infos.iter() {
            self.dst_saved_peer_info_versions
                .entry(info.peer_id)
                .or_insert_with(|| AtomicVersion::new())
                .set_if_larger(info.version);
        }
    }

    fn update_dst_saved_conn_bitmap_version(&self, conn_bitmap: &RouteConnBitmap) {
        for (peer_id, version) in conn_bitmap.peer_ids.iter() {
            self.dst_saved_conn_bitmap_version
                .entry(*peer_id)
                .or_insert_with(|| AtomicVersion::new())
                .set_if_larger(*version);
        }
    }

    fn update_dst_saved_foreign_network_version(&self, foreign_network: &RouteForeignNetworkInfos) {
        for item in foreign_network.infos.iter() {
            self.dst_saved_foreign_network_versions
                .entry(item.key.clone().unwrap())
                .or_insert_with(|| AtomicVersion::new())
                .set_if_larger(item.value.as_ref().unwrap().version);
        }
    }

    fn update_initiator_flag(&self, is_initiator: bool) {
        self.we_are_initiator.store(is_initiator, Ordering::Relaxed);
        self.need_sync_initiator_info.store(true, Ordering::Relaxed);
    }

    fn update_dst_session_id(&self, session_id: SessionId) {
        if session_id != self.dst_session_id.load(Ordering::Relaxed) {
            tracing::warn!(?self, ?session_id, "session id mismatch, clear saved info.");
            self.dst_session_id.store(session_id, Ordering::Relaxed);
            self.dst_saved_conn_bitmap_version.clear();
            self.dst_saved_peer_info_versions.clear();
        }
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

    cost_calculator: std::sync::Mutex<Option<RouteCostCalculator>>,
    route_table: RouteTable,
    route_table_with_cost: RouteTable,
    foreign_network_owner_map: DashMap<NetworkIdentity, Vec<PeerId>>,
    synced_route_info: SyncedRouteInfo,
    cached_local_conn_map: std::sync::Mutex<RouteConnBitmap>,

    last_update_my_foreign_network: AtomicCell<Option<std::time::Instant>>,
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

            cost_calculator: std::sync::Mutex::new(Some(Box::new(DefaultRouteCostCalculator))),

            route_table: RouteTable::new(),
            route_table_with_cost: RouteTable::new(),
            foreign_network_owner_map: DashMap::new(),

            synced_route_info: SyncedRouteInfo {
                peer_infos: DashMap::new(),
                raw_peer_infos: DashMap::new(),
                conn_map: DashMap::new(),
                foreign_network: DashMap::new(),
            },
            cached_local_conn_map: std::sync::Mutex::new(RouteConnBitmap::new()),

            last_update_my_foreign_network: AtomicCell::new(None),
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

        let updated = self
            .synced_route_info
            .update_my_foreign_network(self.my_peer_id, foreign_networks);

        // do not need update owner map because we always filter out my peer id.

        updated
    }

    fn update_route_table(&self) {
        let mut calc_locked = self.cost_calculator.lock().unwrap();

        calc_locked.as_mut().unwrap().begin_update();
        self.route_table.build_from_synced_info(
            self.my_peer_id,
            &self.synced_route_info,
            NextHopPolicy::LeastHop,
            calc_locked.as_mut().unwrap(),
        );

        self.route_table_with_cost.build_from_synced_info(
            self.my_peer_id,
            &self.synced_route_info,
            NextHopPolicy::LeastCost,
            calc_locked.as_mut().unwrap(),
        );
        calc_locked.as_mut().unwrap().end_update();
    }

    fn update_foreign_network_owner_map(&self) {
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
                .or_insert_with(|| Vec::new())
                .push(key.peer_id);
        }
    }

    fn cost_calculator_need_update(&self) -> bool {
        self.cost_calculator
            .lock()
            .unwrap()
            .as_ref()
            .map(|x| x.need_update())
            .unwrap_or(false)
    }

    fn update_route_table_and_cached_local_conn_bitmap(&self) {
        // update route table first because we want to filter out unreachable peers.
        self.update_route_table();

        // the conn_bitmap should contain complete list of directly connected peers.
        // use union of dst peers can preserve this property.
        let all_dst_peer_ids = self
            .synced_route_info
            .conn_map
            .iter()
            .map(|x| x.value().clone().0.into_iter())
            .flatten()
            .collect::<BTreeSet<_>>();

        let all_peer_ids = self
            .synced_route_info
            .conn_map
            .iter()
            .map(|x| (*x.key(), x.value().1.get()))
            // do not sync conn info of peers that are not reachable from any peer.
            .filter(|p| all_dst_peer_ids.contains(&p.0) || self.route_table.peer_reachable(p.0))
            .collect::<Vec<_>>();

        let mut conn_bitmap = RouteConnBitmap::new();
        conn_bitmap.bitmap = vec![0; (all_peer_ids.len() * all_peer_ids.len() + 7) / 8];
        conn_bitmap.peer_ids = all_peer_ids;

        let all_peer_ids = &conn_bitmap.peer_ids;
        for (peer_idx, (peer_id, _)) in all_peer_ids.iter().enumerate() {
            let connected = self.synced_route_info.conn_map.get(peer_id).unwrap();

            for (idx, (other_peer_id, _)) in all_peer_ids.iter().enumerate() {
                if connected.0.contains(other_peer_id) {
                    let bit_idx = peer_idx * all_peer_ids.len() + idx;
                    conn_bitmap.bitmap[bit_idx / 8] |= 1 << (bit_idx % 8);
                }
            }
        }

        *self.cached_local_conn_map.lock().unwrap() = conn_bitmap;
    }

    fn build_route_info(&self, session: &SyncRouteSession) -> Option<Vec<RoutePeerInfo>> {
        let mut route_infos = Vec::new();
        for item in self.synced_route_info.peer_infos.iter() {
            if session
                .check_saved_peer_info_update_to_date(item.value().peer_id, item.value().version)
            {
                continue;
            }

            // do not send unreachable peer info to dst peer.
            if !self.route_table.peer_reachable(*item.key()) {
                continue;
            }

            route_infos.push(item.value().clone());
        }

        if route_infos.is_empty() {
            None
        } else {
            Some(route_infos)
        }
    }

    fn build_conn_bitmap(&self, session: &SyncRouteSession) -> Option<RouteConnBitmap> {
        let mut need_update = false;
        for (peer_id, local_version) in self.cached_local_conn_map.lock().unwrap().peer_ids.iter() {
            let peer_version = session
                .dst_saved_conn_bitmap_version
                .get(&peer_id)
                .map(|item| item.get());
            if Some(*local_version) != peer_version {
                need_update = true;
                break;
            }
        }

        if !need_update {
            return None;
        }

        Some(self.cached_local_conn_map.lock().unwrap().clone())
    }

    fn build_foreign_network_info(
        &self,
        session: &SyncRouteSession,
    ) -> Option<RouteForeignNetworkInfos> {
        let mut foreign_networks = RouteForeignNetworkInfos::default();
        for item in self.synced_route_info.foreign_network.iter() {
            if session
                .dst_saved_foreign_network_versions
                .get(&item.key())
                .map(|x| x.get() >= item.value().version)
                .unwrap_or(false)
            {
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
        my_peer_info_updated || my_conn_info_updated || my_foreign_network_updated
    }

    fn build_sync_request(
        &self,
        session: &SyncRouteSession,
    ) -> (
        Option<Vec<RoutePeerInfo>>,
        Option<RouteConnBitmap>,
        Option<RouteForeignNetworkInfos>,
    ) {
        let route_infos = self.build_route_info(&session);
        let conn_bitmap = self.build_conn_bitmap(&session);
        let foreign_network = self.build_foreign_network_info(&session);

        (route_infos, conn_bitmap, foreign_network)
    }

    fn clear_expired_peer(&self) {
        let now = SystemTime::now();
        let mut to_remove = Vec::new();
        for item in self.synced_route_info.peer_infos.iter() {
            if let Ok(d) = now.duration_since(item.value().last_update.unwrap().try_into().unwrap())
            {
                if d > REMOVE_DEAD_PEER_INFO_AFTER {
                    to_remove.push(*item.key());
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

        tracing::trace!(?req_dynamic_msg, "build_sync_route_raw_req");

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

        let my_peer_id = self.my_peer_id;

        let (peer_infos, conn_bitmap, foreign_network) = self.build_sync_request(&session);
        if peer_infos.is_none()
            && conn_bitmap.is_none()
            && foreign_network.is_none()
            && !session.need_sync_initiator_info.load(Ordering::Relaxed)
            && !(sync_as_initiator && session.we_are_initiator.load(Ordering::Relaxed))
        {
            return true;
        }

        tracing::debug!(?foreign_network, "sync_route request need send to peer. my_id {:?}, pper_id: {:?}, peer_infos: {:?}, conn_bitmap: {:?}, synced_route_info: {:?} session: {:?}",
                       my_peer_id, dst_peer_id, peer_infos, conn_bitmap, self.synced_route_info, session);

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
            conn_bitmap: conn_bitmap.clone().map(Into::into),
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
        let ret = rpc_stub
            .sync_route_info(ctrl, SyncRouteInfoRequest::default())
            .await;

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
                    session.update_dst_saved_peer_info_version(&peer_infos);
                }

                if let Some(conn_bitmap) = &conn_bitmap {
                    session.update_dst_saved_conn_bitmap_version(&conn_bitmap);
                }

                if let Some(foreign_network) = &foreign_network {
                    session.update_dst_saved_foreign_network_version(&foreign_network);
                }
            }
        }
        return false;
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
        let conn_bitmap = request.conn_bitmap.map(Into::into);
        let foreign_network = request.foreign_network_infos;
        let raw_peer_infos = if peer_infos.is_some() {
            let r = get_raw_peer_infos(&mut ctrl.get_raw_input().unwrap()).unwrap();
            assert_eq!(r.len(), peer_infos.as_ref().unwrap().len());
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
                conn_bitmap,
                foreign_network,
            )
            .await;

        Ok(match ret {
            Ok(v) => v,
            Err(e) => {
                let mut resp = SyncRouteInfoResponse::default();
                resp.error = Some(e as i32);
                resp
            }
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
                    break;
                }

                drop(service_impl);
                drop(peer_rpc);

                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            sync_now = sync_now.resubscribe();

            select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                ret = sync_now.recv() => match ret {
                    Err(e) => {
                        tracing::debug!(?e, "session_task sync_now recv failed, ospf route may exit");
                        break;
                    },
                    _ => {}
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
                .map(|x| *x)
                .collect::<Vec<_>>();

            if initiator_candidates.is_empty() {
                next_sleep_ms = 1000;
                continue;
            }

            let mut new_initiator_dst = None;
            // if any peer has NoPAT or OpenInternet stun type, we should use it.
            for peer_id in initiator_candidates.iter() {
                let Some(nat_type) = service_impl.route_table.get_nat_type(*peer_id) else {
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

    async fn do_sync_route_info(
        &self,
        from_peer_id: PeerId,
        from_session_id: SessionId,
        is_initiator: bool,
        peer_infos: Option<Vec<RoutePeerInfo>>,
        raw_peer_infos: Option<Vec<DynamicMessage>>,
        conn_bitmap: Option<RouteConnBitmap>,
        foreign_network: Option<RouteForeignNetworkInfos>,
    ) -> Result<SyncRouteInfoResponse, Error> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };

        let my_peer_id = service_impl.my_peer_id;
        let session = self.get_or_start_session(from_peer_id)?;

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
            session.update_dst_saved_peer_info_version(peer_infos);
            need_update_route_table = true;
        }

        if let Some(conn_bitmap) = &conn_bitmap {
            service_impl.synced_route_info.update_conn_map(&conn_bitmap);
            session.update_dst_saved_conn_bitmap_version(conn_bitmap);
            need_update_route_table = true;
        }

        if need_update_route_table {
            service_impl.update_route_table_and_cached_local_conn_bitmap();
        }

        if let Some(foreign_network) = &foreign_network {
            service_impl
                .synced_route_info
                .update_foreign_network(&foreign_network);
            session.update_dst_saved_foreign_network_version(foreign_network);
        }

        if need_update_route_table || foreign_network.is_some() {
            service_impl.update_foreign_network_owner_map();
        }

        tracing::info!(
            "handling sync_route_info rpc: from_peer_id: {:?}, is_initiator: {:?}, peer_infos: {:?}, conn_bitmap: {:?}, synced_route_info: {:?} session: {:?}, new_route_table: {:?}",
            from_peer_id, is_initiator, peer_infos, conn_bitmap, service_impl.synced_route_info, session, service_impl.route_table);

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
            global_ctx: global_ctx.clone(),
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

    #[tracing::instrument(skip(session_mgr))]
    async fn maintain_session_tasks(
        session_mgr: RouteSessionManager,
        service_impl: Arc<PeerRouteServiceImpl>,
    ) {
        session_mgr.maintain_sessions(service_impl).await;
    }

    #[tracing::instrument(skip(session_mgr))]
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

    async fn list_routes(&self) -> Vec<crate::proto::cli::Route> {
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
            let mut route: crate::proto::cli::Route = item.value().clone().into();
            route.next_hop_peer_id = next_hop_peer.next_hop_peer_id;
            route.cost = (next_hop_peer.path_len - 1) as i32;
            route.path_latency = next_hop_peer.path_latency;

            route.next_hop_peer_id_latency_first =
                next_hop_peer_latency_first.map(|x| x.next_hop_peer_id);
            route.cost_latency_first = next_hop_peer_latency_first.map(|x| x.path_latency);
            route.path_latency_latency_first = next_hop_peer_latency_first.map(|x| x.path_latency);

            route.feature_flag = item.feature_flag.clone();

            routes.push(route);
        }
        routes
    }

    async fn get_peer_id_by_ipv4(&self, ipv4_addr: &Ipv4Addr) -> Option<PeerId> {
        let route_table = &self.service_impl.route_table;
        if let Some(peer_id) = route_table.ipv4_peer_id_map.get(ipv4_addr) {
            return Some(*peer_id);
        }

        if let Some(peer_id) = route_table.get_peer_id_for_proxy(ipv4_addr) {
            return Some(peer_id);
        }

        tracing::debug!(?ipv4_addr, "no peer id for ipv4");
        None
    }

    async fn set_route_cost_fn(&self, _cost_fn: RouteCostCalculator) {
        *self.service_impl.cost_calculator.lock().unwrap() = Some(_cost_fn);
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

    async fn get_feature_flag(&self, peer_id: PeerId) -> Option<PeerFeatureFlag> {
        self.service_impl
            .route_table
            .peer_infos
            .get(&peer_id)
            .and_then(|x| x.feature_flag.clone())
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

    use dashmap::DashMap;
    use prost_reflect::{DynamicMessage, ReflectMessage};

    use crate::{
        common::{global_ctx::tests::get_mock_global_ctx, PeerId},
        connector::udp_hole_punch::tests::replace_stun_info_collector,
        peers::{
            create_packet_recv_chan,
            peer_manager::{PeerManager, RouteAlgoType},
            peer_ospf_route::PeerRouteServiceImpl,
            route_trait::{NextHopPolicy, Route, RouteCostCalculatorInterface},
            tests::connect_peer_manager,
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

    #[tokio::test]
    async fn ospf_route_2node() {
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;

        for r in vec![r_a.clone(), r_b.clone()].iter() {
            wait_for_condition(
                || async { r.list_routes().await.len() == 1 },
                Duration::from_secs(5),
            )
            .await;
        }

        tokio::time::sleep(Duration::from_secs(3)).await;

        assert_eq!(2, r_a.service_impl.synced_route_info.peer_infos.len());
        assert_eq!(2, r_b.service_impl.synced_route_info.peer_infos.len());

        for s in r_a.service_impl.sessions.iter() {
            assert!(s.value().task.is_running());
        }

        assert_eq!(
            r_a.service_impl
                .synced_route_info
                .peer_infos
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
                .0
                .load(Ordering::Relaxed)
        );

        assert_eq!((1, 1), get_rpc_counter(&r_a, p_b.my_peer_id()));
        assert_eq!((1, 1), get_rpc_counter(&r_b, p_a.my_peer_id()));

        let i_a = get_is_initiator(&r_a, p_b.my_peer_id());
        let i_b = get_is_initiator(&r_b, p_a.my_peer_id());
        assert_eq!(i_a.0, i_b.1);
        assert_eq!(i_b.0, i_a.1);

        drop(r_b);
        drop(p_b);

        wait_for_condition(
            || async { r_a.list_routes().await.len() == 0 },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || async { r_a.service_impl.sessions.is_empty() },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn ospf_route_multi_node() {
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_c.clone(), p_b.clone()).await;

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;
        let r_c = create_mock_route(p_c.clone()).await;

        for r in vec![r_a.clone(), r_b.clone(), r_c.clone()].iter() {
            wait_for_condition(
                || async { r.service_impl.synced_route_info.peer_infos.len() == 3 },
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
        let mut all_route = vec![r_a.clone(), r_b.clone(), r_c.clone(), r_d.clone()];
        all_route.sort_by(|a, b| a.my_peer_id.cmp(&b.my_peer_id));
        let mut all_peer_mgr = vec![p_a.clone(), p_b.clone(), p_c.clone(), p_d.clone()];
        all_peer_mgr.sort_by(|a, b| a.my_peer_id().cmp(&b.my_peer_id()));

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
            let conns = synced_info
                .conn_map
                .get(&routable_peer.my_peer_id())
                .unwrap();

            assert_eq!(
                conns.0,
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
                .get(&routable_peer.my_peer_id())
                .unwrap();
            assert_eq!(peer_info.peer_id, routable_peer.my_peer_id());
        }
    }

    async fn print_routes(peers: Vec<Arc<PeerRoute>>) {
        for p in peers.iter() {
            println!("p:{:?}, route: {:#?}", p.my_peer_id, p.list_routes().await);
        }
    }

    #[tokio::test]
    async fn ospf_route_3node_disconnect() {
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_c.clone(), p_b.clone()).await;

        let mgrs = vec![p_a.clone(), p_b.clone(), p_c.clone()];

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;
        let r_c = create_mock_route(p_c.clone()).await;

        for r in vec![r_a.clone(), r_b.clone(), r_c.clone()].iter() {
            wait_for_condition(
                || async { r.service_impl.synced_route_info.peer_infos.len() == 3 },
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

        for r in vec![r_a.clone(), r_b.clone()].iter() {
            wait_for_condition(
                || async { r.list_routes().await.len() == 1 },
                Duration::from_secs(5),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn peer_reconnect() {
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
            || async { r_a.list_routes().await.len() == 0 },
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

    #[tokio::test]
    async fn test_cost_calculator() {
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
            || async { r_d.get_next_hop(p_a.my_peer_id()).await != None },
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

    #[tokio::test]
    async fn test_raw_peer_info() {
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
}
