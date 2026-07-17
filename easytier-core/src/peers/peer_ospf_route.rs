use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwap;
use atomic_shim::AtomicU64;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr, Ipv6Inet};
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use ordered_hash_map::OrderedHashMap;
use parking_lot::{RwLock, lock_api::RwLockUpgradableReadGuard};
use petgraph::{
    Directed,
    algo::dijkstra,
    graph::{Graph, NodeIndex},
    visit::{EdgeRef, IntoNodeReferences},
};
use prefix_trie::PrefixMap;
use prost::Message;
use prost_reflect::{DynamicMessage, ReflectMessage};
use prost_wkt_types::Timestamp;
use quanta::Instant;
use tokio::{
    select,
    sync::{Mutex, RwLock as AsyncRwLock},
    task::{JoinHandle, JoinSet},
};

use crate::{
    config::PeerId,
    peers::{
        PeerPacketFilter,
        context::{
            ArcPeerContext, NetworkIdentity as CoreNetworkIdentity, PeerContext, PeerContextEvent,
            PeerGroupIdentity, TrustedKeyMetadata, TrustedKeySource,
        },
        graph_algo::dijkstra_with_first_hop,
        peer_rpc::PeerRpcManager,
        public_ipv6::{
            PublicIpv6PeerRouteInfo, PublicIpv6RouteControl, PublicIpv6Runtime, PublicIpv6Service,
            PublicIpv6SyncTrigger,
        },
        route_trait::{
            DefaultRouteCostCalculator, ForeignNetworkRouteInfoMap, NextHopPolicy, Route,
            RouteCostCalculator, RouteCostCalculatorInterface, RouteInterfaceBox,
        },
        util::shrink_dashmap,
    },
    proto::{
        common::{NatType, TimestampExt},
        core_peer::peer::{
            ListPublicIpv6InfoResponse as CoreListPublicIpv6InfoResponse,
            PublicIpv6LeaseInfo as CorePublicIpv6LeaseInfo, Route as CoreRouteInfo,
        },
        peer_rpc::{
            ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, OspfRouteRpc,
            OspfRouteRpcClientFactory, OspfRouteRpcServer, PeerGroupInfo, PeerIdVersion,
            PeerIdentityType, PublicIpv6AddrRpcServer, RouteForeignNetworkInfos,
            RouteForeignNetworkSummary, RoutePeerInfo, RoutePeerInfos, SyncRouteInfoError,
            SyncRouteInfoRequest, SyncRouteInfoResponse, TrustedCredentialPubkey,
            TrustedCredentialPubkeyProof, route_foreign_network_infos,
            route_foreign_network_summary, sync_route_info_request::ConnInfo,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
};

pub type Version = u32;

// the cost (latency between two peers) is i32, i32::MAX is large enough.
const AVOID_RELAY_COST: usize = i32::MAX as usize;

/// Check if `child` CIDR is a subset of `parent` CIDR.
/// Returns true if `child` is contained within `parent`, or if they are equal.
pub fn cidr_is_subset(child: &IpCidr, parent: &IpCidr) -> bool {
    match (child, parent) {
        (IpCidr::V4(c), IpCidr::V4(p)) => {
            p.first_address() <= c.first_address() && c.last_address() <= p.last_address()
        }
        (IpCidr::V6(c), IpCidr::V6(p)) => {
            p.first_address() <= c.first_address() && c.last_address() <= p.last_address()
        }
        _ => false, // mixed v4/v6
    }
}

/// Check if `child` CIDR is a subset of `parent` CIDR (both as string representations).
pub fn cidr_is_subset_str(child: &str, parent: &str) -> bool {
    let Ok(child_cidr) = child.parse::<IpCidr>() else {
        return false;
    };
    let Ok(parent_cidr) = parent.parse::<IpCidr>() else {
        return false;
    };
    cidr_is_subset(&child_cidr, &parent_cidr)
}

#[derive(Debug, Clone)]
pub struct AtomicVersion(Arc<AtomicU32>);

impl AtomicVersion {
    pub fn new() -> Self {
        AtomicVersion(Arc::new(AtomicU32::new(0)))
    }

    pub fn get(&self) -> Version {
        self.0.load(Ordering::Relaxed)
    }

    pub fn inc(&self) -> Version {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn set_if_larger(&self, version: Version) -> bool {
        // return true if the version is set.
        self.0.fetch_max(version, Ordering::Relaxed) < version
    }
}

impl From<Version> for AtomicVersion {
    fn from(version: Version) -> Self {
        AtomicVersion(Arc::new(AtomicU32::new(version)))
    }
}

#[derive(Debug, Clone)]
pub struct OspfPeerInfo {
    pub peer_id: PeerId,
    pub info: RoutePeerInfo,
}

#[derive(Debug, Clone)]
pub struct OspfPeerConnInfo {
    pub peer_id: PeerId,
    pub connected_peers: BTreeSet<PeerId>,
}

#[derive(Debug, Clone)]
pub struct OspfRouteSnapshot {
    pub peer_infos: Vec<OspfPeerInfo>,
    pub conn_map: Vec<OspfPeerConnInfo>,
    pub suppressed_peer_ids: BTreeSet<PeerId>,
    pub version: Version,
}

impl OspfRouteSnapshot {
    fn lookup(&self) -> OspfRouteSnapshotLookup<'_> {
        OspfRouteSnapshotLookup {
            peer_infos: self
                .peer_infos
                .iter()
                .map(|entry| (entry.peer_id, &entry.info))
                .collect(),
            conn_map: self
                .conn_map
                .iter()
                .map(|entry| (entry.peer_id, entry))
                .collect(),
        }
    }
}

struct OspfRouteSnapshotLookup<'a> {
    peer_infos: HashMap<PeerId, &'a RoutePeerInfo>,
    conn_map: HashMap<PeerId, &'a OspfPeerConnInfo>,
}

impl OspfRouteSnapshotLookup<'_> {
    fn peer_info(&self, peer_id: PeerId) -> Option<&RoutePeerInfo> {
        self.peer_infos.get(&peer_id).copied()
    }

    fn connected_peers<T: FromIterator<PeerId>>(&self, peer_id: PeerId) -> Option<T> {
        self.conn_map
            .get(&peer_id)
            .map(|entry| entry.connected_peers.iter().copied().collect())
    }

    fn get_avoid_relay_data(&self, peer_id: PeerId) -> bool {
        // if avoid relay, just set all outgoing edges to a large value: AVOID_RELAY_COST.
        self.peer_info(peer_id)
            .and_then(|x| x.feature_flag)
            .map(|x| x.avoid_relay_data)
            .unwrap_or_default()
    }
}

type PeerGraph = Graph<PeerId, usize, Directed>;
type PeerIdToNodeIdxMap = DashMap<PeerId, NodeIndex>;

#[derive(Debug, Clone, Copy)]
pub struct OspfNextHopInfo {
    pub next_hop_peer_id: PeerId,
    pub path_latency: i32,
    pub path_len: usize, // path includes src and dst.
    pub version: Version,
}

type NextHopMap = DashMap<PeerId, OspfNextHopInfo>;

// computed with SyncedRouteInfo snapshot. used to get next hop.
#[derive(Debug)]
pub struct OspfRouteTable {
    peer_infos: DashMap<PeerId, RoutePeerInfo>,
    next_hop_map: NextHopMap,
    suppressed_peer_ids: DashMap<PeerId, ()>,
    ipv4_peer_id_map: DashMap<Ipv4Addr, PeerIdVersion>,
    ipv6_peer_id_map: DashMap<Ipv6Addr, PeerIdVersion>,
    cidr_peer_id_map: ArcSwap<PrefixMap<Ipv4Cidr, PeerIdVersion>>,
    cidr_v6_peer_id_map: ArcSwap<PrefixMap<Ipv6Cidr, PeerIdVersion>>,
    next_hop_map_version: AtomicVersion,
}

impl OspfRouteTable {
    pub fn new() -> Self {
        OspfRouteTable {
            peer_infos: DashMap::new(),
            next_hop_map: DashMap::new(),
            suppressed_peer_ids: DashMap::new(),
            ipv4_peer_id_map: DashMap::new(),
            ipv6_peer_id_map: DashMap::new(),
            cidr_peer_id_map: ArcSwap::new(Arc::new(PrefixMap::new())),
            cidr_v6_peer_id_map: ArcSwap::new(Arc::new(PrefixMap::new())),
            next_hop_map_version: AtomicVersion::new(),
        }
    }

    pub fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<OspfNextHopInfo> {
        if self.suppressed_peer_ids.contains_key(&dst_peer_id) {
            return None;
        }
        self.get_topology_next_hop(dst_peer_id)
    }

    pub fn get_topology_next_hop(&self, dst_peer_id: PeerId) -> Option<OspfNextHopInfo> {
        let cur_version = self.next_hop_map_version.get();
        self.next_hop_map.get(&dst_peer_id).and_then(|x| {
            if x.version >= cur_version {
                Some(*x)
            } else {
                None
            }
        })
    }

    pub fn peer_reachable(&self, peer_id: PeerId) -> bool {
        self.get_next_hop(peer_id).is_some()
    }

    pub fn topology_peer_reachable(&self, peer_id: PeerId) -> bool {
        self.get_topology_next_hop(peer_id).is_some()
    }

    pub fn get_udp_nat_type(&self, peer_id: PeerId) -> Option<NatType> {
        self.peer_infos
            .get(&peer_id)
            .map(|x| NatType::try_from(x.udp_nat_type).unwrap_or_default())
    }

    pub fn get_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        self.peer_infos.get(&peer_id).map(|x| x.clone())
    }

    pub fn get_peer_id_by_ipv4(&self, ipv4_addr: &Ipv4Addr) -> Option<PeerId> {
        self.ipv4_peer_id_map.get(ipv4_addr).map(|p| p.peer_id)
    }

    pub fn get_peer_id_by_ipv6(&self, ipv6_addr: &Ipv6Addr) -> Option<PeerId> {
        self.ipv6_peer_id_map.get(ipv6_addr).map(|p| p.peer_id)
    }

    fn sync_suppressed_peer_ids(&self, snapshot: &OspfRouteSnapshot) {
        self.suppressed_peer_ids
            .retain(|peer_id, _| snapshot.suppressed_peer_ids.contains(peer_id));
        for peer_id in &snapshot.suppressed_peer_ids {
            self.suppressed_peer_ids.insert(*peer_id, ());
        }
    }

    // return graph and start node index (node of my peer id).
    fn build_peer_graph_from_snapshot<T: RouteCostCalculatorInterface>(
        my_peer_id: PeerId,
        snapshot: &OspfRouteSnapshot,
        lookup: &OspfRouteSnapshotLookup<'_>,
        cost_calc: &T,
    ) -> (PeerGraph, NodeIndex) {
        let mut graph: PeerGraph = PeerGraph::new();

        let mut start_node_idx = None;
        let peer_id_to_node_index: PeerIdToNodeIdxMap = DashMap::new();
        for entry in &snapshot.peer_infos {
            let peer_id = entry.peer_id;

            if entry.info.version == 0 {
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
            let src_peer_id = *item.key();
            if src_peer_id != my_peer_id && snapshot.suppressed_peer_ids.contains(&src_peer_id) {
                continue;
            }
            let src_node_idx = item.value();
            let connected_peers: BTreeSet<_> =
                lookup.connected_peers(src_peer_id).unwrap_or_default();

            // if avoid relay, just set all outgoing edges to a large value: AVOID_RELAY_COST.
            let peer_avoid_relay_data = lookup.get_avoid_relay_data(src_peer_id);

            for dst_peer_id in connected_peers.iter() {
                let Some(dst_node_idx) = peer_id_to_node_index.get(dst_peer_id) else {
                    continue;
                };

                let mut cost = cost_calc.calculate_cost(src_peer_id, *dst_peer_id) as usize;
                if peer_avoid_relay_data {
                    cost += AVOID_RELAY_COST;
                }

                graph.add_edge(*src_node_idx, *dst_node_idx, cost);
            }
        }

        (graph, start_node_idx.unwrap())
    }

    pub fn clean_expired_route_info(&self) {
        let cur_version = self.next_hop_map_version.get();
        self.next_hop_map.retain(|_, v| {
            // remove next hop map for peers we cannot reach.
            v.version >= cur_version
        });
        self.peer_infos.retain(|k, _| {
            // remove peer info for peers we cannot forward to.
            self.peer_reachable(*k)
        });
        self.ipv4_peer_id_map.retain(|_, v| {
            // remove ipv4 map for peers we cannot forward to.
            self.peer_reachable(v.peer_id)
        });
        self.ipv6_peer_id_map.retain(|_, v| {
            // remove ipv6 map for peers we cannot forward to.
            self.peer_reachable(v.peer_id)
        });

        shrink_dashmap(&self.peer_infos, None);
        shrink_dashmap(&self.next_hop_map, None);
        shrink_dashmap(&self.suppressed_peer_ids, None);
        shrink_dashmap(&self.ipv4_peer_id_map, None);
        shrink_dashmap(&self.ipv6_peer_id_map, None);
    }

    fn gen_next_hop_map_with_least_hop(
        &self,
        graph: &PeerGraph,
        start_node: &NodeIndex,
        version: Version,
    ) {
        if graph.node_weight(*start_node).is_none() {
            tracing::warn!(
                ?start_node,
                version,
                "invalid start node for least-hop route rebuild"
            );
            return;
        }
        let normalize_edge_cost = |e: petgraph::graph::EdgeReference<usize>| {
            if *e.weight() >= AVOID_RELAY_COST {
                AVOID_RELAY_COST + 1
            } else {
                1
            }
        };
        // Step 1: first Dijkstra, compute shortest hop count.
        let path_len_map = dijkstra(graph, *start_node, None, normalize_edge_cost);

        // Step 2: build subgraph containing only shortest-hop and AVOID RELAY edges.
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

        // Step 3: second Dijkstra on subgraph, choose least-cost among shortest-hop paths.
        self.gen_next_hop_map_with_least_cost(&subgraph, &start_node_idx.unwrap(), version);
    }

    fn gen_next_hop_map_with_least_cost(
        &self,
        graph: &PeerGraph,
        start_node: &NodeIndex,
        version: Version,
    ) {
        if graph.node_weight(*start_node).is_none() {
            tracing::warn!(
                ?start_node,
                version,
                "invalid start node for least-cost route rebuild"
            );
            return;
        }
        let (costs, next_hops) = dijkstra_with_first_hop(graph, *start_node, |e| *e.weight());

        for (dst, (next_hop, path_len)) in next_hops.iter() {
            let info = OspfNextHopInfo {
                next_hop_peer_id: *graph.node_weight(*next_hop).unwrap(),
                path_latency: (*costs.get(dst).unwrap() % AVOID_RELAY_COST) as i32,
                path_len: *path_len,
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

    pub fn build_from_snapshot<T: RouteCostCalculatorInterface>(
        &self,
        my_peer_id: PeerId,
        snapshot: &OspfRouteSnapshot,
        policy: NextHopPolicy,
        cost_calc: &T,
    ) {
        let version = snapshot.version;
        self.sync_suppressed_peer_ids(snapshot);
        let lookup = snapshot.lookup();

        let local_proxy_cidrs = lookup
            .peer_info(my_peer_id)
            .into_iter()
            .flat_map(|info| &info.proxy_cidrs)
            .filter_map(|cidr| cidr.parse::<IpCidr>().ok())
            .collect::<Vec<_>>();

        // build next hop map
        let (graph, start_node) =
            Self::build_peer_graph_from_snapshot(my_peer_id, snapshot, &lookup, cost_calc);

        if graph.node_count() == 0 {
            tracing::warn!("no peer in graph, cannot build next hop map");
            self.next_hop_map_version.set_if_larger(version);
            self.clean_expired_route_info();
            return;
        }
        if start_node == NodeIndex::end() {
            tracing::warn!(
                ?my_peer_id,
                version,
                "my peer id is missing in graph, skip next-hop rebuild this round"
            );
            self.next_hop_map_version.set_if_larger(version);
            self.clean_expired_route_info();
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
            if !self.peer_reachable(*peer_id) {
                continue;
            }

            let Some(info) = lookup.peer_info(*peer_id).cloned() else {
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

            if let Some(ipv6_addr) = info
                .ipv6_public_addr_lease
                .as_ref()
                .and_then(|addr| addr.address)
            {
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
                let Ok(cidr) = cidr.parse::<IpCidr>() else {
                    tracing::warn!("invalid proxy cidr: {:?}, from peer: {:?}", cidr, peer_id);
                    continue;
                };

                if *peer_id != my_peer_id
                    && local_proxy_cidrs
                        .iter()
                        .any(|local_cidr| cidr_is_subset(&cidr, local_cidr))
                {
                    tracing::debug!(
                        ?peer_id,
                        ?my_peer_id,
                        ?local_proxy_cidrs,
                        ?cidr,
                        "skip remote proxy cidr covered by local announced proxy cidr while building route table"
                    );
                    continue;
                }
                match cidr {
                    IpCidr::V4(cidr) => {
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

                    IpCidr::V6(cidr) => {
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
        self.clean_expired_route_info();
    }

    pub fn get_peer_id_for_proxy(&self, ip: &IpAddr) -> Option<PeerId> {
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

    pub fn list_routes(
        &self,
        my_peer_id: PeerId,
        route_table_with_cost: &Self,
    ) -> Vec<CoreRouteInfo> {
        let mut routes = Vec::new();
        for item in self.peer_infos.iter() {
            if *item.key() == my_peer_id {
                continue;
            }
            let Some(next_hop_peer) = self.get_next_hop(*item.key()) else {
                continue;
            };
            let next_hop_peer_latency_first = route_table_with_cost.get_next_hop(*item.key());
            let mut route: CoreRouteInfo = item.value().clone().into();
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

    pub fn list_proxy_cidrs_excluding(&self, peer_id: PeerId) -> BTreeSet<Ipv4Cidr> {
        self.cidr_peer_id_map
            .load()
            .iter()
            .filter(|(_, pv)| pv.peer_id != peer_id)
            .map(|(cidr, _)| *cidr)
            .collect()
    }

    pub fn list_proxy_cidrs_v6_excluding(&self, peer_id: PeerId) -> BTreeSet<Ipv6Cidr> {
        self.cidr_v6_peer_id_map
            .load()
            .iter()
            .filter(|(_, pv)| pv.peer_id != peer_id)
            .map(|(cidr, _)| *cidr)
            .collect()
    }
}

static UPDATE_PEER_INFO_PERIOD: Duration = Duration::from_secs(3600);
static REMOVE_DEAD_PEER_INFO_AFTER: Duration = Duration::from_secs(3660);
static FORCE_USE_CONN_LIST: AtomicBool = AtomicBool::new(false);

// if a peer is unreachable for `REMOVE_UNREACHABLE_PEER_INFO_AFTER` time, we can remove it because
// 1. all the ospf sessions between two zone are already destroy, new created session will resend the peer info.
// 2. all the dst_saved_peer_info_version in all sessions already remove the peer info, the peer info will be propagated
//    in another zone when two zone restore the conneciton.
static REMOVE_UNREACHABLE_PEER_INFO_AFTER: Duration = Duration::from_secs(90);

/// Patch specific fields in a raw DynamicMessage from a decoded RoutePeerInfo,
/// preserving all other fields (including unknown ones).
fn patch_raw_from_info(raw: &mut DynamicMessage, info: &RoutePeerInfo, fields: &[&str]) {
    let mut decoded_raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
    decoded_raw.transcode_from(info).unwrap();
    for field_name in fields {
        if let Some(value) = decoded_raw.get_field_by_name(field_name) {
            raw.set_field_by_name(field_name, value.into_owned());
        }
    }
}

fn raw_credential_bytes_from_route_info(
    raw_route_info: &DynamicMessage,
    proof_idx: usize,
) -> Option<Vec<u8>> {
    raw_route_info
        .get_field_by_name("trusted_credential_pubkeys")?
        .as_list()?
        .get(proof_idx)?
        .as_message()?
        .get_field_by_name("credential")?
        .as_message()
        .map(|credential| credential.encode_to_vec())
}

fn route_peer_inst_id(info: &RoutePeerInfo) -> Option<uuid::Uuid> {
    info.inst_id.map(Into::into)
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

#[allow(deprecated)]
fn new_route_peer_info_with_version(easytier_version: String) -> RoutePeerInfo {
    RoutePeerInfo {
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
        easytier_version,
        feature_flag: None,
        peer_route_id: 0,
        network_length: 24,
        ipv6_addr: None,
        groups: Vec::new(),

        quic_port: None,
        noise_static_pubkey: Vec::new(),
        trusted_credential_pubkeys: Vec::new(),
        ipv6_public_addr_prefix: None,
        ipv6_public_addr_lease: None,
    }
}

/// Creates a new `RoutePeerInfo` instance with updated information from the given context.
pub fn new_updated_self_route_peer_info(
    my_peer_id: PeerId,
    peer_route_id: u64,
    context: &dyn PeerContext,
    public_ipv6_addr_lease: Option<Ipv6Inet>,
) -> RoutePeerInfo {
    let stun_info = context.stun_info();
    let network_identity = context.network_identity();
    let ipv4 = context.ipv4();
    let noise_static_pubkey = context
        .secure_mode()
        .and_then(|cfg| cfg.public_key().ok())
        .map(|pk| pk.as_bytes().to_vec())
        .unwrap_or_default();
    RoutePeerInfo {
        peer_id: my_peer_id,
        inst_id: Some(context.instance_id().into()),
        cost: 0,
        ipv4_addr: ipv4.as_ref().map(|x| x.address().into()),
        proxy_cidrs: context
            .proxy_cidrs()
            .into_iter()
            .chain(context.vpn_portal_cidr())
            .map(|x| x.to_string())
            .collect(),
        hostname: Some(context.hostname()),
        udp_nat_type: stun_info.udp_nat_type,
        tcp_nat_type: stun_info.tcp_nat_type,

        // these two fields should not participate in comparison.
        last_update: None,
        version: 0,

        easytier_version: context.easytier_version(),
        feature_flag: Some(context.feature_flags()),
        peer_route_id,
        network_length: ipv4
            .as_ref()
            .map(|x| x.network_length() as u32)
            .unwrap_or(24),

        ipv6_addr: context.ipv6().map(|x| x.into()),
        ipv6_public_addr_prefix: context.advertised_ipv6_public_addr_prefix().map(|prefix| {
            Ipv6Inet::new(prefix.first_address(), prefix.network_length())
                .unwrap()
                .into()
        }),
        ipv6_public_addr_lease: public_ipv6_addr_lease.map(Into::into),

        groups: context.peer_groups(my_peer_id),

        noise_static_pubkey,

        // Only admin nodes (holding network_secret) publish trusted credential pubkeys
        trusted_credential_pubkeys: if let Some(network_secret) =
            network_identity.network_secret.as_deref()
        {
            context.trusted_credential_pubkeys(network_secret)
        } else {
            Vec::new()
        },

        ..Default::default()
    }
}

type RouteConnBitmap = crate::proto::peer_rpc::RouteConnBitmap;
type RouteConnPeerList = crate::proto::peer_rpc::RouteConnPeerList;
type PeerConnInfo = crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo;

/// Attempts to update the `new` RoutePeerInfo based on the `old` RoutePeerInfo.
fn try_update_new_peer_info(old: &RoutePeerInfo, new: &mut RoutePeerInfo) -> bool {
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

#[derive(Debug, Default)]
struct InterfacePeerSnapshot {
    generation: u64,
    peers: BTreeSet<PeerId>,
    identity_types: BTreeMap<PeerId, Option<PeerIdentityType>>,
}

// constructed with all infos synced from all peers.
struct SyncedRouteInfo {
    default_easytier_version: String,
    peer_infos: RwLock<OrderedHashMap<PeerId, RoutePeerInfo>>,
    // prost doesn't support unknown fields, so we use DynamicMessage to store raw infos and propagate them to other peers.
    raw_peer_infos: DashMap<PeerId, DynamicMessage>,
    conn_map: RwLock<OrderedHashMap<PeerId, RouteConnInfo>>,
    foreign_network: DashMap<ForeignNetworkRouteInfoKey, ForeignNetworkRouteInfoEntry>,
    group_trust_map: DashMap<PeerId, HashMap<String, Vec<u8>>>,
    group_trust_map_cache: DashMap<PeerId, Arc<Vec<String>>>, // cache for group trust map, should sync with group_trust_map

    // Aggregated trusted credential pubkeys from all admin nodes
    // Maps pubkey bytes -> TrustedCredentialPubkey
    trusted_credential_pubkeys: DashMap<Vec<u8>, TrustedCredentialPubkey>,
    // Tracks the currently accepted peer for non-reusable credentials.
    // Maps credential pubkey bytes -> peer_id.
    non_reusable_credential_owners: DashMap<Vec<u8>, PeerId>,
    // Duplicate non-reusable credential peers are kept for OSPF sync and topology
    // reachability, but excluded from forwarding until owner election selects them.
    suppressed_non_reusable_credential_peers: DashMap<PeerId, ()>,

    version: AtomicVersion,
}

impl Debug for SyncedRouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncedRouteInfo")
            .field("default_easytier_version", &self.default_easytier_version)
            .field("peer_infos", &self.peer_infos)
            .field("conn_map", &self.conn_map)
            .field("foreign_network", &self.foreign_network)
            .field("group_trust_map", &self.group_trust_map)
            .field("version", &self.version.get())
            .finish()
    }
}

#[allow(dead_code)]
impl SyncedRouteInfo {
    fn set_peer_groups(&self, peer_id: PeerId, groups: HashMap<String, Vec<u8>>) {
        if groups.is_empty() {
            self.group_trust_map.remove(&peer_id);
            self.group_trust_map_cache.remove(&peer_id);
            return;
        }

        let group_names = groups.keys().cloned().collect();
        self.group_trust_map.insert(peer_id, groups);
        self.group_trust_map_cache
            .insert(peer_id, Arc::new(group_names));
    }

    fn get_proof_groups(&self, peer_id: PeerId) -> HashMap<String, Vec<u8>> {
        self.group_trust_map
            .get(&peer_id)
            .map(|groups| {
                groups
                    .iter()
                    .filter(|(_, proof)| !proof.is_empty())
                    .map(|(group, proof)| (group.clone(), proof.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn mark_credential_peer(info: &mut RoutePeerInfo, is_credential_peer: bool) {
        let mut feature_flag = info.feature_flag.unwrap_or_default();
        feature_flag.is_credential_peer = is_credential_peer;
        info.feature_flag = Some(feature_flag);
    }

    fn is_credential_peer_info(info: &RoutePeerInfo) -> bool {
        info.feature_flag
            .as_ref()
            .map(|x| x.is_credential_peer)
            .unwrap_or(false)
    }

    fn credential_is_reusable(info: &TrustedCredentialPubkey) -> bool {
        info.reusable.unwrap_or(true)
    }

    fn credential_proof_is_valid(
        &self,
        raw_route_info: Option<&DynamicMessage>,
        proof_idx: usize,
        proof: &TrustedCredentialPubkeyProof,
        network_secret: Option<&str>,
    ) -> bool {
        network_secret
            .map(|secret| {
                raw_route_info
                    .and_then(|raw| raw_credential_bytes_from_route_info(raw, proof_idx))
                    .map(|raw_credential_bytes| {
                        proof.verify_credential_hmac_with_bytes(&raw_credential_bytes, secret)
                    })
                    .unwrap_or_else(|| proof.verify_credential_hmac(secret))
            })
            .unwrap_or(true)
    }

    fn collect_trusted_credentials(
        &self,
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        network_secret: Option<&str>,
        now: i64,
    ) -> (
        HashMap<Vec<u8>, TrustedCredentialPubkey>,
        HashMap<Vec<u8>, TrustedKeyMetadata>,
    ) {
        let mut all_trusted = HashMap::new();
        let mut global_trusted_keys = HashMap::new();

        for (peer_id, info) in peer_infos.iter() {
            if !self.is_admin_peer(info) {
                continue;
            }

            if !info.noise_static_pubkey.is_empty() {
                global_trusted_keys.insert(
                    info.noise_static_pubkey.clone(),
                    TrustedKeyMetadata {
                        source: TrustedKeySource::OspfNode,
                        expiry_unix: None,
                    },
                );
            }

            let raw_route_info = self.raw_peer_infos.get(peer_id);
            let raw_route_info = raw_route_info.as_deref();

            for (proof_idx, proof) in info.trusted_credential_pubkeys.iter().enumerate() {
                if !self.credential_proof_is_valid(raw_route_info, proof_idx, proof, network_secret)
                {
                    continue;
                }

                let Some(credential) = proof.credential.as_ref() else {
                    continue;
                };
                if credential.expiry_unix <= now {
                    continue;
                }

                all_trusted
                    .entry(credential.pubkey.clone())
                    .or_insert_with(|| credential.clone());
                global_trusted_keys.insert(
                    credential.pubkey.clone(),
                    TrustedKeyMetadata {
                        source: TrustedKeySource::OspfCredential,
                        expiry_unix: Some(credential.expiry_unix),
                    },
                );
            }
        }

        (all_trusted, global_trusted_keys)
    }

    fn replace_trusted_credential_pubkeys(
        &self,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
    ) -> HashSet<Vec<u8>> {
        let prev_trusted = self
            .trusted_credential_pubkeys
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        self.trusted_credential_pubkeys.clear();
        for (pubkey, credential) in all_trusted {
            self.trusted_credential_pubkeys
                .insert(pubkey.clone(), credential.clone());
        }

        prev_trusted
    }

    fn collect_non_reusable_credential_owners<F>(
        &self,
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
        mut is_peer_active: F,
    ) -> (HashMap<Vec<u8>, PeerId>, BTreeSet<PeerId>)
    where
        F: FnMut(PeerId) -> bool,
    {
        let mut candidates: BTreeMap<Vec<u8>, BTreeSet<PeerId>> = BTreeMap::new();

        for (peer_id, info) in peer_infos.iter() {
            if info.noise_static_pubkey.is_empty() {
                continue;
            }

            let Some(credential) = all_trusted.get(&info.noise_static_pubkey) else {
                continue;
            };
            if Self::credential_is_reusable(credential) {
                continue;
            }
            if !is_peer_active(*peer_id) {
                continue;
            }

            candidates
                .entry(info.noise_static_pubkey.clone())
                .or_default()
                .insert(*peer_id);
        }

        let mut active_owners = HashMap::new();
        let mut duplicate_untrusted_peers = BTreeSet::new();

        for (pubkey, candidate_peer_ids) in candidates {
            let Some(owner_peer_id) = candidate_peer_ids.iter().next().copied() else {
                continue;
            };
            active_owners.insert(pubkey, owner_peer_id);

            duplicate_untrusted_peers.extend(
                candidate_peer_ids
                    .into_iter()
                    .filter(|peer_id| *peer_id != owner_peer_id),
            );
        }

        (active_owners, duplicate_untrusted_peers)
    }

    fn replace_non_reusable_credential_owners(&self, active_owners: HashMap<Vec<u8>, PeerId>) {
        self.non_reusable_credential_owners
            .retain(|pubkey, _| active_owners.contains_key(pubkey));

        for (pubkey, peer_id) in active_owners {
            self.non_reusable_credential_owners.insert(pubkey, peer_id);
        }
    }

    fn replace_suppressed_non_reusable_credential_peers(
        &self,
        suppressed_peers: BTreeSet<PeerId>,
    ) -> bool {
        let current: BTreeSet<_> = self
            .suppressed_non_reusable_credential_peers
            .iter()
            .map(|entry| *entry.key())
            .collect();
        if current == suppressed_peers {
            return false;
        }

        self.suppressed_non_reusable_credential_peers
            .retain(|peer_id, _| suppressed_peers.contains(peer_id));

        for peer_id in suppressed_peers {
            self.suppressed_non_reusable_credential_peers
                .insert(peer_id, ());
        }

        self.version.inc();
        true
    }

    fn update_credential_groups(
        &self,
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
    ) {
        for (_, info) in peer_infos.iter() {
            if info.noise_static_pubkey.is_empty() {
                continue;
            }

            let Some(credential) = all_trusted.get(&info.noise_static_pubkey) else {
                continue;
            };
            let mut group_map = self.get_proof_groups(info.peer_id);
            for group in &credential.groups {
                group_map.entry(group.clone()).or_default();
            }
            self.set_peer_groups(info.peer_id, group_map);
        }
    }

    fn collect_revoked_credential_peers(
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        prev_trusted: &HashSet<Vec<u8>>,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
    ) -> BTreeSet<PeerId> {
        let mut untrusted_peers = BTreeSet::new();

        for (peer_id, info) in peer_infos.iter() {
            if info.noise_static_pubkey.is_empty() || info.version == 0 {
                continue;
            }

            if prev_trusted.contains(&info.noise_static_pubkey)
                && !all_trusted.contains_key(&info.noise_static_pubkey)
            {
                untrusted_peers.insert(*peer_id);
            }
        }

        untrusted_peers
    }

    fn get_connected_peers<T: FromIterator<PeerId>>(&self, peer_id: PeerId) -> Option<T> {
        self.conn_map
            .read()
            .get(&peer_id)
            .map(|x| x.connected_peers.iter().copied().collect())
    }

    fn route_snapshot(&self) -> OspfRouteSnapshot {
        let version = self.version.get();
        OspfRouteSnapshot {
            peer_infos: self
                .peer_infos
                .read()
                .iter()
                .map(|(peer_id, info)| OspfPeerInfo {
                    peer_id: *peer_id,
                    info: info.clone(),
                })
                .collect(),
            conn_map: self
                .conn_map
                .read()
                .iter()
                .map(|(peer_id, info)| OspfPeerConnInfo {
                    peer_id: *peer_id,
                    connected_peers: info.connected_peers.clone(),
                })
                .collect(),
            suppressed_peer_ids: self
                .suppressed_non_reusable_credential_peers
                .iter()
                .map(|entry| *entry.key())
                .collect(),
            version,
        }
    }

    fn remove_peer(&self, peer_id: PeerId) {
        self.remove_peers([peer_id]);
    }

    fn remove_peers<I>(&self, peer_ids: I)
    where
        I: IntoIterator<Item = PeerId>,
    {
        let peer_ids: HashSet<_> = peer_ids.into_iter().collect();
        if peer_ids.is_empty() {
            return;
        }

        for peer_id in &peer_ids {
            tracing::warn!(?peer_id, "remove_peer from synced_route_info");
        }

        {
            let mut peer_infos = self.peer_infos.write();
            let mut conn_map = self.conn_map.write();
            for peer_id in &peer_ids {
                peer_infos.remove(peer_id);
                conn_map.remove(peer_id);
            }
        }

        for peer_id in &peer_ids {
            self.raw_peer_infos.remove(peer_id);
            self.group_trust_map.remove(peer_id);
            self.group_trust_map_cache.remove(peer_id);
        }
        self.foreign_network
            .retain(|k, _| !peer_ids.contains(&k.peer_id));

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
                let mut peer_info =
                    new_route_peer_info_with_version(self.default_easytier_version.clone());
                let mut guard = RwLockUpgradableReadGuard::upgrade(guard);
                peer_info.last_update = Some(Timestamp::now());
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
            route_info.last_update = Some(Timestamp::now());
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
            need_inc_version |= self.update_conn_info_one_peer(peer_id_version, connceted_peers);
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
            need_inc_version |= self.update_conn_info_one_peer(&peer_id_version, connected_peers);
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

    fn update_foreign_network(&self, foreign_network: &RouteForeignNetworkInfos) -> bool {
        let mut changed = false;
        for item in foreign_network.infos.iter().map(Clone::clone) {
            let Some(key) = item.key else {
                continue;
            };
            let Some(mut entry) = item.value else {
                continue;
            };

            entry.last_update = Some(Timestamp::now());

            self.foreign_network
                .entry(key.clone())
                .and_modify(|old_entry| {
                    if entry.version > old_entry.version {
                        *old_entry = entry.clone();
                        changed = true;
                    }
                })
                .or_insert_with(|| {
                    changed = true;
                    entry.clone()
                });
        }
        changed
    }

    fn update_my_peer_info(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        context: &dyn PeerContext,
        public_ipv6_addr_lease: Option<Ipv6Inet>,
    ) -> bool {
        let mut new = new_updated_self_route_peer_info(
            my_peer_id,
            my_peer_route_id,
            context,
            public_ipv6_addr_lease,
        );
        let mut guard = self.peer_infos.upgradable_read();
        let old = guard.get(&my_peer_id);
        let new_version = old.map(|x| x.version).unwrap_or(0) + 1;
        let need_insert_new = if let Some(old) = old {
            try_update_new_peer_info(old, &mut new)
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
                new.last_update = Some(Timestamp::now());
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
                item.last_update = Some(Timestamp::now());
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
        local_group_declarations: &[PeerGroupIdentity],
        trust_admin_groups_without_proof: bool,
    ) {
        let local_group_declarations = local_group_declarations
            .iter()
            .map(|g| (g.group_name.as_str(), g.group_secret.as_str()))
            .collect::<std::collections::HashMap<&str, &str>>();

        let verify_groups = |info: &RoutePeerInfo| -> HashMap<String, Vec<u8>> {
            let mut trusted_groups_for_peer: HashMap<String, Vec<u8>> = HashMap::new();

            for group_proof in &info.groups {
                let name = &group_proof.group_name;
                let proof_bytes = group_proof.group_proof.clone();

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

            if trust_admin_groups_without_proof && self.is_admin_peer(info) {
                for group_proof in &info.groups {
                    trusted_groups_for_peer
                        .entry(group_proof.group_name.clone())
                        .or_default();
                }
            }

            trusted_groups_for_peer
        };

        for info in peer_infos {
            match self.group_trust_map.entry(info.peer_id) {
                dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                    let trusted_groups_for_peer = verify_groups(info);

                    if trusted_groups_for_peer.is_empty() {
                        entry.remove();
                        self.group_trust_map_cache.remove(&info.peer_id);
                    } else {
                        let group_names = trusted_groups_for_peer.keys().cloned().collect();
                        self.group_trust_map_cache
                            .insert(info.peer_id, Arc::new(group_names));
                        *entry.get_mut() = trusted_groups_for_peer;
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    let trusted_groups_for_peer = verify_groups(info);

                    if !trusted_groups_for_peer.is_empty() {
                        let group_names = trusted_groups_for_peer.keys().cloned().collect();
                        self.group_trust_map_cache
                            .insert(info.peer_id, Arc::new(group_names));
                        entry.insert(trusted_groups_for_peer);
                    }
                }
            }
        }
    }

    fn update_my_group_trusts(&self, my_peer_id: PeerId, groups: &[PeerGroupInfo]) {
        let mut my_group_map = HashMap::new();

        for group in groups.iter() {
            my_group_map.insert(group.group_name.clone(), group.group_proof.clone());
        }

        self.set_peer_groups(my_peer_id, my_group_map);
    }

    /// Collect trusted credential pubkeys from admin nodes (network_secret holders)
    /// and verify credential peers. Returns set of peer_ids that should be removed.
    /// Also returns trusted-key metadata for the core trust-state update.
    fn verify_and_update_credential_trusts(
        &self,
        network_secret: Option<&str>,
    ) -> (Vec<PeerId>, HashMap<Vec<u8>, TrustedKeyMetadata>) {
        self.verify_and_update_credential_trusts_with_active_peers(network_secret, |_| true)
    }

    fn verify_and_update_credential_trusts_with_active_peers<F>(
        &self,
        network_secret: Option<&str>,
        is_peer_active: F,
    ) -> (Vec<PeerId>, HashMap<Vec<u8>, TrustedKeyMetadata>)
    where
        F: FnMut(PeerId) -> bool,
    {
        let (untrusted_peers, global_trusted_keys, _) = self
            .verify_and_update_credential_trusts_with_active_peers_protecting(
                network_secret,
                is_peer_active,
                None,
            );
        (untrusted_peers, global_trusted_keys)
    }

    fn verify_and_update_credential_trusts_with_active_peers_protecting<F>(
        &self,
        network_secret: Option<&str>,
        is_peer_active: F,
        protected_peer_id: Option<PeerId>,
    ) -> (Vec<PeerId>, HashMap<Vec<u8>, TrustedKeyMetadata>, bool)
    where
        F: FnMut(PeerId) -> bool,
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let peer_infos = self.peer_infos.read();
        let (all_trusted, global_trusted_keys) =
            self.collect_trusted_credentials(&peer_infos, network_secret, now);
        let prev_trusted = self.replace_trusted_credential_pubkeys(&all_trusted);
        let (active_non_reusable_owners, mut duplicate_untrusted_peers) =
            self.collect_non_reusable_credential_owners(&peer_infos, &all_trusted, is_peer_active);
        if let Some(protected_peer_id) = protected_peer_id {
            duplicate_untrusted_peers.remove(&protected_peer_id);
        }
        self.replace_non_reusable_credential_owners(active_non_reusable_owners);
        let suppressed_changed =
            self.replace_suppressed_non_reusable_credential_peers(duplicate_untrusted_peers);
        self.update_credential_groups(&peer_infos, &all_trusted);

        let mut untrusted_peers =
            Self::collect_revoked_credential_peers(&peer_infos, &prev_trusted, &all_trusted);
        if let Some(protected_peer_id) = protected_peer_id {
            untrusted_peers.remove(&protected_peer_id);
        }

        // Remove untrusted peers from peer_infos so they won't appear in route graph
        if !untrusted_peers.is_empty() {
            drop(peer_infos); // release read lock before writing
            for peer_id in &untrusted_peers {
                tracing::warn!(?peer_id, "removing untrusted peer from route info");
            }
            self.remove_peers(untrusted_peers.iter().copied());
        }

        (
            untrusted_peers.into_iter().collect(),
            global_trusted_keys,
            suppressed_changed,
        )
    }

    fn is_admin_peer(&self, info: &RoutePeerInfo) -> bool {
        if info.version == 0 {
            return false;
        }
        !Self::is_credential_peer_info(info)
    }

    fn is_credential_peer(&self, peer_id: PeerId) -> bool {
        let peer_infos = self.peer_infos.read();
        peer_infos
            .get(&peer_id)
            .map(Self::is_credential_peer_info)
            .unwrap_or(false)
    }

    fn get_credential_info_by_pubkey(&self, peer_pubkey: &[u8]) -> Option<TrustedCredentialPubkey> {
        if peer_pubkey.is_empty() {
            return None;
        }
        self.trusted_credential_pubkeys
            .get(peer_pubkey)
            .map(|r| r.value().clone())
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

    async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
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
#[allow(dead_code)]
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
    context: ArcPeerContext,
    sessions: DashMap<PeerId, Arc<SyncRouteSession>>,
    stopped: AtomicBool,
    session_operation: AsyncRwLock<()>,

    interface: Mutex<Option<RouteInterfaceBox>>,

    cost_calculator: std::sync::RwLock<Option<RouteCostCalculator>>,
    route_table: OspfRouteTable,
    route_table_with_cost: OspfRouteTable,
    foreign_network_owner_map: DashMap<CoreNetworkIdentity, Vec<PeerId>>,
    foreign_network_my_peer_id_map: DashMap<(String, PeerId), PeerId>,
    synced_route_info: SyncedRouteInfo,
    public_ipv6_service: std::sync::Mutex<Weak<PublicIpv6Service>>,
    self_public_ipv6_addr_lease: std::sync::Mutex<Option<Ipv6Inet>>,
    cached_local_conn_map: std::sync::Mutex<RouteConnBitmap>,
    cached_local_conn_map_version: AtomicVersion,
    cached_interface_peer_snapshot: std::sync::Mutex<Arc<InterfacePeerSnapshot>>,
    interface_peers_generation: AtomicU64,
    applied_interface_peers_generation: AtomicU64,

    last_update_my_foreign_network: AtomicCell<Option<Instant>>,

    peer_info_last_update: AtomicCell<Instant>,
}

impl Debug for PeerRouteServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRouteServiceImpl")
            .field("my_peer_id", &self.my_peer_id)
            .field("my_peer_route_id", &self.my_peer_route_id)
            .field("network", &self.context.network_identity())
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

#[allow(dead_code)]
impl PeerRouteServiceImpl {
    fn new(my_peer_id: PeerId, context: ArcPeerContext) -> Self {
        PeerRouteServiceImpl {
            my_peer_id,
            my_peer_route_id: rand::random(),
            context: context.clone(),
            sessions: DashMap::new(),
            stopped: AtomicBool::new(false),
            session_operation: AsyncRwLock::new(()),

            interface: Mutex::new(None),

            cost_calculator: std::sync::RwLock::new(Some(Box::new(DefaultRouteCostCalculator))),

            route_table: OspfRouteTable::new(),
            route_table_with_cost: OspfRouteTable::new(),
            foreign_network_owner_map: DashMap::new(),
            foreign_network_my_peer_id_map: DashMap::new(),

            synced_route_info: SyncedRouteInfo {
                default_easytier_version: context.easytier_version(),
                peer_infos: RwLock::new(OrderedHashMap::new()),
                raw_peer_infos: DashMap::new(),
                conn_map: RwLock::new(OrderedHashMap::new()),
                foreign_network: DashMap::new(),
                group_trust_map: DashMap::new(),
                group_trust_map_cache: DashMap::new(),
                trusted_credential_pubkeys: DashMap::new(),
                non_reusable_credential_owners: DashMap::new(),
                suppressed_non_reusable_credential_peers: DashMap::new(),
                version: AtomicVersion::new(),
            },
            public_ipv6_service: std::sync::Mutex::new(Weak::new()),
            self_public_ipv6_addr_lease: std::sync::Mutex::new(None),
            cached_local_conn_map: std::sync::Mutex::new(RouteConnBitmap::default()),
            cached_local_conn_map_version: AtomicVersion::new(),
            cached_interface_peer_snapshot: std::sync::Mutex::new(Arc::new(
                InterfacePeerSnapshot::default(),
            )),
            interface_peers_generation: AtomicU64::new(1),
            applied_interface_peers_generation: AtomicU64::new(0),

            last_update_my_foreign_network: AtomicCell::new(None),

            peer_info_last_update: AtomicCell::new(Instant::now()),
        }
    }

    fn is_credential_node(&self) -> bool {
        self.context.network_identity().network_secret.is_none()
            && self
                .context
                .secure_mode()
                .map(|c| c.enabled)
                .unwrap_or(false)
    }

    fn set_public_ipv6_service(&self, service: Weak<PublicIpv6Service>) {
        *self.public_ipv6_service.lock().unwrap() = service;
    }

    fn public_ipv6_service(&self) -> Option<Arc<PublicIpv6Service>> {
        self.public_ipv6_service.lock().unwrap().upgrade()
    }

    fn notify_public_ipv6_route_change(&self) -> bool {
        self.public_ipv6_service()
            .map(|service| service.handle_route_change())
            .unwrap_or(false)
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

    pub fn mark_interface_peers_dirty(&self) {
        self.interface_peers_generation
            .fetch_add(1, Ordering::Relaxed);
    }

    async fn interface_peer_snapshot_uncached(&self) -> InterfacePeerSnapshot {
        let interface = self.interface.lock().await;
        let interface = interface.as_ref().unwrap();

        let peers: BTreeSet<_> = interface.list_peers().await.into_iter().collect();
        let mut identity_types = BTreeMap::new();
        for peer_id in peers.iter().copied() {
            identity_types.insert(peer_id, interface.get_peer_identity_type(peer_id).await);
        }

        InterfacePeerSnapshot {
            generation: 0,
            peers,
            identity_types,
        }
    }

    async fn interface_peer_snapshot(&self) -> Arc<InterfacePeerSnapshot> {
        loop {
            let start_generation = self.interface_peers_generation.load(Ordering::Acquire);
            {
                let cached = self.cached_interface_peer_snapshot.lock().unwrap();
                if cached.generation == start_generation {
                    return cached.clone();
                }
            }

            let mut snapshot = self.interface_peer_snapshot_uncached().await;
            let end_generation = self.interface_peers_generation.load(Ordering::Acquire);
            if start_generation == end_generation {
                snapshot.generation = end_generation;
                let snapshot = Arc::new(snapshot);
                *self.cached_interface_peer_snapshot.lock().unwrap() = snapshot.clone();
                return snapshot;
            }
        }
    }

    async fn list_peers_from_interface_snapshot(&self) -> (u64, BTreeSet<PeerId>) {
        let snapshot = self.interface_peer_snapshot().await;
        (snapshot.generation, snapshot.peers.clone())
    }

    async fn get_peer_identity_type_from_interface(
        &self,
        peer_id: PeerId,
    ) -> Option<PeerIdentityType> {
        let snapshot = self.interface_peer_snapshot().await;
        if let Some(identity_type) = snapshot.identity_types.get(&peer_id) {
            return *identity_type;
        }

        self.interface
            .lock()
            .await
            .as_ref()
            .unwrap()
            .get_peer_identity_type(peer_id)
            .await
    }

    async fn get_peer_public_key_from_interface(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        self.interface
            .lock()
            .await
            .as_ref()
            .unwrap()
            .get_peer_public_key(peer_id)
            .await
    }

    fn update_my_peer_info(&self) -> bool {
        self.synced_route_info.update_my_peer_info(
            self.my_peer_id,
            self.my_peer_route_id,
            self.context.as_ref(),
            *self.self_public_ipv6_addr_lease.lock().unwrap(),
        )
    }

    async fn update_my_conn_info(&self) -> bool {
        let current_generation = self.interface_peers_generation.load(Ordering::Acquire);
        let generation_applied = self
            .applied_interface_peers_generation
            .load(Ordering::Acquire)
            == current_generation;
        if generation_applied {
            let need_periodic_requery = self
                .interface
                .lock()
                .await
                .as_ref()
                .map(|x| x.need_periodic_requery_peers())
                .unwrap_or(false);
            if !need_periodic_requery {
                return false;
            }

            self.mark_interface_peers_dirty();
        }

        let (generation, connected_peers) = self.list_peers_from_interface_snapshot().await;
        let updated = self
            .synced_route_info
            .update_my_conn_info(self.my_peer_id, connected_peers);
        self.applied_interface_peers_generation
            .store(generation, Ordering::Release);
        updated
    }

    async fn update_my_foreign_network(&self) -> bool {
        let last_time = self.last_update_my_foreign_network.load();
        if last_time.is_some()
            && last_time.unwrap().elapsed().as_secs()
                < self.context.ospf_update_my_foreign_network_interval_sec()
        {
            return false;
        }

        self.last_update_my_foreign_network
            .store(Some(Instant::now()));

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
        let route_snapshot = self.synced_route_info.route_snapshot();

        self.route_table.build_from_snapshot(
            self.my_peer_id,
            &route_snapshot,
            NextHopPolicy::LeastHop,
            calc_locked.as_ref().unwrap(),
        );

        self.route_table_with_cost.build_from_snapshot(
            self.my_peer_id,
            &route_snapshot,
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
            let network_identity = CoreNetworkIdentity {
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

    fn handle_peer_context_event(&self, _event: &PeerContextEvent) {
        self.mark_interface_peers_dirty();
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
            if !self.route_table.topology_peer_reachable(src_peer_id) {
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
                let last_update = SystemTime::try_from(last_update).unwrap();
                if last_sync_succ_timestamp.is_some_and(|t| last_update < t) {
                    break;
                }
            }

            if session.check_saved_peer_info_update_to_date(peer_info.peer_id, peer_info.version) {
                continue;
            }

            // do not send unreachable peer info to dst peer.
            if !self.route_table.topology_peer_reachable(*peer_id) {
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

            if self.route_table.topology_peer_reachable(*peer_id) {
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
                break;
            }

            if session.check_saved_conn_version_update_to_date(*peer_id, conn_info.version.get()) {
                continue;
            }

            if !self.route_table.topology_peer_reachable(*peer_id) {
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

            if self.route_table.topology_peer_reachable(*peer_id) {
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
        let mut untrusted_changed = false;
        if my_peer_info_updated || my_conn_info_updated {
            untrusted_changed = self.refresh_credential_trusts_and_disconnect().await;
        }

        let mut public_ipv6_state_updated = false;
        if my_peer_info_updated || my_conn_info_updated || untrusted_changed {
            self.update_route_table_and_cached_local_conn_bitmap();
            self.update_foreign_network_owner_map();
            public_ipv6_state_updated = self.notify_public_ipv6_route_change();
        }
        if my_peer_info_updated {
            self.update_peer_info_last_update();
        }
        my_peer_info_updated
            || my_conn_info_updated
            || my_foreign_network_updated
            || public_ipv6_state_updated
    }

    async fn refresh_acl_groups(&self) -> bool {
        let my_peer_info_updated = self.update_my_peer_info();
        let trust_admin_groups_without_proof =
            self.context.network_identity().network_secret.is_none();

        let peer_infos: Vec<_> = self
            .synced_route_info
            .peer_infos
            .read()
            .iter()
            .map(|(_, info)| info.clone())
            .collect();
        self.synced_route_info.verify_and_update_group_trusts(
            &peer_infos,
            &self.context.acl_group_declarations(),
            trust_admin_groups_without_proof,
        );

        let untrusted = self.refresh_credential_trusts_with_current_topology();
        self.disconnect_untrusted_peers(&untrusted).await;

        let mut public_ipv6_state_updated = false;
        if my_peer_info_updated || !untrusted.is_empty() {
            self.update_route_table_and_cached_local_conn_bitmap();
            self.update_foreign_network_owner_map();
            public_ipv6_state_updated = self.notify_public_ipv6_route_change();
        }
        if my_peer_info_updated {
            self.update_peer_info_last_update();
        }

        my_peer_info_updated || !untrusted.is_empty() || public_ipv6_state_updated
    }

    fn refresh_credential_trusts(&self) -> Vec<PeerId> {
        let network_identity = self.context.network_identity();
        let (untrusted, global_trusted_keys, _) = self
            .synced_route_info
            .verify_and_update_credential_trusts_with_active_peers_protecting(
                network_identity.network_secret.as_deref(),
                |_| true,
                Some(self.my_peer_id),
            );
        PeerContext::update_trusted_keys(
            self.context.as_ref(),
            global_trusted_keys,
            &network_identity.network_name,
        );

        untrusted
    }

    fn refresh_credential_trusts_with_current_topology(&self) -> Vec<PeerId> {
        let network_identity = self.context.network_identity();

        // Non-reusable credential owner election depends on reachability, so rebuild the
        // route table from the latest synced peer/conn state before checking active peers.
        self.update_route_table_and_cached_local_conn_bitmap();

        let (untrusted, global_trusted_keys, suppressed_changed) = self
            .synced_route_info
            .verify_and_update_credential_trusts_with_active_peers_protecting(
                network_identity.network_secret.as_deref(),
                |peer_id| {
                    peer_id == self.my_peer_id || self.route_table.topology_peer_reachable(peer_id)
                },
                Some(self.my_peer_id),
            );
        PeerContext::update_trusted_keys(
            self.context.as_ref(),
            global_trusted_keys,
            &network_identity.network_name,
        );

        if !untrusted.is_empty() || suppressed_changed {
            self.update_route_table_and_cached_local_conn_bitmap();
        }
        untrusted
    }

    async fn refresh_credential_trusts_and_disconnect(&self) -> bool {
        let untrusted = self.refresh_credential_trusts_with_current_topology();
        self.disconnect_untrusted_peers(&untrusted).await;
        !untrusted.is_empty()
    }

    async fn disconnect_untrusted_peers(&self, untrusted_peers: &[PeerId]) {
        if untrusted_peers.is_empty() {
            return;
        }

        let interface = self.interface.lock().await;
        let Some(interface) = interface.as_ref() else {
            return;
        };

        for peer_id in untrusted_peers {
            tracing::warn!(?peer_id, "disconnecting untrusted peer");
            interface.close_peer(*peer_id).await;
        }
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

    async fn clear_expired_peer(&self) {
        let now = SystemTime::now();
        let mut to_remove = Vec::new();
        for (peer_id, peer_info) in self.synced_route_info.peer_infos.read().iter() {
            if let Ok(d) = now.duration_since(peer_info.last_update.unwrap().try_into().unwrap())
                && (d > REMOVE_DEAD_PEER_INFO_AFTER
                    || (d > REMOVE_UNREACHABLE_PEER_INFO_AFTER
                        && !self.route_table.topology_peer_reachable(*peer_id)))
            {
                to_remove.push(*peer_id);
            }
        }

        self.synced_route_info
            .remove_peers(to_remove.iter().copied());

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

        self.refresh_credential_trusts_and_disconnect().await;
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

        tracing::debug!(
            ?foreign_network,
            "sync_route request need send to peer. my_id {:?}, dst_peer_id: {:?}, peer_infos: {:?}, conn_info: {:?}, synced_route_info: {:?} session: {:?}",
            my_peer_id,
            dst_peer_id,
            peer_infos,
            conn_info,
            self.synced_route_info,
            session
        );

        session
            .need_sync_initiator_info
            .store(false, Ordering::Relaxed);

        let rpc_stub = peer_rpc
            .rpc_client()
            .scoped_client::<OspfRouteRpcClientFactory<BaseController>>(
                self.my_peer_id,
                dst_peer_id,
                self.context.network_name(),
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
            ret,
            sync_route_info_req,
            session,
            self.context.network_identity(),
            next_last_sync_succ_timestamp
        );

        match ret.as_ref() {
            Err(e) => {
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
            }
            Ok(resp) => {
                if let Some(err) = resp.error {
                    if err == Error::DuplicatePeerId as i32 {
                        if !self.context.feature_flags().is_public_server {
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

                    if let Some(conn_info) = &conn_info {
                        session.update_dst_saved_conn_info_version(conn_info, dst_peer_id);
                    }

                    if let Some(foreign_network) = &foreign_network {
                        session
                            .update_dst_saved_foreign_network_version(foreign_network, dst_peer_id);
                    }
                    session.update_last_sync_succ_timestamp(next_last_sync_succ_timestamp);
                }
            }
        }
        false
    }

    fn update_peer_info_last_update(&self) {
        tracing::debug!(
            "update_peer_info_last_update, my_peer_id: {:?}, prev: {:?}, new: {:?}",
            self.my_peer_id,
            self.peer_info_last_update.load(),
            Instant::now()
        );
        self.peer_info_last_update.store(Instant::now());
    }

    fn get_peer_info_last_update(&self) -> Instant {
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

#[allow(dead_code)]
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
        const RETRY_BASE_MS: u64 = 50;
        const RETRY_MAX_MS: u64 = 5000;

        let mut last_sync = Instant::now();
        let mut last_clean_dst_saved_map = Instant::now();
        // Keep retry_delay_ms across outer iterations so that rapid
        // connect/disconnect flaps don't fully reset the backoff.
        let mut retry_delay_ms = RETRY_BASE_MS;
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
                    // Successful sync: decay backoff towards base so the next
                    // real failure still starts at a reasonable level, but
                    // don't fully reset to avoid 50ms bursts during flapping.
                    retry_delay_ms = (retry_delay_ms / 2).max(RETRY_BASE_MS);
                    break;
                }

                drop(service_impl);
                drop(peer_rpc);

                crate::runtime_time::sleep(Duration::from_millis(retry_delay_ms)).await;
                retry_delay_ms = (retry_delay_ms * 2).min(RETRY_MAX_MS);
            }

            sync_now = sync_now.resubscribe();

            select! {
                _ = crate::runtime_time::sleep(Duration::from_secs(1)) => {}
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
        if service_impl.stopped.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }

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
                _ = crate::runtime_time::sleep(Duration::from_millis(next_sleep_ms)) => {}
                _ = recv.recv() => {}
            }

            let interface_snapshot = service_impl.interface_peer_snapshot().await;
            let peers = &interface_snapshot.peers;
            let session_peers = self.list_session_peer_set();
            for peer_id in session_peers.iter() {
                if !peers.contains(peer_id) {
                    if Some(*peer_id) == cur_dst_peer_id_to_initiate {
                        cur_dst_peer_id_to_initiate = None;
                    }
                    let _ = self.stop_session(*peer_id);
                }
            }

            // find peer_ids that are not initiators.
            let mut initiator_candidates = Vec::new();
            for peer_id in peers.iter().copied() {
                // Step 9a: Filter OSPF session candidates based on direct auth level.
                // - Credential nodes only initiate sessions to admin nodes (not other credential nodes)
                // - Admin nodes don't initiate sessions to credential nodes
                let identity_type = interface_snapshot
                    .identity_types
                    .get(&peer_id)
                    .copied()
                    .flatten()
                    .unwrap_or(PeerIdentityType::Admin);
                if matches!(identity_type, PeerIdentityType::Credential) {
                    continue;
                }

                let Some(session) = service_impl.get_session(peer_id) else {
                    initiator_candidates.push(peer_id);
                    continue;
                };

                if !session.dst_is_initiator.load(Ordering::Relaxed) {
                    initiator_candidates.push(peer_id);
                }
            }

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
                if let Some(cur_peer_id_to_initiate) = cur_dst_peer_id_to_initiate
                    && let Some(session) = service_impl.get_session(cur_peer_id_to_initiate)
                {
                    session.update_initiator_flag(false);
                }

                cur_dst_peer_id_to_initiate = new_initiator_dst;
                // update initiator flag for new session
                let Ok(session) = self.get_or_start_session(new_initiator_dst.unwrap()) else {
                    tracing::warn!("get_or_start_session failed");
                    continue;
                };
                session.update_initiator_flag(true);
                self.sync_now("update_initiator_flag");
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

    fn list_session_peer_set(&self) -> BTreeSet<PeerId> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return BTreeSet::new();
        };

        service_impl.list_session_peers().into_iter().collect()
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

    fn extract_credential_peer_info(
        &self,
        from_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
        credential: &TrustedCredentialPubkey,
    ) -> Option<(RoutePeerInfo, DynamicMessage)> {
        let info_idx = peer_infos.iter().position(|p| p.peer_id == from_peer_id)?;
        let mut info = peer_infos[info_idx].clone();
        let mut raw_info = raw_peer_infos[info_idx].clone();
        let allowed_cidrs = &credential.allowed_proxy_cidrs;
        // Filter proxy_cidrs to only those allowed by credential
        if !allowed_cidrs.is_empty() {
            info.proxy_cidrs.retain(|cidr| {
                allowed_cidrs
                    .iter()
                    .any(|allowed| cidr_is_subset_str(cidr, allowed))
            });
        } else {
            // No allowed_proxy_cidrs → no proxy_cidrs allowed
            info.proxy_cidrs.clear();
        }
        SyncedRouteInfo::mark_credential_peer(&mut info, true);
        patch_raw_from_info(&mut raw_info, &info, &["proxy_cidrs", "feature_flag"]);
        Some((info, raw_info))
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
        let _session_operation = service_impl.session_operation.read().await;
        if service_impl.stopped.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }

        let my_peer_id = service_impl.my_peer_id;
        let session = self.get_or_start_session(from_peer_id)?;

        let from_identity_type = service_impl
            .get_peer_identity_type_from_interface(from_peer_id)
            .await
            .unwrap_or(PeerIdentityType::Admin);
        let from_is_credential = matches!(from_identity_type, PeerIdentityType::Credential);
        let credential_info = if from_is_credential {
            service_impl
                .get_peer_public_key_from_interface(from_peer_id)
                .await
                .and_then(|pubkey| {
                    service_impl
                        .synced_route_info
                        .get_credential_info_by_pubkey(&pubkey)
                })
        } else {
            None
        };
        if from_is_credential && credential_info.is_none() {
            // no credential found
            return Err(Error::Stopped);
        }

        let _session_lock = session.lock.lock();

        session.rpc_rx_count.fetch_add(1, Ordering::Relaxed);

        session.update_dst_session_id(from_session_id);

        let mut need_update_route_table = false;
        let mut untrusted_peers = Vec::new();

        if let Some(peer_infos) = &peer_infos {
            // Step 9b: credential peers can only propagate their own route info
            // patch_raw_from_info(&mut raw, info, &["proxy_cidrs", "feature_flag"]);
            let (pi, rpi) = if from_is_credential {
                if let Some(ret) = self.extract_credential_peer_info(
                    from_peer_id,
                    peer_infos,
                    raw_peer_infos.as_deref().unwrap(),
                    credential_info.as_ref().unwrap(),
                ) {
                    (&vec![ret.0], &vec![ret.1])
                } else {
                    (&vec![], &vec![])
                }
            } else {
                (peer_infos, raw_peer_infos.as_ref().unwrap())
            };
            if !pi.is_empty() {
                let trust_admin_groups_without_proof = service_impl
                    .context
                    .network_identity()
                    .network_secret
                    .is_none();
                service_impl.synced_route_info.update_peer_infos(
                    my_peer_id,
                    service_impl.my_peer_route_id,
                    from_peer_id,
                    pi,
                    rpi,
                )?;
                service_impl
                    .synced_route_info
                    .verify_and_update_group_trusts(
                        pi,
                        &service_impl.context.acl_group_declarations(),
                        trust_admin_groups_without_proof,
                    );
                session.update_dst_saved_peer_info_version(pi, from_peer_id);
                need_update_route_table = true;
            }
        }

        // Step 9b: credential peers' conn_info depends on allow_relay flag
        if let Some(conn_info) = &conn_info {
            let accept_conn_info =
                !from_is_credential || credential_info.map(|tc| tc.allow_relay).unwrap_or(false);
            if accept_conn_info {
                service_impl.synced_route_info.update_conn_info(conn_info);
                session.update_dst_saved_conn_info_version(conn_info, from_peer_id);
                need_update_route_table = true;
            }
        }

        if need_update_route_table {
            untrusted_peers = service_impl.refresh_credential_trusts_with_current_topology();
        }

        let mut foreign_network_changed = false;
        if let Some(foreign_network) = &foreign_network {
            // Step 9b: credential peers' foreign_network_infos are always ignored
            if !from_is_credential {
                foreign_network_changed = service_impl
                    .synced_route_info
                    .update_foreign_network(foreign_network);
                session.update_dst_saved_foreign_network_version(foreign_network, from_peer_id);
            }
        }

        if need_update_route_table || foreign_network_changed {
            service_impl.update_route_table_and_cached_local_conn_bitmap();
            service_impl.update_foreign_network_owner_map();
            if need_update_route_table
                && let Some(public_ipv6_service) = service_impl.public_ipv6_service()
            {
                public_ipv6_service.handle_route_change();
            }
        }

        tracing::debug!(
            "handling sync_route_info rpc: from_peer_id: {:?}, is_initiator: {:?}, peer_infos: {:?}, conn_info: {:?}, synced_route_info: {:?} session: {:?}, new_route_table: {:?}",
            from_peer_id,
            is_initiator,
            peer_infos,
            conn_info,
            service_impl.synced_route_info,
            session,
            service_impl.route_table
        );

        session
            .dst_is_initiator
            .store(is_initiator, Ordering::Relaxed);
        let is_initiator = session.we_are_initiator.load(Ordering::Relaxed);
        let session_id = session.my_session_id.load(Ordering::Relaxed);

        drop(_session_lock);
        service_impl
            .disconnect_untrusted_peers(&untrusted_peers)
            .await;

        // Only trigger reverse sync when we actually received new data that
        // needs to be propagated to other peers.  Previously this was
        // unconditional, which created an A→B→A→B ping-pong storm even when
        // there was nothing new to propagate.
        if need_update_route_table || foreign_network_changed {
            self.sync_now("sync_route_info");
        }

        Ok(SyncRouteInfoResponse {
            is_initiator,
            session_id,
            error: None,
        })
    }
}

struct OspfPublicIpv6RouteHandle {
    service_impl: Weak<PeerRouteServiceImpl>,
}

impl PublicIpv6RouteControl for OspfPublicIpv6RouteHandle {
    fn my_peer_id(&self) -> PeerId {
        self.service_impl
            .upgrade()
            .map(|service_impl| service_impl.my_peer_id)
            .unwrap_or_default()
    }

    fn peer_route_snapshot(&self) -> Vec<PublicIpv6PeerRouteInfo> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Vec::new();
        };

        service_impl
            .synced_route_info
            .peer_infos
            .read()
            .iter()
            .map(|(peer_id, info)| PublicIpv6PeerRouteInfo {
                peer_id: *peer_id,
                inst_id: route_peer_inst_id(info),
                is_provider: info
                    .feature_flag
                    .as_ref()
                    .map(|flags| flags.ipv6_public_addr_provider)
                    .unwrap_or(false),
                prefix: info
                    .ipv6_public_addr_prefix
                    .map(Into::into)
                    .map(|prefix: Ipv6Inet| prefix.network()),
                lease: info.ipv6_public_addr_lease.map(Into::into),
                reachable: *peer_id == service_impl.my_peer_id
                    || service_impl.route_table.peer_reachable(*peer_id),
            })
            .collect()
    }

    fn publish_self_public_ipv6_lease(&self, lease: Option<Ipv6Inet>) -> bool {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return false;
        };

        let mut current = service_impl.self_public_ipv6_addr_lease.lock().unwrap();
        if *current == lease {
            return false;
        }
        *current = lease;
        drop(current);

        let changed = service_impl.update_my_peer_info();
        if changed {
            service_impl.update_route_table_and_cached_local_conn_bitmap();
            service_impl.update_foreign_network_owner_map();
        }
        changed
    }
}

#[derive(Clone)]
struct OspfPublicIpv6SyncTrigger {
    session_mgr: RouteSessionManager,
}

impl PublicIpv6SyncTrigger for OspfPublicIpv6SyncTrigger {
    fn sync_now(&self, reason: &str) {
        self.session_mgr.sync_now(reason);
    }
}

pub struct PeerRoute {
    my_peer_id: PeerId,
    context: ArcPeerContext,
    peer_rpc: Weak<PeerRpcManager>,

    service_impl: Arc<PeerRouteServiceImpl>,
    public_ipv6_service: Arc<PublicIpv6Service>,
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
        context: ArcPeerContext,
        public_ipv6_runtime: Arc<dyn PublicIpv6Runtime>,
        peer_rpc: Arc<PeerRpcManager>,
    ) -> Arc<Self> {
        let service_impl = Arc::new(PeerRouteServiceImpl::new(my_peer_id, context.clone()));
        let session_mgr = RouteSessionManager::new(service_impl.clone(), peer_rpc.clone());
        let public_ipv6_service = Arc::new(PublicIpv6Service::new(
            public_ipv6_runtime,
            Arc::downgrade(&peer_rpc),
            Arc::new(OspfPublicIpv6RouteHandle {
                service_impl: Arc::downgrade(&service_impl),
            }),
            Arc::new(OspfPublicIpv6SyncTrigger {
                session_mgr: session_mgr.clone(),
            }),
        ));
        service_impl.set_public_ipv6_service(Arc::downgrade(&public_ipv6_service));

        Arc::new(PeerRoute {
            my_peer_id,
            context,
            peer_rpc: Arc::downgrade(&peer_rpc),

            service_impl,
            public_ipv6_service,
            session_mgr,

            tasks: std::sync::Mutex::new(JoinSet::new()),
        })
    }

    async fn clear_expired_peer(service_impl: Arc<PeerRouteServiceImpl>) {
        loop {
            crate::runtime_time::sleep(Duration::from_secs(60)).await;
            service_impl.clear_expired_peer().await;
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
        let mut peer_event_receiver = service_impl.context.subscribe_peer_events();
        service_impl.mark_interface_peers_dirty();
        loop {
            if service_impl.update_my_infos().await {
                session_mgr.sync_now("update_my_infos");
            }

            if service_impl.cost_calculator_need_update() {
                tracing::debug!("cost_calculator_need_update");
                service_impl.synced_route_info.version.inc();
                service_impl.update_route_table();
                if let Some(public_ipv6_service) = service_impl.public_ipv6_service() {
                    public_ipv6_service.handle_route_change();
                }
            }

            if let Some(receiver) = peer_event_receiver.as_mut() {
                let event = select! {
                    ev = receiver.recv() => Some(ev),
                    _ = crate::runtime_time::sleep(Duration::from_secs(1)) => None,
                };

                if let Some(ev) = event {
                    if let Ok(ev_ref) = &ev {
                        service_impl.handle_peer_context_event(ev_ref);
                    } else {
                        service_impl.mark_interface_peers_dirty();
                        peer_event_receiver = service_impl.context.subscribe_peer_events();
                    }
                    tracing::info!(
                        ?ev,
                        "peer context event received in update_my_peer_info_routine"
                    );
                }
            } else {
                crate::runtime_time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    async fn start(&self) {
        let Some(peer_rpc) = self.peer_rpc.upgrade() else {
            return;
        };

        // make sure my_peer_id is in the peer_infos.
        self.service_impl.update_my_infos().await;
        self.public_ipv6_service.handle_route_change();

        peer_rpc.rpc_server().registry().register(
            OspfRouteRpcServer::new(self.session_mgr.clone()),
            &self.context.network_name(),
        );
        peer_rpc.rpc_server().registry().register(
            PublicIpv6AddrRpcServer::new(self.public_ipv6_service.rpc_server()),
            &self.context.network_name(),
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

        self.tasks
            .lock()
            .unwrap()
            .spawn(self.public_ipv6_service.clone().provider_gc_routine());

        self.tasks
            .lock()
            .unwrap()
            .spawn(self.public_ipv6_service.clone().client_routine());
    }

    fn unregister_rpc_services(&self) {
        let Some(peer_rpc) = self.peer_rpc.upgrade() else {
            return;
        };

        peer_rpc.rpc_server().registry().unregister(
            OspfRouteRpcServer::new(self.session_mgr.clone()),
            &self.context.network_name(),
        );
        peer_rpc.rpc_server().registry().unregister(
            PublicIpv6AddrRpcServer::new(self.public_ipv6_service.rpc_server()),
            &self.context.network_name(),
        );
    }

    async fn stop(&self) {
        self.service_impl.stopped.store(true, Ordering::Release);
        self.unregister_rpc_services();

        let mut tasks = {
            let mut tasks = self.tasks.lock().unwrap();
            std::mem::replace(&mut *tasks, JoinSet::new())
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}

        let _session_operation = self.service_impl.session_operation.write().await;
        let sessions = self
            .service_impl
            .sessions
            .iter()
            .map(|session| session.value().clone())
            .collect::<Vec<_>>();
        self.service_impl.sessions.clear();
        self.service_impl.sessions.shrink_to_fit();
        for session in sessions {
            session.task.stop().await;
        }

        *self.service_impl.interface.lock().await = None;
    }
}

impl Drop for PeerRoute {
    fn drop(&mut self) {
        tracing::debug!(
            self.my_peer_id,
            network = ?self.context.network_identity(),
            service = ?self.service_impl,
            "PeerRoute drop"
        );

        self.unregister_rpc_services();
    }
}

#[async_trait::async_trait]
impl Route for PeerRoute {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()> {
        *self.service_impl.interface.lock().await = Some(interface);
        self.start().await;
        Ok(1)
    }

    async fn close(&self) {
        self.stop().await;
    }

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

    async fn list_routes(&self) -> Vec<CoreRouteInfo> {
        self.service_impl
            .route_table
            .list_routes(self.my_peer_id, &self.service_impl.route_table_with_cost)
    }

    async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr> {
        self.service_impl
            .route_table
            .list_proxy_cidrs_excluding(self.my_peer_id)
    }

    async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr> {
        self.service_impl
            .route_table
            .list_proxy_cidrs_v6_excluding(self.my_peer_id)
    }

    async fn list_public_ipv6_routes(&self) -> BTreeSet<Ipv6Inet> {
        self.public_ipv6_service.list_routes()
    }

    async fn get_my_public_ipv6_addr(&self) -> Option<Ipv6Inet> {
        self.public_ipv6_service.my_addr()
    }

    async fn get_public_ipv6_gateway_peer_id(&self) -> Option<PeerId> {
        self.public_ipv6_service.provider_peer_id_for_client()
    }

    async fn get_local_public_ipv6_info(&self) -> CoreListPublicIpv6InfoResponse {
        let Some((provider, leases)) = self.public_ipv6_service.local_provider_state() else {
            return CoreListPublicIpv6InfoResponse::default();
        };

        CoreListPublicIpv6InfoResponse {
            provider_prefix: Some(
                Ipv6Inet::new(
                    provider.prefix.first_address(),
                    provider.prefix.network_length(),
                )
                .unwrap()
                .into(),
            ),
            provider_leases: leases
                .into_iter()
                .map(|lease| CorePublicIpv6LeaseInfo {
                    peer_id: lease.peer_id,
                    inst_id: lease.inst_id.to_string(),
                    leased_addr: Some(lease.addr.into()),
                    valid_until_unix_seconds: lease
                        .valid_until
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                    reused: lease.reused,
                })
                .collect(),
        }
    }

    async fn get_peer_id_by_ipv4(&self, ipv4_addr: &Ipv4Addr) -> Option<PeerId> {
        let route_table = &self.service_impl.route_table;
        if let Some(peer_id) = route_table.get_peer_id_by_ipv4(ipv4_addr) {
            return Some(peer_id);
        }

        // only get peer id for proxy when the dst ipv4 is not in same network with us
        if PeerContext::is_ip_in_same_network(self.context.as_ref(), &IpAddr::V4(*ipv4_addr)) {
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
        if let Some(peer_id) = route_table.get_peer_id_by_ipv6(ipv6_addr) {
            return Some(peer_id);
        }

        // only get peer id for proxy when the dst ipv4 is not in same network with us
        if PeerContext::is_ip_in_same_network(self.context.as_ref(), &IpAddr::V6(*ipv6_addr)) {
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
        network_identity: &CoreNetworkIdentity,
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
        self.service_impl.route_table.get_peer_info(peer_id)
    }

    async fn get_peer_info_last_update_time(&self) -> Instant {
        self.service_impl.get_peer_info_last_update()
    }

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>> {
        self.service_impl.get_peer_groups(peer_id)
    }

    async fn refresh_acl_groups(&self) {
        if self.service_impl.refresh_acl_groups().await {
            self.session_mgr.sync_now("refresh_acl_groups");
        }
    }
}

impl PeerPacketFilter for PeerRoute {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::ZCPacket;
    use crate::peers::context::tests::NoopPeerContext;
    use crate::peers::peer_rpc::PeerRpcManagerTransport;
    use crate::peers::route_trait::{DefaultRouteCostCalculator, RouteInterface};
    use parking_lot::Mutex;
    use tokio::sync::Notify;

    impl PeerRouteServiceImpl {
        pub(crate) async fn list_peers_from_interface<T: FromIterator<PeerId>>(&self) -> T {
            self.interface_peer_snapshot()
                .await
                .peers
                .iter()
                .copied()
                .collect()
        }
    }

    impl PeerRoute {
        pub(crate) fn task_count(&self) -> usize {
            let route_tasks = self.tasks.lock().unwrap().len();
            let session_tasks = self
                .service_impl
                .sessions
                .iter()
                .filter(|session| session.task.is_running())
                .count();
            route_tasks + session_tasks
        }
    }

    struct CountingInterface {
        my_peer_id: PeerId,
        peers: Arc<Mutex<Vec<PeerId>>>,
        peer_identity_types: Arc<Mutex<HashMap<PeerId, Option<PeerIdentityType>>>>,
        list_peers_calls: Arc<AtomicU32>,
        get_peer_identity_type_calls: Arc<AtomicU32>,
    }

    struct BlockingInterface {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl RouteInterface for BlockingInterface {
        async fn list_peers(&self) -> Vec<PeerId> {
            self.entered.notify_one();
            self.release.notified().await;
            vec![2]
        }

        async fn get_peer_identity_type(&self, _peer_id: PeerId) -> Option<PeerIdentityType> {
            Some(PeerIdentityType::Admin)
        }

        fn my_peer_id(&self) -> PeerId {
            1
        }
    }

    struct TestPeerRpcTransport;

    #[async_trait::async_trait]
    impl PeerRpcManagerTransport for TestPeerRpcTransport {
        fn my_peer_id(&self) -> PeerId {
            1
        }

        async fn send(&self, _msg: ZCPacket, _dst_peer_id: PeerId) -> anyhow::Result<()> {
            Ok(())
        }

        async fn recv(&self) -> anyhow::Result<ZCPacket> {
            std::future::pending().await
        }
    }

    struct TestPublicIpv6Runtime;

    #[async_trait::async_trait]
    impl PublicIpv6Runtime for TestPublicIpv6Runtime {
        fn ipv6_public_addr_auto(&self) -> bool {
            false
        }

        fn ipv6_public_addr_provider(&self) -> bool {
            false
        }

        fn instance_id(&self) -> uuid::Uuid {
            uuid::Uuid::nil()
        }

        fn network_name(&self) -> String {
            "default".to_owned()
        }

        async fn collect_reserved_public_ipv6_addrs(&self, _prefix: Ipv6Cidr) -> HashSet<Ipv6Addr> {
            HashSet::new()
        }

        fn public_ipv6_lease_changed(&self, _old: Option<Ipv6Inet>, _new: Option<Ipv6Inet>) {}

        fn public_ipv6_routes_changed(&self, _added: Vec<Ipv6Inet>, _removed: Vec<Ipv6Inet>) {}
    }

    #[async_trait::async_trait]
    impl RouteInterface for CountingInterface {
        async fn list_peers(&self) -> Vec<PeerId> {
            self.list_peers_calls.fetch_add(1, Ordering::Relaxed);
            self.peers.lock().clone()
        }

        async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
            self.get_peer_identity_type_calls
                .fetch_add(1, Ordering::Relaxed);
            self.peer_identity_types
                .lock()
                .get(&peer_id)
                .copied()
                .flatten()
        }

        fn my_peer_id(&self) -> PeerId {
            self.my_peer_id
        }
    }

    fn test_service_impl(my_peer_id: PeerId) -> PeerRouteServiceImpl {
        PeerRouteServiceImpl::new(my_peer_id, Arc::new(NoopPeerContext::default()))
    }

    fn peer(peer_id: PeerId) -> OspfPeerInfo {
        OspfPeerInfo {
            peer_id,
            info: RoutePeerInfo {
                peer_id,
                version: 1,
                ..Default::default()
            },
        }
    }

    fn connected(
        peer_id: PeerId,
        connected_peers: impl IntoIterator<Item = PeerId>,
    ) -> OspfPeerConnInfo {
        OspfPeerConnInfo {
            peer_id,
            connected_peers: connected_peers.into_iter().collect(),
        }
    }

    #[tokio::test]
    async fn interface_peer_cache_refreshes_only_when_marked_dirty() {
        let service_impl = test_service_impl(1);
        let peers = Arc::new(Mutex::new(vec![2, 3]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::new()));
        let list_peers_calls = Arc::new(AtomicU32::new(0));
        let get_peer_identity_type_calls = Arc::new(AtomicU32::new(0));
        *service_impl.interface.lock().await = Some(Box::new(CountingInterface {
            my_peer_id: 1,
            peers: peers.clone(),
            peer_identity_types,
            list_peers_calls: list_peers_calls.clone(),
            get_peer_identity_type_calls,
        }));

        let first: BTreeSet<_> = service_impl.list_peers_from_interface().await;
        let second: BTreeSet<_> = service_impl.list_peers_from_interface().await;

        assert_eq!(first, BTreeSet::from([2, 3]));
        assert_eq!(second, BTreeSet::from([2, 3]));
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);

        *peers.lock() = vec![2, 4];
        service_impl.handle_peer_context_event(&PeerContextEvent::PeerConnAdded);

        let third: BTreeSet<_> = service_impl.list_peers_from_interface().await;
        assert_eq!(third, BTreeSet::from([2, 4]));
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn update_my_conn_info_skips_interface_scan_when_topology_is_unchanged() {
        let service_impl = test_service_impl(1);
        let peers = Arc::new(Mutex::new(vec![2, 3]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::new()));
        let list_peers_calls = Arc::new(AtomicU32::new(0));
        let get_peer_identity_type_calls = Arc::new(AtomicU32::new(0));
        *service_impl.interface.lock().await = Some(Box::new(CountingInterface {
            my_peer_id: 1,
            peers: peers.clone(),
            peer_identity_types,
            list_peers_calls: list_peers_calls.clone(),
            get_peer_identity_type_calls: get_peer_identity_type_calls.clone(),
        }));

        assert!(service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        assert!(!service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        *peers.lock() = vec![2, 4];
        service_impl.handle_peer_context_event(&PeerContextEvent::PeerConnRemoved);

        assert!(service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);

        assert!(!service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn get_peer_identity_type_reuses_snapshot_until_topology_changes() {
        let service_impl = test_service_impl(1);
        let peers = Arc::new(Mutex::new(vec![2, 3]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::from([
            (2, Some(PeerIdentityType::Credential)),
            (3, Some(PeerIdentityType::Admin)),
            (4, Some(PeerIdentityType::Admin)),
        ])));
        let list_peers_calls = Arc::new(AtomicU32::new(0));
        let get_peer_identity_type_calls = Arc::new(AtomicU32::new(0));
        *service_impl.interface.lock().await = Some(Box::new(CountingInterface {
            my_peer_id: 1,
            peers: peers.clone(),
            peer_identity_types: peer_identity_types.clone(),
            list_peers_calls: list_peers_calls.clone(),
            get_peer_identity_type_calls: get_peer_identity_type_calls.clone(),
        }));

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(2).await,
            Some(PeerIdentityType::Credential)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(2).await,
            Some(PeerIdentityType::Credential)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        *peers.lock() = vec![2, 4];
        service_impl.handle_peer_context_event(&PeerContextEvent::PeerConnRemoved);

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(4).await,
            Some(PeerIdentityType::Admin)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(4).await,
            Some(PeerIdentityType::Admin)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn stop_waits_for_in_flight_route_sync_before_draining_sessions() {
        let peer_rpc = Arc::new(PeerRpcManager::new(TestPeerRpcTransport));
        let route = PeerRoute::new(
            1,
            Arc::new(NoopPeerContext::default()),
            Arc::new(TestPublicIpv6Runtime),
            peer_rpc,
        );
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *route.service_impl.interface.lock().await = Some(Box::new(BlockingInterface {
            entered: entered.clone(),
            release: release.clone(),
        }));

        let sync_task = tokio::spawn({
            let session_mgr = route.session_mgr.clone();
            async move {
                session_mgr
                    .do_sync_route_info(2, 1, false, None, None, None, None)
                    .await
            }
        });
        crate::runtime_time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("route sync did not enter the interface call");

        let stop_task = tokio::spawn({
            let route = route.clone();
            async move { route.stop().await }
        });
        crate::runtime_time::timeout(Duration::from_secs(1), async {
            while !route.service_impl.stopped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("route did not enter the stopped state");

        assert!(!stop_task.is_finished());
        assert!(matches!(
            route.session_mgr.get_or_start_session(3),
            Err(Error::Stopped)
        ));

        release.notify_one();
        sync_task
            .await
            .expect("route sync task panicked")
            .expect("in-flight route sync failed");
        crate::runtime_time::timeout(Duration::from_secs(1), stop_task)
            .await
            .expect("route stop did not finish")
            .expect("route stop task panicked");

        assert!(route.service_impl.sessions.is_empty());
        assert_eq!(route.task_count(), 0);
    }

    #[test]
    fn builds_next_hop_and_proxy_lookup_from_snapshot() {
        let mut remote_proxy_peer = peer(3);
        remote_proxy_peer
            .info
            .proxy_cidrs
            .push("10.10.0.0/16".into());

        let snapshot = OspfRouteSnapshot {
            peer_infos: vec![peer(1), peer(2), remote_proxy_peer],
            conn_map: vec![connected(1, [2]), connected(2, [1, 3]), connected(3, [2])],
            suppressed_peer_ids: BTreeSet::new(),
            version: 1,
        };

        let table = OspfRouteTable::new();
        table.build_from_snapshot(
            1,
            &snapshot,
            NextHopPolicy::LeastHop,
            &DefaultRouteCostCalculator,
        );

        let next_hop = table.get_next_hop(3).unwrap();
        assert_eq!(next_hop.next_hop_peer_id, 2);
        assert_eq!(next_hop.path_len, 2);
        assert_eq!(
            table.get_peer_id_for_proxy(&"10.10.1.1".parse::<IpAddr>().unwrap()),
            Some(3)
        );
    }
}
