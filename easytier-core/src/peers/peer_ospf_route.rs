use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use arc_swap::ArcSwap;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use dashmap::DashMap;
use petgraph::{
    Directed,
    algo::dijkstra,
    graph::{Graph, NodeIndex},
    visit::{EdgeRef, IntoNodeReferences},
};
use prefix_trie::PrefixMap;

use crate::{
    config::PeerId,
    peers::{
        graph_algo::dijkstra_with_first_hop,
        route_trait::{NextHopPolicy, RouteCostCalculatorInterface},
        util::shrink_dashmap,
    },
    proto::{
        common::NatType,
        core_peer::peer::Route as CoreRouteInfo,
        peer_rpc::{PeerIdVersion, RoutePeerInfo},
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

    pub fn set(&self, version: Version) {
        self.0.store(version, Ordering::Relaxed);
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
    pub version: Version,
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

    pub fn contains_peer_info(&self, peer_id: PeerId) -> bool {
        self.peer_infos.contains_key(&peer_id)
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

    #[doc(hidden)]
    pub fn replace_next_hops_for_testing<I>(&self, version: Version, next_hops: I)
    where
        I: IntoIterator<Item = (PeerId, OspfNextHopInfo)>,
    {
        self.next_hop_map.clear();
        for (peer_id, next_hop) in next_hops {
            self.next_hop_map.insert(peer_id, next_hop);
        }
        self.next_hop_map_version.set(version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::route_trait::DefaultRouteCostCalculator;

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
            version: 1,
        }
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
