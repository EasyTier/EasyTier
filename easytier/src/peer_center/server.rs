use std::{
    collections::BinaryHeap,
    hash::{Hash, Hasher},
    sync::Arc,
};

use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use tokio::task::JoinSet;

use crate::{
    common::PeerId,
    proto::{
        peer_rpc::{
            DirectConnectedPeerInfo, GetGlobalPeerMapRequest, GetGlobalPeerMapResponse,
            GlobalPeerMap, PeerCenterRpc, PeerInfoForGlobalMap, ReportPeersRequest,
            ReportPeersResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

use super::Digest;

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub(crate) struct SrcDstPeerPair {
    src: PeerId,
    dst: PeerId,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerCenterInfoEntry {
    info: DirectConnectedPeerInfo,
    update_time: std::time::Instant,
}

#[derive(Default)]
pub(crate) struct PeerCenterServerGlobalData {
    pub(crate) global_peer_map: DashMap<SrcDstPeerPair, PeerCenterInfoEntry>,
    pub(crate) peer_report_time: DashMap<PeerId, std::time::Instant>,
    pub(crate) digest: AtomicCell<Digest>,
}

// a global unique instance for PeerCenterServer
pub(crate) static GLOBAL_DATA: Lazy<DashMap<PeerId, Arc<PeerCenterServerGlobalData>>> =
    Lazy::new(DashMap::new);

pub(crate) fn get_global_data(node_id: PeerId) -> Arc<PeerCenterServerGlobalData> {
    GLOBAL_DATA
        .entry(node_id)
        .or_insert_with(|| Arc::new(PeerCenterServerGlobalData::default()))
        .value()
        .clone()
}

#[derive(Clone, Debug)]
pub struct PeerCenterServer {
    // every peer has its own server, so use per-struct dash map is ok.
    my_node_id: PeerId,
    tasks: Arc<JoinSet<()>>,
}

impl PeerCenterServer {
    pub fn new(my_node_id: PeerId) -> Self {
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                PeerCenterServer::clean_outdated_peer(my_node_id).await;
            }
        });

        PeerCenterServer {
            my_node_id,
            tasks: Arc::new(tasks),
        }
    }

    async fn clean_outdated_peer(my_node_id: PeerId) {
        let data = get_global_data(my_node_id);
        data.peer_report_time.retain(|_, v| {
            std::time::Instant::now().duration_since(*v) < std::time::Duration::from_secs(180)
        });
        data.global_peer_map.retain(|_, v| {
            std::time::Instant::now().duration_since(v.update_time)
                < std::time::Duration::from_secs(180)
        });
    }

    fn calc_global_digest(my_node_id: PeerId) -> Digest {
        let data = get_global_data(my_node_id);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        data.global_peer_map
            .iter()
            .map(|v| v.key().clone())
            .collect::<BinaryHeap<_>>()
            .into_sorted_vec()
            .into_iter()
            .for_each(|v| v.hash(&mut hasher));
        hasher.finish()
    }
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterServer {
    type Controller = BaseController;

    #[tracing::instrument()]
    async fn report_peers(
        &self,
        _: BaseController,
        req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        let my_peer_id = req.my_peer_id;
        let peers = req.peer_infos.unwrap_or_default();

        tracing::debug!("receive report_peers");

        let data = get_global_data(self.my_node_id);
        data.peer_report_time
            .insert(my_peer_id, std::time::Instant::now());

        for (peer_id, peer_info) in peers.direct_peers {
            let pair = SrcDstPeerPair {
                src: my_peer_id,
                dst: peer_id,
            };
            let entry = PeerCenterInfoEntry {
                info: peer_info,
                update_time: std::time::Instant::now(),
            };
            data.global_peer_map.insert(pair, entry);
        }

        data.digest
            .store(PeerCenterServer::calc_global_digest(self.my_node_id));

        Ok(ReportPeersResponse::default())
    }

    #[tracing::instrument()]
    async fn get_global_peer_map(
        &self,
        _: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let digest = req.digest;

        let data = get_global_data(self.my_node_id);
        if digest == data.digest.load() && digest != 0 {
            return Ok(GetGlobalPeerMapResponse::default());
        }

        let mut global_peer_map = GlobalPeerMap::default();
        for item in data.global_peer_map.iter() {
            let (pair, entry) = item.pair();
            global_peer_map
                .map
                .entry(pair.src)
                .or_insert_with(|| PeerInfoForGlobalMap {
                    direct_peers: Default::default(),
                })
                .direct_peers
                .insert(pair.dst, entry.info.clone());
        }

        Ok(GetGlobalPeerMapResponse {
            global_peer_map: global_peer_map.map,
            digest: Some(data.digest.load()),
        })
    }
}
