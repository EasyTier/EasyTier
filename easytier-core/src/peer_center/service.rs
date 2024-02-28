use std::collections::BTreeMap;

use crate::peers::PeerId;

use super::{Digest, Error};
use crate::rpc::PeerInfo;

pub type LatencyLevel = crate::rpc::cli::LatencyLevel;

impl LatencyLevel {
    pub const fn from_latency_ms(lat_ms: u32) -> Self {
        if lat_ms < 10 {
            LatencyLevel::VeryLow
        } else if lat_ms < 50 {
            LatencyLevel::Low
        } else if lat_ms < 100 {
            LatencyLevel::Normal
        } else if lat_ms < 200 {
            LatencyLevel::High
        } else {
            LatencyLevel::VeryHigh
        }
    }
}

pub type PeerConnInfoForGlobalMap = crate::rpc::cli::PeerConnInfoForGlobalMap;
pub type PeerConnInfosForGlobalMap = crate::rpc::cli::PeerConnInfosForGlobalMap;
pub type PeerInfoForGlobalMap = crate::rpc::cli::PeerInfoForGlobalMap;

impl From<Vec<PeerInfo>> for PeerInfoForGlobalMap {
    fn from(peers: Vec<PeerInfo>) -> Self {
        let mut peer_map = BTreeMap::new();
        for peer in peers {
            let mut conn_info = Vec::new();
            for conn in peer.conns {
                conn_info.push(PeerConnInfoForGlobalMap {
                    to_peer_id: conn.peer_id.as_bytes().to_vec(),
                    latency_level: LatencyLevel::from_latency_ms(
                        conn.stats.unwrap().latency_us as u32 / 1000,
                    ) as i32,
                });
            }
            // sort conn info so hash result is stable
            conn_info.sort_by(|a, b| a.to_peer_id.cmp(&b.to_peer_id));
            peer_map.insert(peer.peer_id, PeerConnInfosForGlobalMap { conns: conn_info });
        }
        PeerInfoForGlobalMap {
            direct_peers: peer_map,
        }
    }
}

// a global peer topology map, peers can use it to find optimal path to other peers
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GlobalPeerMap {
    pub map: BTreeMap<PeerId, PeerInfoForGlobalMap>,
}

impl GlobalPeerMap {
    pub fn new() -> Self {
        GlobalPeerMap {
            map: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct GetGlobalPeerMapResponse {
    pub global_peer_map: GlobalPeerMap,
    pub digest: Digest,
}

#[tarpc::service]
pub trait PeerCenterService {
    // report center server which peer is directly connected to me
    // digest is a hash of current peer map, if digest not match, we need to transfer the whole map
    async fn report_peers(
        my_peer_id: PeerId,
        peers: Option<PeerInfoForGlobalMap>,
        digest: Digest,
    ) -> Result<(), Error>;

    async fn get_global_peer_map(digest: Digest)
        -> Result<Option<GetGlobalPeerMapResponse>, Error>;
}
