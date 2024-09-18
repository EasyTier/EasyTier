// peer_center is used to collect peer info into one peer node.
// the center node is selected with the following rules:
// 1. has smallest peer id
// 2. TODO: has allow_to_be_center peer feature
// peer center is not guaranteed to be stable and can be changed when peer enter or leave.
// it's used to reduce the cost to exchange infos between peers.

use std::collections::BTreeMap;

use crate::proto::cli::PeerInfo;
use crate::proto::peer_rpc::{DirectConnectedPeerInfo, PeerInfoForGlobalMap};

pub mod instance;
mod server;

#[derive(thiserror::Error, Debug, serde::Deserialize, serde::Serialize)]
pub enum Error {
    #[error("Digest not match, need provide full peer info to center server.")]
    DigestMismatch,
    #[error("Not center server")]
    NotCenterServer,
}

pub type Digest = u64;

impl From<Vec<PeerInfo>> for PeerInfoForGlobalMap {
    fn from(peers: Vec<PeerInfo>) -> Self {
        let mut peer_map = BTreeMap::new();
        for peer in peers {
            let Some(min_lat) = peer
                .conns
                .iter()
                .map(|conn| conn.stats.as_ref().unwrap().latency_us)
                .min()
            else {
                continue;
            };

            let dp_info = DirectConnectedPeerInfo {
                latency_ms: std::cmp::max(1, (min_lat as u32 / 1000) as i32),
            };

            // sort conn info so hash result is stable
            peer_map.insert(peer.peer_id, dp_info);
        }
        PeerInfoForGlobalMap {
            direct_peers: peer_map,
        }
    }
}
