use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use tokio::sync::RwLock;

use crate::peers::PeerId;

use super::{
    service::{GlobalPeerMap, PeerCenterService, PeerInfoForGlobalMap},
    Digest, Error,
};

pub(crate) struct PeerCenterServerGlobalData {
    pub global_peer_map: GlobalPeerMap,
    pub digest: Digest,
    pub update_time: std::time::Instant,
}

impl PeerCenterServerGlobalData {
    fn new() -> Self {
        PeerCenterServerGlobalData {
            global_peer_map: GlobalPeerMap::new(),
            digest: Digest::default(),
            update_time: std::time::Instant::now(),
        }
    }
}

// a global unique instance for PeerCenterServer
pub(crate) static GLOBAL_DATA: Lazy<DashMap<PeerId, Arc<RwLock<PeerCenterServerGlobalData>>>> =
    Lazy::new(DashMap::new);

pub(crate) fn get_global_data(node_id: PeerId) -> Arc<RwLock<PeerCenterServerGlobalData>> {
    GLOBAL_DATA
        .entry(node_id)
        .or_insert_with(|| Arc::new(RwLock::new(PeerCenterServerGlobalData::new())))
        .value()
        .clone()
}

#[derive(Clone, Debug)]
pub struct PeerCenterServer {
    // every peer has its own server, so use per-struct dash map is ok.
    my_node_id: PeerId,
    digest_map: DashMap<PeerId, Digest>,
}

impl PeerCenterServer {
    pub fn new(my_node_id: PeerId) -> Self {
        PeerCenterServer {
            my_node_id,
            digest_map: DashMap::new(),
        }
    }
}

#[tarpc::server]
impl PeerCenterService for PeerCenterServer {
    #[tracing::instrument()]
    async fn report_peers(
        self,
        _: tarpc::context::Context,
        my_peer_id: PeerId,
        peers: Option<PeerInfoForGlobalMap>,
        digest: Digest,
    ) -> Result<(), Error> {
        tracing::warn!("receive report_peers");

        let old_digest = self.digest_map.get(&my_peer_id);
        // if digest match, no need to update
        if let Some(old_digest) = old_digest {
            if *old_digest == digest {
                return Ok(());
            }
        }

        if peers.is_none() {
            return Err(Error::DigestMismatch);
        }

        self.digest_map.insert(my_peer_id, digest);
        let data = get_global_data(self.my_node_id);
        let mut locked_data = data.write().await;
        locked_data
            .global_peer_map
            .map
            .insert(my_peer_id, peers.unwrap());

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        locked_data.global_peer_map.map.hash(&mut hasher);
        locked_data.digest = hasher.finish() as Digest;

        Ok(())
    }

    async fn get_global_peer_map(
        self,
        _: tarpc::context::Context,
        digest: Digest,
    ) -> Result<Option<GlobalPeerMap>, Error> {
        let data = get_global_data(self.my_node_id);
        if digest == data.read().await.digest {
            return Ok(None);
        }

        let data = get_global_data(self.my_node_id);
        let locked_data = data.read().await;
        Ok(Some(locked_data.global_peer_map.clone()))
    }
}
