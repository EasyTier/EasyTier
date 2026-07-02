use std::sync::Arc;

use easytier_core::peers::peer_map::PeerMap;
use parking_lot::Mutex;

use crate::{
    common::{PeerId, error::Error, global_ctx::ArcGlobalCtx},
    tunnel::packet_def::ZCPacket,
};

use super::{
    PacketRecvChan,
    peer_conn::{PeerConn, PeerConnId},
    peer_rpc::PeerRpcManager,
};

pub struct ForeignNetworkClient {
    core: easytier_core::peers::foreign_network_client::ForeignNetworkClient,
    alive_client_urls: Arc<Mutex<multimap::MultiMap<url::Url, PeerConnId>>>,
}

impl ForeignNetworkClient {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        packet_sender_to_mgr: PacketRecvChan,
        peer_rpc: Arc<PeerRpcManager>,
        my_peer_id: PeerId,
    ) -> Self {
        Self {
            core: easytier_core::peers::foreign_network_client::ForeignNetworkClient::new(
                global_ctx,
                packet_sender_to_mgr,
                peer_rpc,
                my_peer_id,
            ),
            alive_client_urls: Arc::new(Mutex::new(multimap::MultiMap::new())),
        }
    }

    pub async fn add_new_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        let _ = self.maintain_alive_client_urls(&peer_conn);
        self.core
            .add_new_peer_conn(peer_conn)
            .await
            .map_err(Into::into)
    }

    fn maintain_alive_client_urls(&self, peer_conn: &PeerConn) -> Option<()> {
        let conn_info = peer_conn.get_conn_info();
        if !conn_info.is_client {
            return None;
        }

        let close_notifier = peer_conn.get_close_notifier();
        let alive_conns_weak = Arc::downgrade(&self.alive_client_urls);
        let conn_id = close_notifier.get_conn_id();
        let alive_client_url: url::Url = conn_info.tunnel?.remote_addr?.into();
        self.alive_client_urls
            .lock()
            .insert(alive_client_url.clone(), conn_id);

        tokio::spawn(async move {
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            let Some(alive_conns) = alive_conns_weak.upgrade() else {
                return;
            };
            let mut guard = alive_conns.lock();
            if let Some(mut conn_ids) = guard.remove(&alive_client_url) {
                conn_ids.retain(|id| id != &conn_id);
                if !conn_ids.is_empty() {
                    guard.insert_many(alive_client_url, conn_ids);
                }
            };
            let alive_conn_count = guard.len();
            drop(guard);
            tracing::debug!(
                ?conn_id,
                "peer conn is closed, current alive conns: {}",
                alive_conn_count
            );
        });

        Some(())
    }

    pub fn is_client_url_alive(&self, url: &url::Url) -> bool {
        self.alive_client_urls.lock().contains_key(url)
    }

    pub fn has_next_hop(&self, peer_id: PeerId) -> bool {
        self.core.has_next_hop(peer_id)
    }

    pub async fn list_public_peers(&self) -> Vec<PeerId> {
        self.core.list_public_peers().await
    }

    pub fn get_next_hop(&self, peer_id: PeerId) -> Option<PeerId> {
        self.core.get_next_hop(peer_id)
    }

    pub async fn send_msg(&self, msg: ZCPacket, peer_id: PeerId) -> Result<(), Error> {
        self.core.send_msg(msg, peer_id).await.map_err(Into::into)
    }

    pub async fn run(&self) {
        self.core.run().await;
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.core.get_peer_map()
    }
}
