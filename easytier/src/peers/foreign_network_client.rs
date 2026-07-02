use std::sync::Arc;

use easytier_core::peers::peer_map::PeerMap;

use crate::{
    common::{PeerId, error::Error, global_ctx::ArcGlobalCtx},
    tunnel::packet_def::ZCPacket,
};

use super::{PacketRecvChan, peer_conn::PeerConn, peer_rpc::PeerRpcManager};

pub struct ForeignNetworkClient {
    core: easytier_core::peers::foreign_network_client::ForeignNetworkClient,
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
        }
    }

    pub async fn add_new_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        self.core
            .add_new_peer_conn(peer_conn)
            .await
            .map_err(Into::into)
    }

    pub fn is_client_url_alive(&self, url: &url::Url) -> bool {
        self.core.is_client_url_alive(url)
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
