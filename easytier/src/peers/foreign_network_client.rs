use std::sync::{Arc, Mutex};

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, scoped_task::ScopedTask, PeerId},
    tunnel::packet_def::ZCPacket,
};

use super::{peer_conn::PeerConn, peer_map::PeerMap, peer_rpc::PeerRpcManager, PacketRecvChan};

pub struct ForeignNetworkClient {
    global_ctx: ArcGlobalCtx,
    peer_rpc: Arc<PeerRpcManager>,
    my_peer_id: PeerId,

    peer_map: Arc<PeerMap>,
    task: Mutex<Option<ScopedTask<()>>>,
}

impl ForeignNetworkClient {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        packet_sender_to_mgr: PacketRecvChan,
        peer_rpc: Arc<PeerRpcManager>,
        my_peer_id: PeerId,
    ) -> Self {
        let peer_map = Arc::new(PeerMap::new(
            packet_sender_to_mgr,
            global_ctx.clone(),
            my_peer_id,
        ));
        Self {
            global_ctx,
            peer_rpc,
            my_peer_id,

            peer_map,
            task: Mutex::new(None),
        }
    }

    pub async fn add_new_peer_conn(&self, peer_conn: PeerConn) {
        tracing::warn!(peer_conn = ?peer_conn.get_conn_info(), network = ?peer_conn.get_network_identity(), "add new peer conn in foreign network client");
        self.peer_map.add_new_peer_conn(peer_conn).await
    }

    pub fn has_next_hop(&self, peer_id: PeerId) -> bool {
        self.get_next_hop(peer_id).is_some()
    }

    pub async fn list_public_peers(&self) -> Vec<PeerId> {
        self.peer_map.list_peers().await
    }

    pub fn get_next_hop(&self, peer_id: PeerId) -> Option<PeerId> {
        if self.peer_map.has_peer(peer_id) {
            return Some(peer_id);
        }
        None
    }

    pub async fn send_msg(&self, msg: ZCPacket, peer_id: PeerId) -> Result<(), Error> {
        if let Some(next_hop) = self.get_next_hop(peer_id) {
            let ret = self.peer_map.send_msg_directly(msg, next_hop).await;
            if ret.is_err() {
                tracing::error!(
                    ?ret,
                    ?peer_id,
                    ?next_hop,
                    "foreign network client send msg failed"
                );
            } else {
                tracing::info!(
                    ?peer_id,
                    ?next_hop,
                    "foreign network client send msg success"
                );
            }
            return ret;
        }
        Err(Error::RouteError(Some("no next hop".to_string())))
    }

    pub async fn run(&self) {
        let peer_map = Arc::downgrade(&self.peer_map);
        *self.task.lock().unwrap() = Some(
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    let Some(peer_map) = peer_map.upgrade() else {
                        break;
                    };
                    peer_map.clean_peer_without_conn().await;
                }
            })
            .into(),
        );
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peer_map.clone()
    }
}
