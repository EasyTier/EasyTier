use std::sync::Arc;

use anyhow::Context;
use dashmap::DashMap;
use easytier_rpc::PeerConnInfo;
use tokio::sync::mpsc;
use tokio_util::bytes::Bytes;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    tunnels::TunnelError,
};

use super::{peer::Peer, peer_conn::PeerConn, route_trait::ArcRoute, PeerId};

pub struct PeerMap {
    global_ctx: ArcGlobalCtx,
    peer_map: DashMap<PeerId, Arc<Peer>>,
    packet_send: mpsc::Sender<Bytes>,
}

impl PeerMap {
    pub fn new(packet_send: mpsc::Sender<Bytes>, global_ctx: ArcGlobalCtx) -> Self {
        PeerMap {
            global_ctx,
            peer_map: DashMap::new(),
            packet_send,
        }
    }

    async fn add_new_peer(&self, peer: Peer) {
        self.peer_map.insert(peer.peer_node_id, Arc::new(peer));
    }

    pub async fn add_new_peer_conn(&self, peer_conn: PeerConn) {
        let peer_id = peer_conn.get_peer_id();
        let no_entry = self.peer_map.get(&peer_id).is_none();
        if no_entry {
            let new_peer = Peer::new(peer_id, self.packet_send.clone(), self.global_ctx.clone());
            new_peer.add_peer_conn(peer_conn).await;
            self.add_new_peer(new_peer).await;
        } else {
            let peer = self.peer_map.get(&peer_id).unwrap().clone();
            peer.add_peer_conn(peer_conn).await;
        }
    }

    fn get_peer_by_id(&self, peer_id: &PeerId) -> Option<Arc<Peer>> {
        self.peer_map.get(peer_id).map(|v| v.clone())
    }

    pub async fn send_msg_directly(
        &self,
        msg: Bytes,
        dst_peer_id: &uuid::Uuid,
    ) -> Result<(), Error> {
        if *dst_peer_id == self.global_ctx.get_id() {
            return Ok(self
                .packet_send
                .send(msg)
                .await
                .with_context(|| "send msg to self failed")?);
        }

        match self.get_peer_by_id(dst_peer_id) {
            Some(peer) => {
                peer.send_msg(msg).await?;
            }
            None => {
                log::error!("no peer for dst_peer_id: {}", dst_peer_id);
                return Ok(());
            }
        }

        Ok(())
    }

    pub async fn send_msg(
        &self,
        msg: Bytes,
        dst_peer_id: &uuid::Uuid,
        route: ArcRoute,
    ) -> Result<(), Error> {
        if *dst_peer_id == self.global_ctx.get_id() {
            return Ok(self
                .packet_send
                .send(msg)
                .await
                .with_context(|| "send msg to self failed")?);
        }

        // get route info
        let gateway_peer_id = route.get_next_hop(dst_peer_id).await;

        if gateway_peer_id.is_none() {
            log::error!("no gateway for dst_peer_id: {}", dst_peer_id);
            return Ok(());
        }

        let gateway_peer_id = gateway_peer_id.unwrap();
        self.send_msg_directly(msg, &gateway_peer_id).await?;

        Ok(())
    }

    pub async fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = Vec::new();
        for item in self.peer_map.iter() {
            let peer_id = item.key();
            ret.push(*peer_id);
        }
        ret
    }

    pub async fn list_peers_with_conn(&self) -> Vec<PeerId> {
        let mut ret = Vec::new();
        let peers = self.list_peers().await;
        for peer_id in peers.iter() {
            let Some(peer) = self.get_peer_by_id(peer_id) else {
                continue;
            };
            if peer.list_peer_conns().await.len() > 0 {
                ret.push(*peer_id);
            }
        }
        ret
    }

    pub async fn list_peer_conns(&self, peer_id: &PeerId) -> Option<Vec<PeerConnInfo>> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            Some(p.list_peer_conns().await)
        } else {
            return None;
        }
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: &PeerId,
        conn_id: &uuid::Uuid,
    ) -> Result<(), Error> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            p.close_peer_conn(conn_id).await
        } else {
            return Err(Error::NotFound);
        }
    }

    pub async fn close_peer(&self, peer_id: &PeerId) -> Result<(), TunnelError> {
        let remove_ret = self.peer_map.remove(peer_id);
        tracing::info!(
            ?peer_id,
            has_old_value = ?remove_ret.is_some(),
            peer_ref_counter = ?remove_ret.map(|v| Arc::strong_count(&v.1)),
            "peer is closed"
        );
        Ok(())
    }
}
