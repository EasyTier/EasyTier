use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Context;
use dashmap::DashMap;
use tokio::sync::RwLock;

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        PeerId,
    },
    proto::cli::PeerConnInfo,
    tunnel::{packet_def::ZCPacket, TunnelError},
};

use super::{
    peer::Peer,
    peer_conn::{PeerConn, PeerConnId},
    route_trait::{ArcRoute, NextHopPolicy},
    PacketRecvChan,
};

pub struct PeerMap {
    global_ctx: ArcGlobalCtx,
    my_peer_id: PeerId,
    peer_map: DashMap<PeerId, Arc<Peer>>,
    packet_send: PacketRecvChan,
    routes: RwLock<Vec<ArcRoute>>,
}

impl PeerMap {
    pub fn new(packet_send: PacketRecvChan, global_ctx: ArcGlobalCtx, my_peer_id: PeerId) -> Self {
        PeerMap {
            global_ctx,
            my_peer_id,
            peer_map: DashMap::new(),
            packet_send,
            routes: RwLock::new(Vec::new()),
        }
    }

    async fn add_new_peer(&self, peer: Peer) {
        let peer_id = peer.peer_node_id.clone();
        self.peer_map.insert(peer_id.clone(), Arc::new(peer));
        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerAdded(peer_id));
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

    fn get_peer_by_id(&self, peer_id: PeerId) -> Option<Arc<Peer>> {
        self.peer_map.get(&peer_id).map(|v| v.clone())
    }

    pub fn has_peer(&self, peer_id: PeerId) -> bool {
        peer_id == self.my_peer_id || self.peer_map.contains_key(&peer_id)
    }

    pub async fn send_msg_directly(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        if dst_peer_id == self.my_peer_id {
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
                tracing::error!("no peer for dst_peer_id: {}", dst_peer_id);
                return Err(Error::RouteError(Some(format!(
                    "peer map sengmsg directly no connected dst_peer_id: {}",
                    dst_peer_id
                ))));
            }
        }

        Ok(())
    }

    pub async fn get_gateway_peer_id(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        if dst_peer_id == self.my_peer_id {
            return Some(dst_peer_id);
        }

        if self.has_peer(dst_peer_id) && matches!(policy, NextHopPolicy::LeastHop) {
            return Some(dst_peer_id);
        }

        // get route info
        for route in self.routes.read().await.iter() {
            if let Some(gateway_peer_id) = route
                .get_next_hop_with_policy(dst_peer_id, policy.clone())
                .await
            {
                // NOTIC: for foreign network, gateway_peer_id may not connect to me
                return Some(gateway_peer_id);
            }
        }

        None
    }

    pub async fn list_peers_own_foreign_network(
        &self,
        network_identity: &NetworkIdentity,
    ) -> Vec<PeerId> {
        let mut ret = Vec::new();
        for route in self.routes.read().await.iter() {
            let peers = route
                .list_peers_own_foreign_network(&network_identity)
                .await;
            ret.extend(peers);
        }
        ret
    }

    pub async fn send_msg(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let Some(gateway_peer_id) = self.get_gateway_peer_id(dst_peer_id, policy).await else {
            return Err(Error::RouteError(Some(format!(
                "peer map sengmsg no gateway for dst_peer_id: {}",
                dst_peer_id
            ))));
        };

        self.send_msg_directly(msg, gateway_peer_id).await?;
        return Ok(());
    }

    pub async fn get_peer_id_by_ipv4(&self, ipv4: &Ipv4Addr) -> Option<PeerId> {
        for route in self.routes.read().await.iter() {
            let peer_id = route.get_peer_id_by_ipv4(ipv4).await;
            if peer_id.is_some() {
                return peer_id;
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.peer_map.is_empty()
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
            let Some(peer) = self.get_peer_by_id(*peer_id) else {
                continue;
            };
            if peer.list_peer_conns().await.len() > 0 {
                ret.push(*peer_id);
            }
        }
        ret
    }

    pub async fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            Some(p.list_peer_conns().await)
        } else {
            return None;
        }
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            p.close_peer_conn(conn_id).await
        } else {
            return Err(Error::NotFound);
        }
    }

    pub async fn close_peer(&self, peer_id: PeerId) -> Result<(), TunnelError> {
        let remove_ret = self.peer_map.remove(&peer_id);
        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        tracing::info!(
            ?peer_id,
            has_old_value = ?remove_ret.is_some(),
            peer_ref_counter = ?remove_ret.map(|v| Arc::strong_count(&v.1)),
            "peer is closed"
        );
        Ok(())
    }

    pub async fn add_route(&self, route: ArcRoute) {
        let mut routes = self.routes.write().await;
        routes.insert(0, route);
    }

    pub async fn clean_peer_without_conn(&self) {
        let mut to_remove = vec![];

        for peer_id in self.list_peers().await {
            let conns = self.list_peer_conns(peer_id).await;
            if conns.is_none() || conns.as_ref().unwrap().is_empty() {
                to_remove.push(peer_id);
            }
        }

        for peer_id in to_remove {
            self.close_peer(peer_id).await.unwrap();
        }
    }

    pub async fn list_routes(&self) -> DashMap<PeerId, PeerId> {
        let route_map = DashMap::new();
        for route in self.routes.read().await.iter() {
            for item in route.list_routes().await.iter() {
                route_map.insert(item.peer_id, item.next_hop_peer_id);
            }
        }
        route_map
    }
}

impl Drop for PeerMap {
    fn drop(&mut self) {
        tracing::debug!(
            self.my_peer_id,
            network = ?self.global_ctx.get_network_identity(),
            "PeerMap is dropped"
        );
    }
}
