use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use dashmap::{DashMap, DashSet};
use easytier_core::peers::peer_map::PeerMap as CorePeerMap;
use parking_lot::Mutex;
use tokio::sync::RwLock;

use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{ArcGlobalCtx, NetworkIdentity},
    },
    proto::{
        api::instance::{self, PeerConnInfo},
        peer_rpc::{PeerIdentityType, RoutePeerInfo},
    },
    tunnel::{TunnelError, packet_def::ZCPacket},
};

use super::{
    PacketRecvChan,
    peer::Peer,
    peer_conn::{PeerConn, PeerConnId},
    route_trait::{ArcRoute, NextHopPolicy},
};

pub struct PeerMap {
    core: CorePeerMap,
    global_ctx: ArcGlobalCtx,
    routes: RwLock<Vec<ArcRoute>>,
    alive_client_urls: Arc<Mutex<multimap::MultiMap<url::Url, PeerConnId>>>,
}

impl PeerMap {
    pub fn new(packet_send: PacketRecvChan, global_ctx: ArcGlobalCtx, my_peer_id: PeerId) -> Self {
        Self {
            core: CorePeerMap::new(packet_send, global_ctx.clone(), my_peer_id),
            global_ctx,
            routes: RwLock::new(Vec::new()),
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

    pub fn get_peer_by_id(&self, peer_id: PeerId) -> Option<Arc<Peer>> {
        self.core.get_peer_by_id(peer_id)
    }

    pub fn get_directly_connections_by_peer_id(&self, peer_id: PeerId) -> DashSet<uuid::Uuid> {
        self.core.get_directly_connections_by_peer_id(peer_id)
    }

    pub fn has_peer(&self, peer_id: PeerId) -> bool {
        self.core.has_peer(peer_id)
    }

    pub async fn send_msg_directly(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        self.core
            .send_msg_directly(msg, dst_peer_id)
            .await
            .map_err(Into::into)
    }

    pub async fn get_gateway_peer_id(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        if dst_peer_id == self.my_peer_id() {
            return Some(dst_peer_id);
        }

        if self.has_peer(dst_peer_id) && matches!(policy, NextHopPolicy::LeastHop) {
            return Some(dst_peer_id);
        }

        for route in self.routes.read().await.iter() {
            if let Some(gateway_peer_id) = route
                .get_next_hop_with_policy(dst_peer_id, policy.clone())
                .await
            {
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
            let peers = route.list_peers_own_foreign_network(network_identity).await;
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

        self.send_msg_directly(msg, gateway_peer_id).await
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

    pub async fn get_peer_id_by_ipv6(&self, ipv6: &Ipv6Addr) -> Option<PeerId> {
        for route in self.routes.read().await.iter() {
            let peer_id = route.get_peer_id_by_ipv6(ipv6).await;
            if peer_id.is_some() {
                return peer_id;
            }
        }
        None
    }

    pub async fn get_route_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        for route in self.routes.read().await.iter() {
            if let Some(info) = route.get_peer_info(peer_id).await {
                return Some(info);
            }
        }
        None
    }

    pub async fn get_origin_my_peer_id(
        &self,
        network_name: &str,
        foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        for route in self.routes.read().await.iter() {
            let origin_peer_id = route
                .get_origin_my_peer_id(network_name, foreign_my_peer_id)
                .await;
            if origin_peer_id.is_some() {
                return origin_peer_id;
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.core.is_empty()
    }

    pub fn list_peers(&self) -> Vec<PeerId> {
        self.core.list_peers()
    }

    pub async fn list_peers_with_conn(&self) -> Vec<PeerId> {
        self.core.list_peers_with_conn().await
    }

    pub async fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>> {
        self.core
            .list_peer_conns(peer_id)
            .await
            .map(|conns| conns.into_iter().map(Into::into).collect())
    }

    pub async fn get_peer_default_conn_id(&self, peer_id: PeerId) -> Option<PeerConnId> {
        self.core.get_peer_default_conn_id(peer_id).await
    }

    pub fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
        self.core.get_peer_identity_type(peer_id)
    }

    pub fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        self.core.get_peer_public_key(peer_id)
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        self.core
            .close_peer_conn(peer_id, conn_id)
            .await
            .map_err(Into::into)
    }

    pub async fn close_peer(&self, peer_id: PeerId) -> Result<(), TunnelError> {
        self.core.close_peer(peer_id).await
    }

    pub async fn add_route(&self, route: ArcRoute) {
        let mut routes = self.routes.write().await;
        routes.insert(0, route);
    }

    pub async fn clean_peer_without_conn(&self) {
        let mut to_remove = vec![];

        for peer_id in self.list_peers() {
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

    pub async fn list_route_infos(&self) -> Vec<instance::Route> {
        if let Some(route) = self.routes.read().await.iter().next() {
            return route.list_routes().await;
        }
        vec![]
    }

    pub async fn need_relay_by_foreign_network(&self, dst_peer_id: PeerId) -> Result<bool, Error> {
        let gateway_id = self
            .get_gateway_peer_id(dst_peer_id, NextHopPolicy::LeastHop)
            .await
            .ok_or(Error::RouteError(Some(format!(
                "peer map need_relay_by_foreign_network no gateway for dst_peer_id: {}",
                dst_peer_id
            ))))?;

        Ok(!self.has_peer(gateway_id))
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.core.my_peer_id()
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }
}

impl Drop for PeerMap {
    fn drop(&mut self) {
        tracing::debug!(
            my_peer_id = self.my_peer_id(),
            network = ?self.global_ctx.get_network_identity(),
            "PeerMap is dropped"
        );
    }
}
