use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use dashmap::{DashMap, DashSet};
use easytier_core::peers::{
    context::NetworkIdentity as CoreNetworkIdentity, peer_map::PeerMap as CorePeerMap,
};

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
}

impl PeerMap {
    pub fn new(packet_send: PacketRecvChan, global_ctx: ArcGlobalCtx, my_peer_id: PeerId) -> Self {
        Self {
            core: CorePeerMap::new(packet_send, global_ctx.clone(), my_peer_id),
            global_ctx,
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
        self.core.get_gateway_peer_id(dst_peer_id, policy).await
    }

    pub async fn list_peers_own_foreign_network(
        &self,
        network_identity: &NetworkIdentity,
    ) -> Vec<PeerId> {
        self.core
            .list_peers_own_foreign_network(&CoreNetworkIdentity {
                network_name: network_identity.network_name.clone(),
                network_secret: network_identity.network_secret.clone(),
                network_secret_digest: network_identity.network_secret_digest,
            })
            .await
    }

    pub async fn send_msg(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        self.core
            .send_msg(msg, dst_peer_id, policy)
            .await
            .map_err(Into::into)
    }

    pub async fn get_peer_id_by_ipv4(&self, ipv4: &Ipv4Addr) -> Option<PeerId> {
        self.core.get_peer_id_by_ipv4(ipv4).await
    }

    pub async fn get_peer_id_by_ipv6(&self, ipv6: &Ipv6Addr) -> Option<PeerId> {
        self.core.get_peer_id_by_ipv6(ipv6).await
    }

    pub async fn get_route_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        self.core.get_route_peer_info(peer_id).await
    }

    pub async fn get_origin_my_peer_id(
        &self,
        network_name: &str,
        foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        self.core
            .get_origin_my_peer_id(network_name, foreign_my_peer_id)
            .await
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
        self.core.add_route(route).await;
    }

    pub async fn clean_peer_without_conn(&self) {
        self.core.clean_peer_without_conn().await;
    }

    pub async fn list_routes(&self) -> DashMap<PeerId, PeerId> {
        self.core.list_routes().await
    }

    pub async fn list_route_infos(&self) -> Vec<instance::Route> {
        self.core
            .list_route_infos()
            .await
            .into_iter()
            .map(Into::into)
            .collect()
    }

    pub async fn need_relay_by_foreign_network(&self, dst_peer_id: PeerId) -> Result<bool, Error> {
        self.core
            .need_relay_by_foreign_network(dst_peer_id)
            .await
            .map_err(Into::into)
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
