use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use dashmap::{DashMap, DashSet};
use easytier_core::{
    peers::{
        context::NetworkIdentity as CoreNetworkIdentity,
        peer_map::PeerMap as CorePeerMap,
        route_trait::{
            ArcRoute as CoreArcRoute, Route as CoreRoute,
            RouteInterfaceBox as CoreRouteInterfaceBox,
        },
    },
    proto::core_peer::peer::Route as CoreRouteInfo,
};
use parking_lot::Mutex;

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
    route_trait::{ArcRoute, NextHopPolicy, RouteInterface as RuntimeRouteInterface},
};

pub struct PeerMap {
    core: CorePeerMap,
    global_ctx: ArcGlobalCtx,
    alive_client_urls: Arc<Mutex<multimap::MultiMap<url::Url, PeerConnId>>>,
}

struct CoreRouteAdapter {
    route: ArcRoute,
}

struct RuntimeRouteInterfaceAdapter {
    inner: CoreRouteInterfaceBox,
}

fn core_network_identity_to_runtime(identity: &CoreNetworkIdentity) -> NetworkIdentity {
    NetworkIdentity {
        network_name: identity.network_name.clone(),
        network_secret: identity.network_secret.clone(),
        network_secret_digest: identity.network_secret_digest,
    }
}

fn api_route_to_core(route: instance::Route) -> CoreRouteInfo {
    CoreRouteInfo {
        peer_id: route.peer_id,
        ipv4_addr: route.ipv4_addr,
        next_hop_peer_id: route.next_hop_peer_id,
        cost: route.cost,
        proxy_cidrs: route.proxy_cidrs,
        hostname: route.hostname,
        stun_info: route.stun_info,
        inst_id: route.inst_id,
        version: route.version,
        feature_flag: route.feature_flag,
        path_latency: route.path_latency,
        next_hop_peer_id_latency_first: route.next_hop_peer_id_latency_first,
        cost_latency_first: route.cost_latency_first,
        path_latency_latency_first: route.path_latency_latency_first,
        ipv6_addr: route.ipv6_addr,
        public_ipv6_addr: route.public_ipv6_addr,
        ipv6_public_addr_prefix: route.ipv6_public_addr_prefix,
    }
}

#[async_trait::async_trait]
impl RuntimeRouteInterface for RuntimeRouteInterfaceAdapter {
    async fn list_peers(&self) -> Vec<PeerId> {
        self.inner.list_peers().await
    }

    fn my_peer_id(&self) -> PeerId {
        self.inner.my_peer_id()
    }

    fn need_periodic_requery_peers(&self) -> bool {
        self.inner.need_periodic_requery_peers()
    }

    async fn close_peer(&self, peer_id: PeerId) {
        self.inner.close_peer(peer_id).await;
    }

    async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        self.inner.get_peer_public_key(peer_id).await
    }

    async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
        self.inner.get_peer_identity_type(peer_id).await
    }

    async fn list_foreign_networks(&self) -> super::route_trait::ForeignNetworkRouteInfoMap {
        self.inner.list_foreign_networks().await
    }
}

#[async_trait::async_trait]
impl CoreRoute for CoreRouteAdapter {
    async fn open(&self, interface: CoreRouteInterfaceBox) -> Result<u8, ()> {
        self.route
            .open(Box::new(RuntimeRouteInterfaceAdapter { inner: interface }))
            .await
    }

    async fn close(&self) {
        self.route.close().await;
    }

    async fn get_next_hop(&self, peer_id: PeerId) -> Option<PeerId> {
        self.route.get_next_hop(peer_id).await
    }

    async fn get_next_hop_with_policy(
        &self,
        peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        self.route.get_next_hop_with_policy(peer_id, policy).await
    }

    async fn list_routes(&self) -> Vec<CoreRouteInfo> {
        self.route
            .list_routes()
            .await
            .into_iter()
            .map(api_route_to_core)
            .collect()
    }

    async fn list_proxy_cidrs(&self) -> BTreeSet<cidr::Ipv4Cidr> {
        self.route.list_proxy_cidrs().await
    }

    async fn list_proxy_cidrs_v6(&self) -> BTreeSet<cidr::Ipv6Cidr> {
        self.route.list_proxy_cidrs_v6().await
    }

    async fn list_public_ipv6_routes(&self) -> BTreeSet<cidr::Ipv6Inet> {
        self.route.list_public_ipv6_routes().await
    }

    async fn get_my_public_ipv6_addr(&self) -> Option<cidr::Ipv6Inet> {
        self.route.get_my_public_ipv6_addr().await
    }

    async fn get_public_ipv6_gateway_peer_id(&self) -> Option<PeerId> {
        self.route.get_public_ipv6_gateway_peer_id().await
    }

    async fn get_peer_id_by_ipv4(&self, ipv4: &Ipv4Addr) -> Option<PeerId> {
        self.route.get_peer_id_by_ipv4(ipv4).await
    }

    async fn get_peer_id_by_ipv6(&self, ipv6: &Ipv6Addr) -> Option<PeerId> {
        self.route.get_peer_id_by_ipv6(ipv6).await
    }

    async fn list_peers_own_foreign_network(
        &self,
        network_identity: &CoreNetworkIdentity,
    ) -> Vec<PeerId> {
        self.route
            .list_peers_own_foreign_network(&core_network_identity_to_runtime(network_identity))
            .await
    }

    async fn list_foreign_network_info(&self) -> crate::proto::peer_rpc::RouteForeignNetworkInfos {
        self.route.list_foreign_network_info().await
    }

    async fn get_foreign_network_summary(
        &self,
    ) -> crate::proto::peer_rpc::RouteForeignNetworkSummary {
        self.route.get_foreign_network_summary().await
    }

    async fn get_origin_my_peer_id(
        &self,
        network_name: &str,
        foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        self.route
            .get_origin_my_peer_id(network_name, foreign_my_peer_id)
            .await
    }

    async fn set_route_cost_fn(
        &self,
        cost_fn: easytier_core::peers::route_trait::RouteCostCalculator,
    ) {
        self.route.set_route_cost_fn(cost_fn).await;
    }

    async fn get_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        self.route.get_peer_info(peer_id).await
    }

    async fn get_peer_info_last_update_time(&self) -> quanta::Instant {
        self.route.get_peer_info_last_update_time().await
    }

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>> {
        self.route.get_peer_groups(peer_id)
    }

    async fn refresh_acl_groups(&self) {
        self.route.refresh_acl_groups().await;
    }

    async fn dump(&self) -> String {
        self.route.dump().await
    }
}

impl PeerMap {
    pub fn new(packet_send: PacketRecvChan, global_ctx: ArcGlobalCtx, my_peer_id: PeerId) -> Self {
        Self {
            core: CorePeerMap::new(packet_send, global_ctx.clone(), my_peer_id),
            global_ctx,
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
        let Some(gateway_peer_id) = self.get_gateway_peer_id(dst_peer_id, policy).await else {
            return Err(Error::RouteError(Some(format!(
                "peer map sengmsg no gateway for dst_peer_id: {}",
                dst_peer_id
            ))));
        };

        self.send_msg_directly(msg, gateway_peer_id).await
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
        let route: CoreArcRoute = Arc::new(Box::new(CoreRouteAdapter { route }));
        self.core.add_route(route).await;
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
