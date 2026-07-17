use std::{net::IpAddr, sync::Arc};

use url::Url;

use crate::{
    connectivity::{
        direct::DirectConnectorHost, hole_punch::tcp::TcpHolePunchHost,
        manual::ManualConnectorSnapshot,
    },
    foundation::stats::MetricSnapshot,
    peers::{
        acl_config::AclWhitelistSnapshot,
        credential_manager::{CredentialCreateOptions, CredentialInfo, GeneratedCredential},
        peer_center::instance::PeerCenterInstanceService,
        peer_conn::PeerConnId,
        peer_manager::PeerSnapshot,
    },
};

#[cfg(feature = "proxy-packet")]
use crate::gateway::proxy::wrapped_transport::{WrappedTransportKind, WrappedTransportRole};

use super::{CoreInstance, CorePacketPlane};

impl<H> CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub fn add_connector(&self, url: Url) -> anyhow::Result<()> {
        self.manual.add_connector(url)
    }

    pub fn remove_connector(&self, url: &Url) -> bool {
        self.manual.remove_connector(url)
    }

    pub fn clear_connectors(&self) {
        self.manual.clear_connectors();
    }

    pub fn list_connectors(&self) -> Vec<ManualConnectorSnapshot> {
        self.manual.list_connectors()
    }

    pub fn running_listeners(&self) -> Vec<Url> {
        self.running_listeners.running_listeners()
    }

    pub fn peer_id(&self) -> crate::config::PeerId {
        self.peer_manager.my_peer_id()
    }

    pub fn packet_plane(&self) -> Arc<CorePacketPlane> {
        self.packet_plane.clone()
    }

    pub fn peer_center_rpc_service(&self) -> PeerCenterInstanceService {
        self.peer_center.get_rpc_service()
    }

    pub async fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peer_manager.list_peer_snapshots().await
    }

    pub async fn node_snapshot(&self) -> crate::peers::peer_manager::NodeSnapshot {
        let mut snapshot = self
            .peer_manager
            .node_snapshot(self.running_listeners())
            .await;
        snapshot.ip_list = self
            .direct
            .local_address_observations_with_stun(&snapshot.stun_info)
            .await;
        snapshot
    }

    pub async fn route_snapshots(&self) -> Vec<crate::proto::core_peer::peer::Route> {
        self.peer_manager.list_route_snapshots().await
    }

    pub async fn dump_route(&self) -> String {
        self.peer_manager.dump_route().await
    }

    pub async fn local_public_ipv6_info(
        &self,
    ) -> crate::proto::core_peer::peer::ListPublicIpv6InfoResponse {
        self.peer_manager.local_public_ipv6_info().await
    }

    pub async fn foreign_network_route_infos(
        &self,
    ) -> crate::proto::peer_rpc::RouteForeignNetworkInfos {
        self.peer_manager.foreign_network_route_infos().await
    }

    pub async fn foreign_network_snapshots(
        &self,
        include_trusted_keys: bool,
    ) -> std::collections::HashMap<
        String,
        crate::peers::foreign_network_manager::ForeignNetworkEntryInfo,
    > {
        self.peer_manager
            .list_foreign_network_infos(include_trusted_keys)
            .await
    }

    pub async fn foreign_network_route_summary(
        &self,
    ) -> crate::proto::peer_rpc::RouteForeignNetworkSummary {
        self.peer_manager.foreign_network_route_summary().await
    }

    pub fn acl_stats(&self) -> crate::proto::acl::AclStats {
        self.peer_manager.acl_stats()
    }

    pub fn acl_whitelist_snapshot(&self) -> AclWhitelistSnapshot {
        let config = self.runtime_config.snapshot();
        AclWhitelistSnapshot::from(&config.services.acl)
    }

    #[cfg(feature = "proxy-packet")]
    pub fn tcp_proxy_entry_snapshots(
        &self,
    ) -> Vec<crate::gateway::proxy::tcp_proxy_engine::TcpNatEntrySnapshot> {
        self.proxy.tcp_entry_snapshots()
    }

    #[cfg(feature = "proxy-packet")]
    pub fn wrapped_tcp_proxy_entry_snapshots(
        &self,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> Vec<crate::gateway::proxy::tcp_proxy_engine::TcpNatEntrySnapshot> {
        self.transport_proxy
            .as_ref()
            .map_or_else(Vec::new, |proxy| match role {
                WrappedTransportRole::Source => proxy.source_entry_snapshots(transport),
                WrappedTransportRole::Destination => proxy.destination_entry_snapshots(transport),
            })
    }

    #[cfg(feature = "proxy-packet")]
    pub fn wrapped_transport_is_started(
        &self,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> bool {
        self.transport_proxy
            .as_ref()
            .is_some_and(|proxy| match role {
                WrappedTransportRole::Source => proxy.source_is_started(transport),
                WrappedTransportRole::Destination => proxy.destination_is_started(transport),
            })
    }

    pub fn generate_credential(
        &self,
        options: CredentialCreateOptions,
    ) -> anyhow::Result<GeneratedCredential> {
        if !self.peer_manager.can_manage_credentials() {
            anyhow::bail!("only admin nodes (with network_secret) can generate credentials");
        }
        if options.ttl.is_zero() {
            anyhow::bail!("ttl_seconds must be positive");
        }
        let generated = self
            .peer_manager
            .credential_manager()
            .generate_credential_with_options(
                options.groups,
                options.allow_relay,
                options.allowed_proxy_cidrs,
                options.ttl,
                options.credential_id,
                options.reusable,
            );
        self.peer_manager.notify_credential_changed();
        Ok(generated)
    }

    pub fn revoke_credential(&self, credential_id: &str) -> anyhow::Result<bool> {
        if !self.peer_manager.can_manage_credentials() {
            anyhow::bail!("only admin nodes (with network_secret) can revoke credentials");
        }
        let revoked = self
            .peer_manager
            .credential_manager()
            .revoke_credential(credential_id);
        if revoked {
            self.peer_manager.notify_credential_changed();
        }
        Ok(revoked)
    }

    pub fn credential_snapshots(&self) -> Vec<CredentialInfo> {
        self.peer_manager.credential_manager().list_credentials()
    }

    pub fn metric_snapshots(&self) -> Vec<MetricSnapshot> {
        self.peer_manager.stats_manager().get_all_metrics()
    }

    pub fn prometheus_metrics(&self) -> String {
        self.peer_manager.stats_manager().export_prometheus()
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: crate::config::PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), crate::peers::error::Error> {
        self.peer_manager.close_peer_conn(peer_id, conn_id).await
    }

    pub async fn update_exit_nodes(&self, exit_nodes: Vec<IpAddr>) {
        self.peer_manager.update_exit_nodes(exit_nodes).await;
    }

    pub async fn refresh_acl_groups(&self) {
        self.peer_manager.get_route().refresh_acl_groups().await;
    }
}
