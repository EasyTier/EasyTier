use std::{marker::PhantomData, sync::Arc};

use easytier_proto::{
    api::instance::{
        Connector, ConnectorManageRpc, ConnectorStatus, DumpRouteRequest, DumpRouteResponse,
        ForeignNetworkEntryPb, GetForeignNetworkSummaryRequest, GetForeignNetworkSummaryResponse,
        ListConnectorRequest, ListConnectorResponse, ListForeignNetworkRequest,
        ListForeignNetworkResponse, ListGlobalForeignNetworkRequest,
        ListGlobalForeignNetworkResponse, ListPeerRequest, ListPeerResponse,
        ListPublicIpv6InfoRequest, ListPublicIpv6InfoResponse, ListRouteRequest, ListRouteResponse,
        NodeInfo, PeerInfo, PeerManageRpc, ShowNodeInfoRequest, ShowNodeInfoResponse,
        TrustedKeyInfoPb, TrustedKeySourcePb,
        list_global_foreign_network_response::OneForeignNetwork,
    },
    rpc_types::{self, controller::BaseController},
};

use crate::{
    config::{IpPrefix, ProxyNetworkConfig},
    connectivity::manual::{ManualConnectorSnapshot, ManualConnectorStatus},
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    peers::{context::TrustedKeySource, foreign_network::ForeignNetworkEntryInfo},
};

use super::resolve_instance;

#[cfg(feature = "management")]
pub(super) mod full;
#[cfg(all(feature = "management", feature = "proxy-packet"))]
pub(super) mod packet_proxy;
mod projection;

/// One process-level implementation for Instance-targeted management RPC.
pub struct InstanceManagementRpc<F, H>
where
    F: InstanceFactory,
{
    manager: Arc<InstanceManager<F>>,
    host: PhantomData<fn() -> H>,
}

impl<F, H> Clone for InstanceManagementRpc<F, H>
where
    F: InstanceFactory,
{
    fn clone(&self) -> Self {
        Self {
            manager: self.manager.clone(),
            host: PhantomData,
        }
    }
}

impl<F, H> InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    pub fn new(manager: Arc<InstanceManager<F>>) -> Self {
        Self {
            manager,
            host: PhantomData,
        }
    }

    fn instance(
        &self,
        identifier: Option<&easytier_proto::api::instance::InstanceIdentifier>,
    ) -> rpc_types::error::Result<Arc<CoreInstance<H>>> {
        resolve_instance(&self.manager, identifier).map_err(Into::into)
    }
}

fn foreign_network_info_to_api(info: ForeignNetworkEntryInfo) -> ForeignNetworkEntryPb {
    ForeignNetworkEntryPb {
        network_secret_digest: info.network_secret_digest,
        my_peer_id_for_this_network: info.my_peer_id_for_this_network,
        peers: info
            .peers
            .into_iter()
            .map(|peer| PeerInfo {
                peer_id: peer.peer_id,
                conns: peer.conns.into_iter().map(Into::into).collect(),
                ..Default::default()
            })
            .collect(),
        trusted_keys: info
            .trusted_keys
            .into_iter()
            .map(|key| TrustedKeyInfoPb {
                pubkey: key.pubkey,
                source: match key.source {
                    TrustedKeySource::OspfNode => TrustedKeySourcePb::OspfNode.into(),
                    TrustedKeySource::OspfCredential => TrustedKeySourcePb::OspfCredential.into(),
                },
                expiry_unix: key.expiry_unix,
            })
            .collect(),
    }
}

fn format_prefix(prefix: &IpPrefix) -> String {
    format!("{}/{}", prefix.address, prefix.prefix_len)
}

fn format_proxy_network(proxy: ProxyNetworkConfig) -> String {
    let real = format_prefix(&proxy.real);
    match proxy.mapped {
        Some(mapped) => format!("{}->{}", real, format_prefix(&mapped)),
        None => real,
    }
}

fn connector_snapshots_to_api(snapshots: Vec<ManualConnectorSnapshot>) -> Vec<Connector> {
    let mut connectors = Vec::with_capacity(snapshots.len());
    for connector in snapshots {
        let status = match connector.status {
            ManualConnectorStatus::Connected => ConnectorStatus::Connected,
            ManualConnectorStatus::Disconnected => ConnectorStatus::Disconnected,
            ManualConnectorStatus::Connecting => ConnectorStatus::Connecting,
        };
        connectors.insert(
            0,
            Connector {
                url: Some(connector.url.into()),
                status: status.into(),
            },
        );
    }
    connectors
}

#[async_trait::async_trait]
impl<F, H> PeerManageRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn list_peer(
        &self,
        _: BaseController,
        request: ListPeerRequest,
    ) -> rpc_types::error::Result<ListPeerResponse> {
        let peer_infos = self
            .instance(request.instance.as_ref())?
            .peer_snapshots()
            .await
            .into_iter()
            .map(|snapshot| PeerInfo {
                peer_id: snapshot.peer_id,
                default_conn_id: snapshot.default_conn_id.map(Into::into),
                directly_connected_conns: snapshot
                    .directly_connected_conns
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                conns: snapshot.conns.into_iter().map(Into::into).collect(),
            })
            .collect();
        Ok(ListPeerResponse {
            peer_infos,
            ..Default::default()
        })
    }

    async fn list_public_ipv6_info(
        &self,
        _: BaseController,
        request: ListPublicIpv6InfoRequest,
    ) -> rpc_types::error::Result<ListPublicIpv6InfoResponse> {
        Ok(self
            .instance(request.instance.as_ref())?
            .local_public_ipv6_info()
            .await
            .into())
    }

    async fn list_route(
        &self,
        _: BaseController,
        request: ListRouteRequest,
    ) -> rpc_types::error::Result<ListRouteResponse> {
        Ok(ListRouteResponse {
            routes: self
                .instance(request.instance.as_ref())?
                .route_snapshots()
                .await
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    async fn dump_route(
        &self,
        _: BaseController,
        request: DumpRouteRequest,
    ) -> rpc_types::error::Result<DumpRouteResponse> {
        Ok(DumpRouteResponse {
            result: self.instance(request.instance.as_ref())?.dump_route().await,
        })
    }

    async fn list_foreign_network(
        &self,
        _: BaseController,
        request: ListForeignNetworkRequest,
    ) -> rpc_types::error::Result<ListForeignNetworkResponse> {
        Ok(ListForeignNetworkResponse {
            foreign_networks: self
                .instance(request.instance.as_ref())?
                .foreign_network_snapshots(request.include_trusted_keys)
                .await
                .into_iter()
                .map(|(network_name, info)| (network_name, foreign_network_info_to_api(info)))
                .collect(),
        })
    }

    async fn list_global_foreign_network(
        &self,
        _: BaseController,
        request: ListGlobalForeignNetworkRequest,
    ) -> rpc_types::error::Result<ListGlobalForeignNetworkResponse> {
        let mut response = ListGlobalForeignNetworkResponse::default();
        let route_infos = self
            .instance(request.instance.as_ref())?
            .foreign_network_route_infos()
            .await;
        for info in &route_infos.infos {
            let Some(key) = info.key.as_ref() else {
                continue;
            };
            let Some(route_info) = info.value.as_ref() else {
                continue;
            };
            response
                .foreign_networks
                .entry(key.peer_id)
                .or_default()
                .foreign_networks
                .push(OneForeignNetwork {
                    network_name: key.network_name.clone(),
                    peer_ids: route_info.foreign_peer_ids.clone(),
                    last_updated: match route_info.last_update.as_ref() {
                        Some(last_update) => projection::format_last_update(last_update)?,
                        None => String::new(),
                    },
                    version: route_info.version,
                });
        }
        Ok(response)
    }

    async fn get_foreign_network_summary(
        &self,
        _: BaseController,
        request: GetForeignNetworkSummaryRequest,
    ) -> rpc_types::error::Result<GetForeignNetworkSummaryResponse> {
        Ok(GetForeignNetworkSummaryResponse {
            summary: Some(
                self.instance(request.instance.as_ref())?
                    .foreign_network_route_summary()
                    .await,
            ),
        })
    }

    async fn show_node_info(
        &self,
        _: BaseController,
        request: ShowNodeInfoRequest,
    ) -> rpc_types::error::Result<ShowNodeInfoResponse> {
        let instance = self.instance(request.instance.as_ref())?;
        let config = projection::node_config(instance.as_ref())?;
        let snapshot = instance.node_snapshot().await;
        Ok(ShowNodeInfoResponse {
            node_info: Some(NodeInfo {
                peer_id: snapshot.peer_id,
                ipv4_addr: snapshot
                    .ipv4_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
                proxy_cidrs: snapshot
                    .proxy_networks
                    .into_iter()
                    .map(format_proxy_network)
                    .collect(),
                hostname: snapshot.hostname,
                stun_info: Some(snapshot.stun_info),
                inst_id: snapshot.instance_id.to_string(),
                listeners: snapshot
                    .listeners
                    .into_iter()
                    .map(|listener| listener.to_string())
                    .collect(),
                config,
                version: snapshot.version,
                feature_flag: Some(snapshot.feature_flags),
                ip_list: Some(snapshot.ip_list),
                public_ipv6_addr: snapshot.public_ipv6_addr.map(Into::into),
                ipv6_public_addr_prefix: snapshot.ipv6_public_addr_prefix.map(Into::into),
            }),
        })
    }
}

#[async_trait::async_trait]
impl<F, H> ConnectorManageRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn list_connector(
        &self,
        _: BaseController,
        request: ListConnectorRequest,
    ) -> rpc_types::error::Result<ListConnectorResponse> {
        Ok(ListConnectorResponse {
            connectors: connector_snapshots_to_api(
                self.instance(request.instance.as_ref())?.list_connectors(),
            ),
        })
    }
}
