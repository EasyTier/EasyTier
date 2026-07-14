use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use crate::{
    common::credential_manager::core_credential_info_to_api,
    common::global_ctx::GlobalCtx,
    connector::core_instance::RuntimeCoreInstance,
    proto::{
        api::instance::{
            AclManageRpc, CredentialManageRpc, DumpRouteRequest, DumpRouteResponse,
            GenerateCredentialRequest, GenerateCredentialResponse, GetAclStatsRequest,
            GetAclStatsResponse, GetForeignNetworkSummaryRequest, GetForeignNetworkSummaryResponse,
            GetWhitelistRequest, GetWhitelistResponse, ListCredentialsRequest,
            ListCredentialsResponse, ListForeignNetworkRequest, ListForeignNetworkResponse,
            ListGlobalForeignNetworkRequest, ListGlobalForeignNetworkResponse, ListPeerRequest,
            ListPeerResponse, ListPublicIpv6InfoRequest, ListPublicIpv6InfoResponse,
            ListRouteRequest, ListRouteResponse, NodeInfo, PeerInfo, PeerManageRpc,
            RevokeCredentialRequest, RevokeCredentialResponse, ShowNodeInfoRequest,
            ShowNodeInfoResponse, list_global_foreign_network_response::OneForeignNetwork,
        },
        rpc_types::{self, controller::BaseController},
    },
    utils::weak_upgrade,
};

use super::foreign_network_manager::foreign_network_info_to_api;

#[derive(Clone)]
pub struct PeerManagerRpcService {
    global_ctx: Weak<GlobalCtx>,
    core_instance: Weak<RuntimeCoreInstance>,
}

impl PeerManagerRpcService {
    pub(crate) fn new(
        global_ctx: &Arc<GlobalCtx>,
        core_instance: &Arc<RuntimeCoreInstance>,
    ) -> Self {
        PeerManagerRpcService {
            global_ctx: Arc::downgrade(global_ctx),
            core_instance: Arc::downgrade(core_instance),
        }
    }

    async fn list_peers(core_instance: &RuntimeCoreInstance) -> Vec<PeerInfo> {
        core_instance
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
            .collect()
    }

    async fn list_global_foreign_network(
        core_instance: &RuntimeCoreInstance,
    ) -> ListGlobalForeignNetworkResponse {
        let mut response = ListGlobalForeignNetworkResponse::default();
        let route_infos = core_instance.foreign_network_route_infos().await;
        for info in &route_infos.infos {
            let key = info.key.as_ref().unwrap();
            let entry = response.foreign_networks.entry(key.peer_id).or_default();
            let Some(route_info) = info.value.as_ref() else {
                continue;
            };
            entry.foreign_networks.push(OneForeignNetwork {
                network_name: key.network_name.clone(),
                peer_ids: route_info.foreign_peer_ids.clone(),
                last_updated: serde_json::to_string(&route_info.last_update.unwrap()).unwrap(),
                version: route_info.version,
            });
        }
        response
    }

    async fn list_foreign_networks(
        core_instance: &RuntimeCoreInstance,
        include_trusted_keys: bool,
    ) -> ListForeignNetworkResponse {
        ListForeignNetworkResponse {
            foreign_networks: core_instance
                .foreign_network_snapshots(include_trusted_keys)
                .await
                .into_iter()
                .map(|(network_name, info)| (network_name, foreign_network_info_to_api(info)))
                .collect(),
        }
    }

    fn format_prefix(prefix: &easytier_core::config::IpPrefix) -> String {
        format!("{}/{}", prefix.address, prefix.prefix_len)
    }

    fn format_proxy_network(proxy: easytier_core::config::ProxyNetworkConfig) -> String {
        let real = Self::format_prefix(&proxy.real);
        match proxy.mapped {
            Some(mapped) => format!("{}->{}", real, Self::format_prefix(&mapped)),
            None => real,
        }
    }
}

#[async_trait::async_trait]
impl PeerManageRpc for PeerManagerRpcService {
    type Controller = BaseController;
    async fn list_peer(
        &self,
        _: BaseController,
        _request: ListPeerRequest, // Accept request of type HelloRequest
    ) -> Result<ListPeerResponse, rpc_types::error::Error> {
        let mut reply = ListPeerResponse::default();

        let core_instance = weak_upgrade(&self.core_instance)?;
        let peers = PeerManagerRpcService::list_peers(&core_instance).await;
        for peer in peers {
            reply.peer_infos.push(peer);
        }

        Ok(reply)
    }

    async fn list_public_ipv6_info(
        &self,
        _: BaseController,
        _request: ListPublicIpv6InfoRequest,
    ) -> Result<ListPublicIpv6InfoResponse, rpc_types::error::Error> {
        Ok(weak_upgrade(&self.core_instance)?
            .local_public_ipv6_info()
            .await
            .into())
    }

    async fn list_route(
        &self,
        _: BaseController,
        _request: ListRouteRequest, // Accept request of type HelloRequest
    ) -> Result<ListRouteResponse, rpc_types::error::Error> {
        let reply = ListRouteResponse {
            routes: weak_upgrade(&self.core_instance)?
                .route_snapshots()
                .await
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        Ok(reply)
    }

    async fn dump_route(
        &self,
        _: BaseController,
        _request: DumpRouteRequest, // Accept request of type HelloRequest
    ) -> Result<DumpRouteResponse, rpc_types::error::Error> {
        let reply = DumpRouteResponse {
            result: weak_upgrade(&self.core_instance)?.dump_route().await,
        };
        Ok(reply)
    }

    async fn list_foreign_network(
        &self,
        _: BaseController,
        request: ListForeignNetworkRequest,
    ) -> Result<ListForeignNetworkResponse, rpc_types::error::Error> {
        let core_instance = weak_upgrade(&self.core_instance)?;
        Ok(Self::list_foreign_networks(&core_instance, request.include_trusted_keys).await)
    }

    async fn list_global_foreign_network(
        &self,
        _: BaseController,
        _request: ListGlobalForeignNetworkRequest,
    ) -> Result<ListGlobalForeignNetworkResponse, rpc_types::error::Error> {
        let core_instance = weak_upgrade(&self.core_instance)?;
        Ok(Self::list_global_foreign_network(&core_instance).await)
    }

    async fn get_foreign_network_summary(
        &self,
        _: BaseController,
        _request: GetForeignNetworkSummaryRequest,
    ) -> Result<GetForeignNetworkSummaryResponse, rpc_types::error::Error> {
        Ok(GetForeignNetworkSummaryResponse {
            summary: Some(
                weak_upgrade(&self.core_instance)?
                    .foreign_network_route_summary()
                    .await,
            ),
        })
    }

    async fn show_node_info(
        &self,
        _: BaseController,
        _request: ShowNodeInfoRequest, // Accept request of type HelloRequest
    ) -> Result<ShowNodeInfoResponse, rpc_types::error::Error> {
        let global_ctx = weak_upgrade(&self.global_ctx)?;
        let snapshot = weak_upgrade(&self.core_instance)?.node_snapshot().await;
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
                    .map(Self::format_proxy_network)
                    .collect(),
                hostname: snapshot.hostname,
                stun_info: Some(snapshot.stun_info),
                inst_id: snapshot.instance_id.to_string(),
                listeners: snapshot
                    .listeners
                    .into_iter()
                    .map(|listener| listener.to_string())
                    .collect(),
                config: global_ctx.config.dump(),
                version: snapshot.version,
                feature_flag: Some(snapshot.feature_flags),
                ip_list: Some(global_ctx.get_ip_collector().collect_ip_addrs().await),
                public_ipv6_addr: snapshot.public_ipv6_addr.map(Into::into),
                ipv6_public_addr_prefix: snapshot.ipv6_public_addr_prefix.map(Into::into),
            }),
        })
    }
}

#[async_trait::async_trait]
impl AclManageRpc for PeerManagerRpcService {
    type Controller = BaseController;

    async fn get_acl_stats(
        &self,
        _: BaseController,
        _request: GetAclStatsRequest,
    ) -> Result<GetAclStatsResponse, rpc_types::error::Error> {
        let acl_stats = weak_upgrade(&self.core_instance)?.acl_stats();
        Ok(GetAclStatsResponse {
            acl_stats: Some(acl_stats),
        })
    }

    async fn get_whitelist(
        &self,
        _: BaseController,
        _request: GetWhitelistRequest,
    ) -> Result<GetWhitelistResponse, rpc_types::error::Error> {
        let snapshot = weak_upgrade(&self.core_instance)?.acl_whitelist_snapshot();
        tracing::info!(
            "Getting whitelist - TCP: {:?}, UDP: {:?}",
            snapshot.tcp_ports,
            snapshot.udp_ports
        );
        Ok(GetWhitelistResponse {
            tcp_ports: snapshot.tcp_ports,
            udp_ports: snapshot.udp_ports,
        })
    }
}

#[async_trait::async_trait]
impl CredentialManageRpc for PeerManagerRpcService {
    type Controller = BaseController;

    async fn generate_credential(
        &self,
        _: BaseController,
        request: GenerateCredentialRequest,
    ) -> Result<GenerateCredentialResponse, rpc_types::error::Error> {
        let ttl = if request.ttl_seconds > 0 {
            Duration::from_secs(request.ttl_seconds as u64)
        } else {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "ttl_seconds must be positive"
            )));
        };

        let generated = weak_upgrade(&self.core_instance)?
            .generate_credential(easytier_core::instance::CredentialCreateOptions {
                groups: request.groups,
                allow_relay: request.allow_relay,
                allowed_proxy_cidrs: request.allowed_proxy_cidrs,
                ttl,
                credential_id: request.credential_id,
                reusable: request.reusable.unwrap_or(true),
            })
            .map_err(rpc_types::error::Error::ExecutionError)?;

        Ok(GenerateCredentialResponse {
            credential_id: generated.credential_id,
            credential_secret: generated.secret,
        })
    }

    async fn revoke_credential(
        &self,
        _: BaseController,
        request: RevokeCredentialRequest,
    ) -> Result<RevokeCredentialResponse, rpc_types::error::Error> {
        let success = weak_upgrade(&self.core_instance)?
            .revoke_credential(&request.credential_id)
            .map_err(rpc_types::error::Error::ExecutionError)?;

        Ok(RevokeCredentialResponse { success })
    }

    async fn list_credentials(
        &self,
        _: BaseController,
        _request: ListCredentialsRequest,
    ) -> Result<ListCredentialsResponse, rpc_types::error::Error> {
        Ok(ListCredentialsResponse {
            credentials: weak_upgrade(&self.core_instance)?
                .credential_snapshots()
                .into_iter()
                .map(core_credential_info_to_api)
                .collect(),
        })
    }
}
