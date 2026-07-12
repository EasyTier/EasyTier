use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use crate::{
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
            ListRouteRequest, ListRouteResponse, PeerInfo, PeerManageRpc, RevokeCredentialRequest,
            RevokeCredentialResponse, ShowNodeInfoRequest, ShowNodeInfoResponse,
            list_global_foreign_network_response::OneForeignNetwork,
        },
        rpc_types::{self, controller::BaseController},
    },
    utils::weak_upgrade,
};

use super::peer_manager::PeerManager;

#[derive(Clone)]
pub struct PeerManagerRpcService {
    peer_manager: Weak<PeerManager>,
    core_instance: Weak<RuntimeCoreInstance>,
}

impl PeerManagerRpcService {
    pub(crate) fn new(
        peer_manager: Arc<PeerManager>,
        core_instance: &Arc<RuntimeCoreInstance>,
    ) -> Self {
        PeerManagerRpcService {
            peer_manager: Arc::downgrade(&peer_manager),
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
        let reply = weak_upgrade(&self.peer_manager)?
            .get_foreign_network_manager()
            .list_foreign_networks_with_options(request.include_trusted_keys)
            .await;
        Ok(reply)
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
        Ok(ShowNodeInfoResponse {
            node_info: Some(weak_upgrade(&self.peer_manager)?.get_my_info().await),
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
        let global_ctx = weak_upgrade(&self.peer_manager)?.get_global_ctx();
        let tcp_ports = global_ctx.config.get_tcp_whitelist();
        let udp_ports = global_ctx.config.get_udp_whitelist();
        tracing::info!(
            "Getting whitelist - TCP: {:?}, UDP: {:?}",
            tcp_ports,
            udp_ports
        );
        Ok(GetWhitelistResponse {
            tcp_ports,
            udp_ports,
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
        let pm = weak_upgrade(&self.peer_manager)?;
        let global_ctx = pm.get_global_ctx();

        if global_ctx.get_network_identity().network_secret.is_none() {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "only admin nodes (with network_secret) can generate credentials"
            )));
        }

        let ttl = if request.ttl_seconds > 0 {
            Duration::from_secs(request.ttl_seconds as u64)
        } else {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "ttl_seconds must be positive"
            )));
        };

        let (id, secret) = global_ctx
            .get_credential_manager()
            .generate_credential_with_options(
                request.groups,
                request.allow_relay,
                request.allowed_proxy_cidrs,
                ttl,
                request.credential_id,
                request.reusable.unwrap_or(true),
            );

        global_ctx.issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

        Ok(GenerateCredentialResponse {
            credential_id: id,
            credential_secret: secret,
        })
    }

    async fn revoke_credential(
        &self,
        _: BaseController,
        request: RevokeCredentialRequest,
    ) -> Result<RevokeCredentialResponse, rpc_types::error::Error> {
        let pm = weak_upgrade(&self.peer_manager)?;
        let global_ctx = pm.get_global_ctx();
        if global_ctx.get_network_identity().network_secret.is_none() {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "only admin nodes (with network_secret) can revoke credentials"
            )));
        }

        let success = global_ctx
            .get_credential_manager()
            .revoke_credential(&request.credential_id);

        if success {
            global_ctx.issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);
        }

        Ok(RevokeCredentialResponse { success })
    }

    async fn list_credentials(
        &self,
        _: BaseController,
        _request: ListCredentialsRequest,
    ) -> Result<ListCredentialsResponse, rpc_types::error::Error> {
        let pm = weak_upgrade(&self.peer_manager)?;
        let global_ctx = pm.get_global_ctx();

        Ok(ListCredentialsResponse {
            credentials: global_ctx.get_credential_manager().list_credentials(),
        })
    }
}
