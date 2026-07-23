use std::{sync::Arc, time::Duration};

use easytier_proto::{
    api::{
        config::{
            ConfigRpc, GetConfigRequest, GetConfigResponse, PatchConfigRequest, PatchConfigResponse,
        },
        instance::{
            AclManageRpc, ConnectorManageRpc, CredentialInfo, CredentialManageRpc,
            GenerateCredentialRequest, GenerateCredentialResponse, GetAclStatsRequest,
            GetAclStatsResponse, GetPrometheusStatsRequest, GetPrometheusStatsResponse,
            GetStatsRequest, GetStatsResponse, GetVpnPortalInfoRequest, GetVpnPortalInfoResponse,
            GetWhitelistRequest, GetWhitelistResponse, ListCredentialsRequest,
            ListCredentialsResponse, ListMappedListenerRequest, ListMappedListenerResponse,
            ListPortForwardRequest, ListPortForwardResponse, MappedListener,
            MappedListenerManageRpc, MetricSnapshot, PeerManageRpc, PortForwardManageRpc,
            RevokeCredentialRequest, RevokeCredentialResponse, StatsRpc, VpnPortalInfo,
            VpnPortalRpc,
        },
    },
    common::PortForwardConfigPb,
    peer_rpc::{
        GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, PeerCenterRpc, ReportPeersRequest,
        ReportPeersResponse,
    },
    rpc_types::{self, controller::BaseController},
};

use crate::{
    config::{api::network_config_from_toml, toml::ConfigLoader as _},
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    peers::credential_manager::{CredentialCreateOptions, CredentialInfo as CoreCredentialInfo},
};

use super::InstanceManagementRpc;
use crate::management::{
    full::{apply_config_patch, packet_proxy},
    resolve_instance,
};

/// Dispatches the JSON form of an Instance-targeted management RPC without
/// introducing a second, Host-owned set of service implementations.
pub async fn call_instance_json_rpc<F, H>(
    manager: &Arc<InstanceManager<F>>,
    service_name: &str,
    method_name: &str,
    domain_name: Option<&str>,
    payload: serde_json::Value,
) -> rpc_types::error::Result<serde_json::Value>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    let payload =
        match packet_proxy::call_json(manager, service_name, method_name, domain_name, payload)
            .await
        {
            Ok(response) => return response,
            Err(payload) => payload,
        };
    let ctrl = BaseController::default();
    let rpc = InstanceManagementRpc::<F, H>::new(manager.clone());

    match service_name {
        "api.instance.PeerManageRpcService" => {
            PeerManageRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.PeerCenterManageRpcService" => {
            PeerCenterRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.ConnectorManageRpcService" => {
            ConnectorManageRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.MappedListenerManageRpcService" => {
            MappedListenerManageRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.VpnPortalRpcService" => {
            VpnPortalRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.AclManageRpcService" => {
            AclManageRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.PortForwardManageRpcService" => {
            PortForwardManageRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.StatsRpcService" => {
            StatsRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.instance.CredentialManageRpcService" => {
            CredentialManageRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        "api.config.ConfigRpcService" => {
            ConfigRpc::json_call_method(&rpc, ctrl, method_name, payload).await
        }
        _ => Err(rpc_types::error::Error::InvalidServiceKey(
            service_name.to_owned(),
            service_name.to_owned(),
        )),
    }
}

fn credential_info_to_api(info: CoreCredentialInfo) -> CredentialInfo {
    CredentialInfo {
        credential_id: info.credential_id,
        groups: info.groups,
        allow_relay: info.allow_relay,
        expiry_unix: info.expiry_unix,
        allowed_proxy_cidrs: info.allowed_proxy_cidrs,
        reusable: info.reusable,
    }
}

#[async_trait::async_trait]
impl<F, H> MappedListenerManageRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn list_mapped_listener(
        &self,
        _: BaseController,
        request: ListMappedListenerRequest,
    ) -> rpc_types::error::Result<ListMappedListenerResponse> {
        let config = self
            .instance(request.instance.as_ref())?
            .toml_config()
            .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
        Ok(ListMappedListenerResponse {
            mappedlisteners: config
                .get_mapped_listeners()
                .into_iter()
                .map(|url| MappedListener {
                    url: Some(url.into()),
                })
                .collect(),
        })
    }
}

#[async_trait::async_trait]
impl<F, H> VpnPortalRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn get_vpn_portal_info(
        &self,
        _: BaseController,
        request: GetVpnPortalInfoRequest,
    ) -> rpc_types::error::Result<GetVpnPortalInfoResponse> {
        let info = self
            .instance(request.instance.as_ref())?
            .vpn_portal_info()
            .await;
        Ok(GetVpnPortalInfoResponse {
            vpn_portal_info: Some(VpnPortalInfo {
                vpn_type: info.vpn_type,
                client_config: info.client_config,
                connected_clients: info.connected_clients,
            }),
        })
    }
}

#[async_trait::async_trait]
impl<F, H> AclManageRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn get_acl_stats(
        &self,
        _: BaseController,
        request: GetAclStatsRequest,
    ) -> rpc_types::error::Result<GetAclStatsResponse> {
        Ok(GetAclStatsResponse {
            acl_stats: Some(self.instance(request.instance.as_ref())?.acl_stats()),
        })
    }

    async fn get_whitelist(
        &self,
        _: BaseController,
        request: GetWhitelistRequest,
    ) -> rpc_types::error::Result<GetWhitelistResponse> {
        let whitelist = self
            .instance(request.instance.as_ref())?
            .acl_whitelist_snapshot();
        Ok(GetWhitelistResponse {
            tcp_ports: whitelist.tcp_ports,
            udp_ports: whitelist.udp_ports,
        })
    }
}

#[async_trait::async_trait]
impl<F, H> PortForwardManageRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn list_port_forward(
        &self,
        _: BaseController,
        request: ListPortForwardRequest,
    ) -> rpc_types::error::Result<ListPortForwardResponse> {
        let config = self
            .instance(request.instance.as_ref())?
            .toml_config()
            .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
        Ok(ListPortForwardResponse {
            cfgs: config
                .get_port_forwards()
                .into_iter()
                .map(PortForwardConfigPb::from)
                .collect(),
        })
    }
}

#[async_trait::async_trait]
impl<F, H> StatsRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn get_stats(
        &self,
        _: BaseController,
        request: GetStatsRequest,
    ) -> rpc_types::error::Result<GetStatsResponse> {
        Ok(GetStatsResponse {
            metrics: self
                .instance(request.instance.as_ref())?
                .metric_snapshots()
                .into_iter()
                .map(|snapshot| MetricSnapshot {
                    name: snapshot.name_str(),
                    value: snapshot.value,
                    labels: snapshot
                        .labels
                        .labels()
                        .iter()
                        .map(|label| (label.key.clone(), label.value.clone()))
                        .collect(),
                })
                .collect(),
        })
    }

    async fn get_prometheus_stats(
        &self,
        _: BaseController,
        request: GetPrometheusStatsRequest,
    ) -> rpc_types::error::Result<GetPrometheusStatsResponse> {
        Ok(GetPrometheusStatsResponse {
            prometheus_text: self
                .instance(request.instance.as_ref())?
                .prometheus_metrics(),
        })
    }
}

#[async_trait::async_trait]
impl<F, H> CredentialManageRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn generate_credential(
        &self,
        _: BaseController,
        request: GenerateCredentialRequest,
    ) -> rpc_types::error::Result<GenerateCredentialResponse> {
        if request.ttl_seconds <= 0 {
            return Err(anyhow::anyhow!("ttl_seconds must be positive").into());
        }
        let generated = self
            .instance(request.instance.as_ref())?
            .generate_credential(CredentialCreateOptions {
                groups: request.groups,
                allow_relay: request.allow_relay,
                allowed_proxy_cidrs: request.allowed_proxy_cidrs,
                ttl: Duration::from_secs(request.ttl_seconds as u64),
                credential_id: request.credential_id,
                reusable: request.reusable.unwrap_or(true),
            })?;
        Ok(GenerateCredentialResponse {
            credential_id: generated.credential_id,
            credential_secret: generated.secret,
        })
    }

    async fn revoke_credential(
        &self,
        _: BaseController,
        request: RevokeCredentialRequest,
    ) -> rpc_types::error::Result<RevokeCredentialResponse> {
        Ok(RevokeCredentialResponse {
            success: self
                .instance(request.instance.as_ref())?
                .revoke_credential(&request.credential_id)?,
        })
    }

    async fn list_credentials(
        &self,
        _: BaseController,
        request: ListCredentialsRequest,
    ) -> rpc_types::error::Result<ListCredentialsResponse> {
        Ok(ListCredentialsResponse {
            credentials: self
                .instance(request.instance.as_ref())?
                .credential_snapshots()
                .into_iter()
                .map(credential_info_to_api)
                .collect(),
        })
    }
}

#[async_trait::async_trait]
impl<F, H> PeerCenterRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn get_global_peer_map(
        &self,
        _: BaseController,
        _: GetGlobalPeerMapRequest,
    ) -> rpc_types::error::Result<GetGlobalPeerMapResponse> {
        let instance = resolve_instance(&self.manager, None).map_err(|error| {
            if error.to_string().contains("please specify the instance ID") {
                anyhow::anyhow!(
                    "PeerCenter management RPC cannot select an instance automatically when \
                     multiple instances are running; please use an API that allows specifying \
                     an instance identifier."
                )
            } else {
                error
            }
        })?;
        Ok(instance.global_peer_map_snapshot())
    }

    async fn report_peers(
        &self,
        _: BaseController,
        _: ReportPeersRequest,
    ) -> rpc_types::error::Result<ReportPeersResponse> {
        Err(anyhow::anyhow!("not implemented for management API").into())
    }
}

#[async_trait::async_trait]
impl<F, H> ConfigRpc for InstanceManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn patch_config(
        &self,
        _: BaseController,
        request: PatchConfigRequest,
    ) -> rpc_types::error::Result<PatchConfigResponse> {
        let instance = self.instance(request.instance.as_ref())?;
        if let Some(patch) = request.patch {
            apply_config_patch(&instance, patch).await?;
        }
        Ok(PatchConfigResponse::default())
    }

    async fn get_config(
        &self,
        _: BaseController,
        request: GetConfigRequest,
    ) -> rpc_types::error::Result<GetConfigResponse> {
        let config = self
            .instance(request.instance.as_ref())?
            .toml_config()
            .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
        Ok(GetConfigResponse {
            config: Some(network_config_from_toml(&config)),
        })
    }
}
