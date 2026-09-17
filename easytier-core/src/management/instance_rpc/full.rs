use std::{sync::Arc, time::Duration};

use easytier_proto::{
    api::{
        config::ConfigRpc,
        instance::{
            AclManageRpc, ConnectorManageRpc, CredentialInfo, CredentialManageRpc,
            GenerateCredentialRequest, GenerateCredentialResponse, GetAclStatsRequest,
            GetAclStatsResponse, GetPrometheusStatsRequest, GetPrometheusStatsResponse,
            GetStatsRequest, GetStatsResponse, GetVpnPortalInfoRequest, GetVpnPortalInfoResponse,
            GetWhitelistRequest, GetWhitelistResponse, ListCredentialsRequest,
            ListCredentialsResponse, ListMappedListenerRequest, ListMappedListenerResponse,
            ListPortForwardRequest, ListPortForwardResponse, MappedListener,
            MappedListenerManageRpc, MetricSnapshot, PeerManageRpc, PortForwardManageRpc,
            RevokeCredentialRequest, RevokeCredentialResponse, StatsRpc, UpsertCredentialRequest,
            UpsertCredentialResponse, VpnPortalClientInfo, VpnPortalClientState, VpnPortalInfo,
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
    config::toml::ConfigLoader as _,
    gateway::vpn_portal::{PortalClientState, PortalInfoSnapshot},
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    peers::credential_manager::{
        CredentialCreateOptions, CredentialInfo as CoreCredentialInfo, CredentialUpsertOptions,
    },
};

use super::InstanceManagementRpc;
use crate::management::{full::packet_proxy, resolve_instance};

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
    let rpc = InstanceManagementRpc::<F>::new(manager.clone());

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
        public_key_fingerprint: info.public_key_fingerprint,
    }
}

#[async_trait::async_trait]
impl<F, H> MappedListenerManageRpc for InstanceManagementRpc<F>
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

fn vpn_portal_info_to_proto(info: PortalInfoSnapshot) -> VpnPortalInfo {
    let client_config = info
        .clients
        .first()
        .map(|client| client.client_config.clone())
        .unwrap_or_default();
    let connected_clients = info
        .clients
        .iter()
        .filter(|client| client.state == PortalClientState::Online)
        .filter_map(|client| client.endpoint.clone())
        .collect();
    #[allow(deprecated)]
    VpnPortalInfo {
        vpn_type: info.vpn_type,
        client_config,
        connected_clients,
        clients: info
            .clients
            .into_iter()
            .map(|client| VpnPortalClientInfo {
                name: client.name,
                virtual_ip: client.virtual_ip.to_string(),
                groups: client.groups,
                state: match client.state {
                    PortalClientState::Offline => VpnPortalClientState::Offline as i32,
                    PortalClientState::Connecting => VpnPortalClientState::Connecting as i32,
                    PortalClientState::Online => VpnPortalClientState::Online as i32,
                    PortalClientState::Error => VpnPortalClientState::Error as i32,
                },
                peer_id: client.peer_id,
                endpoint: client.endpoint,
                tunnel_ip: client.tunnel_ip.map(|address| address.to_string()),
                client_config: client.client_config,
                error: client.error,
            })
            .collect(),
        listener: info.listener,
    }
}

#[async_trait::async_trait]
impl<F, H> VpnPortalRpc for InstanceManagementRpc<F>
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
            vpn_portal_info: Some(vpn_portal_info_to_proto(info)),
        })
    }
}

#[async_trait::async_trait]
impl<F, H> AclManageRpc for InstanceManagementRpc<F>
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
impl<F, H> PortForwardManageRpc for InstanceManagementRpc<F>
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
impl<F, H> StatsRpc for InstanceManagementRpc<F>
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
impl<F, H> CredentialManageRpc for InstanceManagementRpc<F>
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
            expiry_unix: generated.expiry_unix,
        })
    }

    async fn upsert_credential(
        &self,
        _: BaseController,
        request: UpsertCredentialRequest,
    ) -> rpc_types::error::Result<UpsertCredentialResponse> {
        let changed = self
            .instance(request.instance.as_ref())?
            .upsert_credential(CredentialUpsertOptions {
                credential_id: request.credential_id,
                credential_secret: request.credential_secret,
                groups: request.groups,
                allow_relay: request.allow_relay,
                allowed_proxy_cidrs: request.allowed_proxy_cidrs,
                expiry_unix: request.expiry_unix,
                reusable: request.reusable.unwrap_or(true),
            })?;
        Ok(UpsertCredentialResponse { changed })
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
impl<F, H> PeerCenterRpc for InstanceManagementRpc<F>
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
        let instance = resolve_instance(self.manager(), None).map_err(|error| {
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::gateway::vpn_portal::PortalClientInfoSnapshot;

    #[test]
    #[allow(deprecated)]
    fn vpn_portal_info_to_proto_preserves_per_client_status() {
        let info = vpn_portal_info_to_proto(PortalInfoSnapshot {
            vpn_type: "wireguard".to_owned(),
            clients: vec![
                PortalClientInfoSnapshot {
                    name: "alice".to_owned(),
                    virtual_ip: Ipv4Addr::new(10, 82, 0, 2),
                    groups: vec!["ops".to_owned()],
                    state: PortalClientState::Online,
                    peer_id: Some(42),
                    endpoint: Some("198.51.100.2:51820".to_owned()),
                    tunnel_ip: Some(Ipv4Addr::new(10, 82, 0, 2)),
                    client_config: "[Interface]\nPrivateKey = secret\n".to_owned(),
                    error: None,
                },
                PortalClientInfoSnapshot {
                    name: "bob".to_owned(),
                    virtual_ip: Ipv4Addr::new(10, 82, 0, 3),
                    groups: vec!["guests".to_owned()],
                    state: PortalClientState::Error,
                    peer_id: None,
                    endpoint: None,
                    tunnel_ip: None,
                    client_config: String::new(),
                    error: Some("activation failed".to_owned()),
                },
            ],
            listener: Some("udp://0.0.0.0:51820".to_owned()),
        });

        assert_eq!(info.vpn_type, "wireguard");
        assert_eq!(info.listener.as_deref(), Some("udp://0.0.0.0:51820"));
        assert_eq!(info.client_config, "[Interface]\nPrivateKey = secret\n");
        assert_eq!(info.connected_clients, ["198.51.100.2:51820"]);
        assert_eq!(info.clients.len(), 2);

        let online = &info.clients[0];
        assert_eq!(online.name, "alice");
        assert_eq!(online.virtual_ip, "10.82.0.2");
        assert_eq!(online.groups, ["ops"]);
        assert_eq!(online.state, VpnPortalClientState::Online as i32);
        assert_eq!(online.peer_id, Some(42));
        assert_eq!(online.endpoint.as_deref(), Some("198.51.100.2:51820"));
        assert_eq!(online.tunnel_ip.as_deref(), Some("10.82.0.2"));
        assert_eq!(online.client_config, "[Interface]\nPrivateKey = secret\n");
        assert_eq!(online.error, None);

        let failed = &info.clients[1];
        assert_eq!(failed.name, "bob");
        assert_eq!(failed.state, VpnPortalClientState::Error as i32);
        assert_eq!(failed.peer_id, None);
        assert_eq!(failed.endpoint, None);
        assert_eq!(failed.tunnel_ip, None);
        assert_eq!(failed.error.as_deref(), Some("activation failed"));
    }
}
