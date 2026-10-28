use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use axum_login::AuthUser as _;
use easytier::proto::{
    api::{
        config::{ConfigRpc, GetConfigRequest, PatchConfigRequest},
        instance::{
            GenerateCredentialRequest, InstanceIdentifier, RevokeCredentialRequest,
            UpsertCredentialRequest, instance_identifier,
        },
        manage::{
            DeleteNetworkInstanceRequest, RetainNetworkInstanceRequest, RunNetworkInstanceRequest,
        },
    },
    rpc_types::controller::BaseController,
};

use crate::{
    central_network::service::CentralNetworkService,
    db::{CentralOwnedRuntimeConfig, UserIdInDb},
};

use super::{AppState, HttpHandleError, other_error};

#[derive(Debug, serde::Deserialize)]
pub struct ProxyRpcRequest {
    pub service_name: String,
    pub method_name: String,
    pub payload: serde_json::Value,
    pub scope: Option<String>,
}

macro_rules! match_service {
    ($factory:ty, $method_name:expr, $payload:expr, $session:expr) => {{
        let client = $session.scoped_client::<$factory>();
        client
            .json_call_method(BaseController::default(), &$method_name, $payload)
            .await
    }};
}

async fn handle_proxy_rpc_by_session(
    session: &crate::client_manager::session::Session,
    req: ProxyRpcRequest,
) -> Result<Json<serde_json::Value>, HttpHandleError> {
    let ProxyRpcRequest {
        service_name,
        method_name,
        payload,
        scope,
    } = req;

    let mutates_runtime_config = proxy_rpc_mutates_runtime_config(&service_name, &method_name);
    if mutates_runtime_config {
        session
            .invalidate_runtime_config_for_direct_mutation()
            .await;
    }

    let resp = match service_name.as_str() {
        "api.manage.WebClientService" => match_service!(
            easytier::proto::api::manage::WebClientServiceClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.PeerManageRpcService" => match_service!(
            easytier::proto::api::instance::PeerManageRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.PeerCenterManageRpcService" => match_service!(
            easytier::proto::peer_rpc::PeerCenterRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.ConnectorManageRpcService" => match_service!(
            easytier::proto::api::instance::ConnectorManageRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.MappedListenerManageRpcService" => match_service!(
            easytier::proto::api::instance::MappedListenerManageRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.VpnPortalRpcService" => match_service!(
            easytier::proto::api::instance::VpnPortalRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.TcpProxyRpcService" => {
            let client = if let Some(ref domain) = scope {
                session.scoped_client_with_domain::<
                    easytier::proto::api::instance::TcpProxyRpcClientFactory<BaseController>,
                >(domain.clone())
            } else {
                session.scoped_client::<
                    easytier::proto::api::instance::TcpProxyRpcClientFactory<BaseController>,
                >()
            };
            client
                .json_call_method(BaseController::default(), &method_name, payload)
                .await
        }
        "api.instance.AclManageRpcService" => match_service!(
            easytier::proto::api::instance::AclManageRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.PortForwardManageRpcService" => match_service!(
            easytier::proto::api::instance::PortForwardManageRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.StatsRpcService" => match_service!(
            easytier::proto::api::instance::StatsRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.instance.CredentialManageRpcService" => match_service!(
            easytier::proto::api::instance::CredentialManageRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.logger.LoggerRpcService" => match_service!(
            easytier::proto::api::logger::LoggerRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        "api.config.ConfigRpcService" => match_service!(
            easytier::proto::api::config::ConfigRpcClientFactory<BaseController>,
            method_name,
            payload,
            session
        ),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                other_error(format!("Unknown service: {}", service_name)).into(),
            ));
        }
    };

    if mutates_runtime_config {
        session
            .invalidate_runtime_config_for_direct_mutation()
            .await;
    }

    match resp {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            other_error(format!("RPC Error: {:?}", e)).into(),
        )),
    }
}

async fn ensure_instance_mutation_allowed(
    req: &mut ProxyRpcRequest,
    central: &[CentralOwnedRuntimeConfig],
    client: &mut (impl ConfigRpc<Controller = BaseController> + Send + ?Sized),
) -> Result<(), HttpHandleError> {
    if central.is_empty() {
        return Ok(());
    }
    let instance = match req.method_name.as_str() {
        "generate_credential" | "GenerateCredential" => {
            serde_json::from_value::<GenerateCredentialRequest>(req.payload.clone())
                .map(|request| request.instance)
        }
        "revoke_credential" | "RevokeCredential" => {
            serde_json::from_value::<RevokeCredentialRequest>(req.payload.clone())
                .map(|request| request.instance)
        }
        "upsert_credential" | "UpsertCredential" => {
            serde_json::from_value::<UpsertCredentialRequest>(req.payload.clone())
                .map(|request| request.instance)
        }
        "patch_config" | "PatchConfig" => {
            serde_json::from_value::<PatchConfigRequest>(req.payload.clone())
                .map(|request| request.instance)
        }
        _ => return Ok(()),
    }
    .map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            other_error(format!("Invalid RPC payload: {error}")).into(),
        )
    })?;
    let instance_id = match instance
        .as_ref()
        .and_then(|instance| instance.selector.as_ref())
    {
        Some(instance_identifier::Selector::Id(id)) => uuid::Uuid::from(*id),
        Some(instance_identifier::Selector::InstanceSelector(selector))
            if selector.name.is_some() =>
        {
            // Resolve names on the same session that receives the mutation:
            // the desired network name may differ from the running instance.
            let response = client
                .get_config(BaseController::default(), GetConfigRequest { instance })
                .await
                .map_err(|error| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        other_error(format!("RPC Error: {error:?}")).into(),
                    )
                })?;
            response
                .config
                .and_then(|config| config.instance_id)
                .and_then(|id| id.parse::<uuid::Uuid>().ok())
                .ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        other_error("RPC returned no valid instance ID").into(),
                    )
                })?
        }
        _ => return Err(super::network::central_ownership_conflict()),
    };
    if central
        .iter()
        .any(|config| config.instance_id == instance_id)
    {
        return Err(super::network::central_ownership_conflict());
    }
    // Pin the authorized instance so a concurrent rename cannot retarget it.
    req.payload["instance"] = serde_json::json!(InstanceIdentifier {
        selector: Some(instance_identifier::Selector::Id(instance_id.into())),
    });
    Ok(())
}

async fn ensure_runtime_mutation_allowed(
    req: &mut ProxyRpcRequest,
    central: &[CentralOwnedRuntimeConfig],
    client: &mut (impl ConfigRpc<Controller = BaseController> + Send + ?Sized),
) -> Result<(), HttpHandleError> {
    if central.is_empty() {
        return Ok(());
    }
    if req.service_name == "api.instance.CredentialManageRpcService" {
        return ensure_instance_mutation_allowed(req, central, client).await;
    }
    fn parse<T: serde::de::DeserializeOwned>(req: &ProxyRpcRequest) -> Result<T, HttpHandleError> {
        serde_json::from_value(req.payload.clone()).map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                other_error(format!("Invalid RPC payload: {error}")).into(),
            )
        })
    }
    let conflicts = match (req.service_name.as_str(), req.method_name.as_str()) {
        ("api.manage.WebClientService", "run_network_instance" | "RunNetworkInstance") => {
            let request: RunNetworkInstanceRequest = parse(req)?;
            central.iter().any(|config| {
                request
                    .inst_id
                    .is_some_and(|id| uuid::Uuid::from(id) == config.instance_id)
                    || request.config.as_ref().is_some_and(|requested| {
                        requested
                            .instance_id
                            .as_deref()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok())
                            == Some(config.instance_id)
                            || requested.network_name.as_deref()
                                == Some(config.network_name.as_str())
                    })
            })
        }
        ("api.manage.WebClientService", "retain_network_instance" | "RetainNetworkInstance") => {
            let request: RetainNetworkInstanceRequest = parse(req)?;
            central.iter().any(|config| {
                !request
                    .inst_ids
                    .iter()
                    .any(|id| uuid::Uuid::from(*id) == config.instance_id)
            })
        }
        ("api.manage.WebClientService", "delete_network_instance" | "DeleteNetworkInstance") => {
            let request: DeleteNetworkInstanceRequest = parse(req)?;
            central.iter().any(|config| {
                request
                    .inst_ids
                    .iter()
                    .any(|id| uuid::Uuid::from(*id) == config.instance_id)
            })
        }
        ("api.config.ConfigRpcService", "patch_config" | "PatchConfig") => {
            return ensure_instance_mutation_allowed(req, central, client).await;
        }
        _ => false,
    };
    if conflicts {
        return Err(super::network::central_ownership_conflict());
    }
    Ok(())
}

fn proxy_rpc_mutates_runtime_config(service_name: &str, method_name: &str) -> bool {
    matches!(
        (service_name, method_name),
        (
            "api.manage.WebClientService",
            "run_network_instance"
                | "RunNetworkInstance"
                | "retain_network_instance"
                | "RetainNetworkInstance"
                | "delete_network_instance"
                | "DeleteNetworkInstance"
        ) | (
            "api.config.ConfigRpcService",
            "patch_config" | "PatchConfig"
        ) | (
            "api.instance.CredentialManageRpcService",
            "generate_credential"
                | "GenerateCredential"
                | "revoke_credential"
                | "RevokeCredential"
                | "upsert_credential"
                | "UpsertCredential"
        )
    )
}

pub async fn handle_proxy_rpc(
    auth_session: super::users::AuthSession,
    State(client_mgr): AppState,
    Extension(network_service): Extension<Arc<CentralNetworkService>>,
    Path(machine_id): Path<uuid::Uuid>,
    Json(mut req): Json<ProxyRpcRequest>,
) -> Result<Json<serde_json::Value>, HttpHandleError> {
    let user_id = auth_session
        .user
        .as_ref()
        .ok_or((StatusCode::UNAUTHORIZED, other_error("Unauthorized").into()))?
        .id();

    let _mutation = if proxy_rpc_mutates_runtime_config(&req.service_name, &req.method_name) {
        Some(network_service.lock_mutations().await)
    } else {
        None
    };
    let session = client_mgr
        .get_session_by_machine_id(user_id, &machine_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            other_error("Session not found").into(),
        ))?;
    if _mutation.is_some() {
        let central = network_service
            .db
            .central_owned_runtime_configs(user_id, machine_id)
            .await
            .map_err(super::convert_db_error)?;
        ensure_runtime_mutation_allowed(
            &mut req,
            &central,
            session.scoped_config_client().as_mut(),
        )
        .await?;
    }
    handle_proxy_rpc_by_session(session.as_ref(), req).await
}

pub fn router() -> Router<super::AppStateInner> {
    Router::new().route(
        "/api/v1/machines/{machine-id}/proxy-rpc",
        post(handle_proxy_rpc),
    )
}

/// Internal proxy-rpc handler: no AuthSession, resolves the active session by machine_id.
pub async fn handle_proxy_rpc_internal(
    State(client_mgr): AppState,
    Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
    Json(req): Json<ProxyRpcRequest>,
) -> Result<Json<serde_json::Value>, HttpHandleError> {
    let session = client_mgr
        .get_session_by_machine_id(user_id, &machine_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            other_error("Session not found").into(),
        ))?;
    handle_proxy_rpc_by_session(session.as_ref(), req).await
}

pub fn router_internal() -> Router<super::AppStateInner> {
    Router::new().route(
        "/api/internal/users/{user-id}/machines/{machine-id}/proxy-rpc",
        post(handle_proxy_rpc_internal),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier::proto::api::config::{GetConfigResponse, PatchConfigResponse};

    #[derive(Default)]
    struct ConfigClient {
        instances: Vec<(&'static str, uuid::Uuid)>,
        requests: std::sync::Mutex<Vec<InstanceIdentifier>>,
    }

    #[async_trait::async_trait]
    impl ConfigRpc for ConfigClient {
        type Controller = BaseController;

        async fn get_config(
            &self,
            _: BaseController,
            request: GetConfigRequest,
        ) -> easytier::proto::rpc_types::error::Result<GetConfigResponse> {
            let instance = request.instance.unwrap();
            self.requests.lock().unwrap().push(instance.clone());
            let Some(instance_identifier::Selector::InstanceSelector(selector)) = instance.selector
            else {
                panic!("UUID and default selectors must not require a runtime read");
            };
            let id = self
                .instances
                .iter()
                .find(|(name, _)| Some(*name) == selector.name.as_deref())
                .map(|(_, id)| *id)
                .ok_or_else(|| anyhow::anyhow!("No instance matches the selector"))?;
            Ok(GetConfigResponse {
                config: Some(easytier::proto::api::manage::NetworkConfig {
                    instance_id: Some(id.to_string()),
                    // Instance selectors resolve instance_name, not network_name.
                    network_name: Some("different-network-name".into()),
                    ..Default::default()
                }),
                ..Default::default()
            })
        }

        async fn patch_config(
            &self,
            _: BaseController,
            _: PatchConfigRequest,
        ) -> easytier::proto::rpc_types::error::Result<PatchConfigResponse> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn config_proxy_mutations_cannot_overwrite_or_remove_central_instances() {
        let central_id = uuid::Uuid::new_v4();
        let other_id = uuid::Uuid::new_v4();
        let central = [CentralOwnedRuntimeConfig {
            instance_id: central_id,
            network_name: "central-network".into(),
        }];
        let cases = [
            (
                "RunNetworkInstance",
                serde_json::to_value(RunNetworkInstanceRequest {
                    inst_id: Some(central_id.into()),
                    ..Default::default()
                })
                .unwrap(),
                true,
            ),
            (
                "RunNetworkInstance",
                serde_json::to_value(RunNetworkInstanceRequest {
                    config: Some(easytier::proto::api::manage::NetworkConfig {
                        instance_id: Some(other_id.to_string()),
                        network_name: Some("central-network".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .unwrap(),
                true,
            ),
            (
                "RetainNetworkInstance",
                serde_json::to_value(RetainNetworkInstanceRequest {
                    inst_ids: vec![other_id.into()],
                })
                .unwrap(),
                true,
            ),
            (
                "RetainNetworkInstance",
                serde_json::to_value(RetainNetworkInstanceRequest {
                    inst_ids: vec![central_id.into()],
                })
                .unwrap(),
                false,
            ),
            (
                "DeleteNetworkInstance",
                serde_json::to_value(DeleteNetworkInstanceRequest {
                    inst_ids: vec![central_id.into()],
                })
                .unwrap(),
                true,
            ),
            (
                "DeleteNetworkInstance",
                serde_json::to_value(DeleteNetworkInstanceRequest {
                    inst_ids: vec![other_id.into()],
                })
                .unwrap(),
                false,
            ),
            (
                "PatchConfig",
                serde_json::to_value(PatchConfigRequest::default()).unwrap(),
                true,
            ),
            (
                "PatchConfig",
                serde_json::to_value(PatchConfigRequest {
                    instance: Some(InstanceIdentifier {
                        selector: Some(instance_identifier::Selector::Id(other_id.into())),
                    }),
                    ..Default::default()
                })
                .unwrap(),
                false,
            ),
        ];
        for (method, payload, conflicts) in cases {
            let mut request = ProxyRpcRequest {
                service_name: if method == "PatchConfig" {
                    "api.config.ConfigRpcService"
                } else {
                    "api.manage.WebClientService"
                }
                .into(),
                method_name: method.into(),
                payload,
                scope: None,
            };
            let result = ensure_runtime_mutation_allowed(
                &mut request,
                &central,
                &mut ConfigClient::default(),
            )
            .await;
            assert_eq!(result.is_err(), conflicts, "{method}");
            if let Err(error) = result {
                assert_eq!(error.0, StatusCode::CONFLICT);
            }
            ensure_runtime_mutation_allowed(&mut request, &[], &mut ConfigClient::default())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn credential_mutations_preserve_central_ownership_for_all_selectors() {
        let central_id = uuid::Uuid::new_v4();
        let central = [CentralOwnedRuntimeConfig {
            instance_id: central_id,
            network_name: "central-network".into(),
        }];
        let mut client = ConfigClient {
            instances: vec![
                ("central-network", central_id),
                ("console-network", uuid::Uuid::new_v4()),
            ],
            ..Default::default()
        };
        let by_id = |id: uuid::Uuid| InstanceIdentifier {
            selector: Some(instance_identifier::Selector::Id(id.into())),
        };
        let by_name = |name: Option<&str>| InstanceIdentifier {
            selector: Some(instance_identifier::Selector::InstanceSelector(
                instance_identifier::InstanceSelector {
                    name: name.map(str::to_owned),
                },
            )),
        };
        for (method, payload) in [
            (
                "GenerateCredential",
                serde_json::to_value(GenerateCredentialRequest::default()).unwrap(),
            ),
            (
                "UpsertCredential",
                serde_json::to_value(UpsertCredentialRequest::default()).unwrap(),
            ),
            (
                "RevokeCredential",
                serde_json::to_value(RevokeCredentialRequest::default()).unwrap(),
            ),
        ] {
            let snake_case = method.replace("Credential", "_credential").to_lowercase();
            for method in [method, snake_case.as_str()] {
                for (instance, conflicts) in [
                    (None, true),
                    (Some(InstanceIdentifier::default()), true),
                    (Some(by_name(None)), true),
                    (Some(by_id(central_id)), true),
                    (Some(by_name(Some("central-network"))), true),
                    (Some(by_id(uuid::Uuid::new_v4())), false),
                    (Some(by_name(Some("console-network"))), false),
                ] {
                    let mut req = ProxyRpcRequest {
                        service_name: "api.instance.CredentialManageRpcService".into(),
                        method_name: method.into(),
                        payload: payload.clone(),
                        scope: None,
                    };
                    req.payload["instance"] = serde_json::to_value(instance).unwrap();
                    let result =
                        ensure_runtime_mutation_allowed(&mut req, &central, &mut client).await;
                    if conflicts {
                        assert_eq!(result.unwrap_err().0, StatusCode::CONFLICT, "{method}");
                    } else {
                        result.unwrap();
                    }
                    // Devices with only external or manual configs remain unrestricted.
                    ensure_runtime_mutation_allowed(&mut req, &[], &mut client)
                        .await
                        .unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn named_mutations_resolve_pending_renames_and_forward_the_checked_id() {
        let central_id = uuid::Uuid::new_v4();
        let ordinary_id = uuid::Uuid::new_v4();
        let central = [CentralOwnedRuntimeConfig {
            instance_id: central_id,
            network_name: "central-new-name".into(),
        }];
        let mut client = ConfigClient {
            instances: vec![
                ("central-old-name", central_id),
                ("ordinary-instance", ordinary_id),
            ],
            ..Default::default()
        };
        for (service, method, payload) in [
            (
                "api.instance.CredentialManageRpcService",
                "GenerateCredential",
                serde_json::to_value(GenerateCredentialRequest::default()).unwrap(),
            ),
            (
                "api.instance.CredentialManageRpcService",
                "UpsertCredential",
                serde_json::to_value(UpsertCredentialRequest::default()).unwrap(),
            ),
            (
                "api.instance.CredentialManageRpcService",
                "RevokeCredential",
                serde_json::to_value(RevokeCredentialRequest::default()).unwrap(),
            ),
            (
                "api.config.ConfigRpcService",
                "PatchConfig",
                serde_json::to_value(PatchConfigRequest::default()).unwrap(),
            ),
        ] {
            let snake_case = method
                .replace("Credential", "_credential")
                .replace("Config", "_config")
                .to_lowercase();
            for method in [method, snake_case.as_str()] {
                for (name, expected_id) in [
                    ("central-old-name", None),
                    ("ordinary-instance", Some(ordinary_id)),
                ] {
                    let instance = InstanceIdentifier {
                        selector: Some(instance_identifier::Selector::InstanceSelector(
                            instance_identifier::InstanceSelector {
                                name: Some(name.into()),
                            },
                        )),
                    };
                    let mut req = ProxyRpcRequest {
                        service_name: service.into(),
                        method_name: method.into(),
                        payload: payload.clone(),
                        scope: None,
                    };
                    req.payload["instance"] = serde_json::to_value(&instance).unwrap();
                    let result =
                        ensure_runtime_mutation_allowed(&mut req, &central, &mut client).await;
                    assert_eq!(client.requests.lock().unwrap().last(), Some(&instance));
                    if let Some(expected_id) = expected_id {
                        result.unwrap();
                        // Forward the authorized UUID even if the runtime name changes
                        // again before the actual mutation is dispatched.
                        let forwarded: GetConfigRequest =
                            serde_json::from_value(req.payload).unwrap();
                        assert_eq!(
                            forwarded.instance.unwrap().selector,
                            Some(instance_identifier::Selector::Id(expected_id.into()))
                        );
                    } else {
                        assert_eq!(result.unwrap_err().0, StatusCode::CONFLICT, "{method}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn named_mutations_require_resolution_only_on_central_devices() {
        let central = [CentralOwnedRuntimeConfig {
            instance_id: uuid::Uuid::new_v4(),
            network_name: "central-network".into(),
        }];
        let mut client = ConfigClient::default();
        let mut request = ProxyRpcRequest {
            service_name: "api.config.ConfigRpcService".into(),
            method_name: "PatchConfig".into(),
            payload: serde_json::to_value(PatchConfigRequest {
                instance: Some(InstanceIdentifier {
                    selector: Some(instance_identifier::Selector::InstanceSelector(
                        instance_identifier::InstanceSelector {
                            name: Some("missing-instance".into()),
                        },
                    )),
                }),
                ..Default::default()
            })
            .unwrap(),
            scope: None,
        };
        let payload = request.payload.clone();
        ensure_runtime_mutation_allowed(&mut request, &[], &mut client)
            .await
            .unwrap();
        assert_eq!(request.payload, payload);
        assert!(client.requests.lock().unwrap().is_empty());

        assert_eq!(
            ensure_runtime_mutation_allowed(&mut request, &central, &mut client)
                .await
                .unwrap_err()
                .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(request.payload, payload);
    }

    #[test]
    fn runtime_config_mutation_detection_covers_proxy_rpc_aliases() {
        for (service, method) in [
            ("api.manage.WebClientService", "run_network_instance"),
            ("api.manage.WebClientService", "RetainNetworkInstance"),
            ("api.manage.WebClientService", "delete_network_instance"),
            ("api.config.ConfigRpcService", "PatchConfig"),
            (
                "api.instance.CredentialManageRpcService",
                "generate_credential",
            ),
            (
                "api.instance.CredentialManageRpcService",
                "RevokeCredential",
            ),
            (
                "api.instance.CredentialManageRpcService",
                "upsert_credential",
            ),
        ] {
            assert!(
                proxy_rpc_mutates_runtime_config(service, method),
                "{service}/{method} must invalidate the managed revision fence"
            );
        }

        for (service, method) in [
            ("api.manage.WebClientService", "list_network_instance"),
            ("api.config.ConfigRpcService", "get_config"),
            (
                "api.instance.CredentialManageRpcService",
                "list_credentials",
            ),
            ("api.instance.StatsRpcService", "get_stats"),
        ] {
            assert!(
                !proxy_rpc_mutates_runtime_config(service, method),
                "{service}/{method} must remain read-only"
            );
        }
    }
}
