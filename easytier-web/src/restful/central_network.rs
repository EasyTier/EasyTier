use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    routing::{delete, get, patch},
};
use uuid::Uuid;

use super::{AppStateInner, Error, HttpHandleError, authed_user_id, users::AuthSession};
use crate::central_network::{
    model::AclPolicy,
    service::{
        AddMembersReq, CentralNetworkService, CentralNetworkServiceError, GenerateCredentialReq,
        MemberInfo, MembersView, NetworkCredentialInfo, NetworkDetail, NetworkSettings,
        NetworkSummary, UpdateMemberReq, UpdateNetworkReq,
    },
};

type Service = Extension<Arc<CentralNetworkService>>;

pub(super) fn convert_error(error: CentralNetworkServiceError) -> HttpHandleError {
    let status = match error {
        CentralNetworkServiceError::Invalid(_) => StatusCode::BAD_REQUEST,
        CentralNetworkServiceError::NotFound(_) => StatusCode::NOT_FOUND,
        CentralNetworkServiceError::Conflict(_) => StatusCode::CONFLICT,
        CentralNetworkServiceError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(Error {
            message: error.to_string(),
            code: None,
            current_config_revision: None,
        }),
    )
}

fn user_id(auth_session: &AuthSession) -> Result<i32, HttpHandleError> {
    authed_user_id(auth_session)
}

#[derive(Debug, serde::Deserialize)]
struct CreateNetworkJsonReq {
    settings: NetworkSettings,
    network_secret: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ListNetworksJsonResp {
    networks: Vec<NetworkSummary>,
}

#[derive(Debug, serde::Serialize)]
struct ListCredentialsJsonResp {
    credentials: Vec<NetworkCredentialInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct SetMemberConfigJsonReq {
    config: easytier::common::config::NetworkConfig,
}

#[derive(Debug, serde::Serialize)]
struct AclPolicyInfo {
    policy: AclPolicy,
}

#[derive(Debug, serde::Serialize)]
struct GatewayInfoJsonResp {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_url: Option<String>,
    relay_data: bool,
}

pub struct CentralNetworkApi;

impl CentralNetworkApi {
    async fn list_networks(
        auth: AuthSession,
        Extension(service): Service,
    ) -> Result<Json<ListNetworksJsonResp>, HttpHandleError> {
        let networks = service
            .list_networks(user_id(&auth)?)
            .await
            .map_err(convert_error)?;
        Ok(Json(ListNetworksJsonResp { networks }))
    }

    async fn create_network(
        auth: AuthSession,
        Extension(service): Service,
        Json(request): Json<CreateNetworkJsonReq>,
    ) -> Result<Json<NetworkDetail>, HttpHandleError> {
        service
            .create_network(user_id(&auth)?, request.settings, request.network_secret)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn get_network(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
    ) -> Result<Json<NetworkDetail>, HttpHandleError> {
        service
            .get_network(user_id(&auth)?, network_id)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn update_network(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
        Json(request): Json<UpdateNetworkReq>,
    ) -> Result<Json<NetworkDetail>, HttpHandleError> {
        service
            .update_network(user_id(&auth)?, network_id, request)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn delete_network(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
    ) -> Result<StatusCode, HttpHandleError> {
        service
            .delete_network(user_id(&auth)?, network_id)
            .await
            .map_err(convert_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn list_members(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
    ) -> Result<Json<MembersView>, HttpHandleError> {
        service
            .list_members(user_id(&auth)?, network_id)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn add_members(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
        Json(request): Json<AddMembersReq>,
    ) -> Result<StatusCode, HttpHandleError> {
        service
            .add_members(user_id(&auth)?, network_id, request)
            .await
            .map_err(convert_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn update_member(
        auth: AuthSession,
        Extension(service): Service,
        Path((network_id, device_id)): Path<(Uuid, Uuid)>,
        Json(request): Json<UpdateMemberReq>,
    ) -> Result<Json<MemberInfo>, HttpHandleError> {
        service
            .update_member(user_id(&auth)?, network_id, device_id, request)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn remove_member(
        auth: AuthSession,
        Extension(service): Service,
        Path((network_id, device_id)): Path<(Uuid, Uuid)>,
    ) -> Result<StatusCode, HttpHandleError> {
        service
            .remove_member(user_id(&auth)?, network_id, device_id)
            .await
            .map_err(convert_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn get_member_config(
        auth: AuthSession,
        Extension(service): Service,
        Path((network_id, device_id)): Path<(Uuid, Uuid)>,
    ) -> Result<Json<easytier::common::config::NetworkConfig>, HttpHandleError> {
        service
            .get_member_config(user_id(&auth)?, network_id, device_id)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn set_member_config(
        auth: AuthSession,
        Extension(service): Service,
        Path((network_id, device_id)): Path<(Uuid, Uuid)>,
        Json(request): Json<SetMemberConfigJsonReq>,
    ) -> Result<Json<MemberInfo>, HttpHandleError> {
        service
            .set_member_config(user_id(&auth)?, network_id, device_id, request.config)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn clear_member_config(
        auth: AuthSession,
        Extension(service): Service,
        Path((network_id, device_id)): Path<(Uuid, Uuid)>,
    ) -> Result<StatusCode, HttpHandleError> {
        service
            .clear_member_config(user_id(&auth)?, network_id, device_id)
            .await
            .map_err(convert_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn get_acl_policy(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
    ) -> Result<Json<AclPolicyInfo>, HttpHandleError> {
        let policy = service
            .get_acl_policy(user_id(&auth)?, network_id)
            .await
            .map_err(convert_error)?;
        Ok(Json(AclPolicyInfo { policy }))
    }

    async fn update_acl_policy(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
        Json(policy): Json<AclPolicy>,
    ) -> Result<Json<AclPolicyInfo>, HttpHandleError> {
        let policy = service
            .update_acl_policy(user_id(&auth)?, network_id, policy)
            .await
            .map_err(convert_error)?;
        Ok(Json(AclPolicyInfo { policy }))
    }

    async fn list_credentials(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
    ) -> Result<Json<ListCredentialsJsonResp>, HttpHandleError> {
        let credentials = service
            .list_credentials(user_id(&auth)?, network_id)
            .await
            .map_err(convert_error)?;
        Ok(Json(ListCredentialsJsonResp { credentials }))
    }

    async fn generate_credential(
        auth: AuthSession,
        Extension(service): Service,
        Path(network_id): Path<Uuid>,
        Json(request): Json<GenerateCredentialReq>,
    ) -> Result<Json<NetworkCredentialInfo>, HttpHandleError> {
        service
            .generate_credential(user_id(&auth)?, network_id, request)
            .await
            .map(Json)
            .map_err(convert_error)
    }

    async fn revoke_credential(
        auth: AuthSession,
        Extension(service): Service,
        Path((network_id, credential_id)): Path<(Uuid, String)>,
    ) -> Result<StatusCode, HttpHandleError> {
        service
            .revoke_credential(user_id(&auth)?, network_id, &credential_id)
            .await
            .map_err(convert_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn gateway_info(Extension(service): Service) -> Json<GatewayInfoJsonResp> {
        let config = service.gateway_config();
        Json(GatewayInfoJsonResp {
            enabled: config.is_some(),
            peer_url: config.map(|config| config.peer_url.clone()),
            relay_data: config.is_some_and(|config| config.relay_data),
        })
    }

    pub fn build_route() -> Router<AppStateInner> {
        Router::new()
            .route(
                "/api/v1/networks",
                get(Self::list_networks).post(Self::create_network),
            )
            .route("/api/v1/networks/gateway-info", get(Self::gateway_info))
            .route(
                "/api/v1/networks/{network-id}",
                get(Self::get_network)
                    .patch(Self::update_network)
                    .delete(Self::delete_network),
            )
            .route(
                "/api/v1/networks/{network-id}/acl-policy",
                get(Self::get_acl_policy).put(Self::update_acl_policy),
            )
            .route(
                "/api/v1/networks/{network-id}/members",
                get(Self::list_members).post(Self::add_members),
            )
            .route(
                "/api/v1/networks/{network-id}/members/{device-id}",
                patch(Self::update_member).delete(Self::remove_member),
            )
            .route(
                "/api/v1/networks/{network-id}/members/{device-id}/config",
                get(Self::get_member_config)
                    .put(Self::set_member_config)
                    .delete(Self::clear_member_config),
            )
            .route(
                "/api/v1/networks/{network-id}/credentials",
                get(Self::list_credentials).post(Self::generate_credential),
            )
            .route(
                "/api/v1/networks/{network-id}/credentials/{credential-id}",
                delete(Self::revoke_credential),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_errors_map_to_stable_http_statuses() {
        assert_eq!(
            convert_error(CentralNetworkServiceError::Invalid("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            convert_error(CentralNetworkServiceError::NotFound("x".into())).0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            convert_error(CentralNetworkServiceError::Conflict("x".into())).0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            convert_error(CentralNetworkServiceError::Database("x".into())).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn gateway_info_is_disabled_without_runtime_lifecycle() {
        let db = crate::db::Db::memory_db().await;
        let manager = Arc::new(crate::client_manager::ClientManager::new(
            db.clone(),
            None,
            crate::client_manager::HeartbeatPolicy::default(),
            Arc::new(crate::FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        ));
        let service = Arc::new(CentralNetworkService::new(db, manager));
        let Json(info) = CentralNetworkApi::gateway_info(Extension(service)).await;
        assert!(!info.enabled);
        assert_eq!(info.peer_url, None);
        assert!(!info.relay_data);
    }

    #[tokio::test]
    async fn gateway_info_exposes_enabled_runtime_configuration() {
        let db = crate::db::Db::memory_db().await;
        let instances = Arc::new(
            crate::central_network::gateway::NetworkInstanceManager::new(
                crate::central_network::gateway::GatewayConfig {
                    peer_url: "tcp://gateway.example:22020".to_owned(),
                    relay_data: true,
                },
            ),
        );
        let manager = Arc::new(crate::client_manager::ClientManager::new(
            db.clone(),
            None,
            crate::client_manager::HeartbeatPolicy::default(),
            Arc::new(crate::FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        ));
        let service = Arc::new(CentralNetworkService::with_gateway(
            db,
            manager,
            Some(instances),
        ));

        let Json(info) = CentralNetworkApi::gateway_info(Extension(service)).await;

        assert!(info.enabled);
        assert_eq!(
            info.peer_url.as_deref(),
            Some("tcp://gateway.example:22020")
        );
        assert!(info.relay_data);
    }
}
