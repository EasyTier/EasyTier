use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use axum_login::AuthUser as _;

use super::{other_error, AppState, HttpHandleError};

#[derive(Debug, serde::Deserialize)]
pub struct ProxyRpcRequest {
    pub service_name: String,
    pub method_name: String,
    pub payload: serde_json::Value,
}

macro_rules! match_service {
    ($factory:ty, $method_name:expr, $payload:expr, $session:expr) => {{
        let client = $session.scoped_client::<$factory>();
        client
            .json_call_method(
                easytier::proto::rpc_types::controller::BaseController::default(),
                &$method_name,
                $payload,
            )
            .await
    }};
}

pub async fn handle_proxy_rpc(
    auth_session: super::users::AuthSession,
    State(client_mgr): AppState,
    Path(machine_id): Path<uuid::Uuid>,
    Json(req): Json<ProxyRpcRequest>,
) -> Result<Json<serde_json::Value>, HttpHandleError> {
    let user_id = auth_session
        .user
        .as_ref()
        .ok_or((StatusCode::UNAUTHORIZED, other_error("Unauthorized").into()))?
        .id();

    let session = client_mgr
        .get_session_by_machine_id(user_id, &machine_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            other_error("Session not found").into(),
        ))?;

    let ProxyRpcRequest {
        service_name,
        method_name,
        payload,
    } = req;

    let resp = match service_name.as_str() {
        "api.manage.WebClientService" => match_service!(
            easytier::proto::api::manage::WebClientServiceClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.PeerManageRpcService" => match_service!(
            easytier::proto::api::instance::PeerManageRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.ConnectorManageRpcService" => match_service!(
            easytier::proto::api::instance::ConnectorManageRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.MappedListenerManageRpcService" => match_service!(
            easytier::proto::api::instance::MappedListenerManageRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.VpnPortalRpcService" => match_service!(
            easytier::proto::api::instance::VpnPortalRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.TcpProxyRpcService" => match_service!(
            easytier::proto::api::instance::TcpProxyRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.AclManageRpcService" => match_service!(
            easytier::proto::api::instance::AclManageRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.PortForwardManageRpcService" => match_service!(
            easytier::proto::api::instance::PortForwardManageRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.StatsRpcService" => match_service!(
            easytier::proto::api::instance::StatsRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.instance.CredentialManageRpcService" => match_service!(
            easytier::proto::api::instance::CredentialManageRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.logger.LoggerRpcService" => match_service!(
            easytier::proto::api::logger::LoggerRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        "api.config.ConfigRpcService" => match_service!(
            easytier::proto::api::config::ConfigRpcClientFactory<
                easytier::proto::rpc_types::controller::BaseController,
            >,
            method_name,
            payload,
            session
        ),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                other_error(format!("Unknown service: {}", service_name)).into(),
            ))
        }
    };

    match resp {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            other_error(format!("RPC Error: {:?}", e)).into(),
        )),
    }
}

pub fn router() -> Router<super::AppStateInner> {
    Router::new().route(
        "/api/v1/machines/:machine-id/proxy-rpc",
        post(handle_proxy_rpc),
    )
}
