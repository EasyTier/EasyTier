use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{extract::State, routing::get, Json, Router};
use dashmap::DashSet;
use easytier::proto::rpc_types::controller::BaseController;
use easytier::proto::{self, web::*};

use crate::client_manager::session::Session;
use crate::client_manager::ClientManager;

use super::users::AuthSession;
use super::{AppState, AppStateInner, Error, ErrorKind, HttpHandleError, RpcError};

fn convert_rpc_error(e: RpcError) -> (StatusCode, Json<Error>) {
    let status_code = match &e {
        RpcError::ExecutionError(_) => StatusCode::BAD_REQUEST,
        RpcError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    let error = Error::from(&e);
    (status_code, Json(error))
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ValidateConfigJsonReq {
    config: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RunNetworkJsonReq {
    config: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ColletNetworkInfoJsonReq {
    inst_ids: Option<Vec<uuid::Uuid>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoveNetworkJsonReq {
    inst_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListNetworkInstanceIdsJsonResp(Vec<uuid::Uuid>);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListMachineItem {
    client_url: Option<url::Url>,
    info: Option<HeartbeatRequest>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListMachineJsonResp {
    machines: Vec<ListMachineItem>,
}

pub struct NetworkApi {}

impl NetworkApi {
    pub fn new() -> Self {
        Self {}
    }

    async fn get_session_by_machine_id(
        auth_session: &AuthSession,
        client_mgr: &ClientManager,
        machine_id: &uuid::Uuid,
    ) -> Result<Arc<Session>, HttpHandleError> {
        let Some(result) = client_mgr.get_session_by_machine_id(machine_id) else {
            return Err((
                StatusCode::NOT_FOUND,
                Error {
                    error_kind: Some(ErrorKind::OtherError(proto::error::OtherError {
                        error_message: format!("No such session: {}", machine_id),
                    })),
                }
                .into(),
            ));
        };

        let Some(token) = result.get_token().await else {
            return Err((
                StatusCode::UNAUTHORIZED,
                Error {
                    error_kind: Some(ErrorKind::OtherError(proto::error::OtherError {
                        error_message: "No token reported".to_string(),
                    })),
                }
                .into(),
            ));
        };

        if !auth_session
            .user
            .as_ref()
            .map(|x| x.tokens.contains(&token.token))
            .unwrap_or(false)
        {
            return Err((
                StatusCode::FORBIDDEN,
                Error {
                    error_kind: Some(ErrorKind::OtherError(proto::error::OtherError {
                        error_message: "Token mismatch".to_string(),
                    })),
                }
                .into(),
            ));
        }

        Ok(result)
    }

    async fn handle_validate_config(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<ValidateConfigJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let config = payload.config;
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        c.validate_config(BaseController::default(), ValidateConfigRequest { config })
            .await
            .map_err(convert_rpc_error)?;
        Ok(())
    }

    async fn handle_run_network_instance(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<RunNetworkJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let config = payload.config;
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        c.run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest { config },
        )
        .await
        .map_err(convert_rpc_error)?;
        Ok(())
    }

    async fn handle_collect_one_network_info(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let ret = c
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: vec![inst_id.into()],
                },
            )
            .await
            .map_err(convert_rpc_error)?;
        Ok(ret.into())
    }

    async fn handle_collect_network_info(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Query(payload): Query<ColletNetworkInfoJsonReq>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let ret = c
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: payload
                        .inst_ids
                        .unwrap_or_default()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                },
            )
            .await
            .map_err(convert_rpc_error)?;
        Ok(ret.into())
    }

    async fn handle_list_network_instance_ids(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
    ) -> Result<Json<ListNetworkInstanceIdsJsonResp>, HttpHandleError> {
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let ret = c
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await
            .map_err(convert_rpc_error)?;
        Ok(
            ListNetworkInstanceIdsJsonResp(ret.inst_ids.into_iter().map(Into::into).collect())
                .into(),
        )
    }

    async fn handle_remove_network_instance(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(), HttpHandleError> {
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        c.delete_network_instance(
            BaseController::default(),
            DeleteNetworkInstanceRequest {
                inst_ids: vec![inst_id.into()],
            },
        )
        .await
        .map_err(convert_rpc_error)?;
        Ok(())
    }

    async fn handle_list_machines(
        auth_session: AuthSession,
        State(client_mgr): AppState,
    ) -> Result<Json<ListMachineJsonResp>, HttpHandleError> {
        let tokens = auth_session
            .user
            .as_ref()
            .map(|x| x.tokens.clone())
            .unwrap_or_default();

        let client_urls = DashSet::new();
        for token in tokens {
            let urls = client_mgr.list_machine_by_token(token);
            for url in urls {
                client_urls.insert(url);
            }
        }

        let mut machines = vec![];
        for item in client_urls.iter() {
            let client_url = item.key().clone();
            let session = client_mgr.get_heartbeat_requests(&client_url).await;
            machines.push(ListMachineItem {
                client_url: Some(client_url),
                info: session,
            });
        }

        Ok(Json(ListMachineJsonResp { machines }))
    }

    pub fn build_route(&mut self) -> Router<AppStateInner> {
        Router::new()
            .route("/api/v1/machines", get(Self::handle_list_machines))
            .route(
                "/api/v1/machines/:machine-id/validate-config",
                post(Self::handle_validate_config),
            )
            .route(
                "/api/v1/machines/:machine-id/networks",
                post(Self::handle_run_network_instance).get(Self::handle_list_network_instance_ids),
            )
            .route(
                "/api/v1/machines/:machine-id/networks/:inst-id",
                delete(Self::handle_remove_network_instance),
            )
            .route(
                "/api/v1/machines/:machine-id/networks/info",
                get(Self::handle_collect_network_info),
            )
            .route(
                "/api/v1/machines/:machine-id/networks/info/:inst-id",
                get(Self::handle_collect_one_network_info),
            )
    }
}
