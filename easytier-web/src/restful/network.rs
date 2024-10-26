use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{extract::State, routing::get, Json, Router};
use easytier::proto::rpc_types::controller::BaseController;
use easytier::proto::{self, web::*};

use crate::client_manager::session::Session;
use crate::client_manager::ClientManager;

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

pub struct NetworkApi {}

impl NetworkApi {
    pub fn new() -> Self {
        Self {}
    }

    async fn get_session_by_machine_id(
        client_mgr: &ClientManager,
        machine_id: &uuid::Uuid,
    ) -> Result<Arc<Session>, HttpHandleError> {
        let Some(result) = client_mgr.get_session_by_machine_id(machine_id) else {
            return Err((
                StatusCode::NOT_FOUND,
                Error {
                    error_kind: Some(ErrorKind::OtherError(proto::error::OtherError {
                        error_message: "No such session".to_string(),
                    })),
                }
                .into(),
            ));
        };

        Ok(result)
    }

    async fn handle_validate_config(
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<ValidateConfigJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let config = payload.config;
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        c.validate_config(BaseController::default(), ValidateConfigRequest { config })
            .await
            .map_err(convert_rpc_error)?;
        Ok(())
    }

    async fn handle_run_network_instance(
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<RunNetworkJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let config = payload.config;
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

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
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

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
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Query(payload): Query<ColletNetworkInfoJsonReq>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

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
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
    ) -> Result<Json<ListNetworkInstanceIdsJsonResp>, HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

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
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(), HttpHandleError> {
        let result = Self::get_session_by_machine_id(&client_mgr, &machine_id).await?;

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

    pub fn build_route(&mut self) -> Router<AppStateInner> {
        Router::new()
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
