use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{extract::State, routing::get, Json, Router};
use axum_login::AuthUser;
use dashmap::DashSet;
use easytier::launcher::NetworkConfig;
use easytier::proto::common::Void;
use easytier::proto::rpc_types::controller::BaseController;
use easytier::proto::web::*;

use crate::client_manager::session::Session;
use crate::client_manager::ClientManager;

use super::users::AuthSession;
use super::{
    convert_db_error, other_error, AppState, AppStateInner, Error, HttpHandleError, RpcError,
};

fn convert_rpc_error(e: RpcError) -> (StatusCode, Json<Error>) {
    let status_code = match &e {
        RpcError::ExecutionError(_) => StatusCode::BAD_REQUEST,
        RpcError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    let error = Error {
        message: format!("{:?}", e),
    };
    (status_code, Json(error))
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ValidateConfigJsonReq {
    config: NetworkConfig,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RunNetworkJsonReq {
    config: NetworkConfig,
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
                other_error(format!("No such session: {}", machine_id)).into(),
            ));
        };

        let Some(token) = result.get_token().await else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error(format!("No token reported")).into(),
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
                other_error(format!("Token mismatch")).into(),
            ));
        }

        Ok(result)
    }

    async fn handle_validate_config(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<ValidateConfigJsonReq>,
    ) -> Result<Json<ValidateConfigResponse>, HttpHandleError> {
        let config = payload.config;
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let ret = c
            .validate_config(
                BaseController::default(),
                ValidateConfigRequest {
                    config: Some(config),
                },
            )
            .await
            .map_err(convert_rpc_error)?;
        Ok(ret.into())
    }

    async fn handle_run_network_instance(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<RunNetworkJsonReq>,
    ) -> Result<Json<Void>, HttpHandleError> {
        let config = payload.config;
        let result =
            Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;

        let c = result.scoped_rpc_client();
        let resp = c
            .run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: None,
                    config: Some(config.clone()),
                },
            )
            .await
            .map_err(convert_rpc_error)?;

        client_mgr
            .db()
            .insert_or_update_user_network_config(
                auth_session.user.as_ref().unwrap().id(),
                machine_id,
                resp.inst_id.clone().unwrap_or_default().into(),
                serde_json::to_string(&config).unwrap(),
            )
            .await
            .map_err(convert_db_error)?;

        Ok(Void::default().into())
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

        client_mgr
            .db()
            .delete_network_config(auth_session.user.as_ref().unwrap().id(), inst_id)
            .await
            .map_err(convert_db_error)?;

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
            let urls = client_mgr.list_machine_by_token(token).await;
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

    async fn handle_get_network_config(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<Json<NetworkConfig>, HttpHandleError> {
        let inst_id = inst_id.to_string();

        let db_row = client_mgr
            .db()
            .list_network_configs(auth_session.user.unwrap().id(), Some(machine_id), false)
            .await
            .map_err(convert_db_error)?
            .iter()
            .find(|x| x.network_instance_id == inst_id)
            .map(|x| x.network_config.clone())
            .ok_or((
                StatusCode::NOT_FOUND,
                other_error(format!("No such network instance: {}", inst_id)).into(),
            ))?;

        Ok(serde_json::from_str::<NetworkConfig>(&db_row)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    other_error(format!("Failed to parse network config: {:?}", e)).into(),
                )
            })?
            .into())
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
            .route(
                "/api/v1/machines/:machine-id/networks/config/:inst-id",
                get(Self::handle_get_network_config),
            )
    }
}
