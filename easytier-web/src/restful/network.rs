use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{extract::State, routing::get, Json, Router};
use axum_login::AuthUser;
use easytier::launcher::NetworkConfig;
use easytier::proto::common::Void;
use easytier::proto::rpc_types::controller::BaseController;
use easytier::proto::{self, api::manage::*, web::*};

use crate::client_manager::session::{Location, Session};
use crate::client_manager::ClientManager;
use crate::db::{ListNetworkProps, UserIdInDb};

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
struct UpdateNetworkStateJsonReq {
    disabled: bool,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoveNetworkJsonReq {
    inst_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListNetworkInstanceIdsJsonResp {
    running_inst_ids: Vec<easytier::proto::common::Uuid>,
    disabled_inst_ids: Vec<easytier::proto::common::Uuid>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListMachineItem {
    client_url: Option<url::Url>,
    info: Option<HeartbeatRequest>,
    location: Option<Location>,
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

    fn get_user_id(auth_session: &AuthSession) -> Result<UserIdInDb, (StatusCode, Json<Error>)> {
        let Some(user_id) = auth_session.user.as_ref().map(|x| x.id()) else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("No user id found".to_string()).into(),
            ));
        };
        Ok(user_id)
    }

    async fn get_session_by_machine_id(
        auth_session: &AuthSession,
        client_mgr: &ClientManager,
        machine_id: &uuid::Uuid,
    ) -> Result<Arc<Session>, HttpHandleError> {
        let user_id = Self::get_user_id(auth_session)?;

        let Some(result) = client_mgr.get_session_by_machine_id(user_id, machine_id) else {
            return Err((
                StatusCode::NOT_FOUND,
                other_error(format!("No such session: {}", machine_id)).into(),
            ));
        };

        let Some(token) = result.get_token().await else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("No token reported".to_string()).into(),
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
                other_error("Token mismatch".to_string()).into(),
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
                resp.inst_id.unwrap_or_default().into(),
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
        Json(payload): Json<ColletNetworkInfoJsonReq>,
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

        let running_inst_ids = ret.inst_ids.clone().into_iter().collect();

        // collect networks that are disabled
        let disabled_inst_ids = client_mgr
            .db()
            .list_network_configs(
                auth_session.user.unwrap().id(),
                Some(machine_id),
                ListNetworkProps::DisabledOnly,
            )
            .await
            .map_err(convert_db_error)?
            .iter()
            .map(|x| Into::<proto::common::Uuid>::into(x.network_instance_id.clone()))
            .collect::<Vec<_>>();

        Ok(ListNetworkInstanceIdsJsonResp {
            running_inst_ids,
            disabled_inst_ids,
        }
        .into())
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
        let user_id = Self::get_user_id(&auth_session)?;

        let client_urls = client_mgr.list_machine_by_user_id(user_id).await;

        let mut machines = vec![];
        for item in client_urls.iter() {
            let client_url = item.clone();
            let session = client_mgr.get_heartbeat_requests(&client_url).await;
            let location = client_mgr.get_machine_location(&client_url).await;
            machines.push(ListMachineItem {
                client_url: Some(client_url),
                info: session,
                location,
            });
        }

        Ok(Json(ListMachineJsonResp { machines }))
    }

    async fn handle_update_network_state(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, Option<uuid::Uuid>)>,
        Json(payload): Json<UpdateNetworkStateJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let Some(inst_id) = inst_id else {
            // not implement disable all
            return Err((
                StatusCode::NOT_IMPLEMENTED,
                other_error("Not implemented".to_string()).into(),
            ));
        };

        let sess = Self::get_session_by_machine_id(&auth_session, &client_mgr, &machine_id).await?;
        let cfg = client_mgr
            .db()
            .update_network_config_state(auth_session.user.unwrap().id(), inst_id, payload.disabled)
            .await
            .map_err(convert_db_error)?;

        let c = sess.scoped_rpc_client();

        if payload.disabled {
            c.delete_network_instance(
                BaseController::default(),
                DeleteNetworkInstanceRequest {
                    inst_ids: vec![inst_id.into()],
                },
            )
            .await
            .map_err(convert_rpc_error)?;
        } else {
            c.run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: Some(inst_id.into()),
                    config: Some(serde_json::from_str(&cfg.network_config).unwrap()),
                },
            )
            .await
            .map_err(convert_rpc_error)?;
        }

        Ok(())
    }

    async fn handle_get_network_config(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<Json<NetworkConfig>, HttpHandleError> {
        let inst_id = inst_id.to_string();

        let db_row = client_mgr
            .db()
            .get_network_config(auth_session.user.unwrap().id(), &machine_id, &inst_id)
            .await
            .map_err(convert_db_error)?
            .ok_or((
                StatusCode::NOT_FOUND,
                other_error(format!("No such network instance: {}", inst_id)).into(),
            ))?;

        Ok(
            serde_json::from_str::<NetworkConfig>(&db_row.network_config)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        other_error(format!("Failed to parse network config: {:?}", e)).into(),
                    )
                })?
                .into(),
        )
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
                delete(Self::handle_remove_network_instance).put(Self::handle_update_network_state),
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
