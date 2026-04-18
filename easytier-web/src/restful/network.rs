use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router, extract::State, routing::get};
use axum_login::AuthUser;
use easytier::launcher::NetworkConfig;
use easytier::proto::common::Void;
use easytier::proto::{api::manage::*, web::*};
use easytier::rpc_service::remote_client::{
    GetNetworkMetasResponse, ListNetworkInstanceIdsJsonResp, RemoteClientError, RemoteClientManager,
};
use sea_orm::DbErr;

use crate::client_manager::session::Location;
use crate::db::UserIdInDb;

use super::users::AuthSession;
use super::{
    AppState, AppStateInner, Error, HttpHandleError, RpcError, convert_db_error, other_error,
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

fn convert_error(e: RemoteClientError<DbErr>) -> (StatusCode, Json<Error>) {
    match e {
        RemoteClientError::PersistentError(e) => convert_db_error(e),
        RemoteClientError::RpcError(e) => convert_rpc_error(e),
        RemoteClientError::ClientNotFound => (
            StatusCode::NOT_FOUND,
            other_error("Client not found").into(),
        ),
        RemoteClientError::NotFound(msg) => (StatusCode::NOT_FOUND, other_error(msg).into()),
        RemoteClientError::Other(msg) => {
            (StatusCode::INTERNAL_SERVER_ERROR, other_error(msg).into())
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ValidateConfigJsonReq {
    config: NetworkConfig,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SaveNetworkJsonReq {
    config: NetworkConfig,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RunNetworkJsonReq {
    config: NetworkConfig,
    save: bool,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct CollectNetworkInfoJsonReq {
    inst_ids: Option<Vec<uuid::Uuid>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct UpdateNetworkStateJsonReq {
    disabled: bool,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GetNetworkMetasJsonReq {
    instance_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoveNetworkJsonReq {
    inst_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListMachineItem {
    machine_id: uuid::Uuid,
    client_url: Option<url::Url>,
    info: Option<HeartbeatRequest>,
    location: Option<Location>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListMachineJsonResp {
    machines: Vec<ListMachineItem>,
}

pub struct NetworkApi;

impl NetworkApi {
    fn get_user_id(auth_session: &AuthSession) -> Result<UserIdInDb, (StatusCode, Json<Error>)> {
        let Some(user_id) = auth_session.user.as_ref().map(|x| x.id()) else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("No user id found".to_string()).into(),
            ));
        };
        Ok(user_id)
    }

    async fn handle_validate_config(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<ValidateConfigJsonReq>,
    ) -> Result<Json<ValidateConfigResponse>, HttpHandleError> {
        Ok(client_mgr
            .handle_validate_config(
                (Self::get_user_id(&auth_session)?, machine_id),
                payload.config,
            )
            .await
            .map_err(convert_error)?
            .into())
    }

    async fn handle_run_network_instance(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<RunNetworkJsonReq>,
    ) -> Result<Json<Void>, HttpHandleError> {
        client_mgr
            .handle_run_network_instance(
                (Self::get_user_id(&auth_session)?, machine_id),
                payload.config,
                payload.save,
            )
            .await
            .map_err(convert_error)?;
        Ok(Void::default().into())
    }

    async fn handle_collect_one_network_info(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        Ok(client_mgr
            .handle_collect_network_info(
                (Self::get_user_id(&auth_session)?, machine_id),
                Some(vec![inst_id]),
            )
            .await
            .map_err(convert_error)?
            .into())
    }

    async fn handle_collect_network_info(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<CollectNetworkInfoJsonReq>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        Ok(client_mgr
            .handle_collect_network_info(
                (Self::get_user_id(&auth_session)?, machine_id),
                payload.inst_ids,
            )
            .await
            .map_err(convert_error)?
            .into())
    }

    async fn handle_list_network_instance_ids(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
    ) -> Result<Json<ListNetworkInstanceIdsJsonResp>, HttpHandleError> {
        Ok(client_mgr
            .handle_list_network_instance_ids((Self::get_user_id(&auth_session)?, machine_id))
            .await
            .map_err(convert_error)?
            .into())
    }

    async fn handle_remove_network_instance(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(), HttpHandleError> {
        client_mgr
            .handle_remove_network_instances(
                (Self::get_user_id(&auth_session)?, machine_id),
                vec![inst_id],
            )
            .await
            .map_err(convert_error)
    }

    async fn handle_list_machines(
        auth_session: AuthSession,
        State(client_mgr): AppState,
    ) -> Result<Json<ListMachineJsonResp>, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;

        let machine_tokens = client_mgr.list_machine_tokens_by_user_id(user_id).await;

        let mut machines = vec![];
        for token in machine_tokens.iter() {
            let client_url = token.client_url.clone();
            let session = client_mgr.get_heartbeat_requests(&client_url).await;
            let location = client_mgr.get_machine_location(&client_url).await;
            machines.push(ListMachineItem {
                machine_id: token.machine_id,
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

        client_mgr
            .handle_update_network_state(
                (auth_session.user.unwrap().id(), machine_id),
                inst_id,
                payload.disabled,
            )
            .await
            .map_err(convert_error)
    }

    async fn handle_get_network_metas(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(machine_id): Path<uuid::Uuid>,
        Json(payload): Json<GetNetworkMetasJsonReq>,
    ) -> Result<Json<GetNetworkMetasResponse>, HttpHandleError> {
        Ok(Json(
            client_mgr
                .handle_get_network_metas(
                    (Self::get_user_id(&auth_session)?, machine_id),
                    payload.instance_ids,
                )
                .await
                .map_err(convert_error)?,
        ))
    }

    async fn handle_save_network_config(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
        Json(payload): Json<SaveNetworkJsonReq>,
    ) -> Result<(), HttpHandleError> {
        if payload.config.instance_id() != inst_id.to_string() {
            return Err((
                StatusCode::BAD_REQUEST,
                other_error("Instance ID mismatch".to_string()).into(),
            ));
        }
        client_mgr
            .handle_save_network_config(
                (Self::get_user_id(&auth_session)?, machine_id),
                inst_id,
                payload.config,
            )
            .await
            .map_err(convert_error)
    }

    async fn handle_get_network_config(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<Json<NetworkConfig>, HttpHandleError> {
        Ok(client_mgr
            .handle_get_network_config((auth_session.user.unwrap().id(), machine_id), inst_id)
            .await
            .map_err(convert_error)?
            .into())
    }

    // --- Token-authenticated machine-scoped handlers (no AuthSession) ---

    async fn handle_run_network_instance_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
        Json(payload): Json<RunNetworkJsonReq>,
    ) -> Result<Json<Void>, HttpHandleError> {
        client_mgr
            .handle_run_network_instance((user_id, machine_id), payload.config, payload.save)
            .await
            .map_err(convert_error)?;
        Ok(Void::default().into())
    }

    async fn handle_remove_network_instance_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id, inst_id)): Path<(UserIdInDb, uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(), HttpHandleError> {
        client_mgr
            .handle_remove_network_instances((user_id, machine_id), vec![inst_id])
            .await
            .map_err(convert_error)
    }

    async fn handle_list_network_instance_ids_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
    ) -> Result<Json<ListNetworkInstanceIdsJsonResp>, HttpHandleError> {
        Ok(client_mgr
            .handle_list_network_instance_ids((user_id, machine_id))
            .await
            .map_err(convert_error)?
            .into())
    }

    async fn handle_collect_network_info_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
        Json(payload): Json<CollectNetworkInfoJsonReq>,
    ) -> Result<Json<CollectNetworkInfoResponse>, HttpHandleError> {
        Ok(client_mgr
            .handle_collect_network_info((user_id, machine_id), payload.inst_ids)
            .await
            .map_err(convert_error)?
            .into())
    }

    pub fn build_route_internal() -> Router<AppStateInner> {
        Router::new()
            .route(
                "/api/internal/users/:user-id/machines/:machine-id/networks",
                post(Self::handle_run_network_instance_internal)
                    .get(Self::handle_list_network_instance_ids_internal),
            )
            .route(
                "/api/internal/users/:user-id/machines/:machine-id/networks/:inst-id",
                delete(Self::handle_remove_network_instance_internal),
            )
            .route(
                "/api/internal/users/:user-id/machines/:machine-id/networks/info",
                get(Self::handle_collect_network_info_internal),
            )
    }

    pub fn build_route() -> Router<AppStateInner> {
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
                get(Self::handle_get_network_config).put(Self::handle_save_network_config),
            )
            .route(
                "/api/v1/machines/:machine-id/networks/metas",
                post(Self::handle_get_network_metas),
            )
    }
}
