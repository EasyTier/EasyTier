use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{extract::State, routing::get, Json, Router};
use axum_login::AuthUser;
use easytier::launcher::NetworkConfig;
use easytier::proto::common::Void;
use easytier::proto::{api::manage::*, web::*};
use easytier::rpc_service::remote_client::{
    ListNetworkInstanceIdsJsonResp, RemoteClientError, RemoteClientManager,
};
use sea_orm::DbErr;

use crate::client_manager::session::Location;
use crate::db::UserIdInDb;

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
struct RunNetworkJsonReq {
    config: NetworkConfig,
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
struct RemoveNetworkJsonReq {
    inst_ids: Vec<uuid::Uuid>,
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

        client_mgr
            .handle_update_network_state(
                (auth_session.user.unwrap().id(), machine_id),
                inst_id,
                payload.disabled,
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
                get(Self::handle_get_network_config),
            )
    }
}
