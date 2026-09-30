use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Query};
use axum::http::StatusCode;
use axum::routing::{delete, post, put};
use axum::{Extension, Json, Router, extract::State, routing::get};
use axum_login::AuthUser;
use easytier::common::config::{
    ConfigSource as RuntimeConfigSource, NetworkConfig, config_source_from_rpc,
};
use easytier::proto::api::config::VpnPortalClientPatch;
use easytier::proto::common::Void;
use easytier::proto::{api::manage::*, web::*};
use easytier_core::management::remote_client::{
    GetNetworkMetasResponse, ListNetworkInstanceIdsJsonResp, RemoteClientError, RemoteClientManager,
};
use sea_orm::DbErr;

use crate::central_network::service::{CentralNetworkService, DeviceNetworkSummary};
use crate::client_manager::session::Location;
use crate::db::UserIdInDb;

use super::users::AuthSession;
use super::{
    AppState, AppStateInner, Error, HttpHandleError, RpcError, convert_db_error, other_error,
};

const MAX_MANAGED_CONFIG_REQUEST_BODY_SIZE: usize = 32 * 1024 * 1024;

pub(super) fn central_ownership_conflict() -> HttpHandleError {
    (
        StatusCode::CONFLICT,
        Json(Error {
            message: "central network config must be changed through its network intent".to_owned(),
            code: Some("central_network_ownership_conflict".to_owned()),
            current_config_revision: None,
        }),
    )
}

async fn ensure_direct_mutation_allowed(
    service: &CentralNetworkService,
    user_id: UserIdInDb,
    machine_id: uuid::Uuid,
    instance_id: uuid::Uuid,
    network_name: Option<&str>,
) -> Result<(), HttpHandleError> {
    let central = service
        .db
        .central_owned_runtime_configs(user_id, machine_id)
        .await
        .map_err(convert_db_error)?;
    if central.iter().any(|config| {
        config.instance_id == instance_id
            || network_name.is_some_and(|name| config.network_name == name)
    }) {
        return Err(central_ownership_conflict());
    }
    Ok(())
}

fn convert_rpc_error(e: RpcError) -> (StatusCode, Json<Error>) {
    let status_code = match &e {
        RpcError::ExecutionError(_) => StatusCode::BAD_REQUEST,
        RpcError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    let error = Error {
        message: format!("{:?}", e),
        code: None,
        current_config_revision: None,
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
        RemoteClientError::Other(msg) if msg.starts_with("invalid instance ID:") => {
            (StatusCode::BAD_REQUEST, other_error(msg).into())
        }
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

#[derive(Debug, serde::Deserialize)]
struct PatchVpnPortalClientsJsonReq {
    patches: Vec<VpnPortalClientPatch>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RunNetworkJsonReq {
    config: NetworkConfig,
    save: bool,
    source: Option<i32>,
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
struct DeleteMachineParams {
    block: Option<bool>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct UpdateDeviceAliasJsonReq {
    alias: String,
}

#[derive(Debug, serde::Serialize)]
struct BlockedDeviceItem {
    id: String,
    user_id: UserIdInDb,
    hostname: String,
    blocked_time: chrono::DateTime<chrono::FixedOffset>,
    attempt_count: i32,
    last_attempt_time: Option<chrono::DateTime<chrono::FixedOffset>>,
}

impl From<crate::db::entity::blocked_devices::Model> for BlockedDeviceItem {
    fn from(device: crate::db::entity::blocked_devices::Model) -> Self {
        Self {
            id: device.machine_id,
            user_id: device.user_id,
            hostname: device.hostname,
            blocked_time: device.blocked_time,
            attempt_count: device.attempt_count,
            last_attempt_time: device.last_attempt_time,
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct ListBlockedDevicesJsonResp {
    blocked: Vec<BlockedDeviceItem>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ManagedNetworkConfigJson {
    instance_id: uuid::Uuid,
    network_config: serde_json::Value,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ReconcileManagedNetworkConfigsJsonReq {
    managed_network_configs: Vec<ManagedNetworkConfigJson>,
    config_revision: Option<String>,
    expected_config_revision: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct PatchManagedNetworkConfigsJsonReq {
    upserts: Vec<ManagedNetworkConfigJson>,
    delete_instance_ids: Vec<uuid::Uuid>,
    config_revision: String,
    expected_config_revision: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListMachineItem {
    client_url: Option<url::Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    info: Option<HeartbeatRequest>,
    location: Option<Location>,
    #[serde(default)]
    networks: Vec<DeviceNetworkSummary>,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    last_seen: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ListMachineJsonResp {
    machines: Vec<ListMachineItem>,
}

pub struct NetworkApi;

const DEVICE_ALIAS_MAX_CHARS: usize = 64;

impl NetworkApi {
    fn convert_managed_config_error(error: anyhow::Error) -> HttpHandleError {
        let (status, code, current_config_revision) =
            match error.downcast_ref::<crate::client_manager::ManagedConfigError>() {
                Some(crate::client_manager::ManagedConfigError::Invalid(_)) => {
                    (StatusCode::BAD_REQUEST, None, None)
                }
                Some(crate::client_manager::ManagedConfigError::RevisionConflict {
                    current,
                    ..
                }) => (
                    StatusCode::CONFLICT,
                    Some("managed_config_revision_conflict".to_string()),
                    current.clone(),
                ),
                Some(crate::client_manager::ManagedConfigError::OwnershipConflict { .. }) => (
                    StatusCode::CONFLICT,
                    Some("managed_config_ownership_conflict".to_string()),
                    None,
                ),
                None => (StatusCode::INTERNAL_SERVER_ERROR, None, None),
            };
        (
            status,
            Json(Error {
                message: error.to_string(),
                code,
                current_config_revision,
            }),
        )
    }

    fn get_user_id(auth_session: &AuthSession) -> Result<UserIdInDb, (StatusCode, Json<Error>)> {
        super::authed_user_id(auth_session)
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
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
        Path(machine_id): Path<uuid::Uuid>,
        Json(mut payload): Json<RunNetworkJsonReq>,
    ) -> Result<Json<Void>, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        let instance_id = match payload.config.instance_id.as_deref() {
            Some(raw) => uuid::Uuid::parse_str(raw).map_err(|error| {
                (
                    StatusCode::BAD_REQUEST,
                    other_error(format!("invalid instance ID: {error}")).into(),
                )
            })?,
            None => uuid::Uuid::new_v4(),
        };
        payload.config.instance_id = Some(instance_id.to_string());
        let _mutation = network_service.lock_mutations().await;
        ensure_direct_mutation_allowed(
            &network_service,
            user_id,
            machine_id,
            instance_id,
            payload.config.network_name.as_deref(),
        )
        .await?;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        let result = client_mgr
            .handle_run_network_instance_with_source(
                (user_id, machine_id),
                payload.config,
                payload.save,
                RuntimeConfigSource::Web,
            )
            .await;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        result.map_err(convert_error)?;
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
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(), HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        let _mutation = network_service.lock_mutations().await;
        ensure_direct_mutation_allowed(&network_service, user_id, machine_id, inst_id, None)
            .await?;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        let result = client_mgr
            .handle_remove_network_instances((user_id, machine_id), vec![inst_id])
            .await;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        result.map_err(convert_error)?;
        Ok(())
    }

    async fn handle_delete_machine(
        auth_session: AuthSession,
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
        Path(machine_id): Path<uuid::Uuid>,
        Query(params): Query<DeleteMachineParams>,
    ) -> Result<StatusCode, HttpHandleError> {
        let deleted = network_service
            .delete_device(
                Self::get_user_id(&auth_session)?,
                machine_id,
                params.block.unwrap_or(false),
            )
            .await
            .map_err(super::central_network::convert_error)?;
        if !deleted {
            return Err((
                StatusCode::NOT_FOUND,
                other_error(format!("device not found: {machine_id}")).into(),
            ));
        }
        Ok(StatusCode::NO_CONTENT)
    }

    async fn handle_update_machine_alias(
        auth_session: AuthSession,
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
        Path(machine_id): Path<uuid::Uuid>,
        Json(request): Json<UpdateDeviceAliasJsonReq>,
    ) -> Result<StatusCode, HttpHandleError> {
        let alias = request.alias.trim().to_owned();
        if alias.chars().count() > DEVICE_ALIAS_MAX_CHARS {
            return Err((
                StatusCode::BAD_REQUEST,
                other_error(format!(
                    "alias must be at most {DEVICE_ALIAS_MAX_CHARS} characters"
                ))
                .into(),
            ));
        }
        let updated = network_service
            .db
            .set_device_alias((Self::get_user_id(&auth_session)?, machine_id), alias)
            .await
            .map_err(convert_db_error)?;
        if !updated {
            return Err((
                StatusCode::NOT_FOUND,
                other_error(format!("device not found: {machine_id}")).into(),
            ));
        }
        Ok(StatusCode::NO_CONTENT)
    }

    async fn handle_list_blocked_devices(
        auth_session: AuthSession,
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
    ) -> Result<Json<ListBlockedDevicesJsonResp>, HttpHandleError> {
        let blocked = network_service
            .db
            .list_blocked_devices(Self::get_user_id(&auth_session)?)
            .await
            .map_err(convert_db_error)?
            .into_iter()
            .map(BlockedDeviceItem::from)
            .collect();
        Ok(Json(ListBlockedDevicesJsonResp { blocked }))
    }

    async fn handle_unblock_device(
        auth_session: AuthSession,
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
        Path(machine_id): Path<uuid::Uuid>,
    ) -> Result<StatusCode, HttpHandleError> {
        network_service
            .db
            .unblock_device((Self::get_user_id(&auth_session)?, machine_id))
            .await
            .map_err(convert_db_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn handle_list_machines(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Extension(config): Extension<super::ConsoleInfoConfig>,
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
    ) -> Result<Json<ListMachineJsonResp>, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        if config.webhook_auth {
            let client_urls = client_mgr.list_machine_by_user_id(user_id).await;
            let mut machines = Vec::with_capacity(client_urls.len());
            for client_url in client_urls {
                let info = client_mgr.get_heartbeat_requests(&client_url).await;
                let location = client_mgr.get_machine_location(&client_url).await;
                machines.push(ListMachineItem {
                    client_url: Some(client_url),
                    online: info.is_some(),
                    last_seen: info.as_ref().map(|info| info.report_time.clone()),
                    info,
                    location,
                    alias: None,
                    networks: Vec::new(),
                });
            }
            return Ok(Json(ListMachineJsonResp { machines }));
        }
        let devices = network_service
            .db
            .list_devices(user_id)
            .await
            .map_err(convert_db_error)?;
        let mut device_networks = network_service
            .list_device_networks(user_id)
            .await
            .map_err(super::central_network::convert_error)?;

        let mut machines = Vec::with_capacity(devices.len());
        for device in devices {
            let machine_id = uuid::Uuid::parse_str(&device.machine_id).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    other_error(format!(
                        "invalid device id in registry: {}",
                        device.machine_id
                    ))
                    .into(),
                )
            })?;
            let session = client_mgr.get_session_by_machine_id(user_id, &machine_id);
            let client_url = match &session {
                Some(session) => session.get_token().await.map(|token| token.client_url),
                None => device.client_url.parse::<url::Url>().ok(),
            };
            let location = match &session {
                Some(session) => session.data().read().await.location().cloned(),
                None => None,
            };
            let online = session.is_some();
            let info = match session {
                Some(session) => session.get_heartbeat_req().await,
                None => Some(HeartbeatRequest {
                    machine_id: Some(machine_id.into()),
                    inst_id: None,
                    user_token: String::new(),
                    easytier_version: device.easytier_version.clone(),
                    report_time: device.last_seen_time.to_rfc3339(),
                    hostname: device.hostname.clone(),
                    running_network_instances: Vec::new(),
                    device_os: serde_json::from_str(&device.device_os).ok(),
                    support_config_source: false,
                    failed_network_instances: Vec::new(),
                    support_heartbeat_policy: false,
                }),
            };
            machines.push(ListMachineItem {
                client_url,
                alias: (!device.alias.is_empty()).then_some(device.alias),
                info,
                location,
                networks: device_networks
                    .remove(&device.machine_id)
                    .unwrap_or_default(),
                online,
                last_seen: Some(device.last_seen_time.to_rfc3339()),
            });
        }

        machines.sort_by(|a, b| {
            b.online
                .cmp(&a.online)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        });

        Ok(Json(ListMachineJsonResp { machines }))
    }

    async fn handle_update_network_state(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
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

        let user_id = Self::get_user_id(&auth_session)?;
        let _mutation = network_service.lock_mutations().await;
        ensure_direct_mutation_allowed(&network_service, user_id, machine_id, inst_id, None)
            .await?;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        let result = client_mgr
            .handle_update_network_state((user_id, machine_id), inst_id, payload.disabled)
            .await;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        result.map_err(convert_error)?;
        Ok(())
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
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
        Json(payload): Json<SaveNetworkJsonReq>,
    ) -> Result<(), HttpHandleError> {
        if payload.config.instance_id() != inst_id.to_string() {
            return Err((
                StatusCode::BAD_REQUEST,
                other_error("Instance ID mismatch".to_string()).into(),
            ));
        }
        let user_id = Self::get_user_id(&auth_session)?;
        let _mutation = network_service.lock_mutations().await;
        ensure_direct_mutation_allowed(
            &network_service,
            user_id,
            machine_id,
            inst_id,
            payload.config.network_name.as_deref(),
        )
        .await?;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        let result = client_mgr
            .handle_save_network_config_with_source(
                (user_id, machine_id),
                inst_id,
                payload.config,
                RuntimeConfigSource::Web,
            )
            .await;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        result.map_err(convert_error)?;
        Ok(())
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

    async fn handle_patch_vpn_portal_clients(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Extension(network_service): Extension<Arc<CentralNetworkService>>,
        Path((machine_id, inst_id)): Path<(uuid::Uuid, uuid::Uuid)>,
        Json(payload): Json<PatchVpnPortalClientsJsonReq>,
    ) -> Result<(), HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        let _mutation = network_service.lock_mutations().await;
        ensure_direct_mutation_allowed(&network_service, user_id, machine_id, inst_id, None)
            .await?;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        let result = client_mgr
            .handle_patch_vpn_portal_clients((user_id, machine_id), inst_id, payload.patches)
            .await;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        result.map_err(convert_error)
    }

    // --- Token-authenticated machine-scoped handlers (no AuthSession) ---

    async fn handle_run_network_instance_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
        Json(payload): Json<RunNetworkJsonReq>,
    ) -> Result<Json<Void>, HttpHandleError> {
        let source = payload
            .source
            .and_then(config_source_from_rpc)
            .unwrap_or(RuntimeConfigSource::Web);
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        let result = client_mgr
            .handle_run_network_instance_with_source(
                (user_id, machine_id),
                payload.config,
                payload.save,
                source,
            )
            .await;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        result.map_err(convert_error)?;
        Ok(Void::default().into())
    }

    async fn handle_remove_network_instance_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id, inst_id)): Path<(UserIdInDb, uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(), HttpHandleError> {
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        let result = client_mgr
            .handle_remove_network_instances((user_id, machine_id), vec![inst_id])
            .await;
        client_mgr
            .invalidate_applied_config_revision(user_id, machine_id)
            .await;
        result.map_err(convert_error)?;
        Ok(())
    }

    async fn handle_reconcile_managed_network_configs_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
        Json(payload): Json<ReconcileManagedNetworkConfigsJsonReq>,
    ) -> Result<StatusCode, HttpHandleError> {
        let desired = payload
            .managed_network_configs
            .into_iter()
            .map(|item| crate::webhook::ManagedNetworkConfig {
                instance_id: item.instance_id.to_string(),
                network_config: item.network_config,
            })
            .collect();
        client_mgr
            .reconcile_managed_network_configs(
                user_id,
                machine_id,
                desired,
                payload.config_revision,
                payload.expected_config_revision,
            )
            .await
            .map_err(Self::convert_managed_config_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn handle_patch_managed_network_configs_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
        Json(payload): Json<PatchManagedNetworkConfigsJsonReq>,
    ) -> Result<StatusCode, HttpHandleError> {
        let upserts = payload
            .upserts
            .into_iter()
            .map(|item| crate::webhook::ManagedNetworkConfig {
                instance_id: item.instance_id.to_string(),
                network_config: item.network_config,
            })
            .collect();
        client_mgr
            .patch_managed_network_configs(
                user_id,
                machine_id,
                upserts,
                payload.delete_instance_ids,
                payload.config_revision,
                payload.expected_config_revision,
            )
            .await
            .map_err(Self::convert_managed_config_error)?;
        Ok(StatusCode::NO_CONTENT)
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
                "/api/internal/users/{user-id}/machines/{machine-id}/networks",
                put(Self::handle_reconcile_managed_network_configs_internal)
                    .patch(Self::handle_patch_managed_network_configs_internal)
                    .layer(DefaultBodyLimit::max(MAX_MANAGED_CONFIG_REQUEST_BODY_SIZE))
                    .post(Self::handle_run_network_instance_internal)
                    .get(Self::handle_list_network_instance_ids_internal),
            )
            .route(
                "/api/internal/users/{user-id}/machines/{machine-id}/networks/{inst-id}",
                delete(Self::handle_remove_network_instance_internal),
            )
            .route(
                "/api/internal/users/{user-id}/machines/{machine-id}/networks/info",
                get(Self::handle_collect_network_info_internal),
            )
    }

    pub fn build_route() -> Router<AppStateInner> {
        Router::new()
            .route("/api/v1/machines", get(Self::handle_list_machines))
            .route(
                "/api/v1/machines/{machine-id}",
                delete(Self::handle_delete_machine),
            )
            .route(
                "/api/v1/machines/{machine-id}/alias",
                put(Self::handle_update_machine_alias),
            )
            .route(
                "/api/v1/blocked-devices",
                get(Self::handle_list_blocked_devices),
            )
            .route(
                "/api/v1/blocked-devices/{machine-id}",
                delete(Self::handle_unblock_device),
            )
            .route(
                "/api/v1/machines/{machine-id}/validate-config",
                post(Self::handle_validate_config),
            )
            .route(
                "/api/v1/machines/{machine-id}/networks",
                post(Self::handle_run_network_instance).get(Self::handle_list_network_instance_ids),
            )
            .route(
                "/api/v1/machines/{machine-id}/networks/{inst-id}",
                delete(Self::handle_remove_network_instance).put(Self::handle_update_network_state),
            )
            .route(
                "/api/v1/machines/{machine-id}/networks/info",
                get(Self::handle_collect_network_info),
            )
            .route(
                "/api/v1/machines/{machine-id}/networks/info/{inst-id}",
                get(Self::handle_collect_one_network_info),
            )
            .route(
                "/api/v1/machines/{machine-id}/networks/config/{inst-id}",
                get(Self::handle_get_network_config).put(Self::handle_save_network_config),
            )
            .route(
                "/api/v1/machines/{machine-id}/networks/{inst-id}/vpn-portal-clients",
                axum::routing::patch(Self::handle_patch_vpn_portal_clients),
            )
            .route(
                "/api/v1/machines/{machine-id}/networks/metas",
                post(Self::handle_get_network_metas),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn internal_runtime_only_write_reconciles_the_already_applied_revision() {
        use std::{future::Future, time::Duration};

        use easytier::{
            common::config::NetworkConfigExt as _, instance::factory::native_instance_manager,
            web_client::WebClient,
        };
        use easytier_core::{
            connectivity::protocol::raw::TunnelDialer,
            socket::SocketListener,
            tunnel::{
                Tunnel,
                ring::{RING_TUNNEL_CAP, RingTunnel, create_ring_socket_pair},
            },
        };
        use tower::ServiceExt as _;

        use crate::{
            client_manager::{ClientManager, HeartbeatPolicy},
            db::Db,
            webhook::{
                ManagedNetworkConfig, ValidateTokenRequest, ValidateTokenResponse, WebhookConfig,
                WebhookHandler,
            },
        };

        // Exercise the actual REST, Web RPC, and reconcile paths without an
        // operating-system listener or a test-only ClientManager interface.
        #[derive(Debug)]
        struct Listener(tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>);
        #[async_trait::async_trait]
        impl SocketListener for Listener {
            type Accepted = Box<dyn Tunnel>;
            async fn listen(&mut self) -> anyhow::Result<()> {
                Ok(())
            }
            async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
                self.0
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("test listener closed"))
            }
            fn local_url(&self) -> url::Url {
                "ring://server".parse().unwrap()
            }
        }
        struct Dialer(tokio::sync::mpsc::UnboundedSender<Box<dyn Tunnel>>);
        #[async_trait::async_trait]
        impl TunnelDialer for Dialer {
            async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
                let (server, client) = create_ring_socket_pair(RING_TUNNEL_CAP);
                let server = Box::new(RingTunnel::new(
                    server,
                    Some(easytier::proto::common::TunnelInfo {
                        tunnel_type: "ring".to_owned(),
                        local_addr: Some("ring://server".parse::<url::Url>().unwrap().into()),
                        remote_addr: Some(
                            format!("ring://{}", uuid::Uuid::new_v4())
                                .parse::<url::Url>()
                                .unwrap()
                                .into(),
                        ),
                        ..Default::default()
                    }),
                ));
                self.0
                    .send(server)
                    .map_err(|_| anyhow::anyhow!("test listener closed"))?;
                Ok(Box::new(RingTunnel::new(client, None)))
            }
            fn remote_url(&self) -> url::Url {
                "ring://server".parse().unwrap()
            }
        }
        #[derive(Debug, Default)]
        struct Webhook(std::sync::Mutex<Option<String>>);
        #[async_trait::async_trait]
        impl WebhookHandler for Webhook {
            async fn validate_token(
                &self,
                request: &ValidateTokenRequest,
            ) -> anyhow::Result<ValidateTokenResponse> {
                *self.0.lock().unwrap() = request.applied_config_revision.clone();
                Ok(ValidateTokenResponse {
                    valid: true,
                    pre_approved: true,
                    binding_version: 0,
                    config_revision: "revision-1".to_owned(),
                })
            }
        }
        async fn wait_until<F, Fut>(mut condition: F)
        where
            F: FnMut() -> Fut,
            Fut: Future<Output = bool>,
        {
            tokio::time::timeout(Duration::from_secs(20), async {
                while !condition().await {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("runtime did not converge");
        }

        let db = Db::memory_db().await;
        let db_user = db.auto_create_user("rest-revision").await.unwrap();
        let user_id = db_user.id;
        let machine_id = uuid::Uuid::new_v4();
        let instance_id = uuid::Uuid::new_v4();
        let webhook = Arc::new(Webhook::default());
        let mut manager = ClientManager::new(
            db.clone(),
            None,
            HeartbeatPolicy::from_millis(1_000, 10_000).unwrap(),
            Arc::new(crate::FeatureFlags::default()),
            Arc::new(
                WebhookConfig::new(None, None, None, None, None).with_handler(webhook.clone()),
            ),
        );
        let (connections, listener) = tokio::sync::mpsc::unbounded_channel();
        manager.add_listener(Listener(listener)).await.unwrap();
        let manager = Arc::new(manager);
        let core = Arc::new(native_instance_manager());
        let client = WebClient::new(
            Dialer(connections),
            "rest-revision",
            machine_id,
            "test-device",
            false,
            core.clone(),
            None,
        );
        let desired = serde_json::json!({
            "instance_id": instance_id.to_string(),
            "network_name": "managed-network", "network_secret": "secret",
            "networking_method": "Standalone", "no_tun": true,
            "disable_ipv6": true, "multi_thread": false,
        });
        manager
            .reconcile_managed_network_configs(
                user_id,
                machine_id,
                vec![ManagedNetworkConfig {
                    instance_id: instance_id.to_string(),
                    network_config: desired.clone(),
                }],
                Some("revision-1".to_owned()),
                None,
            )
            .await
            .unwrap();
        wait_until(|| async { webhook.0.lock().unwrap().as_deref() == Some("revision-1") }).await;

        // External Console authentication does not populate central devices.
        // Both public views must still expose the live, webhook-managed Core.
        assert!(db.list_devices(user_id).await.unwrap().is_empty());
        let service = Arc::new(CentralNetworkService::new(db.clone(), manager.clone()));
        let session_store = tower_sessions_sqlx_store::SqliteStore::new(db.inner());
        session_store.migrate().await.unwrap();
        let session_layer = axum_login::tower_sessions::SessionManagerLayer::new(session_store);
        let auth_layer = axum_login::AuthManagerLayerBuilder::new(
            super::super::users::Backend::new(db.clone()),
            session_layer,
        )
        .build();
        let probe_manager = manager.clone();
        let response = Router::new()
            .route(
                "/views",
                get(move |mut auth: AuthSession| async move {
                    auth.user = Some(super::super::users::User {
                        db_user,
                        tokens: vec![],
                    });
                    let config = super::super::ConsoleInfoConfig {
                        config_server_protocol: "tcp".into(),
                        config_server_port: 22020,
                        webhook_auth: true,
                    };
                    let machines = NetworkApi::handle_list_machines(
                        auth.clone(),
                        State(probe_manager.clone()),
                        Extension(config.clone()),
                        Extension(service.clone()),
                    )
                    .await
                    .unwrap()
                    .0;
                    let summary = super::super::RestfulServer::handle_get_summary(
                        auth,
                        State(probe_manager),
                        Extension(config),
                        Extension(service),
                    )
                    .await
                    .unwrap()
                    .0;
                    assert_eq!(summary.device_count, 1);
                    assert_eq!(machines.machines.len(), 1);
                    assert!(machines.machines[0].online);
                    assert_eq!(
                        machines.machines[0].info.as_ref().unwrap().machine_id,
                        Some(machine_id.into())
                    );
                    StatusCode::OK
                }),
            )
            .layer(auth_layer)
            .oneshot(
                axum::http::Request::get("/views")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut drifted = desired;
        drifted["network_name"] = serde_json::json!("runtime-only-change");
        let response = NetworkApi::build_route_internal()
            .with_state(manager.clone())
            .oneshot(
                axum::http::Request::post(format!(
                    "/api/internal/users/{user_id}/machines/{machine_id}/networks"
                ))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"config": drifted, "save": false}).to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        wait_until(|| async {
            core.config(instance_id)
                .and_then(|config| NetworkConfig::new_from_config(&config).ok())
                .is_some_and(|config| config.network_name.as_deref() == Some("managed-network"))
        })
        .await;
        assert_eq!(
            db.get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .as_deref(),
            Some("revision-1")
        );
        drop(client);
        manager
            .disconnect_session_by_machine_id(user_id, &machine_id)
            .await;
        core.delete_network_instances([instance_id]).await.unwrap();
    }

    #[test]
    fn blocked_device_response_keeps_the_public_id_field() {
        let machine_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Local::now().fixed_offset();
        let item = BlockedDeviceItem::from(crate::db::entity::blocked_devices::Model {
            user_id: 7,
            machine_id: machine_id.clone(),
            hostname: "blocked-device".to_owned(),
            blocked_time: now,
            attempt_count: 3,
            last_attempt_time: Some(now),
        });

        let value = serde_json::to_value(item).unwrap();
        assert_eq!(value["id"], machine_id);
        assert!(value.get("machine_id").is_none());
    }

    #[test]
    fn revision_conflict_response_exposes_machine_readable_current_revision() {
        let error = crate::client_manager::ManagedConfigError::RevisionConflict {
            expected: Some("rev-1".to_string()),
            current: Some("rev-2".to_string()),
        };

        let (status, Json(body)) = NetworkApi::convert_managed_config_error(error.into());

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body.code.as_deref(),
            Some("managed_config_revision_conflict")
        );
        assert_eq!(body.current_config_revision.as_deref(), Some("rev-2"));
    }

    #[test]
    fn ownership_conflict_is_distinct_from_revision_conflict() {
        let error = crate::client_manager::ManagedConfigError::OwnershipConflict {
            instance_id: uuid::Uuid::new_v4(),
        };

        let (status, Json(body)) = NetworkApi::convert_managed_config_error(error.into());

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body.code.as_deref(),
            Some("managed_config_ownership_conflict")
        );
        assert_eq!(body.current_config_revision, None);
    }
}
