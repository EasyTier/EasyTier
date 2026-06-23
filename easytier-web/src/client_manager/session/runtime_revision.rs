use std::collections::HashSet;

use easytier::{
    proto::{
        api::manage::{
            DeleteNetworkInstanceRequest, ListNetworkInstanceMetaRequest,
            ListNetworkInstanceRequest, NetworkConfig, NetworkMeta, RunNetworkInstanceRequest,
        },
        rpc_types::controller::BaseController,
        web::HeartbeatRequest,
    },
    rpc_service::remote_client::{ListNetworkProps, Storage as _},
};
use tokio::sync::{RwLock, broadcast};

use super::{SessionConfigClient, SessionData, SessionRpcClient, SessionRpcService};
use crate::client_manager::{
    managed_config::{self, PersistedConfigSource},
    runtime_reconcile,
    storage::{StorageInner, WeakRefStorage},
};

async fn recv_latest_heartbeat(
    heartbeat_waiter: &mut broadcast::Receiver<HeartbeatRequest>,
) -> Option<HeartbeatRequest> {
    let mut req = loop {
        match heartbeat_waiter.recv().await {
            Ok(req) => break req,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!(
                    skipped,
                    "heartbeat reconcile worker lagged, waiting for latest request"
                );
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::error!("Failed to receive heartbeat request: channel closed");
                return None;
            }
        }
    };

    // Drop any heartbeat backlog accumulated while the previous reconcile
    // round was doing DB/RPC IO. The newest heartbeat has the freshest
    // runtime instance list, which is all this task needs.
    loop {
        match heartbeat_waiter.try_recv() {
            Ok(next_req) => req = next_req,
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(broadcast::error::TryRecvError::Closed) => return None,
        }
    }

    Some(req)
}

pub(super) async fn reconcile_network_configs_on_heartbeat(
    session_data: std::sync::Weak<RwLock<SessionData>>,
    mut heartbeat_waiter: broadcast::Receiver<HeartbeatRequest>,
    storage: WeakRefStorage,
    mut rpc_client: SessionRpcClient,
    mut config_client: SessionConfigClient,
) {
    let mut cache = ReconcileCache::default();
    loop {
        let Some(req) = recv_latest_heartbeat(&mut heartbeat_waiter).await else {
            return;
        };
        let Some(storage) = storage.upgrade() else {
            tracing::error!("Failed to get storage");
            return;
        };

        let mut round =
            match prepare_reconcile_round(&session_data, &storage, &mut rpc_client, req).await {
                RoundStatus::Ready(round) => round,
                RoundStatus::Skip => continue,
                RoundStatus::Stop => return,
            };
        let running_metas =
            match sync_running_sources_for_round(&mut rpc_client, &storage, &mut round).await {
                RoundStatus::Ready(running_metas) => running_metas,
                RoundStatus::Skip => continue,
                RoundStatus::Stop => return,
            };

        let desired_web_inst_ids =
            managed_config::desired_web_source_instance_ids(&round.local_configs);
        let mut outcome = match cleanup_stale_web_source_instances(
            &session_data,
            &storage,
            &mut rpc_client,
            &round,
            running_metas.as_deref(),
            &desired_web_inst_ids,
            &mut cache,
        )
        .await
        {
            RoundStatus::Ready(outcome) => outcome,
            RoundStatus::Skip => continue,
            RoundStatus::Stop => return,
        };

        outcome.merge(
            reconcile_desired_runtime_configs(
                &session_data,
                &mut rpc_client,
                &mut config_client,
                &round,
            )
            .await,
        );

        if !outcome.has_failed {
            cache.last_desired_web_inst_ids = Some(desired_web_inst_ids);
        }
        match mark_config_revision_applied_if_current(&session_data, &storage, &round, &outcome)
            .await
        {
            RoundStatus::Ready(()) | RoundStatus::Skip => {}
            RoundStatus::Stop => return,
        }
    }
}

enum RoundStatus<T> {
    Ready(T),
    Skip,
    Stop,
}

enum ConfigActionResult {
    Success,
    Failed,
    StopRound,
}

#[derive(Default)]
struct ReconcileCache {
    cleaned_web_source_instances: bool,
    last_desired_web_inst_ids: Option<HashSet<String>>,
}

#[derive(Default)]
struct ReconcileOutcome {
    has_failed: bool,
    managed_revision_failed: bool,
}

impl ReconcileOutcome {
    fn record_failure(&mut self, managed_revision_failed: bool) {
        self.has_failed = true;
        self.managed_revision_failed |= managed_revision_failed;
    }

    fn merge(&mut self, other: Self) {
        self.has_failed |= other.has_failed;
        self.managed_revision_failed |= other.managed_revision_failed;
    }
}

struct ReconcileRound {
    req: HeartbeatRequest,
    machine_id: uuid::Uuid,
    user_id: i32,
    running_inst_ids: HashSet<String>,
    local_configs: Vec<crate::db::entity::user_running_network_configs::Model>,
    target_config_revision: Option<String>,
    should_apply_runtime_revision: bool,
}

async fn prepare_reconcile_round(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage: &StorageInner,
    rpc_client: &mut SessionRpcClient,
    req: HeartbeatRequest,
) -> RoundStatus<ReconcileRound> {
    let Some(machine_id) = req.machine_id.map(uuid::Uuid::from) else {
        tracing::warn!(?req, "Machine id is not set, ignore");
        return RoundStatus::Skip;
    };
    if !SessionRpcService::runtime_heartbeat_is_current(session_data, &req).await {
        tracing::debug!(?machine_id, "skip stale heartbeat reconcile request");
        return RoundStatus::Skip;
    }

    let user_id = match storage
        .db
        .get_user_id_by_token(req.user_token.clone())
        .await
    {
        Ok(Some(user_id)) => user_id,
        Ok(None) => {
            tracing::info!("User not found by token: {:?}", req.user_token);
            return RoundStatus::Stop;
        }
        Err(e) => {
            tracing::error!("Failed to get user id by token, error: {:?}", e);
            return RoundStatus::Stop;
        }
    };

    let applied_config_revision = {
        let Some(data) = session_data.upgrade() else {
            return RoundStatus::Stop;
        };
        data.read().await.applied_config_revision.clone()
    };
    let target_config_revision = match storage
        .db
        .get_managed_config_revision((user_id, machine_id))
        .await
    {
        Ok(revision) => revision,
        Err(e) => {
            tracing::error!("Failed to read managed config revision, error: {:?}", e);
            return RoundStatus::Stop;
        }
    };
    let should_apply_runtime_revision =
        target_config_revision.is_some() && target_config_revision != applied_config_revision;
    let running_inst_ids = match running_instance_ids_for_round(
        rpc_client,
        &req,
        user_id,
        machine_id,
        should_apply_runtime_revision,
    )
    .await
    {
        RoundStatus::Ready(ids) => ids,
        RoundStatus::Skip => return RoundStatus::Skip,
        RoundStatus::Stop => return RoundStatus::Stop,
    };

    let local_configs = match storage
        .db
        .list_network_configs((user_id, machine_id), ListNetworkProps::EnabledOnly)
        .await
    {
        Ok(configs) => configs,
        Err(e) => {
            tracing::error!("Failed to list network configs, error: {:?}", e);
            return RoundStatus::Stop;
        }
    };

    RoundStatus::Ready(ReconcileRound {
        req,
        machine_id,
        user_id,
        running_inst_ids,
        local_configs,
        target_config_revision,
        should_apply_runtime_revision,
    })
}

async fn running_instance_ids_for_round(
    rpc_client: &mut SessionRpcClient,
    req: &HeartbeatRequest,
    user_id: i32,
    machine_id: uuid::Uuid,
    should_apply_runtime_revision: bool,
) -> RoundStatus<HashSet<String>> {
    if !should_apply_runtime_revision {
        return RoundStatus::Ready(
            req.running_network_instances
                .iter()
                .map(|x| x.to_string())
                .collect(),
        );
    }

    match rpc_client
        .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
        .await
    {
        Ok(resp) => RoundStatus::Ready(resp.inst_ids.iter().map(|x| x.to_string()).collect()),
        Err(error) => {
            tracing::warn!(
                ?user_id,
                ?machine_id,
                ?error,
                "Failed to refresh running instances for managed config revision"
            );
            RoundStatus::Skip
        }
    }
}

async fn sync_running_sources_for_round(
    rpc_client: &mut SessionRpcClient,
    storage: &StorageInner,
    round: &mut ReconcileRound,
) -> RoundStatus<Option<Vec<NetworkMeta>>> {
    if !round.req.support_config_source {
        return RoundStatus::Ready(None);
    }

    let ret = if round.running_inst_ids.is_empty() {
        Ok(Vec::new())
    } else {
        rpc_client
            .list_network_instance_meta(
                BaseController::default(),
                ListNetworkInstanceMetaRequest {
                    inst_ids: managed_config::parse_instance_ids(
                        round.running_inst_ids.iter().cloned(),
                    ),
                },
            )
            .await
            .map(|resp| resp.metas)
    };

    match ret {
        Ok(metas) => {
            if let Err(e) = managed_config::sync_running_config_sources(
                &storage.db,
                round.user_id,
                round.machine_id,
                &round.local_configs,
                &metas,
            )
            .await
            {
                tracing::warn!(
                    user_id = ?round.user_id,
                    machine_id = ?round.machine_id,
                    %e,
                    "Failed to sync running network config sources"
                );
            } else if !metas.is_empty() {
                round.local_configs = match storage
                    .db
                    .list_network_configs(
                        (round.user_id, round.machine_id),
                        ListNetworkProps::EnabledOnly,
                    )
                    .await
                {
                    Ok(configs) => configs,
                    Err(e) => {
                        tracing::error!(
                            "Failed to reload network configs after source sync, error: {:?}",
                            e
                        );
                        return RoundStatus::Stop;
                    }
                };
            }
            RoundStatus::Ready(Some(metas))
        }
        Err(e) => {
            tracing::warn!(
                user_id = ?round.user_id,
                %e,
                "Failed to list running network instance metadata"
            );
            RoundStatus::Ready(None)
        }
    }
}

async fn cleanup_stale_web_source_instances(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage: &StorageInner,
    rpc_client: &mut SessionRpcClient,
    round: &ReconcileRound,
    running_metas: Option<&[NetworkMeta]>,
    desired_web_inst_ids: &HashSet<String>,
    cache: &mut ReconcileCache,
) -> RoundStatus<ReconcileOutcome> {
    let desired_changed = cache
        .last_desired_web_inst_ids
        .as_ref()
        .is_none_or(|last| last != desired_web_inst_ids);
    if cache.cleaned_web_source_instances && !desired_changed {
        return RoundStatus::Ready(ReconcileOutcome::default());
    }

    let db_web_inst_ids = match storage
        .db
        .list_network_configs((round.user_id, round.machine_id), ListNetworkProps::All)
        .await
    {
        Ok(configs) => managed_config::desired_web_source_instance_ids(&configs),
        Err(e) => {
            tracing::error!("Failed to list all network configs, error: {:?}", e);
            return RoundStatus::Stop;
        }
    };

    let running_web_inst_ids = managed_config::running_web_source_instance_ids(
        &round.running_inst_ids,
        &db_web_inst_ids,
        running_metas,
    );
    let should_delete_ids = managed_config::parse_instance_ids(
        running_web_inst_ids
            .difference(desired_web_inst_ids)
            .cloned(),
    );

    let mut outcome = ReconcileOutcome::default();
    if !should_delete_ids.is_empty() {
        if !SessionRpcService::runtime_heartbeat_is_current(session_data, &round.req).await {
            tracing::debug!(
                machine_id = ?round.machine_id,
                "skip stale cleanup because webhook session is no longer current"
            );
            return RoundStatus::Skip;
        }
        let ret = rpc_client
            .delete_network_instance(
                BaseController::default(),
                DeleteNetworkInstanceRequest {
                    inst_ids: should_delete_ids,
                },
            )
            .await;
        tracing::info!(
            user_id = ?round.user_id,
            "Clean stale web-source network instances on heartbeat: {:?}, user_token: {:?}",
            ret,
            round.req.user_token
        );
        if ret.is_err() {
            outcome.record_failure(true);
        }
    }

    if !outcome.has_failed {
        cache.cleaned_web_source_instances = true;
        cache.last_desired_web_inst_ids = Some(desired_web_inst_ids.clone());
    }

    RoundStatus::Ready(outcome)
}

async fn reconcile_desired_runtime_configs(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    rpc_client: &mut SessionRpcClient,
    config_client: &mut SessionConfigClient,
    round: &ReconcileRound,
) -> ReconcileOutcome {
    let mut outcome = ReconcileOutcome::default();

    // After stale web-owned instances are removed, start every enabled
    // config that the latest heartbeat did not report as running. When
    // a managed config revision is pending, also reconcile running
    // web-owned configs before reporting that revision as applied.
    for config in &round.local_configs {
        let source = PersistedConfigSource::from_db(&config.source);
        let is_running = round.running_inst_ids.contains(&config.network_instance_id);
        let should_reconcile_running_web_config = is_running
            && round.should_apply_runtime_revision
            && source == PersistedConfigSource::Web;
        if is_running && !should_reconcile_running_web_config {
            continue;
        }

        let network_config = match serde_json::from_str::<NetworkConfig>(&config.network_config) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!(
                    user_id = ?round.user_id,
                    machine_id = ?round.machine_id,
                    instance_id = %config.network_instance_id,
                    "Failed to deserialize network config, skipping: {:?}",
                    e
                );
                outcome.record_failure(source == PersistedConfigSource::Web);
                continue;
            }
        };

        let action_result = if should_reconcile_running_web_config {
            reconcile_running_web_config(
                session_data,
                rpc_client,
                config_client,
                round,
                config,
                network_config,
            )
            .await
        } else {
            run_missing_network_config(session_data, rpc_client, round, config, network_config)
                .await
        };

        match action_result {
            ConfigActionResult::Success => {}
            ConfigActionResult::Failed => {
                outcome.record_failure(source == PersistedConfigSource::Web)
            }
            ConfigActionResult::StopRound => {
                outcome.record_failure(source == PersistedConfigSource::Web);
                break;
            }
        }
    }

    outcome
}

async fn reconcile_running_web_config(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    rpc_client: &mut SessionRpcClient,
    config_client: &mut SessionConfigClient,
    round: &ReconcileRound,
    config: &crate::db::entity::user_running_network_configs::Model,
    network_config: NetworkConfig,
) -> ConfigActionResult {
    if !SessionRpcService::runtime_heartbeat_is_current(session_data, &round.req).await {
        tracing::debug!(
            machine_id = ?round.machine_id,
            instance_id = %config.network_instance_id,
            "skip runtime reconcile because webhook session is no longer current"
        );
        return ConfigActionResult::StopRound;
    }

    let ret = async {
        let action = runtime_reconcile::prepare_web_source_runtime_reconcile(
            &mut *rpc_client,
            &config.network_instance_id,
            network_config.clone(),
            true,
        )
        .await?;
        if !SessionRpcService::runtime_heartbeat_is_current(session_data, &round.req).await {
            anyhow::bail!("webhook session is no longer current before runtime reconcile apply");
        }
        runtime_reconcile::apply_web_source_runtime_reconcile(
            &mut *rpc_client,
            &mut *config_client,
            &config.network_instance_id,
            network_config,
            action,
        )
        .await
    }
    .await;
    tracing::info!(
        user_id = ?round.user_id,
        instance_id = %config.network_instance_id,
        "Reconcile running web-source network instance: {:?}, user_token: {:?}",
        ret,
        round.req.user_token
    );

    if ret.is_ok() {
        ConfigActionResult::Success
    } else {
        ConfigActionResult::Failed
    }
}

async fn run_missing_network_config(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    rpc_client: &mut SessionRpcClient,
    round: &ReconcileRound,
    config: &crate::db::entity::user_running_network_configs::Model,
    network_config: NetworkConfig,
) -> ConfigActionResult {
    if !SessionRpcService::runtime_heartbeat_is_current(session_data, &round.req).await {
        tracing::debug!(
            machine_id = ?round.machine_id,
            instance_id = %config.network_instance_id,
            "skip run network instance because webhook session is no longer current"
        );
        return ConfigActionResult::StopRound;
    }

    let ret = rpc_client
        .run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest {
                inst_id: Some(config.network_instance_id.clone().into()),
                config: Some(network_config),
                overwrite: false,
                source: PersistedConfigSource::from_db(&config.source).auto_run_rpc_source() as i32,
            },
        )
        .await;
    tracing::info!(
        user_id = ?round.user_id,
        "Run network instance: {:?}, user_token: {:?}",
        ret,
        round.req.user_token
    );

    if ret.is_ok() {
        ConfigActionResult::Success
    } else {
        ConfigActionResult::Failed
    }
}

async fn mark_config_revision_applied_if_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage: &StorageInner,
    round: &ReconcileRound,
    outcome: &ReconcileOutcome,
) -> RoundStatus<()> {
    if outcome.managed_revision_failed || !round.should_apply_runtime_revision {
        return RoundStatus::Ready(());
    }

    let current_target_config_revision = match storage
        .db
        .get_managed_config_revision((round.user_id, round.machine_id))
        .await
    {
        Ok(revision) => revision,
        Err(e) => {
            tracing::error!("Failed to verify managed config revision, error: {:?}", e);
            return RoundStatus::Stop;
        }
    };
    if current_target_config_revision != round.target_config_revision {
        return RoundStatus::Ready(());
    }
    let Some(data) = session_data.upgrade() else {
        return RoundStatus::Stop;
    };
    let mut data = data.write().await;
    if !SessionRpcService::runtime_heartbeat_is_current_locked(&data, &round.req) {
        return RoundStatus::Ready(());
    }
    data.applied_config_revision = round.target_config_revision.clone();

    RoundStatus::Ready(())
}
