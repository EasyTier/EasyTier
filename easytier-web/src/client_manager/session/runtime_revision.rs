use std::collections::{HashMap, HashSet};

use easytier::proto::{
    api::manage::{
        DeleteNetworkInstanceRequest, DeleteNetworkInstanceResponse,
        ListNetworkInstanceMetaRequest, ListNetworkInstanceRequest, NetworkConfig, NetworkMeta,
        RunNetworkInstanceRequest,
    },
    rpc_types::controller::BaseController,
    web::HeartbeatRequest,
};
use easytier_core::management::remote_client::{ListNetworkProps, Storage as _};
use tokio::sync::{RwLock, broadcast};

use super::{
    ManagedConfigReconcileHint, SessionConfigClient, SessionData, SessionRpcClient,
    SessionRpcService,
};
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
        cache.reset_if_runtime_config_cache_epoch_changed(round.runtime_config_cache_epoch);
        let running_metas =
            match sync_running_sources_for_round(&mut rpc_client, &storage, &mut round).await {
                RoundStatus::Ready(running_metas) => running_metas,
                RoundStatus::Skip => continue,
                RoundStatus::Stop => return,
            };
        let mut mutation_fence = RuntimeMutationFence::default();
        let context = ReconcileRoundContext {
            session_data: &session_data,
            round: &round,
        };

        let mut outcome = match &round.scope {
            ReconcileScope::Full => {
                let desired_web_inst_ids =
                    managed_config::desired_web_source_instance_ids(&round.local_configs);
                cache.runtime_configs.retain_desired(&desired_web_inst_ids);
                match cleanup_stale_web_source_instances(
                    &context,
                    &storage,
                    &mut rpc_client,
                    running_metas.as_deref(),
                    &desired_web_inst_ids,
                    &mut cache,
                    &mut mutation_fence,
                )
                .await
                {
                    RoundStatus::Ready(outcome) => outcome,
                    RoundStatus::Skip => continue,
                    RoundStatus::Stop => return,
                }
            }
            ReconcileScope::Patch { .. } => {
                match cleanup_patch_deleted_instances(
                    &session_data,
                    &mut rpc_client,
                    &round,
                    running_metas.as_deref(),
                    &round.delete_instance_ids,
                    &mut cache,
                    &mut mutation_fence,
                )
                .await
                {
                    RoundStatus::Ready(outcome) => outcome,
                    RoundStatus::Skip => continue,
                    RoundStatus::Stop => return,
                }
            }
        };

        outcome.merge(
            reconcile_desired_runtime_configs(
                &context,
                &mut rpc_client,
                &mut config_client,
                &mut cache,
                &mut mutation_fence,
            )
            .await,
        );

        if !outcome.has_failed {
            match &round.scope {
                ReconcileScope::Full => {
                    cache.last_desired_web_inst_ids = Some(
                        managed_config::desired_web_source_instance_ids(&round.local_configs),
                    );
                }
                ReconcileScope::Patch { dirty_instance_ids } => {
                    if let Some(last) = &mut cache.last_desired_web_inst_ids {
                        last.retain(|id| !dirty_instance_ids.contains(id));
                        last.extend(
                            round
                                .local_configs
                                .iter()
                                .map(|config| config.network_instance_id.clone()),
                        );
                    }
                }
            }
        }

        match mark_config_revision_applied_if_current(
            &session_data,
            &storage,
            &round,
            &outcome,
            &mutation_fence,
        )
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
    runtime_config_cache_epoch: u64,
    cleaned_web_source_instances: bool,
    last_desired_web_inst_ids: Option<HashSet<String>>,
    runtime_configs: SessionRuntimeConfigCache,
}

impl ReconcileCache {
    fn reset_if_runtime_config_cache_epoch_changed(&mut self, current_epoch: u64) {
        if self.runtime_config_cache_epoch == current_epoch {
            return;
        }
        *self = Self {
            runtime_config_cache_epoch: current_epoch,
            ..Default::default()
        };
    }
}

#[derive(Default)]
struct SessionRuntimeConfigCache {
    entries: HashMap<String, NetworkConfig>,
}

impl SessionRuntimeConfigCache {
    fn plan(
        &self,
        inst_id: &str,
        desired_config: NetworkConfig,
    ) -> anyhow::Result<Option<runtime_reconcile::RuntimeReconcileAction>> {
        let Some(observed_config) = self.entries.get(inst_id) else {
            return Ok(None);
        };

        runtime_reconcile::prepare_web_source_runtime_reconcile_from_current(
            observed_config,
            desired_config,
        )
        .map(Some)
    }

    fn remember(&mut self, inst_id: &str, observed_config: NetworkConfig) {
        self.entries.insert(inst_id.to_string(), observed_config);
    }

    fn forget(&mut self, inst_id: &str) {
        self.entries.remove(inst_id);
    }

    fn forget_many<'a>(&mut self, inst_ids: impl IntoIterator<Item = &'a String>) {
        for inst_id in inst_ids {
            self.entries.remove(inst_id);
        }
    }

    fn retain_desired(&mut self, desired_web_inst_ids: &HashSet<String>) {
        self.entries
            .retain(|inst_id, _| desired_web_inst_ids.contains(inst_id));
    }
}

#[derive(Default)]
struct ReconcileOutcome {
    has_failed: bool,
    managed_revision_failed: bool,
}

#[derive(Default)]
struct RuntimeMutationFence {
    started: bool,
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
    delete_instance_ids: HashSet<String>,
    target_config_revision: Option<String>,
    should_apply_runtime_revision: bool,
    scope: ReconcileScope,
    runtime_config_epoch: u64,
    runtime_config_cache_epoch: u64,
}

struct ReconcileRoundContext<'a> {
    session_data: &'a std::sync::Weak<RwLock<SessionData>>,
    round: &'a ReconcileRound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReconcileScope {
    Full,
    Patch { dirty_instance_ids: HashSet<String> },
}

fn select_reconcile_scope(
    pending: Option<&ManagedConfigReconcileHint>,
    known_runtime_base_revision: Option<&str>,
    target_revision: Option<&str>,
) -> ReconcileScope {
    match pending {
        Some(ManagedConfigReconcileHint::Dirty {
            expected_revision,
            target_revision: dirty_target,
            instance_ids,
        }) if known_runtime_base_revision == Some(expected_revision.as_str())
            && target_revision == Some(dirty_target.as_str()) =>
        {
            ReconcileScope::Patch {
                dirty_instance_ids: instance_ids.clone(),
            }
        }
        _ => ReconcileScope::Full,
    }
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
            return RoundStatus::Skip;
        }
        Err(e) => {
            tracing::error!("Failed to get user id by token, error: {:?}", e);
            return RoundStatus::Skip;
        }
    };

    let (
        applied_config_revision,
        known_runtime_base_revision,
        pending_reconcile,
        runtime_config_epoch,
        runtime_config_cache_epoch,
    ) = {
        let Some(data) = session_data.upgrade() else {
            return RoundStatus::Stop;
        };
        let data = data.read().await;
        (
            data.applied_config_revision.clone(),
            data.known_runtime_base_revision.clone(),
            data.pending_managed_config_reconcile.clone(),
            data.runtime_config_epoch,
            data.runtime_config_cache_epoch,
        )
    };
    let target_config_revision =
        match read_managed_config_revision(storage, user_id, machine_id).await {
            RoundStatus::Ready(revision) => revision,
            RoundStatus::Skip => return RoundStatus::Skip,
            RoundStatus::Stop => return RoundStatus::Stop,
        };
    let should_apply_runtime_revision =
        target_config_revision.is_some() && target_config_revision != applied_config_revision;
    let mut scope = if should_apply_runtime_revision {
        select_reconcile_scope(
            pending_reconcile.as_ref(),
            known_runtime_base_revision.as_deref(),
            target_config_revision.as_deref(),
        )
    } else {
        ReconcileScope::Full
    };
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

    let (local_configs, delete_instance_ids) = match load_round_configs(
        storage, user_id, machine_id, &scope,
    )
    .await
    {
        Ok(Some(configs)) => configs,
        Ok(None) => {
            tracing::warn!(
                ?user_id,
                ?machine_id,
                "Managed config dirty instance is no longer a web-owned row; using Full reconcile"
            );
            scope = ReconcileScope::Full;
            match storage
                .db
                .list_network_configs((user_id, machine_id), ListNetworkProps::EnabledOnly)
                .await
            {
                Ok(configs) => (configs, HashSet::new()),
                Err(e) => {
                    tracing::error!("Failed to list network configs, error: {:?}", e);
                    return RoundStatus::Skip;
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to load managed config Patch rows, error: {:?}", e);
            return RoundStatus::Skip;
        }
    };

    RoundStatus::Ready(ReconcileRound {
        req,
        machine_id,
        user_id,
        running_inst_ids,
        local_configs,
        delete_instance_ids,
        target_config_revision,
        should_apply_runtime_revision,
        scope,
        runtime_config_epoch,
        runtime_config_cache_epoch,
    })
}

async fn read_managed_config_revision(
    storage: &StorageInner,
    user_id: i32,
    machine_id: uuid::Uuid,
) -> RoundStatus<Option<String>> {
    match storage
        .db
        .get_managed_config_revision((user_id, machine_id))
        .await
    {
        Ok(revision) => RoundStatus::Ready(revision),
        Err(e) => {
            tracing::error!("Failed to read managed config revision, error: {:?}", e);
            RoundStatus::Skip
        }
    }
}

async fn load_round_configs(
    storage: &StorageInner,
    user_id: i32,
    machine_id: uuid::Uuid,
    scope: &ReconcileScope,
) -> Result<
    Option<(
        Vec<crate::db::entity::user_running_network_configs::Model>,
        HashSet<String>,
    )>,
    sea_orm::DbErr,
> {
    let ReconcileScope::Patch { dirty_instance_ids } = scope else {
        return storage
            .db
            .list_network_configs((user_id, machine_id), ListNetworkProps::EnabledOnly)
            .await
            .map(|configs| Some((configs, HashSet::new())));
    };

    let mut instance_ids = dirty_instance_ids.iter().collect::<Vec<_>>();
    instance_ids.sort_unstable();
    let mut configs = Vec::with_capacity(instance_ids.len());
    let mut delete_instance_ids = HashSet::new();
    for instance_id in instance_ids {
        let config = storage
            .db
            .get_network_config((user_id, machine_id), instance_id)
            .await?;
        match config {
            Some(config)
                if !config.disabled
                    && PersistedConfigSource::from_db(&config.source)
                        == PersistedConfigSource::Web =>
            {
                configs.push(config);
            }
            None => {
                delete_instance_ids.insert(instance_id.clone());
            }
            Some(_) => return Ok(None),
        }
    }
    Ok(Some((configs, delete_instance_ids)))
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
            } else if !metas.is_empty() && matches!(round.scope, ReconcileScope::Full) {
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
                        return RoundStatus::Skip;
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
    context: &ReconcileRoundContext<'_>,
    storage: &StorageInner,
    rpc_client: &mut SessionRpcClient,
    running_metas: Option<&[NetworkMeta]>,
    desired_web_inst_ids: &HashSet<String>,
    cache: &mut ReconcileCache,
    mutation_fence: &mut RuntimeMutationFence,
) -> RoundStatus<ReconcileOutcome> {
    let session_data = context.session_data;
    let round = context.round;
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
            return RoundStatus::Skip;
        }
    };

    let running_web_inst_ids = managed_config::running_web_source_instance_ids(
        &round.running_inst_ids,
        &db_web_inst_ids,
        running_metas,
    );
    let should_delete_inst_ids = running_web_inst_ids
        .difference(desired_web_inst_ids)
        .cloned()
        .collect::<HashSet<_>>();
    let should_delete_ids =
        managed_config::parse_instance_ids(should_delete_inst_ids.iter().cloned());

    let mut outcome = ReconcileOutcome::default();
    if !should_delete_ids.is_empty() {
        if !begin_managed_runtime_mutation(session_data, round, mutation_fence).await {
            tracing::debug!(
                machine_id = ?round.machine_id,
                "skip stale cleanup because the managed runtime fence is no longer current"
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
        match ret {
            Err(_) => outcome.record_failure(true),
            Ok(response) => {
                let undeleted_instance_ids =
                    retained_requested_instance_ids(response, &should_delete_inst_ids);
                if undeleted_instance_ids.is_empty() {
                    cache.runtime_configs.forget_many(&should_delete_inst_ids);
                } else {
                    tracing::warn!(
                        user_id = ?round.user_id,
                        machine_id = ?round.machine_id,
                        instance_ids = ?undeleted_instance_ids,
                        "Stale managed instances were retained by the runtime"
                    );
                    outcome.record_failure(true);
                }
            }
        }
    }

    if !outcome.has_failed {
        cache.cleaned_web_source_instances = true;
        cache.last_desired_web_inst_ids = Some(desired_web_inst_ids.clone());
    }

    RoundStatus::Ready(outcome)
}

async fn cleanup_patch_deleted_instances(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    rpc_client: &mut SessionRpcClient,
    round: &ReconcileRound,
    running_metas: Option<&[NetworkMeta]>,
    delete_instance_ids: &HashSet<String>,
    cache: &mut ReconcileCache,
    mutation_fence: &mut RuntimeMutationFence,
) -> RoundStatus<ReconcileOutcome> {
    let running_web_instance_ids: HashSet<String> = match running_metas {
        Some(metas) => managed_config::running_web_source_instance_ids(
            &round.running_inst_ids,
            delete_instance_ids,
            Some(metas),
        )
        .intersection(delete_instance_ids)
        .cloned()
        .collect(),
        None => round
            .running_inst_ids
            .intersection(delete_instance_ids)
            .cloned()
            .collect(),
    };
    if running_web_instance_ids.is_empty() {
        cache
            .runtime_configs
            .forget_many(delete_instance_ids.iter());
        return RoundStatus::Ready(ReconcileOutcome::default());
    }
    if !begin_managed_runtime_mutation(session_data, round, mutation_fence).await {
        tracing::debug!(
            machine_id = ?round.machine_id,
            "skip managed config Patch cleanup because the runtime fence is no longer current"
        );
        return RoundStatus::Skip;
    }

    let ret = rpc_client
        .delete_network_instance(
            BaseController::default(),
            DeleteNetworkInstanceRequest {
                inst_ids: managed_config::parse_instance_ids(
                    running_web_instance_ids.iter().cloned(),
                ),
            },
        )
        .await;
    tracing::info!(
        user_id = ?round.user_id,
        deleted_instance_ids = ?running_web_instance_ids,
        "Apply managed config Patch deletions at runtime: {:?}",
        ret
    );

    let mut outcome = ReconcileOutcome::default();
    match ret {
        Err(_) => outcome.record_failure(true),
        Ok(response) => {
            let undeleted_instance_ids =
                retained_requested_instance_ids(response, &running_web_instance_ids);
            if undeleted_instance_ids.is_empty() {
                cache
                    .runtime_configs
                    .forget_many(delete_instance_ids.iter());
            } else {
                tracing::warn!(
                    user_id = ?round.user_id,
                    machine_id = ?round.machine_id,
                    instance_ids = ?undeleted_instance_ids,
                    "Managed config Patch deletion was retained by the runtime"
                );
                outcome.record_failure(true);
            }
        }
    }
    RoundStatus::Ready(outcome)
}

async fn begin_managed_runtime_mutation(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    round: &ReconcileRound,
    mutation_fence: &mut RuntimeMutationFence,
) -> bool {
    let Some(data) = session_data.upgrade() else {
        return false;
    };
    let mut data = data.write().await;
    if !SessionRpcService::runtime_heartbeat_is_current_or_invalidate_locked(&mut data, &round.req)
        || data.runtime_config_epoch != round.runtime_config_epoch
    {
        return false;
    }
    if !mutation_fence.started {
        data.applied_config_revision = None;
        if matches!(round.scope, ReconcileScope::Full) {
            data.known_runtime_base_revision = None;
        }
        mutation_fence.started = true;
    }
    true
}

fn retained_requested_instance_ids(
    response: DeleteNetworkInstanceResponse,
    requested_instance_ids: &HashSet<String>,
) -> HashSet<String> {
    response
        .remain_inst_ids
        .into_iter()
        .map(|instance_id| uuid::Uuid::from(instance_id).to_string())
        .filter(|instance_id| requested_instance_ids.contains(instance_id))
        .collect()
}

async fn reconcile_desired_runtime_configs(
    context: &ReconcileRoundContext<'_>,
    rpc_client: &mut SessionRpcClient,
    config_client: &mut SessionConfigClient,
    cache: &mut ReconcileCache,
    mutation_fence: &mut RuntimeMutationFence,
) -> ReconcileOutcome {
    let session_data = context.session_data;
    let round = context.round;
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

        let desired_config = match serde_json::from_str::<NetworkConfig>(&config.network_config) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!(
                    user_id = ?round.user_id,
                    machine_id = ?round.machine_id,
                    instance_id = %config.network_instance_id,
                    "Failed to deserialize network config, skipping: {:?}",
                    e
                );
                if source == PersistedConfigSource::Web {
                    cache.runtime_configs.forget(&config.network_instance_id);
                }
                outcome.record_failure(source == PersistedConfigSource::Web);
                continue;
            }
        };

        let action_result = if should_reconcile_running_web_config {
            reconcile_running_web_config(
                context,
                rpc_client,
                config_client,
                config,
                desired_config,
                &mut cache.runtime_configs,
                mutation_fence,
            )
            .await
        } else {
            if source == PersistedConfigSource::Web {
                cache.runtime_configs.forget(&config.network_instance_id);
            }
            let action_result = run_missing_network_config(
                session_data,
                rpc_client,
                round,
                config,
                desired_config.clone(),
                mutation_fence,
            )
            .await;
            if matches!(action_result, ConfigActionResult::Success)
                && source == PersistedConfigSource::Web
            {
                if let Err(e) = remember_web_runtime_config_after_run(
                    rpc_client,
                    &config.network_instance_id,
                    &desired_config,
                    &mut cache.runtime_configs,
                )
                .await
                {
                    tracing::error!(
                        user_id = ?round.user_id,
                        machine_id = ?round.machine_id,
                        instance_id = %config.network_instance_id,
                        "Failed to cache runtime config after run: {:?}",
                        e
                    );
                    ConfigActionResult::Failed
                } else {
                    action_result
                }
            } else {
                action_result
            }
        };

        match action_result {
            ConfigActionResult::Success => {}
            ConfigActionResult::Failed => {
                if source == PersistedConfigSource::Web {
                    cache.runtime_configs.forget(&config.network_instance_id);
                }
                outcome.record_failure(source == PersistedConfigSource::Web)
            }
            ConfigActionResult::StopRound => {
                if source == PersistedConfigSource::Web {
                    cache.runtime_configs.forget(&config.network_instance_id);
                }
                outcome.record_failure(source == PersistedConfigSource::Web);
                break;
            }
        }
    }

    outcome
}

async fn reconcile_running_web_config(
    context: &ReconcileRoundContext<'_>,
    rpc_client: &mut SessionRpcClient,
    config_client: &mut SessionConfigClient,
    config: &crate::db::entity::user_running_network_configs::Model,
    desired_config: NetworkConfig,
    runtime_config_cache: &mut SessionRuntimeConfigCache,
    mutation_fence: &mut RuntimeMutationFence,
) -> ConfigActionResult {
    let session_data = context.session_data;
    let round = context.round;
    if !SessionRpcService::runtime_heartbeat_is_current(session_data, &round.req).await {
        tracing::debug!(
            machine_id = ?round.machine_id,
            instance_id = %config.network_instance_id,
            "skip runtime reconcile because webhook session is no longer current"
        );
        return ConfigActionResult::StopRound;
    }

    let ret = async {
        let action =
            match runtime_config_cache.plan(&config.network_instance_id, desired_config.clone())? {
                Some(action) => action,
                None => {
                    runtime_reconcile::prepare_web_source_runtime_reconcile(
                        &mut *rpc_client,
                        &config.network_instance_id,
                        desired_config.clone(),
                        true,
                    )
                    .await?
                }
            };
        if !SessionRpcService::runtime_heartbeat_is_current(session_data, &round.req).await {
            anyhow::bail!("webhook session is no longer current before runtime reconcile apply");
        }
        if !matches!(
            action,
            runtime_reconcile::RuntimeReconcileAction::Unchanged(_)
        ) && !begin_managed_runtime_mutation(session_data, round, mutation_fence).await
        {
            anyhow::bail!("managed runtime mutation fence is no longer current");
        }
        let observed_config = runtime_reconcile::apply_web_source_runtime_reconcile(
            &mut *rpc_client,
            &mut *config_client,
            &config.network_instance_id,
            desired_config.clone(),
            action,
        )
        .await?;
        runtime_config_cache.remember(&config.network_instance_id, observed_config);
        Ok::<(), anyhow::Error>(())
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
        runtime_config_cache.forget(&config.network_instance_id);
        ConfigActionResult::Failed
    }
}

async fn run_missing_network_config(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    rpc_client: &mut SessionRpcClient,
    round: &ReconcileRound,
    config: &crate::db::entity::user_running_network_configs::Model,
    desired_config: NetworkConfig,
    mutation_fence: &mut RuntimeMutationFence,
) -> ConfigActionResult {
    if !SessionRpcService::runtime_heartbeat_is_current(session_data, &round.req).await {
        tracing::debug!(
            machine_id = ?round.machine_id,
            instance_id = %config.network_instance_id,
            "skip run network instance because webhook session is no longer current"
        );
        return ConfigActionResult::StopRound;
    }

    let source = PersistedConfigSource::from_db(&config.source);
    if source == PersistedConfigSource::Web
        && !begin_managed_runtime_mutation(session_data, round, mutation_fence).await
    {
        tracing::debug!(
            machine_id = ?round.machine_id,
            instance_id = %config.network_instance_id,
            "skip run network instance because the managed runtime fence is no longer current"
        );
        return ConfigActionResult::StopRound;
    }

    let ret = rpc_client
        .run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest {
                inst_id: Some(config.network_instance_id.clone().into()),
                config: Some(desired_config),
                overwrite: false,
                source: source.auto_run_rpc_source() as i32,
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

async fn remember_web_runtime_config_after_run(
    rpc_client: &mut SessionRpcClient,
    inst_id: &str,
    desired_config: &NetworkConfig,
    runtime_config_cache: &mut SessionRuntimeConfigCache,
) -> anyhow::Result<()> {
    let observed_config = runtime_reconcile::get_runtime_config(rpc_client, inst_id).await?;
    remember_if_runtime_matches_desired(
        inst_id,
        desired_config,
        observed_config,
        runtime_config_cache,
    )
}

fn remember_if_runtime_matches_desired(
    inst_id: &str,
    desired_config: &NetworkConfig,
    observed_config: NetworkConfig,
    runtime_config_cache: &mut SessionRuntimeConfigCache,
) -> anyhow::Result<()> {
    let action = runtime_reconcile::prepare_web_source_runtime_reconcile_from_current(
        &observed_config,
        desired_config.clone(),
    )?;
    if !matches!(
        action,
        runtime_reconcile::RuntimeReconcileAction::Unchanged(_)
    ) {
        anyhow::bail!("runtime config still differs after managed run");
    }
    runtime_config_cache.remember(inst_id, observed_config);
    Ok(())
}

async fn mark_config_revision_applied_if_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage: &StorageInner,
    round: &ReconcileRound,
    outcome: &ReconcileOutcome,
    mutation_fence: &RuntimeMutationFence,
) -> RoundStatus<()> {
    if outcome.managed_revision_failed
        || (!round.should_apply_runtime_revision && !mutation_fence.started)
    {
        return RoundStatus::Ready(());
    }

    let current_target_config_revision =
        match read_managed_config_revision(storage, round.user_id, round.machine_id).await {
            RoundStatus::Ready(revision) => revision,
            RoundStatus::Skip => return RoundStatus::Skip,
            RoundStatus::Stop => return RoundStatus::Stop,
        };
    if current_target_config_revision != round.target_config_revision {
        return RoundStatus::Ready(());
    }
    let Some(data) = session_data.upgrade() else {
        return RoundStatus::Stop;
    };
    let notify = {
        let mut data = data.write().await;
        if !SessionRpcService::runtime_heartbeat_is_current_or_invalidate_locked(
            &mut data, &round.req,
        ) {
            return RoundStatus::Ready(());
        }
        if data.runtime_config_epoch != round.runtime_config_epoch {
            return RoundStatus::Ready(());
        }
        record_applied_config_revision(&mut data, round.target_config_revision.clone())
    };
    if let Some(notify) = notify {
        notify.notify_one();
    }

    RoundStatus::Ready(())
}

fn record_applied_config_revision(
    data: &mut SessionData,
    revision: Option<String>,
) -> Option<std::sync::Arc<tokio::sync::Notify>> {
    let changed = data.applied_config_revision != revision;
    data.known_runtime_base_revision = revision.clone();
    data.applied_config_revision = revision;
    data.pending_managed_config_reconcile = None;
    changed.then(|| SessionRpcService::mark_webhook_validation_state_changed_locked(data))
}

#[cfg(test)]
mod tests {
    use easytier::proto::api::manage::{NetworkingMethod, PortForwardConfig};

    use super::*;

    fn config_with_port_forwards(port_forwards: Vec<PortForwardConfig>) -> NetworkConfig {
        NetworkConfig {
            instance_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
            dhcp: Some(true),
            network_name: Some("managed".to_string()),
            network_secret: Some("secret".to_string()),
            networking_method: Some(NetworkingMethod::Manual as i32),
            port_forwards,
            ..Default::default()
        }
    }

    fn port_forward(bind_port: u32, dst_port: u32) -> PortForwardConfig {
        PortForwardConfig {
            bind_ip: "127.0.0.1".to_string(),
            bind_port,
            dst_ip: "10.144.0.1".to_string(),
            dst_port,
            proto: "tcp".to_string(),
        }
    }

    #[tokio::test]
    async fn managed_revision_read_failure_retries_on_a_later_round() {
        let storage =
            crate::client_manager::storage::Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let machine_id = uuid::Uuid::new_v4();
        let pool = storage.db().inner();
        sqlx::query("DROP TABLE managed_config_revisions")
            .execute(&pool)
            .await
            .unwrap();
        let storage_inner = storage.weak_ref().upgrade().unwrap();

        assert!(matches!(
            read_managed_config_revision(&storage_inner, user_id, machine_id).await,
            RoundStatus::Skip
        ));

        sqlx::query(
            r#"
            CREATE TABLE managed_config_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                config_revision TEXT NOT NULL,
                create_time TEXT NOT NULL,
                update_time TEXT NOT NULL,
                CONSTRAINT fk_managed_config_revisions_user_id_to_users_id
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE UNIQUE INDEX idx_managed_config_revisions_scope \
             ON managed_config_revisions(user_id, device_id)",
        )
        .execute(&pool)
        .await
        .unwrap();
        storage
            .db()
            .set_managed_config_revision((user_id, machine_id), "rev-recovered")
            .await
            .unwrap();

        assert!(matches!(
            read_managed_config_revision(&storage_inner, user_id, machine_id).await,
            RoundStatus::Ready(Some(revision)) if revision == "rev-recovered"
        ));
    }

    #[tokio::test]
    async fn newly_applied_revision_wakes_webhook_validation() {
        let storage =
            crate::client_manager::storage::Storage::new(crate::db::Db::memory_db().await);
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            std::sync::Arc::new(crate::FeatureFlags::default()),
            std::sync::Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        data.pending_managed_config_reconcile = Some(ManagedConfigReconcileHint::Dirty {
            expected_revision: "rev-a".to_string(),
            target_revision: "rev-b".to_string(),
            instance_ids: HashSet::from(["managed".to_string()]),
        });

        let notify = record_applied_config_revision(&mut data, Some("rev-applied".to_string()))
            .expect("new applied revision should wake validation");
        assert_eq!(data.applied_config_revision.as_deref(), Some("rev-applied"));
        assert_eq!(
            data.known_runtime_base_revision.as_deref(),
            Some("rev-applied")
        );
        assert_eq!(data.pending_managed_config_reconcile, None);
        assert!(data.webhook_validation_dirty);
        assert_eq!(data.webhook_validation_change_epoch, 1);

        notify.notify_one();
        tokio::time::timeout(std::time::Duration::from_millis(100), notify.notified())
            .await
            .expect("validation worker was not notified");
    }

    #[tokio::test]
    async fn unchanged_applied_revision_does_not_add_validation_work() {
        let storage =
            crate::client_manager::storage::Storage::new(crate::db::Db::memory_db().await);
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            std::sync::Arc::new(crate::FeatureFlags::default()),
            std::sync::Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        data.applied_config_revision = Some("rev-applied".to_string());

        assert!(
            record_applied_config_revision(&mut data, Some("rev-applied".to_string())).is_none()
        );
        assert_eq!(
            data.known_runtime_base_revision.as_deref(),
            Some("rev-applied")
        );
        assert!(!data.webhook_validation_dirty);
    }

    #[test]
    fn patch_delete_requires_runtime_to_remove_every_requested_instance() {
        let deleted_id = uuid::Uuid::new_v4();
        let requested = HashSet::from([deleted_id.to_string()]);

        assert_eq!(
            retained_requested_instance_ids(
                DeleteNetworkInstanceResponse {
                    remain_inst_ids: vec![deleted_id.into()],
                },
                &requested,
            ),
            requested
        );
        assert!(
            retained_requested_instance_ids(
                DeleteNetworkInstanceResponse {
                    remain_inst_ids: Vec::new(),
                },
                &requested,
            )
            .is_empty()
        );
    }

    #[tokio::test]
    async fn managed_runtime_mutation_preserves_base_only_for_patch_scope() {
        let machine_id = uuid::Uuid::new_v4();
        let req = HeartbeatRequest {
            user_token: "token".to_string(),
            machine_id: Some(machine_id.into()),
            ..Default::default()
        };
        let storage =
            crate::client_manager::storage::Storage::new(crate::db::Db::memory_db().await);
        let client_url = url::Url::parse("http://127.0.0.1").unwrap();
        let mut data = SessionData::new(
            storage.weak_ref(),
            client_url.clone(),
            None,
            std::sync::Arc::new(crate::FeatureFlags::default()),
            std::sync::Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        let storage_token = crate::client_manager::storage::StorageToken {
            token: req.user_token.clone(),
            client_url,
            machine_id,
            user_id: 7,
        };
        storage.update_session_client(storage_token.clone(), 1, true, 0);
        data.storage_token = Some(storage_token);
        data.req = Some(req.clone());
        data.auth_state = super::super::SessionAuthState::Authorized;
        data.applied_config_revision = Some("rev-a".to_string());
        data.known_runtime_base_revision = Some("rev-a".to_string());
        data.pending_managed_config_reconcile = Some(ManagedConfigReconcileHint::Dirty {
            expected_revision: "rev-a".to_string(),
            target_revision: "rev-b".to_string(),
            instance_ids: HashSet::from(["managed".to_string()]),
        });
        data.runtime_config_epoch = 11;
        let session_data = std::sync::Arc::new(RwLock::new(data));
        let mut round = ReconcileRound {
            req,
            machine_id,
            user_id: 7,
            running_inst_ids: HashSet::new(),
            local_configs: Vec::new(),
            delete_instance_ids: HashSet::new(),
            target_config_revision: Some("rev-b".to_string()),
            should_apply_runtime_revision: true,
            scope: ReconcileScope::Patch {
                dirty_instance_ids: HashSet::from(["managed".to_string()]),
            },
            runtime_config_epoch: 11,
            runtime_config_cache_epoch: 0,
        };
        let mut mutation_fence = RuntimeMutationFence::default();

        assert!(
            begin_managed_runtime_mutation(
                &std::sync::Arc::downgrade(&session_data),
                &round,
                &mut mutation_fence,
            )
            .await
        );

        let data = session_data.read().await;
        assert!(mutation_fence.started);
        assert_eq!(data.applied_config_revision, None);
        assert_eq!(data.known_runtime_base_revision.as_deref(), Some("rev-a"));
        assert_eq!(
            data.pending_managed_config_reconcile,
            Some(ManagedConfigReconcileHint::Dirty {
                expected_revision: "rev-a".to_string(),
                target_revision: "rev-b".to_string(),
                instance_ids: HashSet::from(["managed".to_string()]),
            })
        );
        assert_eq!(data.runtime_config_epoch, 11);
        assert_eq!(
            select_reconcile_scope(
                data.pending_managed_config_reconcile.as_ref(),
                data.known_runtime_base_revision.as_deref(),
                Some("rev-b"),
            ),
            ReconcileScope::Patch {
                dirty_instance_ids: HashSet::from(["managed".to_string()]),
            }
        );
        drop(data);

        {
            let mut data = session_data.write().await;
            data.applied_config_revision = Some("rev-a".to_string());
        }
        round.scope = ReconcileScope::Full;
        let mut mutation_fence = RuntimeMutationFence::default();
        assert!(
            begin_managed_runtime_mutation(
                &std::sync::Arc::downgrade(&session_data),
                &round,
                &mut mutation_fence,
            )
            .await
        );

        let data = session_data.read().await;
        assert_eq!(data.applied_config_revision, None);
        assert_eq!(data.known_runtime_base_revision, None);
    }

    #[test]
    fn dirty_hint_without_known_runtime_base_uses_full_reconcile() {
        assert_eq!(
            select_reconcile_scope(
                Some(&ManagedConfigReconcileHint::Dirty {
                    expected_revision: "rev-a".to_string(),
                    target_revision: "rev-b".to_string(),
                    instance_ids: HashSet::from(["upsert".to_string(), "delete".to_string(),]),
                }),
                None,
                Some("rev-b"),
            ),
            ReconcileScope::Full
        );
    }

    #[test]
    fn matching_known_runtime_base_and_target_select_dirty_instances() {
        assert_eq!(
            select_reconcile_scope(
                Some(&ManagedConfigReconcileHint::Dirty {
                    expected_revision: "rev-a".to_string(),
                    target_revision: "rev-b".to_string(),
                    instance_ids: HashSet::from(["upsert".to_string(), "delete".to_string(),]),
                }),
                Some("rev-a"),
                Some("rev-b"),
            ),
            ReconcileScope::Patch {
                dirty_instance_ids: HashSet::from(["upsert".to_string(), "delete".to_string()]),
            }
        );
    }

    #[test]
    fn mismatched_known_runtime_base_uses_full_reconcile() {
        let hint = ManagedConfigReconcileHint::Dirty {
            expected_revision: "rev-b".to_string(),
            target_revision: "rev-c".to_string(),
            instance_ids: HashSet::from(["managed".to_string()]),
        };

        assert_eq!(
            select_reconcile_scope(Some(&hint), Some("rev-a"), Some("rev-c")),
            ReconcileScope::Full
        );
    }

    #[test]
    fn missing_or_full_hint_uses_full_reconcile() {
        assert_eq!(
            select_reconcile_scope(
                Some(&ManagedConfigReconcileHint::Full),
                Some("rev-a"),
                Some("rev-b"),
            ),
            ReconcileScope::Full
        );
        assert_eq!(
            select_reconcile_scope(None, Some("rev-a"), Some("rev-b")),
            ReconcileScope::Full
        );
    }

    #[test]
    fn dirty_hint_for_older_target_uses_full_reconcile() {
        let hint = ManagedConfigReconcileHint::Dirty {
            expected_revision: "rev-0".to_string(),
            target_revision: "rev-a".to_string(),
            instance_ids: HashSet::from(["managed".to_string()]),
        };

        assert_eq!(
            select_reconcile_scope(Some(&hint), Some("rev-0"), Some("rev-b")),
            ReconcileScope::Full
        );
    }

    #[test]
    fn managed_revision_change_preserves_runtime_config_cache() {
        let mut cache = ReconcileCache::default();
        cache.runtime_configs.remember(
            "managed",
            config_with_port_forwards(vec![port_forward(23000, 5174)]),
        );

        cache.reset_if_runtime_config_cache_epoch_changed(0);

        assert!(cache.runtime_configs.entries.contains_key("managed"));
    }

    #[test]
    fn direct_runtime_mutation_invalidates_runtime_config_cache() {
        let mut cache = ReconcileCache::default();
        cache.runtime_configs.remember(
            "managed",
            config_with_port_forwards(vec![port_forward(23000, 5174)]),
        );

        cache.reset_if_runtime_config_cache_epoch_changed(1);

        assert!(!cache.runtime_configs.entries.contains_key("managed"));
        assert_eq!(cache.runtime_config_cache_epoch, 1);
    }

    #[tokio::test]
    async fn patch_scope_reads_latest_persisted_state_for_dirty_instances() {
        let storage =
            crate::client_manager::storage::Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let machine_id = uuid::Uuid::new_v4();
        let persisted_id = uuid::Uuid::new_v4();
        let missing_id = uuid::Uuid::new_v4();
        crate::client_manager::managed_config::reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![crate::webhook::ManagedNetworkConfig {
                instance_id: persisted_id.to_string(),
                network_config: serde_json::to_value(config_with_port_forwards(Vec::new()))
                    .unwrap(),
            }],
            Some("rev-1"),
            crate::client_manager::managed_config::ExpectedConfigRevision::Any,
        )
        .await
        .unwrap();
        let scope = ReconcileScope::Patch {
            dirty_instance_ids: HashSet::from([persisted_id.to_string(), missing_id.to_string()]),
        };

        let storage_inner = storage.weak_ref().upgrade().unwrap();
        let (configs, deleted) = load_round_configs(&storage_inner, user_id, machine_id, &scope)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].network_instance_id, persisted_id.to_string());
        assert_eq!(deleted, HashSet::from([missing_id.to_string()]));

        crate::client_manager::managed_config::patch_web_source_configs(
            &storage,
            user_id,
            machine_id,
            Vec::new(),
            vec![persisted_id],
            "rev-2",
            "rev-1",
        )
        .await
        .unwrap();

        let (configs, deleted) = load_round_configs(&storage_inner, user_id, machine_id, &scope)
            .await
            .unwrap()
            .unwrap();

        assert!(configs.is_empty());
        assert_eq!(
            deleted,
            HashSet::from([persisted_id.to_string(), missing_id.to_string()])
        );
    }

    #[test]
    fn session_runtime_config_cache_misses_unknown_instance() {
        let cache = SessionRuntimeConfigCache::default();
        let action = cache
            .plan("missing", config_with_port_forwards(Vec::new()))
            .expect("prepare action");

        assert!(action.is_none());
    }

    #[test]
    fn session_runtime_config_cache_skips_matching_observed_config() {
        let mut cache = SessionRuntimeConfigCache::default();
        let config = config_with_port_forwards(vec![port_forward(23000, 5174)]);

        cache.remember("managed", config.clone());
        let action = cache
            .plan("managed", config)
            .expect("prepare action")
            .expect("cached action");

        assert!(matches!(
            action,
            runtime_reconcile::RuntimeReconcileAction::Unchanged(_)
        ));
    }

    #[test]
    fn cache_preserves_ignored_runtime_hostname_for_later_explicit_clear() {
        let mut cache = SessionRuntimeConfigCache::default();
        let mut observed = config_with_port_forwards(Vec::new());
        observed.hostname = Some("runtime-host".to_string());
        cache.remember("managed", observed);

        let unmanaged_desired = config_with_port_forwards(Vec::new());
        let action = cache
            .plan("managed", unmanaged_desired)
            .expect("prepare unmanaged hostname action")
            .expect("cached action");
        let runtime_reconcile::RuntimeReconcileAction::Unchanged(observed) = action else {
            panic!("unmanaged hostname should preserve the observed config");
        };
        assert_eq!(observed.hostname.as_deref(), Some("runtime-host"));
        cache.remember("managed", *observed);

        let mut explicit_clear = config_with_port_forwards(Vec::new());
        explicit_clear.hostname = Some(String::new());
        let action = cache
            .plan("managed", explicit_clear)
            .expect("prepare explicit clear action")
            .expect("cached action");
        let runtime_reconcile::RuntimeReconcileAction::Patch(patch) = action else {
            panic!("explicit clear should patch the observed runtime hostname");
        };

        assert_eq!(patch.hostname.as_deref(), Some(""));
    }

    #[test]
    fn session_runtime_config_cache_plans_patch_from_observed_config() {
        let mut cache = SessionRuntimeConfigCache::default();
        let current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        let desired =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);

        cache.remember("managed", current);
        let action = cache
            .plan("managed", desired)
            .expect("prepare action")
            .expect("cached action");

        let runtime_reconcile::RuntimeReconcileAction::Patch(patch) = action else {
            panic!("expected cached runtime config to produce hot patch");
        };
        assert_eq!(patch.port_forwards.len(), 1);
    }

    #[test]
    fn session_runtime_config_cache_retain_desired_removes_stale_entries() {
        let mut cache = SessionRuntimeConfigCache::default();
        let config = config_with_port_forwards(Vec::new());
        cache.remember("keep", config.clone());
        cache.remember("drop", config);

        cache.retain_desired(&HashSet::from(["keep".to_string()]));

        assert!(cache.entries.contains_key("keep"));
        assert!(!cache.entries.contains_key("drop"));
    }

    #[test]
    fn session_runtime_config_cache_forget_removes_observed_config() {
        let mut cache = SessionRuntimeConfigCache::default();
        let config = config_with_port_forwards(Vec::new());
        cache.remember("managed", config.clone());

        cache.forget("managed");

        let action = cache
            .plan("managed", config)
            .expect("prepare action after remove");
        assert!(action.is_none());
    }

    #[test]
    fn missing_run_remembers_observed_config_when_it_matches_desired() {
        let mut cache = SessionRuntimeConfigCache::default();
        let config = config_with_port_forwards(vec![port_forward(23000, 5174)]);

        remember_if_runtime_matches_desired("managed", &config, config.clone(), &mut cache)
            .expect("remember observed config after run");
        let action = cache
            .plan("managed", config)
            .expect("prepare action after run")
            .expect("cached action");

        assert!(matches!(
            action,
            runtime_reconcile::RuntimeReconcileAction::Unchanged(_)
        ));
    }

    #[test]
    fn missing_run_does_not_remember_observed_config_that_still_differs() {
        let mut cache = SessionRuntimeConfigCache::default();
        let current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        let desired =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);

        let err = remember_if_runtime_matches_desired("managed", &desired, current, &mut cache)
            .expect_err("expected stale run result not to be cached");

        assert!(
            err.to_string()
                .contains("runtime config still differs after managed run")
        );
        let action = cache
            .plan("managed", desired)
            .expect("prepare action after stale run result");
        assert!(action.is_none());
    }

    #[test]
    fn missing_run_does_not_accept_omitted_hostname() {
        let mut cache = SessionRuntimeConfigCache::default();
        let observed = config_with_port_forwards(Vec::new());
        let mut desired = observed.clone();
        desired.hostname = Some("device-host".to_string());

        let err = remember_if_runtime_matches_desired("managed", &desired, observed, &mut cache)
            .expect_err("missing run must not trust an omitted hostname");

        assert!(
            err.to_string()
                .contains("runtime config still differs after managed run")
        );
        assert!(!cache.entries.contains_key("managed"));
    }
}
