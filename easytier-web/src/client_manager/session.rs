use std::{
    collections::HashSet,
    fmt::Debug,
    str::FromStr as _,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::Context;
use easytier::proto::{
    api::{
        config::{ConfigRpc, ConfigRpcClientFactory},
        manage::{WebClientService, WebClientServiceClientFactory},
    },
    rpc::bidirect::BidirectRpcManager,
    rpc_types::{self, controller::BaseController},
    web::{HeartbeatRequest, HeartbeatResponse, WebServerService, WebServerServiceServer},
};
use easytier_core::tunnel::Tunnel;
use tokio::sync::{Notify, RwLock, broadcast};
use tokio_util::task::AbortOnDropHandle;

use super::{
    HeartbeatPolicy,
    storage::{Storage, StorageToken, WeakRefStorage},
};
use crate::FeatureFlags;
use crate::webhook::SharedWebhookConfig;

mod runtime_revision;
mod webhook_validation;

const WEBHOOK_VALIDATION_HEARTBEAT_INTERVAL: u32 = 10;
const CONNECTED_WEBHOOK_RETRY_DELAYS: [Duration; 2] =
    [Duration::from_millis(100), Duration::from_millis(500)];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Location {
    pub country: String,
    pub city: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionAuthState {
    Init,
    Authorized,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ManagedConfigPersistedChange {
    pub expected_revision: String,
    pub target_revision: String,
    pub dirty_instance_ids: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ManagedConfigReconcileHint {
    Full,
    Dirty {
        expected_revision: String,
        target_revision: String,
        instance_ids: HashSet<String>,
    },
}

pub(super) fn record_managed_config_reconcile_hint(
    pending: &mut Option<ManagedConfigReconcileHint>,
    hint: ManagedConfigReconcileHint,
) {
    match hint {
        ManagedConfigReconcileHint::Full => {
            *pending = Some(ManagedConfigReconcileHint::Full);
        }
        ManagedConfigReconcileHint::Dirty {
            expected_revision,
            target_revision,
            instance_ids,
        } => match pending {
            Some(ManagedConfigReconcileHint::Full) => {}
            Some(ManagedConfigReconcileHint::Dirty {
                target_revision: pending_target,
                instance_ids: pending_ids,
                ..
            }) => {
                if *pending_target == expected_revision {
                    *pending_target = target_revision;
                    pending_ids.extend(instance_ids);
                } else {
                    *pending = Some(ManagedConfigReconcileHint::Full);
                }
            }
            None => {
                *pending = Some(ManagedConfigReconcileHint::Dirty {
                    expected_revision,
                    target_revision,
                    instance_ids,
                });
            }
        },
    }
}

#[derive(Debug, Default)]
pub(super) struct ManagedRuntimeState {
    pub(super) applied_config_revision: Option<String>,
    pub(super) applied_config_revision_known: bool,
    pub(super) known_runtime_base_revision: Option<String>,
    pub(super) pending_managed_config_reconcile: Option<ManagedConfigReconcileHint>,
    pub(super) runtime_config_epoch: u64,
    pub(super) runtime_config_cache_epoch: u64,
}

pub(super) type SharedManagedRuntimeState = Arc<Mutex<ManagedRuntimeState>>;

impl SessionAuthState {
    fn is_authorized(self) -> bool {
        matches!(self, Self::Authorized)
    }
}

#[derive(Debug)]
pub struct SessionData {
    storage: WeakRefStorage,
    feature_flags: Arc<FeatureFlags>,
    webhook_config: SharedWebhookConfig,
    client_url: url::Url,

    storage_token: Option<StorageToken>,
    binding_version: Option<u64>,
    managed_runtime: SharedManagedRuntimeState,
    direct_run_failed_instance_ids: HashSet<String>,
    notifier: broadcast::Sender<HeartbeatRequest>,
    req: Option<HeartbeatRequest>,
    location: Option<Location>,
    heartbeat_count: std::sync::atomic::AtomicU32,
    session_identity: Option<HeartbeatIdentity>,
    auth_state: SessionAuthState,
    webhook_connected_binding_version: Option<u64>,
    webhook_validation_dirty: bool,
    webhook_validation_change_epoch: u64,
    webhook_validation_notify: Arc<Notify>,
    session_epoch: u64,
}

impl SessionData {
    fn new(
        storage: WeakRefStorage,
        client_url: url::Url,
        location: Option<Location>,
        feature_flags: Arc<FeatureFlags>,
        webhook_config: SharedWebhookConfig,
    ) -> Self {
        let (tx, _rx1) = broadcast::channel(2);

        SessionData {
            storage,
            feature_flags,
            webhook_config,
            client_url,
            storage_token: None,
            binding_version: None,
            managed_runtime: Arc::new(Mutex::new(ManagedRuntimeState::default())),
            direct_run_failed_instance_ids: HashSet::new(),
            notifier: tx,
            req: None,
            location,
            heartbeat_count: std::sync::atomic::AtomicU32::new(0),
            session_identity: None,
            auth_state: SessionAuthState::Init,
            webhook_connected_binding_version: None,
            webhook_validation_dirty: false,
            webhook_validation_change_epoch: 0,
            webhook_validation_notify: Arc::new(Notify::new()),
            session_epoch: 0,
        }
    }

    pub fn req(&self) -> Option<HeartbeatRequest> {
        self.req.clone()
    }

    pub fn heartbeat_waiter(&self) -> broadcast::Receiver<HeartbeatRequest> {
        self.notifier.subscribe()
    }

    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    fn managed_runtime(&self) -> MutexGuard<'_, ManagedRuntimeState> {
        self.managed_runtime
            .lock()
            .expect("managed runtime state lock poisoned")
    }
}

async fn send_webhook_node_disconnected(
    webhook: SharedWebhookConfig,
    token: StorageToken,
    binding_version: u64,
) {
    let machine_id = token.machine_id.to_string();
    let user_id = Some(token.user_id);
    let token_value = token.token.clone();
    let web_instance_id = webhook.web_instance_id.clone();
    webhook
        .notify_node_disconnected(&crate::webhook::NodeDisconnectedRequest {
            machine_id,
            token: token_value,
            user_id,
            web_instance_id,
            binding_version: Some(binding_version),
        })
        .await;
}

fn notify_webhook_node_disconnected(
    webhook: SharedWebhookConfig,
    token: StorageToken,
    binding_version: u64,
) {
    tokio::spawn(async move {
        send_webhook_node_disconnected(webhook, token, binding_version).await;
    });
}

struct WebhookDisconnectNotification {
    webhook: SharedWebhookConfig,
    storage_token: StorageToken,
    binding_version: u64,
}

struct WebhookConnectNotification {
    webhook: SharedWebhookConfig,
    storage_token: StorageToken,
    binding_version: u64,
    req: crate::webhook::NodeConnectedRequest,
}

fn storage_tokens_match(left: &StorageToken, right: &StorageToken) -> bool {
    left.token == right.token
        && left.client_url == right.client_url
        && left.machine_id == right.machine_id
        && left.user_id == right.user_id
}

fn connection_state_matches(
    data: &SessionData,
    storage_token: &StorageToken,
    binding_version: u64,
) -> bool {
    data.auth_state.is_authorized()
        && data.binding_version == Some(binding_version)
        && data
            .storage_token
            .as_ref()
            .is_some_and(|current| storage_tokens_match(current, storage_token))
}

fn connected_delivery_state_matches(
    data: &SessionData,
    storage_token: &StorageToken,
    binding_version: u64,
) -> bool {
    connection_state_matches(data, storage_token, binding_version)
        && data.storage.upgrade().is_some_and(|storage| {
            storage.owns_authorized_session(storage_token, data.session_epoch)
        })
}

async fn connected_delivery_is_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage_token: &StorageToken,
    binding_version: u64,
) -> bool {
    let Some(session_data) = session_data.upgrade() else {
        return false;
    };
    let data = session_data.read().await;
    connected_delivery_state_matches(&data, storage_token, binding_version)
}

enum ConnectedBindingRecord {
    Recorded,
    /// The session identity moved on; the delivered connected webhook should
    /// be compensated with a disconnect.
    IdentityStale,
    /// A newer session already owns the machine route; its bindings must be
    /// left untouched so a stale disconnect cannot revoke them.
    OwnershipLost,
}

async fn record_webhook_connected_binding_if_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage_token: &StorageToken,
    binding_version: u64,
) -> Option<ConnectedBindingRecord> {
    let session_data = session_data.upgrade()?;
    let mut data = session_data.write().await;
    if !connection_state_matches(&data, storage_token, binding_version) {
        return Some(ConnectedBindingRecord::IdentityStale);
    }
    if !data
        .storage
        .upgrade()
        .is_some_and(|storage| storage.owns_authorized_session(storage_token, data.session_epoch))
    {
        return Some(ConnectedBindingRecord::OwnershipLost);
    }
    data.webhook_connected_binding_version = Some(binding_version);
    Some(ConnectedBindingRecord::Recorded)
}

async fn send_webhook_connection_transition(
    session_data: std::sync::Weak<RwLock<SessionData>>,
    disconnect: Option<WebhookDisconnectNotification>,
    connect: Option<WebhookConnectNotification>,
) {
    if let Some(disconnect) = disconnect {
        send_webhook_node_disconnected(
            disconnect.webhook,
            disconnect.storage_token,
            disconnect.binding_version,
        )
        .await;
    }

    let Some(connect) = connect else {
        return;
    };
    let delivery_started_at = Instant::now();
    let mut attempt = 1;
    loop {
        if !connected_delivery_is_current(
            &session_data,
            &connect.storage_token,
            connect.binding_version,
        )
        .await
        {
            return;
        }
        match connect.webhook.notify_node_connected(&connect.req).await {
            Ok(()) => {
                let elapsed = delivery_started_at.elapsed();
                if attempt > 1 || elapsed >= Duration::from_secs(2) {
                    tracing::info!(
                        machine_id = %connect.storage_token.machine_id,
                        binding_version = connect.binding_version,
                        attempt,
                        elapsed_ms = elapsed.as_millis(),
                        "node-connected webhook delivery completed"
                    );
                }
                break;
            }
            Err(error) => {
                let retry_delay = if error.is_retryable() {
                    CONNECTED_WEBHOOK_RETRY_DELAYS.get(attempt - 1).copied()
                } else {
                    None
                };
                tracing::warn!(
                    machine_id = %connect.storage_token.machine_id,
                    binding_version = connect.binding_version,
                    attempt,
                    elapsed_ms = delivery_started_at.elapsed().as_millis(),
                    will_retry = retry_delay.is_some(),
                    %error,
                    "node-connected webhook delivery failed"
                );
                let Some(retry_delay) = retry_delay else {
                    return;
                };
                if !connected_delivery_is_current(
                    &session_data,
                    &connect.storage_token,
                    connect.binding_version,
                )
                .await
                {
                    return;
                }
                tokio::time::sleep(retry_delay).await;
                attempt += 1;
            }
        }
    }
    if !connected_delivery_is_current(
        &session_data,
        &connect.storage_token,
        connect.binding_version,
    )
    .await
    {
        return;
    }
    match record_webhook_connected_binding_if_current(
        &session_data,
        &connect.storage_token,
        connect.binding_version,
    )
    .await
    {
        Some(ConnectedBindingRecord::Recorded) => {}
        Some(ConnectedBindingRecord::OwnershipLost) => {
            tracing::debug!(
                machine_id = %connect.storage_token.machine_id,
                binding_version = connect.binding_version,
                "skip disconnect compensation because a newer session owns the route"
            );
        }
        Some(ConnectedBindingRecord::IdentityStale) | None => {
            send_webhook_node_disconnected(
                connect.webhook,
                connect.storage_token,
                connect.binding_version,
            )
            .await;
        }
    }
}

impl Drop for SessionData {
    fn drop(&mut self) {
        if let Ok(storage) = Storage::try_from(self.storage.clone())
            && let Some(token) = self.storage_token.as_ref()
        {
            let removed_current_session = storage.remove_session_client(token, self.session_epoch);

            if removed_current_session {
                tracing::info!(
                    machine_id = %token.machine_id,
                    user_id = token.user_id,
                    session_epoch = self.session_epoch,
                    "session disconnected"
                );
            }

            // Notify the webhook receiver when a node disconnects.
            if removed_current_session
                && self.webhook_config.is_enabled()
                && let Some(binding_version) = self.webhook_connected_binding_version
            {
                notify_webhook_node_disconnected(
                    self.webhook_config.clone(),
                    token.clone(),
                    binding_version,
                );
            }
        }
    }
}

pub type SharedSessionData = Arc<RwLock<SessionData>>;

#[derive(Clone)]
pub(super) struct SessionRpcService {
    data: SharedSessionData,
    heartbeat_policy: HeartbeatPolicy,
}

impl SessionRpcService {
    fn heartbeat_response(&self) -> HeartbeatResponse {
        self.heartbeat_policy.response()
    }
}

fn heartbeat_response_delay(elapsed: Duration, min_response_delay: Duration) -> Option<Duration> {
    min_response_delay
        .checked_sub(elapsed)
        .filter(|delay| !delay.is_zero())
}

fn should_delay_heartbeat_response(
    supports_heartbeat_policy: bool,
    is_paced_session: bool,
    is_first_heartbeat: bool,
) -> bool {
    !supports_heartbeat_policy && is_paced_session && !is_first_heartbeat
}

fn should_delay_session_heartbeat_response(
    data: &SessionData,
    supports_heartbeat_policy: bool,
) -> bool {
    should_delay_heartbeat_response(
        supports_heartbeat_policy,
        data.webhook_config.is_enabled() || data.auth_state.is_authorized(),
        data.req.is_none(),
    )
}

fn should_notify_webhook_validation(heartbeat_count: u32) -> bool {
    heartbeat_count % WEBHOOK_VALIDATION_HEARTBEAT_INTERVAL == 1
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeartbeatIdentity {
    token: String,
    machine_id: uuid::Uuid,
    runtime_id: Option<uuid::Uuid>,
}

impl HeartbeatIdentity {
    fn new(token: String, machine_id: uuid::Uuid, runtime_id: Option<uuid::Uuid>) -> Self {
        Self {
            token,
            machine_id,
            runtime_id,
        }
    }
}

impl SessionRpcService {
    fn heartbeat_report_timestamp(req: &HeartbeatRequest) -> i64 {
        match chrono::DateTime::<chrono::Local>::from_str(&req.report_time) {
            Ok(report_time) => report_time.timestamp(),
            Err(error) => {
                tracing::warn!(
                    report_time = %req.report_time,
                    %error,
                    "invalid heartbeat report time, using server time"
                );
                chrono::Local::now().timestamp()
            }
        }
    }

    fn store_latest_heartbeat_req(
        data: &mut SessionData,
        req: HeartbeatRequest,
    ) -> HeartbeatRequest {
        data.req = Some(req);
        data.req
            .clone()
            .expect("heartbeat request should be initialized")
    }

    fn storage_token_matches_heartbeat(
        storage_token: &StorageToken,
        req: &HeartbeatRequest,
    ) -> bool {
        req.user_token == storage_token.token
            && req.machine_id.map(uuid::Uuid::from) == Some(storage_token.machine_id)
    }

    async fn runtime_heartbeat_is_current(
        session_data: &std::sync::Weak<RwLock<SessionData>>,
        req: &HeartbeatRequest,
    ) -> bool {
        let Some(session_data) = session_data.upgrade() else {
            return false;
        };
        let data = session_data.read().await;
        Self::runtime_heartbeat_is_current_locked(&data, req)
    }

    fn runtime_heartbeat_is_current_locked(data: &SessionData, req: &HeartbeatRequest) -> bool {
        data.storage_token.as_ref().is_some_and(|storage_token| {
            Self::storage_token_matches_heartbeat(storage_token, req)
                && data.req.as_ref().is_some_and(|current_req| {
                    Self::storage_token_matches_heartbeat(storage_token, current_req)
                })
                && data.auth_state.is_authorized()
                && data.storage.upgrade().is_some_and(|storage| {
                    storage.owns_authorized_session(storage_token, data.session_epoch)
                })
        })
    }

    fn heartbeat_matches_identity(
        req: &HeartbeatRequest,
        token: &str,
        machine_id: uuid::Uuid,
    ) -> bool {
        req.user_token == token && req.machine_id.map(uuid::Uuid::from) == Some(machine_id)
    }

    fn heartbeat_identity(req: &HeartbeatRequest, machine_id: uuid::Uuid) -> HeartbeatIdentity {
        HeartbeatIdentity::new(
            req.user_token.clone(),
            machine_id,
            Self::heartbeat_runtime_id(req),
        )
    }

    fn heartbeat_runtime_id(req: &HeartbeatRequest) -> Option<uuid::Uuid> {
        req.inst_id.map(uuid::Uuid::from).filter(|id| !id.is_nil())
    }

    fn ensure_session_identity_locked(
        data: &mut SessionData,
        req: &HeartbeatRequest,
        machine_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        let identity = Self::heartbeat_identity(req, machine_id);
        match data.session_identity.as_ref() {
            Some(existing) if existing != &identity => {
                anyhow::bail!(
                    "Heartbeat identity does not match session token, machine_id: {:?}",
                    machine_id
                );
            }
            Some(_) => {}
            None => data.session_identity = Some(identity),
        }
        Ok(())
    }

    fn mark_webhook_validation_dirty_locked(data: &mut SessionData) -> Arc<Notify> {
        data.webhook_validation_dirty = true;
        data.webhook_validation_notify.clone()
    }

    fn mark_webhook_validation_state_changed_locked(data: &mut SessionData) -> Arc<Notify> {
        data.webhook_validation_change_epoch = data.webhook_validation_change_epoch.wrapping_add(1);
        Self::mark_webhook_validation_dirty_locked(data)
    }

    fn failed_instance_ids(
        req: Option<&HeartbeatRequest>,
        direct_run_failed_instance_ids: &HashSet<String>,
    ) -> HashSet<String> {
        let mut instance_ids = req
            .into_iter()
            .flat_map(|req| &req.failed_network_instances)
            .map(ToString::to_string)
            .collect::<HashSet<_>>();
        instance_ids.extend(direct_run_failed_instance_ids.iter().cloned());
        instance_ids
    }

    fn failed_instance_ids_locked(data: &SessionData) -> HashSet<String> {
        Self::failed_instance_ids(data.req.as_ref(), &data.direct_run_failed_instance_ids)
    }

    fn sorted_failed_instance_ids_locked(data: &SessionData) -> Vec<String> {
        let mut instance_ids = Self::failed_instance_ids_locked(data)
            .into_iter()
            .collect::<Vec<_>>();
        instance_ids.sort_unstable();
        instance_ids
    }

    fn update_heartbeat_failed_instance_ids_locked(
        data: &mut SessionData,
        req: &HeartbeatRequest,
    ) -> Option<Arc<Notify>> {
        let previous_instance_ids = Self::failed_instance_ids_locked(data);
        let next_instance_ids =
            Self::failed_instance_ids(Some(req), &data.direct_run_failed_instance_ids);
        if next_instance_ids == previous_instance_ids {
            return None;
        }
        tracing::info!(
            machine_id = ?req.machine_id,
            failed_instance_ids = ?next_instance_ids,
            "heartbeat failed instance set changed"
        );
        Some(Self::mark_webhook_validation_state_changed_locked(data))
    }

    fn update_direct_run_failures_locked(
        data: &mut SessionData,
        update: impl FnOnce(&mut HashSet<String>),
    ) -> Option<Arc<Notify>> {
        let previous_failed_instance_ids = Self::failed_instance_ids_locked(data);
        update(&mut data.direct_run_failed_instance_ids);
        let failed_instance_ids = Self::failed_instance_ids_locked(data);
        (failed_instance_ids != previous_failed_instance_ids)
            .then(|| Self::mark_webhook_validation_state_changed_locked(data))
    }

    fn update_direct_run_failure_locked(
        data: &mut SessionData,
        instance_id: &str,
        failed: bool,
    ) -> Option<Arc<Notify>> {
        Self::update_direct_run_failures_locked(data, |direct_run_instance_ids| {
            if failed {
                direct_run_instance_ids.insert(instance_id.to_owned());
            } else {
                direct_run_instance_ids.remove(instance_id);
            }
        })
    }

    fn retain_direct_run_failures_locked(
        data: &mut SessionData,
        desired_instance_ids: &HashSet<String>,
    ) -> Option<Arc<Notify>> {
        Self::update_direct_run_failures_locked(data, |direct_run_instance_ids| {
            direct_run_instance_ids
                .retain(|instance_id| desired_instance_ids.contains(instance_id));
        })
    }

    fn remove_direct_run_failures_locked(
        data: &mut SessionData,
        instance_ids: &HashSet<String>,
    ) -> Option<Arc<Notify>> {
        Self::update_direct_run_failures_locked(data, |direct_run_instance_ids| {
            direct_run_instance_ids.retain(|instance_id| !instance_ids.contains(instance_id));
        })
    }

    async fn handle_webhook_heartbeat(
        &self,
        storage: &Storage,
        req: HeartbeatRequest,
        machine_id: uuid::Uuid,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let (notify, runtime_notify) = {
            let mut data = self.data.write().await;
            Self::ensure_session_identity_locked(&mut data, &req, machine_id)
                .map_err(rpc_types::error::Error::from)?;
            if matches!(data.auth_state, SessionAuthState::Invalid) {
                tracing::info!(
                    %machine_id,
                    "webhook session is invalid; failing heartbeat to require client reconnect"
                );
                return Err(anyhow::anyhow!("webhook session is invalid").into());
            }
            let failure_notify = Self::update_heartbeat_failed_instance_ids_locked(&mut data, &req);
            let runtime_req = Self::store_latest_heartbeat_req(&mut data, req);
            let heartbeat_count = data
                .heartbeat_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            let notify = failure_notify.or_else(|| {
                should_notify_webhook_validation(heartbeat_count)
                    .then(|| Self::mark_webhook_validation_dirty_locked(&mut data))
            });
            let authorized = data.auth_state.is_authorized();
            if let Some(storage_token) = data.storage_token.clone() {
                let report_time = Self::heartbeat_report_timestamp(&runtime_req);
                storage.update_session_client(
                    storage_token,
                    report_time,
                    authorized,
                    data.session_epoch,
                );
            }
            let runtime_notify = (authorized && data.storage_token.is_some())
                .then(|| (data.notifier.clone(), runtime_req));
            (notify, runtime_notify)
        };

        if let Some((notifier, runtime_req)) = runtime_notify {
            let _ = notifier.send(runtime_req);
        }
        if let Some(notify) = notify {
            notify.notify_one();
        }
        Ok(self.heartbeat_response())
    }

    async fn handle_heartbeat(
        &self,
        req: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let (storage, feature_flags, webhook_config) = {
            let data = self.data.read().await;
            let Ok(storage) = Storage::try_from(data.storage.clone()) else {
                tracing::error!("Failed to get storage");
                return Ok(self.heartbeat_response());
            };
            (
                storage,
                data.feature_flags.clone(),
                data.webhook_config.clone(),
            )
        };

        let machine_id: uuid::Uuid = req.machine_id.map(Into::into).ok_or(anyhow::anyhow!(
            "Machine id is not set correctly, expect uuid but got: {:?}",
            req.machine_id
        ))?;

        if webhook_config.is_enabled() {
            return self
                .handle_webhook_heartbeat(&storage, req, machine_id)
                .await;
        }

        {
            let mut data = self.data.write().await;
            Self::ensure_session_identity_locked(&mut data, &req, machine_id)
                .map_err(rpc_types::error::Error::from)?;
        }

        let user_id = match storage
            .db()
            .get_user_id_by_token(req.user_token.clone())
            .await
            .with_context(|| "Failed to get user id by token from db".to_string())?
        {
            Some(id) => id,
            None if feature_flags.allow_auto_create_user => storage
                .auto_create_user(&req.user_token)
                .await
                .with_context(|| "Failed to auto-create user".to_string())?,
            None => {
                return Err(anyhow::anyhow!("User not found by token").into());
            }
        };

        let (storage_token, notifier, runtime_req, session_epoch, validation_notify) = {
            let mut data = self.data.write().await;
            let is_new_storage_token = data.storage_token.is_none();
            let validation_notify =
                Self::update_heartbeat_failed_instance_ids_locked(&mut data, &req);
            let runtime_req = Self::store_latest_heartbeat_req(&mut data, req.clone());
            data.heartbeat_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if is_new_storage_token {
                assert!(data.storage_token.is_none());
                data.managed_runtime = storage.bind_managed_runtime_state(
                    user_id,
                    machine_id,
                    Self::heartbeat_runtime_id(&runtime_req),
                    data.session_epoch,
                );
                data.storage_token = Some(StorageToken {
                    token: runtime_req.user_token.clone(),
                    client_url: data.client_url.clone(),
                    machine_id,
                    user_id,
                });
                tracing::info!(
                    %machine_id,
                    user_id,
                    session_epoch = data.session_epoch,
                    client_url = %data.client_url,
                    "session identity established"
                );
            }
            data.auth_state = SessionAuthState::Authorized;

            let Some(storage_token) = data.storage_token.as_ref().cloned() else {
                tracing::error!("Heartbeat succeeded before session token was initialized");
                return Ok(self.heartbeat_response());
            };
            (
                storage_token,
                data.notifier.clone(),
                runtime_req,
                data.session_epoch,
                validation_notify,
            )
        };

        let report_time = Self::heartbeat_report_timestamp(&runtime_req);
        storage.update_session_client(storage_token, report_time, true, session_epoch);
        let _ = notifier.send(runtime_req);
        if let Some(notify) = validation_notify {
            notify.notify_one();
        }
        Ok(self.heartbeat_response())
    }
}

#[async_trait::async_trait]
impl WebServerService for SessionRpcService {
    type Controller = BaseController;

    async fn heartbeat(
        &self,
        _: BaseController,
        req: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let started_at = Instant::now();
        let support_heartbeat_policy = req.support_heartbeat_policy;
        let should_delay_response = {
            let data = self.data.read().await;
            should_delay_session_heartbeat_response(&data, support_heartbeat_policy)
        };
        let ret = self.handle_heartbeat(req).await;
        if ret.is_err() {
            tracing::warn!("Failed to handle heartbeat: {:?}", ret);
            // sleep for a while to avoid client busy loop
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        } else if should_delay_response
            && let Some(delay) = heartbeat_response_delay(
                started_at.elapsed(),
                self.heartbeat_policy.legacy_response_delay(),
            )
        {
            tokio::time::sleep(delay).await;
        }
        ret
    }

    async fn get_feature(
        &self,
        _: BaseController,
        _: easytier::proto::web::GetFeatureRequest,
    ) -> rpc_types::error::Result<easytier::proto::web::GetFeatureResponse> {
        Ok(easytier::proto::web::GetFeatureResponse {
            support_encryption: easytier_core::tunnel::web_security::web_secure_tunnel_supported(),
        })
    }
}

pub struct Session {
    rpc_mgr: BidirectRpcManager,

    data: SharedSessionData,

    webhook_validation_task: Option<AbortOnDropHandle<()>>,
    config_reconcile_task: Option<AbortOnDropHandle<()>>,
    route_ready: Arc<Notify>,
}

impl Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("data", &self.data).finish()
    }
}

pub(super) type SessionRpcClient = Box<dyn WebClientService<Controller = BaseController> + Send>;
pub(super) type SessionConfigClient = Box<dyn ConfigRpc<Controller = BaseController> + Send>;

impl Session {
    pub fn new(
        storage: WeakRefStorage,
        client_url: url::Url,
        location: Option<Location>,
        heartbeat_policy: HeartbeatPolicy,
        feature_flags: Arc<FeatureFlags>,
        webhook_config: SharedWebhookConfig,
        session_epoch: u64,
    ) -> Self {
        let mut session_data =
            SessionData::new(storage, client_url, location, feature_flags, webhook_config);
        session_data.session_epoch = session_epoch;
        let data = Arc::new(RwLock::new(session_data));

        let rpc_mgr =
            BidirectRpcManager::new().set_rx_timeout(Some(heartbeat_policy.session_rx_timeout()));

        rpc_mgr.rpc_server().registry().register(
            WebServerServiceServer::new(SessionRpcService {
                data: data.clone(),
                heartbeat_policy,
            }),
            "",
        );

        Session {
            rpc_mgr,
            data,
            webhook_validation_task: None,
            config_reconcile_task: None,
            route_ready: Arc::new(Notify::new()),
        }
    }

    pub async fn serve(&mut self, tunnel: Box<dyn Tunnel>) {
        self.rpc_mgr.run_with_tunnel(tunnel);

        let data = self.data.read().await;
        if data.webhook_config.is_enabled() {
            let route_ready = self.route_ready.clone();
            let session_data = Arc::downgrade(&self.data);
            self.webhook_validation_task
                .replace(AbortOnDropHandle::new(tokio::spawn(async move {
                    route_ready.notified().await;
                    webhook_validation::run_worker(session_data).await;
                })));
        }
        self.config_reconcile_task
            .replace(AbortOnDropHandle::new(tokio::spawn(
                runtime_revision::reconcile_network_configs_on_heartbeat(
                    Arc::downgrade(&self.data),
                    data.heartbeat_waiter(),
                    data.storage.clone(),
                    self.scoped_rpc_client(),
                    self.scoped_config_client(),
                ),
            )));
    }

    pub fn mark_route_ready(&self) {
        self.route_ready.notify_one();
    }

    pub fn is_running(&self) -> bool {
        self.rpc_mgr.is_running()
    }

    pub async fn stop(&self) {
        self.rpc_mgr.stop().await;
    }

    pub fn data(&self) -> SharedSessionData {
        self.data.clone()
    }

    pub fn scoped_client<F: rpc_types::__rt::RpcClientFactory>(&self) -> F::ClientImpl {
        self.rpc_mgr
            .rpc_client()
            .scoped_client::<F>(1, 1, "".to_string())
    }

    pub fn scoped_client_with_domain<F: rpc_types::__rt::RpcClientFactory>(
        &self,
        domain_name: String,
    ) -> F::ClientImpl {
        self.rpc_mgr
            .rpc_client()
            .scoped_client::<F>(1, 1, domain_name)
    }

    pub fn scoped_rpc_client(&self) -> SessionRpcClient {
        self.scoped_client::<WebClientServiceClientFactory<BaseController>>()
    }

    pub fn scoped_config_client(&self) -> SessionConfigClient {
        self.scoped_client::<ConfigRpcClientFactory<BaseController>>()
    }

    pub(super) async fn notify_managed_runtime_state_changed(
        &self,
        user_id: i32,
        machine_id: uuid::Uuid,
    ) {
        let notify = {
            let data = self.data.read().await;
            if !data.auth_state.is_authorized() {
                return;
            }
            if !data
                .storage_token
                .as_ref()
                .is_some_and(|token| token.user_id == user_id && token.machine_id == machine_id)
            {
                return;
            }
            data.req.clone().map(|req| (data.notifier.clone(), req))
        };
        if let Some((notifier, req)) = notify {
            let _ = notifier.send(req);
        }
    }

    pub(crate) async fn invalidate_runtime_config_for_direct_mutation(&self) {
        let notify = {
            let data = self.data.write().await;
            if data.storage_token.is_none() {
                return;
            }
            let mut runtime = data.managed_runtime();
            runtime.applied_config_revision = None;
            runtime.applied_config_revision_known = true;
            runtime.known_runtime_base_revision = None;
            runtime.pending_managed_config_reconcile = Some(ManagedConfigReconcileHint::Full);
            runtime.runtime_config_epoch = runtime.runtime_config_epoch.wrapping_add(1);
            runtime.runtime_config_cache_epoch = runtime.runtime_config_cache_epoch.wrapping_add(1);
            drop(runtime);
            data.req.clone().map(|req| (data.notifier.clone(), req))
        };
        if let Some((notifier, req)) = notify {
            let _ = notifier.send(req);
        }
    }

    pub async fn get_token(&self) -> Option<StorageToken> {
        self.data.read().await.storage_token.clone()
    }

    pub async fn get_heartbeat_req(&self) -> Option<HeartbeatRequest> {
        self.data.read().await.req()
    }

    #[cfg(test)]
    pub(super) async fn applied_config_revision(&self) -> Option<String> {
        let data = self.data.read().await;
        data.managed_runtime().applied_config_revision.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
    use serde_json::json;
    use tokio::sync::{Mutex, Notify, oneshot};

    use super::{super::storage::Storage, *};

    #[test]
    fn heartbeat_response_delay_only_fills_remaining_time() {
        assert_eq!(
            heartbeat_response_delay(Duration::from_millis(100), Duration::from_millis(3500)),
            Some(Duration::from_millis(3400))
        );
        assert_eq!(
            heartbeat_response_delay(Duration::from_millis(3500), Duration::from_millis(3500)),
            None
        );
        assert_eq!(
            heartbeat_response_delay(Duration::from_millis(3600), Duration::from_millis(3500)),
            None
        );
    }

    #[test]
    fn heartbeat_response_delay_skips_unpaced_and_first_heartbeat() {
        assert!(!HeartbeatRequest::default().support_heartbeat_policy);
        assert!(!should_delay_heartbeat_response(false, false, true));
        assert!(!should_delay_heartbeat_response(false, false, false));
        assert!(!should_delay_heartbeat_response(false, true, true));
        assert!(should_delay_heartbeat_response(false, true, false));
        assert!(!should_delay_heartbeat_response(true, true, false));
    }

    #[tokio::test]
    async fn webhook_heartbeat_response_pacing_does_not_require_authorized() {
        let machine_id = uuid::Uuid::new_v4();
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                Some("http://127.0.0.1:1".to_string()),
                None,
                None,
                None,
                None,
            )),
        );

        assert!(!should_delay_session_heartbeat_response(&data, false));

        data.req = Some(heartbeat_request("token", machine_id));
        assert!(should_delay_session_heartbeat_response(&data, false));
        assert!(!should_delay_session_heartbeat_response(&data, true));

        data.auth_state = SessionAuthState::Invalid;
        assert!(should_delay_session_heartbeat_response(&data, false));
    }

    #[test]
    fn webhook_validation_retry_delay_is_bounded() {
        let retry_delay = webhook_validation::retry_delay(uuid::Uuid::new_v4());
        assert!(retry_delay >= Duration::from_millis(webhook_validation::VALIDATION_RETRY_MS));
        assert!(
            retry_delay
                <= Duration::from_millis(
                    webhook_validation::VALIDATION_RETRY_MS
                        + webhook_validation::VALIDATION_RETRY_MS
                )
        );
    }

    fn heartbeat_request(token: &str, machine_id: uuid::Uuid) -> HeartbeatRequest {
        HeartbeatRequest {
            machine_id: Some(machine_id.into()),
            user_token: token.to_string(),
            ..Default::default()
        }
    }

    async fn failure_state_test_data() -> SessionData {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        )
    }

    #[tokio::test]
    async fn failed_instance_ids_merge_core_and_web_local_failures() {
        let mut data = failure_state_test_data().await;
        let core_failed = uuid::Uuid::new_v4();
        let local_failed = uuid::Uuid::new_v4().to_string();
        let core_failed_req = HeartbeatRequest {
            failed_network_instances: vec![core_failed.into()],
            ..Default::default()
        };

        assert!(
            SessionRpcService::update_heartbeat_failed_instance_ids_locked(
                &mut data,
                &core_failed_req,
            )
            .is_some()
        );
        SessionRpcService::store_latest_heartbeat_req(&mut data, core_failed_req);
        assert_eq!(
            SessionRpcService::failed_instance_ids_locked(&data),
            HashSet::from([core_failed.to_string()])
        );

        assert!(
            SessionRpcService::update_direct_run_failure_locked(&mut data, &local_failed, true)
                .is_some()
        );
        assert_eq!(
            SessionRpcService::failed_instance_ids_locked(&data),
            HashSet::from([core_failed.to_string(), local_failed.clone()])
        );

        let recovered_req = HeartbeatRequest::default();
        SessionRpcService::update_heartbeat_failed_instance_ids_locked(&mut data, &recovered_req);
        SessionRpcService::store_latest_heartbeat_req(&mut data, recovered_req);
        assert_eq!(
            SessionRpcService::failed_instance_ids_locked(&data),
            HashSet::from([local_failed])
        );
    }

    #[tokio::test]
    async fn stable_failed_instance_ids_do_not_repeat_validation_work() {
        let mut data = failure_state_test_data().await;
        let failed = uuid::Uuid::new_v4();
        let failed_req = HeartbeatRequest {
            failed_network_instances: vec![failed.into()],
            ..Default::default()
        };
        assert!(
            SessionRpcService::update_heartbeat_failed_instance_ids_locked(&mut data, &failed_req)
                .is_some()
        );
        SessionRpcService::store_latest_heartbeat_req(&mut data, failed_req);
        data.webhook_validation_dirty = false;
        let change_epoch = data.webhook_validation_change_epoch;

        assert!(
            SessionRpcService::update_direct_run_failure_locked(
                &mut data,
                &failed.to_string(),
                true,
            )
            .is_none()
        );
        let recovered_req = HeartbeatRequest::default();
        assert!(
            SessionRpcService::update_heartbeat_failed_instance_ids_locked(
                &mut data,
                &recovered_req,
            )
            .is_none()
        );
        SessionRpcService::store_latest_heartbeat_req(&mut data, recovered_req);
        assert!(!data.webhook_validation_dirty);
        assert_eq!(data.webhook_validation_change_epoch, change_epoch);
    }

    #[tokio::test]
    async fn direct_run_failure_is_added_and_direct_success_clears_it() {
        let mut data = failure_state_test_data().await;
        let instance_id = uuid::Uuid::new_v4().to_string();

        assert!(
            SessionRpcService::update_direct_run_failure_locked(&mut data, &instance_id, true)
                .is_some()
        );
        assert_eq!(
            SessionRpcService::failed_instance_ids_locked(&data),
            HashSet::from([instance_id.clone()])
        );

        assert!(
            SessionRpcService::update_direct_run_failure_locked(&mut data, &instance_id, false)
                .is_some()
        );
        assert!(SessionRpcService::failed_instance_ids_locked(&data).is_empty());
    }

    #[derive(Clone)]
    struct ValidateWebhookTestState {
        received: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        release: Arc<Notify>,
        connected_received: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        connected_release: Option<Arc<Notify>>,
    }

    async fn valid_validate_token_handler(
        State(state): State<ValidateWebhookTestState>,
    ) -> Json<serde_json::Value> {
        if let Some(sender) = state.received.lock().await.take() {
            let _ = sender.send(());
        }
        state.release.notified().await;

        Json(json!({
            "valid": true,
            "binding_version": 1,
            "config_revision": "rev-1"
        }))
    }

    async fn node_connected_handler(
        State(state): State<ValidateWebhookTestState>,
    ) -> Json<serde_json::Value> {
        if let Some(sender) = state.connected_received.lock().await.take() {
            let _ = sender.send(());
        }
        if let Some(release) = state.connected_release {
            release.notified().await;
        }

        Json(json!({}))
    }

    async fn test_webhook_config(
        state: ValidateWebhookTestState,
    ) -> (SharedWebhookConfig, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/validate-token", post(valid_validate_token_handler))
            .route("/webhook/node-connected", post(node_connected_handler))
            .with_state(state);
        test_webhook_server(app).await
    }

    async fn test_webhook_server(
        app: Router,
    ) -> (SharedWebhookConfig, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let webhook_config = Arc::new(crate::webhook::WebhookConfig::new(
            Some(format!("http://{addr}")),
            None,
            None,
            None,
            None,
        ));

        (webhook_config, server)
    }

    #[derive(Clone)]
    struct RetryingConnectedWebhookState {
        attempts: Arc<AtomicUsize>,
        second_received: Arc<Notify>,
        second_release: Arc<Notify>,
    }

    async fn retrying_node_connected_handler(
        State(state): State<RetryingConnectedWebhookState>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let attempt = state.attempts.fetch_add(1, Ordering::Relaxed) + 1;
        if attempt == 1 {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error"})),
            );
        }
        state.second_received.notify_one();
        state.second_release.notified().await;
        (StatusCode::OK, Json(json!({"status": "ok"})))
    }

    #[tokio::test]
    async fn connected_webhook_is_confirmed_only_after_successful_retry() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let second_received = Arc::new(Notify::new());
        let second_release = Arc::new(Notify::new());
        let app = Router::new()
            .route(
                "/webhook/node-connected",
                post(retrying_node_connected_handler),
            )
            .with_state(RetryingConnectedWebhookState {
                attempts: attempts.clone(),
                second_received: second_received.clone(),
                second_release: second_release.clone(),
            });
        let (webhook_config, server) = test_webhook_server(app).await;
        let fixture = connected_delivery_fixture(webhook_config).await;
        let session_data = fixture.session_data.clone();
        let delivery = tokio::spawn(send_webhook_connection_transition(
            Arc::downgrade(&session_data),
            None,
            Some(fixture.notification),
        ));

        tokio::time::timeout(Duration::from_secs(1), second_received.notified())
            .await
            .expect("5xx connected webhook should be retried");
        assert_eq!(
            session_data.read().await.webhook_connected_binding_version,
            None
        );

        second_release.notify_one();
        delivery.await.unwrap();
        server.abort();

        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert_eq!(
            session_data.read().await.webhook_connected_binding_version,
            Some(1)
        );
    }

    #[derive(Clone)]
    struct FailingConnectedWebhookState {
        attempts: Arc<AtomicUsize>,
        first_received: Arc<Notify>,
        first_release: Option<Arc<Notify>>,
        status: StatusCode,
    }

    async fn failing_node_connected_handler(
        State(state): State<FailingConnectedWebhookState>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let attempt = state.attempts.fetch_add(1, Ordering::Relaxed) + 1;
        if attempt == 1 {
            state.first_received.notify_one();
            if let Some(first_release) = state.first_release {
                first_release.notified().await;
            }
        }
        (state.status, Json(json!({"status": "error"})))
    }

    struct ConnectedDeliveryFixture {
        storage: Storage,
        session_data: Arc<RwLock<SessionData>>,
        notification: WebhookConnectNotification,
        machine_id: uuid::Uuid,
        user_id: i32,
    }

    async fn connected_delivery_fixture(
        webhook_config: SharedWebhookConfig,
    ) -> ConnectedDeliveryFixture {
        let machine_id = uuid::Uuid::new_v4();
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let storage_token = StorageToken {
            token: "token".to_string(),
            client_url: url::Url::parse("http://127.0.0.1:1000").unwrap(),
            machine_id,
            user_id,
        };
        storage.update_session_client(storage_token.clone(), 1, true, 1);
        let mut session = SessionData::new(
            storage.weak_ref(),
            storage_token.client_url.clone(),
            None,
            Arc::new(FeatureFlags::default()),
            webhook_config.clone(),
        );
        session.storage_token = Some(storage_token.clone());
        session.auth_state = SessionAuthState::Authorized;
        session.binding_version = Some(1);
        session.session_epoch = 1;

        ConnectedDeliveryFixture {
            storage,
            session_data: Arc::new(RwLock::new(session)),
            notification: WebhookConnectNotification {
                webhook: webhook_config,
                storage_token,
                binding_version: 1,
                req: crate::webhook::NodeConnectedRequest {
                    machine_id: machine_id.to_string(),
                    token: "token".to_string(),
                    user_id: Some(user_id),
                    hostname: String::new(),
                    version: String::new(),
                    os_type: None,
                    os_version: None,
                    os_distribution: None,
                    web_instance_id: None,
                    binding_version: Some(1),
                },
            },
            machine_id,
            user_id,
        }
    }

    #[tokio::test]
    async fn connected_webhook_retry_stops_after_session_replacement() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let first_received = Arc::new(Notify::new());
        let first_release = Arc::new(Notify::new());
        let app = Router::new()
            .route(
                "/webhook/node-connected",
                post(failing_node_connected_handler),
            )
            .with_state(FailingConnectedWebhookState {
                attempts: attempts.clone(),
                first_received: first_received.clone(),
                first_release: Some(first_release.clone()),
                status: StatusCode::INTERNAL_SERVER_ERROR,
            });
        let (webhook_config, server) = test_webhook_server(app).await;

        let fixture = connected_delivery_fixture(webhook_config).await;
        let session_data = fixture.session_data.clone();
        let delivery = tokio::spawn(send_webhook_connection_transition(
            Arc::downgrade(&session_data),
            None,
            Some(fixture.notification),
        ));

        tokio::time::timeout(Duration::from_secs(1), first_received.notified())
            .await
            .unwrap();
        fixture.storage.update_session_client(
            StorageToken {
                token: "token".to_string(),
                client_url: url::Url::parse("http://127.0.0.1:2000").unwrap(),
                machine_id: fixture.machine_id,
                user_id: fixture.user_id,
            },
            2,
            true,
            2,
        );
        first_release.notify_one();
        delivery.await.unwrap();
        server.abort();

        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert_eq!(
            session_data.read().await.webhook_connected_binding_version,
            None
        );
    }

    #[tokio::test]
    async fn connected_binding_record_respects_route_ownership() {
        let webhook_config = Arc::new(crate::webhook::WebhookConfig::new(
            None, None, None, None, None,
        ));
        let fixture = connected_delivery_fixture(webhook_config).await;
        let session_data = fixture.session_data.clone();
        let storage_token = fixture.notification.storage_token.clone();

        let outcome = record_webhook_connected_binding_if_current(
            &Arc::downgrade(&session_data),
            &storage_token,
            1,
        )
        .await;
        assert!(matches!(outcome, Some(ConnectedBindingRecord::Recorded)));
        assert_eq!(
            session_data.read().await.webhook_connected_binding_version,
            Some(1)
        );

        // A replacement session wins the machine route; the stale task must
        // neither record its binding nor earn disconnect compensation.
        fixture.storage.update_session_client(
            StorageToken {
                token: storage_token.token.clone(),
                client_url: url::Url::parse("http://127.0.0.1:2000").unwrap(),
                machine_id: fixture.machine_id,
                user_id: fixture.user_id,
            },
            2,
            true,
            2,
        );
        session_data.write().await.webhook_connected_binding_version = None;
        let outcome = record_webhook_connected_binding_if_current(
            &Arc::downgrade(&session_data),
            &storage_token,
            1,
        )
        .await;
        assert!(matches!(
            outcome,
            Some(ConnectedBindingRecord::OwnershipLost)
        ));
        assert_eq!(
            session_data.read().await.webhook_connected_binding_version,
            None
        );
    }

    async fn run_failed_connected_delivery(status: StatusCode) -> (usize, Option<u64>) {
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/webhook/node-connected",
                post(failing_node_connected_handler),
            )
            .with_state(FailingConnectedWebhookState {
                attempts: attempts.clone(),
                first_received: Arc::new(Notify::new()),
                first_release: None,
                status,
            });
        let (webhook_config, server) = test_webhook_server(app).await;
        let fixture = connected_delivery_fixture(webhook_config).await;
        let session_data = fixture.session_data.clone();

        send_webhook_connection_transition(
            Arc::downgrade(&session_data),
            None,
            Some(fixture.notification),
        )
        .await;
        server.abort();

        let confirmed_binding_version = session_data.read().await.webhook_connected_binding_version;
        (attempts.load(Ordering::Relaxed), confirmed_binding_version)
    }

    #[tokio::test]
    async fn connected_webhook_retry_is_bounded_when_receiver_keeps_failing() {
        let (attempts, confirmed_binding_version) =
            run_failed_connected_delivery(StatusCode::INTERNAL_SERVER_ERROR).await;

        assert_eq!(attempts, CONNECTED_WEBHOOK_RETRY_DELAYS.len() + 1);
        assert_eq!(confirmed_binding_version, None);
    }

    #[tokio::test]
    async fn connected_webhook_does_not_retry_or_confirm_client_error() {
        let (attempts, confirmed_binding_version) =
            run_failed_connected_delivery(StatusCode::BAD_REQUEST).await;

        assert_eq!(attempts, 1);
        assert_eq!(confirmed_binding_version, None);
    }

    #[test]
    fn heartbeat_identity_requires_matching_token_and_machine_id() {
        let machine_id = uuid::Uuid::new_v4();
        let other_machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token-a", machine_id);

        assert!(SessionRpcService::heartbeat_matches_identity(
            &req, "token-a", machine_id
        ));
        assert!(!SessionRpcService::heartbeat_matches_identity(
            &req, "token-b", machine_id
        ));
        assert!(!SessionRpcService::heartbeat_matches_identity(
            &req,
            "token-a",
            other_machine_id
        ));
    }

    #[test]
    fn session_identity_includes_runtime_id() {
        let machine_id = uuid::Uuid::new_v4();
        let mut request = heartbeat_request("token", machine_id);
        let first_runtime_id = uuid::Uuid::new_v4();
        request.inst_id = Some(first_runtime_id.into());
        let first = SessionRpcService::heartbeat_identity(&request, machine_id);

        request.inst_id = Some(uuid::Uuid::new_v4().into());
        let restarted = SessionRpcService::heartbeat_identity(&request, machine_id);

        assert_eq!(first.runtime_id, Some(first_runtime_id));
        assert_ne!(first, restarted);
    }

    #[tokio::test]
    async fn webhook_heartbeat_saves_latest_and_marks_validation_dirty() {
        let machine_id = uuid::Uuid::new_v4();
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let data = Arc::new(RwLock::new(SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                Some("http://127.0.0.1:1".to_string()),
                None,
                None,
                None,
                None,
            )),
        )));
        let service = SessionRpcService {
            data: data.clone(),
            heartbeat_policy: HeartbeatPolicy::default(),
        };

        service
            .handle_heartbeat(heartbeat_request("token", machine_id))
            .await
            .unwrap();

        let data = data.read().await;
        assert!(data.webhook_validation_dirty);
        assert_eq!(data.webhook_validation_change_epoch, 0);
        assert_eq!(data.auth_state, SessionAuthState::Init);
        assert!(data.storage_token.is_none());
        assert!(SessionRpcService::heartbeat_matches_identity(
            data.req.as_ref().unwrap(),
            "token",
            machine_id,
        ));
        drop(data);
        assert!(
            storage
                .db()
                .get_user_id_by_token("token")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn webhook_validation_round_sets_token_and_notifies_runtime() {
        let machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let (received_tx, received_rx) = oneshot::channel();
        let (connected_tx, connected_rx) = oneshot::channel();
        let release = Arc::new(Notify::new());
        let connected_release = Arc::new(Notify::new());
        let (webhook_config, server) = test_webhook_config(ValidateWebhookTestState {
            received: Arc::new(Mutex::new(Some(received_tx))),
            release: release.clone(),
            connected_received: Arc::new(Mutex::new(Some(connected_tx))),
            connected_release: Some(connected_release.clone()),
        })
        .await;
        let mut session = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags::default()),
            webhook_config.clone(),
        );
        session.req = Some(req.clone());
        session.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        let session_data = Arc::new(RwLock::new(session));
        let mut heartbeat_waiter = session_data.read().await.heartbeat_waiter();

        let validation = tokio::spawn(webhook_validation::run_round(
            Arc::downgrade(&session_data),
            webhook_validation::WebhookValidationInput {
                storage: storage.clone(),
                webhook_config,
                client_url: url::Url::parse("http://127.0.0.1").unwrap(),
                applied_config_revision: None,
                applied_config_revision_known: false,
                failed_instance_ids: Vec::new(),
                req,
                machine_id,
            },
            session_data.read().await.webhook_validation_change_epoch,
        ));
        received_rx.await.unwrap();
        release.notify_waiters();
        connected_rx.await.unwrap();
        let user_id = storage
            .db()
            .get_user_id_by_token("token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.get_client_url_by_machine_id(user_id, &machine_id),
            Some(url::Url::parse("http://127.0.0.1").unwrap())
        );
        connected_release.notify_waiters();
        validation.await.unwrap().unwrap();
        server.abort();

        let data = session_data.read().await;
        assert_eq!(data.auth_state, SessionAuthState::Authorized);
        assert!(data.storage_token.is_some());
        assert_eq!(data.binding_version, Some(1));
        assert_eq!(data.webhook_connected_binding_version, Some(1));
        drop(data);
        assert_eq!(heartbeat_waiter.recv().await.unwrap().user_token, "token");
        assert!(
            storage
                .db()
                .get_user_id_by_token("token")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn authenticated_heartbeat_rejects_mismatched_identity() {
        let machine_id = uuid::Uuid::new_v4();
        let other_machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let (received_tx, received_rx) = oneshot::channel();
        let release = Arc::new(Notify::new());
        let (webhook_config, server) = test_webhook_config(ValidateWebhookTestState {
            received: Arc::new(Mutex::new(Some(received_tx))),
            release,
            connected_received: Arc::new(Mutex::new(None)),
            connected_release: None,
        })
        .await;
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags {
                allow_auto_create_user: true,
                ..Default::default()
            }),
            webhook_config,
        );
        data.storage_token = Some(StorageToken {
            token: "token".to_string(),
            client_url: url::Url::parse("http://127.0.0.1").unwrap(),
            machine_id,
            user_id,
        });
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.auth_state = SessionAuthState::Authorized;
        data.req = Some(req);
        let session_data = Arc::new(RwLock::new(data));
        let service = SessionRpcService {
            data: session_data.clone(),
            heartbeat_policy: HeartbeatPolicy::default(),
        };

        let err = service
            .handle_heartbeat(heartbeat_request("other-token", other_machine_id))
            .await
            .expect_err("mismatched authenticated heartbeat must fail");
        assert!(
            err.to_string()
                .contains("Heartbeat identity does not match")
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), received_rx)
                .await
                .is_err()
        );
        server.abort();

        let data = session_data.read().await;
        assert!(SessionRpcService::storage_token_matches_heartbeat(
            data.storage_token.as_ref().unwrap(),
            data.req.as_ref().unwrap()
        ));
        assert_eq!(
            data.heartbeat_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        drop(data);
        assert!(
            storage
                .db()
                .get_user_id_by_token("other-token")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn non_webhook_mismatched_identity_does_not_auto_create_user() {
        let machine_id = uuid::Uuid::new_v4();
        let other_machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags {
                allow_auto_create_user: true,
                ..Default::default()
            }),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        data.storage_token = Some(StorageToken {
            token: "token".to_string(),
            client_url: url::Url::parse("http://127.0.0.1").unwrap(),
            machine_id,
            user_id,
        });
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.req = Some(req);
        let session_data = Arc::new(RwLock::new(data));
        let service = SessionRpcService {
            data: session_data,
            heartbeat_policy: HeartbeatPolicy::default(),
        };

        let err = service
            .handle_heartbeat(heartbeat_request("other-token", other_machine_id))
            .await
            .expect_err("mismatched heartbeat must fail before DB side effects");
        assert!(
            err.to_string()
                .contains("Heartbeat identity does not match")
        );
        assert!(
            storage
                .db()
                .get_user_id_by_token("other-token")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn webhook_reject_keeps_session_visible_but_invalid() {
        let machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let storage_token = StorageToken {
            token: "token".to_string(),
            client_url: url::Url::parse("http://127.0.0.1").unwrap(),
            machine_id,
            user_id,
        };
        storage.update_client(storage_token.clone(), 1, true);
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                Some("http://127.0.0.1:1".to_string()),
                None,
                None,
                None,
                None,
            )),
        );
        data.storage_token = Some(storage_token);
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.req = Some(req.clone());
        data.auth_state = SessionAuthState::Authorized;
        data.webhook_validation_dirty = true;
        data.webhook_connected_binding_version = Some(3);
        let session_data = Arc::new(RwLock::new(data));

        webhook_validation::apply_rejected(
            &Arc::downgrade(&session_data),
            &webhook_validation::WebhookValidationInput {
                storage: storage.clone(),
                webhook_config: Arc::new(crate::webhook::WebhookConfig::new(
                    None, None, None, None, None,
                )),
                client_url: url::Url::parse("http://127.0.0.1").unwrap(),
                applied_config_revision: None,
                applied_config_revision_known: false,
                failed_instance_ids: Vec::new(),
                req,
                machine_id,
            },
        )
        .await;

        let data = session_data.read().await;
        assert!(data.storage_token.is_some());
        assert_eq!(data.auth_state, SessionAuthState::Invalid);
        assert!(!data.webhook_validation_dirty);
        assert_eq!(data.webhook_connected_binding_version, None);
        drop(data);
        assert_eq!(
            storage.get_client_url_by_machine_id(user_id, &machine_id),
            None
        );
        assert_eq!(
            storage.get_client_url_by_machine_id_with_auth(user_id, &machine_id, false),
            Some(url::Url::parse("http://127.0.0.1").unwrap())
        );
    }

    #[tokio::test]
    async fn webhook_reject_prevents_reauthorize_same_session() {
        let machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let client_url = url::Url::parse("http://127.0.0.1").unwrap();
        let storage_token = StorageToken {
            token: "token".to_string(),
            client_url: client_url.clone(),
            machine_id,
            user_id,
        };
        storage.update_client(storage_token.clone(), 1, true);
        let mut data = SessionData::new(
            storage.weak_ref(),
            client_url.clone(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                Some("http://127.0.0.1:1".to_string()),
                None,
                None,
                None,
                None,
            )),
        );
        data.storage_token = Some(storage_token);
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.req = Some(req.clone());
        data.auth_state = SessionAuthState::Authorized;
        data.webhook_connected_binding_version = Some(6);
        let session_data = Arc::new(RwLock::new(data));
        let weak_session = Arc::downgrade(&session_data);

        let input = webhook_validation::WebhookValidationInput {
            storage: storage.clone(),
            webhook_config: Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
            client_url: client_url.clone(),
            applied_config_revision: None,
            applied_config_revision_known: false,
            failed_instance_ids: Vec::new(),
            req: req.clone(),
            machine_id,
        };
        webhook_validation::apply_rejected(&weak_session, &input).await;
        assert_eq!(
            session_data.read().await.webhook_connected_binding_version,
            None
        );
        assert_eq!(
            storage.get_client_url_by_machine_id(user_id, &machine_id),
            None
        );
        assert_eq!(
            storage.get_client_url_by_machine_id_with_auth(user_id, &machine_id, false),
            Some(client_url.clone())
        );

        webhook_validation::apply_success(
            &weak_session,
            input,
            webhook_validation::WebhookHeartbeatValidation {
                config_revision: "rev-1".to_string(),
                binding_version: 7,
            },
            user_id,
        )
        .await;

        let data = session_data.read().await;
        assert!(data.storage_token.is_some());
        assert_eq!(data.auth_state, SessionAuthState::Invalid);
        assert_eq!(data.binding_version, None);
        assert_eq!(data.webhook_connected_binding_version, None);
        drop(data);
        assert_eq!(
            storage.get_client_url_by_machine_id(user_id, &machine_id),
            None
        );
        assert_eq!(
            storage.get_client_url_by_machine_id_with_auth(user_id, &machine_id, false),
            Some(client_url)
        );
    }

    #[tokio::test]
    async fn invalid_webhook_session_does_not_revalidate_on_same_connection() {
        let machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let client_url = url::Url::parse("http://127.0.0.1").unwrap();
        let mut data = SessionData::new(
            storage.weak_ref(),
            client_url.clone(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                Some("http://127.0.0.1:1".to_string()),
                None,
                None,
                None,
                None,
            )),
        );
        data.storage_token = Some(StorageToken {
            token: "token".to_string(),
            client_url,
            machine_id,
            user_id,
        });
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.auth_state = SessionAuthState::Invalid;
        data.webhook_validation_dirty = false;
        data.heartbeat_count.store(
            WEBHOOK_VALIDATION_HEARTBEAT_INTERVAL,
            std::sync::atomic::Ordering::Relaxed,
        );
        let session_data = Arc::new(RwLock::new(data));
        let service = SessionRpcService {
            data: session_data.clone(),
            heartbeat_policy: HeartbeatPolicy::default(),
        };

        service
            .handle_heartbeat(req)
            .await
            .expect_err("invalid webhook session must fail heartbeat");

        let data = session_data.read().await;
        assert!(!data.webhook_validation_dirty);
        assert_eq!(data.auth_state, SessionAuthState::Invalid);
    }

    #[tokio::test]
    async fn invalid_webhook_heartbeat_returns_error() {
        let machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let client_url = url::Url::parse("http://127.0.0.1").unwrap();
        let storage_token = StorageToken {
            token: "token".to_string(),
            client_url: client_url.clone(),
            machine_id,
            user_id,
        };
        storage.update_client(storage_token.clone(), 1, false);
        let mut data = SessionData::new(
            storage.weak_ref(),
            client_url.clone(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                Some("http://127.0.0.1:1".to_string()),
                None,
                None,
                None,
                None,
            )),
        );
        data.storage_token = Some(storage_token);
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.auth_state = SessionAuthState::Invalid;
        let session_data = Arc::new(RwLock::new(data));
        let service = SessionRpcService {
            data: session_data,
            heartbeat_policy: HeartbeatPolicy::default(),
        };

        service
            .handle_heartbeat(req)
            .await
            .expect_err("invalid webhook heartbeat must fail");

        assert_eq!(
            storage.get_client_url_by_machine_id(user_id, &machine_id),
            None
        );
        assert_eq!(
            storage.get_client_url_by_machine_id_with_auth(user_id, &machine_id, false),
            Some(client_url)
        );
    }

    #[tokio::test]
    async fn webhook_success_replaces_connected_binding_version() {
        let machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let client_url = url::Url::parse("http://127.0.0.1").unwrap();
        let storage_token = StorageToken {
            token: "token".to_string(),
            client_url: client_url.clone(),
            machine_id,
            user_id,
        };
        let mut data = SessionData::new(
            storage.weak_ref(),
            client_url.clone(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        data.storage_token = Some(storage_token);
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.req = Some(req.clone());
        data.auth_state = SessionAuthState::Authorized;
        data.binding_version = Some(6);
        data.webhook_connected_binding_version = Some(6);
        let session_data = Arc::new(RwLock::new(data));

        webhook_validation::apply_success(
            &Arc::downgrade(&session_data),
            webhook_validation::WebhookValidationInput {
                storage,
                webhook_config: Arc::new(crate::webhook::WebhookConfig::new(
                    None, None, None, None, None,
                )),
                client_url,
                applied_config_revision: None,
                applied_config_revision_known: false,
                failed_instance_ids: Vec::new(),
                req,
                machine_id,
            },
            webhook_validation::WebhookHeartbeatValidation {
                config_revision: "rev-1".to_string(),
                binding_version: 7,
            },
            user_id,
        )
        .await;

        let data = session_data.read().await;
        assert_eq!(data.auth_state, SessionAuthState::Authorized);
        assert_eq!(data.binding_version, Some(7));
        assert_eq!(data.webhook_connected_binding_version, Some(7));
    }

    #[tokio::test]
    async fn rejected_session_stops_reconcile_without_clearing_runtime_state() {
        let machine_id = uuid::Uuid::new_v4();
        let req = heartbeat_request("token", machine_id);
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let storage_token = StorageToken {
            token: "token".to_string(),
            client_url: url::Url::parse("http://127.0.0.1").unwrap(),
            machine_id,
            user_id,
        };
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                Some("http://127.0.0.1:1".to_string()),
                None,
                None,
                None,
                None,
            )),
        );
        storage.update_session_client(storage_token.clone(), 1, true, 0);
        data.storage_token = Some(storage_token);
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.req = Some(req.clone());
        data.auth_state = SessionAuthState::Authorized;
        {
            let mut runtime = data.managed_runtime();
            runtime.applied_config_revision = Some("rev-1".to_string());
            runtime.applied_config_revision_known = true;
            runtime.known_runtime_base_revision = Some("rev-1".to_string());
        }
        let session_data = Arc::new(RwLock::new(data));
        let weak_session = Arc::downgrade(&session_data);

        assert!(SessionRpcService::runtime_heartbeat_is_current(&weak_session, &req).await);

        webhook_validation::apply_rejected(
            &weak_session,
            &webhook_validation::WebhookValidationInput {
                storage,
                webhook_config: Arc::new(crate::webhook::WebhookConfig::new(
                    None, None, None, None, None,
                )),
                client_url: url::Url::parse("http://127.0.0.1").unwrap(),
                applied_config_revision: None,
                applied_config_revision_known: false,
                failed_instance_ids: Vec::new(),
                req: req.clone(),
                machine_id,
            },
        )
        .await;

        assert!(!SessionRpcService::runtime_heartbeat_is_current(&weak_session, &req).await);
        let data = session_data.read().await;
        let runtime = data.managed_runtime();
        assert_eq!(runtime.applied_config_revision.as_deref(), Some("rev-1"));
        assert!(runtime.applied_config_revision_known);
        assert_eq!(
            runtime.known_runtime_base_revision.as_deref(),
            Some("rev-1")
        );
    }

    #[tokio::test]
    async fn fresh_session_application_revision_is_unknown() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );

        let runtime = data.managed_runtime();
        assert_eq!(runtime.applied_config_revision, None);
        assert!(!runtime.applied_config_revision_known);
    }

    #[test]
    fn validate_token_request_includes_config_revisions() {
        let req = crate::webhook::ValidateTokenRequest {
            token: "token".to_string(),
            machine_id: "machine".to_string(),
            public_ip: Some("127.0.0.1".to_string()),
            hostname: "host".to_string(),
            version: "1.0.0".to_string(),
            os_type: None,
            os_version: None,
            os_distribution: None,
            web_instance_id: Some("web-1".to_string()),
            web_instance_api_base_url: Some("http://console".to_string()),
            persisted_config_revision: Some("rev-0".to_string()),
            applied_config_revision: Some("rev-1".to_string()),
            applied_config_revision_known: true,
            failed_instance_ids: vec!["failed-instance".to_string()],
        };

        let value = serde_json::to_value(req).unwrap();
        assert_eq!(
            value
                .get("persisted_config_revision")
                .and_then(|v| v.as_str()),
            Some("rev-0")
        );
        assert_eq!(
            value
                .get("applied_config_revision")
                .and_then(|v| v.as_str()),
            Some("rev-1")
        );
        assert_eq!(
            value
                .get("applied_config_revision_known")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            value.get("failed_instance_ids"),
            Some(&json!(["failed-instance"]))
        );
    }

    #[test]
    fn managed_patch_hints_merge_while_runtime_lags() {
        let mut hint = None;

        record_managed_config_reconcile_hint(
            &mut hint,
            ManagedConfigReconcileHint::Dirty {
                expected_revision: "rev-a".to_string(),
                target_revision: "rev-b".to_string(),
                instance_ids: HashSet::from(["instance-a".to_string()]),
            },
        );
        record_managed_config_reconcile_hint(
            &mut hint,
            ManagedConfigReconcileHint::Dirty {
                expected_revision: "rev-b".to_string(),
                target_revision: "rev-c".to_string(),
                instance_ids: HashSet::from(["instance-b".to_string()]),
            },
        );

        assert_eq!(
            hint,
            Some(ManagedConfigReconcileHint::Dirty {
                expected_revision: "rev-a".to_string(),
                target_revision: "rev-c".to_string(),
                instance_ids: HashSet::from(["instance-a".to_string(), "instance-b".to_string(),]),
            })
        );
    }

    #[test]
    fn non_contiguous_managed_patch_hints_require_full_reconcile() {
        let mut hint = Some(ManagedConfigReconcileHint::Dirty {
            expected_revision: "rev-a".to_string(),
            target_revision: "rev-b".to_string(),
            instance_ids: HashSet::from(["instance-a".to_string()]),
        });

        record_managed_config_reconcile_hint(
            &mut hint,
            ManagedConfigReconcileHint::Dirty {
                expected_revision: "rev-c".to_string(),
                target_revision: "rev-d".to_string(),
                instance_ids: HashSet::from(["instance-b".to_string()]),
            },
        );

        assert_eq!(hint, Some(ManagedConfigReconcileHint::Full));
    }

    #[test]
    fn managed_patch_hint_does_not_narrow_pending_full_reconcile() {
        let mut hint = Some(ManagedConfigReconcileHint::Full);

        record_managed_config_reconcile_hint(
            &mut hint,
            ManagedConfigReconcileHint::Dirty {
                expected_revision: "rev-0".to_string(),
                target_revision: "rev-a".to_string(),
                instance_ids: HashSet::from(["instance-a".to_string()]),
            },
        );

        assert_eq!(hint, Some(ManagedConfigReconcileHint::Full));
    }

    #[test]
    fn full_reconcile_hint_replaces_pending_dirty_instances() {
        let mut hint = Some(ManagedConfigReconcileHint::Dirty {
            expected_revision: "rev-0".to_string(),
            target_revision: "rev-a".to_string(),
            instance_ids: HashSet::from(["instance-a".to_string()]),
        });

        record_managed_config_reconcile_hint(&mut hint, ManagedConfigReconcileHint::Full);

        assert_eq!(hint, Some(ManagedConfigReconcileHint::Full));
    }
}
