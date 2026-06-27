use std::{
    fmt::Debug,
    str::FromStr as _,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use easytier::{
    proto::{
        api::{
            config::{ConfigRpc, ConfigRpcClientFactory},
            manage::{WebClientService, WebClientServiceClientFactory},
        },
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::{self, controller::BaseController},
        web::{HeartbeatRequest, HeartbeatResponse, WebServerService, WebServerServiceServer},
    },
    tunnel::Tunnel,
};
use tokio::sync::{Notify, RwLock, broadcast};
use tokio_util::task::AbortOnDropHandle;

use super::storage::{Storage, StorageToken, WeakRefStorage};
use crate::FeatureFlags;
use crate::webhook::SharedWebhookConfig;

mod runtime_revision;
mod webhook_validation;

const WEBHOOK_VALIDATION_HEARTBEAT_INTERVAL: u32 = 10;

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
    applied_config_revision: Option<String>,
    notifier: broadcast::Sender<HeartbeatRequest>,
    req: Option<HeartbeatRequest>,
    location: Option<Location>,
    heartbeat_count: std::sync::atomic::AtomicU32,
    session_identity: Option<HeartbeatIdentity>,
    auth_state: SessionAuthState,
    webhook_connected_binding_version: Option<u64>,
    webhook_validation_dirty: bool,
    webhook_validation_notify: Arc<Notify>,
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
            applied_config_revision: None,
            notifier: tx,
            req: None,
            location,
            heartbeat_count: std::sync::atomic::AtomicU32::new(0),
            session_identity: None,
            auth_state: SessionAuthState::Init,
            webhook_connected_binding_version: None,
            webhook_validation_dirty: false,
            webhook_validation_notify: Arc::new(Notify::new()),
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

async fn connection_state_is_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage_token: &StorageToken,
    binding_version: u64,
) -> bool {
    let Some(session_data) = session_data.upgrade() else {
        return false;
    };
    let data = session_data.read().await;
    connection_state_matches(&data, storage_token, binding_version)
}

async fn record_webhook_connected_binding_if_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    storage_token: &StorageToken,
    binding_version: u64,
) -> bool {
    let Some(session_data) = session_data.upgrade() else {
        return false;
    };
    let mut data = session_data.write().await;
    if !connection_state_matches(&data, storage_token, binding_version) {
        return false;
    }
    data.webhook_connected_binding_version = Some(binding_version);
    true
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
    if !connection_state_is_current(
        &session_data,
        &connect.storage_token,
        connect.binding_version,
    )
    .await
    {
        return;
    }

    connect.webhook.notify_node_connected(&connect.req).await;
    if !record_webhook_connected_binding_if_current(
        &session_data,
        &connect.storage_token,
        connect.binding_version,
    )
    .await
    {
        send_webhook_node_disconnected(
            connect.webhook,
            connect.storage_token,
            connect.binding_version,
        )
        .await;
    }
}

impl Drop for SessionData {
    fn drop(&mut self) {
        if let Ok(storage) = Storage::try_from(self.storage.clone())
            && let Some(token) = self.storage_token.as_ref()
        {
            storage.remove_client(token);

            // Notify the webhook receiver when a node disconnects.
            if self.webhook_config.is_enabled()
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
    heartbeat_min_response_delay: Duration,
}

fn heartbeat_response_delay(elapsed: Duration, min_response_delay: Duration) -> Option<Duration> {
    min_response_delay
        .checked_sub(elapsed)
        .filter(|delay| !delay.is_zero())
}

fn should_delay_heartbeat_response(is_paced_session: bool, is_first_heartbeat: bool) -> bool {
    is_paced_session && !is_first_heartbeat
}

fn should_delay_session_heartbeat_response(data: &SessionData) -> bool {
    should_delay_heartbeat_response(
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
}

impl HeartbeatIdentity {
    fn new(token: String, machine_id: uuid::Uuid) -> Self {
        Self { token, machine_id }
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
        HeartbeatIdentity::new(req.user_token.clone(), machine_id)
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
            let runtime_req = Self::store_latest_heartbeat_req(&mut data, req);
            let heartbeat_count = data
                .heartbeat_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            let notify = should_notify_webhook_validation(heartbeat_count)
                .then(|| Self::mark_webhook_validation_dirty_locked(&mut data));
            let authorized = data.auth_state.is_authorized();
            if let Some(storage_token) = data.storage_token.clone() {
                let report_time = Self::heartbeat_report_timestamp(&runtime_req);
                storage.update_client(storage_token, report_time, authorized);
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
        Ok(HeartbeatResponse {})
    }

    async fn handle_heartbeat(
        &self,
        req: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let (storage, feature_flags, webhook_config) = {
            let data = self.data.read().await;
            let Ok(storage) = Storage::try_from(data.storage.clone()) else {
                tracing::error!("Failed to get storage");
                return Ok(HeartbeatResponse {});
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
            .with_context(|| {
                format!(
                    "Failed to get user id by token from db: {:?}",
                    req.user_token
                )
            })? {
            Some(id) => id,
            None if feature_flags.allow_auto_create_user => storage
                .auto_create_user(&req.user_token)
                .await
                .with_context(|| format!("Failed to auto-create user: {:?}", req.user_token))?,
            None => {
                return Err(
                    anyhow::anyhow!("User not found by token: {:?}", req.user_token).into(),
                );
            }
        };

        let (storage_token, notifier, runtime_req) = {
            let mut data = self.data.write().await;
            let is_new_storage_token = data.storage_token.is_none();
            let runtime_req = Self::store_latest_heartbeat_req(&mut data, req.clone());
            data.heartbeat_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if is_new_storage_token {
                assert!(data.storage_token.is_none());
                data.storage_token = Some(StorageToken {
                    token: runtime_req.user_token.clone(),
                    client_url: data.client_url.clone(),
                    machine_id,
                    user_id,
                });
            }
            data.auth_state = SessionAuthState::Authorized;

            let Some(storage_token) = data.storage_token.as_ref().cloned() else {
                tracing::error!("Heartbeat succeeded before session token was initialized");
                return Ok(HeartbeatResponse {});
            };
            (storage_token, data.notifier.clone(), runtime_req)
        };

        let report_time = Self::heartbeat_report_timestamp(&runtime_req);
        storage.update_client(storage_token, report_time, true);
        let _ = notifier.send(runtime_req);
        Ok(HeartbeatResponse {})
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
        let should_delay_response = {
            let data = self.data.read().await;
            should_delay_session_heartbeat_response(&data)
        };
        let ret = self.handle_heartbeat(req).await;
        if ret.is_err() {
            tracing::warn!("Failed to handle heartbeat: {:?}", ret);
            // sleep for a while to avoid client busy loop
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        } else if should_delay_response
            && let Some(delay) =
                heartbeat_response_delay(started_at.elapsed(), self.heartbeat_min_response_delay)
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
            support_encryption: easytier::web_client::security::web_secure_tunnel_supported(),
        })
    }
}

pub struct Session {
    rpc_mgr: BidirectRpcManager,

    data: SharedSessionData,

    webhook_validation_task: Option<AbortOnDropHandle<()>>,
    config_reconcile_task: Option<AbortOnDropHandle<()>>,
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
        heartbeat_min_response_delay: Duration,
        feature_flags: Arc<FeatureFlags>,
        webhook_config: SharedWebhookConfig,
    ) -> Self {
        let session_data =
            SessionData::new(storage, client_url, location, feature_flags, webhook_config);
        let data = Arc::new(RwLock::new(session_data));

        let rpc_mgr =
            BidirectRpcManager::new().set_rx_timeout(Some(std::time::Duration::from_secs(30)));

        rpc_mgr.rpc_server().registry().register(
            WebServerServiceServer::new(SessionRpcService {
                data: data.clone(),
                heartbeat_min_response_delay,
            }),
            "",
        );

        Session {
            rpc_mgr,
            data,
            webhook_validation_task: None,
            config_reconcile_task: None,
        }
    }

    pub async fn serve(&mut self, tunnel: Box<dyn Tunnel>) {
        self.rpc_mgr.run_with_tunnel(tunnel);

        let data = self.data.read().await;
        if data.webhook_config.is_enabled() {
            self.webhook_validation_task
                .replace(AbortOnDropHandle::new(tokio::spawn(
                    webhook_validation::run_worker(Arc::downgrade(&self.data)),
                )));
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

    pub async fn notify_config_revision_changed(
        &self,
        user_id: i32,
        machine_id: uuid::Uuid,
        config_revision: String,
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
            if data.applied_config_revision.as_deref() == Some(config_revision.as_str()) {
                return;
            }
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
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, extract::State, routing::post};
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
        assert!(!should_delay_heartbeat_response(false, true));
        assert!(!should_delay_heartbeat_response(false, false));
        assert!(!should_delay_heartbeat_response(true, true));
        assert!(should_delay_heartbeat_response(true, false));
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

        assert!(!should_delay_session_heartbeat_response(&data));

        data.req = Some(heartbeat_request("token", machine_id));
        assert!(should_delay_session_heartbeat_response(&data));

        data.auth_state = SessionAuthState::Invalid;
        assert!(should_delay_session_heartbeat_response(&data));
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

    #[derive(Clone)]
    struct ValidateWebhookTestState {
        received: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        release: Arc<Notify>,
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

    async fn test_webhook_config(
        state: ValidateWebhookTestState,
    ) -> (SharedWebhookConfig, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/validate-token", post(valid_validate_token_handler))
            .with_state(state);
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
            heartbeat_min_response_delay: Duration::ZERO,
        };

        service
            .handle_heartbeat(heartbeat_request("token", machine_id))
            .await
            .unwrap();

        let data = data.read().await;
        assert!(data.webhook_validation_dirty);
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
        let release = Arc::new(Notify::new());
        let (webhook_config, server) = test_webhook_config(ValidateWebhookTestState {
            received: Arc::new(Mutex::new(Some(received_tx))),
            release: release.clone(),
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
                req,
                machine_id,
            },
        ));
        received_rx.await.unwrap();
        release.notify_waiters();
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
            heartbeat_min_response_delay: Duration::ZERO,
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
            heartbeat_min_response_delay: Duration::ZERO,
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
            heartbeat_min_response_delay: Duration::ZERO,
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
            heartbeat_min_response_delay: Duration::ZERO,
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
    async fn runtime_heartbeat_rechecks_webhook_state_before_reconcile() {
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
        data.storage_token = Some(storage_token);
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&req, machine_id));
        data.req = Some(req.clone());
        data.auth_state = SessionAuthState::Authorized;
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
                req: req.clone(),
                machine_id,
            },
        )
        .await;

        assert!(!SessionRpcService::runtime_heartbeat_is_current(&weak_session, &req).await);
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
    }
}
