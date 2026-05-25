use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    str::FromStr as _,
    sync::Arc,
};

use anyhow::Context;
use easytier::{
    common::config::ConfigSource,
    proto::{
        api::manage::{
            ConfigSource as RpcConfigSource, DeleteNetworkInstanceRequest,
            ListNetworkInstanceMetaRequest, NetworkConfig, NetworkMeta, RunNetworkInstanceRequest,
            WebClientService, WebClientServiceClientFactory,
        },
        common::Uuid as RpcUuid,
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::{self, controller::BaseController},
        web::{HeartbeatRequest, HeartbeatResponse, WebServerService, WebServerServiceServer},
    },
    rpc_service::remote_client::{ListNetworkProps, PersistentConfig as _, Storage as _},
    tunnel::Tunnel,
};
use tokio::sync::{RwLock, broadcast};
use tokio_util::task::AbortOnDropHandle;

use super::storage::{Storage, StorageToken, WeakRefStorage};
use crate::FeatureFlags;
use crate::webhook::SharedWebhookConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistedConfigSource {
    User,
    Web,
}

impl PersistedConfigSource {
    fn from_db(source: &str) -> Self {
        match source {
            "web" => Self::Web,
            "user" => Self::User,
            _ => Self::User,
        }
    }

    fn should_update_from_runtime(self, runtime_source: ConfigSource) -> bool {
        match (self, runtime_source) {
            // Older clients report missing source as `user`, which is not authoritative enough
            // to downgrade an existing web-owned row.
            (Self::Web, ConfigSource::User) => false,
            _ => self.as_runtime_source() != runtime_source,
        }
    }

    fn as_runtime_source(self) -> ConfigSource {
        match self {
            Self::User => ConfigSource::User,
            Self::Web => ConfigSource::Web,
        }
    }

    fn auto_run_rpc_source(self) -> RpcConfigSource {
        match self {
            Self::User => RpcConfigSource::User,
            Self::Web => RpcConfigSource::Web,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Location {
    pub country: String,
    pub city: Option<String>,
    pub region: Option<String>,
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

impl Drop for SessionData {
    fn drop(&mut self) {
        if let Ok(storage) = Storage::try_from(self.storage.clone())
            && let Some(token) = self.storage_token.as_ref()
        {
            storage.remove_client(token);

            // Notify the webhook receiver when a node disconnects.
            if self.webhook_config.is_enabled() {
                let webhook = self.webhook_config.clone();
                let machine_id = token.machine_id.to_string();
                let user_id = Some(token.user_id);
                let token_value = token.token.clone();
                let web_instance_id = webhook.web_instance_id.clone();
                let binding_version = self.binding_version;
                tokio::spawn(async move {
                    webhook
                        .notify_node_disconnected(&crate::webhook::NodeDisconnectedRequest {
                            machine_id,
                            token: token_value,
                            user_id,
                            web_instance_id,
                            binding_version,
                        })
                        .await;
                });
            }
        }
    }
}

pub type SharedSessionData = Arc<RwLock<SessionData>>;

#[derive(Clone)]
pub(super) struct SessionRpcService {
    data: SharedSessionData,
}

impl SessionRpcService {
    fn normalize_network_config(
        mut network_config: serde_json::Value,
        inst_id: uuid::Uuid,
    ) -> anyhow::Result<NetworkConfig> {
        let network_name = network_config
            .get("network_name")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow::anyhow!("webhook response missing network_name"))?
            .to_string();
        let config_obj = network_config
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("webhook network_config must be a JSON object"))?;
        config_obj.insert(
            "instance_id".to_string(),
            serde_json::Value::String(inst_id.to_string()),
        );
        config_obj
            .entry("instance_name".to_string())
            .or_insert_with(|| serde_json::Value::String(network_name));

        Ok(serde_json::from_value::<NetworkConfig>(network_config)?)
    }

    pub(super) async fn reconcile_web_source_configs(
        storage: &Storage,
        user_id: i32,
        machine_id: uuid::Uuid,
        desired_configs: Vec<crate::webhook::ManagedNetworkConfig>,
    ) -> anyhow::Result<()> {
        let existing_configs = storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::All)
            .await
            .map_err(|e| anyhow::anyhow!("failed to list existing network configs: {:?}", e))?;
        let existing_sources = existing_configs
            .iter()
            .filter_map(|cfg| {
                uuid::Uuid::parse_str(&cfg.network_instance_id)
                    .ok()
                    .map(|inst_id| (inst_id, PersistedConfigSource::from_db(&cfg.source)))
            })
            .collect::<HashMap<_, _>>();
        let existing_web_ids = existing_sources
            .iter()
            .filter_map(|(inst_id, source)| {
                (*source == PersistedConfigSource::Web).then_some(*inst_id)
            })
            .collect::<HashSet<_>>();

        let mut desired_ids = HashSet::with_capacity(desired_configs.len());
        let mut normalized = HashMap::with_capacity(desired_configs.len());
        for desired in desired_configs {
            let inst_id = uuid::Uuid::parse_str(&desired.instance_id).with_context(|| {
                format!(
                    "invalid desired web config instance id: {}",
                    desired.instance_id
                )
            })?;
            if let Some(PersistedConfigSource::User) = existing_sources.get(&inst_id) {
                tracing::warn!(
                    ?user_id,
                    ?machine_id,
                    instance_id = %inst_id,
                    "skip web config because a user-owned config already exists"
                );
                continue;
            }
            let config = Self::normalize_network_config(desired.network_config, inst_id)?;
            desired_ids.insert(inst_id);
            normalized.insert(inst_id, config);
        }

        for (inst_id, config) in normalized {
            storage
                .db()
                .insert_or_update_user_network_config(
                    (user_id, machine_id),
                    inst_id,
                    config,
                    ConfigSource::Web,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("failed to persist web network config {}: {:?}", inst_id, e)
                })?;
        }

        let stale_ids = existing_web_ids
            .difference(&desired_ids)
            .copied()
            .collect::<Vec<_>>();
        if !stale_ids.is_empty() {
            storage
                .db()
                .delete_network_configs((user_id, machine_id), &stale_ids)
                .await
                .map_err(|e| anyhow::anyhow!("failed to delete stale network configs: {:?}", e))?;
        }

        Ok(())
    }

    fn managed_configs_for_revision(
        applied_config_revision: Option<&str>,
        resp: crate::webhook::ValidateTokenResponse,
    ) -> anyhow::Result<(Vec<crate::webhook::ManagedNetworkConfig>, String)> {
        let config_revision = resp.config_revision;
        let managed_configs = match resp.managed_network_configs {
            Some(configs) => configs,
            None if applied_config_revision == Some(config_revision.as_str()) => Vec::new(),
            None => {
                anyhow::bail!(
                    "Webhook token validation response omitted managed configs for changed revision {:?}",
                    config_revision
                );
            }
        };

        Ok((managed_configs, config_revision))
    }

    async fn handle_heartbeat(
        &self,
        req: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let (storage, feature_flags, webhook_config, client_url, applied_config_revision) = {
            let data = self.data.read().await;
            let Ok(storage) = Storage::try_from(data.storage.clone()) else {
                tracing::error!("Failed to get storage");
                return Ok(HeartbeatResponse {});
            };
            (
                storage,
                data.feature_flags.clone(),
                data.webhook_config.clone(),
                data.client_url.clone(),
                data.applied_config_revision.clone(),
            )
        };

        let machine_id: uuid::Uuid = req.machine_id.map(Into::into).ok_or(anyhow::anyhow!(
            "Machine id is not set correctly, expect uuid but got: {:?}",
            req.machine_id
        ))?;

        // First heartbeat must validate token through webhook;
        // afterwards only every 10th heartbeat calls the webhook.
        let (should_call_webhook, cached_storage_token) = {
            let data = self.data.read().await;
            let count = data
                .heartbeat_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            let is_first = data.req.is_none();
            let should_call = webhook_config.is_enabled() && (is_first || count % 10 == 1);
            (should_call, data.storage_token.clone())
        };

        let (
            user_id,
            webhook_source_configs,
            webhook_config_revision,
            webhook_validated,
            binding_version,
        ) = if webhook_config.is_enabled() {
            if should_call_webhook {
                let webhook_req = crate::webhook::ValidateTokenRequest {
                    token: req.user_token.clone(),
                    machine_id: machine_id.to_string(),
                    public_ip: client_url.host_str().map(str::to_string),
                    hostname: req.hostname.clone(),
                    version: req.easytier_version.clone(),
                    os_type: req.device_os.as_ref().map(|info| info.os_type.clone()),
                    os_version: req.device_os.as_ref().map(|info| info.version.clone()),
                    os_distribution: req.device_os.as_ref().map(|info| info.distribution.clone()),
                    web_instance_id: webhook_config.web_instance_id.clone(),
                    web_instance_api_base_url: webhook_config.web_instance_api_base_url.clone(),
                    applied_config_revision: applied_config_revision.clone(),
                };
                let resp = webhook_config
                    .validate_token(&webhook_req)
                    .await
                    .map_err(|e| anyhow::anyhow!("Webhook token validation failed: {:?}", e))?;

                if resp.valid {
                    let user_id = match storage
                        .db()
                        .get_user_id_by_token(req.user_token.clone())
                        .await
                        .map_err(|e| anyhow::anyhow!("DB error: {:?}", e))?
                    {
                        Some(id) => id,
                        None => storage
                            .auto_create_user(&req.user_token)
                            .await
                            .with_context(|| {
                                format!("Failed to auto-create webhook user: {:?}", req.user_token)
                            })?,
                    };
                    let binding_version = resp.binding_version;
                    let (webhook_source_configs, webhook_config_revision) =
                        Self::managed_configs_for_revision(
                            applied_config_revision.as_deref(),
                            resp,
                        )
                        .map_err(rpc_types::error::Error::from)?;
                    (
                        user_id,
                        webhook_source_configs,
                        webhook_config_revision,
                        true,
                        Some(binding_version),
                    )
                } else {
                    return Err(anyhow::anyhow!(
                        "Webhook rejected token for machine {:?}: {:?}",
                        machine_id,
                        req.user_token
                    )
                    .into());
                }
            } else {
                let user_id = cached_storage_token
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Storage token not found for non-first heartbeat")
                    })?
                    .user_id;
                let binding_version = {
                    let data = self.data.read().await;
                    data.binding_version
                };
                (user_id, Vec::new(), String::new(), false, binding_version)
            }
        } else {
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
            (user_id, Vec::new(), String::new(), false, None)
        };

        let should_reconcile = webhook_validated
            && applied_config_revision.as_deref() != Some(webhook_config_revision.as_str());
        if should_reconcile {
            Self::reconcile_web_source_configs(
                &storage,
                user_id,
                machine_id,
                webhook_source_configs,
            )
            .await
            .map_err(rpc_types::error::Error::from)?;
        }

        let mut connect_notification = None;
        let (storage_token, notifier) = {
            let mut data = self.data.write().await;

            if should_reconcile {
                data.applied_config_revision = Some(webhook_config_revision);
            }

            if data.req.replace(req.clone()).is_none() {
                assert!(data.storage_token.is_none());
                data.storage_token = Some(StorageToken {
                    token: req.user_token.clone(),
                    client_url: data.client_url.clone(),
                    machine_id,
                    user_id,
                });
                data.binding_version = binding_version;

                if data.webhook_config.is_enabled() {
                    connect_notification = Some((
                        data.webhook_config.clone(),
                        crate::webhook::NodeConnectedRequest {
                            machine_id: machine_id.to_string(),
                            token: req.user_token.clone(),
                            user_id: Some(user_id),
                            hostname: req.hostname.clone(),
                            version: req.easytier_version.clone(),
                            os_type: req.device_os.as_ref().map(|info| info.os_type.clone()),
                            os_version: req.device_os.as_ref().map(|info| info.version.clone()),
                            os_distribution: req
                                .device_os
                                .as_ref()
                                .map(|info| info.distribution.clone()),
                            web_instance_id: data.webhook_config.web_instance_id.clone(),
                            binding_version,
                        },
                    ));
                }
            }

            let Some(storage_token) = data.storage_token.as_ref().cloned() else {
                tracing::error!("Heartbeat succeeded before session token was initialized");
                return Ok(HeartbeatResponse {});
            };
            (storage_token, data.notifier.clone())
        };

        if let Some((webhook, connect_req)) = connect_notification {
            tokio::spawn(async move {
                webhook.notify_node_connected(&connect_req).await;
            });
        }

        let Ok(report_time) = chrono::DateTime::<chrono::Local>::from_str(&req.report_time) else {
            tracing::error!("Failed to parse report time: {:?}", req.report_time);
            return Ok(HeartbeatResponse {});
        };
        storage.update_client(storage_token, report_time.timestamp());

        let _ = notifier.send(req);
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
        let ret = self.handle_heartbeat(req).await;
        if ret.is_err() {
            tracing::warn!("Failed to handle heartbeat: {:?}", ret);
            // sleep for a while to avoid client busy loop
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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

    config_reconcile_task: Option<AbortOnDropHandle<()>>,
}

impl Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("data", &self.data).finish()
    }
}

type SessionRpcClient = Box<dyn WebClientService<Controller = BaseController> + Send>;

impl Session {
    pub fn new(
        storage: WeakRefStorage,
        client_url: url::Url,
        location: Option<Location>,
        feature_flags: Arc<FeatureFlags>,
        webhook_config: SharedWebhookConfig,
    ) -> Self {
        let session_data =
            SessionData::new(storage, client_url, location, feature_flags, webhook_config);
        let data = Arc::new(RwLock::new(session_data));

        let rpc_mgr =
            BidirectRpcManager::new().set_rx_timeout(Some(std::time::Duration::from_secs(30)));

        rpc_mgr.rpc_server().registry().register(
            WebServerServiceServer::new(SessionRpcService { data: data.clone() }),
            "",
        );

        Session {
            rpc_mgr,
            data,
            config_reconcile_task: None,
        }
    }

    pub async fn serve(&mut self, tunnel: Box<dyn Tunnel>) {
        self.rpc_mgr.run_with_tunnel(tunnel);

        let data = self.data.read().await;
        self.config_reconcile_task
            .replace(AbortOnDropHandle::new(tokio::spawn(
                Self::reconcile_network_configs_on_heartbeat(
                    data.heartbeat_waiter(),
                    data.storage.clone(),
                    self.scoped_rpc_client(),
                ),
            )));
    }

    fn collect_web_source_instance_ids(metas: &[NetworkMeta]) -> HashSet<String> {
        metas
            .iter()
            .filter_map(|meta| {
                (RpcConfigSource::try_from(meta.source).ok() == Some(RpcConfigSource::Web))
                    .then(|| {
                        meta.inst_id
                            .as_ref()
                            .map(|inst_id| Into::<uuid::Uuid>::into(*inst_id).to_string())
                    })
                    .flatten()
            })
            .collect()
    }

    fn desired_web_source_instance_ids(
        local_configs: &[crate::db::entity::user_running_network_configs::Model],
    ) -> HashSet<String> {
        local_configs
            .iter()
            .filter(|cfg| cfg.get_runtime_network_config_source() == ConfigSource::Web)
            .map(|cfg| cfg.network_instance_id.clone())
            .collect()
    }

    fn running_web_source_instance_ids(
        running_inst_ids: &HashSet<String>,
        db_web_inst_ids: &HashSet<String>,
        running_metas: Option<&[NetworkMeta]>,
    ) -> HashSet<String> {
        match running_metas {
            Some(metas) => Self::collect_web_source_instance_ids(metas),
            None => running_inst_ids
                .intersection(db_web_inst_ids)
                .cloned()
                .collect(),
        }
    }

    fn parse_instance_ids(instance_ids: impl Iterator<Item = String>) -> Vec<RpcUuid> {
        instance_ids
            .filter_map(|inst_id| uuid::Uuid::parse_str(&inst_id).ok())
            .map(Into::into)
            .collect()
    }

    async fn sync_running_config_sources(
        db: &crate::db::Db,
        user_id: i32,
        machine_id: uuid::Uuid,
        local_configs: &[crate::db::entity::user_running_network_configs::Model],
        metas: &[NetworkMeta],
    ) -> anyhow::Result<()> {
        let local_configs_by_id = local_configs
            .iter()
            .map(|cfg| (cfg.network_instance_id.clone(), cfg))
            .collect::<HashMap<_, _>>();

        for meta in metas {
            let Some(inst_id) = meta.inst_id.as_ref().map(|inst_id| {
                let inst_id: uuid::Uuid = (*inst_id).into();
                inst_id
            }) else {
                continue;
            };
            let inst_id_str = inst_id.to_string();
            let Some(local_cfg) = local_configs_by_id.get(&inst_id_str) else {
                continue;
            };

            let Some(running_source) = ConfigSource::from_rpc(meta.source) else {
                continue;
            };
            let local_source = PersistedConfigSource::from_db(&local_cfg.source);
            if !local_source.should_update_from_runtime(running_source) {
                continue;
            }

            db.insert_or_update_user_network_config(
                (user_id, machine_id),
                inst_id,
                local_cfg.get_network_config().map_err(|e| {
                    anyhow::anyhow!("failed to decode local network config {}: {:?}", inst_id, e)
                })?,
                running_source,
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to sync running network config source {}: {:?}",
                    inst_id,
                    e
                )
            })?;
        }

        Ok(())
    }

    async fn reconcile_network_configs_on_heartbeat(
        mut heartbeat_waiter: broadcast::Receiver<HeartbeatRequest>,
        storage: WeakRefStorage,
        rpc_client: SessionRpcClient,
    ) {
        // This is a per-session background task. It starts when the RPC session is
        // created, then reconciles after each heartbeat reports the client's runtime
        // instances. It is deliberately best-effort: a failed round is retried by a
        // later heartbeat instead of blocking heartbeat handling itself.
        let mut cleaned_web_source_instances = false;
        // This is only an in-memory guard for RPC cleanup, not a second source of
        // truth. The DB still owns desired state; the cache lets us avoid listing
        // and deleting runtime instances on every heartbeat when desired web-owned
        // configs have not changed.
        let mut last_desired_web_inst_ids: Option<HashSet<String>> = None;
        loop {
            // Drop any heartbeat backlog accumulated while the previous reconcile
            // round was doing DB/RPC IO. The newest heartbeat has the freshest
            // runtime instance list, which is all this task needs.
            heartbeat_waiter = heartbeat_waiter.resubscribe();
            let req = heartbeat_waiter.recv().await;
            if req.is_err() {
                tracing::error!(
                    "Failed to receive heartbeat request, error: {:?}",
                    req.err()
                );
                return;
            }

            let req = req.unwrap();
            let Some(machine_id) = req.machine_id else {
                tracing::warn!(?req, "Machine id is not set, ignore");
                continue;
            };

            let running_inst_ids = req
                .running_network_instances
                .iter()
                .map(|x| x.to_string())
                .collect::<HashSet<_>>();
            let Some(storage) = storage.upgrade() else {
                tracing::error!("Failed to get storage");
                return;
            };

            let user_id = match storage
                .db
                .get_user_id_by_token(req.user_token.clone())
                .await
            {
                Ok(Some(user_id)) => user_id,
                Ok(None) => {
                    tracing::info!("User not found by token: {:?}", req.user_token);
                    return;
                }
                Err(e) => {
                    tracing::error!("Failed to get user id by token, error: {:?}", e);
                    return;
                }
            };

            let local_configs = match storage
                .db
                .list_network_configs((user_id, machine_id.into()), ListNetworkProps::EnabledOnly)
                .await
            {
                Ok(configs) => configs,
                Err(e) => {
                    tracing::error!("Failed to list network configs, error: {:?}", e);
                    return;
                }
            };

            let mut local_configs = local_configs;
            let running_metas = if req.support_config_source {
                let ret = if running_inst_ids.is_empty() {
                    Ok(Vec::new())
                } else {
                    rpc_client
                        .list_network_instance_meta(
                            BaseController::default(),
                            ListNetworkInstanceMetaRequest {
                                inst_ids: Self::parse_instance_ids(
                                    running_inst_ids.iter().cloned(),
                                ),
                            },
                        )
                        .await
                        .map(|resp| resp.metas)
                };

                match ret {
                    Ok(metas) => {
                        if let Err(e) = Self::sync_running_config_sources(
                            &storage.db,
                            user_id,
                            machine_id.into(),
                            &local_configs,
                            &metas,
                        )
                        .await
                        {
                            tracing::warn!(
                                ?user_id,
                                ?machine_id,
                                %e,
                                "Failed to sync running network config sources"
                            );
                        } else if !metas.is_empty() {
                            local_configs = match storage
                                .db
                                .list_network_configs(
                                    (user_id, machine_id.into()),
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
                                    return;
                                }
                            };
                        }
                        Some(metas)
                    }
                    Err(e) => {
                        tracing::warn!(
                            ?user_id,
                            %e,
                            "Failed to list running network instance metadata"
                        );
                        None
                    }
                }
            } else {
                None
            };

            let should_be_alive_web_inst_ids =
                Self::desired_web_source_instance_ids(&local_configs);
            let desired_changed = last_desired_web_inst_ids
                .as_ref()
                .is_none_or(|last| last != &should_be_alive_web_inst_ids);

            let mut has_failed = false;
            if !cleaned_web_source_instances || desired_changed {
                let db_web_inst_ids = match storage
                    .db
                    .list_network_configs((user_id, machine_id.into()), ListNetworkProps::All)
                    .await
                {
                    Ok(configs) => Self::desired_web_source_instance_ids(&configs),
                    Err(e) => {
                        tracing::error!("Failed to list all network configs, error: {:?}", e);
                        return;
                    }
                };

                let running_web_inst_ids = Self::running_web_source_instance_ids(
                    &running_inst_ids,
                    &db_web_inst_ids,
                    running_metas.as_deref(),
                );

                let should_delete_ids = Self::parse_instance_ids(
                    running_web_inst_ids
                        .difference(&should_be_alive_web_inst_ids)
                        .cloned(),
                );

                if !should_delete_ids.is_empty() {
                    let ret = rpc_client
                        .delete_network_instance(
                            BaseController::default(),
                            DeleteNetworkInstanceRequest {
                                inst_ids: should_delete_ids,
                            },
                        )
                        .await;
                    tracing::info!(
                        ?user_id,
                        "Clean stale web-source network instances on heartbeat: {:?}, user_token: {:?}",
                        ret,
                        req.user_token
                    );
                    has_failed |= ret.is_err();
                }

                if !has_failed {
                    cleaned_web_source_instances = true;
                    last_desired_web_inst_ids = Some(should_be_alive_web_inst_ids.clone());
                }
            }

            // After stale web-owned instances are removed, start every enabled
            // config that the latest heartbeat did not report as running.
            for c in local_configs {
                if running_inst_ids.contains(&c.network_instance_id) {
                    continue;
                }
                let source = PersistedConfigSource::from_db(&c.source).auto_run_rpc_source();
                let network_config = match serde_json::from_str::<NetworkConfig>(&c.network_config)
                {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        tracing::error!(
                            ?user_id,
                            ?machine_id,
                            instance_id = %c.network_instance_id,
                            "Failed to deserialize network config, skipping: {:?}",
                            e
                        );
                        has_failed = true;
                        continue;
                    }
                };
                let ret = rpc_client
                    .run_network_instance(
                        BaseController::default(),
                        RunNetworkInstanceRequest {
                            inst_id: Some(c.network_instance_id.clone().into()),
                            config: Some(network_config),
                            overwrite: false,
                            source: source as i32,
                        },
                    )
                    .await;
                tracing::info!(
                    ?user_id,
                    "Run network instance: {:?}, user_token: {:?}",
                    ret,
                    req.user_token
                );

                has_failed |= ret.is_err();
            }

            if !has_failed {
                last_desired_web_inst_ids = Some(should_be_alive_web_inst_ids);
            }
        }
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

    pub async fn get_token(&self) -> Option<StorageToken> {
        self.data.read().await.storage_token.clone()
    }

    pub async fn get_heartbeat_req(&self) -> Option<HeartbeatRequest> {
        self.data.read().await.req()
    }
}

#[cfg(test)]
mod tests {
    use easytier::{
        common::config::ConfigSource,
        rpc_service::remote_client::{ListNetworkProps, PersistentConfig as _, Storage as _},
    };
    use serde_json::json;

    use super::{super::storage::Storage, *};

    #[tokio::test]
    async fn reconcile_web_source_configs_upserts_and_deletes_exact_set() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("web-user").await.unwrap().id;
        let machine_id = uuid::Uuid::new_v4();
        let keep_id = uuid::Uuid::new_v4();
        let stale_id = uuid::Uuid::new_v4();
        let new_id = uuid::Uuid::new_v4();

        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                keep_id,
                NetworkConfig {
                    network_name: Some("old-name".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();
        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                stale_id,
                NetworkConfig {
                    network_name: Some("stale".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();

        SessionRpcService::reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![
                crate::webhook::ManagedNetworkConfig {
                    instance_id: keep_id.to_string(),
                    network_config: json!({
                        "instance_id": keep_id.to_string(),
                        "network_name": "updated-name"
                    }),
                },
                crate::webhook::ManagedNetworkConfig {
                    instance_id: new_id.to_string(),
                    network_config: json!({
                        "instance_id": new_id.to_string(),
                        "network_name": "new-name"
                    }),
                },
            ],
        )
        .await
        .unwrap();

        let configs = storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::All)
            .await
            .unwrap();
        let config_ids = configs
            .iter()
            .map(|cfg| cfg.network_instance_id.clone())
            .collect::<HashSet<_>>();

        assert_eq!(configs.len(), 2);
        assert!(config_ids.contains(&keep_id.to_string()));
        assert!(config_ids.contains(&new_id.to_string()));
        assert!(!config_ids.contains(&stale_id.to_string()));

        let updated_keep = storage
            .db()
            .get_network_config((user_id, machine_id), &keep_id.to_string())
            .await
            .unwrap()
            .unwrap();
        let updated_keep_config: NetworkConfig =
            serde_json::from_str(&updated_keep.network_config).unwrap();
        assert_eq!(
            updated_keep_config.network_name.as_deref(),
            Some("updated-name")
        );
        assert_eq!(updated_keep.get_network_config_source(), ConfigSource::Web);
    }

    #[tokio::test]
    async fn reconcile_web_source_configs_keep_user_owned_configs() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-keep-user")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let user_owned_id = uuid::Uuid::new_v4();
        let web_owned_id = uuid::Uuid::new_v4();

        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                user_owned_id,
                NetworkConfig {
                    network_name: Some("user-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::User,
            )
            .await
            .unwrap();
        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                web_owned_id,
                NetworkConfig {
                    network_name: Some("web-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();

        SessionRpcService::reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![crate::webhook::ManagedNetworkConfig {
                instance_id: user_owned_id.to_string(),
                network_config: json!({
                    "instance_id": user_owned_id.to_string(),
                    "network_name": "web-tries-to-take-over"
                }),
            }],
        )
        .await
        .unwrap();

        let user_owned = storage
            .db()
            .get_network_config((user_id, machine_id), &user_owned_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_owned.get_network_config_source(), ConfigSource::User);
        let user_owned_cfg: NetworkConfig =
            serde_json::from_str(&user_owned.network_config).unwrap();
        assert_eq!(user_owned_cfg.network_name.as_deref(), Some("user-owned"));

        let web_owned = storage
            .db()
            .get_network_config((user_id, machine_id), &web_owned_id.to_string())
            .await
            .unwrap();
        assert!(web_owned.is_none());
    }

    #[test]
    fn validate_token_request_includes_applied_config_revision() {
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
            applied_config_revision: Some("rev-1".to_string()),
        };

        let value = serde_json::to_value(req).unwrap();
        assert_eq!(
            value
                .get("applied_config_revision")
                .and_then(|v| v.as_str()),
            Some("rev-1")
        );
    }

    #[test]
    fn validate_token_response_without_configs_reuses_same_revision() {
        let resp = crate::webhook::ValidateTokenResponse {
            valid: true,
            pre_approved: true,
            binding_version: 1,
            managed_network_configs: None,
            config_revision: "rev-1".to_string(),
        };

        let (configs, revision) =
            SessionRpcService::managed_configs_for_revision(Some("rev-1"), resp).unwrap();
        assert!(configs.is_empty());
        assert_eq!(revision, "rev-1");
    }

    #[test]
    fn validate_token_response_without_configs_rejects_changed_revision() {
        let resp = crate::webhook::ValidateTokenResponse {
            valid: true,
            pre_approved: true,
            binding_version: 1,
            managed_network_configs: None,
            config_revision: "rev-2".to_string(),
        };

        let err = SessionRpcService::managed_configs_for_revision(Some("rev-1"), resp)
            .expect_err("omitted configs with a changed revision must fail");
        assert!(err.to_string().contains("omitted managed configs"));
    }

    #[tokio::test]
    async fn sync_running_config_sources_updates_enabled_config_source_from_runtime() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-sync-source")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();

        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                inst_id,
                NetworkConfig {
                    network_name: Some("web-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();

        let local_configs = storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::EnabledOnly)
            .await
            .unwrap();
        Session::sync_running_config_sources(
            storage.db(),
            user_id,
            machine_id,
            &local_configs,
            &[easytier::proto::api::manage::NetworkMeta {
                inst_id: Some(inst_id.into()),
                source: RpcConfigSource::User as i32,
                ..Default::default()
            }],
        )
        .await
        .unwrap();

        let updated = storage
            .db()
            .get_network_config((user_id, machine_id), &inst_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.get_network_config_source(), ConfigSource::Web);
    }

    #[test]
    fn persisted_sources_map_to_rpc_sources() {
        assert_eq!(
            PersistedConfigSource::Web.auto_run_rpc_source(),
            RpcConfigSource::Web
        );
        assert_eq!(
            PersistedConfigSource::User.auto_run_rpc_source(),
            RpcConfigSource::User
        );
    }
}
