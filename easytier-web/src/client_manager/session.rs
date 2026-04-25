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
            ConfigSource as RpcConfigSource, NetworkConfig, NetworkMeta, RunNetworkInstanceRequest,
            WebClientService, WebClientServiceClientFactory,
        },
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

const LEGACY_NETWORK_CONFIG_SOURCE: &str = "legacy";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistedConfigSource {
    User,
    Webhook,
    Legacy,
}

impl PersistedConfigSource {
    fn from_db(source: &str) -> Self {
        match source {
            "webhook" => Self::Webhook,
            "user" => Self::User,
            LEGACY_NETWORK_CONFIG_SOURCE => Self::Legacy,
            _ => Self::User,
        }
    }

    fn should_update_from_runtime(self, runtime_source: ConfigSource) -> bool {
        match (self, runtime_source) {
            // Older clients report missing source as `user`, which is not authoritative enough
            // to downgrade an existing webhook-owned or legacy row.
            (Self::Webhook | Self::Legacy, ConfigSource::User) => false,
            _ => self.as_runtime_source() != runtime_source,
        }
    }

    fn as_runtime_source(self) -> ConfigSource {
        match self {
            Self::User | Self::Legacy => ConfigSource::User,
            Self::Webhook => ConfigSource::Webhook,
        }
    }

    fn auto_run_rpc_source(self) -> Option<RpcConfigSource> {
        match self {
            Self::User => Some(RpcConfigSource::User),
            Self::Webhook => Some(RpcConfigSource::Webhook),
            Self::Legacy => None,
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
struct SessionRpcService {
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

    async fn reconcile_webhook_source_configs(
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
        let existing_webhook_ids = existing_sources
            .iter()
            .filter_map(|(inst_id, source)| {
                (*source == PersistedConfigSource::Webhook).then_some(*inst_id)
            })
            .collect::<HashSet<_>>();

        let mut desired_ids = HashSet::with_capacity(desired_configs.len());
        let mut normalized = HashMap::with_capacity(desired_configs.len());
        for desired in desired_configs {
            let inst_id = uuid::Uuid::parse_str(&desired.instance_id).with_context(|| {
                format!(
                    "invalid desired webhook config instance id: {}",
                    desired.instance_id
                )
            })?;
            match existing_sources.get(&inst_id) {
                Some(PersistedConfigSource::User) => {
                    tracing::warn!(
                        ?user_id,
                        ?machine_id,
                        instance_id = %inst_id,
                        "skip webhook config because a user-owned config already exists"
                    );
                    continue;
                }
                Some(PersistedConfigSource::Legacy) => {
                    tracing::info!(
                        ?user_id,
                        ?machine_id,
                        instance_id = %inst_id,
                        "adopt legacy config as webhook-owned during reconciliation"
                    );
                }
                _ => {}
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
                    ConfigSource::Webhook,
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to persist webhook network config {}: {:?}",
                        inst_id,
                        e
                    )
                })?;
        }

        let stale_ids = existing_webhook_ids
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

    async fn handle_heartbeat(
        &self,
        req: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let mut data = self.data.write().await;

        let Ok(storage) = Storage::try_from(data.storage.clone()) else {
            tracing::error!("Failed to get storage");
            return Ok(HeartbeatResponse {});
        };

        let machine_id: uuid::Uuid = req.machine_id.map(Into::into).ok_or(anyhow::anyhow!(
            "Machine id is not set correctly, expect uuid but got: {:?}",
            req.machine_id
        ))?;

        let (
            user_id,
            webhook_source_configs,
            webhook_config_revision,
            webhook_validated,
            binding_version,
        ) = if data.webhook_config.is_enabled() {
            let webhook_req = crate::webhook::ValidateTokenRequest {
                token: req.user_token.clone(),
                machine_id: machine_id.to_string(),
                public_ip: data.client_url.host_str().map(str::to_string),
                hostname: req.hostname.clone(),
                version: req.easytier_version.clone(),
                os_type: req.device_os.as_ref().map(|info| info.os_type.clone()),
                os_version: req.device_os.as_ref().map(|info| info.version.clone()),
                os_distribution: req.device_os.as_ref().map(|info| info.distribution.clone()),
                web_instance_id: data.webhook_config.web_instance_id.clone(),
                web_instance_api_base_url: data.webhook_config.web_instance_api_base_url.clone(),
            };
            let resp = data
                .webhook_config
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
                (
                    user_id,
                    resp.managed_network_configs,
                    resp.config_revision,
                    true,
                    Some(resp.binding_version),
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
                None if data.feature_flags.allow_auto_create_user => storage
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

        if webhook_validated
            && data.applied_config_revision.as_deref() != Some(webhook_config_revision.as_str())
        {
            Self::reconcile_webhook_source_configs(
                &storage,
                user_id,
                machine_id,
                webhook_source_configs,
            )
            .await
            .map_err(rpc_types::error::Error::from)?;
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

            // Notify the webhook receiver on the first successful heartbeat.
            if data.webhook_config.is_enabled() {
                let webhook = data.webhook_config.clone();
                let connect_req = crate::webhook::NodeConnectedRequest {
                    machine_id: machine_id.to_string(),
                    token: req.user_token.clone(),
                    user_id: Some(user_id),
                    hostname: req.hostname.clone(),
                    version: req.easytier_version.clone(),
                    os_type: req.device_os.as_ref().map(|info| info.os_type.clone()),
                    os_version: req.device_os.as_ref().map(|info| info.version.clone()),
                    os_distribution: req.device_os.as_ref().map(|info| info.distribution.clone()),
                    web_instance_id: webhook.web_instance_id.clone(),
                    binding_version,
                };
                tokio::spawn(async move {
                    webhook.notify_node_connected(&connect_req).await;
                });
            }
        }

        let Ok(report_time) = chrono::DateTime::<chrono::Local>::from_str(&req.report_time) else {
            tracing::error!("Failed to parse report time: {:?}", req.report_time);
            return Ok(HeartbeatResponse {});
        };
        storage.update_client(
            data.storage_token.as_ref().unwrap().clone(),
            report_time.timestamp(),
        );

        let _ = data.notifier.send(req);
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

    run_network_on_start_task: Option<AbortOnDropHandle<()>>,
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
            run_network_on_start_task: None,
        }
    }

    pub async fn serve(&mut self, tunnel: Box<dyn Tunnel>) {
        self.rpc_mgr.run_with_tunnel(tunnel);

        let data = self.data.read().await;
        self.run_network_on_start_task
            .replace(AbortOnDropHandle::new(tokio::spawn(
                Self::run_network_on_start(
                    data.heartbeat_waiter(),
                    data.storage.clone(),
                    self.scoped_rpc_client(),
                ),
            )));
    }

    fn collect_webhook_source_instance_ids(
        metas: Vec<easytier::proto::api::manage::NetworkMeta>,
    ) -> HashSet<String> {
        metas
            .into_iter()
            .filter_map(|meta| {
                (RpcConfigSource::try_from(meta.source).ok() == Some(RpcConfigSource::Webhook))
                    .then(|| {
                        meta.inst_id
                            .map(|inst_id| Into::<uuid::Uuid>::into(inst_id).to_string())
                    })
                    .flatten()
            })
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

    async fn repair_legacy_running_config_sources(
        db: &crate::db::Db,
        user_id: i32,
        machine_id: uuid::Uuid,
        local_configs: &[crate::db::entity::user_running_network_configs::Model],
    ) -> anyhow::Result<bool> {
        let legacy_configs = local_configs
            .iter()
            .filter(|cfg| {
                PersistedConfigSource::from_db(&cfg.source) == PersistedConfigSource::Legacy
            })
            .collect::<Vec<_>>();

        if legacy_configs.is_empty() {
            return Ok(false);
        }

        for local_cfg in legacy_configs {
            let inst_id =
                uuid::Uuid::parse_str(&local_cfg.network_instance_id).with_context(|| {
                    format!(
                        "failed to parse legacy network config instance id {}",
                        local_cfg.network_instance_id
                    )
                })?;

            db.insert_or_update_user_network_config(
                (user_id, machine_id),
                inst_id,
                local_cfg.get_network_config().map_err(|e| {
                    anyhow::anyhow!(
                        "failed to decode legacy network config {}: {:?}",
                        inst_id,
                        e
                    )
                })?,
                ConfigSource::User,
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to repair legacy network config source {}: {:?}",
                    inst_id,
                    e
                )
            })?;
        }

        Ok(true)
    }

    async fn run_network_on_start(
        mut heartbeat_waiter: broadcast::Receiver<HeartbeatRequest>,
        storage: WeakRefStorage,
        rpc_client: SessionRpcClient,
    ) {
        let mut cleaned_webhook_source_instances = false;
        let mut last_desired_webhook_inst_ids: Option<HashSet<String>> = None;
        loop {
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
                            easytier::proto::api::manage::ListNetworkInstanceMetaRequest {
                                inst_ids: running_inst_ids
                                    .iter()
                                    .filter_map(|inst_id| uuid::Uuid::parse_str(inst_id).ok())
                                    .map(Into::into)
                                    .collect(),
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

            match Self::repair_legacy_running_config_sources(
                &storage.db,
                user_id,
                machine_id.into(),
                &local_configs,
            )
            .await
            {
                Ok(true) => {
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
                                "Failed to reload network configs after legacy source repair, error: {:?}",
                                e
                            );
                            return;
                        }
                    };
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        ?user_id,
                        ?machine_id,
                        %e,
                        "Failed to repair legacy running network config sources"
                    );
                }
            }

            let mut has_failed = false;
            let should_be_alive_webhook_inst_ids = local_configs
                .iter()
                .filter(|cfg| cfg.get_runtime_network_config_source() == ConfigSource::Webhook)
                .map(|cfg| cfg.network_instance_id.clone())
                .collect::<HashSet<_>>();
            let desired_changed = last_desired_webhook_inst_ids
                .as_ref()
                .is_none_or(|last| last != &should_be_alive_webhook_inst_ids);

            if !cleaned_webhook_source_instances || desired_changed {
                let db_webhook_inst_ids = match storage
                    .db
                    .list_network_configs((user_id, machine_id.into()), ListNetworkProps::All)
                    .await
                {
                    Ok(configs) => configs
                        .iter()
                        .filter(|cfg| {
                            cfg.get_runtime_network_config_source() == ConfigSource::Webhook
                        })
                        .map(|cfg| cfg.network_instance_id.clone())
                        .collect::<HashSet<_>>(),
                    Err(e) => {
                        tracing::error!("Failed to list all network configs, error: {:?}", e);
                        return;
                    }
                };

                let running_webhook_inst_ids = if let Some(metas) = running_metas.as_ref() {
                    Self::collect_webhook_source_instance_ids(metas.clone())
                } else {
                    running_inst_ids
                        .intersection(&db_webhook_inst_ids)
                        .cloned()
                        .collect()
                };

                let should_delete_inst_ids = running_webhook_inst_ids
                    .difference(&should_be_alive_webhook_inst_ids)
                    .cloned()
                    .collect::<HashSet<_>>();

                let should_delete_ids = should_delete_inst_ids
                    .iter()
                    .filter_map(|inst_id| uuid::Uuid::parse_str(inst_id).ok())
                    .map(Into::into)
                    .collect::<Vec<_>>();

                if !should_delete_ids.is_empty() {
                    let ret = rpc_client
                        .delete_network_instance(
                            BaseController::default(),
                            easytier::proto::api::manage::DeleteNetworkInstanceRequest {
                                inst_ids: should_delete_ids,
                            },
                        )
                        .await;
                    tracing::info!(
                        ?user_id,
                        "Clean stale webhook-source network instances on start: {:?}, user_token: {:?}",
                        ret,
                        req.user_token
                    );
                    has_failed |= ret.is_err();
                }

                if !has_failed {
                    cleaned_webhook_source_instances = true;
                    last_desired_webhook_inst_ids = Some(should_be_alive_webhook_inst_ids.clone());
                }
            }

            for c in local_configs {
                if running_inst_ids.contains(&c.network_instance_id) {
                    continue;
                }
                let Some(source) = PersistedConfigSource::from_db(&c.source).auto_run_rpc_source()
                else {
                    tracing::warn!(
                        ?user_id,
                        ?machine_id,
                        instance_id = %c.network_instance_id,
                        "skip auto-run for legacy config until source ownership is repaired"
                    );
                    continue;
                };
                let ret = rpc_client
                    .run_network_instance(
                        BaseController::default(),
                        RunNetworkInstanceRequest {
                            inst_id: Some(c.network_instance_id.clone().into()),
                            config: Some(
                                serde_json::from_str::<NetworkConfig>(&c.network_config).unwrap(),
                            ),
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
                last_desired_webhook_inst_ids = Some(should_be_alive_webhook_inst_ids);
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
    use sea_orm::{ActiveModelTrait, Set};
    use serde_json::json;

    use super::{super::storage::Storage, *};

    #[tokio::test]
    async fn reconcile_webhook_source_configs_upserts_and_deletes_exact_set() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("webhook-user")
            .await
            .unwrap()
            .id;
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
                ConfigSource::Webhook,
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
                ConfigSource::Webhook,
            )
            .await
            .unwrap();

        SessionRpcService::reconcile_webhook_source_configs(
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
        assert_eq!(
            updated_keep.get_network_config_source(),
            ConfigSource::Webhook
        );
    }

    #[tokio::test]
    async fn reconcile_webhook_source_configs_keep_user_owned_configs() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("webhook-user-keep-user")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let user_owned_id = uuid::Uuid::new_v4();
        let webhook_owned_id = uuid::Uuid::new_v4();

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
                webhook_owned_id,
                NetworkConfig {
                    network_name: Some("webhook-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::Webhook,
            )
            .await
            .unwrap();

        SessionRpcService::reconcile_webhook_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![crate::webhook::ManagedNetworkConfig {
                instance_id: user_owned_id.to_string(),
                network_config: json!({
                    "instance_id": user_owned_id.to_string(),
                    "network_name": "webhook-tries-to-take-over"
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

        let webhook_owned = storage
            .db()
            .get_network_config((user_id, machine_id), &webhook_owned_id.to_string())
            .await
            .unwrap();
        assert!(webhook_owned.is_none());
    }

    #[tokio::test]
    async fn reconcile_webhook_source_configs_adopts_legacy_rows_for_webhook() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("webhook-user-legacy")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let legacy_match_id = uuid::Uuid::new_v4();
        let legacy_user_id = uuid::Uuid::new_v4();

        crate::db::entity::user_running_network_configs::ActiveModel {
            user_id: Set(user_id),
            device_id: Set(machine_id.to_string()),
            network_instance_id: Set(legacy_match_id.to_string()),
            network_config: Set(serde_json::to_string(&NetworkConfig {
                network_name: Some("legacy-webhook".to_string()),
                ..Default::default()
            })
            .unwrap()),
            source: Set(LEGACY_NETWORK_CONFIG_SOURCE.to_string()),
            disabled: Set(false),
            create_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            update_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            ..Default::default()
        }
        .insert(storage.db().orm_db())
        .await
        .unwrap();

        crate::db::entity::user_running_network_configs::ActiveModel {
            user_id: Set(user_id),
            device_id: Set(machine_id.to_string()),
            network_instance_id: Set(legacy_user_id.to_string()),
            network_config: Set(serde_json::to_string(&NetworkConfig {
                network_name: Some("legacy-user".to_string()),
                ..Default::default()
            })
            .unwrap()),
            source: Set(LEGACY_NETWORK_CONFIG_SOURCE.to_string()),
            disabled: Set(false),
            create_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            update_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            ..Default::default()
        }
        .insert(storage.db().orm_db())
        .await
        .unwrap();

        SessionRpcService::reconcile_webhook_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![crate::webhook::ManagedNetworkConfig {
                instance_id: legacy_match_id.to_string(),
                network_config: json!({
                    "instance_id": legacy_match_id.to_string(),
                    "network_name": "managed-by-webhook"
                }),
            }],
        )
        .await
        .unwrap();

        let adopted = storage
            .db()
            .get_network_config((user_id, machine_id), &legacy_match_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(adopted.source, ConfigSource::Webhook.as_str());
        let adopted_cfg: NetworkConfig = serde_json::from_str(&adopted.network_config).unwrap();
        assert_eq!(
            adopted_cfg.network_name.as_deref(),
            Some("managed-by-webhook")
        );

        let untouched_legacy = storage
            .db()
            .get_network_config((user_id, machine_id), &legacy_user_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(untouched_legacy.source, LEGACY_NETWORK_CONFIG_SOURCE);
    }

    #[tokio::test]
    async fn sync_running_config_sources_updates_enabled_config_source_from_runtime() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("webhook-user-sync-source")
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
                    network_name: Some("webhook-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::Webhook,
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
        assert_eq!(updated.get_network_config_source(), ConfigSource::Webhook);
    }

    #[tokio::test]
    async fn sync_running_config_sources_keeps_legacy_rows_when_runtime_source_is_user() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("webhook-user-sync-legacy")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();

        crate::db::entity::user_running_network_configs::ActiveModel {
            user_id: Set(user_id),
            device_id: Set(machine_id.to_string()),
            network_instance_id: Set(inst_id.to_string()),
            network_config: Set(serde_json::to_string(&NetworkConfig {
                network_name: Some("legacy".to_string()),
                ..Default::default()
            })
            .unwrap()),
            source: Set(LEGACY_NETWORK_CONFIG_SOURCE.to_string()),
            disabled: Set(false),
            create_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            update_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            ..Default::default()
        }
        .insert(storage.db().orm_db())
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
        assert_eq!(updated.source, LEGACY_NETWORK_CONFIG_SOURCE);
    }

    #[tokio::test]
    async fn repair_legacy_running_config_sources_promotes_remaining_legacy_rows_to_user() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("webhook-user-repair-legacy")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();

        crate::db::entity::user_running_network_configs::ActiveModel {
            user_id: Set(user_id),
            device_id: Set(machine_id.to_string()),
            network_instance_id: Set(inst_id.to_string()),
            network_config: Set(serde_json::to_string(&NetworkConfig {
                network_name: Some("legacy".to_string()),
                ..Default::default()
            })
            .unwrap()),
            source: Set(LEGACY_NETWORK_CONFIG_SOURCE.to_string()),
            disabled: Set(false),
            create_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            update_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            ..Default::default()
        }
        .insert(storage.db().orm_db())
        .await
        .unwrap();

        let local_configs = storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::EnabledOnly)
            .await
            .unwrap();
        assert!(
            Session::repair_legacy_running_config_sources(
                storage.db(),
                user_id,
                machine_id,
                &local_configs,
            )
            .await
            .unwrap()
        );

        let updated = storage
            .db()
            .get_network_config((user_id, machine_id), &inst_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.source, ConfigSource::User.as_str());
    }

    #[test]
    fn legacy_configs_are_not_auto_run_until_repaired() {
        assert_eq!(PersistedConfigSource::Legacy.auto_run_rpc_source(), None);
        assert_eq!(
            PersistedConfigSource::Webhook.auto_run_rpc_source(),
            Some(RpcConfigSource::Webhook)
        );
        assert_eq!(
            PersistedConfigSource::User.auto_run_rpc_source(),
            Some(RpcConfigSource::User)
        );
    }
}
