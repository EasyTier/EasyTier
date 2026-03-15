use std::{fmt::Debug, str::FromStr as _, sync::Arc};

use anyhow::Context;
use easytier::{
    common::scoped_task::ScopedTask,
    proto::{
        api::manage::{
            NetworkConfig, RunNetworkInstanceRequest, WebClientService,
            WebClientServiceClientFactory,
        },
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::{self, controller::BaseController},
        web::{HeartbeatRequest, HeartbeatResponse, WebServerService, WebServerServiceServer},
    },
    rpc_service::remote_client::{ListNetworkProps, Storage as _},
    tunnel::Tunnel,
};
use tokio::sync::{broadcast, RwLock};

use super::storage::{Storage, StorageToken, WeakRefStorage};
use crate::webhook::SharedWebhookConfig;
use crate::FeatureFlags;

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
        if let Ok(storage) = Storage::try_from(self.storage.clone()) {
            if let Some(token) = self.storage_token.as_ref() {
                storage.remove_client(token);

                // Notify the webhook receiver when a node disconnects.
                if self.webhook_config.is_enabled() {
                    let webhook = self.webhook_config.clone();
                    let machine_id = token.machine_id.to_string();
                    let web_instance_id = webhook.web_instance_id.clone();
                    let binding_version = self.binding_version;
                    tokio::spawn(async move {
                        webhook
                            .notify_node_disconnected(&crate::webhook::NodeDisconnectedRequest {
                                machine_id,
                                web_instance_id,
                                binding_version,
                            })
                            .await;
                    });
                }
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
    async fn persist_webhook_network_config(
        storage: &Storage,
        user_id: i32,
        machine_id: uuid::Uuid,
        network_config: serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut network_config = network_config;
        let network_name = network_config
            .get("network_name")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow::anyhow!("webhook response missing network_name"))?
            .to_string();
        let existing_configs = storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::All)
            .await
            .map_err(|e| anyhow::anyhow!("failed to list existing network configs: {:?}", e))?;
        let inst_id = existing_configs
            .iter()
            .find_map(|cfg| {
                let value = serde_json::from_str::<serde_json::Value>(&cfg.network_config).ok()?;
                let cfg_network_name = value.get("network_name")?.as_str()?;
                if cfg_network_name == network_name {
                    uuid::Uuid::parse_str(&cfg.network_instance_id).ok()
                } else {
                    None
                }
            })
            .unwrap_or_else(uuid::Uuid::new_v4);

        let config_obj = network_config
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("webhook network_config must be a JSON object"))?;
        config_obj.insert(
            "instance_id".to_string(),
            serde_json::Value::String(inst_id.to_string()),
        );
        config_obj
            .entry("instance_name".to_string())
            .or_insert_with(|| serde_json::Value::String(network_name.clone()));

        let config = serde_json::from_value::<NetworkConfig>(network_config)?;
        storage
            .db()
            .insert_or_update_user_network_config((user_id, machine_id), inst_id, config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to persist webhook network config: {:?}", e))?;

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

        let (user_id, webhook_network_config, webhook_validated, binding_version) = if data
            .webhook_config
            .is_enabled()
        {
            let webhook_req = crate::webhook::ValidateTokenRequest {
                token: req.user_token.clone(),
                machine_id: machine_id.to_string(),
                hostname: req.hostname.clone(),
                version: req.easytier_version.clone(),
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
                    resp.network_config,
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
            (user_id, None, false, None)
        };

        if webhook_validated {
            if let Some(network_config) = webhook_network_config {
                Self::persist_webhook_network_config(&storage, user_id, machine_id, network_config)
                    .await
                    .map_err(rpc_types::error::Error::from)?;
            }
        } else if webhook_network_config.is_some() {
            return Err(anyhow::anyhow!(
                "unexpected webhook network_config for non-webhook token {:?}",
                req.user_token
            )
            .into());
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
                    hostname: req.hostname.clone(),
                    version: req.easytier_version.clone(),
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
            support_encryption: true,
        })
    }
}

pub struct Session {
    rpc_mgr: BidirectRpcManager,

    data: SharedSessionData,

    run_network_on_start_task: Option<ScopedTask<()>>,
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
        self.run_network_on_start_task.replace(
            tokio::spawn(Self::run_network_on_start(
                data.heartbeat_waiter(),
                data.storage.clone(),
                self.scoped_rpc_client(),
            ))
            .into(),
        );
    }

    async fn run_network_on_start(
        mut heartbeat_waiter: broadcast::Receiver<HeartbeatRequest>,
        storage: WeakRefStorage,
        rpc_client: SessionRpcClient,
    ) {
        let mut cleaned_web_managed_instances = false;
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

            let mut running_inst_ids = req
                .running_network_instances
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>();
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

            let mut has_failed = false;

            if !cleaned_web_managed_instances {
                let all_local_configs = match storage
                    .db
                    .list_network_configs((user_id, machine_id.into()), ListNetworkProps::All)
                    .await
                {
                    Ok(configs) => configs,
                    Err(e) => {
                        tracing::error!("Failed to list all network configs, error: {:?}", e);
                        return;
                    }
                };

                let managed_inst_ids = all_local_configs
                    .iter()
                    .filter_map(|cfg| uuid::Uuid::parse_str(&cfg.network_instance_id).ok())
                    .map(Into::into)
                    .collect::<Vec<_>>();

                if !managed_inst_ids.is_empty() {
                    let ret = rpc_client
                        .delete_network_instance(
                            BaseController::default(),
                            easytier::proto::api::manage::DeleteNetworkInstanceRequest {
                                inst_ids: managed_inst_ids,
                            },
                        )
                        .await;
                    tracing::info!(
                        ?user_id,
                        "Clean web-managed network instances on start: {:?}",
                        ret,
                    );
                    has_failed |= ret.is_err();
                }

                if !has_failed {
                    // Instances were deleted; clear running_inst_ids so enabled configs
                    // are started deterministically in the loop below.
                    running_inst_ids.clear();
                    cleaned_web_managed_instances = true;
                }
            }

            for c in local_configs {
                if running_inst_ids.contains(&c.network_instance_id) {
                    continue;
                }
                let ret = rpc_client
                    .run_network_instance(
                        BaseController::default(),
                        RunNetworkInstanceRequest {
                            inst_id: Some(c.network_instance_id.clone().into()),
                            config: Some(
                                serde_json::from_str::<NetworkConfig>(&c.network_config).unwrap(),
                            ),
                            overwrite: false,
                        },
                    )
                    .await;
                tracing::info!(
                    ?user_id,
                    "Run network instance: {:?}",
                    ret,
                );

                has_failed |= ret.is_err();
            }

            if !has_failed {
                tracing::info!(?req, "All network instances are running");
                break;
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
