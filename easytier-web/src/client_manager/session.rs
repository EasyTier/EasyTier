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
    tunnel::Tunnel,
};
use tokio::sync::{broadcast, RwLock};

use crate::db::ListNetworkProps;

use super::storage::{Storage, StorageToken, WeakRefStorage};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Location {
    pub country: String,
    pub city: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug)]
pub struct SessionData {
    storage: WeakRefStorage,
    client_url: url::Url,

    storage_token: Option<StorageToken>,
    notifier: broadcast::Sender<HeartbeatRequest>,
    req: Option<HeartbeatRequest>,
    location: Option<Location>,
}

impl SessionData {
    fn new(storage: WeakRefStorage, client_url: url::Url, location: Option<Location>) -> Self {
        let (tx, _rx1) = broadcast::channel(2);

        SessionData {
            storage,
            client_url,
            storage_token: None,
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

        let user_id = storage
            .db()
            .get_user_id_by_token(req.user_token.clone())
            .await
            .with_context(|| {
                format!(
                    "Failed to get user id by token from db: {:?}",
                    req.user_token
                )
            })?
            .ok_or(anyhow::anyhow!(
                "User not found by token: {:?}",
                req.user_token
            ))?;

        if data.req.replace(req.clone()).is_none() {
            assert!(data.storage_token.is_none());
            data.storage_token = Some(StorageToken {
                token: req.user_token.clone(),
                client_url: data.client_url.clone(),
                machine_id,
                user_id,
            });
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
    pub fn new(storage: WeakRefStorage, client_url: url::Url, location: Option<Location>) -> Self {
        let session_data = SessionData::new(storage, client_url, location);
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
            if req.machine_id.is_none() {
                tracing::warn!(?req, "Machine id is not set, ignore");
                continue;
            }

            let running_inst_ids = req
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
                .list_network_configs(
                    user_id,
                    Some(req.machine_id.unwrap().into()),
                    ListNetworkProps::EnabledOnly,
                )
                .await
            {
                Ok(configs) => configs,
                Err(e) => {
                    tracing::error!("Failed to list network configs, error: {:?}", e);
                    return;
                }
            };

            let mut has_failed = false;

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
                tracing::info!(?req, "All network instances are running");
                break;
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.rpc_mgr.is_running()
    }

    pub fn data(&self) -> SharedSessionData {
        self.data.clone()
    }

    pub fn scoped_rpc_client(&self) -> SessionRpcClient {
        self.rpc_mgr
            .rpc_client()
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(1, 1, "".to_string())
    }

    pub async fn get_token(&self) -> Option<StorageToken> {
        self.data.read().await.storage_token.clone()
    }

    pub async fn get_heartbeat_req(&self) -> Option<HeartbeatRequest> {
        self.data.read().await.req()
    }
}
