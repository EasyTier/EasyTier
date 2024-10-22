use std::{fmt::Debug, sync::Arc};

use easytier::{
    proto::{
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::{self, controller::BaseController},
        web::{
            HeartbeatRequest, HeartbeatResponse, WebClientService, WebClientServiceClientFactory,
            WebServerService, WebServerServiceServer,
        },
    },
    tunnel::Tunnel,
};
use tokio::sync::{broadcast, RwLock};

use super::storage::{Storage, StorageToken, WeakRefStorage};

#[derive(Debug)]
pub struct SessionData {
    storage: WeakRefStorage,
    client_url: url::Url,

    storage_token: Option<StorageToken>,
    notifier: broadcast::Sender<HeartbeatRequest>,
    req: Option<HeartbeatRequest>,
}

impl SessionData {
    fn new(storage: WeakRefStorage, client_url: url::Url) -> Self {
        let (tx, _rx1) = broadcast::channel(2);

        SessionData {
            storage,
            client_url,
            storage_token: None,
            notifier: tx,
            req: None,
        }
    }

    pub fn req(&self) -> Option<HeartbeatRequest> {
        self.req.clone()
    }

    pub fn heartbeat_waiter(&self) -> broadcast::Receiver<HeartbeatRequest> {
        self.notifier.subscribe()
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

#[async_trait::async_trait]
impl WebServerService for SessionRpcService {
    type Controller = BaseController;

    async fn heartbeat(
        &self,
        _: BaseController,
        req: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let mut data = self.data.write().await;
        if data.req.replace(req.clone()).is_none() {
            assert!(data.storage_token.is_none());
            data.storage_token = Some(StorageToken {
                token: req.user_token.clone().into(),
                client_url: data.client_url.clone(),
                machine_id: req
                    .machine_id
                    .clone()
                    .map(Into::into)
                    .unwrap_or(uuid::Uuid::new_v4()),
            });
            if let Ok(storage) = Storage::try_from(data.storage.clone()) {
                storage.add_client(data.storage_token.as_ref().unwrap().clone());
            }
        }
        let _ = data.notifier.send(req);
        Ok(HeartbeatResponse {})
    }
}

pub struct Session {
    rpc_mgr: BidirectRpcManager,

    data: SharedSessionData,
}

impl Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("data", &self.data).finish()
    }
}

impl Session {
    pub fn new(tunnel: Box<dyn Tunnel>, storage: WeakRefStorage, client_url: url::Url) -> Self {
        let rpc_mgr =
            BidirectRpcManager::new().set_rx_timeout(Some(std::time::Duration::from_secs(30)));
        rpc_mgr.run_with_tunnel(tunnel);

        let data = Arc::new(RwLock::new(SessionData::new(storage, client_url)));

        rpc_mgr.rpc_server().registry().register(
            WebServerServiceServer::new(SessionRpcService { data: data.clone() }),
            "",
        );

        Session { rpc_mgr, data }
    }

    pub fn is_running(&self) -> bool {
        self.rpc_mgr.is_running()
    }

    pub fn data(&self) -> SharedSessionData {
        self.data.clone()
    }

    pub fn scoped_rpc_client(
        &self,
    ) -> Box<dyn WebClientService<Controller = BaseController> + Send> {
        self.rpc_mgr
            .rpc_client()
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(1, 1, "".to_string())
    }

    pub async fn get_token(&self) -> Option<StorageToken> {
        self.data.read().await.storage_token.clone()
    }
}
