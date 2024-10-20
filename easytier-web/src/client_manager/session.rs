use std::sync::Arc;

use easytier::{
    proto::{
        rpc_impl::{bidirect::BidirectRpcManager, service_registry::ServiceRegistry},
        rpc_types::{self, controller::BaseController},
        web::{HeartbeatRequest, HeartbeatResponse, WebServerService, WebServerServiceServer},
    },
    tunnel::Tunnel,
};
use tokio::sync::{broadcast, Mutex, RwLock};

pub struct SessionData {
    notifier: broadcast::Sender<HeartbeatRequest>,
    req: Option<HeartbeatRequest>,
}

impl SessionData {
    fn new() -> Self {
        let (tx, _rx1) = broadcast::channel(2);

        SessionData {
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
        data.req.replace(req.clone());
        let _ = data.notifier.send(req);
        Ok(HeartbeatResponse {})
    }
}

pub struct Session {
    rpc_mgr: BidirectRpcManager,

    data: SharedSessionData,
}

impl Session {
    pub fn new(tunnel: Box<dyn Tunnel>) -> Self {
        let rpc_mgr =
            BidirectRpcManager::new().set_rx_timeout(Some(std::time::Duration::from_secs(30)));
        rpc_mgr.run_with_tunnel(tunnel);

        let data = Arc::new(RwLock::new(SessionData::new()));

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
}
