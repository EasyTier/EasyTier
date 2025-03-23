use std::sync::{Arc, Weak};

use tokio::{
    sync::{broadcast, Mutex},
    task::JoinSet,
    time::interval,
};

use crate::{
    common::{constants::EASYTIER_VERSION, get_machine_id},
    proto::{
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::controller::BaseController,
        web::{
            HeartbeatRequest, HeartbeatResponse, WebClientServiceServer,
            WebServerServiceClientFactory,
        },
    },
    tunnel::Tunnel,
};

use super::controller::Controller;

#[derive(Debug, Clone)]
struct HeartbeatCtx {
    notifier: Arc<broadcast::Sender<HeartbeatResponse>>,
    resp: Arc<Mutex<Option<HeartbeatResponse>>>,
}

pub struct Session {
    rpc_mgr: BidirectRpcManager,
    controller: Arc<Controller>,

    heartbeat_ctx: HeartbeatCtx,

    tasks: Mutex<JoinSet<()>>,
}

impl Session {
    pub fn new(tunnel: Box<dyn Tunnel>, controller: Arc<Controller>) -> Self {
        let rpc_mgr = BidirectRpcManager::new();
        rpc_mgr.run_with_tunnel(tunnel);

        rpc_mgr
            .rpc_server()
            .registry()
            .register(WebClientServiceServer::new(controller.clone()), "");

        let mut tasks: JoinSet<()> = JoinSet::new();
        let heartbeat_ctx =
            Self::heartbeat_routine(&rpc_mgr, Arc::downgrade(&controller), &mut tasks);

        Session {
            rpc_mgr,
            controller,
            heartbeat_ctx,
            tasks: Mutex::new(tasks),
        }
    }

    fn heartbeat_routine(
        rpc_mgr: &BidirectRpcManager,
        controller: Weak<Controller>,
        tasks: &mut JoinSet<()>,
    ) -> HeartbeatCtx {
        let (tx, _rx1) = broadcast::channel(2);

        let ctx = HeartbeatCtx {
            notifier: Arc::new(tx),
            resp: Arc::new(Mutex::new(None)),
        };

        let mid = get_machine_id();
        let inst_id = uuid::Uuid::new_v4();
        let token = controller.upgrade().unwrap().token();
        let hostname = controller.upgrade().unwrap().hostname();

        let ctx_clone = ctx.clone();
        let mut tick = interval(std::time::Duration::from_secs(1));
        let client = rpc_mgr
            .rpc_client()
            .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, "".to_string());
        tasks.spawn(async move {
            loop {
                tick.tick().await;

                let Some(controller) = controller.upgrade() else {
                    break;
                };

                let req = HeartbeatRequest {
                    machine_id: Some(mid.into()),
                    inst_id: Some(inst_id.into()),
                    user_token: token.to_string(),

                    easytier_version: EASYTIER_VERSION.to_string(),
                    hostname: hostname.clone(),
                    report_time: chrono::Local::now().to_rfc3339(),

                    running_network_instances: controller
                        .list_network_instance_ids()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                };

                match client
                    .heartbeat(BaseController::default(), req.clone())
                    .await
                {
                    Err(e) => {
                        tracing::error!("heartbeat failed: {:?}", e);
                        break;
                    }
                    Ok(resp) => {
                        tracing::debug!("heartbeat response: {:?}", resp);
                        let _ = ctx_clone.notifier.send(resp.clone());
                        ctx_clone.resp.lock().await.replace(resp);
                    }
                }
            }
        });

        ctx
    }

    async fn wait_routines(&self) {
        self.tasks.lock().await.join_next().await;
        // if any task failed, we should abort all tasks
        self.tasks.lock().await.abort_all();
    }

    pub async fn wait(&mut self) {
        tokio::select! {
            _ = self.rpc_mgr.wait() => {}
            _ = self.wait_routines() => {}
        }
    }

    pub async fn wait_next_heartbeat(&self) -> Option<HeartbeatResponse> {
        let mut rx = self.heartbeat_ctx.notifier.subscribe();
        rx.recv().await.ok()
    }
}
