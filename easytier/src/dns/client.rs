use crate::dns::config::DNS_SERVER_RPC_ADDR;
use crate::dns::peer_mgr::DnsPeerMgr;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{DnsPeerManagerRpcServer, DnsServerRpcClientFactory, HeartbeatRequest};
use crate::proto::peer_rpc::RoutePeerInfo;
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::TcpTunnelConnector;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Debug)]
pub struct DnsClient {
    mgr: Arc<DnsPeerMgr>,

    tasks: JoinSet<()>,
}

impl DnsClient {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let mgr = Arc::new(DnsPeerMgr::new(peer_mgr.clone()));
        peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DnsPeerManagerRpcServer::new_arc(mgr.clone()),
                &peer_mgr.get_global_ctx_ref().get_network_name(),
            );

        Self {
            mgr,
            tasks: JoinSet::new(),
        }
    }

    pub fn id(&self) -> Uuid {
        self.mgr.get_global_ctx_ref().get_id()
    }

    pub async fn run(&self) {
        let mut rpc = StandAloneClient::new(TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone()));
        let mut heartbeat = HeartbeatRequest {
            id: Some(self.id().into()),

            ..Default::default()
        };
        loop {
            if let Err(e) = self.heartbeat(&mut rpc, &mut heartbeat).await {
                tracing::error!("DnsClient heartbeat failed: {:?}", e);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn heartbeat(
        &self,
        rpc: &mut StandAloneClient<TcpTunnelConnector>,
        heartbeat: &mut HeartbeatRequest,
    ) -> anyhow::Result<()> {
        let request =
            if heartbeat.snapshot.is_none() || self.mgr.dirty.swap(false, Ordering::Release) {
                heartbeat.update(self.mgr.snapshot());
                heartbeat.clone().into()
            } else {
                let snapshot = heartbeat.snapshot.take();
                let request = heartbeat.clone().into();
                heartbeat.snapshot = snapshot;
                request
            };

        let client = rpc
            .scoped_client::<DnsServerRpcClientFactory<BaseController>>("".to_string())
            .await?;

        let response = client.heartbeat(BaseController::default(), request).await?;
        if response.resync {
            client
                .heartbeat(BaseController::default(), heartbeat.clone().into())
                .await?;
        }

        Ok(())
    }

    pub async fn refresh(&mut self, peer_info: &RoutePeerInfo) {
        let mgr = self.mgr.clone();
        let peer_id = peer_info.peer_id;
        let digest = peer_info.dns.clone();
        self.tasks
            .spawn_local(async move { mgr.refresh(peer_id, digest).await });
    }
}
