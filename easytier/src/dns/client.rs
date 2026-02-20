use super::config::DNS_SERVER_RPC_ADDR;
use crate::dns::peer_mgr::{DnsPeerMgr, DnsSnapshot};
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{DnsPeerManagerRpcServer, DnsServerRpcClientFactory, HeartbeatRequest};
use crate::proto::peer_rpc::RoutePeerInfo;
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::TcpTunnelConnector;
use crate::utils::DeterministicDigest;
use derivative::Derivative;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct Heartbeat {
    pub(super) id: Uuid,
    pub(super) digest: Vec<u8>,
    pub(super) snapshot: Option<DnsSnapshot>,
}

impl Heartbeat {
    pub fn new(id: Uuid) -> Self {
        Self {
            id,

            ..Default::default()
        }
    }

    pub fn update(&mut self, snapshot: DnsSnapshot) {
        self.digest = snapshot.digest();
        self.snapshot = Some(snapshot);
    }
}

impl From<Heartbeat> for HeartbeatRequest {
    fn from(value: Heartbeat) -> Self {
        Self {
            id: Some(value.id.into()),
            digest: value.digest,
            snapshot: value.snapshot.map(Into::into),
        }
    }
}

impl TryFrom<HeartbeatRequest> for Heartbeat {
    type Error = anyhow::Error;

    fn try_from(value: HeartbeatRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value
                .id
                .ok_or(anyhow::anyhow!("missing id in heartbeat"))?
                .into(),
            digest: value.digest,
            snapshot: value.snapshot.map(TryInto::try_into).transpose()?,
        })
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
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
        let mut heartbeat = Heartbeat::new(self.id());
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
        heartbeat: &mut Heartbeat,
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
