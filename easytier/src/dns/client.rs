use super::config::{DnsGlobalCtxExt, DNS_SERVER_RPC_ADDR};
use crate::common::config::ConfigLoader;
use crate::common::PeerId;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{
    DeterministicDigest, DnsPeerManagerRpc, DnsPeerManagerRpcClientFactory,
    DnsPeerManagerRpcServer, DnsServerRpcClientFactory, DnsSnapshot, GetExportConfigRequest,
    GetExportConfigResponse, HeartbeatRequest,
};
use crate::proto::peer_rpc::RoutePeerInfo;
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::TcpTunnelConnector;
use anyhow::Context;
use derivative::Derivative;
use derive_more::Deref;
use moka::future::Cache;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DnsPeerInfo {
    digest: Vec<u8>,
    config: GetExportConfigResponse,
}

impl DnsPeerInfo {
    pub fn new(config: GetExportConfigResponse) -> Self {
        Self {
            digest: config.digest(),
            config,
        }
    }
}

#[derive(Derivative, Deref)]
#[derivative(Debug)]
pub struct DnsPeerManager {
    #[deref]
    mgr: Arc<PeerManager>,

    cache: Cache<PeerId, DnsPeerInfo>,
    dirty: AtomicBool,
}

impl DnsPeerManager {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            mgr: peer_mgr.clone(),
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build()
                .into(),
            dirty: AtomicBool::new(true),
        }
    }

    fn snapshot(&self) -> DnsSnapshot {
        let global_ctx = self.get_global_ctx_ref();
        let config = global_ctx.config.get_dns();

        let mut zones = Vec::new();

        zones.extend(config.zones.iter().map(Into::into));
        zones.extend(global_ctx.dns_self_zone().as_ref().map(Into::into));

        for (_, info) in self.cache.iter() {
            zones.extend(info.config.zones.clone().into_iter());
        }

        DnsSnapshot {
            zones,
            addresses: config
                .addresses
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
            listeners: config
                .listeners
                .iter()
                .map(Url::from)
                .map(Into::into)
                .collect(),
        }
    }

    async fn refresh(&self, peer_id: PeerId, digest: Vec<u8>) {
        if let Some(info) = self.cache.get(&peer_id).await {
            if info.digest == *digest {
                return;
            }
        };

        match self.fetch(peer_id).await {
            Ok(config) => {
                self.cache.insert(peer_id, DnsPeerInfo::new(config)).await;
            }
            Err(e) => {
                tracing::warn!("failed to fetch dns config from peer {}: {:?}", peer_id, e);
                self.cache.invalidate(&peer_id).await;
            }
        }

        self.dirty.store(true, Ordering::Release);
    }

    async fn fetch(&self, peer_id: PeerId) -> anyhow::Result<GetExportConfigResponse> {
        self.get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DnsPeerManagerRpcClientFactory<BaseController>>(
                self.mgr.my_peer_id(),
                peer_id,
                "".to_string(),
            )
            .get_export_config(BaseController::default(), GetExportConfigRequest {})
            .await
            .context("rpc call failed")
    }
}

#[async_trait::async_trait]
impl DnsPeerManagerRpc for DnsPeerManager {
    type Controller = BaseController;

    async fn get_export_config(
        &self,
        _: Self::Controller,
        _: GetExportConfigRequest,
    ) -> rpc_types::error::Result<GetExportConfigResponse> {
        Ok(self.get_global_ctx_ref().dns_export_config())
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct DnsClient {
    mgr: Arc<DnsPeerManager>,

    tasks: JoinSet<()>,

    #[derivative(Debug = "ignore")]
    // Client to talk to local DnsServer
    server_rpc_client: Arc<Mutex<StandAloneClient<TcpTunnelConnector>>>,
}

impl DnsClient {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let connector = TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone());
        let server_rpc_client = Arc::new(Mutex::new(StandAloneClient::new(connector)));

        let mgr = Arc::new(DnsPeerManager::new(peer_mgr.clone()));
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
            server_rpc_client,
        }
    }

    pub fn id(&self) -> Uuid {
        self.mgr.get_global_ctx_ref().get_id().into()
    }

    pub async fn run(&self) {
        let mut snapshot = Default::default();
        let mut digest = Vec::new();
        loop {
            let snapshot = self.mgr.dirty.swap(false, Ordering::Release).then(|| {
                snapshot = self.mgr.snapshot();
                digest = snapshot.digest();

                snapshot.clone()
            });

            let heartbeat = HeartbeatRequest {
                id: Some(self.id().into()),
                digest: digest.clone(),
                snapshot,
            };

            if let Err(e) = self.heartbeat(heartbeat).await {
                tracing::error!("DnsClient heartbeat failed: {:?}", e);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn heartbeat(&self, heartbeat: HeartbeatRequest) -> anyhow::Result<()> {
        // scoped_client of StandAloneClient takes &mut self
        let client = {
            let mut client = self.server_rpc_client.lock().await; // Lock the mutex
            client
                .scoped_client::<DnsServerRpcClientFactory<BaseController>>("".to_string())
                .await?
        };

        client
            .heartbeat(BaseController::default(), heartbeat)
            .await?;
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
