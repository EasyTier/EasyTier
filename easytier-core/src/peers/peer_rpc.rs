use std::sync::{Arc, Mutex};

use futures::{SinkExt as _, StreamExt};
use tokio::task::JoinSet;

use crate::{
    config::PeerId,
    foundation::stats::{ArcRpcMetrics, RpcMetricsProvider},
    packet::ZCPacket,
    rpc::{self, bidirect::BidirectRpcManager},
};

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerRpcManagerTransport: Send + Sync + 'static {
    fn my_peer_id(&self) -> PeerId;
    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> anyhow::Result<()>;
    async fn recv(&self) -> anyhow::Result<ZCPacket>;
}

pub struct PeerRpcManager {
    tspt: Arc<Box<dyn PeerRpcManagerTransport>>,
    bidirect_rpc: BidirectRpcManager,
    tasks: Mutex<JoinSet<()>>,
}

impl std::fmt::Debug for PeerRpcManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRpcManager")
            .field("node_id", &self.tspt.my_peer_id())
            .finish()
    }
}

impl PeerRpcManager {
    pub fn new(tspt: impl PeerRpcManagerTransport) -> Self {
        Self {
            tspt: Arc::new(Box::new(tspt)),
            bidirect_rpc: BidirectRpcManager::new(),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub fn new_with_stats_manager<T>(tspt: impl PeerRpcManagerTransport, stats_manager: T) -> Self
    where
        T: Clone + RpcMetricsProvider,
    {
        Self {
            tspt: Arc::new(Box::new(tspt)),
            bidirect_rpc: BidirectRpcManager::new_with_stats_manager(stats_manager),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub fn new_with_metrics(tspt: impl PeerRpcManagerTransport, metrics: ArcRpcMetrics) -> Self {
        Self {
            tspt: Arc::new(Box::new(tspt)),
            bidirect_rpc: BidirectRpcManager::new_with_metrics(metrics),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub fn run(&self) {
        let ret = self.bidirect_rpc.run_and_create_tunnel();
        let (mut rx, mut tx) = ret.split();
        let tspt = self.tspt.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(packet)) = rx.next().await {
                let dst_peer_id = packet.peer_manager_header().unwrap().to_peer_id.into();
                if let Err(e) = tspt.send(packet, dst_peer_id).await {
                    tracing::error!("send to rpc tspt error: {:?}", e);
                }
            }
        });

        let tspt = self.tspt.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(packet) = tspt.recv().await {
                if let Err(e) = tx.send(packet).await {
                    tracing::error!("send to rpc tspt error: {:?}", e);
                }
            }
        });
    }

    pub async fn stop(&self) {
        self.bidirect_rpc.stop().await;
        let mut tasks = {
            let mut task_slot = self.tasks.lock().unwrap();
            std::mem::replace(&mut *task_slot, JoinSet::new())
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    pub fn rpc_client(&self) -> &rpc::client::Client {
        self.bidirect_rpc.rpc_client()
    }

    pub fn rpc_server(&self) -> &rpc::server::Server {
        self.bidirect_rpc.rpc_server()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.tspt.my_peer_id()
    }
}

impl Drop for PeerRpcManager {
    fn drop(&mut self) {
        tracing::debug!("PeerRpcManager drop, my_peer_id: {:?}", self.my_peer_id());
    }
}
