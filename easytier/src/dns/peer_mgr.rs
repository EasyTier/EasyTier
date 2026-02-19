use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use derivative::Derivative;
use derive_more::Deref;
use moka::future::Cache;
use url::Url;
use anyhow::Context;
use crate::common::config::ConfigLoader;
use crate::common::PeerId;
use crate::dns::config::DnsGlobalCtxExt;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{DeterministicDigest, DnsPeerManagerRpc, DnsPeerManagerRpcClientFactory, DnsSnapshot, GetExportConfigRequest, GetExportConfigResponse};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;

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
pub struct DnsPeerMgr {
    #[deref]
    mgr: Arc<PeerManager>,

    cache: Cache<PeerId, DnsPeerInfo>,
    pub(super) dirty: AtomicBool,
}

impl DnsPeerMgr {
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

    pub fn snapshot(&self) -> DnsSnapshot {
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

    pub(super) async fn refresh(&self, peer_id: PeerId, digest: Vec<u8>) {
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
impl DnsPeerManagerRpc for DnsPeerMgr {
    type Controller = BaseController;

    async fn get_export_config(
        &self,
        _: Self::Controller,
        _: GetExportConfigRequest,
    ) -> rpc_types::error::Result<GetExportConfigResponse> {
        Ok(self.get_global_ctx_ref().dns_export_config())
    }
}