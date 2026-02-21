use crate::common::config::ConfigLoader;
use crate::common::PeerId;
use crate::dns::config::{DnsExportConfig, DnsGlobalCtxExt};
use crate::dns::zone::ZoneGroup;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{
    DnsPeerMgrRpc, DnsPeerMgrRpcClientFactory, DnsSnapshot, GetExportConfigRequest,
    GetExportConfigResponse, ZoneData,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::utils::DeterministicDigest;
use anyhow::Context;
use derive_more::Deref;
use itertools::Itertools;
use moka::future::Cache;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DnsPeerInfo {
    digest: Vec<u8>,
    zones: Vec<ZoneData>,
}

impl TryFrom<DnsExportConfig> for DnsPeerInfo {
    type Error = anyhow::Error;

    fn try_from(value: DnsExportConfig) -> Result<Self, Self::Error> {
        let _ = ZoneGroup::try_from(&value.zones)?;
        Ok(Self {
            digest: value.digest(),
            zones: value.zones,
        })
    }
}

const DNS_PEER_TTL: Duration = Duration::from_secs(3);

#[derive(Debug, Deref)]
pub struct DnsPeerMgr {
    #[deref]
    mgr: Arc<PeerManager>,

    peers: Cache<PeerId, DnsPeerInfo>,
    pub(super) dirty: AtomicBool,
}

impl DnsPeerMgr {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            mgr: peer_mgr.clone(),
            peers: Cache::builder().time_to_live(DNS_PEER_TTL).build(),
            dirty: AtomicBool::new(true),
        }
    }

    pub fn snapshot(&self) -> DnsSnapshot {
        let global_ctx = self.get_global_ctx_ref();
        let config = global_ctx.config.get_dns();

        let zones = config
            .zones
            .into_iter()
            .map_into()
            .chain(global_ctx.dns_self_zone().into_iter().map_into())
            .chain(
                self.peers
                    .iter()
                    .map(|(_, info)| info.zones.into_iter())
                    .flatten(),
            )
            .collect();

        DnsSnapshot {
            zones,
            addresses: config.addresses.into(),
            listeners: config.listeners.into(),
        }
    }

    pub(super) async fn refresh(&self, peer_id: PeerId, digest: Vec<u8>) {
        if let Some(info) = self.peers.get(&peer_id).await {
            if info.digest == *digest {
                return;
            }
        };

        match self.fetch(peer_id).await {
            Ok(info) => {
                self.peers.insert(peer_id, info).await;
            }
            Err(e) => {
                tracing::warn!(
                    "failed to fetch dns export config from peer {}: {:?}",
                    peer_id,
                    e
                );
                self.peers.invalidate(&peer_id).await;
            }
        }

        self.dirty.store(true, Ordering::Release);
    }

    async fn fetch(&self, peer_id: PeerId) -> anyhow::Result<DnsPeerInfo> {
        self.get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DnsPeerMgrRpcClientFactory<BaseController>>(
                self.mgr.my_peer_id(),
                peer_id,
                "".to_string(),
            )
            .get_export_config(BaseController::default(), GetExportConfigRequest {})
            .await
            .context("rpc call failed")?
            .try_into()
    }
}

#[async_trait::async_trait]
impl DnsPeerMgrRpc for DnsPeerMgr {
    type Controller = BaseController;

    async fn get_export_config(
        &self,
        _: Self::Controller,
        _: GetExportConfigRequest,
    ) -> rpc_types::error::Result<GetExportConfigResponse> {
        Ok(self.get_global_ctx_ref().dns_export_config())
    }
}
