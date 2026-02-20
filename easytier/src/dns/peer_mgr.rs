use crate::common::config::ConfigLoader;
use crate::common::PeerId;
use crate::dns::config::{DnsExportConfig, DnsGlobalCtxExt};
use crate::dns::utils::NameServerAddrGroup;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::peer_manager::PeerManager;
use crate::proto;
use crate::proto::dns::{DnsPeerManagerRpc, DnsPeerManagerRpcClientFactory, GetExportConfigRequest, GetExportConfigResponse, ZoneData};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use anyhow::Context;
use derive_more::Deref;
use moka::future::Cache;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use itertools::Itertools;
use serde::Serialize;
use crate::utils::DeterministicDigest;

#[derive(Debug, Clone)]
pub struct DnsPeerInfo {
    digest: Vec<u8>,
    config: DnsExportConfig,
}

impl DnsPeerInfo {
    pub fn new(config: DnsExportConfig) -> Self {
        Self {
            digest: config.digest(),
            config,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsSnapshot {
    pub(super) zones: Vec<ZoneData>,
    pub(super) addresses: NameServerAddrGroup,
    pub(super) listeners: NameServerAddrGroup,
}

impl From<DnsSnapshot> for proto::dns::DnsSnapshot {
    fn from(value: DnsSnapshot) -> Self {
        Self {
            zones: value.zones,
            addresses: value.addresses.into(),
            listeners: value.listeners.into(),
        }
    }
}

impl TryFrom<proto::dns::DnsSnapshot> for DnsSnapshot {
    type Error = anyhow::Error;

    fn try_from(value: proto::dns::DnsSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            zones: value.zones,
            addresses: (&value.addresses).try_into()?,
            listeners: (&value.listeners).try_into()?,
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

        let mut zones = Vec::new();

        zones.extend(config.zones.iter().cloned().map_into());
        zones.extend(global_ctx.dns_self_zone().map(Into::into));

        for (_, info) in self.peers.iter() {
            zones.extend(info.config.zones.iter().cloned());
        }

        DnsSnapshot {
            zones,
            addresses: config.addresses.clone(),
            listeners: config.listeners.clone(),
        }
    }

    pub(super) async fn refresh(&self, peer_id: PeerId, digest: Vec<u8>) {
        if let Some(info) = self.peers.get(&peer_id).await {
            if info.digest == *digest {
                return;
            }
        };

        match self.fetch(peer_id).await {
            Ok(config) => {
                self.peers.insert(peer_id, DnsPeerInfo::new(config)).await;
            }
            Err(e) => {
                tracing::warn!("failed to fetch dns export config from peer {}: {:?}", peer_id, e);
                self.peers.invalidate(&peer_id).await;
            }
        }

        self.dirty.store(true, Ordering::Release);
    }

    async fn fetch(&self, peer_id: PeerId) -> anyhow::Result<DnsExportConfig> {
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
