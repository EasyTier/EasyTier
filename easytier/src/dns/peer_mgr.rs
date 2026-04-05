use crate::common::global_ctx::ArcGlobalCtx;
use crate::common::PeerId;
use crate::dns::config::{DnsExportConfig, DnsGlobalCtxExt};
use crate::dns::utils::dirty::DirtyFlag;
use crate::dns::zone::ZoneGroup;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::peer_manager::PeerManager;
use crate::peers::route_trait::Route;
use crate::proto::dns::{
    DnsPeerMgrRpc, DnsPeerMgrRpcClientFactory, DnsPeerMgrRpcServer, DnsSnapshot,
    GetExportConfigRequest, GetExportConfigResponse, ZoneData,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::utils::DeterministicDigest;
use anyhow::Context;
use itertools::Itertools;
use moka::future::Cache;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

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

#[derive(Debug)]
pub struct DnsPeerMgrInner {
    peers: Cache<PeerId, DnsPeerInfo>,
    pub dirty: DirtyFlag,

    peer_mgr: Arc<PeerManager>,
    global_ctx: ArcGlobalCtx,
}

impl DnsPeerMgrInner {
    pub fn snapshot(&self) -> DnsSnapshot {
        let global_ctx = &self.global_ctx;

        let zones = global_ctx
            .dns_iter_zones()
            .map_into()
            .chain(
                self.peers
                    .iter()
                    .flat_map(|(_, info)| info.zones.into_iter()),
            )
            .collect();

        let config = global_ctx.config.get_dns();
        DnsSnapshot {
            zones,
            addresses: config.addresses.into(),
            listeners: config.listeners.into(),
        }
    }

    pub async fn refresh(&self, peer_id: PeerId) {
        if peer_id == self.peer_mgr.my_peer_id() {
            self.dirty.mark();
            self.dirty.notify_one();
            return;
        }

        let Some(route) = self.peer_mgr.get_route().get_peer_info(peer_id).await else {
            return;
        };
        if self
            .peers
            .get(&peer_id)
            .await
            .is_some_and(|info| info.digest == *route.dns)
        {
            return;
        }

        self.dirty.mark();

        let invalidate = route.dns.is_empty()
            || match self.fetch(peer_id).await {
                Ok(info) => {
                    self.peers.insert(peer_id, info).await;
                    false
                }
                Err(error) => {
                    tracing::warn!(%peer_id, ?error, "failed to fetch dns export config from peer");
                    true
                }
            };

        if invalidate {
            self.peers.invalidate(&peer_id).await;
        }

        self.dirty.notify_one();
    }

    #[instrument(skip(self), level = "trace", ret)]
    async fn fetch(&self, peer_id: PeerId) -> anyhow::Result<DnsPeerInfo> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DnsPeerMgrRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                peer_id,
                self.global_ctx.get_network_name(),
            )
            .get_export_config(BaseController::default(), GetExportConfigRequest {})
            .await
            .context("rpc call failed")?
            .try_into()
    }
}

#[async_trait::async_trait]
impl DnsPeerMgrRpc for DnsPeerMgrInner {
    type Controller = BaseController;

    async fn get_export_config(
        &self,
        _: Self::Controller,
        _: GetExportConfigRequest,
    ) -> rpc_types::error::Result<GetExportConfigResponse> {
        Ok(self.global_ctx.dns_export_config())
    }
}

#[derive(Debug)]
pub struct DnsPeerMgr(Arc<DnsPeerMgrInner>);

impl DnsPeerMgr {
    pub fn new(peer_mgr: Arc<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        Self(Arc::new(DnsPeerMgrInner {
            peers: Cache::builder().time_to_live(DNS_PEER_TTL).build(),
            dirty: Default::default(),
            peer_mgr,
            global_ctx,
        }))
    }

    pub fn register(&self) {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DnsPeerMgrRpcServer::new_arc(self.0.clone()),
                &self.global_ctx.get_network_name(),
            );
    }

    pub fn unregister(&self) -> Option<()> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .unregister(
                DnsPeerMgrRpcServer::new_arc(self.0.clone()),
                &self.global_ctx.get_network_name(),
            )
    }
}

impl Deref for DnsPeerMgr {
    type Target = DnsPeerMgrInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for DnsPeerMgr {
    fn drop(&mut self) {
        self.unregister();
    }
}
