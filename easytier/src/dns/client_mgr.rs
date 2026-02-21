use crate::dns::utils::addr::NameServerAddr;
use crate::dns::utils::dirty::{DirtyFlag, DirtyState};
use crate::dns::zone::{Zone, ZoneGroup};
use crate::proto::dns::DnsClientMgrRpc;
use crate::proto::dns::{DnsSnapshot, HeartbeatRequest, HeartbeatResponse};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::utils::{DeterministicDigest, MapTryInto};
use anyhow::Error;
use hickory_server::authority::Catalog;
use itertools::Itertools;
use moka::future::Cache;
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct DnsClientInfo {
    digest: Vec<u8>,
    zones: ZoneGroup,
    addresses: HashSet<NameServerAddr>,
    listeners: HashSet<NameServerAddr>,
}

impl TryFrom<&DnsSnapshot> for DnsClientInfo {
    type Error = Error;

    fn try_from(value: &DnsSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            digest: value.digest(),
            zones: (&value.zones).try_into()?,
            addresses: value.addresses.iter().map_try_into().try_collect()?,
            listeners: value.listeners.iter().map_try_into().try_collect()?,
        })
    }
}

const DNS_CLIENT_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub struct DnsClientMgrDirtyFlags {
    pub(super) catalog: DirtyFlag,
    pub(super) addresses: DirtyFlag,
    pub(super) listeners: DirtyFlag,
}

#[derive(Debug)]
pub struct DnsClientMgr {
    clients: Cache<Uuid, DnsClientInfo>,
    pub(super) dirty: DirtyState<DnsClientMgrDirtyFlags>,
}

impl DnsClientMgr {
    pub fn new() -> Self {
        Self {
            clients: Cache::builder().time_to_live(DNS_CLIENT_TTL).build(),
            dirty: Default::default(),
        }
    }

    pub fn catalog(&self) -> Catalog {
        let zones = self.collect_zones();
        let mut catalog = Catalog::new();

        for zone in zones.iter() {
            catalog.upsert(
                zone.origin.clone(),
                zone.create_memory_authority().into_iter().collect(),
            );
        }

        for zone in zones.iter() {
            catalog.upsert(
                zone.origin.clone(),
                zone.create_forward_authority().into_iter().collect(),
            );
        }

        catalog
    }

    pub fn collect_zones(&self) -> ZoneGroup {
        let mut zones = vec![Zone::system()];
        let mut local = HashSet::<NameServerAddr>::new();

        for (_, info) in self.clients.iter() {
            zones.extend(info.zones);
            local.extend(info.addresses);
            local.extend(info.listeners);
        }

        for zone in zones.iter_mut() {
            if let Some(forward) = zone.forward.as_mut() {
                forward
                    .name_servers
                    .retain(|ns| !local.contains(&ns.clone().into()));
            }
        }

        zones.into()
    }

    pub fn iter_addresses(&self) -> impl Iterator<Item = NameServerAddr> + use<'_> {
        self.clients
            .iter()
            .flat_map(|(_, info)| info.addresses)
            .unique()
    }

    pub fn iter_listeners(&self) -> impl Iterator<Item = NameServerAddr> + use<'_> {
        self.clients
            .iter()
            .flat_map(|(_, info)| info.listeners)
            .unique()
    }
}

#[async_trait::async_trait]
impl DnsClientMgrRpc for DnsClientMgr {
    type Controller = BaseController;

    async fn heartbeat(
        &self,
        _: BaseController,
        input: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let id = input
            .id
            .ok_or(anyhow::anyhow!(
                "missing id in heartbeat request: {:?}",
                input
            ))?
            .into();

        let resync = if let Some(snapshot) = input.snapshot.as_ref() {
            let new = DnsClientInfo::try_from(snapshot)?;
            let old = self.clients.get(&id).await.unwrap_or_default();
            if new.digest != old.digest {
                self.dirty.catalog.mark();
                if new.addresses != old.addresses {
                    self.dirty.addresses.mark();
                }
                if new.listeners != old.listeners {
                    self.dirty.listeners.mark();
                }

                self.clients.insert(id, new).await;
                self.dirty.notify.notify_one();
            }
            false
        } else {
            self.clients
                .get(&id)
                .await
                .is_none_or(|info| info.digest != input.digest)
        };

        Ok(HeartbeatResponse { resync })
    }
}
