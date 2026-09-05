//! The DNS server owns listeners; its Host owns interface and system resources.
use std::{collections::HashSet, net::IpAddr};

use tokio::sync::watch;
use uuid::Uuid;

use super::system::SystemConfig;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsInterfaceState {
    pub generation: u64,
    pub available: bool,
}

#[async_trait::async_trait]
pub trait DnsHost: Send + Sync + std::fmt::Debug {
    fn subscribe(&self) -> watch::Receiver<DnsInterfaceState>;

    /// Returns the requested IPs that are actually available on this generation.
    async fn addresses(
        &self,
        owner: Uuid,
        generation: u64,
        desired: &HashSet<IpAddr>,
    ) -> anyhow::Result<HashSet<IpAddr>>;

    async fn system_dns(
        &self,
        owner: Uuid,
        generation: u64,
        config: &SystemConfig,
    ) -> anyhow::Result<()>;

    async fn clear_system_dns(&self, owner: Uuid) -> anyhow::Result<()>;

    /// Release only this owner's resources, even if the interface has changed.
    async fn release(&self, owner: Uuid) -> anyhow::Result<()>;
}

#[derive(Debug, Default)]
pub struct NoDnsInterface;

#[async_trait::async_trait]
impl DnsHost for NoDnsInterface {
    fn subscribe(&self) -> watch::Receiver<DnsInterfaceState> {
        watch::channel(DnsInterfaceState::default()).1
    }

    async fn addresses(
        &self,
        _: Uuid,
        _: u64,
        _: &HashSet<IpAddr>,
    ) -> anyhow::Result<HashSet<IpAddr>> {
        Ok(HashSet::new())
    }

    async fn system_dns(&self, _: Uuid, _: u64, _: &SystemConfig) -> anyhow::Result<()> {
        Ok(())
    }

    async fn release(&self, _: Uuid) -> anyhow::Result<()> {
        Ok(())
    }

    async fn clear_system_dns(&self, _: Uuid) -> anyhow::Result<()> {
        Ok(())
    }
}
