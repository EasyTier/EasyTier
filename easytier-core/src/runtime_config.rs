//! Atomic runtime configuration owned by one core instance.

use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::{
    peers::{
        acl_config::AclRuleConfig, context::PeerRuntimeSnapshot,
        public_ipv6::PublicIpv6ProviderConfig,
    },
    proxy::{ProxyRuntimeConfig, gateway::GatewayRuntimeConfig},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreRuntimeConfig {
    pub acl: AclRuleConfig,
    pub dhcp_ipv4: bool,
    pub gateway: GatewayRuntimeConfig,
    pub proxy: ProxyRuntimeConfig,
    #[serde(default)]
    pub public_ipv6_auto: bool,
    pub public_ipv6_provider: PublicIpv6ProviderConfig,
}

impl Default for CoreRuntimeConfig {
    fn default() -> Self {
        Self {
            acl: AclRuleConfig::default(),
            dhcp_ipv4: false,
            gateway: GatewayRuntimeConfig::default(),
            proxy: ProxyRuntimeConfig::default(),
            public_ipv6_auto: false,
            public_ipv6_provider: PublicIpv6ProviderConfig {
                provider_enabled: false,
                configured_prefix: None,
                provider_supported: false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreInstanceRuntimeConfig {
    pub services: CoreRuntimeConfig,
    pub peer: Arc<PeerRuntimeSnapshot>,
}

struct CoreRuntimeConfigStoreInner {
    snapshot: ArcSwap<CoreInstanceRuntimeConfig>,
    update: Mutex<()>,
    peer_changes: tokio::sync::watch::Sender<u64>,
    service_changes: tokio::sync::watch::Sender<u64>,
}

/// Atomic configuration authority shared by one core instance and its peer
/// context. Readers always observe a complete submitted version.
#[derive(Clone)]
pub struct CoreRuntimeConfigStore {
    inner: Arc<CoreRuntimeConfigStoreInner>,
}

impl CoreRuntimeConfigStore {
    pub fn new(services: CoreRuntimeConfig, peer: Arc<PeerRuntimeSnapshot>) -> Self {
        let (peer_changes, _) = tokio::sync::watch::channel(0);
        let (service_changes, _) = tokio::sync::watch::channel(0);
        Self {
            inner: Arc::new(CoreRuntimeConfigStoreInner {
                snapshot: ArcSwap::from_pointee(CoreInstanceRuntimeConfig { services, peer }),
                update: Mutex::new(()),
                peer_changes,
                service_changes,
            }),
        }
    }

    pub fn snapshot(&self) -> Arc<CoreInstanceRuntimeConfig> {
        self.inner.snapshot.load_full()
    }

    pub fn replace(&self, config: CoreInstanceRuntimeConfig) {
        let _update = self.inner.update.lock();
        self.inner.snapshot.store(Arc::new(config));
        self.inner.peer_changes.send_modify(|version| *version += 1);
        self.inner
            .service_changes
            .send_modify(|version| *version += 1);
    }

    pub fn update_services(&self, update: impl FnOnce(&mut CoreRuntimeConfig)) {
        let _update = self.inner.update.lock();
        let mut config = self.inner.snapshot.load_full().as_ref().clone();
        update(&mut config.services);
        self.inner.snapshot.store(Arc::new(config));
        self.inner
            .service_changes
            .send_modify(|version| *version += 1);
    }

    pub fn update_peer(&self, peer: Arc<PeerRuntimeSnapshot>) {
        let _update = self.inner.update.lock();
        let mut config = self.inner.snapshot.load_full().as_ref().clone();
        config.peer = peer;
        self.inner.snapshot.store(Arc::new(config));
        self.inner.peer_changes.send_modify(|version| *version += 1);
    }

    pub fn subscribe_peer_runtime_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.peer_changes.subscribe()
    }

    pub fn subscribe_service_runtime_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.service_changes.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_service_and_peer_as_one_version() {
        let mut before_peer = PeerRuntimeSnapshot::default();
        before_peer.runtime.core.node.hostname = Some("before".to_owned());
        let store =
            CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(before_peer));
        let before = store.snapshot();

        let mut after_services = CoreRuntimeConfig::default();
        after_services.dhcp_ipv4 = true;
        let mut after_peer = PeerRuntimeSnapshot::default();
        after_peer.runtime.core.node.hostname = Some("after".to_owned());
        store.replace(CoreInstanceRuntimeConfig {
            services: after_services,
            peer: Arc::new(after_peer),
        });

        assert!(!before.services.dhcp_ipv4);
        assert_eq!(
            before.peer.runtime.core.node.hostname.as_deref(),
            Some("before")
        );
        let after = store.snapshot();
        assert!(after.services.dhcp_ipv4);
        assert_eq!(
            after.peer.runtime.core.node.hostname.as_deref(),
            Some("after")
        );
    }

    #[tokio::test]
    async fn notifies_peer_snapshot_changes() {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let mut changes = store.subscribe_peer_runtime_changes();
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.core.node.hostname = Some("updated".to_owned());

        store.update_peer(Arc::new(peer));

        assert!(changes.changed().await.is_ok());
    }

    #[tokio::test]
    async fn notifies_service_snapshot_changes() {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let mut changes = store.subscribe_service_runtime_changes();

        store.update_services(|services| services.dhcp_ipv4 = true);

        assert!(changes.changed().await.is_ok());
        assert!(store.snapshot().services.dhcp_ipv4);
    }

    #[tokio::test]
    async fn peer_update_does_not_notify_service_watchers() {
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let changes = store.subscribe_service_runtime_changes();
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.core.node.hostname = Some("updated".to_owned());

        store.update_peer(Arc::new(peer));

        assert!(!changes.has_changed().unwrap());
    }
}
