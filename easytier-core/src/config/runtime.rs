//! Atomic runtime configuration owned by one core instance.

use std::{collections::BTreeSet, sync::Arc};

use arc_swap::ArcSwap;
use cidr::Ipv4Cidr;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::host::route::RouteDemand;
use registry::Registration;

use super::{
    gateway::{GatewayRuntimeConfig, ProxyRuntimeConfig},
    peers::{AclRuleConfig, PeerRuntimeSnapshot, PublicIpv6ProviderConfig},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreRuntimeConfig {
    pub acl: AclRuleConfig,
    pub dhcp_ipv4: bool,
    pub gateway: GatewayRuntimeConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_routes: Option<BTreeSet<Ipv4Cidr>>,
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
            manual_routes: None,
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
    manual_registration: Mutex<Option<Registration<RouteDemand>>>,
}

/// Atomic configuration authority shared by one core instance and its peer
/// context. Readers always observe a complete submitted version.
#[derive(Clone)]
pub struct CoreRuntimeConfigStore {
    inner: Arc<CoreRuntimeConfigStoreInner>,
}

impl CoreRuntimeConfigStore {
    pub fn new(
        services: CoreRuntimeConfig,
        peer: Arc<PeerRuntimeSnapshot>,
        manual_registration: Option<Registration<RouteDemand>>,
    ) -> Self {
        let (peer_changes, _) = tokio::sync::watch::channel(0);
        let (service_changes, _) = tokio::sync::watch::channel(0);
        Self {
            inner: Arc::new(CoreRuntimeConfigStoreInner {
                snapshot: ArcSwap::from_pointee(CoreInstanceRuntimeConfig { services, peer }),
                update: Mutex::new(()),
                peer_changes,
                service_changes,
                manual_registration: Mutex::new(manual_registration),
            }),
        }
    }

    pub fn snapshot(&self) -> Arc<CoreInstanceRuntimeConfig> {
        self.inner.snapshot.load_full()
    }

    pub(crate) fn with_snapshot<T>(&self, read: impl FnOnce(&CoreInstanceRuntimeConfig) -> T) -> T {
        let snapshot = self.inner.snapshot.load();
        read(&snapshot)
    }

    pub fn replace(&self, config: CoreInstanceRuntimeConfig) {
        let _update = self.inner.update.lock();
        let current = self.inner.snapshot.load_full();
        let manual_changed = current.services.manual_routes != config.services.manual_routes;
        let new_manual = if manual_changed {
            Some(config.services.manual_routes.clone())
        } else {
            None
        };
        let config = Arc::new(config);
        self.inner.snapshot.store(config);
        if let Some(new_manual) = new_manual {
            let registration = self.inner.manual_registration.lock();
            if let Some(reg) = registration.as_ref() {
                let _ = reg.replace(RouteDemand::ManualProxy(new_manual));
            }
        }
        self.inner.peer_changes.send_modify(|version| *version += 1);
        self.inner
            .service_changes
            .send_modify(|version| *version += 1);
    }

    pub(crate) fn replace_with_current(
        &self,
        mut config: CoreInstanceRuntimeConfig,
        merge: impl FnOnce(&CoreInstanceRuntimeConfig, &mut CoreInstanceRuntimeConfig),
    ) -> Arc<CoreInstanceRuntimeConfig> {
        let _update = self.inner.update.lock();
        let current = self.inner.snapshot.load_full();
        merge(&current, &mut config);
        let manual_changed = current.services.manual_routes != config.services.manual_routes;
        let new_manual = if manual_changed {
            Some(config.services.manual_routes.clone())
        } else {
            None
        };
        let config = Arc::new(config);
        self.inner.snapshot.store(config.clone());
        if let Some(new_manual) = new_manual {
            let registration = self.inner.manual_registration.lock();
            if let Some(reg) = registration.as_ref() {
                let _ = reg.replace(RouteDemand::ManualProxy(new_manual));
            }
        }
        self.inner.peer_changes.send_modify(|version| *version += 1);
        self.inner
            .service_changes
            .send_modify(|version| *version += 1);
        config
    }

    pub fn update_services(&self, update: impl FnOnce(&mut CoreRuntimeConfig)) {
        let _update = self.inner.update.lock();
        let current = self.inner.snapshot.load_full();
        let mut config = current.as_ref().clone();
        update(&mut config.services);
        let manual_changed = current.services.manual_routes != config.services.manual_routes;
        let new_manual = if manual_changed {
            Some(config.services.manual_routes.clone())
        } else {
            None
        };
        let config = Arc::new(config);
        self.inner.snapshot.store(config);
        if let Some(new_manual) = new_manual {
            let registration = self.inner.manual_registration.lock();
            if let Some(reg) = registration.as_ref() {
                let _ = reg.replace(RouteDemand::ManualProxy(new_manual));
            }
        }
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

    pub(crate) fn update_peer_with(&self, update: impl FnOnce(&mut PeerRuntimeSnapshot)) {
        let _update = self.inner.update.lock();
        let mut config = self.inner.snapshot.load_full().as_ref().clone();
        update(Arc::make_mut(&mut config.peer));
        self.inner.snapshot.store(Arc::new(config));
        self.inner.peer_changes.send_modify(|version| *version += 1);
    }

    pub fn subscribe_peer_runtime_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.peer_changes.subscribe()
    }

    pub fn subscribe_service_runtime_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.service_changes.subscribe()
    }
    #[cfg(test)]
    pub(crate) fn peer_change_subscriber_count(&self) -> usize {
        self.inner.peer_changes.receiver_count()
    }

    #[cfg(test)]
    pub(crate) fn service_change_subscriber_count(&self) -> usize {
        self.inner.service_changes.receiver_count()
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
            CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(before_peer), None);
        let before = store.snapshot();

        let after_services = CoreRuntimeConfig {
            dhcp_ipv4: true,
            ..Default::default()
        };
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
            None,
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
            None,
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
            None,
        );
        let changes = store.subscribe_service_runtime_changes();
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.core.node.hostname = Some("updated".to_owned());

        store.update_peer(Arc::new(peer));

        assert!(!changes.has_changed().unwrap());
    }

    #[test]
    fn peer_in_place_update_preserves_the_rest_of_the_atomic_snapshot() {
        let services = CoreRuntimeConfig {
            dhcp_ipv4: true,
            ..Default::default()
        };
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.core.node.hostname = Some("preserved".to_owned());
        let store = CoreRuntimeConfigStore::new(services, Arc::new(peer), None);

        store.update_peer_with(|peer| {
            peer.runtime.core.routes.ipv4 = Some(crate::config::IpPrefix {
                address: "10.20.30.7".parse().unwrap(),
                prefix_len: 24,
            });
        });

        let snapshot = store.snapshot();
        assert!(snapshot.services.dhcp_ipv4);
        assert_eq!(
            snapshot.peer.runtime.core.node.hostname.as_deref(),
            Some("preserved")
        );
        assert_eq!(
            snapshot
                .peer
                .runtime
                .core
                .routes
                .ipv4
                .as_ref()
                .unwrap()
                .address,
            "10.20.30.7".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn manual_routes_update_replaces_registration_only_on_change() {
        let registry = registry::Registry::default();
        let registration = registry
            .register(RouteDemand::ManualProxy(None))
            .expect("register succeeds");

        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
            Some(registration),
        );

        let initial_demand = registry.snapshot();
        assert_eq!(initial_demand[0].as_ref(), &RouteDemand::ManualProxy(None));

        // Update unrelated service: registration remains untouched
        store.update_services(|s| s.dhcp_ipv4 = true);
        assert_eq!(
            registry.snapshot()[0].as_ref(),
            &RouteDemand::ManualProxy(None)
        );

        // Update manual routes: registration updated
        let cidrs: BTreeSet<Ipv4Cidr> = BTreeSet::from(["10.0.0.0/8".parse().unwrap()]);
        store.update_services(|s| s.manual_routes = Some(cidrs.clone()));
        assert_eq!(
            registry.snapshot()[0].as_ref(),
            &RouteDemand::ManualProxy(Some(cidrs.clone()))
        );

        // Update peer: registration unchanged
        store.update_peer(Arc::new(PeerRuntimeSnapshot::default()));
        assert_eq!(
            registry.snapshot()[0].as_ref(),
            &RouteDemand::ManualProxy(Some(cidrs))
        );
    }

    #[test]
    fn missing_manual_routes_preserves_portable_config_compatibility() {
        let encoded = serde_json::to_value(CoreRuntimeConfig::default()).unwrap();
        assert!(encoded.get("manual_routes").is_none());

        let decoded: CoreRuntimeConfig = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.manual_routes, None);
    }
}
