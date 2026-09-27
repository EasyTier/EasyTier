//! Atomic runtime configuration owned by one core instance.

use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::config::InstanceConfig;

struct InstanceConfigStoreInner {
    snapshot: ArcSwap<InstanceConfig>,
    update: Mutex<()>,
    config_changes: tokio::sync::watch::Sender<u64>,
    peer_runtime_changes: tokio::sync::watch::Sender<u64>,
}

/// Atomic configuration authority shared by one core instance and its peer
/// context. Readers always observe a complete submitted version.
#[derive(Clone)]
pub struct InstanceConfigStore {
    inner: Arc<InstanceConfigStoreInner>,
}

impl InstanceConfigStore {
    pub fn new(config: InstanceConfig) -> Self {
        let (config_changes, _) = tokio::sync::watch::channel(0);
        let (peer_runtime_changes, _) = tokio::sync::watch::channel(0);
        Self {
            inner: Arc::new(InstanceConfigStoreInner {
                snapshot: ArcSwap::from_pointee(config),
                update: Mutex::new(()),
                config_changes,
                peer_runtime_changes,
            }),
        }
    }

    pub fn snapshot(&self) -> Arc<InstanceConfig> {
        self.inner.snapshot.load_full()
    }

    pub fn replace(&self, config: InstanceConfig) -> Arc<InstanceConfig> {
        let _update = self.inner.update.lock();
        let config = Arc::new(config);
        self.inner.snapshot.store(config.clone());
        self.inner
            .config_changes
            .send_modify(|version| *version += 1);
        self.inner
            .peer_runtime_changes
            .send_modify(|version| *version += 1);
        config
    }

    pub fn subscribe_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.config_changes.subscribe()
    }

    pub fn subscribe_peer_runtime_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.peer_runtime_changes.subscribe()
    }

    pub(crate) fn notify_peer_runtime_changes(&self) {
        self.inner
            .peer_runtime_changes
            .send_modify(|version| *version += 1);
    }

    #[cfg(test)]
    pub(crate) fn peer_change_subscriber_count(&self) -> usize {
        self.inner.peer_runtime_changes.receiver_count()
    }

    #[cfg(test)]
    pub(crate) fn change_subscriber_count(&self) -> usize {
        self.inner.config_changes.receiver_count()
    }
}

impl From<InstanceConfig> for InstanceConfigStore {
    fn from(config: InstanceConfig) -> Self {
        Self::new(config)
    }
}

impl From<crate::config::InstanceConfigParsed> for InstanceConfigStore {
    fn from(parsed: crate::config::InstanceConfigParsed) -> Self {
        Self::new(parsed.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::toml::TomlConfig;

    #[test]
    fn replaces_config_as_one_version() {
        let before_toml = TomlConfig::new_from_str("hostname = \"before\"").unwrap();
        let store = InstanceConfigStore::new(before_toml.snapshot().unwrap());
        let before = store.snapshot();
        assert_eq!(before.hostname, "before");

        let after_toml = TomlConfig::new_from_str("hostname = \"after\"\ndhcp = true").unwrap();
        store.replace(after_toml.snapshot().unwrap());

        assert_eq!(before.hostname, "before");
        let after = store.snapshot();
        assert_eq!(after.hostname, "after");
        assert!(after.dhcp);
    }

    #[tokio::test]
    async fn notifies_config_changes() {
        let toml = TomlConfig::new_from_str("hostname = \"initial\"").unwrap();
        let store = InstanceConfigStore::new(toml.snapshot().unwrap());
        let mut changes = store.subscribe_changes();

        let updated_toml = TomlConfig::new_from_str("hostname = \"updated\"").unwrap();
        store.replace(updated_toml.snapshot().unwrap());

        assert!(changes.changed().await.is_ok());
        assert_eq!(store.snapshot().hostname, "updated");
    }

    #[tokio::test]
    async fn notifies_peer_runtime_changes() {
        let toml = TomlConfig::new_from_str("hostname = \"initial\"").unwrap();
        let store = InstanceConfigStore::new(toml.snapshot().unwrap());
        let mut changes = store.subscribe_peer_runtime_changes();

        store.notify_peer_runtime_changes();

        assert!(changes.changed().await.is_ok());
    }
}
