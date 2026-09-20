//! Versioned application intent. This is not a claim about a running VPN/TUN.
use std::collections::HashSet;
use std::sync::Mutex;

use super::application_client::{ConfigRepository, StoredConfig};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ApplicationSnapshot {
    pub schema_version: u32,
    pub configs: Vec<StoredConfig>,
    pub desired_enabled: Vec<String>,
    /// Preserve the complete backend profile, including config-server credentials.
    /// Unknown and non-local modes must not be silently interpreted as local mode.
    pub profile: serde_json::Value,
    pub selected_network: Option<String>,
}

impl ApplicationSnapshot {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == 1,
            "Unsupported application storage version"
        );
        anyhow::ensure!(
            self.profile.get("mode").and_then(|v| v.as_str()).is_some(),
            "Missing backend mode"
        );
        let mut ids = HashSet::new();
        for config in &self.configs {
            let id = uuid::Uuid::parse_str(config.config.instance_id())?;
            anyhow::ensure!(
                ids.insert(id),
                "Duplicate network ID in application storage"
            );
        }
        for id in &self.desired_enabled {
            anyhow::ensure!(
                ids.contains(&uuid::Uuid::parse_str(id)?),
                "Enabled network is missing from application storage"
            );
        }
        Ok(())
    }
}

/// Backends must atomically commit and protect the complete payload (it contains secrets).
/// Missing data is `None`; unreadable data must be an error, not `None`.
pub trait SnapshotBackend: Send + Sync {
    fn read(&self) -> anyhow::Result<Option<String>>;
    fn write(&self, payload: &str) -> anyhow::Result<()>;
}

pub struct SnapshotRepository<B: SnapshotBackend> {
    backend: B,
    snapshot: Mutex<ApplicationSnapshot>,
}

impl<B: SnapshotBackend> SnapshotRepository<B> {
    /// One-way, retryable migration: after the first successful commit legacy UI data
    /// is never read again. Corruption and unknown versions stop initialization.
    pub fn open(backend: B, legacy: ApplicationSnapshot) -> anyhow::Result<Self> {
        let snapshot = if let Some(raw) = backend.read()? {
            let existing: ApplicationSnapshot = serde_json::from_str(&raw)
                .map_err(|_| anyhow::anyhow!("Invalid application storage"))?;
            existing.validate()?;
            existing
        } else {
            legacy.validate()?;
            backend.write(&serde_json::to_string(&legacy)?)?;
            legacy
        };
        Ok(Self {
            backend,
            snapshot: Mutex::new(snapshot),
        })
    }

    pub fn snapshot(&self) -> ApplicationSnapshot {
        self.snapshot.lock().unwrap().clone()
    }

    fn update(&self, change: impl FnOnce(&mut ApplicationSnapshot)) -> anyhow::Result<()> {
        let mut current = self.snapshot.lock().unwrap();
        let mut next = current.clone();
        change(&mut next);
        next.validate()?;
        self.backend.write(&serde_json::to_string(&next)?)?;
        *current = next;
        Ok(())
    }

    pub fn save_preferences(
        &self,
        profile: serde_json::Value,
        selected: Option<String>,
    ) -> anyhow::Result<()> {
        self.update(|next| {
            next.profile = profile;
            next.selected_network = selected;
        })
    }
}

impl<B: SnapshotBackend> ConfigRepository for SnapshotRepository<B> {
    fn load_or_import(&self, _legacy: &[StoredConfig]) -> anyhow::Result<Vec<StoredConfig>> {
        Ok(self.snapshot().configs)
    }

    fn save_configs(&self, configs: &[StoredConfig]) -> anyhow::Result<()> {
        self.update(|next| {
            next.configs = configs.to_vec();
            let ids: HashSet<_> = configs.iter().map(|c| c.config.instance_id()).collect();
            next.desired_enabled.retain(|id| ids.contains(id.as_str()));
            if next
                .selected_network
                .as_ref()
                .is_some_and(|id| !ids.contains(id.as_str()))
            {
                next.selected_network = None;
            }
        })
    }

    fn save_enabled(&self, ids: &[String]) -> anyhow::Result<()> {
        self.update(|next| next.desired_enabled = ids.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::super::application_client::PersistedConfigSource;
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Clone, Default)]
    struct MemoryBackend {
        data: Arc<Mutex<Option<String>>>,
        fail: Arc<AtomicBool>,
    }
    impl SnapshotBackend for MemoryBackend {
        fn read(&self) -> anyhow::Result<Option<String>> {
            Ok(self.data.lock().unwrap().clone())
        }
        fn write(&self, payload: &str) -> anyhow::Result<()> {
            anyhow::ensure!(!self.fail.load(Ordering::SeqCst), "simulated write failure");
            *self.data.lock().unwrap() = Some(payload.to_owned());
            Ok(())
        }
    }
    fn snapshot() -> ApplicationSnapshot {
        ApplicationSnapshot {
            schema_version: 1,
            configs: vec![StoredConfig {
                config: easytier_proto::api::manage::NetworkConfig {
                    instance_id: Some(uuid::Uuid::new_v4().to_string()),
                    ..Default::default()
                },
                source: PersistedConfigSource::Legacy,
            }],
            desired_enabled: vec![],
            profile: serde_json::json!({"mode":"normal"}),
            selected_network: None,
        }
    }
    #[test]
    fn migration_is_once_and_ignores_stale_webview_data() {
        let backend = MemoryBackend::default();
        let original = snapshot();
        let repo = SnapshotRepository::open(backend.clone(), original.clone()).unwrap();
        let mut stale = snapshot();
        stale.schema_version = 999;
        let reopened = SnapshotRepository::open(backend, stale).unwrap();
        assert_eq!(
            repo.snapshot().configs[0].config.instance_id(),
            reopened.snapshot().configs[0].config.instance_id()
        );
        assert_eq!(
            repo.snapshot().configs[0].source,
            PersistedConfigSource::Legacy
        );
    }
    #[test]
    fn failed_migration_is_retryable() {
        let backend = MemoryBackend::default();
        backend.fail.store(true, Ordering::SeqCst);
        assert!(SnapshotRepository::open(backend.clone(), snapshot()).is_err());
        assert!(backend.read().unwrap().is_none());
        backend.fail.store(false, Ordering::SeqCst);
        assert!(SnapshotRepository::open(backend, snapshot()).is_ok());
    }
    #[test]
    fn corrupt_or_future_data_is_never_replaced_by_legacy() {
        for raw in ["not json".to_owned(), {
            let mut future = snapshot();
            future.schema_version = 2;
            serde_json::to_string(&future).unwrap()
        }] {
            let backend = MemoryBackend::default();
            *backend.data.lock().unwrap() = Some(raw.clone());
            assert!(SnapshotRepository::open(backend.clone(), snapshot()).is_err());
            assert_eq!(backend.read().unwrap(), Some(raw));
        }
    }
    #[test]
    fn write_failure_does_not_publish_uncommitted_preferences() {
        let backend = MemoryBackend::default();
        let repo = SnapshotRepository::open(backend.clone(), snapshot()).unwrap();
        backend.fail.store(true, Ordering::SeqCst);
        assert!(
            repo.save_preferences(serde_json::json!({"mode":"remote"}), None)
                .is_err()
        );
        assert_eq!(repo.snapshot().profile["mode"], "normal");
    }
    #[test]
    fn complete_backend_profile_is_preserved_not_converted_to_local() {
        for mode in ["remote", "service", "future"] {
            let backend = MemoryBackend::default();
            let mut legacy = snapshot();
            legacy.profile =
                serde_json::json!({"mode":mode,"config_server_url":"wss://example.invalid/token"});
            let repo = SnapshotRepository::open(backend.clone(), legacy.clone()).unwrap();
            assert_eq!(repo.snapshot().profile, legacy.profile);
            assert_eq!(
                SnapshotRepository::open(backend, snapshot())
                    .unwrap()
                    .snapshot()
                    .profile,
                legacy.profile
            );
        }
    }
    #[test]
    fn deletion_prunes_desired_and_selected_state_in_same_commit() {
        let repo = SnapshotRepository::open(MemoryBackend::default(), snapshot()).unwrap();
        let id = repo.snapshot().configs[0].config.instance_id().to_owned();
        repo.save_enabled(&[id.clone()]).unwrap();
        repo.save_preferences(serde_json::json!({"mode":"normal"}), Some(id))
            .unwrap();
        repo.save_configs(&[]).unwrap();
        assert!(repo.snapshot().configs.is_empty());
        assert!(repo.snapshot().desired_enabled.is_empty());
        assert!(repo.snapshot().selected_network.is_none());
    }
    #[test]
    fn invalid_ids_and_duplicate_configs_are_rejected() {
        let mut invalid = snapshot();
        invalid.configs.push(invalid.configs[0].clone());
        assert!(invalid.validate().is_err());
        let mut invalid = snapshot();
        invalid
            .desired_enabled
            .push(uuid::Uuid::new_v4().to_string());
        assert!(invalid.validate().is_err());
    }
}
