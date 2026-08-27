use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Weak},
};

use dashmap::{DashMap, mapref::entry::Entry};
use easytier::{
    common::config::ConfigSource,
    proto::{
        api::manage::{ConfigSource as RpcConfigSource, NetworkConfig, NetworkMeta},
        common::Uuid as RpcUuid,
    },
};
use easytier_core::management::config_source_from_rpc;
use easytier_core::management::remote_client::{PersistentConfig as _, Storage as _};

use super::storage::Storage;
use crate::db::{
    ManagedConfigApplyResult, ManagedConfigExpectedRevision, ManagedConfigUpdate,
    ManagedConfigUpsert,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistedConfigSource {
    User,
    Web,
}

pub(super) enum ExpectedConfigRevision<'a> {
    Any,
    Exact(Option<&'a str>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManagedConfigError {
    #[error("invalid managed config update: {0}")]
    Invalid(String),
    #[error(
        "managed config revision changed while reconciling: expected {expected:?}, current {current:?}"
    )]
    RevisionConflict {
        expected: Option<String>,
        current: Option<String>,
    },
    #[error("managed config instance {instance_id} is user-owned")]
    OwnershipConflict { instance_id: uuid::Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ManagedConfigApplyStatus {
    Applied,
    AlreadyApplied,
}

impl PersistedConfigSource {
    pub(super) fn from_db(source: &str) -> Self {
        match source {
            "web" => Self::Web,
            "user" => Self::User,
            _ => Self::User,
        }
    }

    fn should_update_from_runtime(self, runtime_source: ConfigSource) -> bool {
        match (self, runtime_source) {
            // Older clients report missing source as `user`, which is not authoritative enough
            // to downgrade an existing web-owned row.
            (Self::Web, ConfigSource::User) => false,
            _ => self.as_runtime_source() != runtime_source,
        }
    }

    fn as_runtime_source(self) -> ConfigSource {
        match self {
            Self::User => ConfigSource::User,
            Self::Web => ConfigSource::Web,
        }
    }

    pub(super) fn auto_run_rpc_source(self) -> RpcConfigSource {
        match self {
            Self::User => RpcConfigSource::User,
            Self::Web => RpcConfigSource::Web,
        }
    }
}

type ManagedConfigReconcileKey = (i32, uuid::Uuid);
type ManagedConfigReconcileLock = tokio::sync::Mutex<()>;
type ManagedConfigReconcileLockRef = Arc<ManagedConfigReconcileLock>;
type ManagedConfigReconcileLockWeak = Weak<ManagedConfigReconcileLock>;

static MANAGED_CONFIG_RECONCILE_LOCKS: std::sync::LazyLock<
    DashMap<ManagedConfigReconcileKey, ManagedConfigReconcileLockWeak>,
> = std::sync::LazyLock::new(DashMap::new);

fn managed_config_reconcile_lock(key: ManagedConfigReconcileKey) -> ManagedConfigReconcileLockRef {
    match MANAGED_CONFIG_RECONCILE_LOCKS.entry(key) {
        Entry::Occupied(mut entry) => match entry.get().upgrade() {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                entry.insert(Arc::downgrade(&lock));
                lock
            }
        },
        Entry::Vacant(entry) => {
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            entry.insert(Arc::downgrade(&lock));
            lock
        }
    }
}

fn remove_unused_managed_config_reconcile_lock(
    key: ManagedConfigReconcileKey,
    lock: &ManagedConfigReconcileLockRef,
) {
    let expected_lock = Arc::downgrade(lock);
    MANAGED_CONFIG_RECONCILE_LOCKS.remove_if(&key, |_, current_lock| {
        current_lock.ptr_eq(&expected_lock) && current_lock.strong_count() == 1
    });
}

#[cfg(test)]
fn is_revision_conflict(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<ManagedConfigError>(),
        Some(ManagedConfigError::RevisionConflict { .. })
    )
}

fn snake_to_lower_camel(key: &str) -> Option<String> {
    if !key.contains('_') {
        return None;
    }

    let mut result = String::with_capacity(key.len());
    let mut uppercase_next = false;
    for ch in key.chars() {
        if ch == '_' {
            uppercase_next = true;
            continue;
        }
        if uppercase_next {
            result.push(ch.to_ascii_uppercase());
            uppercase_next = false;
        } else {
            result.push(ch);
        }
    }

    (!result.is_empty()).then_some(result)
}

fn normalize_lower_camel_keys(value: &mut serde_json::Value) -> anyhow::Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            let old_map = std::mem::take(map);
            for (key, mut value) in old_map {
                normalize_lower_camel_keys(&mut value)?;
                let normalized_key = snake_to_lower_camel(&key).unwrap_or(key);
                if map.insert(normalized_key.clone(), value).is_some() {
                    anyhow::bail!(
                        "duplicate network_config field after key normalization: {normalized_key}"
                    );
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                normalize_lower_camel_keys(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_network_config(
    mut network_config: serde_json::Value,
    inst_id: uuid::Uuid,
) -> anyhow::Result<NetworkConfig> {
    let config_obj = network_config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("webhook network_config must be a JSON object"))?;
    config_obj.remove("instance_id");
    config_obj.remove("instanceId");
    normalize_lower_camel_keys(&mut network_config)?;
    let config_obj = network_config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("webhook network_config must be a JSON object"))?;
    config_obj.insert(
        "instanceId".to_string(),
        serde_json::Value::String(inst_id.to_string()),
    );
    network_config
        .get("networkName")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("webhook response missing network_name"))?;

    Ok(serde_json::from_value::<NetworkConfig>(network_config)?)
}

struct NormalizedWebConfigs {
    desired_ids: HashSet<uuid::Uuid>,
    configs: Vec<ManagedConfigUpsert>,
}

fn normalize_desired_web_configs(
    desired_configs: Vec<crate::webhook::ManagedNetworkConfig>,
) -> anyhow::Result<NormalizedWebConfigs> {
    let mut desired_ids = HashSet::with_capacity(desired_configs.len());
    let mut configs = Vec::with_capacity(desired_configs.len());

    for desired in desired_configs {
        let inst_id = uuid::Uuid::parse_str(&desired.instance_id).map_err(|_| {
            ManagedConfigError::Invalid(format!(
                "invalid desired web config instance id: {}",
                desired.instance_id
            ))
        })?;
        if !desired_ids.insert(inst_id) {
            return Err(ManagedConfigError::Invalid(format!(
                "duplicate managed config instance id: {inst_id}"
            ))
            .into());
        }
        let config = normalize_network_config(desired.network_config, inst_id)
            .map_err(|error| ManagedConfigError::Invalid(error.to_string()))?;
        configs.push(ManagedConfigUpsert {
            instance_id: inst_id,
            network_config: config,
        });
    }

    Ok(NormalizedWebConfigs {
        desired_ids,
        configs,
    })
}

fn map_apply_result(result: ManagedConfigApplyResult) -> anyhow::Result<ManagedConfigApplyStatus> {
    match result {
        ManagedConfigApplyResult::Applied => Ok(ManagedConfigApplyStatus::Applied),
        ManagedConfigApplyResult::AlreadyApplied => Ok(ManagedConfigApplyStatus::AlreadyApplied),
        ManagedConfigApplyResult::RevisionConflict { expected, current } => {
            Err(ManagedConfigError::RevisionConflict { expected, current }.into())
        }
        ManagedConfigApplyResult::OwnershipConflict { instance_id } => {
            Err(ManagedConfigError::OwnershipConflict { instance_id }.into())
        }
    }
}

pub(super) async fn reconcile_web_source_configs(
    storage: &Storage,
    user_id: i32,
    machine_id: uuid::Uuid,
    desired_configs: Vec<crate::webhook::ManagedNetworkConfig>,
    config_revision: Option<&str>,
    expected_config_revision: ExpectedConfigRevision<'_>,
) -> anyhow::Result<ManagedConfigApplyStatus> {
    if config_revision.is_some_and(|revision| revision.trim().is_empty()) {
        return Err(
            ManagedConfigError::Invalid("config_revision must not be empty".to_string()).into(),
        );
    }
    let normalized = normalize_desired_web_configs(desired_configs)?;
    let expected_revision = match expected_config_revision {
        ExpectedConfigRevision::Any => ManagedConfigExpectedRevision::Any,
        ExpectedConfigRevision::Exact(revision) => {
            ManagedConfigExpectedRevision::Exact(revision.map(str::to_string))
        }
    };
    let key = (user_id, machine_id);
    let reconcile_lock = managed_config_reconcile_lock(key);
    let result = async {
        let _guard = reconcile_lock.lock().await;

        let result = storage
            .db()
            .apply_managed_config_update(
                (user_id, machine_id),
                ManagedConfigUpdate::Full {
                    upserts: normalized.configs,
                    target_revision: config_revision.map(str::to_string),
                    expected_revision,
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!("failed to apply managed config Full: {error}"))?;
        map_apply_result(result)
    }
    .await;
    remove_unused_managed_config_reconcile_lock(key, &reconcile_lock);
    result
}

pub(super) async fn patch_web_source_configs(
    storage: &Storage,
    user_id: i32,
    machine_id: uuid::Uuid,
    upserts: Vec<crate::webhook::ManagedNetworkConfig>,
    delete_instance_ids: Vec<uuid::Uuid>,
    config_revision: &str,
    expected_config_revision: &str,
) -> anyhow::Result<ManagedConfigApplyStatus> {
    let config_revision = config_revision.trim();
    let expected_config_revision = expected_config_revision.trim();
    if config_revision.is_empty() || expected_config_revision.is_empty() {
        return Err(
            ManagedConfigError::Invalid("Patch revisions must not be empty".to_string()).into(),
        );
    }
    if config_revision == expected_config_revision {
        return Err(ManagedConfigError::Invalid(
            "Patch target revision must differ from expected revision".to_string(),
        )
        .into());
    }

    let normalized = normalize_desired_web_configs(upserts)?;
    let mut delete_ids = HashSet::with_capacity(delete_instance_ids.len());
    for instance_id in delete_instance_ids {
        if !delete_ids.insert(instance_id) {
            return Err(ManagedConfigError::Invalid(format!(
                "duplicate managed config delete instance id: {instance_id}"
            ))
            .into());
        }
    }
    if let Some(instance_id) = delete_ids
        .intersection(&normalized.desired_ids)
        .next()
        .copied()
    {
        return Err(ManagedConfigError::Invalid(format!(
            "managed config instance {instance_id} cannot be upserted and deleted"
        ))
        .into());
    }
    if normalized.configs.is_empty() && delete_ids.is_empty() {
        return Err(ManagedConfigError::Invalid(
            "Patch must contain an upsert or delete".to_string(),
        )
        .into());
    }

    let key = (user_id, machine_id);
    let reconcile_lock = managed_config_reconcile_lock(key);
    let result = async {
        let _guard = reconcile_lock.lock().await;
        let result = storage
            .db()
            .apply_managed_config_update(
                (user_id, machine_id),
                ManagedConfigUpdate::Patch {
                    upserts: normalized.configs,
                    delete_instance_ids: delete_ids.into_iter().collect(),
                    target_revision: config_revision.to_string(),
                    expected_revision: expected_config_revision.to_string(),
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!("failed to apply managed config Patch: {error}"))?;
        map_apply_result(result)
    }
    .await;
    remove_unused_managed_config_reconcile_lock(key, &reconcile_lock);
    result
}

fn collect_web_source_instance_ids(metas: &[NetworkMeta]) -> HashSet<String> {
    metas
        .iter()
        .filter_map(|meta| {
            (RpcConfigSource::try_from(meta.source).ok() == Some(RpcConfigSource::Web))
                .then(|| {
                    meta.inst_id
                        .as_ref()
                        .map(|inst_id| Into::<uuid::Uuid>::into(*inst_id).to_string())
                })
                .flatten()
        })
        .collect()
}

pub(super) fn desired_web_source_instance_ids(
    local_configs: &[crate::db::entity::user_running_network_configs::Model],
) -> HashSet<String> {
    local_configs
        .iter()
        .filter(|cfg| cfg.get_runtime_network_config_source() == ConfigSource::Web)
        .map(|cfg| cfg.network_instance_id.clone())
        .collect()
}

pub(super) fn running_web_source_instance_ids(
    running_inst_ids: &HashSet<String>,
    db_web_inst_ids: &HashSet<String>,
    running_metas: Option<&[NetworkMeta]>,
) -> HashSet<String> {
    match running_metas {
        Some(metas) => collect_web_source_instance_ids(metas),
        None => running_inst_ids
            .intersection(db_web_inst_ids)
            .cloned()
            .collect(),
    }
}

pub(super) fn parse_instance_ids(instance_ids: impl Iterator<Item = String>) -> Vec<RpcUuid> {
    instance_ids
        .filter_map(|inst_id| uuid::Uuid::parse_str(&inst_id).ok())
        .map(Into::into)
        .collect()
}

pub(super) async fn sync_running_config_sources(
    db: &crate::db::Db,
    user_id: i32,
    machine_id: uuid::Uuid,
    local_configs: &[crate::db::entity::user_running_network_configs::Model],
    metas: &[NetworkMeta],
) -> anyhow::Result<()> {
    let local_configs_by_id = local_configs
        .iter()
        .map(|cfg| (cfg.network_instance_id.clone(), cfg))
        .collect::<HashMap<_, _>>();

    for meta in metas {
        let Some(inst_id) = meta.inst_id.as_ref().map(|inst_id| {
            let inst_id: uuid::Uuid = (*inst_id).into();
            inst_id
        }) else {
            continue;
        };
        let inst_id_str = inst_id.to_string();
        let Some(local_cfg) = local_configs_by_id.get(&inst_id_str) else {
            continue;
        };

        let Some(running_source) = config_source_from_rpc(meta.source) else {
            continue;
        };
        let local_source = PersistedConfigSource::from_db(&local_cfg.source);
        if !local_source.should_update_from_runtime(running_source) {
            continue;
        }

        db.insert_or_update_user_network_config(
            (user_id, machine_id),
            inst_id,
            local_cfg.get_network_config().map_err(|e| {
                anyhow::anyhow!("failed to decode local network config {}: {:?}", inst_id, e)
            })?,
            running_source,
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to sync running network config source {}: {:?}",
                inst_id,
                e
            )
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use easytier::{
        common::config::{ConfigLoader as _, ConfigSource, NetworkConfigExt},
        proto::api::manage::{ConfigSource as RpcConfigSource, NetworkConfig, NetworkMeta},
    };
    use easytier_core::management::remote_client::{
        ListNetworkProps, PersistentConfig as _, Storage as _,
    };
    use serde_json::json;

    use super::*;

    fn managed_config(
        instance_id: uuid::Uuid,
        network_name: &str,
    ) -> crate::webhook::ManagedNetworkConfig {
        crate::webhook::ManagedNetworkConfig {
            instance_id: instance_id.to_string(),
            network_config: json!({
                "instance_id": instance_id.to_string(),
                "network_name": network_name
            }),
        }
    }

    #[tokio::test]
    async fn reconcile_web_source_configs_upserts_and_deletes_exact_set() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("web-user").await.unwrap().id;
        let machine_id = uuid::Uuid::new_v4();
        let keep_id = uuid::Uuid::new_v4();
        let stale_id = uuid::Uuid::new_v4();
        let new_id = uuid::Uuid::new_v4();

        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                keep_id,
                NetworkConfig {
                    network_name: Some("old-name".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();
        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                stale_id,
                NetworkConfig {
                    network_name: Some("stale".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();

        reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![
                crate::webhook::ManagedNetworkConfig {
                    instance_id: keep_id.to_string(),
                    network_config: json!({
                        "instance_id": keep_id.to_string(),
                        "network_name": "updated-name"
                    }),
                },
                crate::webhook::ManagedNetworkConfig {
                    instance_id: new_id.to_string(),
                    network_config: json!({
                        "instance_id": new_id.to_string(),
                        "network_name": "new-name"
                    }),
                },
            ],
            None,
            ExpectedConfigRevision::Any,
        )
        .await
        .unwrap();

        let configs = storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::All)
            .await
            .unwrap();
        let config_ids = configs
            .iter()
            .map(|cfg| cfg.network_instance_id.clone())
            .collect::<HashSet<_>>();

        assert_eq!(configs.len(), 2);
        assert!(config_ids.contains(&keep_id.to_string()));
        assert!(config_ids.contains(&new_id.to_string()));
        assert!(!config_ids.contains(&stale_id.to_string()));

        let updated_keep = storage
            .db()
            .get_network_config((user_id, machine_id), &keep_id.to_string())
            .await
            .unwrap()
            .unwrap();
        let updated_keep_config: NetworkConfig =
            serde_json::from_str(&updated_keep.network_config).unwrap();
        assert_eq!(
            updated_keep_config.network_name.as_deref(),
            Some("updated-name")
        );
        assert_eq!(updated_keep.get_network_config_source(), ConfigSource::Web);
    }

    #[tokio::test]
    async fn reconcile_web_source_configs_keep_user_owned_configs() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-keep-user")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let user_owned_id = uuid::Uuid::new_v4();
        let web_owned_id = uuid::Uuid::new_v4();

        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                user_owned_id,
                NetworkConfig {
                    network_name: Some("user-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::User,
            )
            .await
            .unwrap();
        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                web_owned_id,
                NetworkConfig {
                    network_name: Some("web-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();

        reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![crate::webhook::ManagedNetworkConfig {
                instance_id: user_owned_id.to_string(),
                network_config: json!({
                    "instance_id": user_owned_id.to_string(),
                    "network_name": "web-tries-to-take-over"
                }),
            }],
            None,
            ExpectedConfigRevision::Any,
        )
        .await
        .unwrap();

        let user_owned = storage
            .db()
            .get_network_config((user_id, machine_id), &user_owned_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_owned.get_network_config_source(), ConfigSource::User);
        let user_owned_cfg: NetworkConfig =
            serde_json::from_str(&user_owned.network_config).unwrap();
        assert_eq!(user_owned_cfg.network_name.as_deref(), Some("user-owned"));

        let web_owned = storage
            .db()
            .get_network_config((user_id, machine_id), &web_owned_id.to_string())
            .await
            .unwrap();
        assert!(web_owned.is_none());
    }

    #[tokio::test]
    async fn reconcile_web_source_configs_rejects_revision_for_user_owned_config() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-reject-user-owned")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let user_owned_id = uuid::Uuid::new_v4();

        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                user_owned_id,
                NetworkConfig {
                    network_name: Some("user-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::User,
            )
            .await
            .unwrap();

        let err = reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![crate::webhook::ManagedNetworkConfig {
                instance_id: user_owned_id.to_string(),
                network_config: json!({
                    "instance_id": user_owned_id.to_string(),
                    "network_name": "web-tries-to-take-over"
                }),
            }],
            Some("rev-user-owned"),
            ExpectedConfigRevision::Any,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("user-owned"),
            "unexpected error: {err:?}"
        );
        assert_eq!(
            storage
                .db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn reconcile_web_source_configs_persists_config_revision() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-revision")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();

        reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            Vec::new(),
            Some("rev-1"),
            ExpectedConfigRevision::Any,
        )
        .await
        .unwrap();

        assert_eq!(
            storage
                .db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .as_deref(),
            Some("rev-1")
        );
    }

    #[tokio::test]
    async fn reconcile_web_source_configs_rejects_changed_expected_revision() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-expected-revision")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();
        storage
            .db()
            .set_managed_config_revision((user_id, machine_id), "rev-new")
            .await
            .unwrap();

        let err = reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![crate::webhook::ManagedNetworkConfig {
                instance_id: inst_id.to_string(),
                network_config: json!({
                    "instance_id": inst_id.to_string(),
                    "network_name": "stale-config"
                }),
            }],
            Some("rev-old"),
            ExpectedConfigRevision::Exact(Some("rev-old")),
        )
        .await
        .unwrap_err();

        assert!(is_revision_conflict(&err));
        let conflict = err
            .downcast_ref::<ManagedConfigError>()
            .expect("expected typed revision conflict");
        let ManagedConfigError::RevisionConflict { expected, current } = conflict else {
            panic!("unexpected managed config error: {conflict:?}");
        };
        assert_eq!(expected.as_deref(), Some("rev-old"));
        assert_eq!(current.as_deref(), Some("rev-new"));
        assert_eq!(
            storage
                .db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .as_deref(),
            Some("rev-new")
        );
        assert!(
            storage
                .db()
                .get_network_config((user_id, machine_id), &inst_id.to_string())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn patch_web_source_configs_applies_delta_and_is_idempotent() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-patch")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let update_id = uuid::Uuid::new_v4();
        let delete_id = uuid::Uuid::new_v4();
        let add_id = uuid::Uuid::new_v4();

        reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![
                managed_config(update_id, "before"),
                managed_config(delete_id, "delete"),
            ],
            Some("rev-1"),
            ExpectedConfigRevision::Any,
        )
        .await
        .unwrap();

        let status = patch_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![
                managed_config(update_id, "after"),
                managed_config(add_id, "added"),
            ],
            vec![delete_id],
            "rev-2",
            "rev-1",
        )
        .await
        .unwrap();
        assert_eq!(status, ManagedConfigApplyStatus::Applied);

        let retry_status = patch_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![managed_config(update_id, "ignored-on-idempotent-retry")],
            vec![delete_id],
            "rev-2",
            "rev-1",
        )
        .await
        .unwrap();
        assert_eq!(retry_status, ManagedConfigApplyStatus::AlreadyApplied);

        let updated = storage
            .db()
            .get_network_config((user_id, machine_id), &update_id.to_string())
            .await
            .unwrap()
            .unwrap()
            .get_network_config()
            .unwrap();
        assert_eq!(updated.network_name.as_deref(), Some("after"));
        assert!(
            storage
                .db()
                .get_network_config((user_id, machine_id), &delete_id.to_string())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .db()
                .get_network_config((user_id, machine_id), &add_id.to_string())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            storage
                .db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .as_deref(),
            Some("rev-2")
        );
    }

    #[tokio::test]
    async fn patch_web_source_configs_rejects_conflict_and_user_owned_delete() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-patch-conflict")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let user_owned_id = uuid::Uuid::new_v4();
        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                user_owned_id,
                NetworkConfig {
                    network_name: Some("user-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::User,
            )
            .await
            .unwrap();
        storage
            .db()
            .set_managed_config_revision((user_id, machine_id), "rev-current")
            .await
            .unwrap();

        let revision_error = patch_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![managed_config(uuid::Uuid::new_v4(), "new")],
            Vec::new(),
            "rev-next",
            "rev-stale",
        )
        .await
        .unwrap_err();
        assert!(is_revision_conflict(&revision_error));

        let ownership_error = patch_web_source_configs(
            &storage,
            user_id,
            machine_id,
            Vec::new(),
            vec![user_owned_id],
            "rev-next",
            "rev-current",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            ownership_error.downcast_ref::<ManagedConfigError>(),
            Some(ManagedConfigError::OwnershipConflict { instance_id })
                if *instance_id == user_owned_id
        ));
        assert!(
            storage
                .db()
                .get_network_config((user_id, machine_id), &user_owned_id.to_string())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            storage
                .db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .as_deref(),
            Some("rev-current")
        );
    }

    #[tokio::test]
    async fn reconcile_web_source_configs_rolls_back_rows_when_revision_write_fails() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-rollback")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let instance_id = uuid::Uuid::new_v4();
        sqlx::query(
            r#"
            CREATE TRIGGER reject_managed_revision
            BEFORE INSERT ON managed_config_revisions
            WHEN NEW.config_revision = 'reject-revision'
            BEGIN
                SELECT RAISE(ABORT, 'forced revision failure');
            END
            "#,
        )
        .execute(&storage.db().inner())
        .await
        .unwrap();

        reconcile_web_source_configs(
            &storage,
            user_id,
            machine_id,
            vec![managed_config(instance_id, "must-rollback")],
            Some("reject-revision"),
            ExpectedConfigRevision::Any,
        )
        .await
        .unwrap_err();

        assert!(
            storage
                .db()
                .get_network_config((user_id, machine_id), &instance_id.to_string())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .db()
                .get_managed_config_revision((user_id, machine_id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn managed_config_reconcile_lock_reuses_live_entry_and_replaces_stale_entry() {
        let key = (i32::MIN, uuid::Uuid::new_v4());
        MANAGED_CONFIG_RECONCILE_LOCKS.remove(&key);

        let first = managed_config_reconcile_lock(key);
        let second = managed_config_reconcile_lock(key);
        assert!(Arc::ptr_eq(&first, &second));

        let stale = Arc::downgrade(&first);
        drop(first);
        drop(second);
        assert!(stale.upgrade().is_none());

        let third = managed_config_reconcile_lock(key);
        let stored = MANAGED_CONFIG_RECONCILE_LOCKS
            .get(&key)
            .and_then(|lock| lock.upgrade())
            .expect("expected refreshed reconcile lock");
        assert!(Arc::ptr_eq(&third, &stored));
        drop(stored);

        remove_unused_managed_config_reconcile_lock(key, &third);
        assert!(!MANAGED_CONFIG_RECONCILE_LOCKS.contains_key(&key));
    }

    #[test]
    fn managed_config_reconcile_lock_cleanup_keeps_live_waiters() {
        let key = (i32::MIN + 1, uuid::Uuid::new_v4());
        MANAGED_CONFIG_RECONCILE_LOCKS.remove(&key);

        let current = managed_config_reconcile_lock(key);
        let waiter = managed_config_reconcile_lock(key);

        remove_unused_managed_config_reconcile_lock(key, &current);
        assert!(MANAGED_CONFIG_RECONCILE_LOCKS.contains_key(&key));

        drop(waiter);
        remove_unused_managed_config_reconcile_lock(key, &current);
        assert!(!MANAGED_CONFIG_RECONCILE_LOCKS.contains_key(&key));
    }

    #[test]
    fn normalize_network_config_accepts_console_snake_case_fields() {
        let inst_id = uuid::Uuid::new_v4();

        let config = normalize_network_config(
            json!({
                "instance_id": uuid::Uuid::new_v4().to_string(),
                "instanceId": uuid::Uuid::new_v4().to_string(),
                "dhcp": true,
                "network_name": "managed",
                "network_secret": "secret",
                "networking_method": "Manual",
                "peer_urls": ["http://console.example/peer"],
                "listener_urls": ["udp://0.0.0.0:0"],
                "no_tun": true,
                "relay_all_peer_rpc": true,
                "disable_udp_hole_punching": true,
                "enable_private_mode": true,
                "port_forwards": [{
                    "bind_ip": "127.0.0.1",
                    "bind_port": 23000,
                    "dst_ip": "10.144.0.1",
                    "dst_port": 5174,
                    "proto": "tcp"
                }],
                "disable_sym_hole_punching": true,
                "disable_tcp_hole_punching": true,
                "secure_mode": {
                    "enabled": true
                },
                "credential_file": "/tmp/e2e.credentials.json",
                "need_p2p": true,
                "disable_relay_data": false
            }),
            inst_id,
        )
        .unwrap();

        assert_eq!(
            config.instance_id.as_deref(),
            Some(inst_id.to_string().as_str())
        );
        assert_eq!(config.no_tun, Some(true));
        assert_eq!(config.relay_all_peer_rpc, Some(true));
        assert_eq!(config.disable_udp_hole_punching, Some(true));
        assert_eq!(config.enable_private_mode, Some(true));
        assert_eq!(config.disable_sym_hole_punching, Some(true));
        assert_eq!(config.disable_tcp_hole_punching, Some(true));
        assert_eq!(config.need_p2p, Some(true));
        assert_eq!(config.disable_relay_data, Some(false));
        assert_eq!(config.port_forwards.len(), 1);

        let runtime_config = config.gen_config().unwrap();
        let flags = runtime_config.get_flags();
        assert!(flags.no_tun);
        assert!(flags.private_mode);
        assert!(flags.need_p2p);
        assert!(flags.relay_all_peer_rpc);
        assert!(flags.disable_tcp_hole_punching);
        assert!(flags.disable_udp_hole_punching);
        assert!(flags.disable_sym_hole_punching);
        assert_eq!(runtime_config.get_port_forwards().len(), 1);
    }

    #[test]
    fn normalize_network_config_rejects_conflicting_key_spellings() {
        let err = normalize_network_config(
            json!({
                "network_name": "snake",
                "networkName": "camel"
            }),
            uuid::Uuid::new_v4(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("duplicate network_config field after key normalization"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn sync_running_config_sources_updates_enabled_config_source_from_runtime() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage
            .db()
            .auto_create_user("web-user-sync-source")
            .await
            .unwrap()
            .id;
        let machine_id = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();

        storage
            .db()
            .insert_or_update_user_network_config(
                (user_id, machine_id),
                inst_id,
                NetworkConfig {
                    network_name: Some("web-owned".to_string()),
                    ..Default::default()
                },
                ConfigSource::Web,
            )
            .await
            .unwrap();

        let local_configs = storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::EnabledOnly)
            .await
            .unwrap();
        sync_running_config_sources(
            storage.db(),
            user_id,
            machine_id,
            &local_configs,
            &[NetworkMeta {
                inst_id: Some(inst_id.into()),
                source: RpcConfigSource::User as i32,
                ..Default::default()
            }],
        )
        .await
        .unwrap();

        let updated = storage
            .db()
            .get_network_config((user_id, machine_id), &inst_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.get_network_config_source(), ConfigSource::Web);
    }

    #[test]
    fn persisted_sources_map_to_rpc_sources() {
        assert_eq!(
            PersistedConfigSource::Web.auto_run_rpc_source(),
            RpcConfigSource::Web
        );
        assert_eq!(
            PersistedConfigSource::User.auto_run_rpc_source(),
            RpcConfigSource::User
        );
    }
}
