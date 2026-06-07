use super::{field_store, import_export, legacy_migration, validation};
use crate::config::storage::config_meta::{
    get_config_meta, init_config_meta_store, list_config_meta_entries, open_db,
    reset_config_meta_store, upsert_config_meta_in_tx,
};
use crate::config::types::stored_config::{ExportTomlResult, StoredConfigRecord};
use easytier::proto::api::manage::NetworkConfig;
use once_cell::sync::Lazy;
use rusqlite::params;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

static CONFIG_ROOT_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static RUNTIME_CONFIG_SNAPSHOTS: Lazy<Mutex<HashMap<String, RuntimeConfigSnapshot>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
pub(crate) const CONFIG_DIR_NAME: &str = "easytier-configs";
pub(crate) const KERNEL_SOCKET_FILE_NAME: &str = "easytier-kernel.sock";

#[derive(Clone)]
pub(crate) struct RuntimeConfigSnapshot {
    pub display_name: String,
    pub config: NetworkConfig,
}

pub(crate) fn cache_runtime_config_snapshot(
    config_id: String,
    display_name: String,
    config: NetworkConfig,
) {
    if let Ok(mut guard) = RUNTIME_CONFIG_SNAPSHOTS.lock() {
        guard.insert(
            config_id,
            RuntimeConfigSnapshot {
                display_name,
                config,
            },
        );
    }
}

pub(crate) fn clear_runtime_config_snapshot(config_id: &str) {
    if let Ok(mut guard) = RUNTIME_CONFIG_SNAPSHOTS.lock() {
        guard.remove(config_id);
    }
}

pub(crate) fn get_runtime_config_snapshot(config_id: &str) -> Option<RuntimeConfigSnapshot> {
    RUNTIME_CONFIG_SNAPSHOTS
        .lock()
        .ok()
        .and_then(|guard| guard.get(config_id).cloned())
}

pub(crate) fn get_runtime_config_route_overrides(config_id: &str) -> (Vec<String>, Vec<String>) {
    RUNTIME_CONFIG_SNAPSHOTS
        .lock()
        .ok()
        .and_then(|guard| {
            guard.get(config_id).map(|snapshot| {
                (
                    snapshot.config.routes.clone(),
                    snapshot.config.proxy_cidrs.clone(),
                )
            })
        })
        .unwrap_or_default()
}

pub(crate) fn config_root_dir() -> Option<PathBuf> {
    CONFIG_ROOT_DIR
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}

pub(crate) fn kernel_socket_path() -> Option<PathBuf> {
    config_root_dir().map(|root| root.join(KERNEL_SOCKET_FILE_NAME))
}

pub(crate) fn legacy_config_file_path(config_id: &str) -> Option<PathBuf> {
    legacy_migration::legacy_config_file_path(&config_root_dir(), CONFIG_DIR_NAME, config_id)
}

pub fn init_config_store(root_dir: String) -> bool {
    let root = PathBuf::from(root_dir);
    let configs_dir = root.join(CONFIG_DIR_NAME);
    if let Err(e) = std::fs::create_dir_all(&configs_dir) {
        ohrs_log_error!(
            "[Rust] failed to create config dir {}: {}",
            configs_dir.display(),
            e
        );
        return false;
    }

    match CONFIG_ROOT_DIR.lock() {
        Ok(mut guard) => {
            *guard = Some(root.clone());
        }
        Err(e) => {
            ohrs_log_error!("[Rust] failed to lock config root dir: {}", e);
            return false;
        }
    }

    if !init_config_meta_store(root.to_string_lossy().into_owned()) {
        return false;
    }

    ohrs_log_debug!(
        "[Rust] initialized config repo at {}",
        configs_dir.display()
    );
    true
}

pub fn reset_config_store() -> bool {
    if !reset_config_meta_store() {
        return false;
    }
    if let Ok(mut guard) = RUNTIME_CONFIG_SNAPSHOTS.lock() {
        guard.clear();
    }
    true
}

fn migrate_legacy_file_if_needed(config_id: &str) -> Option<()> {
    if validation::validate_config_id(config_id).is_err() {
        return None;
    }
    legacy_migration::migrate_legacy_file_if_needed(
        &config_root_dir(),
        CONFIG_DIR_NAME,
        config_id,
        save_config_record,
    )
}

pub fn save_config_record(
    config_id: String,
    display_name: String,
    config_json: String,
) -> Option<StoredConfigRecord> {
    let config = match validation::validate_config_json(&config_json, config_id.clone()) {
        Ok(config) => config,
        Err(e) => {
            ohrs_log_error!("[Rust] save_config_record failed {}", e);
            return None;
        }
    };

    let normalized_json = match serde_json::to_string(&config) {
        Ok(raw) => raw,
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to serialize normalized config {}: {}",
                config_id,
                e
            );
            return None;
        }
    };

    let fields = match validation::config_to_top_level_map(&config) {
        Some(fields) => fields,
        None => return None,
    };

    let conn = open_db()?;
    let tx = conn.unchecked_transaction().ok()?;
    let existing_meta = tx
        .query_row(
            "SELECT favorite, temporary FROM stored_configs WHERE config_id = ?1",
            params![config_id.clone()],
            |row| Ok((row.get::<_, i64>(0)? != 0, row.get::<_, i64>(1)? != 0)),
        )
        .ok();
    let favorite = existing_meta.map(|meta| meta.0).unwrap_or(false);
    let temporary = existing_meta.map(|meta| meta.1).unwrap_or(false);
    let meta = upsert_config_meta_in_tx(&tx, config_id.clone(), display_name, favorite, temporary)?;

    field_store::replace_config_fields(&tx, &config_id, fields)?;

    tx.commit().ok()?;

    if let Some(legacy_path) = legacy_config_file_path(&config_id) {
        if legacy_path.exists() {
            let _ = std::fs::remove_file(legacy_path);
        }
    }

    Some(StoredConfigRecord {
        meta,
        config_json: normalized_json,
    })
}

pub fn load_config_json(config_id: &str) -> Option<String> {
    validation::validate_config_id(config_id).ok()?;
    migrate_legacy_file_if_needed(config_id)?;
    let object = field_store::load_config_map_from_db(config_id)?;
    serde_json::to_string(&Value::Object(object)).ok()
}

pub fn get_config_record(config_id: &str) -> Option<StoredConfigRecord> {
    validation::validate_config_id(config_id).ok()?;
    let config_json = load_config_json(config_id)?;
    let meta = get_config_meta(config_id)?;
    Some(StoredConfigRecord { meta, config_json })
}

pub fn get_config_field_value(config_id: &str, field: &str) -> Option<String> {
    let total_start = Instant::now();
    validation::validate_config_id(config_id).ok()?;
    migrate_legacy_file_if_needed(config_id)?;
    let open_start = Instant::now();
    let conn = open_db()?;
    let open_elapsed = open_start.elapsed();
    let query_start = Instant::now();
    let result = conn
        .query_row(
            "SELECT field_json FROM stored_config_fields
         WHERE config_id = ?1 AND field_name = ?2",
            params![config_id, field],
            |row| row.get::<_, String>(0),
        )
        .ok();
    ohrs_log_debug!(
        "[Rust] get_config_field_value config={} field={} found={} open_ms={} query_ms={} total_ms={} len={}",
        config_id,
        field,
        result.is_some(),
        open_elapsed.as_millis(),
        query_start.elapsed().as_millis(),
        total_start.elapsed().as_millis(),
        result.as_ref().map(|value| value.len()).unwrap_or(0)
    );
    result
}

pub fn set_config_field_value(config_id: &str, field: &str, json_value: &str) -> bool {
    if validation::validate_config_id(config_id).is_err() {
        return false;
    }
    if field.contains('.') {
        return false;
    }

    let raw = match load_config_json(config_id) {
        Some(raw) => raw,
        None => return false,
    };
    let mut value = match serde_json::from_str::<Value>(&raw) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let new_field_value = match serde_json::from_str::<Value>(json_value) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let object = match value.as_object_mut() {
        Some(object) => object,
        None => return false,
    };
    object.insert(field.to_string(), new_field_value);

    let normalized = match serde_json::to_string(&value) {
        Ok(raw) => raw,
        Err(_) => return false,
    };

    let display_name = get_config_meta(config_id)
        .map(|meta| meta.display_name)
        .unwrap_or_else(|| config_id.to_string());

    save_config_record(config_id.to_string(), display_name, normalized).is_some()
}

pub fn get_default_config_json() -> Option<String> {
    crate::build_default_network_config_json().ok()
}

pub fn create_config_record(config_id: String, display_name: String) -> Option<StoredConfigRecord> {
    validation::validate_config_id(&config_id).ok()?;
    let raw = get_default_config_json()?;
    let mut config = serde_json::from_str::<NetworkConfig>(&raw).ok()?;
    config.instance_id = Some(config_id.clone());
    let normalized_json = serde_json::to_string(&config).ok()?;
    save_config_record(config_id, display_name, normalized_json)
}

pub fn start_kernel_with_config_id(config_id: &str) -> bool {
    if validation::validate_config_id(config_id).is_err() {
        return false;
    }
    let raw = match load_config_json(config_id) {
        Some(raw) => raw,
        None => return false,
    };
    let display_name = get_config_meta(config_id)
        .map(|meta| meta.display_name)
        .unwrap_or_else(|| config_id.to_string());
    let started = crate::run_network_instance_from_json(&raw);
    if started && let Ok(config) = serde_json::from_str::<NetworkConfig>(&raw) {
        cache_runtime_config_snapshot(config_id.to_string(), display_name, config);
    }
    started
}

pub fn list_config_meta_json() -> String {
    serde_json::to_string(&list_config_meta_entries().configs).unwrap_or_else(|_| "[]".to_string())
}

pub fn delete_config_record(config_id: &str) -> bool {
    if validation::validate_config_id(config_id).is_err() {
        return false;
    }
    if let Some(path) = legacy_config_file_path(config_id) {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    let conn = match open_db() {
        Some(conn) => conn,
        None => return false,
    };
    if let Err(e) = conn.execute(
        "DELETE FROM stored_config_fields WHERE config_id = ?1",
        params![config_id],
    ) {
        ohrs_log_error!("[Rust] failed to delete config fields {}: {}", config_id, e);
        return false;
    }

    match conn.execute(
        "DELETE FROM stored_configs WHERE config_id = ?1",
        params![config_id],
    ) {
        Ok(rows) => rows > 0,
        Err(e) => {
            ohrs_log_error!("[Rust] failed to delete config meta {}: {}", config_id, e);
            false
        }
    }
}

pub fn export_config_toml(config_id: &str) -> Option<ExportTomlResult> {
    validation::validate_config_id(config_id).ok()?;
    let record = get_config_record(config_id)?;
    import_export::export_config_toml_from_record(&record)
}

pub fn import_toml_config(
    toml_text: String,
    display_name: Option<String>,
) -> Option<StoredConfigRecord> {
    import_export::import_toml_to_record(toml_text, display_name, save_config_record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root() -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("easytier_ohrs_test_{}", unique));
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn save_get_export_delete_roundtrip() {
        let root = test_root();
        assert!(init_config_store(root.clone()));

        let config_json = crate::build_default_network_config_json().expect("default config");
        let saved = save_config_record("cfg-1".to_string(), "test-config".to_string(), config_json)
            .expect("save config");

        assert_eq!(saved.meta.config_id, "cfg-1");
        assert_eq!(saved.meta.display_name, "test-config");

        let loaded = get_config_record("cfg-1").expect("load config");
        assert_eq!(loaded.meta.display_name, "test-config");
        assert!(loaded.config_json.contains("cfg-1"));

        let legacy_json_path = PathBuf::from(&root)
            .join(CONFIG_DIR_NAME)
            .join("cfg-1.json");
        assert!(
            !legacy_json_path.exists(),
            "config should no longer be persisted as a per-config json file"
        );

        let conn = open_db().expect("db should be open");
        let field_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM stored_config_fields WHERE config_id = ?1",
                params!["cfg-1"],
                |row| row.get(0),
            )
            .expect("count config fields");
        assert!(field_count > 0, "config fields should be stored in sqlite");

        let exported = export_config_toml("cfg-1").expect("export toml");
        assert!(exported.toml_text.contains("instance_id"));

        assert!(delete_config_record("cfg-1"));
        assert!(get_config_record("cfg-1").is_none());
    }

    #[test]
    fn set_config_field_updates_only_requested_top_level_field() {
        let root = test_root();
        assert!(init_config_store(root));

        let config_json = crate::build_default_network_config_json().expect("default config");
        save_config_record(
            "cfg-field".to_string(),
            "field-config".to_string(),
            config_json,
        )
        .expect("save config");

        let before_network_name = get_config_field_value("cfg-field", "network_name");
        let before_instance_id = get_config_field_value("cfg-field", "instance_id")
            .expect("instance id field should exist");

        assert!(set_config_field_value(
            "cfg-field",
            "network_name",
            "\"changed-network\""
        ));

        assert_eq!(
            get_config_field_value("cfg-field", "network_name"),
            Some("\"changed-network\"".to_string())
        );
        assert_eq!(
            get_config_field_value("cfg-field", "instance_id"),
            Some(before_instance_id)
        );
        assert_ne!(
            get_config_field_value("cfg-field", "network_name"),
            before_network_name
        );
    }
}
