use crate::config_meta::{
    delete_config_meta, get_config_meta, init_config_meta_store, list_config_meta_entries,
    now_ts_string, open_db, upsert_config_meta_in_tx,
};
use crate::stored_config::{ExportTomlResult, StoredConfigRecord};
use easytier::common::config::ConfigLoader;
use easytier::proto::api::manage::NetworkConfig;
use ohos_hilog_binding::{hilog_debug, hilog_error};
use rusqlite::params;
use serde_json::{Map, Value};
use std::path::PathBuf;
use std::sync::Mutex;

static CONFIG_ROOT_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
pub(crate) const CONFIG_DIR_NAME: &str = "easytier-configs";
pub(crate) const KERNEL_SOCKET_FILE_NAME: &str = "easytier-kernel.sock";

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
    config_root_dir().map(|root| root.join(CONFIG_DIR_NAME).join(format!("{}.json", config_id)))
}

pub fn init_config_store(root_dir: String) -> bool {
    let root = PathBuf::from(root_dir);
    let configs_dir = root.join(CONFIG_DIR_NAME);
    if let Err(e) = std::fs::create_dir_all(&configs_dir) {
        hilog_error!("[Rust] failed to create config dir {}: {}", configs_dir.display(), e);
        return false;
    }

    match CONFIG_ROOT_DIR.lock() {
        Ok(mut guard) => {
            *guard = Some(root.clone());
        }
        Err(e) => {
            hilog_error!("[Rust] failed to lock config root dir: {}", e);
            return false;
        }
    }

    if !init_config_meta_store(root.to_string_lossy().into_owned()) {
        return false;
    }

    hilog_debug!("[Rust] initialized config repo at {}", configs_dir.display());
    true
}

fn normalize_config_id(mut config: NetworkConfig, requested_id: String) -> Result<NetworkConfig, String> {
    if requested_id.is_empty() {
        return Err("config_id is required".to_string());
    }
    config.instance_id = Some(requested_id);
    Ok(config)
}

fn validate_config_json(config_json: &str, config_id: String) -> Result<NetworkConfig, String> {
    let config = serde_json::from_str::<NetworkConfig>(config_json)
        .map_err(|e| format!("parse config json failed: {}", e))?;
    let config = normalize_config_id(config, config_id)?;
    config
        .gen_config()
        .map_err(|e| format!("generate toml failed: {}", e))?;
    Ok(config)
}

fn config_to_top_level_map(config: &NetworkConfig) -> Option<Map<String, Value>> {
    serde_json::to_value(config).ok()?.as_object().cloned()
}

fn load_config_map_from_db(config_id: &str) -> Option<Map<String, Value>> {
    let conn = open_db()?;
    let mut stmt = conn
        .prepare(
            "SELECT field_name, field_json
             FROM stored_config_fields
             WHERE config_id = ?1",
        )
        .ok()?;
    let rows = stmt
        .query_map(params![config_id], |row| {
            let field_name: String = row.get(0)?;
            let field_json: String = row.get(1)?;
            Ok((field_name, field_json))
        })
        .ok()?;

    let mut object = Map::new();
    for row in rows {
        let (field_name, field_json) = row.ok()?;
        let value = serde_json::from_str::<Value>(&field_json).ok()?;
        object.insert(field_name, value);
    }

    if object.is_empty() { None } else { Some(object) }
}

fn migrate_legacy_file_if_needed(config_id: &str) -> Option<()> {
    let legacy_path = legacy_config_file_path(config_id)?;
    if !legacy_path.exists() {
        return Some(());
    }

    let raw = std::fs::read_to_string(&legacy_path).ok()?;
    let display_name = get_config_meta(config_id)
        .map(|meta| meta.display_name)
        .unwrap_or_else(|| config_id.to_string());
    save_config_record(config_id.to_string(), display_name, raw)?;

    if let Err(e) = std::fs::remove_file(&legacy_path) {
        hilog_error!("[Rust] failed to remove legacy config file {}: {}", legacy_path.display(), e);
    }
    Some(())
}

pub fn save_config_record(
    config_id: String,
    display_name: String,
    config_json: String,
) -> Option<StoredConfigRecord> {
    let config = match validate_config_json(&config_json, config_id.clone()) {
        Ok(config) => config,
        Err(e) => {
            hilog_error!("[Rust] save_config_record failed {}", e);
            return None;
        }
    };

    let normalized_json = match serde_json::to_string(&config) {
        Ok(raw) => raw,
        Err(e) => {
            hilog_error!("[Rust] failed to serialize normalized config {}: {}", config_id, e);
            return None;
        }
    };

    let fields = match config_to_top_level_map(&config) {
        Some(fields) => fields,
        None => return None,
    };

    let conn = open_db()?;
    let tx = conn.unchecked_transaction().ok()?;
    let existing_meta = get_config_meta(&config_id);
    let favorite = existing_meta.as_ref().map(|meta| meta.favorite).unwrap_or(false);
    let temporary = existing_meta
        .as_ref()
        .map(|meta| meta.temporary)
        .unwrap_or(false);
    let meta = upsert_config_meta_in_tx(&tx, config_id.clone(), display_name, favorite, temporary)?;

    if let Err(e) = tx.execute(
        "DELETE FROM stored_config_fields WHERE config_id = ?1",
        params![config_id],
    ) {
        hilog_error!("[Rust] failed to clear existing config fields {}: {}", config_id, e);
        return None;
    }

    for (field_name, value) in fields {
        let field_json = serde_json::to_string(&value).ok()?;
        if let Err(e) = tx.execute(
            "INSERT INTO stored_config_fields (config_id, field_name, field_json, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![config_id, field_name, field_json, now_ts_string()],
        ) {
            hilog_error!("[Rust] failed to persist config field {}: {}", config_id, e);
            return None;
        }
    }

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
    migrate_legacy_file_if_needed(config_id)?;
    let object = load_config_map_from_db(config_id)?;
    serde_json::to_string(&Value::Object(object)).ok()
}

pub fn get_config_record(config_id: &str) -> Option<StoredConfigRecord> {
    let config_json = load_config_json(config_id)?;
    let meta = get_config_meta(config_id)?;
    Some(StoredConfigRecord { meta, config_json })
}

pub fn get_config_field_value(config_id: &str, field: &str) -> Option<String> {
    migrate_legacy_file_if_needed(config_id)?;
    let conn = open_db()?;
    conn.query_row(
        "SELECT field_json FROM stored_config_fields
         WHERE config_id = ?1 AND field_name = ?2",
        params![config_id, field],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

pub fn set_config_field_value(config_id: &str, field: &str, json_value: &str) -> bool {
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

pub fn get_display_name(config_id: &str) -> Option<String> {
    get_config_meta(config_id).map(|meta| meta.display_name)
}

pub fn get_default_config_json() -> Option<String> {
    crate::build_default_network_config_json().ok()
}

pub fn create_config_record(config_id: String, display_name: String) -> Option<StoredConfigRecord> {
    let raw = get_default_config_json()?;
    let mut config = serde_json::from_str::<NetworkConfig>(&raw).ok()?;
    config.instance_id = Some(config_id.clone());
    let normalized_json = serde_json::to_string(&config).ok()?;
    save_config_record(config_id, display_name, normalized_json)
}

pub fn start_kernel_with_config_id(config_id: &str) -> bool {
    let raw = match load_config_json(config_id) {
        Some(raw) => raw,
        None => return false,
    };
    crate::run_network_instance_from_json(&raw)
}

pub fn list_config_meta_json() -> String {
    serde_json::to_string(&list_config_meta_entries().configs).unwrap_or_else(|_| "[]".to_string())
}

pub fn delete_config_record(config_id: &str) -> bool {
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
        hilog_error!("[Rust] failed to delete config fields {}: {}", config_id, e);
        return false;
    }

    delete_config_meta(config_id)
}

pub fn export_config_toml(config_id: &str) -> Option<ExportTomlResult> {
    let record = get_config_record(config_id)?;
    let config = serde_json::from_str::<NetworkConfig>(&record.config_json).ok()?;
    let toml = config.gen_config().ok()?;
    Some(ExportTomlResult {
        toml_text: toml.dump(),
    })
}

pub fn import_toml_config(toml_text: String, display_name: Option<String>) -> Option<StoredConfigRecord> {
    let config = NetworkConfig::new_from_config(
        easytier::common::config::TomlConfigLoader::new_from_str(&toml_text).ok()?,
    )
    .ok()?;

    let config_id = config.instance_id.clone()?;
    let name_from_toml = toml_text
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("instance_name") {
                return None;
            }
            trimmed
                .split_once('=')
                .map(|(_, value)| value.trim().trim_matches('"').trim_matches('\'').to_string())
        })
        .filter(|name| !name.is_empty());

    let final_name = display_name
        .filter(|name| !name.is_empty())
        .or(name_from_toml)
        .unwrap_or_else(|| config_id.clone());

    let config_json = serde_json::to_string(&config).ok()?;
    save_config_record(config_id, final_name, config_json)
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
        let saved = save_config_record(
            "cfg-1".to_string(),
            "test-config".to_string(),
            config_json,
        )
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
