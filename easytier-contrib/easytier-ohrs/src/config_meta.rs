use crate::stored_config::{StoredConfigList, StoredConfigMeta};
use ohos_hilog_binding::{hilog_debug, hilog_error};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static CONFIG_DB_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
const CONFIG_DB_FILE_NAME: &str = "easytier-config-store.db";

#[derive(Debug, Clone)]
struct StoredConfigMetaRecord {
    config_id: String,
    display_name: String,
    created_at: String,
    updated_at: String,
    favorite: bool,
    temporary: bool,
}

pub(crate) fn now_ts_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn db_file_path() -> Option<PathBuf> {
    CONFIG_DB_PATH
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS stored_configs (
             config_id TEXT PRIMARY KEY,
             display_name TEXT NOT NULL,
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             favorite INTEGER NOT NULL DEFAULT 0,
             temporary INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS stored_config_fields (
             config_id TEXT NOT NULL,
             field_name TEXT NOT NULL,
             field_json TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             PRIMARY KEY (config_id, field_name),
             FOREIGN KEY (config_id) REFERENCES stored_configs(config_id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_stored_config_fields_config_id
             ON stored_config_fields(config_id);",
    )
}

pub(crate) fn open_db() -> Option<Connection> {
    let path = db_file_path()?;
    let conn = match Connection::open(&path) {
        Ok(conn) => conn,
        Err(e) => {
            hilog_error!("[Rust] failed to open config db {}: {}", path.display(), e);
            return None;
        }
    };

    if let Err(e) = init_schema(&conn) {
        hilog_error!("[Rust] failed to initialize config db {}: {}", path.display(), e);
        return None;
    }

    Some(conn)
}

fn row_to_meta(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredConfigMetaRecord> {
    Ok(StoredConfigMetaRecord {
        config_id: row.get(0)?,
        display_name: row.get(1)?,
        created_at: row.get(2)?,
        updated_at: row.get(3)?,
        favorite: row.get::<_, i64>(4)? != 0,
        temporary: row.get::<_, i64>(5)? != 0,
    })
}

fn load_meta_record(conn: &Connection, config_id: &str) -> Option<StoredConfigMetaRecord> {
    conn.query_row(
        "SELECT config_id, display_name, created_at, updated_at, favorite, temporary
         FROM stored_configs WHERE config_id = ?1",
        params![config_id],
        row_to_meta,
    )
    .optional()
    .ok()
    .flatten()
}

fn to_meta(record: StoredConfigMetaRecord) -> StoredConfigMeta {
    StoredConfigMeta {
        config_id: record.config_id,
        display_name: record.display_name,
        created_at: record.created_at,
        updated_at: record.updated_at,
        favorite: record.favorite,
        temporary: record.temporary,
    }
}

pub fn init_config_meta_store(root_dir: String) -> bool {
    let root = PathBuf::from(root_dir);
    if let Err(e) = std::fs::create_dir_all(&root) {
        hilog_error!("[Rust] failed to create config db dir {}: {}", root.display(), e);
        return false;
    }

    let db_path = root.join(CONFIG_DB_FILE_NAME);
    match CONFIG_DB_PATH.lock() {
        Ok(mut guard) => {
            *guard = Some(db_path.clone());
        }
        Err(e) => {
            hilog_error!("[Rust] failed to lock config db path: {}", e);
            return false;
        }
    }

    if open_db().is_none() {
        return false;
    }

    hilog_debug!("[Rust] initialized config db at {}", db_path.display());
    true
}

pub fn list_config_meta_entries() -> StoredConfigList {
    let Some(conn) = open_db() else {
        return StoredConfigList { configs: vec![] };
    };

    let mut stmt = match conn.prepare(
        "SELECT config_id, display_name, created_at, updated_at, favorite, temporary
         FROM stored_configs
         ORDER BY updated_at DESC, display_name ASC",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            hilog_error!("[Rust] failed to prepare list meta query: {}", e);
            return StoredConfigList { configs: vec![] };
        }
    };

    let rows = match stmt.query_map([], row_to_meta) {
        Ok(rows) => rows,
        Err(e) => {
            hilog_error!("[Rust] failed to list config meta rows: {}", e);
            return StoredConfigList { configs: vec![] };
        }
    };

    let configs = rows.filter_map(Result::ok).map(to_meta).collect();
    StoredConfigList { configs }
}

pub fn get_config_display_name(config_id: &str) -> Option<String> {
    let conn = open_db()?;
    load_meta_record(&conn, config_id).map(|record| record.display_name)
}

pub fn get_config_meta(config_id: &str) -> Option<StoredConfigMeta> {
    let conn = open_db()?;
    load_meta_record(&conn, config_id).map(to_meta)
}

pub fn upsert_config_meta(
    config_id: String,
    display_name: String,
    favorite: bool,
    temporary: bool,
) -> StoredConfigMeta {
    let now = now_ts_string();
    let Some(conn) = open_db() else {
        return StoredConfigMeta {
            config_id,
            display_name,
            created_at: now.clone(),
            updated_at: now,
            favorite,
            temporary,
        };
    };

    let created_at = load_meta_record(&conn, &config_id)
        .map(|record| record.created_at)
        .unwrap_or_else(|| now.clone());

    if let Err(e) = conn.execute(
        "INSERT INTO stored_configs (
             config_id, display_name, created_at, updated_at, favorite, temporary
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(config_id) DO UPDATE SET
             display_name = excluded.display_name,
             updated_at = excluded.updated_at,
             favorite = excluded.favorite,
             temporary = excluded.temporary",
        params![
            config_id,
            display_name,
            created_at,
            now,
            if favorite { 1 } else { 0 },
            if temporary { 1 } else { 0 }
        ],
    ) {
        hilog_error!("[Rust] failed to upsert config meta: {}", e);
    }

    get_config_meta(&config_id).unwrap_or(StoredConfigMeta {
        config_id,
        display_name,
        created_at,
        updated_at: now,
        favorite,
        temporary,
    })
}

pub fn set_config_display_name(config_id: String, display_name: String) -> Option<StoredConfigMeta> {
    let conn = open_db()?;
    let mut record = load_meta_record(&conn, &config_id)?;
    record.display_name = display_name;
    record.updated_at = now_ts_string();

    conn.execute(
        "UPDATE stored_configs
         SET display_name = ?2, updated_at = ?3
         WHERE config_id = ?1",
        params![config_id, record.display_name, record.updated_at],
    )
    .ok()?;

    Some(to_meta(record))
}

pub fn delete_config_meta(config_id: &str) -> bool {
    let Some(conn) = open_db() else {
        return false;
    };

    match conn.execute(
        "DELETE FROM stored_configs WHERE config_id = ?1",
        params![config_id],
    ) {
        Ok(rows) => rows > 0,
        Err(e) => {
            hilog_error!("[Rust] failed to delete config meta {}: {}", config_id, e);
            false
        }
    }
}
