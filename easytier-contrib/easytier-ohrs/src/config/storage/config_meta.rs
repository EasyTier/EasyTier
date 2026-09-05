use crate::config::types::stored_config::{
    SnapshotImportResult, StoredConfigList, StoredConfigMeta,
};
use once_cell::sync::Lazy;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

static CONFIG_DB_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static CONFIG_DB_CONNECTION: Lazy<Mutex<Option<CachedConfigDb>>> = Lazy::new(|| Mutex::new(None));
const CONFIG_DB_FILE_NAME: &str = "easytier-config-store.db";

struct CachedConfigDb {
    path: PathBuf,
    conn: Connection,
}

pub(crate) struct ConfigDbGuard<'a> {
    guard: MutexGuard<'a, Option<CachedConfigDb>>,
}

impl Deref for ConfigDbGuard<'_> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self
            .guard
            .as_ref()
            .expect("config db connection guard must contain a connection")
            .conn
    }
}

impl DerefMut for ConfigDbGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .guard
            .as_mut()
            .expect("config db connection guard must contain a connection")
            .conn
    }
}

#[derive(Debug, Clone)]
struct StoredConfigMetaRecord {
    config_id: String,
    display_name: String,
    created_at: String,
    updated_at: String,
    favorite: bool,
    temporary: bool,
}

type SnapshotFieldRow = (String, String, String, String);

fn snapshot_import_ok() -> SnapshotImportResult {
    SnapshotImportResult {
        ok: true,
        error_code: String::new(),
        error_message: String::new(),
        snapshot_invalid: false,
    }
}

fn snapshot_import_err(
    error_code: &str,
    error_message: impl Into<String>,
    snapshot_invalid: bool,
) -> SnapshotImportResult {
    SnapshotImportResult {
        ok: false,
        error_code: error_code.to_string(),
        error_message: error_message.into(),
        snapshot_invalid,
    }
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
    )?;

    ensure_column(
        conn,
        "stored_configs",
        "favorite",
        "ALTER TABLE stored_configs ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0;",
    )?;
    ensure_column(
        conn,
        "stored_configs",
        "temporary",
        "ALTER TABLE stored_configs ADD COLUMN temporary INTEGER NOT NULL DEFAULT 0;",
    )?;
    ensure_column(
        conn,
        "stored_config_fields",
        "updated_at",
        "ALTER TABLE stored_config_fields ADD COLUMN updated_at TEXT NOT NULL DEFAULT '0';",
    )?;

    if !validate_store_schema(conn)? {
        return Err(rusqlite::Error::InvalidQuery);
    }

    conn.execute_batch("PRAGMA user_version = 1;")
}

fn table_columns(conn: &Connection, table_name: &str) -> rusqlite::Result<HashSet<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table_name))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut columns = HashSet::new();
    for row in rows {
        columns.insert(row?);
    }
    Ok(columns)
}

fn ensure_column(
    conn: &Connection,
    table_name: &str,
    column_name: &str,
    alter_sql: &str,
) -> rusqlite::Result<()> {
    let columns = table_columns(conn, table_name)?;
    if !columns.contains(column_name) {
        conn.execute_batch(alter_sql)?;
    }
    Ok(())
}

fn validate_store_schema(conn: &Connection) -> rusqlite::Result<bool> {
    let meta_columns = table_columns(conn, "stored_configs")?;
    let field_columns = table_columns(conn, "stored_config_fields")?;
    let required_meta = [
        "config_id",
        "display_name",
        "created_at",
        "updated_at",
        "favorite",
        "temporary",
    ];
    let required_fields = ["config_id", "field_name", "field_json", "updated_at"];

    Ok(required_meta
        .iter()
        .all(|column| meta_columns.contains(*column))
        && required_fields
            .iter()
            .all(|column| field_columns.contains(*column)))
}

fn move_db_file_if_exists(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }
    let target = PathBuf::from(format!(
        "{}.corrupt.{}",
        path.to_string_lossy(),
        now_ts_string()
    ));
    match std::fs::rename(path, &target) {
        Ok(_) => true,
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to move corrupt config db {} to {}: {}",
                path.display(),
                target.display(),
                e
            );
            false
        }
    }
}

fn recover_config_db_files(path: &Path) -> bool {
    let main_ok = move_db_file_if_exists(path);
    let wal_ok = move_db_file_if_exists(Path::new(&format!("{}-wal", path.to_string_lossy())));
    let shm_ok = move_db_file_if_exists(Path::new(&format!("{}-shm", path.to_string_lossy())));
    main_ok && wal_ok && shm_ok
}

fn open_connection(path: &Path) -> Option<Connection> {
    let conn = match Connection::open(path) {
        Ok(conn) => conn,
        Err(e) => {
            ohrs_log_error!("[Rust] failed to open config db {}: {}", path.display(), e);
            return None;
        }
    };

    if let Err(e) = init_schema(&conn) {
        ohrs_log_error!(
            "[Rust] failed to initialize config db {}: {}",
            path.display(),
            e
        );
        drop(conn);
        if !recover_config_db_files(path) {
            return None;
        }

        let recovered = match Connection::open(path) {
            Ok(conn) => conn,
            Err(e) => {
                ohrs_log_error!(
                    "[Rust] failed to open recovered config db {}: {}",
                    path.display(),
                    e
                );
                return None;
            }
        };
        if let Err(e) = init_schema(&recovered) {
            ohrs_log_error!(
                "[Rust] failed to initialize recovered config db {}: {}",
                path.display(),
                e
            );
            return None;
        }
        return Some(recovered);
    }

    Some(conn)
}

pub(crate) fn open_db() -> Option<ConfigDbGuard<'static>> {
    let path = db_file_path()?;
    let mut guard = match CONFIG_DB_CONNECTION.lock() {
        Ok(guard) => guard,
        Err(e) => {
            ohrs_log_error!("[Rust] failed to lock config db connection: {}", e);
            return None;
        }
    };

    let should_open = guard
        .as_ref()
        .map(|cached| cached.path != path || !cached.path.exists())
        .unwrap_or(true);
    if should_open {
        let conn = open_connection(&path)?;

        *guard = Some(CachedConfigDb { path, conn });
    }

    Some(ConfigDbGuard { guard })
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

fn validate_snapshot_schema(conn: &Connection) -> bool {
    let has_stored_configs = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'stored_configs'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten()
        .is_some();
    let has_stored_fields = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'stored_config_fields'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten()
        .is_some();
    has_stored_configs && has_stored_fields
}

fn read_snapshot_tables(
    src: &Connection,
) -> rusqlite::Result<(Vec<StoredConfigMetaRecord>, Vec<SnapshotFieldRow>)> {
    src.execute_batch("BEGIN DEFERRED TRANSACTION")?;

    let mut meta_rows = Vec::<StoredConfigMetaRecord>::new();
    let mut field_rows = Vec::<SnapshotFieldRow>::new();

    let read_result = (|| -> rusqlite::Result<()> {
        {
            let mut stmt = src.prepare(
                "SELECT config_id, display_name, created_at, updated_at, favorite, temporary
                 FROM stored_configs",
            )?;
            let rows = stmt.query_map([], row_to_meta)?;
            for row in rows {
                meta_rows.push(row?);
            }
        }

        {
            let mut stmt = src.prepare(
                "SELECT config_id, field_name, field_json, updated_at
                 FROM stored_config_fields",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                field_rows.push(row?);
            }
        }

        Ok(())
    })();

    match read_result {
        Ok(()) => {
            src.execute_batch("COMMIT")?;
            Ok((meta_rows, field_rows))
        }
        Err(err) => {
            let _ = src.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

fn write_snapshot_tables(
    dst: &mut Connection,
    meta_rows: Vec<StoredConfigMetaRecord>,
    field_rows: Vec<SnapshotFieldRow>,
) -> rusqlite::Result<()> {
    let tx = dst.unchecked_transaction()?;
    tx.execute("DELETE FROM stored_config_fields", [])?;
    tx.execute("DELETE FROM stored_configs", [])?;

    for row in meta_rows {
        tx.execute(
            "INSERT INTO stored_configs (
                 config_id, display_name, created_at, updated_at, favorite, temporary
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.config_id,
                row.display_name,
                row.created_at,
                row.updated_at,
                if row.favorite { 1 } else { 0 },
                if row.temporary { 1 } else { 0 }
            ],
        )?;
    }

    for (config_id, field_name, field_json, updated_at) in field_rows {
        tx.execute(
            "INSERT INTO stored_config_fields (config_id, field_name, field_json, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![config_id, field_name, field_json, updated_at],
        )?;
    }

    tx.commit()
}

fn copy_snapshot_tables(src: &Connection, dst: &mut Connection) -> rusqlite::Result<()> {
    let (meta_rows, field_rows) = read_snapshot_tables(src)?;
    write_snapshot_tables(dst, meta_rows, field_rows)
}

fn ensure_parent_dir(path: &Path) -> bool {
    match path.parent() {
        Some(parent) => match std::fs::create_dir_all(parent) {
            Ok(_) => true,
            Err(e) => {
                ohrs_log_error!(
                    "[Rust] failed to create snapshot parent {}: {}",
                    parent.display(),
                    e
                );
                false
            }
        },
        None => true,
    }
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
        ohrs_log_error!(
            "[Rust] failed to create config db dir {}: {}",
            root.display(),
            e
        );
        return false;
    }

    let db_path = root.join(CONFIG_DB_FILE_NAME);
    match CONFIG_DB_PATH.lock() {
        Ok(mut guard) => {
            *guard = Some(db_path.clone());
        }
        Err(e) => {
            ohrs_log_error!("[Rust] failed to lock config db path: {}", e);
            return false;
        }
    }

    if open_db().is_none() {
        return false;
    }

    ohrs_log_debug!("[Rust] initialized config db at {}", db_path.display());
    true
}

pub fn export_config_store_snapshot(target_path: String) -> bool {
    let target = PathBuf::from(target_path);
    if !ensure_parent_dir(&target) {
        return false;
    }
    let Some(src) = open_db() else {
        return false;
    };
    let mut dst = match Connection::open(&target) {
        Ok(conn) => conn,
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to open snapshot target {}: {}",
                target.display(),
                e
            );
            return false;
        }
    };
    if let Err(e) = init_schema(&dst) {
        ohrs_log_error!(
            "[Rust] failed to init snapshot schema {}: {}",
            target.display(),
            e
        );
        return false;
    }
    match copy_snapshot_tables(&src, &mut dst) {
        Ok(_) => true,
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to export snapshot {}: {}",
                target.display(),
                e
            );
            false
        }
    }
}

pub fn import_config_store_snapshot_with_result(source_path: String) -> SnapshotImportResult {
    let source = PathBuf::from(source_path);
    let src = match Connection::open(&source) {
        Ok(conn) => conn,
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to open snapshot source {}: {}",
                source.display(),
                e
            );
            return snapshot_import_err("source_open_failed", e.to_string(), false);
        }
    };
    if !validate_snapshot_schema(&src) {
        ohrs_log_error!("[Rust] invalid snapshot schema {}", source.display());
        return snapshot_import_err(
            "invalid_snapshot_schema",
            format!("invalid snapshot schema: {}", source.display()),
            true,
        );
    }
    let (meta_rows, field_rows) = match read_snapshot_tables(&src) {
        Ok(rows) => rows,
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to read snapshot source {}: {}",
                source.display(),
                e
            );
            return snapshot_import_err("invalid_snapshot_data", e.to_string(), true);
        }
    };
    let Some(mut dst) = open_db() else {
        return snapshot_import_err(
            "destination_open_failed",
            "failed to open local config store",
            false,
        );
    };
    match write_snapshot_tables(&mut dst, meta_rows, field_rows) {
        Ok(_) => snapshot_import_ok(),
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to import snapshot {}: {}",
                source.display(),
                e
            );
            snapshot_import_err("destination_write_failed", e.to_string(), false)
        }
    }
}

pub fn import_config_store_snapshot(source_path: String) -> bool {
    import_config_store_snapshot_with_result(source_path).ok
}

pub fn reset_config_meta_store() -> bool {
    let Some(conn) = open_db() else {
        return false;
    };
    let tx = match conn.unchecked_transaction() {
        Ok(tx) => tx,
        Err(e) => {
            ohrs_log_error!(
                "[Rust] failed to start config store reset transaction: {}",
                e
            );
            return false;
        }
    };

    if let Err(e) = tx.execute("DELETE FROM stored_config_fields", []) {
        ohrs_log_error!("[Rust] failed to reset config fields: {}", e);
        let _ = tx.rollback();
        return false;
    }
    if let Err(e) = tx.execute("DELETE FROM stored_configs", []) {
        ohrs_log_error!("[Rust] failed to reset config meta: {}", e);
        let _ = tx.rollback();
        return false;
    }

    match tx.commit() {
        Ok(_) => true,
        Err(e) => {
            ohrs_log_error!("[Rust] failed to commit config store reset: {}", e);
            false
        }
    }
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
            ohrs_log_error!("[Rust] failed to prepare list meta query: {}", e);
            return StoredConfigList { configs: vec![] };
        }
    };

    let rows = match stmt.query_map([], row_to_meta) {
        Ok(rows) => rows,
        Err(e) => {
            ohrs_log_error!("[Rust] failed to list config meta rows: {}", e);
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

pub(crate) fn upsert_config_meta_in_tx(
    tx: &rusqlite::Transaction<'_>,
    config_id: String,
    display_name: String,
    favorite: bool,
    temporary: bool,
) -> Option<StoredConfigMeta> {
    let now = now_ts_string();
    let created_at = tx
        .query_row(
            "SELECT config_id, display_name, created_at, updated_at, favorite, temporary
             FROM stored_configs WHERE config_id = ?1",
            params![config_id],
            row_to_meta,
        )
        .optional()
        .ok()
        .flatten()
        .map(|record| record.created_at)
        .unwrap_or_else(|| now.clone());

    tx.execute(
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
    )
    .ok()?;

    tx.query_row(
        "SELECT config_id, display_name, created_at, updated_at, favorite, temporary
         FROM stored_configs WHERE config_id = ?1",
        params![config_id],
        row_to_meta,
    )
    .optional()
    .ok()
    .flatten()
    .map(to_meta)
    .or(Some(StoredConfigMeta {
        config_id,
        display_name,
        created_at,
        updated_at: now,
        favorite,
        temporary,
    }))
}

pub fn set_config_display_name(
    config_id: String,
    display_name: String,
) -> Option<StoredConfigMeta> {
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

pub fn set_config_favorite(config_id: String, favorite: bool) -> Option<StoredConfigMeta> {
    let conn = open_db()?;
    let now = now_ts_string();
    let tx = conn.unchecked_transaction().ok()?;

    if favorite {
        tx.execute(
            "UPDATE stored_configs
             SET favorite = 0,
                 updated_at = CASE WHEN favorite != 0 THEN ?1 ELSE updated_at END
             WHERE favorite != 0 AND config_id <> ?2",
            params![now, config_id.clone()],
        )
        .ok()?;
    }

    let rows = tx
        .execute(
            "UPDATE stored_configs
             SET favorite = ?2, updated_at = ?3
             WHERE config_id = ?1",
            params![config_id.clone(), if favorite { 1 } else { 0 }, now],
        )
        .ok()?;
    if rows == 0 {
        return None;
    }

    let meta = tx
        .query_row(
            "SELECT config_id, display_name, created_at, updated_at, favorite, temporary
             FROM stored_configs WHERE config_id = ?1",
            params![config_id],
            row_to_meta,
        )
        .optional()
        .ok()
        .flatten()
        .map(to_meta)?;
    tx.commit().ok()?;
    Some(meta)
}
