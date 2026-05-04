use crate::config::storage::config_meta::{now_ts_string, open_db};
use ohos_hilog_binding::hilog_error;
use rusqlite::{Connection, params};
use serde_json::{Map, Value};

pub(super) fn load_config_map_from_db(config_id: &str) -> Option<Map<String, Value>> {
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

pub(super) fn replace_config_fields(
    tx: &Connection,
    config_id: &str,
    fields: Map<String, Value>,
) -> Option<()> {
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

    Some(())
}
