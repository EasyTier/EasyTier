use crate::config::storage::config_meta::get_config_meta;
use ohos_hilog_binding::hilog_error;
use std::path::PathBuf;

pub(super) fn legacy_config_file_path(root_dir: &Option<PathBuf>, config_dir_name: &str, config_id: &str) -> Option<PathBuf> {
    root_dir.as_ref().map(|root| root.join(config_dir_name).join(format!("{}.json", config_id)))
}

pub(super) fn migrate_legacy_file_if_needed(
    root_dir: &Option<PathBuf>,
    config_dir_name: &str,
    config_id: &str,
    save_config_record: impl Fn(String, String, String) -> Option<crate::config::types::stored_config::StoredConfigRecord>,
) -> Option<()> {
    let legacy_path = legacy_config_file_path(root_dir, config_dir_name, config_id)?;
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
