//! Tauri adapter only; the repository schema and rules live in easytier-core.
use easytier_core::management::application_snapshot::{
    ApplicationSnapshot, SnapshotBackend, SnapshotRepository,
};
use std::sync::Arc;
use tauri::{AppHandle, Manager};
use tauri_plugin_vpnservice::VpnserviceExt;

pub struct AndroidSnapshotBackend(AppHandle);
impl SnapshotBackend for AndroidSnapshotBackend {
    fn read(&self) -> anyhow::Result<Option<String>> {
        Ok(self.0.vpnservice().read_management_snapshot()?)
    }
    fn write(&self, payload: &str) -> anyhow::Result<()> {
        self.0
            .vpnservice()
            .write_management_snapshot(payload.to_owned())?;
        Ok(())
    }
}

pub type Repository = SnapshotRepository<AndroidSnapshotBackend>;
static BOOTSTRAP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tauri::command]
pub async fn bootstrap_android_management(
    app: AppHandle,
    legacy: Option<ApplicationSnapshot>,
) -> Result<Option<ApplicationSnapshot>, String> {
    let _bootstrap = BOOTSTRAP.lock().await;
    // Mobile plugin dispatch may block; never occupy the UI thread or a core worker.
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(repo) = app.try_state::<Arc<Repository>>() {
            return Ok(Some(repo.snapshot()));
        }
        let backend = AndroidSnapshotBackend(app.clone());
        if legacy.is_none() && backend.read().map_err(|e| e.to_string())?.is_none() {
            return Ok(None);
        }
        let legacy = legacy.unwrap_or(ApplicationSnapshot {
            schema_version: 1,
            configs: vec![],
            desired_enabled: vec![],
            profile: serde_json::json!({"mode": "normal"}),
            selected_network: None,
        });
        let repo = Arc::new(
            Repository::open(AndroidSnapshotBackend(app.clone()), legacy)
                .map_err(|e| e.to_string())?,
        );
        let snapshot = repo.snapshot();
        app.manage(repo);
        Ok(Some(snapshot))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn save_android_management_preferences(
    app: AppHandle,
    profile: serde_json::Value,
    selected_network: Option<String>,
) -> Result<(), String> {
    let repo = app
        .try_state::<Arc<Repository>>()
        .ok_or("Android management storage is not initialized")?
        .inner()
        .clone();
    tauri::async_runtime::spawn_blocking(move || {
        repo.save_preferences(profile, selected_network)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
