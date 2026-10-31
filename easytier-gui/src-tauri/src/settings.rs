use std::sync::Mutex;

use tauri::{AppHandle, Manager};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct GuiSettings {
    pub close_to_tray: bool,
    pub auto_start_network: bool,
    pub startup_network_id: Option<String>,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            auto_start_network: false,
            startup_network_id: None,
        }
    }
}

pub struct SettingsState(Mutex<GuiSettings>);

impl SettingsState {
    pub fn load(app: &AppHandle) -> anyhow::Result<Self> {
        let path = app.path().app_config_dir()?.join("gui-settings.json");
        let settings = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                eprintln!("Failed to read GUI settings, using defaults: {error}");
                GuiSettings::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => GuiSettings::default(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self(Mutex::new(settings)))
    }

    pub fn close_to_tray(&self) -> bool {
        self.0.lock().unwrap().close_to_tray
    }
}

#[tauri::command]
pub fn get_gui_settings(state: tauri::State<'_, SettingsState>) -> GuiSettings {
    state.inner().0.lock().unwrap().clone()
}

#[tauri::command]
pub fn save_gui_settings(
    app: AppHandle,
    state: tauri::State<'_, SettingsState>,
    settings: GuiSettings,
) -> Result<(), String> {
    let mut current = state.inner().0.lock().unwrap();
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let data = serde_json::to_vec_pretty(&settings).map_err(|e| e.to_string())?;
    let temp_path = dir.join("gui-settings.json.tmp");
    std::fs::write(&temp_path, data).map_err(|e| e.to_string())?;
    std::fs::rename(temp_path, dir.join("gui-settings.json")).map_err(|e| e.to_string())?;
    *current = settings;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::GuiSettings;

    #[test]
    fn missing_preferences_preserve_close_behavior_without_starting_a_network() {
        let settings: GuiSettings = serde_json::from_str("{}").unwrap();
        assert!(settings.close_to_tray);
        assert!(!settings.auto_start_network);
        assert!(settings.startup_network_id.is_none());
    }

    #[test]
    fn preferences_round_trip_with_frontend_field_names() {
        let value = serde_json::json!({
            "closeToTray": false,
            "autoStartNetwork": true,
            "startupNetworkId": "10c504d4-8f35-4401-87a0-605984ac2f10",
        });
        let settings: GuiSettings = serde_json::from_value(value.clone()).unwrap();
        assert!(!settings.close_to_tray);
        assert_eq!(serde_json::to_value(settings).unwrap(), value);
    }
}
