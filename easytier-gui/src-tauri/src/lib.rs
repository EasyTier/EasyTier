// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeMap;

use easytier::{
    common::config::{ConfigLoader, FileLoggerConfig, LoggingConfigBuilder, TomlConfigLoader},
    instance_manager::NetworkInstanceManager,
    launcher::{ConfigSource, NetworkConfig, NetworkInstanceRunningInfo},
    utils::{self, NewFilterSender},
};

use tauri::Manager as _;

pub const AUTOSTART_ARG: &str = "--autostart";

#[cfg(not(target_os = "android"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

static INSTANCE_MANAGER: once_cell::sync::Lazy<NetworkInstanceManager> =
    once_cell::sync::Lazy::new(NetworkInstanceManager::new);

static mut LOGGER_LEVEL_SENDER: once_cell::sync::Lazy<Option<NewFilterSender>> =
    once_cell::sync::Lazy::new(Default::default);

#[tauri::command]
fn easytier_version() -> Result<String, String> {
    Ok(easytier::VERSION.to_string())
}

#[tauri::command]
fn is_autostart() -> Result<bool, String> {
    let args: Vec<String> = std::env::args().collect();
    println!("{:?}", args);
    Ok(args.contains(&AUTOSTART_ARG.to_owned()))
}

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn parse_network_config(cfg: NetworkConfig) -> Result<String, String> {
    let toml = cfg.gen_config().map_err(|e| e.to_string())?;
    Ok(toml.dump())
}

#[tauri::command]
fn generate_network_config(toml_config: String) -> Result<NetworkConfig, String> {
    let config = TomlConfigLoader::new_from_str(&toml_config).map_err(|e| e.to_string())?;
    let cfg = NetworkConfig::new_from_config(&config).map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[tauri::command]
fn run_network_instance(cfg: NetworkConfig) -> Result<(), String> {
    let instance_id = cfg.instance_id().to_string();
    let cfg = cfg.gen_config().map_err(|e| e.to_string())?;
    INSTANCE_MANAGER
        .run_network_instance(cfg, ConfigSource::GUI)
        .map_err(|e| e.to_string())?;
    println!("instance {} started", instance_id);
    Ok(())
}

#[tauri::command]
fn retain_network_instance(instance_ids: Vec<String>) -> Result<(), String> {
    let instance_ids = instance_ids
        .into_iter()
        .filter_map(|id| uuid::Uuid::parse_str(&id).ok())
        .collect();
    let retained = INSTANCE_MANAGER
        .retain_network_instance(instance_ids)
        .map_err(|e| e.to_string())?;
    println!("instance {:?} retained", retained);
    Ok(())
}

#[tauri::command]
fn collect_network_infos() -> Result<BTreeMap<String, NetworkInstanceRunningInfo>, String> {
    let infos = INSTANCE_MANAGER
        .collect_network_infos()
        .map_err(|e| e.to_string())?;

    let mut ret = BTreeMap::new();
    for (uuid, info) in infos {
        ret.insert(uuid.to_string(), info);
    }

    Ok(ret)
}

#[tauri::command]
fn get_os_hostname() -> Result<String, String> {
    Ok(gethostname::gethostname().to_string_lossy().to_string())
}

#[tauri::command]
fn set_logging_level(level: String) -> Result<(), String> {
    #[allow(static_mut_refs)]
    let sender = unsafe { LOGGER_LEVEL_SENDER.as_ref().unwrap() };
    sender.send(level).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn set_tun_fd(instance_id: String, fd: i32) -> Result<(), String> {
    let uuid = uuid::Uuid::parse_str(&instance_id).map_err(|e| e.to_string())?;
    INSTANCE_MANAGER
        .set_tun_fd(&uuid, fd)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn toggle_window_visibility<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or_default() {
            if window.is_minimized().unwrap_or_default() {
                let _ = window.unminimize();
                let _ = window.set_focus();
            } else {
                let _ = window.hide();
            }
        } else {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

#[cfg(not(target_os = "android"))]
fn check_sudo() -> bool {
    let is_elevated = elevated_command::Command::is_elevated();
    if !is_elevated {
        let exe_path = std::env::var("APPIMAGE")
            .ok()
            .or_else(|| std::env::args().next())
            .unwrap_or_default();
        let args: Vec<String> = std::env::args().collect();
        let mut stdcmd = std::process::Command::new(&exe_path);
        if args.contains(&AUTOSTART_ARG.to_owned()) {
            stdcmd.arg(AUTOSTART_ARG);
        }
        elevated_command::Command::new(stdcmd)
            .output()
            .expect("Failed to run elevated command");
    }
    is_elevated
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(not(target_os = "android"))]
    if !check_sudo() {
        use std::process;
        process::exit(0);
    }

    utils::setup_panic_handler();

    let mut builder = tauri::Builder::default();

    #[cfg(not(target_os = "android"))]
    {
        use tauri_plugin_autostart::MacosLauncher;
        builder = builder.plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![AUTOSTART_ARG]),
        ));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            app.webview_windows()
                .values()
                .next()
                .expect("Sorry, no window found")
                .set_focus()
                .expect("Can't Bring Window to Focus");
        }));
    }

    builder = builder
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_vpnservice::init());

    let app = builder
        .setup(|app| {
            // for logging config
            let Ok(log_dir) = app.path().app_log_dir() else {
                return Ok(());
            };
            let config = LoggingConfigBuilder::default()
                .file_logger(FileLoggerConfig {
                    dir: Some(log_dir.to_string_lossy().to_string()),
                    level: None,
                    file: None,
                })
                .build()
                .map_err(|e| e.to_string())?;
            let Ok(Some(logger_reinit)) = utils::init_logger(&config, true) else {
                return Ok(());
            };
            #[allow(static_mut_refs)]
            unsafe {
                LOGGER_LEVEL_SENDER.replace(logger_reinit)
            };

            // for tray icon, menu need to be built in js
            #[cfg(not(target_os = "android"))]
            let _tray_menu = TrayIconBuilder::with_id("main")
                .menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        toggle_window_visibility(app);
                    }
                })
                .icon(tauri::image::Image::from_bytes(include_bytes!(
                    "../icons/icon.png"
                ))?)
                .icon_as_template(false)
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            parse_network_config,
            generate_network_config,
            run_network_instance,
            retain_network_instance,
            collect_network_infos,
            get_os_hostname,
            set_logging_level,
            set_tun_fd,
            is_autostart,
            easytier_version
        ])
        .on_window_event(|_win, event| match event {
            #[cfg(not(target_os = "android"))]
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let _ = _win.hide();
                api.prevent_close();
            }
            _ => {}
        })
        .build(tauri::generate_context!())
        .unwrap();

    #[cfg(not(target_os = "macos"))]
    app.run(|_app, _event| {});

    #[cfg(target_os = "macos")]
    {
        use tauri::RunEvent;
        app.run(|app, event| match event {
            RunEvent::Reopen { .. } => {
                toggle_window_visibility(app);
            }
            _ => {}
        });
    }
}
