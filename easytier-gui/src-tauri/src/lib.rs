// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeMap;

use dashmap::DashMap;
use easytier::{
    common::config::{ConfigLoader, FileLoggerConfig, TomlConfigLoader},
    launcher::{NetworkConfig, NetworkInstance, NetworkInstanceRunningInfo},
    utils::{self, NewFilterSender},
};

use tauri::Manager as _;

pub const AUTOSTART_ARG: &str = "--autostart";

#[cfg(not(target_os = "android"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

static INSTANCE_MAP: once_cell::sync::Lazy<DashMap<String, NetworkInstance>> =
    once_cell::sync::Lazy::new(DashMap::new);

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
fn run_network_instance(cfg: NetworkConfig) -> Result<(), String> {
    if INSTANCE_MAP.contains_key(cfg.instance_id()) {
        return Err("instance already exists".to_string());
    }
    let instance_id = cfg.instance_id().to_string();

    let cfg = cfg.gen_config().map_err(|e| e.to_string())?;
    let mut instance = NetworkInstance::new(cfg);
    instance.start().map_err(|e| e.to_string())?;

    println!("instance {} started", instance_id);
    INSTANCE_MAP.insert(instance_id, instance);
    Ok(())
}

#[tauri::command]
fn retain_network_instance(instance_ids: Vec<String>) -> Result<(), String> {
    let _ = INSTANCE_MAP.retain(|k, _| instance_ids.contains(k));
    println!(
        "instance {:?} retained",
        INSTANCE_MAP
            .iter()
            .map(|item| item.key().clone())
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[tauri::command]
fn collect_network_infos() -> Result<BTreeMap<String, NetworkInstanceRunningInfo>, String> {
    let mut ret = BTreeMap::new();
    for instance in INSTANCE_MAP.iter() {
        if let Some(info) = instance.get_running_info() {
            ret.insert(instance.key().clone(), info);
        }
    }
    Ok(ret)
}

#[tauri::command]
fn get_os_hostname() -> Result<String, String> {
    Ok(gethostname::gethostname().to_string_lossy().to_string())
}

#[tauri::command]
fn set_logging_level(level: String) -> Result<(), String> {
    let sender = unsafe { LOGGER_LEVEL_SENDER.as_ref().unwrap() };
    sender.send(level).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn set_tun_fd(instance_id: String, fd: i32) -> Result<(), String> {
    let mut instance = INSTANCE_MAP
        .get_mut(&instance_id)
        .ok_or("instance not found")?;
    instance.set_tun_fd(fd);
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn toggle_window_visibility<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or_default() {
            let _ = window.hide();
        } else {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

#[cfg(not(target_os = "android"))]
fn check_sudo() -> bool {
    use std::env::current_exe;
    let is_elevated = privilege::user::privileged();
    if !is_elevated {
        let Ok(exe) = current_exe() else {
            return true;
        };
        let args: Vec<String> = std::env::args().collect();
        let mut elevated_cmd = privilege::runas::Command::new(exe);
        if args.contains(&AUTOSTART_ARG.to_owned()) {
            elevated_cmd.arg(AUTOSTART_ARG);
        }
        let _ = elevated_cmd.force_prompt(true).hide(true).gui(true).run();
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
            let config = TomlConfigLoader::default();
            config.set_file_logger_config(FileLoggerConfig {
                dir: Some(log_dir.to_string_lossy().to_string()),
                level: None,
                file: None,
            });
            let Ok(Some(logger_reinit)) = utils::init_logger(config, true) else {
                return Ok(());
            };
            unsafe { LOGGER_LEVEL_SENDER.replace(logger_reinit) };

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
