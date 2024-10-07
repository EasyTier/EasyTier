// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod command;
mod constant;

use command::LOGGER_LEVEL_SENDER;
use easytier::{
    common::config::{ConfigLoader, FileLoggerConfig, TomlConfigLoader},
    utils::{self},
};

use constant::*;
use tauri::Emitter;
use tauri::Manager as _;

#[cfg(not(mobile))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

#[cfg(not(mobile))]
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

#[cfg(not(mobile))]
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
    #[cfg(not(mobile))]
    {
        if !check_sudo() {
            use std::process;
            process::exit(0);
        }

        utils::setup_panic_handler();
    }

    let mut builder = tauri::Builder::default();

    #[cfg(not(mobile))]
    {
        use tauri_plugin_autostart::MacosLauncher;
        builder = builder.plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![AUTOSTART_ARG]),
        ));
        
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

    builder
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
            #[cfg(not(mobile))]
            {
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
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            command::parse_network_config,
            command::run_network_instance,
            command::stop_network_instance,
            command::get_os_hostname,
            command::set_logging_level,
            command::set_tun_fd,
            command::is_autostart,
            command::easytier_version
        ])
        .on_window_event(|win, event| match event {
            #[cfg(not(mobile))]
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let _ = win.emit(CLOSE_REQUESTED_EVENT, ());
                api.prevent_close();
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
