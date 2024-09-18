// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeMap;

use anyhow::Context;
use dashmap::DashMap;
use easytier::{
    common::config::{
        ConfigLoader, FileLoggerConfig, Flags, NetworkIdentity, PeerConfig, TomlConfigLoader,
        VpnPortalConfig,
    },
    launcher::{NetworkInstance, NetworkInstanceRunningInfo},
    utils::{self, NewFilterSender},
};
use serde::{Deserialize, Serialize};

use tauri::Manager as _;

pub const AUTOSTART_ARG: &str = "--autostart";

#[derive(Deserialize, Serialize, PartialEq, Debug)]
enum NetworkingMethod {
    PublicServer,
    Manual,
    Standalone,
}

impl Default for NetworkingMethod {
    fn default() -> Self {
        NetworkingMethod::PublicServer
    }
}

#[cfg(not(target_os = "android"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

#[derive(Deserialize, Serialize, Debug, Default)]
struct NetworkConfig {
    instance_id: String,

    dhcp: bool,
    virtual_ipv4: String,
    hostname: Option<String>,
    network_name: String,
    network_secret: String,
    networking_method: NetworkingMethod,

    public_server_url: String,
    peer_urls: Vec<String>,

    proxy_cidrs: Vec<String>,

    enable_vpn_portal: bool,
    vpn_portal_listen_port: i32,
    vpn_portal_client_network_addr: String,
    vpn_portal_client_network_len: i32,

    advanced_settings: bool,

    listener_urls: Vec<String>,
    rpc_port: i32,
    latency_first: bool,
}

impl NetworkConfig {
    fn gen_config(&self) -> Result<TomlConfigLoader, anyhow::Error> {
        let cfg = TomlConfigLoader::default();
        cfg.set_id(
            self.instance_id
                .parse()
                .with_context(|| format!("failed to parse instance id: {}", self.instance_id))?,
        );
        cfg.set_hostname(self.hostname.clone());
        cfg.set_dhcp(self.dhcp);
        cfg.set_inst_name(self.network_name.clone());
        cfg.set_network_identity(NetworkIdentity::new(
            self.network_name.clone(),
            self.network_secret.clone(),
        ));

        if !self.dhcp {
            if self.virtual_ipv4.len() > 0 {
                cfg.set_ipv4(Some(self.virtual_ipv4.parse().with_context(|| {
                    format!("failed to parse ipv4 address: {}", self.virtual_ipv4)
                })?))
            }
        }

        match self.networking_method {
            NetworkingMethod::PublicServer => {
                cfg.set_peers(vec![PeerConfig {
                    uri: self.public_server_url.parse().with_context(|| {
                        format!(
                            "failed to parse public server uri: {}",
                            self.public_server_url
                        )
                    })?,
                }]);
            }
            NetworkingMethod::Manual => {
                let mut peers = vec![];
                for peer_url in self.peer_urls.iter() {
                    if peer_url.is_empty() {
                        continue;
                    }
                    peers.push(PeerConfig {
                        uri: peer_url
                            .parse()
                            .with_context(|| format!("failed to parse peer uri: {}", peer_url))?,
                    });
                }

                cfg.set_peers(peers);
            }
            NetworkingMethod::Standalone => {}
        }

        let mut listener_urls = vec![];
        for listener_url in self.listener_urls.iter() {
            if listener_url.is_empty() {
                continue;
            }
            listener_urls.push(
                listener_url
                    .parse()
                    .with_context(|| format!("failed to parse listener uri: {}", listener_url))?,
            );
        }
        cfg.set_listeners(listener_urls);

        for n in self.proxy_cidrs.iter() {
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))?,
            );
        }

        cfg.set_rpc_portal(
            format!("0.0.0.0:{}", self.rpc_port)
                .parse()
                .with_context(|| format!("failed to parse rpc portal port: {}", self.rpc_port))?,
        );

        if self.enable_vpn_portal {
            let cidr = format!(
                "{}/{}",
                self.vpn_portal_client_network_addr, self.vpn_portal_client_network_len
            );
            cfg.set_vpn_portal_config(VpnPortalConfig {
                client_cidr: cidr
                    .parse()
                    .with_context(|| format!("failed to parse vpn portal client cidr: {}", cidr))?,
                wireguard_listen: format!("0.0.0.0:{}", self.vpn_portal_listen_port)
                    .parse()
                    .with_context(|| {
                        format!(
                            "failed to parse vpn portal wireguard listen port. {}",
                            self.vpn_portal_listen_port
                        )
                    })?,
            });
        }
        let mut flags = Flags::default();
        flags.latency_first = self.latency_first;
        cfg.set_flags(flags);
        Ok(cfg)
    }
}

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
    if INSTANCE_MAP.contains_key(&cfg.instance_id) {
        return Err("instance already exists".to_string());
    }
    let instance_id = cfg.instance_id.clone();

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

    #[cfg(not(target_os = "android"))]
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
