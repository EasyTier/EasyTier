// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod launcher;

use std::{collections::BTreeMap, env::current_exe, process};

use anyhow::Context;
use chrono::{DateTime, Local};
use dashmap::DashMap;
use easytier::{
    common::{
        config::{ConfigLoader, NetworkIdentity, PeerConfig, TomlConfigLoader, VpnPortalConfig},
        global_ctx::GlobalCtxEvent,
    },
    rpc::{PeerInfo, Route},
    utils::{list_peer_route_pair, PeerRoutePair},
};
use launcher::{EasyTierLauncher, MyNodeInfo};
use serde::{Deserialize, Serialize};

use tauri::{
    CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem,
    Window,
};

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

#[derive(Deserialize, Serialize, Debug, Default)]
struct NetworkConfig {
    instance_id: String,

    virtual_ipv4: String,
    hostname: Option<String>,
    network_name: String,
    network_secret: String,
    networking_method: NetworkingMethod,

    public_server_url: String,
    peer_urls: Vec<String>,

    proxy_cidrs: Vec<String>,

    enable_vpn_portal: bool,
    vpn_portal_listne_port: i32,
    vpn_portal_client_network_addr: String,
    vpn_portal_client_network_len: i32,

    advanced_settings: bool,

    listener_urls: Vec<String>,
    rpc_port: i32,
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
        cfg.set_inst_name(self.network_name.clone());
        cfg.set_network_identity(NetworkIdentity::new(
            self.network_name.clone(),
            self.network_secret.clone(),
        ));

        if self.virtual_ipv4.len() > 0 {
            cfg.set_ipv4(
                self.virtual_ipv4.parse().with_context(|| {
                    format!("failed to parse ipv4 address: {}", self.virtual_ipv4)
                })?,
            )
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
            format!("127.0.0.1:{}", self.rpc_port)
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
                wireguard_listen: format!("0.0.0.0:{}", self.vpn_portal_listne_port)
                    .parse()
                    .with_context(|| {
                        format!(
                            "failed to parse vpn portal wireguard listen port. {}",
                            self.vpn_portal_listne_port
                        )
                    })?,
            });
        }

        Ok(cfg)
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct NetworkInstanceRunningInfo {
    my_node_info: MyNodeInfo,
    events: Vec<(DateTime<Local>, GlobalCtxEvent)>,
    node_info: MyNodeInfo,
    routes: Vec<Route>,
    peers: Vec<PeerInfo>,
    peer_route_pairs: Vec<PeerRoutePair>,
    running: bool,
    error_msg: Option<String>,
}

struct NetworkInstance {
    config: TomlConfigLoader,
    launcher: Option<EasyTierLauncher>,
}

impl NetworkInstance {
    fn new(cfg: NetworkConfig) -> Result<Self, anyhow::Error> {
        Ok(Self {
            config: cfg.gen_config()?,
            launcher: None,
        })
    }

    fn is_easytier_running(&self) -> bool {
        self.launcher.is_some() && self.launcher.as_ref().unwrap().running()
    }

    fn get_running_info(&self) -> Option<NetworkInstanceRunningInfo> {
        if self.launcher.is_none() {
            return None;
        }

        let launcher = self.launcher.as_ref().unwrap();

        let peers = launcher.get_peers();
        let routes = launcher.get_routes();
        let peer_route_pairs = list_peer_route_pair(peers.clone(), routes.clone());

        Some(NetworkInstanceRunningInfo {
            my_node_info: launcher.get_node_info(),
            events: launcher.get_events(),
            node_info: launcher.get_node_info(),
            routes,
            peers,
            peer_route_pairs,
            running: launcher.running(),
            error_msg: launcher.error_msg(),
        })
    }

    fn start(&mut self) -> Result<(), anyhow::Error> {
        if self.is_easytier_running() {
            return Ok(());
        }

        let mut launcher = EasyTierLauncher::new();
        launcher.start(|| Ok(self.config.clone()));

        self.launcher = Some(launcher);
        Ok(())
    }
}

static INSTANCE_MAP: once_cell::sync::Lazy<DashMap<String, NetworkInstance>> =
    once_cell::sync::Lazy::new(DashMap::new);

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

    let mut instance = NetworkInstance::new(cfg).map_err(|e| e.to_string())?;
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

fn toggle_window_visibility(window: &Window) {
    if window.is_visible().unwrap() {
        window.hide().unwrap();
    } else {
        window.show().unwrap();
        window.set_focus().unwrap();
    }
}

fn check_sudo() -> bool {
    let is_elevated = privilege::user::privileged();
    if !is_elevated {
        let Ok(my_exe) = current_exe() else {
            return true;
        };
        let mut elevated_cmd = privilege::runas::Command::new(my_exe);
        let _ = elevated_cmd.force_prompt(true).gui(true).run();
    }
    is_elevated
}

fn main() {
    if !check_sudo() {
        process::exit(0);
    }
    let quit = CustomMenuItem::new("quit".to_string(), "退出 Quit");
    let hide = CustomMenuItem::new("hide".to_string(), "显示 Show / 隐藏 Hide");
    let tray_menu = SystemTrayMenu::new()
        .add_item(quit)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(hide);

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            parse_network_config,
            run_network_instance,
            retain_network_instance,
            collect_network_infos,
            get_os_hostname
        ])
        .system_tray(SystemTray::new().with_menu(tray_menu))
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::DoubleClick {
                position: _,
                size: _,
                ..
            } => {
                let window = app.get_window("main").unwrap();
                toggle_window_visibility(&window);
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    std::process::exit(0);
                }
                "hide" => {
                    let window = app.get_window("main").unwrap();
                    toggle_window_visibility(&window);
                }
                _ => {}
            },
            _ => {}
        })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                event.window().hide().unwrap();
                api.prevent_close();
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
