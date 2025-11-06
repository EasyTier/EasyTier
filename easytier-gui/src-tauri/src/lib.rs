// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod elevate;

use easytier::proto::api::manage::{
    CollectNetworkInfoResponse, ValidateConfigResponse, WebClientService,
    WebClientServiceClientFactory,
};
use easytier::rpc_service::remote_client::{
    GetNetworkMetasResponse, ListNetworkInstanceIdsJsonResp, ListNetworkProps, RemoteClientManager,
    Storage,
};
use easytier::{
    common::config::{ConfigLoader, FileLoggerConfig, LoggingConfigBuilder, TomlConfigLoader},
    instance_manager::NetworkInstanceManager,
    launcher::NetworkConfig,
    rpc_service::ApiRpcServer,
    tunnel::ring::RingTunnelListener,
    utils::{self, NewFilterSender},
};
use std::ops::Deref;
use std::sync::Arc;
use uuid::Uuid;

use tauri::{AppHandle, Emitter, Manager as _};

#[cfg(not(target_os = "android"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

pub const AUTOSTART_ARG: &str = "--autostart";

static INSTANCE_MANAGER: once_cell::sync::Lazy<Arc<NetworkInstanceManager>> =
    once_cell::sync::Lazy::new(|| Arc::new(NetworkInstanceManager::new()));

static mut LOGGER_LEVEL_SENDER: once_cell::sync::Lazy<Option<NewFilterSender>> =
    once_cell::sync::Lazy::new(Default::default);

static RPC_RING_UUID: once_cell::sync::Lazy<uuid::Uuid> =
    once_cell::sync::Lazy::new(uuid::Uuid::new_v4);

static CLIENT_MANAGER: once_cell::sync::OnceCell<manager::GUIClientManager> =
    once_cell::sync::OnceCell::new();

#[tauri::command]
fn easytier_version() -> Result<String, String> {
    Ok(easytier::VERSION.to_string())
}

#[tauri::command]
fn set_dock_visibility(app: tauri::AppHandle, visible: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use tauri::ActivationPolicy;
        app.set_activation_policy(if visible {
            ActivationPolicy::Regular
        } else {
            ActivationPolicy::Accessory
        })
        .map_err(|e| e.to_string())?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (app, visible);
    Ok(())
}

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
async fn run_network_instance(app: AppHandle, cfg: NetworkConfig) -> Result<(), String> {
    let instance_id = cfg.instance_id().to_string();

    app.emit("pre_run_network_instance", cfg.instance_id())
        .map_err(|e| e.to_string())?;

    #[cfg(target_os = "android")]
    if cfg.no_tun() == false {
        CLIENT_MANAGER
            .get()
            .unwrap()
            .disable_instances_with_tun(&app)
            .await
            .map_err(|e| e.to_string())?;
    }

    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_run_network_instance(app.clone(), cfg)
        .await
        .map_err(|e| e.to_string())?;

    app.emit("post_run_network_instance", instance_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn collect_network_info(
    app: AppHandle,
    instance_id: String,
) -> Result<CollectNetworkInfoResponse, String> {
    let instance_id = instance_id
        .parse()
        .map_err(|e: uuid::Error| e.to_string())?;
    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_collect_network_info(app, Some(vec![instance_id]))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn set_logging_level(level: String) -> Result<(), String> {
    #[allow(static_mut_refs)]
    let sender = unsafe { LOGGER_LEVEL_SENDER.as_ref().unwrap() };
    sender.send(level).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn set_tun_fd(fd: i32) -> Result<(), String> {
    if let Some(uuid) = CLIENT_MANAGER
        .get()
        .unwrap()
        .get_enabled_instances_with_tun_ids()
        .next()
    {
        INSTANCE_MANAGER
            .set_tun_fd(&uuid, fd)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn list_network_instance_ids(
    app: AppHandle,
) -> Result<ListNetworkInstanceIdsJsonResp, String> {
    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_list_network_instance_ids(app)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn remove_network_instance(app: AppHandle, instance_id: String) -> Result<(), String> {
    let instance_id = instance_id
        .parse()
        .map_err(|e: uuid::Error| e.to_string())?;
    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_remove_network_instances(app.clone(), vec![instance_id])
        .await
        .map_err(|e| e.to_string())?;
    CLIENT_MANAGER
        .get()
        .unwrap()
        .notify_vpn_stop_if_no_tun(&app)?;
    Ok(())
}

#[tauri::command]
async fn update_network_config_state(
    app: AppHandle,
    instance_id: String,
    disabled: bool,
) -> Result<(), String> {
    let instance_id = instance_id
        .parse()
        .map_err(|e: uuid::Error| e.to_string())?;
    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_update_network_state(app.clone(), instance_id, disabled)
        .await
        .map_err(|e| e.to_string())?;
    if disabled {
        CLIENT_MANAGER
            .get()
            .unwrap()
            .notify_vpn_stop_if_no_tun(&app)?;
    }
    Ok(())
}

#[tauri::command]
async fn save_network_config(app: AppHandle, cfg: NetworkConfig) -> Result<(), String> {
    let instance_id = cfg
        .instance_id()
        .parse()
        .map_err(|e: uuid::Error| e.to_string())?;
    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_save_network_config(app, instance_id, cfg)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn validate_config(
    app: AppHandle,
    config: NetworkConfig,
) -> Result<ValidateConfigResponse, String> {
    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_validate_config(app, config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_config(app: AppHandle, instance_id: String) -> Result<NetworkConfig, String> {
    let cfg = CLIENT_MANAGER
        .get()
        .unwrap()
        .storage
        .get_network_config(app, &instance_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Config not found for instance ID: {}", instance_id))?;
    Ok(cfg.1)
}

#[tauri::command]
async fn load_configs(
    configs: Vec<NetworkConfig>,
    enabled_networks: Vec<String>,
) -> Result<(), String> {
    CLIENT_MANAGER
        .get()
        .unwrap()
        .storage
        .load_configs(configs, enabled_networks)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn get_network_metas(
    app: AppHandle,
    instance_ids: Vec<uuid::Uuid>,
) -> Result<GetNetworkMetasResponse, String> {
    CLIENT_MANAGER
        .get()
        .unwrap()
        .handle_get_network_metas(app, instance_ids)
        .await
        .map_err(|e| e.to_string())
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
    let is_elevated = elevate::Command::is_elevated();
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
        elevate::Command::new(stdcmd)
            .output()
            .expect("Failed to run elevated command");
    }
    is_elevated
}

mod manager {
    use super::*;
    use async_trait::async_trait;
    use dashmap::{DashMap, DashSet};
    use easytier::launcher::NetworkConfig;
    use easytier::proto::rpc_impl::bidirect::BidirectRpcManager;
    use easytier::proto::rpc_types::controller::BaseController;
    use easytier::rpc_service::remote_client::PersistentConfig;
    use easytier::tunnel::ring::RingTunnelConnector;
    use easytier::tunnel::TunnelConnector;

    #[derive(Clone)]
    pub(super) struct GUIConfig(String, pub(crate) NetworkConfig);
    impl PersistentConfig<anyhow::Error> for GUIConfig {
        fn get_network_inst_id(&self) -> &str {
            &self.0
        }
        fn get_network_config(&self) -> Result<NetworkConfig, anyhow::Error> {
            Ok(self.1.clone())
        }
    }

    pub(super) struct GUIStorage {
        network_configs: DashMap<Uuid, GUIConfig>,
        enabled_networks: DashSet<Uuid>,
    }
    impl GUIStorage {
        fn new() -> Self {
            Self {
                network_configs: DashMap::new(),
                enabled_networks: DashSet::new(),
            }
        }

        pub(super) async fn load_configs(
            &self,
            configs: Vec<NetworkConfig>,
            enabled_networks: Vec<String>,
        ) -> anyhow::Result<()> {
            self.network_configs.clear();
            for cfg in configs {
                let instance_id = cfg.instance_id();
                self.network_configs.insert(
                    instance_id.parse()?,
                    GUIConfig(instance_id.to_string(), cfg),
                );
            }

            self.enabled_networks.clear();
            INSTANCE_MANAGER
                .filter_network_instance(|_, _| true)
                .into_iter()
                .for_each(|id| {
                    self.enabled_networks.insert(id);
                });
            for id in enabled_networks {
                if let Ok(uuid) = id.parse() {
                    if !self.enabled_networks.contains(&uuid) {
                        let config = self
                            .network_configs
                            .get(&uuid)
                            .map(|i| i.value().1.gen_config())
                            .ok_or_else(|| anyhow::anyhow!("Config not found"))??;
                        INSTANCE_MANAGER.run_network_instance(config, true)?;
                        self.enabled_networks.insert(uuid);
                    }
                }
            }
            Ok(())
        }

        fn save_configs(&self, app: &AppHandle) -> anyhow::Result<()> {
            let configs: Result<Vec<String>, _> = self
                .network_configs
                .iter()
                .map(|entry| serde_json::to_string(&entry.value().1))
                .collect();
            let payload = format!("[{}]", configs?.join(","));
            app.emit_str("save_configs", payload)?;
            Ok(())
        }

        fn save_enabled_networks(&self, app: &AppHandle) -> anyhow::Result<()> {
            let payload: Vec<String> = self
                .enabled_networks
                .iter()
                .map(|entry| entry.key().to_string())
                .collect();
            app.emit("save_enabled_networks", payload)?;
            Ok(())
        }

        fn save_config(
            &self,
            app: &AppHandle,
            inst_id: Uuid,
            cfg: NetworkConfig,
        ) -> anyhow::Result<()> {
            let config = GUIConfig(inst_id.to_string(), cfg);
            self.network_configs.insert(inst_id, config);
            self.save_configs(app)
        }
    }
    #[async_trait]
    impl Storage<AppHandle, GUIConfig, anyhow::Error> for GUIStorage {
        async fn insert_or_update_user_network_config(
            &self,
            app: AppHandle,
            network_inst_id: Uuid,
            network_config: NetworkConfig,
        ) -> Result<(), anyhow::Error> {
            self.save_config(&app, network_inst_id, network_config)?;
            self.enabled_networks.insert(network_inst_id);
            self.save_enabled_networks(&app)?;
            Ok(())
        }

        async fn delete_network_configs(
            &self,
            app: AppHandle,
            network_inst_ids: &[Uuid],
        ) -> Result<(), anyhow::Error> {
            for network_inst_id in network_inst_ids {
                self.network_configs.remove(network_inst_id);
                self.enabled_networks.remove(network_inst_id);
            }
            self.save_configs(&app)
        }

        async fn update_network_config_state(
            &self,
            app: AppHandle,
            network_inst_id: Uuid,
            disabled: bool,
        ) -> Result<GUIConfig, anyhow::Error> {
            if disabled {
                self.enabled_networks.remove(&network_inst_id);
            } else {
                self.enabled_networks.insert(network_inst_id);
            }
            self.save_enabled_networks(&app)?;
            let cfg = self
                .network_configs
                .get(&network_inst_id)
                .ok_or_else(|| anyhow::anyhow!("Config not found"))?;
            Ok(cfg.value().clone())
        }

        async fn list_network_configs(
            &self,
            _: AppHandle,
            props: ListNetworkProps,
        ) -> Result<Vec<GUIConfig>, anyhow::Error> {
            let mut ret = Vec::new();
            for entry in self.network_configs.iter() {
                let id: Uuid = entry.key().to_owned();
                match props {
                    ListNetworkProps::All => {
                        ret.push(entry.value().clone());
                    }
                    ListNetworkProps::EnabledOnly => {
                        if self.enabled_networks.contains(&id) {
                            ret.push(entry.value().clone());
                        }
                    }
                    ListNetworkProps::DisabledOnly => {
                        if !self.enabled_networks.contains(&id) {
                            ret.push(entry.value().clone());
                        }
                    }
                }
            }
            Ok(ret)
        }

        async fn get_network_config(
            &self,
            _: AppHandle,
            network_inst_id: &str,
        ) -> Result<Option<GUIConfig>, anyhow::Error> {
            let uuid = Uuid::parse_str(network_inst_id)?;
            Ok(self
                .network_configs
                .get(&uuid)
                .map(|entry| entry.value().clone()))
        }
    }

    pub(super) struct GUIClientManager {
        pub(super) storage: GUIStorage,
        rpc_manager: BidirectRpcManager,
    }
    impl GUIClientManager {
        pub async fn new() -> Result<Self, anyhow::Error> {
            let mut connector = RingTunnelConnector::new(
                format!("ring://{}", RPC_RING_UUID.deref()).parse().unwrap(),
            );
            let tunnel = connector.connect().await?;
            let rpc_manager = BidirectRpcManager::new();
            rpc_manager.run_with_tunnel(tunnel);

            Ok(Self {
                storage: GUIStorage::new(),
                rpc_manager,
            })
        }

        pub fn get_enabled_instances_with_tun_ids(&self) -> impl Iterator<Item = uuid::Uuid> + '_ {
            self.storage
                .network_configs
                .iter()
                .filter(|v| self.storage.enabled_networks.contains(v.key()))
                .filter(|v| !v.1.no_tun())
                .filter_map(|c| c.1.instance_id().parse::<uuid::Uuid>().ok())
        }

        #[cfg(target_os = "android")]
        pub(super) async fn disable_instances_with_tun(
            &self,
            app: &AppHandle,
        ) -> Result<(), easytier::rpc_service::remote_client::RemoteClientError<anyhow::Error>>
        {
            for inst_id in self.get_enabled_instances_with_tun_ids() {
                self.handle_update_network_state(app.clone(), inst_id, true)
                    .await?;
            }
            Ok(())
        }

        pub(super) fn notify_vpn_stop_if_no_tun(&self, app: &AppHandle) -> Result<(), String> {
            let has_tun = self.get_enabled_instances_with_tun_ids().any(|_| true);
            if !has_tun {
                app.emit("vpn_service_stop", "")
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }
    impl RemoteClientManager<AppHandle, GUIConfig, anyhow::Error> for GUIClientManager {
        fn get_rpc_client(
            &self,
            _: AppHandle,
        ) -> Option<Box<dyn WebClientService<Controller = BaseController> + Send>> {
            Some(
                self.rpc_manager
                    .rpc_client()
                    .scoped_client::<WebClientServiceClientFactory<BaseController>>(
                        1,
                        1,
                        "".to_string(),
                    ),
            )
        }

        fn get_storage(&self) -> &impl Storage<AppHandle, GUIConfig, anyhow::Error> {
            &self.storage
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(not(target_os = "android"))]
    if !check_sudo() {
        use std::process;
        process::exit(0);
    }

    utils::setup_panic_handler();

    let _rpc_server_handle = tauri::async_runtime::spawn(async move {
        let rpc_server = ApiRpcServer::from_tunnel(
            RingTunnelListener::new(format!("ring://{}", RPC_RING_UUID.deref()).parse().unwrap()),
            INSTANCE_MANAGER.clone(),
        )
        .serve()
        .await
        .expect("Failed to start RPC server");

        let _ = CLIENT_MANAGER.set(
            manager::GUIClientManager::new()
                .await
                .expect("Failed to create GUI client manager"),
        );

        rpc_server
    });

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
                    size_mb: None,
                    count: None,
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
                .show_menu_on_left_click(false)
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
            collect_network_info,
            set_logging_level,
            set_tun_fd,
            easytier_version,
            set_dock_visibility,
            list_network_instance_ids,
            remove_network_instance,
            update_network_config_state,
            save_network_config,
            validate_config,
            get_config,
            load_configs,
            get_network_metas,
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
