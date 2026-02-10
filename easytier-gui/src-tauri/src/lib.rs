// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod elevate;

use anyhow::Context;
use easytier::proto::api::manage::{
    CollectNetworkInfoResponse, ValidateConfigResponse, WebClientService,
    WebClientServiceClientFactory,
};
use easytier::rpc_service::remote_client::{
    GetNetworkMetasResponse, ListNetworkInstanceIdsJsonResp, ListNetworkProps, RemoteClientManager,
    Storage,
};
use easytier::web_client::{self, WebClient};
use easytier::{
    common::config::{ConfigLoader, FileLoggerConfig, LoggingConfigBuilder, TomlConfigLoader},
    instance_manager::NetworkInstanceManager,
    launcher::NetworkConfig,
    rpc_service::ApiRpcServer,
    tunnel::ring::RingTunnelListener,
    tunnel::tcp::TcpTunnelListener,
    tunnel::TunnelListener,
    utils::{self},
};
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, RwLockReadGuard};
use uuid::Uuid;

use tauri::{AppHandle, Emitter, Manager as _};

#[cfg(not(target_os = "android"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

static INSTANCE_MANAGER: once_cell::sync::Lazy<RwLock<Option<Arc<NetworkInstanceManager>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

static RPC_RING_UUID: once_cell::sync::Lazy<uuid::Uuid> =
    once_cell::sync::Lazy::new(uuid::Uuid::new_v4);

static CLIENT_MANAGER: once_cell::sync::Lazy<RwLock<Option<manager::GUIClientManager>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

type BoxedTunnelListener = Box<dyn TunnelListener>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RpcServerKind {
    Ring,
    Tcp,
}

struct RpcServer {
    kind: RpcServerKind,
    _server: ApiRpcServer<BoxedTunnelListener>,
    bind_url: Option<url::Url>,
}
static RPC_SERVER: once_cell::sync::Lazy<Mutex<Option<RpcServer>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

static WEB_CLIENT: once_cell::sync::Lazy<RwLock<Option<WebClient>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

macro_rules! get_client_manager {
    () => {{
        let guard = CLIENT_MANAGER
            .try_read()
            .map_err(|_| "Failed to acquire read lock for client manager")?;
        RwLockReadGuard::try_map(guard, |cm| cm.as_ref())
            .map_err(|_| "RPC connection not initialized".to_string())
    }};
}

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
async fn run_network_instance(
    app: AppHandle,
    cfg: NetworkConfig,
    save: bool,
) -> Result<(), String> {
    let client_manager = get_client_manager!()?;
    let toml_config = cfg.gen_config().map_err(|e| e.to_string())?;
    client_manager
        .pre_run_network_instance_hook(&app, &toml_config)
        .await?;
    client_manager
        .handle_run_network_instance(app.clone(), cfg, save)
        .await
        .map_err(|e| e.to_string())?;
    client_manager
        .post_run_network_instance_hook(&app, &toml_config.get_id())
        .await?;
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
    get_client_manager!()?
        .handle_collect_network_info(app, Some(vec![instance_id]))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_logging_level(level: String) -> Result<(), String> {
    println!("Setting logging level to: {}", level);
    get_client_manager!()?
        .set_logging_level(level.clone())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn set_tun_fd(fd: i32) -> Result<(), String> {
    let Some(instance_manager) = INSTANCE_MANAGER.read().await.clone() else {
        return Err("set_tun_fd is not supported in remote mode".to_string());
    };
    if let Some(uuid) = get_client_manager!()?
        .get_enabled_instances_with_tun_ids()
        .next()
    {
        instance_manager
            .set_tun_fd(&uuid, fd)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn list_network_instance_ids(
    app: AppHandle,
) -> Result<ListNetworkInstanceIdsJsonResp, String> {
    get_client_manager!()?
        .handle_list_network_instance_ids(app)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn remove_network_instance(app: AppHandle, instance_id: String) -> Result<(), String> {
    let instance_id = instance_id
        .parse()
        .map_err(|e: uuid::Error| e.to_string())?;
    let client_manager = get_client_manager!()?;
    client_manager
        .handle_remove_network_instances(app.clone(), vec![instance_id])
        .await
        .map_err(|e| e.to_string())?;
    client_manager
        .post_remove_network_instances_hook(&app, &[instance_id])
        .await?;

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
    let client_manager = get_client_manager!()?;
    client_manager
        .handle_update_network_state(app.clone(), instance_id, disabled)
        .await
        .map_err(|e| e.to_string())?;

    if disabled {
        client_manager
            .post_remove_network_instances_hook(&app, &[instance_id])
            .await?;
    }

    Ok(())
}

#[tauri::command]
async fn save_network_config(app: AppHandle, cfg: NetworkConfig) -> Result<(), String> {
    let instance_id = cfg
        .instance_id()
        .parse()
        .map_err(|e: uuid::Error| e.to_string())?;
    get_client_manager!()?
        .handle_save_network_config(app, instance_id, cfg)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn validate_config(
    app: AppHandle,
    config: NetworkConfig,
) -> Result<ValidateConfigResponse, String> {
    get_client_manager!()?
        .handle_validate_config(app, config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_config(app: AppHandle, instance_id: String) -> Result<NetworkConfig, String> {
    let instance_id = instance_id
        .parse()
        .map_err(|e: uuid::Error| e.to_string())?;
    let cfg = get_client_manager!()?
        .handle_get_network_config(app, instance_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[tauri::command]
async fn load_configs(
    app: AppHandle,
    configs: Vec<NetworkConfig>,
    enabled_networks: Vec<String>,
) -> Result<(), String> {
    get_client_manager!()?
        .load_configs(app, configs, enabled_networks)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn get_network_metas(
    app: AppHandle,
    instance_ids: Vec<uuid::Uuid>,
) -> Result<GetNetworkMetasResponse, String> {
    get_client_manager!()?
        .handle_get_network_metas(app, instance_ids)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn init_service() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn init_service(opts: Option<service::ServiceOptions>) -> Result<(), String> {
    match opts {
        Some(args) => {
            let path = std::path::Path::new(&args.config_dir);
            if !path.exists() {
                std::fs::create_dir_all(&args.config_dir).map_err(|e| e.to_string())?;
            } else if !path.is_dir() {
                return Err("config_dir exists but is not a directory".to_string());
            }
            let path = std::path::Path::new(&args.file_log_dir);
            if !path.exists() {
                std::fs::create_dir_all(&args.file_log_dir).map_err(|e| e.to_string())?;
            } else if !path.is_dir() {
                return Err("file_log_dir exists but is not a directory".to_string());
            }

            service::install(args).map_err(|e| format!("{:#}", e))?;
        }
        None => {
            service::uninstall().map_err(|e| format!("{:#}", e))?;
        }
    }
    Ok(())
}

#[tauri::command]
fn set_service_status(_enable: bool) -> Result<(), String> {
    #[cfg(not(target_os = "android"))]
    {
        service::set_status(_enable).map_err(|e| format!("{:#}", e))?;
    }
    Ok(())
}

#[tauri::command]
fn get_service_status() -> Result<&'static str, String> {
    #[cfg(not(target_os = "android"))]
    {
        use easytier::service_manager::ServiceStatus;
        let status = service::status().map_err(|e| format!("{:#}", e))?;
        match status {
            ServiceStatus::NotInstalled => Ok("NotInstalled"),
            ServiceStatus::Stopped(_) => Ok("Stopped"),
            ServiceStatus::Running => Ok("Running"),
        }
    }
    #[cfg(target_os = "android")]
    {
        Ok("NotInstalled")
    }
}

fn normalize_normal_mode_rpc_portal(portal: &str) -> Result<(url::Url, url::Url), String> {
    let portal_url: url::Url = portal
        .parse()
        .map_err(|e| format!("invalid rpc portal: {:#}", e))?;
    let bind_url = portal_url.clone();
    let mut connect_url = portal_url.clone();
    // if bind addr is 0.0.0.0, should convert to 127.0.0.1
    if connect_url.host_str() == Some("0.0.0.0") {
        connect_url.set_host(Some("127.0.0.1")).unwrap();
    }
    Ok((bind_url, connect_url))
}

#[tauri::command]
async fn init_rpc_connection(
    _app: AppHandle,
    is_normal_mode: bool,
    url: Option<String>,
) -> Result<(), String> {
    let mut client_manager_guard =
        tokio::time::timeout(std::time::Duration::from_secs(5), CLIENT_MANAGER.write())
            .await
            .map_err(|_| "Failed to acquire write lock for client manager")?;
    let mut instance_manager_guard = INSTANCE_MANAGER
        .try_write()
        .map_err(|_| "Failed to acquire write lock for instance manager")?;
    let mut rpc_server_guard = RPC_SERVER
        .try_lock()
        .map_err(|_| "Failed to acquire lock for rpc server")?;

    let mut client_url = url.clone();
    if is_normal_mode {
        let instance_manager = if let Some(im) = instance_manager_guard.take() {
            im
        } else {
            Arc::new(NetworkInstanceManager::new())
        };

        let portal = url.and_then(|s| {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        let (desired_kind, bind_url, connect_url) = if let Some(portal) = portal {
            let (bind_url, connect_url) = normalize_normal_mode_rpc_portal(&portal)?;
            (RpcServerKind::Tcp, Some(bind_url), Some(connect_url))
        } else {
            (RpcServerKind::Ring, None, None)
        };

        let need_restart = rpc_server_guard
            .as_ref()
            .map(|x| x.kind != desired_kind || x.bind_url != bind_url)
            .unwrap_or(true);

        if need_restart {
            *rpc_server_guard = None;

            let tunnel: BoxedTunnelListener = match desired_kind {
                RpcServerKind::Ring => Box::new(RingTunnelListener::new(
                    format!("ring://{}", RPC_RING_UUID.deref()).parse().unwrap(),
                )),
                RpcServerKind::Tcp => Box::new(TcpTunnelListener::new(
                    bind_url.clone().expect("tcp rpc must have bind url"),
                )),
            };

            let rpc_server = ApiRpcServer::from_tunnel(tunnel, instance_manager.clone())
                .with_rx_timeout(None)
                .serve()
                .await
                .map_err(|e| e.to_string())?;
            *rpc_server_guard = Some(RpcServer {
                kind: desired_kind,
                _server: rpc_server,
                bind_url,
            });
        }

        *instance_manager_guard = Some(instance_manager);
        client_url = connect_url.map(|u| u.to_string());
    } else {
        *rpc_server_guard = None;
    }

    let client_manager = tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        manager::GUIClientManager::new(client_url),
    )
    .await
    .map_err(|_| "connect remote rpc timed out".to_string())?
    .with_context(|| "Failed to connect remote rpc")
    .map_err(|e| format!("{:#}", e))?;
    *client_manager_guard = Some(client_manager);

    if !is_normal_mode {
        drop(WEB_CLIENT.write().await.take());
        if let Some(instance_manager) = instance_manager_guard.take() {
            instance_manager
                .retain_network_instance(vec![])
                .map_err(|e| e.to_string())?;
            drop(instance_manager);
        }
    }

    Ok(())
}

#[tauri::command]
async fn is_client_running() -> Result<bool, String> {
    Ok(get_client_manager!()?.rpc_manager.is_running())
}

#[tauri::command]
async fn init_web_client(app: AppHandle, url: Option<String>) -> Result<(), String> {
    let mut web_client_guard = WEB_CLIENT.write().await;
    let Some(url) = url else {
        *web_client_guard = None;
        return Ok(());
    };
    let instance_manager = INSTANCE_MANAGER
        .try_read()
        .map_err(|_| "Failed to acquire read lock for instance manager")?
        .clone()
        .ok_or_else(|| "Instance manager is not available".to_string())?;

    let hooks = Arc::new(manager::GuiHooks { app: app.clone() });

    let web_client =
        web_client::run_web_client(url.as_str(), None, None, instance_manager, Some(hooks))
            .await
            .with_context(|| "Failed to initialize web client")
            .map_err(|e| format!("{:#}", e))?;
    *web_client_guard = Some(web_client);
    Ok(())
}

#[tauri::command]
async fn is_web_client_connected() -> Result<bool, String> {
    let web_client_guard = WEB_CLIENT.read().await;
    if let Some(web_client) = web_client_guard.as_ref() {
        Ok(web_client.is_connected())
    } else {
        Ok(false)
    }
}

// 获取日志目录的辅助函数
fn get_log_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, tauri::Error> {
    if cfg!(target_os = "android") {
        // Android: cache_dir + logs 子目录
        app.path().cache_dir().map(|p| p.join("logs"))
    } else {
        // 其他平台: 默认日志目录
        app.path().app_log_dir()
    }
}

#[tauri::command]
async fn get_log_dir_path(app: tauri::AppHandle) -> Result<String, String> {
    match get_log_dir(&app) {
        Ok(log_dir) => {
            std::fs::create_dir_all(&log_dir).ok();
            Ok(log_dir.to_string_lossy().to_string())
        }
        Err(e) => Err(format!("Failed to get log directory: {}", e)),
    }
}

#[cfg(not(target_os = "android"))]
fn toggle_window_visibility(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let visible = if window.is_visible().unwrap_or_default() {
            if window.is_minimized().unwrap_or_default() {
                let _ = window.unminimize();
                false
            } else if window.is_focused().unwrap_or_default() {
                true
            } else {
                false
            }
        } else {
            let _ = window.show();
            false
        };
        if visible {
            let _ = window.hide();
        } else {
            let _ = window.set_focus();
        }
        let _ = set_dock_visibility(app.clone(), !visible);
    }
}

fn get_exe_path() -> String {
    if let Ok(appimage_path) = std::env::var("APPIMAGE") {
        if !appimage_path.is_empty() {
            return appimage_path;
        }
    }
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[cfg(not(target_os = "android"))]
fn check_sudo() -> bool {
    let is_elevated = elevate::Command::is_elevated();
    if !is_elevated {
        let exe_path = get_exe_path();
        let stdcmd = std::process::Command::new(&exe_path);
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
    use easytier::common::global_ctx::GlobalCtx;
    use easytier::common::stun::MockStunInfoCollector;
    use easytier::launcher::NetworkConfig;
    use easytier::proto::api::logger::{LoggerRpc, LoggerRpcClientFactory, SetLoggerConfigRequest};
    use easytier::proto::api::manage::RunNetworkInstanceRequest;
    use easytier::proto::common::NatType;
    use easytier::proto::rpc_impl::bidirect::BidirectRpcManager;
    use easytier::proto::rpc_types::controller::BaseController;
    use easytier::rpc_service::logger::LoggerRpcService;
    use easytier::rpc_service::remote_client::PersistentConfig;
    use easytier::tunnel::ring::RingTunnelConnector;
    use easytier::tunnel::TunnelConnector;
    use easytier::web_client::WebClientHooks;

    pub(super) struct GuiHooks {
        pub(super) app: AppHandle,
    }

    #[async_trait]
    impl WebClientHooks for GuiHooks {
        async fn pre_run_network_instance(
            &self,
            cfg: &easytier::common::config::TomlConfigLoader,
        ) -> Result<(), String> {
            let client_manager = get_client_manager!()?;
            client_manager
                .pre_run_network_instance_hook(&self.app, cfg)
                .await
        }

        async fn post_run_network_instance(&self, instance_id: &uuid::Uuid) -> Result<(), String> {
            let client_manager = get_client_manager!()?;
            client_manager
                .post_run_network_instance_hook(&self.app, instance_id)
                .await
        }

        async fn post_remove_network_instances(&self, ids: &[uuid::Uuid]) -> Result<(), String> {
            let client_manager = get_client_manager!()?;
            client_manager
                .post_remove_network_instances_hook(&self.app, ids)
                .await
        }
    }

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
        ) -> Result<(), anyhow::Error> {
            if disabled {
                self.enabled_networks.remove(&network_inst_id);
            } else {
                self.enabled_networks.insert(network_inst_id);
            }
            self.save_enabled_networks(&app)?;
            Ok(())
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
        pub(super) rpc_manager: BidirectRpcManager,
    }
    impl GUIClientManager {
        pub async fn new(rpc_url: Option<String>) -> Result<Self, anyhow::Error> {
            let global_ctx = Arc::new(GlobalCtx::new(TomlConfigLoader::default()));
            global_ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
                udp_nat_type: NatType::Unknown,
            }));
            let mut flags = global_ctx.get_flags();
            flags.bind_device = false;
            global_ctx.set_flags(flags);
            let tunnel = if let Some(url) = rpc_url {
                let mut connector = easytier::connector::create_connector_by_url(
                    &url,
                    &global_ctx,
                    easytier::tunnel::IpVersion::Both,
                )
                .await?;
                connector.connect().await?
            } else {
                let mut connector = RingTunnelConnector::new(
                    format!("ring://{}", RPC_RING_UUID.deref()).parse().unwrap(),
                );
                connector.connect().await?
            };

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
            let inst_ids: Vec<uuid::Uuid> = self.get_enabled_instances_with_tun_ids().collect();
            for inst_id in inst_ids {
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

        pub(super) async fn pre_run_network_instance_hook(
            &self,
            app: &AppHandle,
            cfg: &easytier::common::config::TomlConfigLoader,
        ) -> Result<(), String> {
            let instance_id = cfg.get_id();
            app.emit("pre_run_network_instance", instance_id)
                .map_err(|e| e.to_string())?;

            #[cfg(target_os = "android")]
            if !cfg.get_flags().no_tun {
                self.disable_instances_with_tun(app)
                    .await
                    .map_err(|e| e.to_string())?;
            }

            self.storage
                .save_config(
                    app,
                    instance_id,
                    NetworkConfig::new_from_config(cfg).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;

            Ok(())
        }

        pub(super) async fn post_run_network_instance_hook(
            &self,
            app: &AppHandle,
            instance_id: &uuid::Uuid,
        ) -> Result<(), String> {
            #[cfg(target_os = "android")]
            if let Some(instance_manager) = super::INSTANCE_MANAGER.read().await.as_ref() {
                let instance_uuid = *instance_id;
                if let Some(instance_ref) = instance_manager
                    .iter()
                    .find(|item| *item.key() == instance_uuid)
                {
                    if let Some(mut event_receiver) = instance_ref.value().subscribe_event() {
                        let app_clone = app.clone();
                        let instance_id_clone = *instance_id;
                        tokio::spawn(async move {
                            loop {
                                match event_receiver.recv().await {
                                    Ok(easytier::common::global_ctx::GlobalCtxEvent::DhcpIpv4Changed(_, _)) => {
                                        let _ = app_clone.emit("dhcp_ip_changed", instance_id_clone);
                                    }
                                    Ok(easytier::common::global_ctx::GlobalCtxEvent::ProxyCidrsUpdated(_, _)) => {
                                        let _ = app_clone.emit("proxy_cidrs_updated", instance_id_clone);
                                    }
                                    Ok(_) => {}
                                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                        break;
                                    }
                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                        let _ = app_clone.emit("event_lagged", instance_id_clone);
                                        event_receiver = event_receiver.resubscribe();
                                    }
                                }
                            }
                        });
                    }
                }
            }

            self.storage.enabled_networks.insert(*instance_id);

            app.emit("post_run_network_instance", instance_id)
                .map_err(|e| e.to_string())?;

            Ok(())
        }

        pub(super) async fn post_remove_network_instances_hook(
            &self,
            app: &AppHandle,
            _ids: &[uuid::Uuid],
        ) -> Result<(), String> {
            self.storage
                .enabled_networks
                .retain(|id| !_ids.contains(id));
            self.notify_vpn_stop_if_no_tun(app)?;
            Ok(())
        }

        fn get_logger_rpc_client(
            &self,
        ) -> Option<Box<dyn LoggerRpc<Controller = BaseController> + Send>> {
            Some(
                self.rpc_manager
                    .rpc_client()
                    .scoped_client::<LoggerRpcClientFactory<BaseController>>(1, 1, "".to_string()),
            )
        }

        pub(super) async fn set_logging_level(&self, level: String) -> Result<(), anyhow::Error> {
            let logger_rpc = self
                .get_logger_rpc_client()
                .ok_or_else(|| anyhow::anyhow!("Logger RPC client not available"))?;
            logger_rpc
                .set_logger_config(
                    BaseController::default(),
                    SetLoggerConfigRequest {
                        level: LoggerRpcService::string_to_log_level(&level).into(),
                    },
                )
                .await?;
            Ok(())
        }

        pub(super) async fn load_configs(
            &self,
            app: AppHandle,
            configs: Vec<NetworkConfig>,
            enabled_networks: Vec<String>,
        ) -> anyhow::Result<()> {
            self.storage.network_configs.clear();
            for cfg in configs {
                let instance_id = cfg.instance_id();
                self.storage.network_configs.insert(
                    instance_id.parse()?,
                    GUIConfig(instance_id.to_string(), cfg),
                );
            }

            self.storage.enabled_networks.clear();
            let client = self
                .get_rpc_client(app.clone())
                .ok_or_else(|| anyhow::anyhow!("RPC client not found"))?;
            for id in enabled_networks {
                if let Ok(uuid) = id.parse() {
                    if !self.storage.enabled_networks.contains(&uuid) {
                        let config = self
                            .storage
                            .network_configs
                            .get(&uuid)
                            .map(|i| i.value().1.clone());
                        if config.is_none() {
                            continue;
                        }
                        client
                            .run_network_instance(
                                BaseController::default(),
                                RunNetworkInstanceRequest {
                                    inst_id: None,
                                    config,
                                    overwrite: false,
                                },
                            )
                            .await?;
                        self.storage.enabled_networks.insert(uuid);
                    }
                }
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

#[cfg(not(target_os = "android"))]
mod service {
    use anyhow::Context;

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct ServiceOptions {
        pub(super) config_dir: String,
        pub(super) rpc_portal: String,
        pub(super) file_log_level: String,
        pub(super) file_log_dir: String,
        pub(super) config_server: Option<String>,
    }
    impl ServiceOptions {
        fn to_args_vec(&self) -> Vec<std::ffi::OsString> {
            let mut args = vec![
                "--config-dir".into(),
                self.config_dir.clone().into(),
                "--rpc-portal".into(),
                self.rpc_portal.clone().into(),
                "--file-log-level".into(),
                self.file_log_level.clone().into(),
                "--file-log-dir".into(),
                self.file_log_dir.clone().into(),
                "--daemon".into(),
            ];

            if let Some(config_server) = &self.config_server {
                args.push("--config-server".into());
                args.push(config_server.clone().into());
            }

            args
        }
    }

    pub fn install(opts: ServiceOptions) -> anyhow::Result<()> {
        let service = easytier::service_manager::Service::new(env!("CARGO_PKG_NAME").to_string())?;
        let options = easytier::service_manager::ServiceInstallOptions {
            program: super::get_exe_path().into(),
            args: opts.to_args_vec(),
            work_directory: std::env::current_dir()?,
            disable_autostart: false,
            description: Some("EasyTier Gui Service".to_string()),
            display_name: Some("EasyTier Gui Service".to_string()),
            disable_restart_on_failure: false,
        };
        service
            .install(&options)
            .with_context(|| "Failed to install service")?;
        Ok(())
    }

    pub fn uninstall() -> anyhow::Result<()> {
        let service = easytier::service_manager::Service::new(env!("CARGO_PKG_NAME").to_string())?;
        service.uninstall()?;
        Ok(())
    }

    pub fn set_status(enable: bool) -> anyhow::Result<()> {
        use easytier::service_manager::*;
        let service = Service::new(env!("CARGO_PKG_NAME").to_string())?;
        let status = service.status()?;
        if enable && status != ServiceStatus::Running {
            service.start().with_context(|| "Failed to start service")?;
        } else if !enable && status == ServiceStatus::Running {
            service.stop().with_context(|| "Failed to stop service")?;
        } else if status == ServiceStatus::NotInstalled {
            return Err(anyhow::anyhow!("Service not installed"));
        }
        Ok(())
    }

    pub fn status() -> anyhow::Result<easytier::service_manager::ServiceStatus> {
        let service = easytier::service_manager::Service::new(env!("CARGO_PKG_NAME").to_string())?;
        service.status()
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run_gui() -> std::process::ExitCode {
    #[cfg(not(target_os = "android"))]
    if !check_sudo() {
        use std::process;
        process::exit(0);
    }

    utils::setup_panic_handler();

    let mut builder = tauri::Builder::default();

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
            let Ok(log_dir) = get_log_dir(app.app_handle()) else {
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
            let Ok(_) = utils::init_logger(&config, true) else {
                return Ok(());
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
                .icon_as_template(true)
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
            init_service,
            set_service_status,
            get_service_status,
            init_rpc_connection,
            is_client_running,
            init_web_client,
            is_web_client_connected,
            get_log_dir_path,
        ])
        .on_window_event(|_win, event| match event {
            #[cfg(not(target_os = "android"))]
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let _ = _win.hide();
                let _ = set_dock_visibility(_win.app_handle().clone(), false);
                api.prevent_close();
            }
            _ => {}
        })
        .build(tauri::generate_context!())
        .unwrap();

    app.run(|_app, _event| {});

    std::process::ExitCode::SUCCESS
}

pub fn run_cli() -> std::process::ExitCode {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { easytier::core::main().await })
}
