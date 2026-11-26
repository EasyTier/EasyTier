macro_rules! ohrs_log_error {
    ($($arg:tt)*) => {{
        if $crate::platform::logging::log_manager::app_log_enabled(5) {
            $crate::platform::logging::log_manager::record_app_log(
                5,
                "RustOhrs",
                &std::format!($($arg)*),
            );
        }
    }};
}

macro_rules! ohrs_log_info {
    ($($arg:tt)*) => {{
        if $crate::platform::logging::log_manager::app_log_enabled(4) {
            $crate::platform::logging::log_manager::record_app_log(
                4,
                "RustOhrs",
                &std::format!($($arg)*),
            );
        }
    }};
}

mod config;
mod exports;
mod napi_types;
mod platform;
mod runtime;

use config::repository::{cache_runtime_config_snapshot, clear_all_runtime_config_snapshots};
use config::schema::{
    get_network_config_field_mappings as build_network_config_field_mappings,
    get_network_config_schema_json as read_network_config_schema_json,
};
use config::share_link::{
    build_config_share_link_from_json as build_config_share_link_inner,
    parse_config_share_link as parse_config_share_link_inner,
};
use easytier::common::MachineIdOptions;
use easytier::common::config::ConfigLoader;
use easytier::common::constants::EASYTIER_VERSION;
use easytier::proto::api::manage::{NetworkConfig, NetworkingMethod};
use easytier::web_client::{WebClient, WebClientHooks, run_web_client};
use easytier_core::config::api_input::NetworkConfigExt;
use easytier_core::instance::manager::ConfigFileControl;
#[cfg(not(test))]
use napi_derive_ohos::napi;
use napi_types::{ConfigFieldMapping, KeyValuePair, SharedConfigLinkPayload};
use runtime::state::RuntimeAggregateState;
use runtime::{
    ASYNC_RUNTIME, INSTANCE_MANAGER, flush_runtime_allocators, local_dns, socket_protector,
    tun_watcher,
};
use std::collections::{HashMap, HashSet};
use std::format;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

static WEB_CLIENTS: once_cell::sync::Lazy<Mutex<HashMap<String, ManagedWebClient>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));
const PRO_CONFIG_SERVER_CLIENT_ID: &str = "__easytier_pro_config_server_client__";

#[derive(Default)]
struct TrackedWebClientHooks {
    instance_ids: Mutex<HashSet<Uuid>>,
    network_names_by_instance_id: Mutex<HashMap<Uuid, String>>,
    events: Mutex<Vec<serde_json::Value>>,
}

struct ManagedWebClient {
    _client: WebClient,
    hooks: Arc<TrackedWebClientHooks>,
}

fn network_name_for_instance(id: &Uuid) -> Option<String> {
    INSTANCE_MANAGER
        .config(*id)
        .map(|config| config.get_network_identity().network_name)
        .filter(|name| !name.trim().is_empty())
}

#[async_trait::async_trait]
impl WebClientHooks for TrackedWebClientHooks {
    async fn post_run_network_instance(&self, id: &Uuid) -> Result<(), String> {
        self.instance_ids
            .lock()
            .map_err(|err| err.to_string())?
            .insert(*id);
        let tun_enabled = INSTANCE_MANAGER
            .config(*id)
            .map(|cfg| !cfg.get_flags().no_tun)
            .unwrap_or(true);
        tun_watcher::spawn_instance_watcher(*id, tun_enabled);
        let network_name = network_name_for_instance(id);
        if let Some(network_name) = &network_name {
            self.network_names_by_instance_id
                .lock()
                .map_err(|err| err.to_string())?
                .insert(*id, network_name.clone());
        }
        self.events
            .lock()
            .map_err(|err| err.to_string())?
            .push(serde_json::json!({
                "event": "run_network_instance",
                "success": true,
                "instance_id": id.to_string(),
                "instance_name": id.to_string(),
                "network_name": network_name,
            }));
        Ok(())
    }

    async fn post_remove_network_instances(&self, ids: &[Uuid]) -> Result<(), String> {
        let mut guard = self.instance_ids.lock().map_err(|err| err.to_string())?;
        let mut events = self.events.lock().map_err(|err| err.to_string())?;
        let mut network_names_by_instance_id = self
            .network_names_by_instance_id
            .lock()
            .map_err(|err| err.to_string())?;
        for id in ids {
            guard.remove(id);
            let network_name = network_names_by_instance_id.remove(id);
            events.push(serde_json::json!({
                "event": "delete_network_instance",
                "success": true,
                "instance_id": id.to_string(),
                "instance_name": id.to_string(),
                "network_name": network_name,
            }));
        }
        tun_watcher::bump_policy_revision();
        Ok(())
    }
}

fn is_config_server_config(config: &NetworkConfig) -> bool {
    matches!(
        NetworkingMethod::try_from(config.networking_method.unwrap_or_default())
            .unwrap_or_default(),
        NetworkingMethod::PublicServer
    ) && config
        .public_server_url
        .as_ref()
        .is_some_and(|url| !url.trim().is_empty())
}

fn stop_web_client(config_id: &str) -> bool {
    let managed = match WEB_CLIENTS.lock() {
        Ok(mut guard) => guard.remove(config_id),
        Err(err) => {
            ohrs_log_error!("[Rust] stop_web_client lock failed {}", err);
            return false;
        }
    };

    let Some(managed) = managed else {
        return false;
    };

    let tracked_ids = managed
        .hooks
        .instance_ids
        .lock()
        .map(|guard| guard.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    drop(managed);

    if tracked_ids.is_empty() {
        return true;
    }

    ASYNC_RUNTIME
        .block_on(INSTANCE_MANAGER.delete_network_instances(tracked_ids))
        .map(|_| true)
        .unwrap_or_else(|err| {
            ohrs_log_error!(
                "[Rust] stop config server instances failed {}: {}",
                config_id,
                err
            );
            false
        })
}

fn run_config_server_instance(config_id: &str, config: &NetworkConfig) -> bool {
    if !INSTANCE_MANAGER.instance_ids().is_empty() {
        ohrs_log_error!("[Rust] there is a running instance!");
        return false;
    }

    let Some(config_server_url) = config.public_server_url.clone() else {
        ohrs_log_error!("[Rust] public_server_url missing for config server mode");
        return false;
    };
    let hooks = Arc::new(TrackedWebClientHooks::default());
    let secure_mode = config
        .secure_mode
        .as_ref()
        .map(|mode| mode.enabled)
        .unwrap_or(false);
    let hostname = config.hostname.clone();

    let client = ASYNC_RUNTIME.block_on(run_web_client(
        &config_server_url,
        MachineIdOptions::default(),
        hostname,
        secure_mode,
        INSTANCE_MANAGER.clone(),
        Some(hooks.clone()),
    ));

    let client = match client {
        Ok(client) => client,
        Err(err) => {
            ohrs_log_error!("[Rust] start config server failed {}", err);
            return false;
        }
    };

    match WEB_CLIENTS.lock() {
        Ok(mut guard) => {
            guard.insert(
                config_id.to_string(),
                ManagedWebClient {
                    _client: client,
                    hooks,
                },
            );
            tun_watcher::bump_policy_revision();
            true
        }
        Err(err) => {
            ohrs_log_error!("[Rust] store config server client failed {}", err);
            false
        }
    }
}

fn run_config_server_client(
    url: &str,
    hostname: Option<String>,
    machine_id: Option<String>,
    secure_mode: bool,
) -> bool {
    let trimmed_url = url.trim();
    if trimmed_url.is_empty() {
        ohrs_log_error!("[Rust] config server url missing");
        return false;
    }

    let _ = stop_web_client(PRO_CONFIG_SERVER_CLIENT_ID);
    let hooks = Arc::new(TrackedWebClientHooks::default());

    let machine_id_opts = MachineIdOptions {
        explicit_machine_id: machine_id.filter(|value| !value.trim().is_empty()),
        state_dir: None,
    };
    let client = ASYNC_RUNTIME.block_on(run_web_client(
        trimmed_url,
        machine_id_opts,
        hostname.filter(|value| !value.trim().is_empty()),
        secure_mode,
        INSTANCE_MANAGER.clone(),
        Some(hooks.clone()),
    ));

    let client = match client {
        Ok(client) => client,
        Err(err) => {
            ohrs_log_error!("[Rust] start pro config server client failed {}", err);
            return false;
        }
    };

    match WEB_CLIENTS.lock() {
        Ok(mut guard) => {
            guard.insert(
                PRO_CONFIG_SERVER_CLIENT_ID.to_string(),
                ManagedWebClient {
                    _client: client,
                    hooks,
                },
            );
            tun_watcher::bump_policy_revision();
            true
        }
        Err(err) => {
            ohrs_log_error!("[Rust] store pro config server client failed {}", err);
            false
        }
    }
}

fn pro_config_server_client_connected() -> bool {
    WEB_CLIENTS
        .lock()
        .ok()
        .and_then(|guard| {
            guard
                .get(PRO_CONFIG_SERVER_CLIENT_ID)
                .map(|managed| managed._client.is_connected())
        })
        .unwrap_or(false)
}

fn drain_config_server_events_inner() -> Vec<serde_json::Value> {
    let Ok(guard) = WEB_CLIENTS.lock() else {
        return Vec::new();
    };
    let Some(managed) = guard.get(PRO_CONFIG_SERVER_CLIENT_ID) else {
        return Vec::new();
    };
    let Ok(mut events) = managed.hooks.events.lock() else {
        return Vec::new();
    };
    events.drain(..).collect()
}

fn stop_runtime_inner() -> bool {
    let web_keys: Vec<String> = WEB_CLIENTS
        .lock()
        .map(|guard| guard.keys().cloned().collect())
        .unwrap_or_default();
    let mut ok = true;
    for key in web_keys {
        let _ = stop_web_client(&key);
    }
    let ids = INSTANCE_MANAGER.instance_ids();
    if !ids.is_empty() {
        ok = ASYNC_RUNTIME
            .block_on(INSTANCE_MANAGER.delete_network_instances(ids))
            .map(|_| true)
            .unwrap_or_else(|err| {
                ohrs_log_error!("[Rust] stop runtime instances failed {}", err);
                false
            })
            && ok;
    }
    clear_all_runtime_config_snapshots();
    local_dns::stop_all_sync();
    tun_watcher::clear_virtual_tun_fd();
    tun_watcher::bump_policy_revision();
    trim_memory_inner();
    ok
}

fn parse_network_config_inner(cfg_json: &str) -> bool {
    serde_json::from_str::<NetworkConfig>(cfg_json)
        .ok()
        .and_then(|cfg| cfg.gen_config().ok())
        .is_some()
}

pub(crate) fn run_network_instance_from_json(cfg_json: &str, display_name: Option<String>) -> bool {
    let config = match serde_json::from_str::<NetworkConfig>(cfg_json) {
        Ok(cfg) => cfg,
        Err(e) => {
            ohrs_log_error!("[Rust] parse config failed {}", e);
            return false;
        }
    };

    if is_config_server_config(&config) {
        let Some(config_id) = config.instance_id.as_deref() else {
            ohrs_log_error!("[Rust] config server config missing instance id");
            return false;
        };
        let started = run_config_server_instance(config_id, &config);
        if started {
            let label = display_name
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| config_id.to_string());
            cache_runtime_config_snapshot(config_id.to_string(), label, config);
        }
        return started;
    }

    let cfg = match config.gen_config() {
        Ok(toml) => toml,
        Err(e) => {
            ohrs_log_error!("[Rust] parse config failed {}", e);
            return false;
        }
    };

    if !INSTANCE_MANAGER.instance_ids().is_empty() {
        ohrs_log_error!("[Rust] there is a running instance!");
        return false;
    }

    let inst_id = cfg.get_id();
    let tun_enabled = !cfg.get_flags().no_tun;
    if INSTANCE_MANAGER.instance_ids().contains(&inst_id) {
        ohrs_log_error!("[Rust] instance {} already exists", inst_id);
        return false;
    }

    match INSTANCE_MANAGER.run_network_instance(cfg, ConfigFileControl::STATIC_CONFIG) {
        Ok(_) => {
            let label = display_name
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| inst_id.to_string());
            cache_runtime_config_snapshot(inst_id.to_string(), label, config);
            tun_watcher::spawn_instance_watcher(inst_id, tun_enabled);
            let _ = local_dns::refresh_all_sync();
            true
        }
        Err(err) => {
            ohrs_log_error!("[Rust] start_kernel failed for {}: {}", inst_id, err);
            false
        }
    }
}

fn parse_instance_uuid(config_id: &str) -> Option<Uuid> {
    match Uuid::parse_str(config_id) {
        Ok(uuid) => Some(uuid),
        Err(err) => {
            ohrs_log_error!("[Rust] invalid config_id {}: {}", config_id, err);
            None
        }
    }
}

fn trim_memory_inner() -> bool {
    platform::logging::log_manager::trim_memory_lines();
    flush_runtime_allocators();
    true
}

#[cfg_attr(not(test), napi)]
pub fn get_network_config_schema_json() -> String {
    read_network_config_schema_json().to_string()
}

#[cfg_attr(not(test), napi)]
pub fn get_network_config_field_mappings() -> Vec<ConfigFieldMapping> {
    build_network_config_field_mappings()
}

#[cfg_attr(not(test), napi)]
pub fn get_default_config() -> Option<String> {
    exports::config_api::get_default_config()
}

#[cfg_attr(not(test), napi)]
pub fn default_network_config() -> String {
    get_default_config().unwrap_or_else(|| "{}".to_string())
}

#[cfg_attr(not(test), napi)]
pub fn normalize_network_config(cfg_json: String, config_id: Option<String>) -> String {
    exports::config_api::normalize_network_config(&cfg_json, config_id.as_deref())
        .unwrap_or_else(|err| format!("ERROR: {err}"))
}

#[cfg_attr(not(test), napi)]
pub fn parse_network_config(cfg_json: String) -> bool {
    parse_network_config_inner(&cfg_json)
}

#[cfg_attr(not(test), napi)]
pub fn convert_toml_to_network_config(toml_text: String) -> String {
    exports::config_api::convert_toml_to_network_config(&toml_text)
        .unwrap_or_else(|err| format!("ERROR: {err}"))
}

#[cfg_attr(not(test), napi)]
pub fn convert_network_config_to_toml(cfg_json: String) -> String {
    exports::config_api::convert_network_config_to_toml(&cfg_json)
        .unwrap_or_else(|err| format!("ERROR: {err}"))
}

#[cfg_attr(not(test), napi)]
pub fn build_config_share_link_from_json(
    cfg_json: String,
    display_name: Option<String>,
    only_start: Option<bool>,
) -> Option<String> {
    build_config_share_link_inner(&cfg_json, display_name, only_start.unwrap_or(false))
}

#[cfg_attr(not(test), napi)]
pub fn parse_config_share_link(share_link: String) -> Option<SharedConfigLinkPayload> {
    parse_config_share_link_inner(&share_link)
}

#[cfg_attr(not(test), napi)]
pub fn run_network_instance(cfg_json: String, display_name: Option<String>) -> bool {
    run_network_instance_from_json(&cfg_json, display_name)
}

#[cfg_attr(not(test), napi)]
pub fn stop_kernel(config_id: String) -> bool {
    exports::runtime_api::stop_kernel(config_id, stop_web_client, parse_instance_uuid)
}

#[cfg_attr(not(test), napi)]
pub fn stop_network_instance(config_ids: Vec<String>) -> bool {
    exports::runtime_api::stop_network_instance(config_ids, stop_kernel)
}

#[cfg_attr(not(test), napi)]
pub fn start_config_server_client(
    url: String,
    hostname: Option<String>,
    machine_id: Option<String>,
    secure_mode: Option<bool>,
) -> bool {
    run_config_server_client(&url, hostname, machine_id, secure_mode.unwrap_or(false))
}

#[cfg_attr(not(test), napi)]
pub fn stop_config_server_client() -> bool {
    stop_web_client(PRO_CONFIG_SERVER_CLIENT_ID)
}

#[cfg_attr(not(test), napi)]
pub fn is_config_server_client_connected() -> bool {
    pro_config_server_client_connected()
}

#[cfg_attr(not(test), napi)]
pub fn stop_runtime() -> bool {
    stop_runtime_inner()
}

#[cfg_attr(not(test), napi)]
pub fn drain_config_server_events() -> String {
    serde_json::to_string(&drain_config_server_events_inner()).unwrap_or_else(|_| "[]".to_string())
}

#[cfg_attr(not(test), napi)]
pub fn collect_runtime_state_json() -> String {
    serde_json::to_string(&collect_runtime_state_inner()).unwrap_or_else(|_| "{}".to_string())
}

#[cfg_attr(not(test), napi)]
pub fn easytier_version() -> String {
    EASYTIER_VERSION.to_string()
}

#[cfg_attr(not(test), napi)]
pub fn collect_network_infos() -> Vec<KeyValuePair> {
    exports::runtime_api::collect_network_infos()
}

#[cfg_attr(not(test), napi)]
pub fn set_tun_fd(config_id: String, fd: i32) -> bool {
    exports::runtime_api::set_tun_fd(config_id, fd, parse_instance_uuid)
}

#[cfg_attr(not(test), napi)]
pub fn set_virtual_tun_fd(fd: i32) -> bool {
    tun_watcher::set_virtual_tun_fd(fd);
    true
}

#[cfg_attr(not(test), napi)]
pub fn get_policy_revision() -> i64 {
    tun_watcher::policy_revision()
}

#[cfg_attr(not(test), napi)]
pub fn get_topology_revision() -> i64 {
    tun_watcher::topology_revision()
}

#[cfg_attr(not(test), napi)]
pub fn trim_memory() -> bool {
    trim_memory_inner()
}

#[cfg_attr(not(test), napi)]
pub fn set_socket_protect_enabled(enabled: bool) -> String {
    let state = socket_protector::set_socket_protect_enabled(enabled);
    serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
}

#[cfg_attr(not(test), napi)]
pub fn get_socket_protect_state_json() -> String {
    let state = socket_protector::socket_protect_state();
    serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
}

#[cfg_attr(not(test), napi)]
pub fn refresh_physical_network() -> i32 {
    socket_protector::refresh_physical_network()
}

#[cfg_attr(not(test), napi)]
pub fn set_custom_dns_servers(servers: Vec<String>) {
    local_dns::set_custom_dns_servers(servers);
}

#[cfg_attr(not(test), napi)]
pub fn get_local_dns_state_json() -> String {
    let state = local_dns::local_dns_state();
    serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
}

pub(crate) fn collect_runtime_state_inner() -> RuntimeAggregateState {
    exports::runtime_api::collect_runtime_state()
}
