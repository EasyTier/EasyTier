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

macro_rules! ohrs_log_debug {
    ($($arg:tt)*) => {{
        if $crate::platform::logging::log_manager::app_log_enabled(3) {
            $crate::platform::logging::log_manager::record_app_log(
                3,
                "RustOhrs",
                &std::format!($($arg)*),
            );
        }
    }};
}

mod config;
mod exports;
mod kernel_bridge;
mod platform;
mod runtime;

use config::repository::{cache_runtime_config_snapshot, start_kernel_with_config_id};
use config::services::schema_service::{
    ConfigFieldMapping, NetworkConfigSchema,
    get_network_config_field_mappings as build_network_config_field_mappings,
    get_network_config_schema as build_network_config_schema,
};
use config::services::share_link_service::{
    build_config_share_link as build_config_share_link_inner,
    import_config_share_link as import_config_share_link_inner,
    parse_config_share_link as parse_config_share_link_inner,
};
use config::storage::config_meta::get_config_display_name;
use config::types::stored_config::{KeyValuePair, SharedConfigLinkPayload, SnapshotImportResult};
use easytier::common::constants::EASYTIER_VERSION;
use easytier::common::{
    MachineIdOptions,
    config::{ConfigFileControl, ConfigLoader, TomlConfigLoader},
};
use easytier::instance_manager::NetworkInstanceManager;
use easytier::proto::api::manage::NetworkConfig;
use easytier::proto::api::manage::NetworkingMethod;
use easytier::web_client::{WebClient, WebClientHooks, run_web_client};
use kernel_bridge::{
    start_local_socket_server as start_local_socket_server_inner,
    stop_local_socket_server as stop_local_socket_server_inner,
};
use napi_derive_ohos::napi;
use runtime::state::runtime_state::RuntimeAggregateState;
use std::collections::{HashMap, HashSet};
use std::format;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

pub(crate) static INSTANCE_MANAGER: once_cell::sync::Lazy<Arc<NetworkInstanceManager>> =
    once_cell::sync::Lazy::new(|| Arc::new(NetworkInstanceManager::new()));
static ASYNC_RUNTIME: once_cell::sync::Lazy<Runtime> = once_cell::sync::Lazy::new(|| {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for easytier-ohrs")
});
static WEB_CLIENTS: once_cell::sync::Lazy<Mutex<HashMap<String, ManagedWebClient>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Default)]
struct TrackedWebClientHooks {
    instance_ids: Mutex<HashSet<Uuid>>,
}

struct ManagedWebClient {
    _client: WebClient,
    hooks: Arc<TrackedWebClientHooks>,
}

#[async_trait::async_trait]
impl WebClientHooks for TrackedWebClientHooks {
    async fn post_run_network_instance(&self, id: &Uuid) -> Result<(), String> {
        self.instance_ids
            .lock()
            .map_err(|err| err.to_string())?
            .insert(*id);
        Ok(())
    }

    async fn post_remove_network_instances(&self, ids: &[Uuid]) -> Result<(), String> {
        let mut guard = self.instance_ids.lock().map_err(|err| err.to_string())?;
        for id in ids {
            guard.remove(id);
        }
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
        maybe_stop_local_socket_server();
        return true;
    }

    let ret = INSTANCE_MANAGER
        .delete_network_instance(tracked_ids)
        .map(|_| true)
        .unwrap_or_else(|err| {
            ohrs_log_error!(
                "[Rust] stop config server instances failed {}: {}",
                config_id,
                err
            );
            false
        });
    maybe_stop_local_socket_server();
    ret
}

fn ensure_local_socket_server_started() -> bool {
    start_local_socket_server_inner()
}

fn maybe_stop_local_socket_server() {
    let no_local_instances = INSTANCE_MANAGER.list_network_instance_ids().is_empty();
    let no_web_clients = WEB_CLIENTS
        .lock()
        .map(|guard| guard.is_empty())
        .unwrap_or(false);
    if no_local_instances && no_web_clients {
        let _ = stop_local_socket_server_inner();
    }
}

fn run_config_server_instance(config_id: &str, config: &NetworkConfig) -> bool {
    if INSTANCE_MANAGER
        .list_network_instance_ids()
        .iter()
        .next()
        .is_some()
    {
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

    if !ensure_local_socket_server_started() {
        return false;
    }

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
            true
        }
        Err(err) => {
            ohrs_log_error!("[Rust] store config server client failed {}", err);
            false
        }
    }
}

pub(crate) fn build_default_network_config_json() -> Result<String, String> {
    let config = NetworkConfig::new_from_config(TomlConfigLoader::default())
        .map_err(|e| format!("default_network_config failed {}", e))?;
    serde_json::to_string(&config).map_err(|e| format!("default_network_config failed {}", e))
}

fn convert_toml_to_network_config_inner(toml_text: &str) -> Result<String, String> {
    let config = NetworkConfig::new_from_config(
        TomlConfigLoader::new_from_str(toml_text).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    serde_json::to_string(&config).map_err(|e| e.to_string())
}

fn parse_network_config_inner(cfg_json: &str) -> bool {
    serde_json::from_str::<NetworkConfig>(cfg_json)
        .ok()
        .and_then(|cfg| cfg.gen_config().ok())
        .is_some()
}

pub(crate) fn run_network_instance_from_json(cfg_json: &str) -> bool {
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
            cache_runtime_config_snapshot(config_id.to_string(), config_id.to_string(), config);
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

    if !INSTANCE_MANAGER.list_network_instance_ids().is_empty() {
        ohrs_log_error!("[Rust] there is a running instance!");
        return false;
    }

    if !ensure_local_socket_server_started() {
        return false;
    }

    let inst_id = cfg.get_id();
    if INSTANCE_MANAGER
        .list_network_instance_ids()
        .contains(&inst_id)
    {
        ohrs_log_error!("[Rust] instance {} already exists", inst_id);
        return false;
    }

    match INSTANCE_MANAGER.run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG) {
        Ok(_) => {
            cache_runtime_config_snapshot(inst_id.to_string(), inst_id.to_string(), config);
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

#[napi]
pub fn init_config_store(root_dir: String) -> bool {
    exports::config_api::init_config_store(root_dir)
}

#[napi]
pub fn reset_config_store() -> bool {
    exports::config_api::reset_config_store()
}

#[napi]
pub fn list_configs() -> String {
    exports::config_api::list_configs()
}

#[napi]
pub fn get_config_display_name_by_id(config_id: String) -> Option<String> {
    get_config_display_name(&config_id)
}

#[napi]
pub fn save_config(config_id: String, display_name: String, config_json: String) -> bool {
    exports::config_api::save_config(config_id, display_name, config_json)
}

#[napi]
pub fn create_config(config_id: String, display_name: String) -> bool {
    exports::config_api::create_config(config_id, display_name)
}

#[napi]
pub fn rename_stored_config(config_id: String, display_name: String) -> bool {
    config::storage::config_meta::set_config_display_name(config_id, display_name).is_some()
}

#[napi]
pub fn delete_stored_config_meta(config_id: String) -> bool {
    exports::config_api::delete_stored_config_meta(config_id)
}

#[napi]
pub fn get_config(config_id: String) -> Option<String> {
    exports::config_api::get_config(config_id)
}

#[napi]
pub fn get_default_config() -> Option<String> {
    exports::config_api::get_default_config()
}

#[napi]
pub fn get_config_field(config_id: String, field: String) -> Option<String> {
    exports::config_api::get_config_field(config_id, field)
}

#[napi]
pub fn set_config_field(config_id: String, field: String, json_value: String) -> bool {
    exports::config_api::set_config_field(config_id, field, json_value)
}

#[napi]
pub fn set_config_favorite(config_id: String, favorite: bool) -> bool {
    exports::config_api::set_config_favorite(config_id, favorite)
}

#[napi]
pub fn import_toml(toml_text: String, display_name: Option<String>) -> Option<String> {
    exports::config_api::import_toml(toml_text, display_name)
}

#[napi]
pub fn export_toml(config_id: String) -> Option<String> {
    exports::config_api::export_toml(config_id)
}

#[napi]
pub fn export_config_store_snapshot(target_path: String) -> bool {
    exports::config_api::export_config_store_snapshot(target_path)
}

#[napi]
pub fn import_config_store_snapshot(source_path: String) -> bool {
    exports::config_api::import_config_store_snapshot(source_path)
}

#[napi]
pub fn import_config_store_snapshot_with_result(source_path: String) -> SnapshotImportResult {
    exports::config_api::import_config_store_snapshot_with_result(source_path)
}

#[napi]
pub fn start_kernel(config_id: String) -> bool {
    exports::runtime_api::start_kernel(config_id, start_kernel_with_config_id)
}

#[napi]
pub fn stop_kernel(config_id: String) -> bool {
    exports::runtime_api::stop_kernel(
        config_id,
        stop_web_client,
        parse_instance_uuid,
        maybe_stop_local_socket_server,
    )
}

#[napi]
pub fn stop_network_instance(config_ids: Vec<String>) -> bool {
    exports::runtime_api::stop_network_instance(config_ids, stop_kernel)
}

#[napi]
pub fn easytier_version() -> String {
    EASYTIER_VERSION.to_string()
}

#[napi]
pub fn default_network_config() -> String {
    get_default_config().unwrap_or_else(|| "{}".to_string())
}

#[napi]
pub fn convert_toml_to_network_config(toml_text: String) -> String {
    convert_toml_to_network_config_inner(&toml_text).unwrap_or_else(|err| format!("ERROR: {err}"))
}

#[napi]
pub fn parse_network_config(cfg_json: String) -> bool {
    parse_network_config_inner(&cfg_json)
}

#[napi]
pub fn run_network_instance(cfg_json: String) -> bool {
    run_network_instance_from_json(&cfg_json)
}

#[napi]
pub fn collect_network_infos() -> Vec<KeyValuePair> {
    exports::runtime_api::collect_network_infos()
}

#[napi]
pub fn set_tun_fd(config_id: String, fd: i32) -> bool {
    exports::runtime_api::set_tun_fd(config_id, fd, parse_instance_uuid)
}

#[napi]
pub fn get_network_config_schema() -> NetworkConfigSchema {
    build_network_config_schema()
}

#[napi]
pub fn get_network_config_field_mappings() -> Vec<ConfigFieldMapping> {
    build_network_config_field_mappings()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_plain_object_schema_contains_core_networkconfig_metadata() {
        let schema = get_network_config_schema();
        assert_eq!(schema.name, "NetworkConfig");
        assert_eq!(schema.node_kind, "schema");
        assert!(
            schema
                .children
                .iter()
                .any(|field| field.name == "network_name")
        );
        let secure_mode = schema
            .children
            .iter()
            .find(|field| field.name == "secure_mode")
            .expect("secure_mode field");
        assert!(
            secure_mode
                .children
                .iter()
                .any(|field| field.name == "enabled")
        );
    }
}

pub(crate) fn collect_runtime_state_inner() -> RuntimeAggregateState {
    exports::runtime_api::collect_runtime_state()
}

#[napi]
pub fn build_config_share_link(config_id: String, only_start: Option<bool>) -> Option<String> {
    build_config_share_link_inner(&config_id, None, only_start.unwrap_or(false))
}

#[napi]
pub fn parse_config_share_link(share_link: String) -> Option<SharedConfigLinkPayload> {
    parse_config_share_link_inner(&share_link)
}

#[napi]
pub fn import_config_share_link(
    share_link: String,
    display_name_override: Option<String>,
) -> Option<String> {
    import_config_share_link_inner(&share_link, display_name_override)
}
