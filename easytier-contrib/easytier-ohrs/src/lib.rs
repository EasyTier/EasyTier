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
use easytier::common::config::NetworkConfigExt;
use easytier::common::constants::EASYTIER_VERSION;
use easytier::common::{
    MachineIdOptions,
    config::{ConfigFileControl, ConfigLoader, TomlConfigLoader},
};
use easytier::instance::factory::{NativeInstanceManager, native_instance_manager_with_runtime};
use easytier::proto::api::manage::NetworkConfig;
use easytier::proto::api::manage::NetworkingMethod;
use easytier::web_client::{WebClient, WebClientHooks, run_web_client};
use kernel_bridge::{
    start_local_socket_server as start_local_socket_server_inner,
    stop_local_socket_server as stop_local_socket_server_inner,
};
use napi_derive_ohos::napi;
use runtime::state::runtime_state::{RuntimeAggregateState, RuntimeInstanceState};
use std::collections::{HashMap, HashSet};
use std::format;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

static ASYNC_RUNTIME: once_cell::sync::Lazy<Runtime> = once_cell::sync::Lazy::new(|| {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for easytier-ohrs")
});
pub(crate) static INSTANCE_MANAGER: once_cell::sync::Lazy<Arc<NativeInstanceManager>> =
    once_cell::sync::Lazy::new(|| {
        Arc::new(native_instance_manager_with_runtime(
            ASYNC_RUNTIME.handle().clone(),
        ))
    });
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

    let ret = ASYNC_RUNTIME
        .block_on(INSTANCE_MANAGER.delete_network_instances(tracked_ids))
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
    let no_local_instances = INSTANCE_MANAGER.instance_ids().is_empty();
    let no_web_clients = WEB_CLIENTS
        .lock()
        .map(|guard| guard.is_empty())
        .unwrap_or(false);
    if no_local_instances && no_web_clients {
        let _ = stop_local_socket_server_inner();
    }
}

fn run_config_server_instance(config_id: &str, config: &NetworkConfig) -> bool {
    if INSTANCE_MANAGER.instance_ids().iter().next().is_some() {
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

    if !ensure_local_socket_server_started() {
        return false;
    }

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
    let mut ok = stop_web_client(PRO_CONFIG_SERVER_CLIENT_ID);
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
    maybe_stop_local_socket_server();
    ok
}

fn is_pro_internal_instance(instance: &RuntimeInstanceState) -> bool {
    instance.instance_id == PRO_CONFIG_SERVER_CLIENT_ID
        || instance.config_id == PRO_CONFIG_SERVER_CLIENT_ID
        || instance.display_name == PRO_CONFIG_SERVER_CLIENT_ID
}

fn runtime_instance_label(instance: &RuntimeInstanceState) -> String {
    let display_name = instance.display_name.trim();
    if !display_name.is_empty() && display_name != PRO_CONFIG_SERVER_CLIENT_ID {
        return display_name.to_string();
    }
    let instance_id = instance.instance_id.trim();
    if !instance_id.is_empty() {
        return instance_id.to_string();
    }
    instance.config_id.clone()
}

fn runtime_instance_matches(instance: &RuntimeInstanceState, selector: &str) -> bool {
    let target = selector.trim();
    if target.is_empty() {
        return false;
    }
    instance.instance_id == target
        || instance.config_id == target
        || instance.display_name == target
        || runtime_instance_label(instance) == target
}

fn read_json_string_path<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_str().filter(|value| !value.trim().is_empty())
}

fn selected_instance_from_payload(payload_json: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(payload_json).ok()?;
    for path in [
        &["instance", "instance_selector", "name"][..],
        &["instance", "instanceSelector", "name"][..],
        &["instance", "instance_selector", "id"][..],
        &["instance", "instanceSelector", "id"][..],
        &["instance", "name"][..],
        &["instance", "id"][..],
        &["instance_name"][..],
        &["instanceName"][..],
        &["instance_id"][..],
        &["instanceId"][..],
        &["id"][..],
    ] {
        if let Some(value) = read_json_string_path(&value, path) {
            return Some(value.to_string());
        }
    }
    None
}

fn find_runtime_instance<'a>(
    state: &'a RuntimeAggregateState,
    selector: Option<&str>,
) -> Option<&'a RuntimeInstanceState> {
    if let Some(selector) = selector
        && let Some(instance) = state.instances.iter().find(|instance| {
            !is_pro_internal_instance(instance) && runtime_instance_matches(instance, selector)
        })
    {
        return Some(instance);
    }
    state
        .instances
        .iter()
        .find(|instance| !is_pro_internal_instance(instance) && instance.running)
}

fn list_instances_json_inner(state: &RuntimeAggregateState) -> String {
    let mut instances = serde_json::Map::new();
    for instance in state
        .instances
        .iter()
        .filter(|instance| !is_pro_internal_instance(instance) && instance.running)
    {
        let label = runtime_instance_label(instance);
        if !label.trim().is_empty() {
            instances.insert(
                label,
                serde_json::Value::String(instance.instance_id.clone()),
            );
        }
    }
    serde_json::Value::Object(instances).to_string()
}

fn list_pro_instances_json_inner(
    state: &RuntimeAggregateState,
    network_names_by_instance_id: &HashMap<String, String>,
) -> String {
    let mut instances = serde_json::Map::new();
    for instance in state.instances.iter().filter(|instance| instance.running) {
        let Some(network_name) = network_names_by_instance_id.get(&instance.instance_id) else {
            continue;
        };
        let label = if network_name.trim().is_empty() {
            instance.instance_id.clone()
        } else {
            network_name.clone()
        };
        instances.insert(
            label,
            serde_json::Value::String(instance.instance_id.clone()),
        );
    }
    serde_json::Value::Object(instances).to_string()
}

fn find_pro_runtime_instance<'a>(
    state: &'a RuntimeAggregateState,
    network_names_by_instance_id: &HashMap<String, String>,
    selector: Option<&str>,
) -> Option<(&'a RuntimeInstanceState, String)> {
    let mut tracked_instances = state.instances.iter().filter_map(|instance| {
        let network_name = network_names_by_instance_id.get(&instance.instance_id)?;
        Some((instance, network_name))
    });
    if let Some(selector) = selector {
        return tracked_instances
            .filter(|(instance, _)| instance.running)
            .find(|(instance, network_name)| {
                selector == network_name.as_str() || runtime_instance_matches(instance, selector)
            })
            .map(|(instance, network_name)| (instance, network_name.clone()));
    }
    tracked_instances
        .find(|(instance, _)| instance.running)
        .map(|(instance, network_name)| (instance, network_name.clone()))
}

fn call_pro_json_rpc_inner(
    state: &RuntimeAggregateState,
    network_names_by_instance_id: &HashMap<String, String>,
    service_name: &str,
    method_name: &str,
    payload_json: &str,
) -> String {
    let selector = selected_instance_from_payload(payload_json);
    let Some((instance, network_name)) =
        find_pro_runtime_instance(state, network_names_by_instance_id, selector.as_deref())
    else {
        return "{}".to_string();
    };

    let method = method_name.trim();
    let service = service_name.trim();
    let response = match (service, method) {
        (_, "show_node_info") => serde_json::json!({
            "node_info": instance.my_node_info,
        }),
        (_, "list_route") => serde_json::json!({
            "routes": instance.routes,
        }),
        (_, "list_peer") => serde_json::json!({
            "my_info": instance.my_node_info,
            "peer_infos": instance.peers,
        }),
        (_, "get_stats") => {
            let mut rx_bytes = 0_i64;
            let mut tx_bytes = 0_i64;
            for peer in &instance.peers {
                for conn in &peer.conns {
                    if let Some(stats) = &conn.stats {
                        rx_bytes = rx_bytes.saturating_add(stats.rx_bytes);
                        tx_bytes = tx_bytes.saturating_add(stats.tx_bytes);
                    }
                }
            }
            serde_json::json!({
                "metrics": [
                    {
                        "name": "traffic_bytes_self_rx",
                        "labels": { "network_name": network_name },
                        "value": rx_bytes,
                    },
                    {
                        "name": "traffic_bytes_self_tx",
                        "labels": { "network_name": network_name },
                        "value": tx_bytes,
                    }
                ]
            })
        }
        _ => serde_json::json!({}),
    };
    response.to_string()
}

fn pro_runtime_registry_snapshot() -> HashMap<String, String> {
    WEB_CLIENTS
        .lock()
        .ok()
        .and_then(|clients| {
            clients
                .get(PRO_CONFIG_SERVER_CLIENT_ID)
                .and_then(|managed| managed.hooks.network_names_by_instance_id.lock().ok())
                .map(|registry| {
                    registry
                        .iter()
                        .map(|(instance_id, network_name)| {
                            (instance_id.to_string(), network_name.clone())
                        })
                        .collect()
                })
        })
        .unwrap_or_default()
}

fn call_json_rpc_inner(service_name: &str, method_name: &str, payload_json: &str) -> String {
    let state = collect_runtime_state_inner();
    let selector = selected_instance_from_payload(payload_json);
    let Some(instance) = find_runtime_instance(&state, selector.as_deref()) else {
        return "{}".to_string();
    };

    let method = method_name.trim();
    let service = service_name.trim();
    let response = match (service, method) {
        (_, "show_node_info") => serde_json::json!({
            "node_info": instance.my_node_info,
        }),
        (_, "list_route") => serde_json::json!({
            "routes": instance.routes,
        }),
        (_, "list_peer") => serde_json::json!({
            "my_info": instance.my_node_info,
            "peer_infos": instance.peers,
        }),
        (_, "get_stats") => {
            let mut rx_bytes = 0_i64;
            let mut tx_bytes = 0_i64;
            for peer in &instance.peers {
                for conn in &peer.conns {
                    if let Some(stats) = &conn.stats {
                        rx_bytes = rx_bytes.saturating_add(stats.rx_bytes);
                        tx_bytes = tx_bytes.saturating_add(stats.tx_bytes);
                    }
                }
            }
            let network_name = runtime_instance_label(instance);
            serde_json::json!({
                "metrics": [
                    {
                        "name": "traffic_bytes_self_rx",
                        "labels": { "network_name": network_name },
                        "value": rx_bytes,
                    },
                    {
                        "name": "traffic_bytes_self_tx",
                        "labels": { "network_name": network_name },
                        "value": tx_bytes,
                    }
                ]
            })
        }
        _ => serde_json::json!({}),
    };
    response.to_string()
}

fn resolve_instance_id_from_state(
    state: &RuntimeAggregateState,
    instance_name: &str,
) -> Option<String> {
    let instance = state.instances.iter().find(|instance| {
        !is_pro_internal_instance(instance) && runtime_instance_matches(instance, instance_name)
    })?;
    Some(instance.instance_id.clone())
}

fn resolve_instance_id_inner(instance_name: &str) -> Option<String> {
    resolve_instance_id_from_state(&collect_runtime_state_inner(), instance_name)
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

    if !INSTANCE_MANAGER.instance_ids().is_empty() {
        ohrs_log_error!("[Rust] there is a running instance!");
        return false;
    }

    if !ensure_local_socket_server_started() {
        return false;
    }

    let inst_id = cfg.get_id();
    if INSTANCE_MANAGER.instance_ids().contains(&inst_id) {
        ohrs_log_error!("[Rust] instance {} already exists", inst_id);
        return false;
    }

    match INSTANCE_MANAGER.run_network_instance(cfg, ConfigFileControl::STATIC_CONFIG) {
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
pub fn start_config_server_client(
    url: String,
    hostname: Option<String>,
    machine_id: Option<String>,
    secure_mode: Option<bool>,
) -> bool {
    run_config_server_client(&url, hostname, machine_id, secure_mode.unwrap_or(false))
}

#[napi]
pub fn stop_config_server_client() -> bool {
    stop_web_client(PRO_CONFIG_SERVER_CLIENT_ID)
}

#[napi]
pub fn is_config_server_client_connected() -> bool {
    pro_config_server_client_connected()
}

#[napi]
pub fn stop_runtime() -> bool {
    stop_runtime_inner()
}

#[napi]
pub fn drain_config_server_events() -> String {
    serde_json::to_string(&drain_config_server_events_inner()).unwrap_or_else(|_| "[]".to_string())
}

#[napi]
pub fn collect_runtime_state_json() -> String {
    serde_json::to_string(&collect_runtime_state_inner()).unwrap_or_else(|_| "{}".to_string())
}

#[napi]
pub fn list_instances_json() -> String {
    list_instances_json_inner(&collect_runtime_state_inner())
}

#[napi]
pub fn list_pro_instances_json() -> String {
    let registry = pro_runtime_registry_snapshot();
    list_pro_instances_json_inner(&collect_runtime_state_inner(), &registry)
}

#[napi]
pub fn call_json_rpc(service_name: String, method_name: String, payload_json: String) -> String {
    call_json_rpc_inner(&service_name, &method_name, &payload_json)
}

#[napi]
pub fn call_pro_json_rpc(
    service_name: String,
    method_name: String,
    payload_json: String,
) -> String {
    let registry = pro_runtime_registry_snapshot();
    call_pro_json_rpc_inner(
        &collect_runtime_state_inner(),
        &registry,
        &service_name,
        &method_name,
        &payload_json,
    )
}

#[napi]
pub fn resolve_instance_id(instance_name: String) -> Option<String> {
    resolve_instance_id_inner(&instance_name)
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

    fn pro_test_state() -> RuntimeAggregateState {
        RuntimeAggregateState {
            instances: vec![
                RuntimeInstanceState {
                    config_id: "0c4b33ba-4ed5-42d8-9095-21b786c66e94".to_string(),
                    instance_id: "0c4b33ba-4ed5-42d8-9095-21b786c66e94".to_string(),
                    display_name: "0c4b33ba-4ed5-42d8-9095-21b786c66e94".to_string(),
                    running: true,
                    tun_required: false,
                    tun_attached: false,
                    magic_dns_enabled: false,
                    need_exit_node: false,
                    error_message: None,
                    my_node_info: None,
                    events: vec![],
                    routes: vec![],
                    peers: vec![],
                },
                RuntimeInstanceState {
                    config_id: "ec7b6a3c-aeae-4c0e-844e-f7ec2dbdc2ce".to_string(),
                    instance_id: "ec7b6a3c-aeae-4c0e-844e-f7ec2dbdc2ce".to_string(),
                    display_name: "ec7b6a3c-aeae-4c0e-844e-f7ec2dbdc2ce".to_string(),
                    running: true,
                    tun_required: false,
                    tun_attached: false,
                    magic_dns_enabled: false,
                    need_exit_node: false,
                    error_message: None,
                    my_node_info: None,
                    events: vec![],
                    routes: vec![],
                    peers: vec![],
                },
            ],
            tun: runtime::state::runtime_state::TunAggregateState {
                active: false,
                attached_instance_ids: vec![],
                aggregated_routes: vec![],
                dns_servers: vec![],
                need_rebuild: false,
            },
            running_instance_count: 2,
        }
    }

    fn pro_test_registry() -> HashMap<String, String> {
        HashMap::from([(
            "0c4b33ba-4ed5-42d8-9095-21b786c66e94".to_string(),
            "office-network".to_string(),
        )])
    }

    #[test]
    fn pro_instance_list_uses_registry_network_name_and_excludes_untracked_instances() {
        assert_eq!(
            list_pro_instances_json_inner(&pro_test_state(), &pro_test_registry()),
            r#"{"office-network":"0c4b33ba-4ed5-42d8-9095-21b786c66e94"}"#,
        );
    }

    #[test]
    fn pro_json_rpc_selects_instance_by_network_name_and_labels_traffic() {
        let response = call_pro_json_rpc_inner(
            &pro_test_state(),
            &pro_test_registry(),
            "api.instance.StatsRpcService",
            "get_stats",
            r#"{"instance":{"instance_selector":{"name":"office-network"}}}"#,
        );
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            response["metrics"][0]["labels"]["network_name"],
            "office-network",
        );
    }

    #[test]
    fn resolve_instance_id_does_not_fall_back_for_unknown_selector() {
        let state = pro_test_state();
        assert_eq!(
            resolve_instance_id_from_state(&state, "0c4b33ba-4ed5-42d8-9095-21b786c66e94"),
            Some("0c4b33ba-4ed5-42d8-9095-21b786c66e94".to_string()),
        );
        assert_eq!(resolve_instance_id_from_state(&state, "stale-name"), None);
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
