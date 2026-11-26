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
use easytier::common::config::ConfigLoader;
use easytier::common::constants::EASYTIER_VERSION;
use easytier::common::{MachineIdOptions, resolve_machine_id};
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
    fn manages_remote_config_instances(&self) -> bool {
        true
    }

    async fn post_run_network_instance(&self, id: &Uuid) -> Result<(), String> {
        // Clear any stale TUN / packet-plane DNS bindings for the same instance id
        // so overwrite=true replacements re-attach cleanly to the new CoreInstance.
        runtime::state::clear_tun_attached(&id.to_string());
        local_dns::unregister_instance_packet_dns(*id).await;

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
        ohrs_log_info!(
            "[Rust] web_client started remote instance id={} network={:?} tun_enabled={}",
            id,
            network_name,
            tun_enabled
        );
        Ok(())
    }

    async fn post_remove_network_instances(&self, ids: &[Uuid]) -> Result<(), String> {
        {
            let mut guard = self.instance_ids.lock().map_err(|err| err.to_string())?;
            let mut events = self.events.lock().map_err(|err| err.to_string())?;
            let mut network_names_by_instance_id = self
                .network_names_by_instance_id
                .lock()
                .map_err(|err| err.to_string())?;
            for id in ids {
                guard.remove(id);
                runtime::state::clear_tun_attached(&id.to_string());
                let network_name = network_names_by_instance_id.remove(id);
                events.push(serde_json::json!({
                    "event": "delete_network_instance",
                    "success": true,
                    "instance_id": id.to_string(),
                    "instance_name": id.to_string(),
                    "network_name": network_name,
                }));
            }
        }
        for id in ids {
            local_dns::unregister_instance_packet_dns(*id).await;
        }
        let _ = local_dns::refresh_all_async().await;
        tun_watcher::bump_policy_revision();
        ohrs_log_info!("[Rust] web_client removed {} remote instance(s)", ids.len());
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

    for id in &tracked_ids {
        runtime::state::clear_tun_attached(&id.to_string());
    }

    let ok = ASYNC_RUNTIME
        .block_on(INSTANCE_MANAGER.delete_network_instances(tracked_ids.clone()))
        .map(|_| true)
        .unwrap_or_else(|err| {
            ohrs_log_error!(
                "[Rust] stop config server instances failed {}: {}",
                config_id,
                err
            );
            false
        });
    ASYNC_RUNTIME.block_on(async {
        for id in tracked_ids {
            local_dns::unregister_instance_packet_dns(id).await;
        }
        let _ = local_dns::refresh_all_async().await;
    });
    ok
}

fn web_client_machine_id_options(explicit_machine_id: Option<String>) -> MachineIdOptions {
    MachineIdOptions {
        explicit_machine_id: explicit_machine_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        state_dir: runtime::get_state_dir(),
    }
}

fn run_config_server_instance(config_id: &str, config: &NetworkConfig) -> bool {
    if WEB_CLIENTS
        .lock()
        .ok()
        .is_some_and(|guard| guard.contains_key(config_id))
    {
        ohrs_log_error!("[Rust] config server instance {} already exists", config_id);
        return false;
    }

    let Some(config_server_url) = config
        .public_server_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
    else {
        ohrs_log_error!("[Rust] public_server_url missing for config server mode");
        return false;
    };
    let hooks = Arc::new(TrackedWebClientHooks::default());
    let secure_mode = config
        .secure_mode
        .as_ref()
        .map(|mode| mode.enabled)
        .unwrap_or(false);
    let hostname = config
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let machine_id_opts = web_client_machine_id_options(None);

    let client = ASYNC_RUNTIME.block_on(run_web_client(
        config_server_url,
        machine_id_opts.clone(),
        hostname.clone(),
        secure_mode,
        INSTANCE_MANAGER.clone(),
        Some(hooks.clone()),
    ));

    let client = match client {
        Ok(client) => client,
        Err(err) => {
            ohrs_log_error!(
                "[Rust] start config server failed (state_dir={:?}): {:#}",
                machine_id_opts.state_dir,
                err
            );
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
            ohrs_log_info!(
                "[Rust] started web_client config_id={} secure_mode={} has_hostname={}",
                config_id,
                secure_mode,
                hostname.is_some()
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

    let machine_id_opts = web_client_machine_id_options(machine_id);
    let client = ASYNC_RUNTIME.block_on(run_web_client(
        trimmed_url,
        machine_id_opts.clone(),
        hostname.filter(|value| !value.trim().is_empty()),
        secure_mode,
        INSTANCE_MANAGER.clone(),
        Some(hooks.clone()),
    ));

    let client = match client {
        Ok(client) => client,
        Err(err) => {
            ohrs_log_error!(
                "[Rust] start pro config server client failed (state_dir={:?}): {:#}",
                machine_id_opts.state_dir,
                err
            );
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
    runtime::state::clear_all_tun_attached();
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

#[cfg_attr(not(test), napi)]
pub fn set_state_dir(state_dir: String) -> bool {
    let trimmed = state_dir.trim();
    if trimmed.is_empty() {
        return false;
    }
    runtime::set_state_dir(std::path::PathBuf::from(trimmed))
}

#[cfg_attr(not(test), napi)]
pub fn get_machine_id() -> Option<String> {
    let opts = web_client_machine_id_options(None);
    resolve_machine_id(&opts).ok().map(|id| id.to_string())
}

pub(crate) fn collect_runtime_state_inner() -> RuntimeAggregateState {
    exports::runtime_api::collect_runtime_state()
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier::proto::api::manage::{
        DeleteNetworkInstanceRequest, RunNetworkInstanceRequest, WebClientService,
        WebClientServiceClientFactory,
    };
    use easytier::proto::common::TunnelInfo;
    use easytier::proto::rpc_types::controller::BaseController;
    use easytier::proto::web::{
        GetFeatureRequest, GetFeatureResponse, HeartbeatRequest, HeartbeatResponse,
        WebServerService, WebServerServiceServer,
    };
    use easytier_core::rpc::bidirect::BidirectRpcManager;
    use easytier_core::socket::tcp::VirtualTcpSocket;
    use easytier_core::tunnel::tcp::TcpTunnelUpgrader;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;

    struct TestTcpSocket(TcpStream);

    impl AsyncRead for TestTcpSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestTcpSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl VirtualTcpSocket for TestTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.0.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.0.peer_addr()
        }
    }

    #[derive(Clone, Default)]
    struct MockWebServer {
        last_heartbeat: Arc<Mutex<Option<HeartbeatRequest>>>,
        heartbeat_notify: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl WebServerService for MockWebServer {
        type Controller = BaseController;

        async fn heartbeat(
            &self,
            _: BaseController,
            req: HeartbeatRequest,
        ) -> easytier::proto::rpc_types::error::Result<HeartbeatResponse> {
            if let Ok(mut guard) = self.last_heartbeat.lock() {
                *guard = Some(req);
            }
            self.heartbeat_notify.notify_waiters();
            Ok(HeartbeatResponse::default())
        }

        async fn get_feature(
            &self,
            _: BaseController,
            _: GetFeatureRequest,
        ) -> easytier::proto::rpc_types::error::Result<GetFeatureResponse> {
            Ok(GetFeatureResponse {
                support_encryption: false,
            })
        }
    }

    #[test]
    fn web_client_resolves_and_persists_machine_id_in_state_dir() {
        let _ = stop_runtime_inner();
        let temp_root =
            std::env::temp_dir().join(format!("easytier-ohrs-machine-id-test-{}", Uuid::new_v4()));
        let state_dir = temp_root.join("easytier-state");
        assert!(set_state_dir(state_dir.to_string_lossy().into_owned()));

        let first = get_machine_id().expect("machine id should resolve inside state_dir");
        let second = get_machine_id().expect("machine id should stay stable across reads");
        assert_eq!(first, second);
        assert!(state_dir.join("machine_id").is_file());

        let config_id = Uuid::new_v4().to_string();
        let config = NetworkConfig {
            instance_id: Some(config_id.clone()),
            networking_method: Some(NetworkingMethod::PublicServer as i32),
            public_server_url: Some(format!("ring://{}/test-token", Uuid::new_v4())),
            hostname: Some("ohos-test".to_string()),
            ..Default::default()
        };
        assert!(run_config_server_instance(&config_id, &config));
        assert!(stop_web_client(&config_id));

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn web_client_receives_console_pushed_config_without_shell_pollution() {
        let _ = stop_runtime_inner();
        let temp_root =
            std::env::temp_dir().join(format!("easytier-ohrs-webclient-e2e-{}", Uuid::new_v4()));
        let state_dir = temp_root.join("easytier-state");
        assert!(set_state_dir(state_dir.to_string_lossy().into_owned()));

        let mock_server = MockWebServer::default();
        let (addr, server_rpc_slot) = ASYNC_RUNTIME.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock config server");
            let addr = listener.local_addr().expect("local addr");
            let server_rpc_slot: Arc<tokio::sync::Mutex<Option<Arc<BidirectRpcManager>>>> =
                Arc::new(tokio::sync::Mutex::new(None));
            let slot_clone = server_rpc_slot.clone();
            let svc = mock_server.clone();
            tokio::spawn(async move {
                if let Ok((stream, _peer)) = listener.accept().await {
                    let tunnel = TcpTunnelUpgrader::new(TunnelInfo::default())
                        .upgrade(TestTcpSocket(stream))
                        .expect("upgrade tcp tunnel");
                    let rpc = Arc::new(BidirectRpcManager::new());
                    rpc.rpc_server()
                        .registry()
                        .register(WebServerServiceServer::new(svc), "");
                    rpc.run_with_tunnel(tunnel);
                    *slot_clone.lock().await = Some(rpc);
                }
            });
            (addr, server_rpc_slot)
        });

        let shell_config_id = Uuid::new_v4().to_string();
        // Mirrors ArkTS ConfigDefaults.ts + DynamicFieldEditor.ets ("PublicServer" string enum,
        // dirty default virtual_ipv4="10.0.0.1", dhcp=true, empty hostname="").
        let shell_json = serde_json::json!({
            "instance_id": shell_config_id,
            "networking_method": "PublicServer",
            "public_server_url": format!("tcp://{addr}/test-token"),
            "dhcp": true,
            "virtual_ipv4": "10.0.0.1",
            "network_length": 24,
            "hostname": "",
            "network_name": "easytier",
            "enable_magic_dns": true
        })
        .to_string();
        assert!(run_network_instance_from_json(
            &shell_json,
            Some("WebConsole".to_string())
        ));

        // Wait for the client to connect and send its first heartbeat.
        let hb = ASYNC_RUNTIME.block_on(async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(hb) = mock_server
                    .last_heartbeat
                    .lock()
                    .ok()
                    .and_then(|g| g.clone())
                {
                    break hb;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for web client heartbeat"
                );
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    mock_server.heartbeat_notify.notified(),
                )
                .await;
            }
        });
        assert_eq!(hb.user_token, "test-token");
        assert!(
            !hb.hostname.trim().is_empty(),
            "empty hostname must fall back to OS hostname"
        );
        assert_eq!(hb.support_dns_config_patch, Some(true));

        // Before console pushes any network, the shell must NEVER expose fake 10.0.0.1 or fake peers.
        let initial_state = collect_runtime_state_inner();
        assert_eq!(initial_state.instances.len(), 1);
        let shell_state = &initial_state.instances[0];
        assert_eq!(shell_state.config_id, shell_config_id);
        assert_eq!(shell_state.config_server_connected, Some(true));
        assert!(shell_state.my_node_info.is_none());
        assert!(shell_state.routes.is_empty());
        assert!(shell_state.peers.is_empty());
        assert!(shell_state.manual_routes.is_empty());
        assert!(!shell_state.tun_required);
        assert!(initial_state.tun.aggregated_routes.is_empty());

        // Console pushes a real network instance over reverse RPC.
        let pushed_id = Uuid::new_v4();
        let rpc = ASYNC_RUNTIME
            .block_on(async { server_rpc_slot.lock().await.clone() })
            .expect("server rpc handle");
        let client = rpc
            .rpc_client()
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(1, 1, String::new());

        let pushed_cfg = NetworkConfig {
            instance_id: Some(pushed_id.to_string()),
            networking_method: Some(NetworkingMethod::Standalone as i32),
            dhcp: Some(false),
            virtual_ipv4: Some("10.77.88.2".to_string()),
            network_length: Some(24),
            hostname: Some("ohos-pushed".to_string()),
            network_name: Some("corp-mesh".to_string()),
            network_secret: Some("secret-1".to_string()),
            enable_manual_routes: Some(true),
            routes: vec!["192.168.99.0/24".to_string()],
            enable_magic_dns: Some(true),
            no_tun: Some(true),
            listener_urls: vec![],
            ..Default::default()
        };
        let run_resp = ASYNC_RUNTIME
            .block_on(client.run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: Some(pushed_id.into()),
                    config: Some(pushed_cfg.clone()),
                    overwrite: true,
                    source: easytier::proto::api::manage::ConfigSource::Web as i32,
                },
            ))
            .expect("console RunNetworkInstance should succeed");
        assert_eq!(run_resp.inst_id.map(Uuid::from), Some(pushed_id));

        let wait_for_pushed_ip = |expected_ip: &str| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let state = collect_runtime_state_inner();
                assert!(
                    state.instances.iter().all(|inst| {
                        inst.my_node_info
                            .as_ref()
                            .and_then(|n| n.virtual_ipv4.as_deref())
                            != Some("10.0.0.1")
                    }),
                    "shell default IP 10.0.0.1 must never leak into runtime state"
                );
                if let Some(inst) = state
                    .instances
                    .iter()
                    .find(|inst| inst.instance_id == pushed_id.to_string())
                    && inst
                        .my_node_info
                        .as_ref()
                        .and_then(|n| n.virtual_ipv4.as_deref())
                        == Some(expected_ip)
                {
                    return state;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for pushed instance virtual_ipv4={expected_ip}"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        };

        let after_push = wait_for_pushed_ip("10.77.88.2");
        let pushed_state = after_push
            .instances
            .iter()
            .find(|inst| inst.instance_id == pushed_id.to_string())
            .expect("pushed instance should be present in collect_runtime_state");
        assert_eq!(pushed_state.display_name, "corp-mesh");
        assert!(pushed_state.config_server_connected.is_none());
        assert_eq!(
            pushed_state.manual_routes,
            vec!["192.168.99.0/24".to_string()]
        );
        assert!(pushed_state.magic_dns_enabled);

        // Console overwrites the same instance id with a new virtual IP.
        let mut updated_cfg = pushed_cfg;
        updated_cfg.virtual_ipv4 = Some("10.77.88.9".to_string());
        ASYNC_RUNTIME
            .block_on(client.run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: Some(pushed_id.into()),
                    config: Some(updated_cfg),
                    overwrite: true,
                    source: easytier::proto::api::manage::ConfigSource::Web as i32,
                },
            ))
            .expect("console overwrite RunNetworkInstance should succeed");
        let after_overwrite = wait_for_pushed_ip("10.77.88.9");
        let overwritten_state = after_overwrite
            .instances
            .iter()
            .find(|inst| inst.instance_id == pushed_id.to_string())
            .expect("overwritten instance should remain present");
        assert_eq!(
            overwritten_state
                .my_node_info
                .as_ref()
                .and_then(|n| n.virtual_ipv4.as_deref()),
            Some("10.77.88.9")
        );

        // Console deletes the pushed instance.
        ASYNC_RUNTIME
            .block_on(client.delete_network_instance(
                BaseController::default(),
                DeleteNetworkInstanceRequest {
                    inst_ids: vec![pushed_id.into()],
                },
            ))
            .expect("console DeleteNetworkInstance should succeed");
        let after_delete = collect_runtime_state_inner();
        assert_eq!(after_delete.instances.len(), 1);
        assert_eq!(after_delete.instances[0].config_id, shell_config_id);

        // Stopping the config-server shell tears down cleanly.
        assert!(exports::runtime_api::stop_kernel(
            shell_config_id,
            stop_web_client,
            parse_instance_uuid,
        ));
        assert!(collect_runtime_state_inner().instances.is_empty());

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn concurrent_local_instances_and_config_server_preserve_earlier_state() {
        let _ = stop_runtime_inner();
        let temp_root =
            std::env::temp_dir().join(format!("easytier-ohrs-multi-inst-test-{}", Uuid::new_v4()));
        let state_dir = temp_root.join("easytier-state");
        assert!(set_state_dir(state_dir.to_string_lossy().into_owned()));

        let id_a = Uuid::new_v4().to_string();
        let id_b = Uuid::new_v4().to_string();
        let cfg_a = serde_json::json!({
            "instance_id": id_a,
            "networking_method": "Manual",
            "dhcp": false,
            "virtual_ipv4": "10.66.1.2",
            "network_length": 24,
            "hostname": "node-a",
            "network_name": "mesh-a",
            "network_secret": "sec-a",
            "no_tun": true,
            "listener_urls": []
        })
        .to_string();
        let cfg_b = serde_json::json!({
            "instance_id": id_b,
            "networking_method": "Manual",
            "dhcp": false,
            "virtual_ipv4": "10.66.2.2",
            "network_length": 24,
            "hostname": "node-b",
            "network_name": "mesh-b",
            "network_secret": "sec-b",
            "no_tun": true,
            "listener_urls": []
        })
        .to_string();

        assert!(run_network_instance_from_json(
            &cfg_a,
            Some("First".to_string())
        ));
        assert!(run_network_instance_from_json(
            &cfg_b,
            Some("Second".to_string())
        ));
        // Duplicate start of an already-running id must fail without disturbing running instances.
        assert!(!run_network_instance_from_json(
            &cfg_a,
            Some("First".to_string())
        ));

        let wait_for_ips = |expected: &[(&str, &str)]| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let state = collect_runtime_state_inner();
                let all_ready = expected.iter().all(|(id, ip)| {
                    state.instances.iter().any(|inst| {
                        inst.instance_id == *id
                            && inst.running
                            && inst
                                .my_node_info
                                .as_ref()
                                .and_then(|n| n.virtual_ipv4.as_deref())
                                == Some(*ip)
                    })
                });
                if all_ready {
                    return state;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for concurrent instances: {:?}",
                    expected
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        };

        let both = wait_for_ips(&[(&id_a, "10.66.1.2"), (&id_b, "10.66.2.2")]);
        assert_eq!(both.running_instance_count, 2);
        let inst_a = both
            .instances
            .iter()
            .find(|i| i.instance_id == id_a)
            .expect("earlier instance A must remain present");
        assert_eq!(inst_a.display_name, "First");
        assert!(inst_a.config_server_id.is_none());

        // Start a config server alongside the two local instances and push a remote instance.
        let mock_server = MockWebServer::default();
        let (addr, server_rpc_slot) = ASYNC_RUNTIME.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock config server");
            let addr = listener.local_addr().expect("local addr");
            let server_rpc_slot: Arc<tokio::sync::Mutex<Option<Arc<BidirectRpcManager>>>> =
                Arc::new(tokio::sync::Mutex::new(None));
            let slot_clone = server_rpc_slot.clone();
            let svc = mock_server.clone();
            tokio::spawn(async move {
                if let Ok((stream, _peer)) = listener.accept().await {
                    let tunnel = TcpTunnelUpgrader::new(TunnelInfo::default())
                        .upgrade(TestTcpSocket(stream))
                        .expect("upgrade tcp tunnel");
                    let rpc = Arc::new(BidirectRpcManager::new());
                    rpc.rpc_server()
                        .registry()
                        .register(WebServerServiceServer::new(svc), "");
                    rpc.run_with_tunnel(tunnel);
                    *slot_clone.lock().await = Some(rpc);
                }
            });
            (addr, server_rpc_slot)
        });

        let shell_id = Uuid::new_v4().to_string();
        let shell_json = serde_json::json!({
            "instance_id": shell_id,
            "networking_method": "PublicServer",
            "public_server_url": format!("tcp://{addr}/multi-token"),
            "no_tun": true
        })
        .to_string();
        assert!(run_network_instance_from_json(
            &shell_json,
            Some("Console".to_string())
        ));

        ASYNC_RUNTIME.block_on(async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while mock_server
                .last_heartbeat
                .lock()
                .ok()
                .and_then(|g| g.clone())
                .is_none()
            {
                assert!(tokio::time::Instant::now() < deadline);
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    mock_server.heartbeat_notify.notified(),
                )
                .await;
            }
        });

        let pushed_id = Uuid::new_v4();
        let rpc = ASYNC_RUNTIME
            .block_on(async { server_rpc_slot.lock().await.clone() })
            .expect("server rpc handle");
        let client = rpc
            .rpc_client()
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(1, 1, String::new());
        let pushed_cfg = NetworkConfig {
            instance_id: Some(pushed_id.to_string()),
            networking_method: Some(NetworkingMethod::Standalone as i32),
            dhcp: Some(false),
            virtual_ipv4: Some("10.66.3.2".to_string()),
            network_length: Some(24),
            hostname: Some("remote-c".to_string()),
            network_name: Some("mesh-c".to_string()),
            network_secret: Some("sec-c".to_string()),
            no_tun: Some(true),
            listener_urls: vec![],
            ..Default::default()
        };
        ASYNC_RUNTIME
            .block_on(client.run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: Some(pushed_id.into()),
                    config: Some(pushed_cfg),
                    overwrite: true,
                    source: easytier::proto::api::manage::ConfigSource::Web as i32,
                },
            ))
            .expect("push remote instance");

        let pushed_id_str = pushed_id.to_string();
        let all_three = wait_for_ips(&[
            (&id_a, "10.66.1.2"),
            (&id_b, "10.66.2.2"),
            (&pushed_id_str, "10.66.3.2"),
        ]);
        let pushed_state = all_three
            .instances
            .iter()
            .find(|i| i.instance_id == pushed_id_str)
            .expect("pushed instance present");
        assert_eq!(
            pushed_state.config_server_id.as_deref(),
            Some(shell_id.as_str())
        );
        let local_a_state = all_three
            .instances
            .iter()
            .find(|i| i.instance_id == id_a)
            .expect("local instance A present");
        assert!(local_a_state.config_server_id.is_none());

        // Stopping only the config server removes only the shell + its pushed instance,
        // leaving earlier local instances A and B completely intact.
        assert!(exports::runtime_api::stop_kernel(
            shell_id,
            stop_web_client,
            parse_instance_uuid,
        ));
        let after_shell_stop = collect_runtime_state_inner();
        assert_eq!(after_shell_stop.running_instance_count, 2);
        assert!(
            after_shell_stop
                .instances
                .iter()
                .any(|i| i.instance_id == id_a)
        );
        assert!(
            after_shell_stop
                .instances
                .iter()
                .any(|i| i.instance_id == id_b)
        );

        // Stopping B leaves A intact.
        assert!(exports::runtime_api::stop_kernel(
            id_b,
            stop_web_client,
            parse_instance_uuid,
        ));
        let after_b_stop = collect_runtime_state_inner();
        assert_eq!(after_b_stop.running_instance_count, 1);
        assert_eq!(after_b_stop.instances[0].instance_id, id_a);
        assert_eq!(
            after_b_stop.instances[0]
                .my_node_info
                .as_ref()
                .and_then(|n| n.virtual_ipv4.as_deref()),
            Some("10.66.1.2")
        );

        assert!(stop_runtime_inner());
        let _ = std::fs::remove_dir_all(&temp_root);
    }
}
