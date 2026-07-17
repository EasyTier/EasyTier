use std::{
    cell::Cell,
    collections::HashSet,
    ffi::{CString, c_char, c_int, c_void},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use easytier::{
    common::{
        MachineIdOptions,
        config::{ConfigLoader as _, TomlConfigLoader},
    },
    tunnel::TunnelScheme,
    web_client::{WebClient, WebClientHooks, run_web_client},
};
use uuid::Uuid;

use crate::{
    data_plane::remove_data_plane_handles_by_instance_ids,
    error::set_error_msg,
    state::{
        ASYNC_RUNTIME, INSTANCE_MANAGER, INSTANCE_MUTATION_LOCK, INSTANCE_NAME_ID_MAP,
        lock_remote_instance_mutation, remove_instance_name_ids,
    },
    strings::{c_str_to_string, optional_c_str_to_string},
    types::ConfigServerEventCallback,
};

thread_local! {
    static IN_CONFIG_SERVER_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

static CONFIG_SERVER_CLIENT: once_cell::sync::Lazy<Mutex<Option<ManagedConfigServerClient>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));
static CONFIG_SERVER_CLIENT_ACTIVE: once_cell::sync::Lazy<AtomicBool> =
    once_cell::sync::Lazy::new(|| AtomicBool::new(false));
static CONFIG_SERVER_CLIENT_STOPPING: once_cell::sync::Lazy<AtomicBool> =
    once_cell::sync::Lazy::new(|| AtomicBool::new(false));
static LAST_CONFIG_SERVER_CALLBACK_ERROR: once_cell::sync::Lazy<Mutex<Option<String>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

pub(crate) struct ConfigServerCallbackScope;

impl ConfigServerCallbackScope {
    pub(crate) fn enter() -> Self {
        IN_CONFIG_SERVER_CALLBACK.with(|in_callback| in_callback.set(true));
        Self
    }
}

impl Drop for ConfigServerCallbackScope {
    fn drop(&mut self) {
        IN_CONFIG_SERVER_CALLBACK.with(|in_callback| in_callback.set(false));
    }
}

pub fn in_config_server_callback() -> bool {
    IN_CONFIG_SERVER_CALLBACK.with(Cell::get)
}

fn config_server_machine_id_options(machine_id: String) -> MachineIdOptions {
    MachineIdOptions {
        explicit_machine_id: Some(machine_id),
        state_dir: None,
    }
}

pub fn validate_config_server_client_options(
    config_server_url_s: &str,
    machine_id: &str,
) -> Result<(), String> {
    if machine_id.trim().is_empty() {
        return Err("machine_id is empty".to_string());
    }

    let config_server_url = match url::Url::parse(config_server_url_s) {
        Ok(url) => url,
        Err(_) => format!(
            "udp://config-server.easytier.cn:22020/{}",
            config_server_url_s
        )
        .parse()
        .map_err(|err| format!("failed to parse config server URL: {}", err))?,
    };

    TunnelScheme::try_from(&config_server_url).map_err(|_| {
        format!(
            "unsupported config server scheme: {}",
            config_server_url.scheme()
        )
    })?;

    let token = config_server_url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .map(|segment| percent_encoding::percent_decode_str(segment).decode_utf8())
        .transpose()
        .map_err(|err| format!("failed to decode config server token: {}", err))?
        .map(|token| token.to_string())
        .unwrap_or_default();

    if token.is_empty() {
        return Err("empty token".to_string());
    }

    Ok(())
}

struct ManagedConfigServerClient {
    client: WebClient,
    hooks: Arc<ManagedConfigServerClientHooks>,
}

pub(crate) struct ManagedConfigServerClientHooks {
    pub(crate) instance_ids: Mutex<HashSet<Uuid>>,
    callback_delivery: Mutex<()>,
    stopping: AtomicBool,
    callback: ConfigServerEventCallback,
    user_data: usize,
}

impl ManagedConfigServerClientHooks {
    pub(crate) fn new(callback: ConfigServerEventCallback, user_data: *mut c_void) -> Self {
        Self {
            instance_ids: Mutex::new(HashSet::new()),
            callback_delivery: Mutex::new(()),
            stopping: AtomicBool::new(false),
            callback,
            user_data: user_data as usize,
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked_instance_ids(&self) -> Vec<Uuid> {
        self.instance_ids
            .lock()
            .map(|guard| guard.iter().copied().collect())
            .unwrap_or_default()
    }

    fn remove_tracked_instance_ids(&self, ids: &[Uuid]) -> Result<Vec<Uuid>, String> {
        let mut guard = self.instance_ids.lock().map_err(|err| err.to_string())?;
        Ok(ids
            .iter()
            .filter_map(|id| guard.remove(id).then_some(*id))
            .collect())
    }

    fn validate_instance_name(&self, inst_name: &str, inst_id: Uuid) -> Result<(), String> {
        if let Some(existing_id) = INSTANCE_NAME_ID_MAP.get(inst_name).map(|id| *id)
            && existing_id != inst_id
        {
            return Err(format!("instance name {} already exists", inst_name));
        }

        Ok(())
    }

    fn commit_instance_name(&self, inst_name: String, inst_id: Uuid) -> Result<(), String> {
        INSTANCE_NAME_ID_MAP.retain(|_, existing_id| *existing_id != inst_id);
        self.validate_instance_name(&inst_name, inst_id)?;
        INSTANCE_NAME_ID_MAP.insert(inst_name, inst_id);
        Ok(())
    }

    pub(crate) fn start_stopping(&self) -> Vec<Uuid> {
        let _delivery_guard = if in_config_server_callback() {
            None
        } else {
            self.callback_delivery.lock().ok()
        };
        let mut guard = match self.instance_ids.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        self.stopping.store(true, Ordering::Release);
        guard.drain().collect()
    }

    pub(crate) fn note_callback_error(&self, error: String) {
        log::warn!("config server event callback failed: {}", error);
        if let Ok(mut guard) = LAST_CONFIG_SERVER_CALLBACK_ERROR.lock() {
            *guard = Some(error);
        }
    }

    fn emit_event_with_delivery_locked(
        &self,
        event: &str,
        instance_id: Uuid,
    ) -> Result<(), String> {
        if self.stopping.load(Ordering::Acquire) {
            return Ok(());
        }

        let Some(callback) = self.callback else {
            return Ok(());
        };
        let instance_name = INSTANCE_MANAGER
            .get_instance_name(&instance_id)
            .unwrap_or_default();
        let network_name = INSTANCE_MANAGER
            .get_network_name(&instance_id)
            .unwrap_or_default();
        let event_json = serde_json::json!({
            "event": event,
            "success": true,
            "instance_id": instance_id.to_string(),
            "instance_name": instance_name,
            "network_name": network_name,
            "error": null,
        })
        .to_string();
        let event_json = CString::new(event_json).map_err(|err| err.to_string())?;
        let _callback_scope = ConfigServerCallbackScope::enter();
        unsafe {
            callback(event_json.as_ptr(), self.user_data as *mut c_void);
        }
        Ok(())
    }

    fn emit_event(&self, event: &str, instance_id: Uuid) -> Result<(), String> {
        let _delivery_guard = self
            .callback_delivery
            .lock()
            .map_err(|err| err.to_string())?;
        self.emit_event_with_delivery_locked(event, instance_id)
    }

    fn wait_for_callback_delivery(&self) {
        if in_config_server_callback() {
            return;
        }

        if let Ok(guard) = self.callback_delivery.lock() {
            drop(guard);
        }
    }
}

#[async_trait::async_trait]
impl WebClientHooks for ManagedConfigServerClientHooks {
    fn manages_remote_config_instances(&self) -> bool {
        true
    }

    async fn pre_run_network_instance(&self, cfg: &TomlConfigLoader) -> Result<(), String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("config server client is stopping".to_string());
        }

        let inst_name = cfg.get_inst_name();
        let inst_id = cfg.get_id();

        self.validate_instance_name(&inst_name, inst_id)
    }

    async fn post_run_network_instance(&self, id: &Uuid) -> Result<(), String> {
        let _delivery_guard = self
            .callback_delivery
            .lock()
            .map_err(|err| err.to_string())?;
        let Some(inst_name) = INSTANCE_MANAGER.get_instance_name(id) else {
            if !self.stopping.load(Ordering::Acquire) {
                return Err(format!("instance {} not found after start", id));
            }
            return Ok(());
        };

        {
            let _mutation_guard = INSTANCE_MUTATION_LOCK
                .lock()
                .map_err(|err| err.to_string())?;
            if INSTANCE_MANAGER.get_instance_name(id).is_none() {
                if !self.stopping.load(Ordering::Acquire) {
                    return Err(format!("instance {} not found after start", id));
                }
                return Ok(());
            }

            let should_delete = {
                let mut guard = self.instance_ids.lock().map_err(|err| err.to_string())?;
                if self.stopping.load(Ordering::Acquire) {
                    true
                } else {
                    guard.insert(*id);
                    false
                }
            };

            if should_delete {
                if let Err(err) = INSTANCE_MANAGER.delete_network_instance(vec![*id]) {
                    return Err(err.to_string());
                }
                remove_instance_name_ids(&[*id]);
                return Ok(());
            }

            if self.stopping.load(Ordering::Acquire) {
                self.remove_tracked_instance_ids(&[*id])?;
                remove_instance_name_ids(&[*id]);
                return Ok(());
            }

            if let Err(err) = self.commit_instance_name(inst_name.clone(), *id) {
                self.remove_tracked_instance_ids(&[*id])?;
                if let Err(delete_err) = INSTANCE_MANAGER.delete_network_instance(vec![*id]) {
                    return Err(format!(
                        "{}; failed to delete duplicate instance: {}",
                        err, delete_err
                    ));
                }
                return Err(err);
            }

            if self.stopping.load(Ordering::Acquire) {
                self.remove_tracked_instance_ids(&[*id])?;
                remove_instance_name_ids(&[*id]);
                return Ok(());
            }
            if INSTANCE_MANAGER.get_instance_name(id).is_none() {
                self.remove_tracked_instance_ids(&[*id])?;
                remove_instance_name_ids(&[*id]);
                return Err(format!(
                    "instance {} was removed before post-run completed",
                    id
                ));
            }
        }

        remove_data_plane_handles_by_instance_ids(&[*id]);

        if let Err(err) = self.emit_event_with_delivery_locked("run_network_instance", *id) {
            self.note_callback_error(err);
        }
        Ok(())
    }

    async fn post_remove_network_instances(&self, ids: &[Uuid]) -> Result<(), String> {
        let removed_ids = {
            let _mutation_guard = INSTANCE_MUTATION_LOCK
                .lock()
                .map_err(|err| err.to_string())?;
            let removed_ids = self.remove_tracked_instance_ids(ids)?;
            remove_instance_name_ids(ids);
            remove_data_plane_handles_by_instance_ids(&removed_ids);
            removed_ids
        };

        for id in removed_ids {
            if let Err(err) = self.emit_event("delete_network_instance", id) {
                self.note_callback_error(err);
            }
        }
        Ok(())
    }
}

pub(crate) fn remove_config_server_tracked_instance_ids(ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }

    if let Ok(guard) = CONFIG_SERVER_CLIENT.lock()
        && let Some(managed) = guard.as_ref()
        && let Err(err) = managed.hooks.remove_tracked_instance_ids(ids)
    {
        log::warn!("failed to remove config server tracked ids: {}", err);
    }
}

pub(crate) fn wait_for_config_server_delivery() {
    let hooks = CONFIG_SERVER_CLIENT
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|managed| managed.hooks.clone()));
    if let Some(hooks) = hooks {
        hooks.wait_for_callback_delivery();
    }
}

pub(crate) fn last_callback_error() -> Option<String> {
    LAST_CONFIG_SERVER_CALLBACK_ERROR
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

pub(crate) fn clear_last_callback_error() {
    if let Ok(mut guard) = LAST_CONFIG_SERVER_CALLBACK_ERROR.lock() {
        *guard = None;
    }
}

#[cfg(feature = "ffi-dataplane")]
pub(crate) fn is_config_server_active_or_stopping() -> bool {
    CONFIG_SERVER_CLIENT_ACTIVE.load(Ordering::Acquire)
        || CONFIG_SERVER_CLIENT_STOPPING.load(Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn set_active_for_test(active: bool) {
    CONFIG_SERVER_CLIENT_ACTIVE.store(active, Ordering::Release);
}

/// # Safety
/// Start the config server client.
///
/// `config_server_url` must be a valid null-terminated UTF-8 string.
/// `hostname` may be null; if non-null it must be a valid null-terminated UTF-8 string.
/// `machine_id` must be a valid null-terminated UTF-8 string.
/// `event_json` passed to `callback` is valid only during that callback invocation.
pub(crate) unsafe fn start_config_server_client(
    config_server_url: *const c_char,
    hostname: *const c_char,
    machine_id: *const c_char,
    secure_mode: bool,
    callback: ConfigServerEventCallback,
    user_data: *mut c_void,
) -> c_int {
    if in_config_server_callback() {
        set_error_msg("cannot start config server client from config server callback");
        return -1;
    }

    let config_server_url = match unsafe { c_str_to_string(config_server_url, "config_server_url") }
    {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let hostname = match unsafe { optional_c_str_to_string(hostname, "hostname") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let machine_id = match unsafe { c_str_to_string(machine_id, "machine_id") } {
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
        Ok(value) => value,
    };
    if let Err(err) = validate_config_server_client_options(&config_server_url, &machine_id) {
        set_error_msg(&err);
        return -1;
    }

    let mut guard = match CONFIG_SERVER_CLIENT.lock() {
        Ok(guard) => guard,
        Err(err) => {
            set_error_msg(&format!("failed to lock config server client: {}", err));
            return -1;
        }
    };

    if guard.is_some() {
        set_error_msg("config server client already exists");
        return -1;
    }
    if CONFIG_SERVER_CLIENT_STOPPING.load(Ordering::Acquire) {
        set_error_msg("config server client is stopping");
        return -1;
    }
    clear_last_callback_error();

    #[cfg(feature = "ffi-dataplane")]
    let data_plane_usage_guard = match crate::data_plane::lock_for_config_server_start() {
        Ok(guard) => guard,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };

    CONFIG_SERVER_CLIENT_ACTIVE.store(true, Ordering::Release);
    #[cfg(feature = "ffi-dataplane")]
    drop(data_plane_usage_guard);

    let hooks = Arc::new(ManagedConfigServerClientHooks::new(callback, user_data));
    let client = match ASYNC_RUNTIME.block_on(run_web_client(
        &config_server_url,
        config_server_machine_id_options(machine_id),
        hostname,
        secure_mode,
        INSTANCE_MANAGER.clone(),
        Some(hooks.clone()),
    )) {
        Ok(client) => client,
        Err(err) => {
            CONFIG_SERVER_CLIENT_ACTIVE.store(false, Ordering::Release);
            set_error_msg(&format!("failed to start config server client: {}", err));
            return -1;
        }
    };

    *guard = Some(ManagedConfigServerClient { client, hooks });
    0
}

pub(crate) fn stop_config_server_client() -> c_int {
    if in_config_server_callback() {
        set_error_msg("cannot stop config server client from config server callback");
        return -1;
    }

    let mut guard = match CONFIG_SERVER_CLIENT.lock() {
        Ok(guard) => guard,
        Err(err) => {
            set_error_msg(&format!("failed to lock config server client: {}", err));
            return -1;
        }
    };

    let Some(managed) = guard.as_ref() else {
        CONFIG_SERVER_CLIENT_ACTIVE.store(false, Ordering::Release);
        return 0;
    };
    if CONFIG_SERVER_CLIENT_STOPPING.swap(true, Ordering::AcqRel) {
        set_error_msg("config server client is stopping");
        return -1;
    }
    let hooks = managed.hooks.clone();
    let managed = guard.take().expect("config server client exists");
    drop(guard);

    let _remote_mutation_guard = lock_remote_instance_mutation();
    let tracked_ids = hooks.start_stopping();
    drop(managed);

    let _mutation_guard = match INSTANCE_MUTATION_LOCK.lock() {
        Ok(guard) => guard,
        Err(err) => {
            hooks.wait_for_callback_delivery();
            CONFIG_SERVER_CLIENT_ACTIVE.store(false, Ordering::Release);
            CONFIG_SERVER_CLIENT_STOPPING.store(false, Ordering::Release);
            set_error_msg(&format!("failed to lock instance mutation: {}", err));
            return -1;
        }
    };
    let delete_result = INSTANCE_MANAGER.delete_network_instance(tracked_ids.clone());
    if delete_result.is_ok() {
        remove_instance_name_ids(&tracked_ids);
        remove_data_plane_handles_by_instance_ids(&tracked_ids);
    }
    drop(_mutation_guard);
    hooks.wait_for_callback_delivery();
    CONFIG_SERVER_CLIENT_ACTIVE.store(false, Ordering::Release);
    CONFIG_SERVER_CLIENT_STOPPING.store(false, Ordering::Release);

    if let Err(err) = delete_result {
        set_error_msg(&format!(
            "failed to delete config server instances: {}",
            err
        ));
        return -1;
    }
    0
}

pub(crate) fn is_config_server_client_connected() -> c_int {
    CONFIG_SERVER_CLIENT
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|managed| managed.client.is_connected()))
        .map(i32::from)
        .unwrap_or(0)
}
