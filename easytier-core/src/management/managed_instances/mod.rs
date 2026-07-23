use std::{
    marker::PhantomData,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use dashmap::DashMap;

#[cfg(feature = "proxy-smoltcp-stack")]
mod dataplane;
#[cfg(feature = "management")]
mod full;

use crate::{
    config::toml::TomlConfig,
    instance::{
        CoreInstance, CoreInstanceHost, CoreInstanceState,
        manager::{InstanceFactory, InstanceManager},
    },
    process_runtime::CoreProcessRuntime,
};

#[derive(Clone, Copy, Default)]
pub struct ConfigFilePermission(u8);

impl ConfigFilePermission {
    pub const READ_ONLY: u8 = 1 << 0;
    pub const NO_DELETE: u8 = 1 << 1;

    pub fn with_flag(self, flag: u8) -> Self {
        Self(self.0 | flag)
    }

    pub fn remove_flag(self, flag: u8) -> Self {
        Self(self.0 & !flag)
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

impl From<u8> for ConfigFilePermission {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<u32> for ConfigFilePermission {
    fn from(value: u32) -> Self {
        Self(value as u8)
    }
}

impl From<ConfigFilePermission> for u8 {
    fn from(value: ConfigFilePermission) -> Self {
        value.0
    }
}

impl From<ConfigFilePermission> for u32 {
    fn from(value: ConfigFilePermission) -> Self {
        value.0 as u32
    }
}

impl std::fmt::Debug for ConfigFilePermission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let access = if self.has_flag(Self::READ_ONLY) {
            "READ_ONLY"
        } else {
            "EDITABLE"
        };
        let deletion = if self.has_flag(Self::NO_DELETE) {
            "NO_DELETE"
        } else {
            "DELETABLE"
        };
        write!(formatter, "{access}|{deletion}")
    }
}

#[derive(Debug, Clone)]
pub struct ConfigFileControl {
    pub path: Option<PathBuf>,
    pub permission: ConfigFilePermission,
}

impl ConfigFileControl {
    pub const STATIC_CONFIG: Self = Self {
        path: None,
        permission: ConfigFilePermission(
            ConfigFilePermission::READ_ONLY | ConfigFilePermission::NO_DELETE,
        ),
    };

    pub fn new(path: Option<PathBuf>, permission: ConfigFilePermission) -> Self {
        Self { path, permission }
    }

    pub fn is_read_only(&self) -> bool {
        self.permission.has_flag(ConfigFilePermission::READ_ONLY)
    }

    pub fn set_read_only(&mut self, read_only: bool) {
        self.permission = if read_only {
            self.permission.with_flag(ConfigFilePermission::READ_ONLY)
        } else {
            self.permission.remove_flag(ConfigFilePermission::READ_ONLY)
        };
    }

    pub fn is_no_delete(&self) -> bool {
        self.permission.has_flag(ConfigFilePermission::NO_DELETE)
    }

    pub fn set_no_delete(&mut self, no_delete: bool) {
        self.permission = if no_delete {
            self.permission.with_flag(ConfigFilePermission::NO_DELETE)
        } else {
            self.permission.remove_flag(ConfigFilePermission::NO_DELETE)
        };
    }

    pub fn is_deletable(&self) -> bool {
        !self.is_no_delete()
    }
}

pub struct DaemonGuard {
    guard: Option<Arc<()>>,
    notifier: Arc<tokio::sync::Notify>,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        self.notifier.notify_one();
    }
}

struct ActiveStopGuard {
    active_stops: Arc<AtomicUsize>,
    notifier: Arc<tokio::sync::Notify>,
}

impl Drop for ActiveStopGuard {
    fn drop(&mut self) {
        let previous = self.active_stops.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        self.notifier.notify_one();
    }
}

/// Supplies the process runtime used by every instance created by this
/// factory.
pub trait ProcessRuntimeProvider: InstanceFactory {
    fn process_runtime(&self) -> Arc<CoreProcessRuntime>;
}

/// Process-level Instance operations over the canonical core Manager.
pub struct ManagedInstanceSet<F: InstanceFactory> {
    manager: Arc<InstanceManager<F>>,
    config_controls: DashMap<uuid::Uuid, ConfigFileControl>,
    notifier: Arc<tokio::sync::Notify>,
    config_dir: Option<PathBuf>,
    daemon_guard: Arc<()>,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
    process_runtime: Arc<CoreProcessRuntime>,
    runtime_handle: Option<tokio::runtime::Handle>,
    active_stops: Arc<AtomicUsize>,
    host: PhantomData<fn()>,
}

impl<F: InstanceFactory> ManagedInstanceSet<F> {
    pub fn new(factory: F, runtime_handle: Option<tokio::runtime::Handle>) -> Self
    where
        F: ProcessRuntimeProvider,
    {
        let process_runtime = factory.process_runtime();
        Self {
            manager: Arc::new(InstanceManager::new(factory)),
            config_controls: DashMap::new(),
            notifier: Arc::new(tokio::sync::Notify::new()),
            config_dir: None,
            daemon_guard: Arc::new(()),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            process_runtime,
            runtime_handle,
            active_stops: Arc::new(AtomicUsize::new(0)),
            host: PhantomData,
        }
    }

    pub fn with_config_path(mut self, config_dir: Option<PathBuf>) -> Self {
        self.config_dir = config_dir;
        self
    }

    pub fn manager(&self) -> Arc<InstanceManager<F>> {
        self.manager.clone()
    }

    pub fn mutation_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.mutation_lock.clone()
    }

    pub fn process_runtime(&self) -> Arc<CoreProcessRuntime> {
        self.process_runtime.clone()
    }

    pub fn config_dir(&self) -> Option<&PathBuf> {
        self.config_dir.as_ref()
    }

    pub fn register_daemon(&self) -> DaemonGuard {
        DaemonGuard {
            guard: Some(self.daemon_guard.clone()),
            notifier: self.notifier.clone(),
        }
    }
}

impl<F, H> ManagedInstanceSet<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn run_network_instance(
        &self,
        config: TomlConfig,
        _watch_event: bool,
        control: ConfigFileControl,
    ) -> anyhow::Result<uuid::Uuid> {
        let runtime = self
            .runtime_handle
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
            .ok_or_else(|| anyhow::anyhow!("tokio runtime not found, cannot start instance"))?;
        let instance = self
            .manager
            .create(config, ())
            .map_err(anyhow::Error::new)?;
        let instance_id = instance.instance_id();
        self.config_controls.insert(instance_id, control);
        let notifier = self.notifier.clone();
        runtime.spawn(async move {
            if let Err(error) = instance.start_managed().await {
                tracing::error!(%error, %instance_id, "instance failed to start");
            }
            notifier.notify_one();
        });
        Ok(instance_id)
    }

    pub async fn delete_network_instances(
        &self,
        instance_ids: impl IntoIterator<Item = uuid::Uuid>,
    ) -> anyhow::Result<Vec<uuid::Uuid>> {
        let runtime = self
            .runtime_handle
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
            .ok_or_else(|| anyhow::anyhow!("tokio runtime not found, cannot stop instance"))?;
        self.active_stops.fetch_add(1, Ordering::AcqRel);
        let active_stop = ActiveStopGuard {
            active_stops: self.active_stops.clone(),
            notifier: self.notifier.clone(),
        };
        let mut removed = Vec::new();
        for instance_id in instance_ids {
            self.config_controls.remove(&instance_id);
            if let Some(instance) = self.manager.remove(instance_id) {
                removed.push(instance);
            }
        }
        if removed.is_empty() {
            drop(active_stop);
            return Ok(self.instance_ids());
        }

        runtime
            .spawn(async move {
                let _active_stop = active_stop;
                for instance in removed {
                    instance.stop().await;
                }
            })
            .await
            .map_err(|error| anyhow::anyhow!("instance stop task failed: {error}"))?;
        Ok(self.instance_ids())
    }

    pub async fn delete_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> anyhow::Result<Vec<uuid::Uuid>> {
        self.delete_network_instances(instance_ids).await
    }

    pub async fn retain_network_instances(
        &self,
        retained: &[uuid::Uuid],
    ) -> anyhow::Result<Vec<uuid::Uuid>> {
        let removed = self
            .manager
            .list()
            .into_iter()
            .map(|instance| instance.instance_id())
            .filter(|instance_id| !retained.contains(instance_id))
            .collect::<Vec<_>>();
        self.delete_network_instances(removed).await
    }

    pub async fn retain_network_instance(
        &self,
        retained: Vec<uuid::Uuid>,
    ) -> anyhow::Result<Vec<uuid::Uuid>> {
        self.retain_network_instances(&retained).await
    }

    pub fn instance_ids(&self) -> Vec<uuid::Uuid> {
        self.manager
            .list()
            .into_iter()
            .map(|instance| instance.instance_id())
            .collect()
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instance_ids()
    }

    pub fn instance(&self, instance_id: uuid::Uuid) -> Option<Arc<CoreInstance<H>>> {
        self.manager.get(instance_id)
    }

    pub fn instances(&self) -> Vec<Arc<CoreInstance<H>>> {
        self.manager.list()
    }

    pub fn get_instance(&self, instance_id: &uuid::Uuid) -> Option<Arc<CoreInstance<H>>> {
        self.instance(*instance_id)
    }

    pub fn list_instances(&self) -> Vec<Arc<CoreInstance<H>>> {
        self.instances()
    }

    pub fn config_control(&self, instance_id: uuid::Uuid) -> Option<ConfigFileControl> {
        self.config_controls
            .get(&instance_id)
            .map(|control| control.clone())
    }

    pub fn get_instance_config_control(
        &self,
        instance_id: &uuid::Uuid,
    ) -> Option<ConfigFileControl> {
        self.config_control(*instance_id)
    }

    pub fn get_instance_name(&self, instance_id: &uuid::Uuid) -> Option<String> {
        self.instance(*instance_id)
            .map(|instance| instance.instance_name().to_owned())
    }

    pub fn attach_tun_fd(&self, instance_id: uuid::Uuid, fd: i32) -> anyhow::Result<()> {
        self.manager
            .get(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .attach_tun_fd(fd)
    }

    pub fn set_tun_fd(&self, instance_id: &uuid::Uuid, fd: i32) -> anyhow::Result<()> {
        self.attach_tun_fd(*instance_id, fd)
    }

    pub fn data_plane_wait_runtime_handle(
        &self,
        instance_id: &uuid::Uuid,
        _timeout: std::time::Duration,
    ) -> Option<tokio::runtime::Handle> {
        self.instance(*instance_id)?;
        self.runtime_handle
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
    }

    pub async fn wait(&self) {
        loop {
            let instance_running = self
                .manager
                .list()
                .iter()
                .any(|instance| instance.state() != CoreInstanceState::Stopped);
            let daemon_running = Arc::strong_count(&self.daemon_guard) > 1;
            let instance_stopping = self.active_stops.load(Ordering::Acquire) != 0;
            if !instance_running && !instance_stopping && !daemon_running {
                return;
            }
            self.notifier.notified().await;
        }
    }
}
