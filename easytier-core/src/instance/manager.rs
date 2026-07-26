//! Canonical process-level ownership and lifecycle for EasyTier instances.

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fmt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use dashmap::DashMap;
use uuid::Uuid;

use crate::config::toml::TomlConfig;
use crate::instance::{CoreInstance, CoreInstanceHost};
use crate::process_runtime::CoreProcessRuntime;
#[cfg(feature = "management")]
use crate::{
    config::toml::{ConfigLoader as _, ConfigSource},
    management::network_instance_running_info,
};
#[cfg(feature = "management")]
use easytier_proto::api::manage::NetworkInstanceRunningInfo;

/// Stable identity required by the instance collection.
pub trait ManagedInstance: Send + Sync + 'static {
    fn instance_id(&self) -> Uuid;
}

impl<H> ManagedInstance for CoreInstance<H>
where
    H: CoreInstanceHost,
{
    fn instance_id(&self) -> Uuid {
        self.instance_id()
    }
}

/// Host-specific construction seam for one complete instance record.
pub trait InstanceFactory: Send + Sync + 'static {
    type Instance: ManagedInstance;
    type CreateContext;
    type Error;

    fn create(
        &self,
        config: TomlConfig,
        context: Self::CreateContext,
    ) -> Result<Arc<Self::Instance>, Self::Error>;
}

/// Error returned while constructing or registering an instance.
#[derive(Debug)]
pub enum InstanceCreateError<E> {
    Factory(E),
    AlreadyExists { instance_id: Uuid },
}

impl<E> fmt::Display for InstanceCreateError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Factory(error) => write!(formatter, "failed to create instance: {error:#}"),
            Self::AlreadyExists { instance_id } => {
                write!(formatter, "instance {instance_id} already exists")
            }
        }
    }
}

impl<E> Error for InstanceCreateError<E> where E: fmt::Debug + fmt::Display {}

/// Supplies the process runtime used by every instance created by this
/// factory.
pub trait ProcessRuntimeProvider: InstanceFactory {
    fn process_runtime(&self) -> Arc<CoreProcessRuntime>;
}

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

impl fmt::Debug for ConfigFilePermission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// Owns all process-level Instance state and operations.
pub struct InstanceManager<F: InstanceFactory> {
    factory: F,
    instances: Mutex<HashMap<Uuid, Arc<F::Instance>>>,
    config_controls: DashMap<Uuid, ConfigFileControl>,
    notifier: Arc<tokio::sync::Notify>,
    config_dir: Option<PathBuf>,
    daemon_guard: Arc<()>,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
    runtime_handle: Option<tokio::runtime::Handle>,
    active_stops: Arc<AtomicUsize>,
}

impl<F: InstanceFactory> InstanceManager<F> {
    pub fn new(factory: F, runtime_handle: Option<tokio::runtime::Handle>) -> Self {
        Self {
            factory,
            instances: Mutex::new(HashMap::new()),
            config_controls: DashMap::new(),
            notifier: Arc::new(tokio::sync::Notify::new()),
            config_dir: None,
            daemon_guard: Arc::new(()),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            runtime_handle,
            active_stops: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_config_path(mut self, config_dir: Option<PathBuf>) -> Self {
        self.config_dir = config_dir;
        self
    }

    pub fn create(
        &self,
        config: TomlConfig,
        context: F::CreateContext,
    ) -> Result<Arc<F::Instance>, InstanceCreateError<F::Error>> {
        let instance = self
            .factory
            .create(config, context)
            .map_err(InstanceCreateError::Factory)?;
        let instance_id = instance.instance_id();
        let mut instances = self.instances.lock().expect("instance map lock poisoned");

        match instances.entry(instance_id) {
            Entry::Vacant(entry) => {
                entry.insert(instance.clone());
                Ok(instance)
            }
            Entry::Occupied(_) => Err(InstanceCreateError::AlreadyExists { instance_id }),
        }
    }

    pub(crate) fn get(&self, instance_id: Uuid) -> Option<Arc<F::Instance>> {
        self.instances
            .lock()
            .expect("instance map lock poisoned")
            .get(&instance_id)
            .cloned()
    }

    pub(crate) fn list(&self) -> Vec<Arc<F::Instance>> {
        self.instances
            .lock()
            .expect("instance map lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub(crate) fn remove(&self, instance_id: Uuid) -> Option<Arc<F::Instance>> {
        self.instances
            .lock()
            .expect("instance map lock poisoned")
            .remove(&instance_id)
    }

    pub fn mutation_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.mutation_lock.clone()
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

impl<F: ProcessRuntimeProvider> InstanceManager<F> {
    pub fn process_runtime(&self) -> Arc<CoreProcessRuntime> {
        self.factory.process_runtime()
    }
}

impl<F, H> InstanceManager<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: fmt::Debug + fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn run_network_instance(
        &self,
        config: TomlConfig,
        control: ConfigFileControl,
    ) -> anyhow::Result<Uuid> {
        let runtime = self
            .runtime_handle
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
            .ok_or_else(|| anyhow::anyhow!("tokio runtime not found, cannot start instance"))?;
        let instance = self.create(config, ()).map_err(anyhow::Error::new)?;
        let instance_id = instance.instance_id();
        self.config_controls.insert(instance_id, control);
        let notifier = self.notifier.clone();
        runtime.spawn(async move {
            if let Err(error) = instance.start().await {
                tracing::error!(%error, %instance_id, "instance failed to start");
            }
            notifier.notify_one();
        });
        Ok(instance_id)
    }

    pub async fn delete_network_instances(
        &self,
        instance_ids: impl IntoIterator<Item = Uuid>,
    ) -> anyhow::Result<Vec<Uuid>> {
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
            if let Some(instance) = self.remove(instance_id) {
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

    pub async fn retain_network_instances(&self, retained: &[Uuid]) -> anyhow::Result<Vec<Uuid>> {
        let removed = self
            .list()
            .into_iter()
            .map(|instance| instance.instance_id())
            .filter(|instance_id| !retained.contains(instance_id))
            .collect::<Vec<_>>();
        self.delete_network_instances(removed).await
    }

    pub fn instance_ids(&self) -> Vec<Uuid> {
        self.list()
            .into_iter()
            .map(|instance| instance.instance_id())
            .collect()
    }

    pub fn instance(&self, instance_id: Uuid) -> Option<Arc<CoreInstance<H>>> {
        self.get(instance_id)
    }

    pub fn instances(&self) -> Vec<Arc<CoreInstance<H>>> {
        self.list()
    }

    pub fn config_control(&self, instance_id: Uuid) -> Option<ConfigFileControl> {
        self.config_controls
            .get(&instance_id)
            .map(|control| control.clone())
    }

    pub fn attach_tun_fd(&self, instance_id: Uuid, fd: i32) -> anyhow::Result<()> {
        self.get(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .attach_tun_fd(fd)
    }

    pub fn data_plane_runtime_handle(&self, instance_id: &Uuid) -> Option<tokio::runtime::Handle> {
        self.instance(*instance_id)?;
        self.runtime_handle
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
    }

    pub async fn wait(&self) {
        loop {
            let instance_running = self
                .list()
                .iter()
                .any(|instance| instance.state() != crate::instance::CoreInstanceState::Stopped);
            let daemon_running = Arc::strong_count(&self.daemon_guard) > 1;
            let instance_stopping = self.active_stops.load(Ordering::Acquire) != 0;
            if !instance_running && !instance_stopping && !daemon_running {
                return;
            }
            self.notifier.notified().await;
        }
    }

    #[cfg(feature = "management")]
    pub fn config(&self, instance_id: Uuid) -> Option<TomlConfig> {
        self.get(instance_id)
            .and_then(|instance| instance.toml_config())
    }

    #[cfg(feature = "management")]
    pub fn config_source(&self, instance_id: Uuid) -> Option<ConfigSource> {
        self.config(instance_id)
            .map(|config| config.get_network_config_source())
    }

    #[cfg(feature = "management")]
    pub async fn network_info(&self, instance_id: Uuid) -> Option<NetworkInstanceRunningInfo> {
        let instance = self.get(instance_id)?;
        network_instance_running_info(instance.as_ref()).await.ok()
    }

    #[cfg(feature = "management")]
    pub async fn collect_network_infos(
        &self,
    ) -> anyhow::Result<std::collections::BTreeMap<Uuid, NetworkInstanceRunningInfo>> {
        let mut result = std::collections::BTreeMap::new();
        for instance in self.list() {
            result.insert(
                instance.instance_id(),
                network_instance_running_info(instance.as_ref()).await?,
            );
        }
        Ok(result)
    }

    #[cfg(feature = "management")]
    pub fn collect_network_infos_sync(
        &self,
    ) -> anyhow::Result<std::collections::BTreeMap<Uuid, NetworkInstanceRunningInfo>> {
        self.runtime_handle
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("InstanceManager runtime handle is unavailable"))?
            .block_on(self.collect_network_infos())
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub fn data_plane_session(
        &self,
        instance_id: &Uuid,
    ) -> Option<Arc<crate::gateway::DataPlaneSession<H>>> {
        self.instance(*instance_id)
            .map(|instance| instance.data_plane_session())
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_tcp_connect(
        &self,
        instance_id: &Uuid,
        dst_addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneTcpStream> {
        Ok(self
            .instance(*instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .data_plane_tcp_connect(dst_addr, timeout)
            .await?)
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_tcp_bind(
        &self,
        instance_id: &Uuid,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneTcpListener> {
        Ok(self
            .instance(*instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .data_plane_tcp_bind(local_port, timeout)
            .await?)
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_udp_bind(
        &self,
        instance_id: &Uuid,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneUdpSocket> {
        Ok(self
            .instance(*instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .data_plane_udp_bind(local_port, timeout)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use super::*;
    struct TestFactory {
        drops: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct TestInstance {
        id: Uuid,
        drops: Arc<AtomicUsize>,
    }

    impl ManagedInstance for TestInstance {
        fn instance_id(&self) -> Uuid {
            self.id
        }
    }

    impl Drop for TestInstance {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl InstanceFactory for TestFactory {
        type Instance = TestInstance;
        type CreateContext = ();
        type Error = std::convert::Infallible;

        fn create(
            &self,
            config: TomlConfig,
            (): Self::CreateContext,
        ) -> Result<Arc<Self::Instance>, Self::Error> {
            Ok(Arc::new(TestInstance {
                id: config.get_id(),
                drops: self.drops.clone(),
            }))
        }
    }

    fn manager() -> (Arc<InstanceManager<TestFactory>>, Arc<AtomicUsize>) {
        let drops = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(InstanceManager::new(
                TestFactory {
                    drops: drops.clone(),
                },
                None,
            )),
            drops,
        )
    }

    fn config(instance_id: Uuid) -> TomlConfig {
        let config = TomlConfig::default();
        config.set_id(instance_id);
        config
    }

    #[test]
    fn duplicate_create_drops_losing_complete_record() {
        let (manager, drops) = manager();
        let instance_id = Uuid::new_v4();
        let first = manager.create(config(instance_id), ()).unwrap();
        let error = manager.create(config(instance_id), ()).unwrap_err();

        assert!(matches!(
            error,
            InstanceCreateError::AlreadyExists {
                instance_id: duplicate
            } if duplicate == instance_id
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(&first, &manager.get(instance_id).unwrap()));
    }

    #[test]
    fn concurrent_duplicate_create_registers_exactly_one_instance() {
        let (manager, drops) = manager();
        let instance_id = Uuid::new_v4();
        let workers = (0..2)
            .map(|_| {
                let manager = manager.clone();
                thread::spawn(move || manager.create(config(instance_id), ()))
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(manager.list().len(), 1);
    }

    #[test]
    fn list_is_an_arc_snapshot_and_remove_returns_exact_stored_value() {
        let (manager, drops) = manager();
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first = manager.create(config(first_id), ()).unwrap();
        let second = manager.create(config(second_id), ()).unwrap();

        let snapshot = manager.list();
        let removed = manager.remove(first_id).unwrap();

        assert!(Arc::ptr_eq(&first, &removed));
        assert!(snapshot.iter().any(|item| Arc::ptr_eq(item, &removed)));
        assert!(manager.get(first_id).is_none());
        assert!(Arc::ptr_eq(&second, &manager.get(second_id).unwrap()));
        drop(removed);
        drop(first);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(snapshot);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
