use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use easytier_proto::{
    api::manage::{
        CollectNetworkInfoRequest, CollectNetworkInfoResponse, DeleteNetworkInstanceRequest,
        DeleteNetworkInstanceResponse, GetNetworkInstanceConfigRequest,
        GetNetworkInstanceConfigResponse, ListNetworkInstanceMetaRequest,
        ListNetworkInstanceMetaResponse, ListNetworkInstanceRequest, ListNetworkInstanceResponse,
        NetworkInstanceRunningInfoMap, NetworkMeta, RetainNetworkInstanceRequest,
        RetainNetworkInstanceResponse, RunNetworkInstanceRequest, RunNetworkInstanceResponse,
        ValidateConfigRequest, ValidateConfigResponse, WebClientService,
    },
    rpc_types::{self, controller::BaseController},
};

use crate::{
    config::{
        api::network_config_from_toml,
        api_input::NetworkConfigExt as _,
        toml::{ConfigLoader as _, ConfigSource, TomlConfig},
    },
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
};

use super::{
    ConfigFileControl, ConfigFilePermission, ManagedInstanceSet, config_source_from_rpc,
    config_source_to_rpc,
};

#[async_trait::async_trait]
pub trait InstanceMutationHooks: Send + Sync + 'static {
    fn manages_remote_config_instances(&self) -> bool {
        false
    }

    async fn pre_run_network_instance(&self, _config: &TomlConfig) -> Result<(), String> {
        Ok(())
    }

    async fn post_run_network_instance(&self, _instance_id: &uuid::Uuid) -> Result<(), String> {
        Ok(())
    }

    async fn post_remove_network_instances(
        &self,
        _instance_ids: &[uuid::Uuid],
    ) -> Result<(), String> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl InstanceMutationHooks for () {}

/// Host Adapter for configuration-file effects used by process management.
#[async_trait::async_trait]
pub trait ConfigFileStorage: Send + Sync + 'static {
    async fn inspect(&self, path: &Path) -> ConfigFileControl;

    async fn read(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>>;

    async fn write(&self, path: &Path, contents: &[u8]) -> anyhow::Result<()>;

    async fn remove(&self, path: &Path) -> anyhow::Result<()>;
}

#[derive(Default)]
pub struct UnsupportedConfigFileStorage;

#[async_trait::async_trait]
impl ConfigFileStorage for UnsupportedConfigFileStorage {
    async fn inspect(&self, path: &Path) -> ConfigFileControl {
        ConfigFileControl::new(
            Some(path.to_owned()),
            ConfigFilePermission::from(ConfigFilePermission::READ_ONLY),
        )
    }

    async fn read(&self, _path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        anyhow::bail!("configuration-file storage is unsupported by this Host")
    }

    async fn write(&self, _path: &Path, _contents: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("configuration-file storage is unsupported by this Host")
    }

    async fn remove(&self, _path: &Path) -> anyhow::Result<()> {
        anyhow::bail!("configuration-file storage is unsupported by this Host")
    }
}

/// Result of one process-level removal transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceMutationResult {
    pub remaining_instance_ids: Vec<uuid::Uuid>,
    pub removed_instance_ids: Vec<uuid::Uuid>,
}

/// Transport-independent process-level Instance management.
pub struct ProcessManagement<F, H>
where
    F: InstanceFactory,
{
    instances: Arc<ManagedInstanceSet<F>>,
    hooks: Arc<dyn InstanceMutationHooks>,
    storage: Arc<dyn ConfigFileStorage>,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
    host: std::marker::PhantomData<fn() -> H>,
}

impl<F, H> Clone for ProcessManagement<F, H>
where
    F: InstanceFactory,
{
    fn clone(&self) -> Self {
        Self {
            instances: self.instances.clone(),
            hooks: self.hooks.clone(),
            storage: self.storage.clone(),
            mutation_lock: self.mutation_lock.clone(),
            host: std::marker::PhantomData,
        }
    }
}

impl<F, H> ProcessManagement<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn new(
        instances: Arc<ManagedInstanceSet<F>>,
        hooks: Arc<dyn InstanceMutationHooks>,
        storage: Arc<dyn ConfigFileStorage>,
    ) -> Self {
        let mutation_lock = instances.mutation_lock();
        Self {
            instances,
            hooks,
            storage,
            mutation_lock,
            host: std::marker::PhantomData,
        }
    }

    async fn is_remote_removable(&self, control: &ConfigFileControl) -> bool {
        if control.is_read_only() || !control.is_deletable() {
            return false;
        }
        let Some(path) = control.path.as_deref() else {
            return true;
        };
        !self.storage.inspect(path).await.is_read_only()
    }

    async fn ensure_overwritable(
        &self,
        instance_id: uuid::Uuid,
        control: &ConfigFileControl,
        require_deletable: bool,
    ) -> anyhow::Result<()> {
        if control.is_read_only() {
            anyhow::bail!("instance {instance_id} is read-only, cannot be overwritten");
        }
        if require_deletable && !control.is_deletable() {
            anyhow::bail!("instance {instance_id} is no-delete, cannot be overwritten");
        }
        if let Some(path) = control.path.as_deref()
            && self.storage.inspect(path).await.is_read_only()
        {
            anyhow::bail!(
                "config file {} is read-only, cannot be overwritten",
                path.display()
            );
        }
        Ok(())
    }

    async fn apply_file_cleanup(&self, cleanup: ConfigFileCleanup) {
        let result = match cleanup {
            ConfigFileCleanup::Remove(path) => self.storage.remove(&path).await,
            ConfigFileCleanup::Restore { path, contents } => {
                self.storage.write(&path, &contents).await
            }
        };
        if let Err(error) = result {
            tracing::warn!(%error, "failed to roll back configuration file");
        }
    }

    async fn rollback_started_instance(
        &self,
        started_instance_id: Option<uuid::Uuid>,
        file_cleanup: Option<ConfigFileCleanup>,
        restore_instance: Option<(TomlConfig, ConfigFileControl)>,
    ) {
        if let Some(instance_id) = started_instance_id
            && let Err(error) = self
                .instances
                .delete_network_instance(vec![instance_id])
                .await
        {
            tracing::warn!(%error, "failed to remove rolled-back instance");
            return;
        }
        if let Some(cleanup) = file_cleanup {
            self.apply_file_cleanup(cleanup).await;
        }
        if let Some((config, control)) = restore_instance
            && let Err(error) = self.instances.run_network_instance(config, true, control)
        {
            tracing::warn!(%error, "failed to restore overwritten instance");
        }
    }

    pub async fn run_network_instance(
        &self,
        config: TomlConfig,
        requested_id: Option<uuid::Uuid>,
        overwrite: bool,
        requested_source: Option<ConfigSource>,
    ) -> anyhow::Result<uuid::Uuid> {
        let mut instance_id = config.get_id();
        if let Some(requested_id) = requested_id {
            instance_id = requested_id;
            config.set_id(instance_id);
        }
        let _mutation = self.mutation_lock.lock().await;
        let remote_managed = self.hooks.manages_remote_config_instances();

        let mut replacing = false;
        let mut restore_instance = None;
        let mut control = if let Some(control) = self.instances.config_control(instance_id) {
            let existing_source = self.instances.config_source(instance_id);
            let error_message = self
                .instances
                .network_info(instance_id)
                .await
                .and_then(|info| info.error_msg)
                .unwrap_or_default();
            if !overwrite && error_message.is_empty() {
                return Ok(instance_id);
            }
            self.ensure_overwritable(instance_id, &control, remote_managed)
                .await?;
            config.set_network_config_source(requested_source.or(existing_source));
            replacing = true;
            restore_instance = self
                .instances
                .config(instance_id)
                .map(|config| (config, control.clone()));
            control
        } else if let Some(config_dir) = self.instances.config_dir() {
            config.set_network_config_source(requested_source);
            ConfigFileControl::new(
                Some(config_dir.join(format!("{instance_id}.toml"))),
                ConfigFilePermission::default(),
            )
        } else {
            config.set_network_config_source(requested_source);
            ConfigFileControl::new(None, ConfigFilePermission::default())
        };

        self.hooks
            .pre_run_network_instance(&config)
            .await
            .map_err(|error| anyhow::anyhow!("pre-run hook failed: {error}"))?;

        if replacing {
            self.ensure_overwritable(instance_id, &control, remote_managed)
                .await?;
        }

        let mut file_cleanup = None;
        if !control.is_read_only()
            && let Some(path) = control.path.as_deref()
        {
            let cleanup = match self.storage.read(path).await {
                Ok(Some(contents)) => Some(ConfigFileCleanup::Restore {
                    path: path.to_owned(),
                    contents,
                }),
                Ok(None) => Some(ConfigFileCleanup::Remove(path.to_owned())),
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "failed to back up config file {} before overwrite: {error}",
                        path.display()
                    ));
                }
            };
            if let Err(error) = self.storage.write(path, config.dump().as_bytes()).await {
                tracing::warn!(%error, path = %path.display(), "failed to write config file");
                control.set_read_only(true);
            } else {
                file_cleanup = cleanup;
            }
        }

        if replacing
            && let Err(error) = self
                .instances
                .delete_network_instance(vec![instance_id])
                .await
        {
            self.rollback_started_instance(None, file_cleanup, restore_instance)
                .await;
            return Err(error);
        }

        if let Err(error) = self.instances.run_network_instance(config, true, control) {
            self.rollback_started_instance(None, file_cleanup, restore_instance)
                .await;
            return Err(error);
        }

        if let Err(error) = self.hooks.post_run_network_instance(&instance_id).await {
            if remote_managed {
                self.rollback_started_instance(Some(instance_id), file_cleanup, restore_instance)
                    .await;
                return Err(anyhow::anyhow!("post-run hook failed: {error}"));
            }
            tracing::warn!(%error, "post-run hook failed");
        }
        Ok(instance_id)
    }

    pub async fn retain_network_instances(
        &self,
        retained: Vec<uuid::Uuid>,
    ) -> anyhow::Result<InstanceMutationResult> {
        let _mutation = self.mutation_lock.lock().await;
        self.retain_network_instances_locked(retained).await
    }

    /// Resolves retained names and mutates the collection in one transaction.
    pub async fn retain_owned_network_instances_by_name(
        &self,
        retained_names: Vec<String>,
    ) -> anyhow::Result<InstanceMutationResult> {
        let _mutation = self.mutation_lock.lock().await;
        let retained = self.resolve_instance_ids_by_name(&retained_names)?;
        self.retain_network_instances_locked(retained).await
    }

    async fn retain_network_instances_locked(
        &self,
        retained: Vec<uuid::Uuid>,
    ) -> anyhow::Result<InstanceMutationResult> {
        let before = self.instances.instance_ids();
        if !self.hooks.manages_remote_config_instances() {
            let remaining = self.instances.retain_network_instances(&retained).await?;
            let remaining_set = remaining.iter().copied().collect::<HashSet<_>>();
            let removed = before
                .into_iter()
                .filter(|id| !remaining_set.contains(id))
                .collect::<Vec<_>>();
            self.notify_removed_instances(&removed).await?;
            return Ok(InstanceMutationResult {
                removed_instance_ids: removed,
                remaining_instance_ids: remaining,
            });
        }

        let mut retained = retained.into_iter().collect::<HashSet<_>>();
        let mut removed = Vec::new();
        for instance in self.instances.instances() {
            let instance_id = instance.instance_id();
            if retained.contains(&instance_id) {
                continue;
            }
            let Some(control) = self.instances.config_control(instance_id) else {
                continue;
            };
            if self.is_remote_removable(&control).await {
                removed.push(instance_id);
            } else {
                retained.insert(instance_id);
            }
        }
        let remaining = self
            .instances
            .retain_network_instances(&retained.into_iter().collect::<Vec<_>>())
            .await?;
        self.notify_removed_instances(&removed).await?;
        Ok(InstanceMutationResult {
            remaining_instance_ids: remaining,
            removed_instance_ids: removed,
        })
    }

    pub async fn delete_network_instances(
        &self,
        requested: Vec<uuid::Uuid>,
    ) -> anyhow::Result<InstanceMutationResult> {
        let _mutation = self.mutation_lock.lock().await;
        let requested = requested.into_iter().collect::<HashSet<_>>();
        let remote_managed = self.hooks.manages_remote_config_instances();
        let mut removed = Vec::new();
        let mut files = Vec::new();
        for instance in self.instances.instances() {
            let instance_id = instance.instance_id();
            if !requested.contains(&instance_id) {
                continue;
            }
            let Some(control) = self.instances.config_control(instance_id) else {
                continue;
            };
            let removable = if remote_managed {
                self.is_remote_removable(&control).await
            } else {
                control.is_deletable()
            };
            if removable {
                removed.push(instance_id);
                files.extend(control.path);
            }
        }
        let remaining = self
            .instances
            .delete_network_instances(removed.clone())
            .await?;
        self.notify_removed_instances(&removed).await?;
        for path in files {
            if remote_managed && self.storage.inspect(&path).await.is_read_only() {
                continue;
            }
            if let Err(error) = self.storage.remove(&path).await {
                tracing::warn!(%error, path = %path.display(), "failed to remove config file");
            }
        }
        Ok(InstanceMutationResult {
            remaining_instance_ids: remaining,
            removed_instance_ids: removed,
        })
    }

    /// Starts one caller-owned Instance while preserving its static control.
    pub async fn run_owned_network_instance(
        &self,
        config: TomlConfig,
        control: ConfigFileControl,
    ) -> anyhow::Result<uuid::Uuid> {
        let _mutation = self.mutation_lock.lock().await;
        let instance_id = config.get_id();
        if self.instances.instance(instance_id).is_some() {
            anyhow::bail!("instance {instance_id} already exists");
        }
        let instance_name = config.get_inst_name();
        if super::resolve_optional_instance_by_name(
            self.instances.manager().as_ref(),
            &instance_name,
        )?
        .is_some()
        {
            anyhow::bail!("instance name {instance_name} already exists");
        }
        self.instances.run_network_instance(config, false, control)
    }

    /// Removes caller-owned Instances without applying remote config-file policy.
    pub async fn delete_owned_network_instances(
        &self,
        requested: Vec<uuid::Uuid>,
    ) -> anyhow::Result<InstanceMutationResult> {
        self.delete_owned_network_instances_selected_by(|| requested)
            .await
    }

    /// Selects caller-owned Instances and removes them under one lock.
    pub async fn delete_owned_network_instances_selected_by(
        &self,
        select: impl FnOnce() -> Vec<uuid::Uuid>,
    ) -> anyhow::Result<InstanceMutationResult> {
        let _mutation = self.mutation_lock.lock().await;
        let requested = select();
        self.delete_owned_network_instances_locked(requested).await
    }

    /// Resolves requested names and removes them in one transaction.
    pub async fn delete_owned_network_instances_by_name(
        &self,
        requested_names: Vec<String>,
    ) -> anyhow::Result<InstanceMutationResult> {
        let _mutation = self.mutation_lock.lock().await;
        let requested = self.resolve_instance_ids_by_name(&requested_names)?;
        self.delete_owned_network_instances_locked(requested).await
    }

    async fn delete_owned_network_instances_locked(
        &self,
        requested: Vec<uuid::Uuid>,
    ) -> anyhow::Result<InstanceMutationResult> {
        let before = self.instances.instance_ids();
        let remaining = self.instances.delete_network_instances(requested).await?;
        let remaining_set = remaining.iter().copied().collect::<HashSet<_>>();
        let removed = before
            .into_iter()
            .filter(|id| !remaining_set.contains(id))
            .collect::<Vec<_>>();
        self.notify_removed_instances(&removed).await?;
        Ok(InstanceMutationResult {
            removed_instance_ids: removed,
            remaining_instance_ids: remaining,
        })
    }

    fn resolve_instance_ids_by_name(&self, names: &[String]) -> anyhow::Result<Vec<uuid::Uuid>> {
        names
            .iter()
            .map(|name| {
                super::resolve_optional_instance_by_name(self.instances.manager().as_ref(), name)
                    .map(|instance| instance.map(|instance| instance.instance_id()))
            })
            .filter_map(Result::transpose)
            .collect()
    }

    async fn notify_removed_instances(&self, removed: &[uuid::Uuid]) -> anyhow::Result<()> {
        if let Err(error) = self.hooks.post_remove_network_instances(removed).await {
            if self.hooks.manages_remote_config_instances() {
                anyhow::bail!("post-remove hook failed: {error}");
            }
            tracing::warn!(%error, "post-remove hook failed");
        }
        Ok(())
    }
}

enum ConfigFileCleanup {
    Remove(PathBuf),
    Restore { path: PathBuf, contents: Vec<u8> },
}

/// Protobuf projection over transport-independent process management.
pub struct ProcessManagementRpc<F, H>
where
    F: InstanceFactory,
{
    management: ProcessManagement<F, H>,
}

impl<F, H> Clone for ProcessManagementRpc<F, H>
where
    F: InstanceFactory,
{
    fn clone(&self) -> Self {
        Self {
            management: self.management.clone(),
        }
    }
}

impl<F, H> ProcessManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn new(
        instances: Arc<ManagedInstanceSet<F>>,
        hooks: Arc<dyn InstanceMutationHooks>,
        storage: Arc<dyn ConfigFileStorage>,
    ) -> Self {
        Self {
            management: ProcessManagement::new(instances, hooks, storage),
        }
    }
}

#[async_trait::async_trait]
impl<F, H> WebClientService for ProcessManagementRpc<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn validate_config(
        &self,
        _: BaseController,
        request: ValidateConfigRequest,
    ) -> rpc_types::error::Result<ValidateConfigResponse> {
        Ok(ValidateConfigResponse {
            toml_config: request.config.unwrap_or_default().gen_config()?.dump(),
        })
    }

    async fn run_network_instance(
        &self,
        _: BaseController,
        request: RunNetworkInstanceRequest,
    ) -> rpc_types::error::Result<RunNetworkInstanceResponse> {
        let config = request
            .config
            .ok_or_else(|| anyhow::anyhow!("config is required"))?
            .gen_config()?;
        let requested_id = request.inst_id.map(Into::into);
        let requested_source = config_source_from_rpc(request.source);
        let management = self.management.clone();
        let instance_id = tokio::spawn(async move {
            management
                .run_network_instance(config, requested_id, request.overwrite, requested_source)
                .await
        })
        .await
        .map_err(|error| anyhow::anyhow!("instance mutation task failed: {error}"))??;
        Ok(RunNetworkInstanceResponse {
            inst_id: Some(instance_id.into()),
        })
    }

    async fn retain_network_instance(
        &self,
        _: BaseController,
        request: RetainNetworkInstanceRequest,
    ) -> rpc_types::error::Result<RetainNetworkInstanceResponse> {
        let retained = request.inst_ids.into_iter().map(Into::into).collect();
        let management = self.management.clone();
        let result =
            tokio::spawn(async move { management.retain_network_instances(retained).await })
                .await
                .map_err(|error| anyhow::anyhow!("instance mutation task failed: {error}"))??;
        Ok(RetainNetworkInstanceResponse {
            remain_inst_ids: result
                .remaining_instance_ids
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    async fn collect_network_info(
        &self,
        _: BaseController,
        request: CollectNetworkInfoRequest,
    ) -> rpc_types::error::Result<CollectNetworkInfoResponse> {
        let included = request
            .inst_ids
            .into_iter()
            .map(|id| uuid::Uuid::from(id).to_string())
            .collect::<HashSet<_>>();
        let map = self
            .management
            .instances
            .collect_network_infos()
            .await?
            .into_iter()
            .map(|(id, info)| (id.to_string(), info))
            .filter(|(id, _)| included.is_empty() || included.contains(id))
            .collect();
        Ok(CollectNetworkInfoResponse {
            info: Some(NetworkInstanceRunningInfoMap { map }),
        })
    }

    async fn list_network_instance(
        &self,
        _: BaseController,
        _: ListNetworkInstanceRequest,
    ) -> rpc_types::error::Result<ListNetworkInstanceResponse> {
        Ok(ListNetworkInstanceResponse {
            inst_ids: self
                .management
                .instances
                .instance_ids()
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    async fn delete_network_instance(
        &self,
        _: BaseController,
        request: DeleteNetworkInstanceRequest,
    ) -> rpc_types::error::Result<DeleteNetworkInstanceResponse> {
        let requested = request.inst_ids.into_iter().map(Into::into).collect();
        let management = self.management.clone();
        let result =
            tokio::spawn(async move { management.delete_network_instances(requested).await })
                .await
                .map_err(|error| anyhow::anyhow!("instance mutation task failed: {error}"))??;
        Ok(DeleteNetworkInstanceResponse {
            remain_inst_ids: result
                .remaining_instance_ids
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    async fn get_network_instance_config(
        &self,
        _: BaseController,
        request: GetNetworkInstanceConfigRequest,
    ) -> rpc_types::error::Result<GetNetworkInstanceConfigResponse> {
        let instance_id = request
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("instance id is required"))?
            .into();
        let control = self
            .management
            .instances
            .config_control(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance config control not found"))?;
        if control.is_read_only() {
            return Err(
                anyhow::anyhow!("configuration for instance {instance_id} is read-only").into(),
            );
        }
        Ok(GetNetworkInstanceConfigResponse {
            config: self
                .management
                .instances
                .config(instance_id)
                .map(|config| network_config_from_toml(&config)),
            source: config_source_to_rpc(
                self.management
                    .instances
                    .config_source(instance_id)
                    .unwrap_or(ConfigSource::User),
            ),
        })
    }

    async fn list_network_instance_meta(
        &self,
        _: BaseController,
        request: ListNetworkInstanceMetaRequest,
    ) -> rpc_types::error::Result<ListNetworkInstanceMetaResponse> {
        let mut metas = Vec::with_capacity(request.inst_ids.len());
        for instance_id in request.inst_ids.into_iter().map(uuid::Uuid::from) {
            let Some(instance) = self.management.instances.instance(instance_id) else {
                continue;
            };
            let Some(config) = instance.toml_config() else {
                continue;
            };
            let Some(control) = self.management.instances.config_control(instance_id) else {
                continue;
            };
            metas.push(NetworkMeta {
                inst_id: Some(instance_id.into()),
                network_name: config.get_network_identity().network_name,
                config_permission: control.permission.into(),
                instance_name: instance.instance_name().to_owned(),
                source: config_source_to_rpc(config.get_network_config_source()),
            });
        }
        Ok(ListNetworkInstanceMetaResponse { metas })
    }
}
