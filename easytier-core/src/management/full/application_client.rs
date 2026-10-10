//! Application-level network ownership and configuration rules, independent of any UI host.
use super::application_rpc::{InstanceControl, RpcInstanceControl};
use crate::config::api_input::{NetworkConfig, NetworkConfigExt};
use crate::config::toml::{ConfigLoader, ConfigSource};
use crate::management::config_source_to_rpc;
use crate::management::remote_client::PersistentConfig;
use crate::management::remote_client::{ListNetworkProps, RemoteClientManager, Storage};
use crate::rpc::bidirect::BidirectRpcManager;
use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use easytier_proto::api::config::{ConfigRpc, ConfigRpcClientFactory, VpnPortalClientPatch};
use easytier_proto::api::logger::{LoggerRpc, LoggerRpcClientFactory, SetLoggerConfigRequest};
use easytier_proto::api::manage::RunNetworkInstanceRequest;
use easytier_proto::api::manage::{WebClientService, WebClientServiceClientFactory};
use easytier_proto::rpc_types::controller::BaseController;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Default, Debug, serde::Serialize)]
pub struct OperationOutcome {
    pub runtime_applied: bool,
    pub persistence_warning: Option<String>,
    pub reconciliation_warning: Option<String>,
}

#[derive(Clone, serde::Serialize)]
pub struct ManagementStatus {
    pub running_instances: Vec<Uuid>,
    pub desired_enabled: Vec<Uuid>,
    pub runtime_state_known: bool,
    pub last_outcome: OperationOutcome,
}

/// Platform effects are supplied by the caller, not owned by the application manager.
/// Implementations must not hold a management lock while calling back into the manager.
#[async_trait::async_trait]
pub trait ManagementHost: Clone + Send + Sync + 'static {
    fn emit<S: serde::Serialize + Clone>(&self, event: &str, payload: S) -> anyhow::Result<()>;
    fn single_tun(&self) -> bool;
    async fn observe_instance(&self, instance_id: Uuid);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum PersistedConfigSource {
    User,
    #[serde(alias = "webhook")]
    Web,
    #[serde(other)]
    #[default]
    Legacy,
}

impl PersistedConfigSource {
    pub fn from_runtime_source(source: ConfigSource) -> Self {
        match source {
            ConfigSource::User => Self::User,
            ConfigSource::Web => Self::Web,
        }
    }

    fn merge_persisted(self, incoming: Self) -> Self {
        match (self, incoming) {
            // Older runtimes report missing source as `user`. Keep the stronger persisted
            // ownership until web sync or an explicit user save repairs it.
            (Self::Web, Self::User) | (Self::Legacy, Self::User) => self,
            (_, next) => next,
        }
    }

    fn to_runtime_source(self) -> ConfigSource {
        match self {
            Self::User | Self::Legacy => ConfigSource::User,
            Self::Web => ConfigSource::Web,
        }
    }

    fn is_web_like(self) -> bool {
        matches!(self, Self::Web)
    }
}

#[derive(Clone)]
pub struct ApplicationConfig {
    inst_id: String,
    pub config: NetworkConfig,
    source: PersistedConfigSource,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredConfig {
    pub config: NetworkConfig,
    #[serde(default)]
    pub source: PersistedConfigSource,
}

/// Durable storage supplied by a platform adapter. A successful write must be atomic;
/// implementations must propagate errors rather than falling back to stale UI data.
pub trait ConfigRepository: Send + Sync {
    fn load_or_import(&self, legacy: &[StoredConfig]) -> anyhow::Result<Vec<StoredConfig>>;
    fn save_configs(&self, configs: &[StoredConfig]) -> anyhow::Result<()>;
    fn save_enabled(&self, ids: &[String]) -> anyhow::Result<()>;
    fn load_desired_enabled(&self) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
}

impl ApplicationConfig {
    fn new(inst_id: String, config: NetworkConfig, source: PersistedConfigSource) -> Self {
        Self {
            inst_id,
            config,
            source,
        }
    }

    fn into_stored(self) -> StoredConfig {
        StoredConfig {
            config: self.config,
            source: self.source,
        }
    }
}

impl PersistentConfig<anyhow::Error> for ApplicationConfig {
    fn get_network_inst_id(&self) -> &str {
        &self.inst_id
    }
    fn get_network_config(&self) -> Result<NetworkConfig, anyhow::Error> {
        Ok(self.config.clone())
    }
    fn get_network_config_source(&self) -> ConfigSource {
        self.source.to_runtime_source()
    }
}

pub struct ApplicationStorage {
    network_configs: DashMap<Uuid, ApplicationConfig>,
    enabled_networks: DashSet<Uuid>,
    desired_networks: DashSet<Uuid>,
    repository: Option<std::sync::Arc<dyn ConfigRepository>>,
    mutation: std::sync::Mutex<()>,
}
impl ApplicationStorage {
    fn record_running(&self, id: Uuid, running: bool) {
        let _mutation = self.mutation.lock().unwrap();
        if running {
            self.enabled_networks.insert(id);
            self.desired_networks.insert(id);
        } else {
            self.enabled_networks.remove(&id);
            self.desired_networks.remove(&id);
        }
    }

    fn forget(&self, ids: &[Uuid]) {
        let _mutation = self.mutation.lock().unwrap();
        for id in ids {
            self.network_configs.remove(id);
            self.enabled_networks.remove(id);
            self.desired_networks.remove(id);
        }
    }

    fn persist_intent(&self) -> anyhow::Result<()> {
        let _mutation = self.mutation.lock().unwrap();
        if let Some(repository) = &self.repository {
            let configs: Vec<_> = self
                .network_configs
                .iter()
                .map(|v| v.value().clone().into_stored())
                .collect();
            let desired: Vec<_> = self
                .desired_networks
                .iter()
                .map(|v| v.to_string())
                .collect();
            repository.save_configs(&configs)?;
            repository.save_enabled(&desired)?;
        }
        Ok(())
    }
    fn set_enabled<H: ManagementHost>(
        &self,
        app: &H,
        id: Uuid,
        enabled: bool,
    ) -> anyhow::Result<()> {
        let _mutation = self.mutation.lock().unwrap();
        let mut ids: Vec<String> = self
            .enabled_networks
            .iter()
            .filter(|entry| **entry != id)
            .map(|entry| entry.to_string())
            .collect();
        if enabled {
            ids.push(id.to_string());
        }
        if let Some(repository) = &self.repository {
            repository.save_enabled(&ids)?;
        }
        if enabled {
            self.enabled_networks.insert(id);
        } else {
            self.enabled_networks.remove(&id);
        }
        app.emit("save_enabled_networks", ids)
    }

    fn new(repository: Option<std::sync::Arc<dyn ConfigRepository>>) -> Self {
        Self {
            network_configs: DashMap::new(),
            enabled_networks: DashSet::new(),
            desired_networks: DashSet::new(),
            repository,
            mutation: std::sync::Mutex::new(()),
        }
    }

    fn save_configs<H: ManagementHost>(&self, app: &H) -> anyhow::Result<()> {
        let configs = self
            .network_configs
            .iter()
            .map(|entry| entry.value().clone().into_stored())
            .collect::<Vec<_>>();
        app.emit("save_configs", configs)?;
        Ok(())
    }

    fn save_enabled_networks<H: ManagementHost>(&self, app: &H) -> anyhow::Result<()> {
        let payload: Vec<String> = self
            .enabled_networks
            .iter()
            .map(|entry| entry.key().to_string())
            .collect();
        app.emit("save_enabled_networks", payload)?;
        Ok(())
    }

    fn save_config<H: ManagementHost>(
        &self,
        app: &H,
        inst_id: Uuid,
        cfg: NetworkConfig,
        source: PersistedConfigSource,
    ) -> anyhow::Result<()> {
        let _mutation = self.mutation.lock().unwrap();
        let source = self
            .network_configs
            .get(&inst_id)
            .map(|existing| existing.source.merge_persisted(source))
            .unwrap_or(source);
        let config = ApplicationConfig::new(inst_id.to_string(), cfg, source);
        if let Some(repository) = &self.repository {
            let mut configs: Vec<_> = self
                .network_configs
                .iter()
                .filter(|entry| *entry.key() != inst_id)
                .map(|entry| entry.value().clone().into_stored())
                .collect();
            configs.push(config.clone().into_stored());
            repository.save_configs(&configs)?;
        }
        self.network_configs.insert(inst_id, config);
        self.save_configs(app)
    }
}
#[async_trait]
impl<H: ManagementHost> Storage<H, ApplicationConfig, anyhow::Error> for ApplicationStorage {
    async fn insert_or_update_user_network_config(
        &self,
        app: H,
        network_inst_id: Uuid,
        network_config: NetworkConfig,
        source: ConfigSource,
    ) -> Result<(), anyhow::Error> {
        self.save_config(
            &app,
            network_inst_id,
            network_config,
            PersistedConfigSource::from_runtime_source(source),
        )?;
        self.set_enabled(&app, network_inst_id, true)?;
        Ok(())
    }

    async fn delete_network_configs(
        &self,
        app: H,
        network_inst_ids: &[Uuid],
    ) -> Result<(), anyhow::Error> {
        let _mutation = self.mutation.lock().unwrap();
        if let Some(repository) = &self.repository {
            let configs: Vec<_> = self
                .network_configs
                .iter()
                .filter(|entry| !network_inst_ids.contains(entry.key()))
                .map(|entry| entry.value().clone().into_stored())
                .collect();
            repository.save_configs(&configs)?;
        }
        for network_inst_id in network_inst_ids {
            self.network_configs.remove(network_inst_id);
            self.enabled_networks.remove(network_inst_id);
        }
        self.save_configs(&app)?;
        self.save_enabled_networks(&app)?;
        Ok(())
    }

    async fn update_network_config_state(
        &self,
        app: H,
        network_inst_id: Uuid,
        disabled: bool,
    ) -> Result<(), anyhow::Error> {
        self.set_enabled(&app, network_inst_id, !disabled)
    }

    async fn list_network_configs(
        &self,
        _: H,
        props: ListNetworkProps,
    ) -> Result<Vec<ApplicationConfig>, anyhow::Error> {
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
        _: H,
        network_inst_id: &str,
    ) -> Result<Option<ApplicationConfig>, anyhow::Error> {
        let uuid = Uuid::parse_str(network_inst_id)?;
        Ok(self
            .network_configs
            .get(&uuid)
            .map(|entry| entry.value().clone()))
    }
}

pub struct ApplicationClient<H: ManagementHost> {
    host_type: std::marker::PhantomData<H>,
    storage: ApplicationStorage,
    pub rpc_manager: Arc<BidirectRpcManager>,
    control: Arc<dyn InstanceControl>,
    operations: tokio::sync::Mutex<()>,
    last_outcome: std::sync::Mutex<OperationOutcome>,
    runtime_state_known: std::sync::atomic::AtomicBool,
}
impl<H: ManagementHost> ApplicationClient<H> {
    /// Transport reconnects must not reconstruct application state from an older
    /// durable snapshot. The caller holds exclusive access while replacing the
    /// connection, so no operation can retain the previous mutation transport.
    pub fn connect_or_reconnect(
        slot: &mut Option<Self>,
        tunnel: Box<dyn crate::tunnel::Tunnel>,
        repository: Option<Arc<dyn ConfigRepository>>,
    ) -> anyhow::Result<()> {
        if let Some(client) = slot {
            let rpc_manager = Arc::new(BidirectRpcManager::new());
            rpc_manager.run_with_tunnel(tunnel);
            client.control = Arc::new(RpcInstanceControl(rpc_manager.clone()));
            client.rpc_manager = rpc_manager;
            // Keep configurations, desired intent and the last persistence result.
            // Observations from the old endpoint are not proof of current runtime state.
            client
                .runtime_state_known
                .store(false, std::sync::atomic::Ordering::SeqCst);
        } else {
            *slot = Some(Self::new(tunnel, repository)?);
        }
        Ok(())
    }

    pub fn management_status(&self) -> ManagementStatus {
        ManagementStatus {
            running_instances: self.storage.enabled_networks.iter().map(|id| *id).collect(),
            desired_enabled: self.storage.desired_networks.iter().map(|id| *id).collect(),
            runtime_state_known: self
                .runtime_state_known
                .load(std::sync::atomic::Ordering::SeqCst),
            last_outcome: self.last_outcome.lock().unwrap().clone(),
        }
    }

    fn complete(
        &self,
        app: &H,
        runtime_applied: bool,
        effects: Vec<Result<(), String>>,
    ) -> OperationOutcome {
        let mut errors: Vec<_> = effects.into_iter().filter_map(Result::err).collect();
        if !self
            .runtime_state_known
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            errors.push("Runtime state has not been confirmed".into());
        }
        let persistence_warning = self.storage.persist_intent().err().map(|e| e.to_string());
        // Try both view updates, even if one subscriber cannot be reached.
        for effect in [
            self.storage.save_configs(app),
            self.storage.save_enabled_networks(app),
        ] {
            if let Err(error) = effect {
                errors.push(error.to_string());
            }
        }
        let outcome = OperationOutcome {
            runtime_applied,
            persistence_warning,
            reconciliation_warning: if errors.is_empty() {
                None
            } else {
                Some(errors.join("; "))
            },
        };
        *self.last_outcome.lock().unwrap() = outcome.clone();
        if outcome.persistence_warning.is_some() || outcome.reconciliation_warning.is_some() {
            // This is also queryable; event delivery is not the only copy of the warning.
            let _ = app.emit("management_warning", outcome.clone());
        }
        outcome
    }

    async fn reconcile_after_rpc_error(&self, app: &H) {
        match tokio::time::timeout(std::time::Duration::from_secs(5), self.control.running()).await
        {
            Ok(Ok(ids)) => {
                self.runtime_state_known
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                let newly_observed: Vec<_> = ids
                    .iter()
                    .filter(|id| !self.storage.enabled_networks.contains(id))
                    .copied()
                    .collect();
                {
                    let _mutation = self.storage.mutation.lock().unwrap();
                    self.storage.enabled_networks.clear();
                    for id in ids {
                        self.storage.enabled_networks.insert(id);
                    }
                }
                for id in newly_observed {
                    app.observe_instance(id).await;
                }
                // Existing GUI reconciliation re-queries instance configuration and native VPN state.
                let effect = app.emit("vpn_service_stop", "").map_err(|e| e.to_string());
                self.complete(app, false, vec![effect]);
            }
            _ => {
                self.runtime_state_known
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                let outcome = OperationOutcome {
                    runtime_applied: false,
                    persistence_warning: self
                        .last_outcome
                        .lock()
                        .unwrap()
                        .persistence_warning
                        .clone(),
                    reconciliation_warning: Some(
                        "Unable to confirm runtime state after RPC failure".into(),
                    ),
                };
                *self.last_outcome.lock().unwrap() = outcome.clone();
                let _ = app.emit("management_warning", outcome);
            }
        }
    }

    pub async fn run_network(
        &self,
        app: &H,
        config: NetworkConfig,
        source: PersistedConfigSource,
    ) -> Result<OperationOutcome, String> {
        let _operation = self.operations.lock().await;
        if !self
            .runtime_state_known
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.reconcile_after_rpc_error(app).await;
            if !self
                .runtime_state_known
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err("Cannot start another network while runtime state is unknown".into());
            }
        }
        let toml = config.gen_config().map_err(|e| e.to_string())?;
        self.pre_run_network_instance_hook(app, &toml, source)
            .await?;
        self.storage.desired_networks.insert(toml.get_id());
        let request = RunNetworkInstanceRequest {
            inst_id: Some(toml.get_id().into()),
            config: Some(config),
            overwrite: true,
            source: config_source_to_rpc(source.to_runtime_source()),
        };
        match self.control.start(request).await {
            Ok(id) => self.post_run_network_instance_hook(app, &id).await,
            Err(error) => {
                self.reconcile_after_rpc_error(app).await;
                Err(error.to_string())
            }
        }
    }

    async fn stop_confirmed(
        &self,
        app: &H,
        ids: &[Uuid],
        remove_config: bool,
    ) -> Result<OperationOutcome, String> {
        // Disconnect must not depend on a successful config read or disk write.
        if !remove_config {
            for id in ids {
                if !self.storage.network_configs.contains_key(id) {
                    // Preserve a remotely-created profile where possible, but never require
                    // its retrieval or persistence in order to disconnect it.
                    if let Ok(Ok((cfg, source))) = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        self.handle_get_network_config_with_source(app.clone(), *id),
                    )
                    .await
                    {
                        let _mutation = self.storage.mutation.lock().unwrap();
                        self.storage.network_configs.insert(
                            *id,
                            ApplicationConfig::new(
                                id.to_string(),
                                cfg,
                                PersistedConfigSource::from_runtime_source(source),
                            ),
                        );
                    }
                }
            }
        }
        for id in ids {
            self.storage.desired_networks.remove(id);
        }
        if let Err(error) = self.control.stop(ids).await {
            self.reconcile_after_rpc_error(app).await;
            return Err(error.to_string());
        }
        for id in ids {
            self.storage.record_running(*id, false);
        }
        if remove_config {
            self.storage.forget(ids);
        }
        let effect = self.notify_vpn_stop_if_no_tun(app);
        Ok(self.complete(app, true, vec![effect]))
    }

    pub async fn stop_network(
        &self,
        app: &H,
        id: Uuid,
        remove_config: bool,
    ) -> Result<OperationOutcome, String> {
        let _operation = self.operations.lock().await;
        self.stop_confirmed(app, &[id], remove_config).await
    }

    pub async fn enable_network(&self, app: &H, id: Uuid) -> Result<OperationOutcome, String> {
        let (config, source) = self
            .handle_get_network_config_with_source(app.clone(), id)
            .await
            .map_err(|e| e.to_string())?;
        self.run_network(
            app,
            config,
            PersistedConfigSource::from_runtime_source(source),
        )
        .await
    }

    pub async fn save_configuration(&self, app: &H, config: NetworkConfig) -> anyhow::Result<()> {
        let _operation = self.operations.lock().await;
        let id = Uuid::parse_str(config.instance_id())?;
        // Editing a profile is not an instance start/stop operation.
        self.storage
            .save_config(app, id, config, PersistedConfigSource::User)
    }

    pub async fn patch_vpn_portal_clients(
        &self,
        app: H,
        instance_id: Uuid,
        patches: Vec<VpnPortalClientPatch>,
    ) -> anyhow::Result<()> {
        let _operation = self.operations.lock().await;
        self.handle_patch_vpn_portal_clients(app, instance_id, patches)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    pub fn new(
        tunnel: Box<dyn crate::tunnel::Tunnel>,
        repository: Option<std::sync::Arc<dyn ConfigRepository>>,
    ) -> anyhow::Result<Self> {
        let storage = ApplicationStorage::new(repository);
        if let Some(repository) = &storage.repository {
            for id in repository.load_desired_enabled()? {
                storage.desired_networks.insert(Uuid::parse_str(&id)?);
            }
            for stored in repository.load_or_import(&[])? {
                let id = Uuid::parse_str(stored.config.instance_id())?;
                storage.network_configs.insert(
                    id,
                    ApplicationConfig::new(id.to_string(), stored.config, stored.source),
                );
            }
        }
        let rpc_manager = Arc::new(BidirectRpcManager::new());
        rpc_manager.run_with_tunnel(tunnel);

        Ok(Self {
            host_type: std::marker::PhantomData,
            storage,
            control: Arc::new(RpcInstanceControl(rpc_manager.clone())),
            operations: tokio::sync::Mutex::new(()),
            last_outcome: std::sync::Mutex::new(OperationOutcome::default()),
            runtime_state_known: std::sync::atomic::AtomicBool::new(true),
            rpc_manager,
        })
    }

    pub fn get_enabled_instances_with_tun_ids(&self) -> impl Iterator<Item = uuid::Uuid> + '_ {
        self.storage
            .network_configs
            .iter()
            .filter(|v| self.storage.enabled_networks.contains(v.key()))
            .filter(|v| !v.config.no_tun())
            .filter_map(|c| c.config.instance_id().parse::<uuid::Uuid>().ok())
    }

    pub fn get_enabled_instances_with_web_like_tun_ids(
        &self,
    ) -> impl Iterator<Item = uuid::Uuid> + '_ {
        self.storage
            .network_configs
            .iter()
            .filter(|v| self.storage.enabled_networks.contains(v.key()))
            .filter(|v| !v.config.no_tun())
            .filter(|v| v.source.is_web_like())
            .filter_map(|c| c.config.instance_id().parse::<uuid::Uuid>().ok())
    }

    pub async fn disable_instances_with_tun(&self, app: &H, web_only: bool) -> Result<(), String> {
        let inst_ids: Vec<uuid::Uuid> = if web_only {
            self.get_enabled_instances_with_web_like_tun_ids().collect()
        } else {
            self.get_enabled_instances_with_tun_ids().collect()
        };
        for inst_id in inst_ids {
            self.stop_confirmed(app, &[inst_id], false).await?;
        }
        Ok(())
    }

    pub fn notify_vpn_stop_if_no_tun(&self, app: &H) -> Result<(), String> {
        let has_tun = self.get_enabled_instances_with_tun_ids().any(|_| true);
        if !has_tun {
            app.emit("vpn_service_stop", "")
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub async fn pre_run_network_instance_hook(
        &self,
        app: &H,
        cfg: &crate::config::toml::TomlConfigLoader,
        source: PersistedConfigSource,
    ) -> Result<(), String> {
        let instance_id = cfg.get_id();
        // Validate ownership and persist required configuration before any VPN preparation
        // or replacement of an existing instance. Storage failure must leave it untouched.
        if app.single_tun()
            && !cfg.get_flags().no_tun
            && source.is_web_like()
            && self.storage.network_configs.iter().any(|entry| {
                self.storage.enabled_networks.contains(entry.key())
                    && !entry.config.no_tun()
                    && !entry.source.is_web_like()
            })
        {
            return Err(
                "Android only supports one active TUN network; user-managed VPN remains active"
                    .into(),
            );
        }
        self.storage
            .save_config(
                app,
                instance_id,
                NetworkConfig::new_from_config(cfg).map_err(|e| e.to_string())?,
                source,
            )
            .map_err(|e| e.to_string())?;

        if app.single_tun() && !cfg.get_flags().no_tun {
            match source {
                PersistedConfigSource::User | PersistedConfigSource::Legacy => {
                    self.disable_instances_with_tun(app, false)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                PersistedConfigSource::Web => {
                    self.disable_instances_with_tun(app, true)
                        .await
                        .map_err(|e| e.to_string())?;
                    if self.get_enabled_instances_with_tun_ids().next().is_some() {
                        return Err(
                            "Android only supports one active TUN network; user-managed VPN remains active"
                                .to_string(),
                        );
                    }
                }
            }
        }

        if !cfg.get_flags().no_tun {
            app.emit("pre_run_network_instance", instance_id.to_string())
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub async fn post_run_network_instance_hook(
        &self,
        app: &H,
        instance_id: &uuid::Uuid,
    ) -> Result<OperationOutcome, String> {
        self.storage.record_running(*instance_id, true);
        app.observe_instance(*instance_id).await;
        let effect = app
            .emit("post_run_network_instance", instance_id.to_string())
            .map_err(|e| e.to_string());
        Ok(self.complete(app, true, vec![effect]))
    }

    pub async fn post_remote_remove_network_instances_hook(
        &self,
        app: &H,
        ids: &[uuid::Uuid],
    ) -> Result<(), String> {
        // The web client has already removed these instances. Disk failure cannot undo it.
        self.storage.forget(ids);
        let effect = self.notify_vpn_stop_if_no_tun(app);
        self.complete(app, true, vec![effect]);
        Ok(())
    }

    pub async fn post_stop_network_instances_hook(&self, app: &H) -> Result<(), String> {
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

    pub async fn set_logging_level(&self, level: String) -> Result<(), anyhow::Error> {
        let logger_rpc = self
            .get_logger_rpc_client()
            .ok_or_else(|| anyhow::anyhow!("Logger RPC client not available"))?;
        logger_rpc
            .set_logger_config(
                BaseController::default(),
                SetLoggerConfigRequest {
                    level: crate::management::parse_log_level(&level).into(),
                },
            )
            .await?;
        Ok(())
    }

    pub async fn load_configs(
        &self,
        app: H,
        configs: Vec<StoredConfig>,
        enabled_networks: Vec<String>,
    ) -> anyhow::Result<()> {
        let _operation = self.operations.lock().await;
        // Do not replace newer in-memory intent with an older snapshot after a failed write.
        if self
            .last_outcome
            .lock()
            .unwrap()
            .persistence_warning
            .is_some()
        {
            self.storage.persist_intent()?;
            self.last_outcome.lock().unwrap().persistence_warning = None;
        }
        {
            // A concurrent web hook must not persist a half-replaced configuration list.
            // Release this storage lock before the asynchronous instance restoration below.
            let _mutation = self.storage.mutation.lock().unwrap();
            let configs = match &self.storage.repository {
                Some(repository) => repository.load_or_import(&configs)?,
                None => configs,
            };
            // Validate the complete input before replacing the in-memory view.
            for stored in &configs {
                Uuid::parse_str(stored.config.instance_id())?;
            }
            self.storage.network_configs.clear();
            for stored in configs {
                let instance_id = stored.config.instance_id();
                self.storage.network_configs.insert(
                    instance_id.parse()?,
                    ApplicationConfig::new(instance_id.to_string(), stored.config, stored.source),
                );
            }

            self.storage.enabled_networks.clear();
        }
        for id in enabled_networks {
            if let Ok(uuid) = id.parse()
                && !self.storage.enabled_networks.contains(&uuid)
            {
                let config = self
                    .storage
                    .network_configs
                    .get(&uuid)
                    .map(|i| (i.value().config.clone(), i.value().source));
                let Some((config, source)) = config else {
                    continue;
                };
                let toml_config = config.gen_config()?;
                self.pre_run_network_instance_hook(&app, &toml_config, source)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                self.storage.desired_networks.insert(uuid);
                let result = self
                    .control
                    .start(RunNetworkInstanceRequest {
                        inst_id: None,
                        config: Some(config),
                        overwrite: false,
                        source: config_source_to_rpc(source.to_runtime_source()),
                    })
                    .await;
                let running_id = match result {
                    Ok(id) => id,
                    Err(error) => {
                        self.reconcile_after_rpc_error(&app).await;
                        return Err(error);
                    }
                };
                self.post_run_network_instance_hook(&app, &running_id)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
            }
        }
        Ok(())
    }
}
impl<H: ManagementHost> RemoteClientManager<H, ApplicationConfig, anyhow::Error>
    for ApplicationClient<H>
{
    fn get_config_rpc_client(
        &self,
        _: H,
    ) -> Option<Box<dyn ConfigRpc<Controller = BaseController> + Send>> {
        Some(
            self.rpc_manager
                .rpc_client()
                .scoped_client::<ConfigRpcClientFactory<BaseController>>(1, 1, String::new()),
        )
    }

    fn get_rpc_client(
        &self,
        _: H,
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

    fn get_storage(&self) -> &impl Storage<H, ApplicationConfig, anyhow::Error> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_proto::api::manage::NetworkConfig;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct FaultRepository {
        fail_configs: AtomicBool,
        fail_enabled: AtomicBool,
        persisted_enabled: std::sync::Mutex<Vec<String>>,
    }
    impl ConfigRepository for FaultRepository {
        fn load_or_import(&self, legacy: &[StoredConfig]) -> anyhow::Result<Vec<StoredConfig>> {
            Ok(legacy.to_vec())
        }
        fn save_configs(&self, _: &[StoredConfig]) -> anyhow::Result<()> {
            anyhow::ensure!(
                !self.fail_configs.load(Ordering::SeqCst),
                "configuration disk failure"
            );
            Ok(())
        }
        fn save_enabled(&self, ids: &[String]) -> anyhow::Result<()> {
            anyhow::ensure!(
                !self.fail_enabled.load(Ordering::SeqCst),
                "intent disk failure"
            );
            *self.persisted_enabled.lock().unwrap() = ids.to_vec();
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeControl {
        running: std::sync::Mutex<std::collections::HashSet<Uuid>>,
        starts: AtomicUsize,
        stops: AtomicUsize,
        fail_after_start: AtomicBool,
        fail_after_stop: AtomicBool,
        fail_query: AtomicBool,
    }
    #[async_trait]
    impl InstanceControl for FakeControl {
        async fn start(&self, request: RunNetworkInstanceRequest) -> anyhow::Result<Uuid> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            let id = Uuid::parse_str(request.config.unwrap().instance_id())?;
            self.running.lock().unwrap().insert(id);
            anyhow::ensure!(
                !self.fail_after_start.load(Ordering::SeqCst),
                "start response lost"
            );
            Ok(id)
        }
        async fn stop(&self, ids: &[Uuid]) -> anyhow::Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            for id in ids {
                self.running.lock().unwrap().remove(id);
            }
            anyhow::ensure!(
                !self.fail_after_stop.load(Ordering::SeqCst),
                "stop response lost"
            );
            Ok(())
        }
        async fn running(&self) -> anyhow::Result<Vec<Uuid>> {
            anyhow::ensure!(!self.fail_query.load(Ordering::SeqCst), "query unavailable");
            Ok(self.running.lock().unwrap().iter().copied().collect())
        }
    }

    fn fault_client() -> (
        ApplicationClient<TestHost>,
        Arc<FakeControl>,
        Arc<FaultRepository>,
    ) {
        let mut client = client();
        let control = Arc::new(FakeControl::default());
        let repository = Arc::new(FaultRepository::default());
        client.control = control.clone();
        client.storage.repository = Some(repository.clone());
        (client, control, repository)
    }
    fn config() -> NetworkConfig {
        NetworkConfig::new_from_config(&crate::config::toml::TomlConfigLoader::default()).unwrap()
    }

    #[derive(Clone, Default)]
    struct ReconnectBackend {
        data: Arc<std::sync::Mutex<Option<String>>>,
        fail_write: Arc<AtomicBool>,
        fail_read: Arc<AtomicBool>,
    }

    impl super::super::application_snapshot::SnapshotBackend for ReconnectBackend {
        fn read(&self) -> anyhow::Result<Option<String>> {
            anyhow::ensure!(!self.fail_read.load(Ordering::SeqCst), "read unavailable");
            Ok(self.data.lock().unwrap().clone())
        }
        fn write(&self, payload: &str) -> anyhow::Result<()> {
            anyhow::ensure!(!self.fail_write.load(Ordering::SeqCst), "disk unavailable");
            *self.data.lock().unwrap() = Some(payload.to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn reconnect_preserves_failed_deletion_and_warning_until_latest_intent_is_saved() {
        use super::super::application_snapshot::{ApplicationSnapshot, SnapshotRepository};
        use crate::tunnel::ring::create_ring_tunnel_pair;

        let backend = ReconnectBackend::default();
        let removed = config();
        let retained = config();
        let removed_id = Uuid::parse_str(removed.instance_id()).unwrap();
        let retained_id = Uuid::parse_str(retained.instance_id()).unwrap();
        let repository = Arc::new(
            SnapshotRepository::open(
                backend.clone(),
                ApplicationSnapshot {
                    schema_version: 1,
                    configs: vec![
                        StoredConfig {
                            config: removed,
                            source: PersistedConfigSource::User,
                        },
                        StoredConfig {
                            config: retained,
                            source: PersistedConfigSource::Web,
                        },
                    ],
                    desired_enabled: vec![removed_id.to_string(), retained_id.to_string()],
                    profile: serde_json::json!({"mode": "normal"}),
                    selected_network: Some(removed_id.to_string()),
                },
            )
            .unwrap(),
        );
        let mut slot = None;
        let (tunnel, _peer) = create_ring_tunnel_pair();
        ApplicationClient::<TestHost>::connect_or_reconnect(
            &mut slot,
            tunnel,
            Some(repository.clone()),
        )
        .unwrap();
        let host = TestHost::default();
        let client = slot.as_mut().unwrap();
        let control = Arc::new(FakeControl::default());
        control.running.lock().unwrap().insert(removed_id);
        client.control = control.clone();
        client.storage.record_running(removed_id, true);

        backend.fail_write.store(true, Ordering::SeqCst);
        let outcome = client.stop_network(&host, removed_id, true).await.unwrap();
        assert!(outcome.runtime_applied && outcome.persistence_warning.is_some());
        assert!(!control.running.lock().unwrap().contains(&removed_id));
        // The on-disk snapshot really is stale, not a stub that always returns empty.
        assert_eq!(repository.snapshot().unwrap().configs.len(), 2);

        for _ in 0..2 {
            let old_rpc = slot.as_ref().unwrap().rpc_manager.clone();
            let (tunnel, _peer) = create_ring_tunnel_pair();
            backend.fail_read.store(true, Ordering::SeqCst);
            // The GUI uses this exact entry point with the same repository.
            ApplicationClient::connect_or_reconnect(&mut slot, tunnel, Some(repository.clone()))
                .unwrap();
            let client = slot.as_ref().unwrap();
            assert!(!Arc::ptr_eq(&old_rpc, &client.rpc_manager));
            assert!(client.rpc_manager.is_running());
            assert!(!client.storage.network_configs.contains_key(&removed_id));
            assert_eq!(
                client
                    .storage
                    .network_configs
                    .get(&retained_id)
                    .unwrap()
                    .source,
                PersistedConfigSource::Web
            );
            let status = client.management_status();
            assert_eq!(status.desired_enabled, vec![retained_id]);
            assert!(!status.runtime_state_known);
            assert_eq!(
                status.last_outcome.persistence_warning,
                outcome.persistence_warning
            );
            assert!(status.last_outcome.runtime_applied);
            // The frontend reload after reconnect cannot resurrect a failed deletion either.
            assert!(
                client
                    .load_configs(host.clone(), vec![], vec![])
                    .await
                    .is_err()
            );
            assert!(!client.storage.network_configs.contains_key(&removed_id));
            backend.fail_read.store(false, Ordering::SeqCst);
        }
        backend.fail_write.store(false, Ordering::SeqCst);
        let client = slot.as_ref().unwrap();
        client
            .load_configs(host.clone(), vec![], vec![])
            .await
            .unwrap();
        assert!(
            client
                .management_status()
                .last_outcome
                .persistence_warning
                .is_none()
        );
        let persisted = repository.snapshot().unwrap();
        assert_eq!(persisted.configs.len(), 1);
        assert_eq!(
            persisted.configs[0].config.instance_id(),
            retained_id.to_string()
        );
        assert_eq!(persisted.desired_enabled, vec![retained_id.to_string()]);
        assert!(persisted.selected_network.is_none());
        assert_eq!(control.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_start_reconciles_despite_intent_write_failure() {
        let (client, control, repository) = fault_client();
        let host = TestHost::default();
        repository.fail_enabled.store(true, Ordering::SeqCst);
        let cfg = config();
        let id = Uuid::parse_str(cfg.instance_id()).unwrap();
        let outcome = client
            .run_network(&host, cfg, PersistedConfigSource::User)
            .await
            .unwrap();
        assert!(outcome.runtime_applied && outcome.persistence_warning.is_some());
        assert!(control.running.lock().unwrap().contains(&id));
        assert!(client.storage.enabled_networks.contains(&id));
        assert!(
            host.0
                .lock()
                .unwrap()
                .contains(&"post_run_network_instance".into())
        );
        assert!(
            client
                .management_status()
                .last_outcome
                .persistence_warning
                .is_some()
        );
    }

    #[tokio::test]
    async fn storage_failure_cannot_prevent_stop_or_vpn_stop_effect() {
        let (client, control, repository) = fault_client();
        let host = TestHost::default();
        let id = add(&client, PersistedConfigSource::User, false);
        control.running.lock().unwrap().insert(id);
        repository.fail_configs.store(true, Ordering::SeqCst);
        let outcome = client.stop_network(&host, id, false).await.unwrap();
        assert!(outcome.runtime_applied && outcome.persistence_warning.is_some());
        assert_eq!(control.stops.load(Ordering::SeqCst), 1);
        assert!(!client.storage.enabled_networks.contains(&id));
        assert!(!client.storage.desired_networks.contains(&id));
        assert!(host.0.lock().unwrap().contains(&"vpn_service_stop".into()));
    }

    #[tokio::test]
    async fn required_configuration_failure_does_not_replace_old_vpn() {
        let (client, control, repository) = fault_client();
        let host = TestHost::default();
        let old = add(&client, PersistedConfigSource::User, false);
        control.running.lock().unwrap().insert(old);
        repository.fail_configs.store(true, Ordering::SeqCst);
        assert!(
            client
                .run_network(&host, config(), PersistedConfigSource::User)
                .await
                .is_err()
        );
        assert_eq!(control.starts.load(Ordering::SeqCst), 0);
        assert_eq!(control.stops.load(Ordering::SeqCst), 0);
        assert!(client.storage.enabled_networks.contains(&old));
        assert!(
            !host
                .0
                .lock()
                .unwrap()
                .contains(&"pre_run_network_instance".into())
        );
    }

    #[tokio::test]
    async fn deletion_and_web_removal_reconcile_before_disk_errors() {
        for web in [false, true] {
            let (client, control, repository) = fault_client();
            let host = TestHost::default();
            let id = add(&client, PersistedConfigSource::Web, false);
            repository.fail_configs.store(true, Ordering::SeqCst);
            if web {
                client
                    .post_remote_remove_network_instances_hook(&host, &[id])
                    .await
                    .unwrap();
            } else {
                control.running.lock().unwrap().insert(id);
                client.stop_network(&host, id, true).await.unwrap();
            }
            assert!(!client.storage.network_configs.contains_key(&id));
            assert!(!client.storage.enabled_networks.contains(&id));
            assert!(host.0.lock().unwrap().contains(&"vpn_service_stop".into()));
        }
    }

    #[tokio::test]
    async fn lost_rpc_responses_query_actual_state_without_claiming_success() {
        let (client, control, _) = fault_client();
        let host = TestHost::default();
        control.fail_after_start.store(true, Ordering::SeqCst);
        let cfg = config();
        let id = Uuid::parse_str(cfg.instance_id()).unwrap();
        assert!(
            client
                .run_network(&host, cfg, PersistedConfigSource::User)
                .await
                .is_err()
        );
        assert!(client.storage.enabled_networks.contains(&id));
        assert!(!client.management_status().last_outcome.runtime_applied);
        control.fail_after_stop.store(true, Ordering::SeqCst);
        assert!(client.stop_network(&host, id, false).await.is_err());
        assert!(!client.storage.enabled_networks.contains(&id));
    }

    #[tokio::test]
    async fn unknown_rpc_result_is_exposed_as_reconciliation_warning() {
        let (client, control, _) = fault_client();
        let host = TestHost::default();
        control.fail_after_start.store(true, Ordering::SeqCst);
        control.fail_query.store(true, Ordering::SeqCst);
        assert!(
            client
                .run_network(&host, config(), PersistedConfigSource::User)
                .await
                .is_err()
        );
        assert!(
            client
                .management_status()
                .last_outcome
                .reconciliation_warning
                .is_some()
        );
        assert!(!client.management_status().runtime_state_known);
        // A second start cannot use stale single-TUN state, but stop remains available.
        assert!(
            client
                .run_network(&host, config(), PersistedConfigSource::User)
                .await
                .is_err()
        );
        assert_eq!(control.starts.load(Ordering::SeqCst), 1);
        control.fail_query.store(false, Ordering::SeqCst);
        client.reconcile_after_rpc_error(&host).await;
        assert!(client.management_status().runtime_state_known);
    }

    #[tokio::test]
    async fn restoration_also_reconciles_a_lost_start_response() {
        let (client, control, _) = fault_client();
        let cfg = config();
        let id = Uuid::parse_str(cfg.instance_id()).unwrap();
        control.fail_after_start.store(true, Ordering::SeqCst);
        assert!(
            client
                .load_configs(
                    TestHost::default(),
                    vec![StoredConfig {
                        config: cfg,
                        source: PersistedConfigSource::User,
                    }],
                    vec![id.to_string()]
                )
                .await
                .is_err()
        );
        assert!(client.management_status().runtime_state_known);
        assert!(client.management_status().running_instances.contains(&id));
    }

    #[tokio::test]
    async fn reload_cannot_discard_unpersisted_runtime_changes() {
        let (client, _, repository) = fault_client();
        let host = TestHost::default();
        let id = add(&client, PersistedConfigSource::User, false);
        repository.fail_enabled.store(true, Ordering::SeqCst);
        client.stop_network(&host, id, false).await.unwrap();
        assert!(client.load_configs(host, vec![], vec![]).await.is_err());
        assert!(client.storage.network_configs.contains_key(&id));
        assert!(client.management_status().desired_enabled.is_empty());
    }

    #[tokio::test]
    async fn later_flush_uses_latest_stop_intent_not_failed_start_intent() {
        let (client, _, repository) = fault_client();
        let host = TestHost::default();
        repository.fail_enabled.store(true, Ordering::SeqCst);
        let cfg = config();
        let id = Uuid::parse_str(cfg.instance_id()).unwrap();
        client
            .run_network(&host, cfg, PersistedConfigSource::User)
            .await
            .unwrap();
        client.stop_network(&host, id, false).await.unwrap();
        repository.fail_enabled.store(false, Ordering::SeqCst);
        client.complete(&host, false, vec![]);
        assert!(repository.persisted_enabled.lock().unwrap().is_empty());
        assert!(
            client
                .management_status()
                .last_outcome
                .persistence_warning
                .is_none()
        );
    }

    #[tokio::test]
    async fn failed_event_delivery_does_not_hide_success_or_persistence_warning() {
        let (client, _, repository) = fault_client();
        let host = TestHost::default();
        let id = add(&client, PersistedConfigSource::User, false);
        host.1.store(true, Ordering::SeqCst);
        repository.fail_enabled.store(true, Ordering::SeqCst);
        let outcome = client.stop_network(&host, id, false).await.unwrap();
        assert!(outcome.runtime_applied);
        assert!(outcome.persistence_warning.is_some());
        assert!(outcome.reconciliation_warning.is_some());
        assert!(client.management_status().running_instances.is_empty());
        assert!(
            client
                .management_status()
                .last_outcome
                .persistence_warning
                .is_some()
        );
    }

    #[tokio::test]
    async fn stopping_no_tun_with_disk_failure_keeps_other_vpn() {
        let (client, _, repository) = fault_client();
        let host = TestHost::default();
        let vpn = add(&client, PersistedConfigSource::User, false);
        let no_tun = add(&client, PersistedConfigSource::Web, true);
        repository.fail_enabled.store(true, Ordering::SeqCst);
        client.stop_network(&host, no_tun, false).await.unwrap();
        assert!(client.storage.enabled_networks.contains(&vpn));
        assert!(!host.0.lock().unwrap().contains(&"vpn_service_stop".into()));
    }

    #[derive(Clone, Default)]
    struct TestHost(
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        Arc<AtomicBool>,
    );
    #[async_trait]
    impl ManagementHost for TestHost {
        fn emit<S: serde::Serialize + Clone>(&self, event: &str, _: S) -> anyhow::Result<()> {
            self.0.lock().unwrap().push(event.to_owned());
            anyhow::ensure!(!self.1.load(Ordering::SeqCst), "event delivery failed");
            Ok(())
        }
        fn single_tun(&self) -> bool {
            true
        }
        async fn observe_instance(&self, _: Uuid) {}
    }
    fn client() -> ApplicationClient<TestHost> {
        let rpc_manager = Arc::new(BidirectRpcManager::new());
        ApplicationClient {
            host_type: std::marker::PhantomData,
            storage: ApplicationStorage::new(None),
            control: Arc::new(RpcInstanceControl(rpc_manager.clone())),
            rpc_manager,
            operations: tokio::sync::Mutex::new(()),
            last_outcome: std::sync::Mutex::new(OperationOutcome::default()),
            runtime_state_known: std::sync::atomic::AtomicBool::new(true),
        }
    }
    fn add(
        client: &ApplicationClient<TestHost>,
        source: PersistedConfigSource,
        no_tun: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();
        client.storage.network_configs.insert(
            id,
            ApplicationConfig::new(
                id.to_string(),
                NetworkConfig {
                    instance_id: Some(id.to_string()),
                    no_tun: Some(no_tun),
                    ..Default::default()
                },
                source,
            ),
        );
        client.storage.enabled_networks.insert(id);
        client.storage.desired_networks.insert(id);
        id
    }
    #[tokio::test]
    async fn tun_candidates_exclude_no_tun_and_preserve_provenance() {
        let client = client();
        let user = add(&client, PersistedConfigSource::User, false);
        let web = add(&client, PersistedConfigSource::Web, false);
        add(&client, PersistedConfigSource::Web, true);
        add(&client, PersistedConfigSource::User, true);
        let ids: Vec<_> = client.get_enabled_instances_with_tun_ids().collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&user));
        assert!(ids.contains(&web));
        assert_eq!(
            client
                .get_enabled_instances_with_web_like_tun_ids()
                .collect::<Vec<_>>(),
            vec![web]
        );
    }
    #[tokio::test]
    async fn managed_tun_cannot_displace_user_or_legacy_tun() {
        for source in [PersistedConfigSource::User, PersistedConfigSource::Legacy] {
            let client = client();
            let host = TestHost::default();
            let id = add(&client, source, false);
            let cfg = crate::config::toml::TomlConfigLoader::default();
            let error = client
                .pre_run_network_instance_hook(&host, &cfg, PersistedConfigSource::Web)
                .await
                .unwrap_err();
            assert!(error.contains("user-managed VPN remains active"));
            assert!(client.storage.enabled_networks.contains(&id));
        }
    }
    #[tokio::test]
    async fn no_tun_start_coexists_with_user_vpn_without_stop_rpc() {
        let client = client();
        let host = TestHost::default();
        let id = add(&client, PersistedConfigSource::User, false);
        let cfg = crate::config::toml::TomlConfigLoader::default();
        let mut flags = cfg.get_flags();
        flags.no_tun = true;
        cfg.set_flags(flags);
        client
            .pre_run_network_instance_hook(&host, &cfg, PersistedConfigSource::Web)
            .await
            .unwrap();
        assert!(client.storage.enabled_networks.contains(&id));
        assert_eq!(client.storage.network_configs.len(), 2);
    }
    #[tokio::test]
    async fn stop_effect_depends_on_tun_not_no_tun_instances() {
        let client = client();
        let host = TestHost::default();
        add(&client, PersistedConfigSource::User, true);
        client.notify_vpn_stop_if_no_tun(&host).unwrap();
        assert_eq!(*host.0.lock().unwrap(), vec!["vpn_service_stop"]);
        host.0.lock().unwrap().clear();
        add(&client, PersistedConfigSource::User, false);
        client.notify_vpn_stop_if_no_tun(&host).unwrap();
        assert!(host.0.lock().unwrap().is_empty());
    }

    #[test]
    fn stored_gui_config_defaults_missing_source_to_legacy() {
        let stored: StoredConfig = serde_json::from_value(serde_json::json!({
            "config": NetworkConfig::default(),
        }))
        .unwrap();
        assert_eq!(stored.source, PersistedConfigSource::Legacy);
    }

    #[test]
    fn stored_gui_config_deserializes_webhook_source_as_web() {
        let stored: StoredConfig = serde_json::from_value(serde_json::json!({
            "config": NetworkConfig::default(),
            "source": "webhook",
        }))
        .unwrap();
        assert_eq!(stored.source, PersistedConfigSource::Web);
    }

    #[test]
    fn stored_gui_config_defaults_unknown_source_to_legacy() {
        let stored: StoredConfig = serde_json::from_value(serde_json::json!({
            "config": NetworkConfig::default(),
            "source": "unknown",
        }))
        .unwrap();
        assert_eq!(stored.source, PersistedConfigSource::Legacy);
    }

    #[test]
    fn persisted_source_merge_keeps_legacy_and_web_over_ambiguous_user() {
        assert_eq!(
            PersistedConfigSource::Legacy.merge_persisted(PersistedConfigSource::User),
            PersistedConfigSource::Legacy
        );
        assert_eq!(
            PersistedConfigSource::Web.merge_persisted(PersistedConfigSource::User),
            PersistedConfigSource::Web
        );
        assert_eq!(
            PersistedConfigSource::Legacy.merge_persisted(PersistedConfigSource::Web),
            PersistedConfigSource::Web
        );
    }

    #[test]
    fn only_web_configs_are_web_like() {
        assert!(!PersistedConfigSource::Legacy.is_web_like());
        assert!(!PersistedConfigSource::User.is_web_like());
        assert!(PersistedConfigSource::Web.is_web_like());
    }
}
