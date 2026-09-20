//! Application-level network ownership and configuration rules, independent of any UI host.
use crate::config::api_input::{NetworkConfig, NetworkConfigExt};
use crate::config::toml::{ConfigLoader, ConfigSource};
use crate::management::config_source_to_rpc;
use crate::management::remote_client::PersistentConfig;
use crate::management::remote_client::{ListNetworkProps, RemoteClientManager, Storage};
use crate::rpc::bidirect::BidirectRpcManager;
use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use easytier_proto::api::logger::{LoggerRpc, LoggerRpcClientFactory, SetLoggerConfigRequest};
use easytier_proto::api::manage::RunNetworkInstanceRequest;
use easytier_proto::api::manage::{WebClientService, WebClientServiceClientFactory};
use easytier_proto::rpc_types::controller::BaseController;
use uuid::Uuid;

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
    repository: Option<std::sync::Arc<dyn ConfigRepository>>,
    mutation: std::sync::Mutex<()>,
}
impl ApplicationStorage {
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
    pub rpc_manager: BidirectRpcManager,
}
impl<H: ManagementHost> ApplicationClient<H> {
    pub fn new(
        tunnel: Box<dyn crate::tunnel::Tunnel>,
        repository: Option<std::sync::Arc<dyn ConfigRepository>>,
    ) -> anyhow::Result<Self> {
        let storage = ApplicationStorage::new(repository);
        if let Some(repository) = &storage.repository {
            for stored in repository.load_or_import(&[])? {
                let id = Uuid::parse_str(stored.config.instance_id())?;
                storage.network_configs.insert(
                    id,
                    ApplicationConfig::new(id.to_string(), stored.config, stored.source),
                );
            }
        }
        let rpc_manager = BidirectRpcManager::new();
        rpc_manager.run_with_tunnel(tunnel);

        Ok(Self {
            host_type: std::marker::PhantomData,
            storage,
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

    pub async fn disable_instances_with_tun(
        &self,
        app: &H,
        web_only: bool,
    ) -> Result<(), crate::management::remote_client::RemoteClientError<anyhow::Error>> {
        let inst_ids: Vec<uuid::Uuid> = if web_only {
            self.get_enabled_instances_with_web_like_tun_ids().collect()
        } else {
            self.get_enabled_instances_with_tun_ids().collect()
        };
        for inst_id in inst_ids {
            self.handle_update_network_state(app.clone(), inst_id, true)
                .await?;
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
        app.emit("pre_run_network_instance", instance_id.to_string())
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

        self.storage
            .save_config(
                app,
                instance_id,
                NetworkConfig::new_from_config(cfg).map_err(|e| e.to_string())?,
                source,
            )
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn post_run_network_instance_hook(
        &self,
        app: &H,
        instance_id: &uuid::Uuid,
    ) -> Result<(), String> {
        app.observe_instance(*instance_id).await;

        self.storage
            .set_enabled(app, *instance_id, true)
            .map_err(|e| e.to_string())?;

        app.emit("post_run_network_instance", instance_id.to_string())
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn post_remote_remove_network_instances_hook(
        &self,
        app: &H,
        ids: &[uuid::Uuid],
    ) -> Result<(), String> {
        self.storage
            .delete_network_configs(app.clone(), ids)
            .await
            .map_err(|e| e.to_string())?;
        self.notify_vpn_stop_if_no_tun(app)?;
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
        let client = self
            .get_rpc_client(app.clone())
            .ok_or_else(|| anyhow::anyhow!("RPC client not found"))?;
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
                client
                    .run_network_instance(
                        BaseController::default(),
                        RunNetworkInstanceRequest {
                            inst_id: None,
                            config: Some(config),
                            overwrite: false,
                            source: config_source_to_rpc(source.to_runtime_source()),
                        },
                    )
                    .await?;
                self.post_run_network_instance_hook(&app, &uuid)
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

    #[derive(Clone, Default)]
    struct TestHost(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    #[async_trait]
    impl ManagementHost for TestHost {
        fn emit<S: serde::Serialize + Clone>(&self, event: &str, _: S) -> anyhow::Result<()> {
            self.0.lock().unwrap().push(event.to_owned());
            Ok(())
        }
        fn single_tun(&self) -> bool {
            true
        }
        async fn observe_instance(&self, _: Uuid) {}
    }
    fn client() -> ApplicationClient<TestHost> {
        ApplicationClient {
            host_type: std::marker::PhantomData,
            storage: ApplicationStorage::new(None),
            rpc_manager: BidirectRpcManager::new(),
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
