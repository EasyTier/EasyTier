use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

use easytier_proto::{
    rpc_types::controller::BaseController,
    web::{
        DeviceOsInfo, GetFeatureRequest, GetFeatureResponse, HeartbeatRequest,
        WebServerServiceClientFactory,
    },
};
use tokio::{sync::Mutex, task::JoinSet, time::interval};
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    connectivity::protocol::raw::TunnelDialer,
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
    rpc::{bidirect::BidirectRpcManager, service_registry::ServiceRegistry},
    tunnel::{Tunnel, web_security},
};

use super::{
    ConfigFileStorage, DaemonGuard, InstanceMutationHooks, LoggerControl, ManagedInstanceSet,
    register_management_rpc,
};

const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const FEATURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Normalized config-server endpoint and authentication token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigServerEndpoint {
    connect_url: Url,
    token: String,
}

impl ConfigServerEndpoint {
    pub fn parse(input: &str, supports_scheme: impl FnOnce(&Url) -> bool) -> anyhow::Result<Self> {
        let endpoint = match Url::parse(input) {
            Ok(endpoint) => endpoint,
            Err(_) => format!("udp://config-server.easytier.cn:22020/{input}")
                .parse()
                .map_err(|error| anyhow::anyhow!("failed to parse config server URL: {error}"))?,
        };
        if !supports_scheme(&endpoint) {
            anyhow::bail!("unsupported config server scheme: {}", endpoint.scheme());
        }

        let token = endpoint
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .map(|segment| percent_encoding::percent_decode_str(segment).decode_utf8())
            .transpose()
            .map_err(|error| anyhow::anyhow!("failed to decode config server token: {error}"))?
            .map(|token| token.to_string())
            .unwrap_or_default();
        if token.is_empty() {
            anyhow::bail!("empty token");
        }

        let mut connect_url = endpoint;
        if !matches!(connect_url.scheme(), "ws" | "wss") {
            connect_url.set_path("");
        }
        Ok(Self { connect_url, token })
    }

    pub fn connect_url(&self) -> &Url {
        &self.connect_url
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

pub struct WebClientConfig {
    pub token: String,
    pub machine_id: uuid::Uuid,
    pub hostname: String,
    pub device_os: DeviceOsInfo,
    pub easytier_version: String,
    pub secure_mode: bool,
}

struct WebClientController<F, H>
where
    F: InstanceFactory,
{
    config: WebClientConfig,
    instances: Arc<ManagedInstanceSet<F>>,
    hooks: Arc<dyn InstanceMutationHooks>,
    storage: Arc<dyn ConfigFileStorage>,
    logger: Arc<dyn LoggerControl>,
    host: std::marker::PhantomData<fn() -> H>,
}

impl<F, H> WebClientController<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    fn register_management_entry(&self, registry: &ServiceRegistry) {
        register_management_rpc(
            self.instances.clone(),
            registry,
            self.hooks.clone(),
            self.storage.clone(),
            self.logger.clone(),
        );
    }
}

/// Portable config-server client. Hosts only supply identity and adapters.
pub struct WebClient<F, H>
where
    F: InstanceFactory,
{
    _controller: Arc<WebClientController<F, H>>,
    _tasks: AbortOnDropHandle<()>,
    _manager_guard: DaemonGuard,
    connected: Arc<AtomicBool>,
}

impl<F, H> WebClient<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn new<T: TunnelDialer + 'static>(
        connector: T,
        config: WebClientConfig,
        instances: Arc<ManagedInstanceSet<F>>,
        hooks: Arc<dyn InstanceMutationHooks>,
        storage: Arc<dyn ConfigFileStorage>,
        logger: Arc<dyn LoggerControl>,
    ) -> Self {
        let manager_guard = instances.register_daemon();
        let controller = Arc::new(WebClientController {
            config,
            instances,
            hooks,
            storage,
            logger,
            host: std::marker::PhantomData,
        });
        let connected = Arc::new(AtomicBool::new(false));
        let tasks = AbortOnDropHandle::new(tokio::spawn(Self::routine(
            controller.clone(),
            connected.clone(),
            Box::new(connector),
        )));

        Self {
            _controller: controller,
            _tasks: tasks,
            _manager_guard: manager_guard,
            connected,
        }
    }

    async fn routine(
        controller: Arc<WebClientController<F, H>>,
        connected: Arc<AtomicBool>,
        connector: Box<dyn TunnelDialer>,
    ) {
        loop {
            let connection = match connector.connect().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "failed to connect to config server; retrying");
                    tokio::time::sleep(RETRY_INTERVAL).await;
                    continue;
                }
            };

            connected.store(true, Ordering::Release);
            tracing::info!(?connection, "connected to config server");
            let mut session = WebClientSession::new(connection, controller.clone());
            let support_encryption =
                match tokio::time::timeout(FEATURE_TIMEOUT, session.get_feature()).await {
                    Ok(Ok(feature)) => feature.support_encryption,
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "GetFeature RPC failed; using legacy tunnel");
                        false
                    }
                    Err(_) => {
                        tracing::warn!("GetFeature RPC timed out; using legacy tunnel");
                        false
                    }
                };

            if support_encryption && web_security::web_secure_tunnel_supported() {
                drop(session);
                let connection = match connector.connect().await {
                    Ok(connection) => connection,
                    Err(error) => {
                        connected.store(false, Ordering::Release);
                        tracing::warn!(%error, "failed to reconnect secure config-server tunnel");
                        tokio::time::sleep(RETRY_INTERVAL).await;
                        continue;
                    }
                };
                let connection = match web_security::upgrade_client_tunnel(connection).await {
                    Ok(connection) => connection,
                    Err(error) => {
                        connected.store(false, Ordering::Release);
                        tracing::warn!(%error, "config-server secure handshake failed");
                        tokio::time::sleep(RETRY_INTERVAL).await;
                        continue;
                    }
                };
                let mut session = WebClientSession::new(connection, controller.clone());
                session.start_heartbeat().await;
                session.wait().await;
                connected.store(false, Ordering::Release);
                continue;
            }

            if support_encryption {
                if controller.config.secure_mode {
                    connected.store(false, Ordering::Release);
                    tracing::warn!(
                        "secure mode requires web secure-tunnel support in the local build"
                    );
                    tokio::time::sleep(RETRY_INTERVAL).await;
                    continue;
                }
                tracing::warn!(
                    "server supports encryption but the local build is using a legacy tunnel"
                );
            }
            if controller.config.secure_mode {
                connected.store(false, Ordering::Release);
                tracing::warn!("secure mode requires config-server encryption support");
                tokio::time::sleep(RETRY_INTERVAL).await;
                continue;
            }

            session.start_heartbeat().await;
            session.wait().await;
            connected.store(false, Ordering::Release);
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}

struct WebClientSession<F, H>
where
    F: InstanceFactory,
{
    rpc: BidirectRpcManager,
    controller: Arc<WebClientController<F, H>>,
    heartbeat_started: AtomicBool,
    tasks: Mutex<JoinSet<()>>,
}

impl<F, H> WebClientSession<F, H>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    fn new(tunnel: Box<dyn Tunnel>, controller: Arc<WebClientController<F, H>>) -> Self {
        let rpc = BidirectRpcManager::new();
        rpc.run_with_tunnel(tunnel);
        controller.register_management_entry(rpc.rpc_server().registry());
        Self {
            rpc,
            controller,
            heartbeat_started: AtomicBool::new(false),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub async fn start_heartbeat(&self) {
        if self.heartbeat_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut tasks = self.tasks.lock().await;
        Self::heartbeat_routine(&self.rpc, Arc::downgrade(&self.controller), &mut tasks);
    }

    fn heartbeat_routine(
        rpc: &BidirectRpcManager,
        controller: Weak<WebClientController<F, H>>,
        tasks: &mut JoinSet<()>,
    ) {
        let controller = controller.upgrade().expect("web client controller");
        let machine_id = controller.config.machine_id;
        let session_id = uuid::Uuid::new_v4();
        let token = controller.config.token.clone();
        let hostname = controller.config.hostname.clone();
        let device_os = controller.config.device_os.clone();
        let easytier_version = controller.config.easytier_version.clone();
        let controller = Arc::downgrade(&controller);
        let client = rpc
            .rpc_client()
            .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, String::new());
        let mut tick = interval(std::time::Duration::from_secs(1));

        tasks.spawn(async move {
            loop {
                tick.tick().await;
                let Some(controller) = controller.upgrade() else {
                    break;
                };
                let request = HeartbeatRequest {
                    machine_id: Some(machine_id.into()),
                    inst_id: Some(session_id.into()),
                    user_token: token.clone(),
                    easytier_version: easytier_version.clone(),
                    hostname: hostname.clone(),
                    report_time: chrono::Local::now().to_rfc3339(),
                    device_os: Some(device_os.clone()),
                    support_config_source: true,
                    running_network_instances: controller
                        .instances
                        .instance_ids()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                };

                match client.heartbeat(BaseController::default(), request).await {
                    Ok(response) => {
                        tracing::debug!(?response, "config-server heartbeat response");
                    }
                    Err(error) => {
                        tracing::error!(?error, "config-server heartbeat failed");
                        break;
                    }
                }
            }
        });
    }

    async fn wait_routines(&self) {
        self.tasks.lock().await.join_next().await;
        self.tasks.lock().await.abort_all();
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.rpc.wait() => {}
            _ = self.wait_routines() => {}
        }
    }

    async fn get_feature(
        &self,
    ) -> Result<GetFeatureResponse, easytier_proto::rpc_types::error::Error> {
        let client = self
            .rpc
            .rpc_client()
            .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, String::new());
        client
            .get_feature(BaseController::default(), GetFeatureRequest {})
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_normalizes_shorthand_and_non_websocket_paths() {
        let endpoint = ConfigServerEndpoint::parse("team%2Ftoken", |_| true).unwrap();
        assert_eq!(endpoint.token(), "team/token");
        assert_eq!(
            endpoint.connect_url().as_str(),
            "udp://config-server.easytier.cn:22020"
        );
    }

    #[test]
    fn endpoint_preserves_websocket_path_and_validates_scheme() {
        let endpoint =
            ConfigServerEndpoint::parse("wss://example.com/team", |url| url.scheme() == "wss")
                .unwrap();
        assert_eq!(endpoint.token(), "team");
        assert_eq!(endpoint.connect_url().as_str(), "wss://example.com/team");

        let error =
            ConfigServerEndpoint::parse("unknown://example.com/team", |_| false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported config server scheme")
        );
    }

    #[test]
    fn endpoint_rejects_an_empty_token() {
        assert!(ConfigServerEndpoint::parse("udp://example.com", |_| true).is_err());
    }
}
