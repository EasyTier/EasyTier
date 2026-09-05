use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use easytier_proto::{
    rpc_types::controller::BaseController,
    web::{
        DeviceOsInfo, GetFeatureRequest, GetFeatureResponse, HeartbeatRequest, HeartbeatResponse,
        WebServerServiceClientFactory,
    },
};
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    connectivity::protocol::raw::TunnelDialer,
    foundation::time,
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
    rpc::{bidirect::BidirectRpcManager, service_registry::ServiceRegistry},
    tunnel::{Tunnel, web_security},
};

#[cfg(not(feature = "management"))]
use super::register_web_client_rpc;
use super::{ConfigFileStorage, DaemonGuard, InstanceManager, InstanceMutationHooks};
#[cfg(feature = "management")]
use super::{LoggerControl, register_management_rpc};

const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
// Keep retry ownership in this loop when transport or protocol handshakes stall.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const FEATURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const DEFAULT_HEARTBEAT_INTERVAL_MS: u32 = 3_500;
const DEFAULT_HEARTBEAT_TIMEOUT_MS: u32 = 15_000;
const MIN_HEARTBEAT_INTERVAL_MS: u32 = 1_000;
const MAX_HEARTBEAT_INTERVAL_MS: u32 = 60_000;
const MIN_HEARTBEAT_TIMEOUT_MS: u32 = 5_000;
const MAX_HEARTBEAT_TIMEOUT_MS: u32 = 120_000;
const MIN_HEARTBEAT_TIMEOUT_MARGIN_MS: u32 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeartbeatPolicy {
    interval: std::time::Duration,
    timeout_ms: i32,
}

impl Default for HeartbeatPolicy {
    fn default() -> Self {
        Self {
            interval: std::time::Duration::from_millis(DEFAULT_HEARTBEAT_INTERVAL_MS.into()),
            timeout_ms: DEFAULT_HEARTBEAT_TIMEOUT_MS as i32,
        }
    }
}

impl HeartbeatPolicy {
    fn from_response(response: &HeartbeatResponse) -> (Self, bool) {
        let requested_interval = response
            .heartbeat_interval_ms
            .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_MS);
        let requested_timeout = response
            .heartbeat_timeout_ms
            .unwrap_or(DEFAULT_HEARTBEAT_TIMEOUT_MS);
        let interval_ms =
            requested_interval.clamp(MIN_HEARTBEAT_INTERVAL_MS, MAX_HEARTBEAT_INTERVAL_MS);
        let timeout_ms = requested_timeout
            .clamp(MIN_HEARTBEAT_TIMEOUT_MS, MAX_HEARTBEAT_TIMEOUT_MS)
            .max(interval_ms.saturating_add(MIN_HEARTBEAT_TIMEOUT_MARGIN_MS));
        (
            Self {
                interval: std::time::Duration::from_millis(interval_ms.into()),
                timeout_ms: timeout_ms as i32,
            },
            interval_ms != requested_interval || timeout_ms != requested_timeout,
        )
    }

    fn controller(self) -> BaseController {
        BaseController {
            timeout_ms: self.timeout_ms,
            ..Default::default()
        }
    }

    fn remaining_interval(self, elapsed: std::time::Duration) -> Option<std::time::Duration> {
        self.interval
            .checked_sub(elapsed)
            .filter(|delay| !delay.is_zero())
    }
}

async fn connect_config_server(
    connector: &dyn TunnelDialer,
    timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn Tunnel>> {
    time::timeout(timeout, connector.connect())
        .await
        .map_err(|_| anyhow::anyhow!("config-server connection timed out after {timeout:?}"))?
}

/// Normalized config-server endpoint and authentication token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigServerEndpoint {
    connect_url: Url,
    token: String,
}

impl ConfigServerEndpoint {
    pub fn parse(input: &str, supports_scheme: impl FnOnce(&Url) -> bool) -> anyhow::Result<Self> {
        let endpoint = Url::parse(input)
            .map_err(|error| anyhow::anyhow!("failed to parse config server URL: {error}"))?;
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

#[async_trait]
pub(crate) trait WebClientBackend: Send + Sync + 'static {
    fn register(&self, registry: &ServiceRegistry);

    async fn instance_ids(&self) -> anyhow::Result<Vec<uuid::Uuid>>;

    fn failed_instance_ids(&self) -> Vec<uuid::Uuid>;

    fn instance_state_generation(&self) -> usize {
        0
    }

    async fn wait_for_instance_state_change(&self, _generation: usize) -> usize {
        std::future::pending().await
    }
}

struct NativeWebClientBackend<F>
where
    F: InstanceFactory,
{
    instances: Arc<InstanceManager<F>>,
    hooks: Arc<dyn InstanceMutationHooks>,
    storage: Arc<dyn ConfigFileStorage>,
    #[cfg(feature = "management")]
    logger: Arc<dyn LoggerControl>,
}

#[async_trait]
impl<F, H> WebClientBackend for NativeWebClientBackend<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    fn register(&self, registry: &ServiceRegistry) {
        #[cfg(feature = "management")]
        register_management_rpc(
            self.instances.clone(),
            registry,
            self.hooks.clone(),
            self.storage.clone(),
            self.logger.clone(),
        );
        #[cfg(not(feature = "management"))]
        register_web_client_rpc(
            self.instances.clone(),
            registry,
            self.hooks.clone(),
            self.storage.clone(),
        );
    }

    async fn instance_ids(&self) -> anyhow::Result<Vec<uuid::Uuid>> {
        Ok(self.instances.instance_ids())
    }

    fn failed_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instances.failed_instance_ids()
    }

    fn instance_state_generation(&self) -> usize {
        self.instances.instance_state_generation()
    }

    async fn wait_for_instance_state_change(&self, generation: usize) -> usize {
        self.instances
            .wait_for_instance_state_change(generation)
            .await
    }
}

struct WebClientController {
    config: WebClientConfig,
    backend: Arc<dyn WebClientBackend>,
}

/// Portable config-server client. Hosts only supply identity and adapters.
pub struct WebClient<F> {
    _controller: Arc<WebClientController>,
    _tasks: AbortOnDropHandle<()>,
    _manager_guard: Option<DaemonGuard>,
    connected: Arc<AtomicBool>,
    _factory: std::marker::PhantomData<F>,
}

impl<F, H> WebClient<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn new<T: TunnelDialer + 'static>(
        connector: T,
        config: WebClientConfig,
        instances: Arc<InstanceManager<F>>,
        hooks: Arc<dyn InstanceMutationHooks>,
        storage: Arc<dyn ConfigFileStorage>,
        #[cfg(feature = "management")] logger: Arc<dyn LoggerControl>,
    ) -> Self {
        let manager_guard = instances.register_daemon();
        let backend = Arc::new(NativeWebClientBackend {
            instances,
            hooks,
            storage,
            #[cfg(feature = "management")]
            logger,
        });
        Self::start(connector, config, backend, Some(manager_guard))
    }
}

#[cfg(target_os = "wasi")]
impl WebClient<()> {
    pub(crate) fn with_backend<T: TunnelDialer + 'static>(
        connector: T,
        config: WebClientConfig,
        backend: Arc<dyn WebClientBackend>,
    ) -> Self {
        Self::start(connector, config, backend, None)
    }
}

impl<F> WebClient<F> {
    fn start<T: TunnelDialer + 'static>(
        connector: T,
        config: WebClientConfig,
        backend: Arc<dyn WebClientBackend>,
        manager_guard: Option<DaemonGuard>,
    ) -> Self {
        let controller = Arc::new(WebClientController { config, backend });
        let connected = Arc::new(AtomicBool::new(false));
        let tasks = AbortOnDropHandle::new(tokio::spawn(web_client_routine(
            controller.clone(),
            connected.clone(),
            Box::new(connector),
        )));

        Self {
            _controller: controller,
            _tasks: tasks,
            _manager_guard: manager_guard,
            connected,
            _factory: std::marker::PhantomData,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}

async fn web_client_routine(
    controller: Arc<WebClientController>,
    connected: Arc<AtomicBool>,
    connector: Box<dyn TunnelDialer>,
) {
    loop {
        let connection = match connect_config_server(connector.as_ref(), CONNECT_TIMEOUT).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "failed to connect to config server; retrying");
                time::sleep(RETRY_INTERVAL).await;
                continue;
            }
        };

        connected.store(true, Ordering::Release);
        tracing::info!(?connection, "connected to config server");
        let mut session = WebClientSession::new(connection, controller.clone());
        let support_encryption = match time::timeout(FEATURE_TIMEOUT, session.get_feature()).await {
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
            let connection = match connect_config_server(connector.as_ref(), CONNECT_TIMEOUT).await
            {
                Ok(connection) => connection,
                Err(error) => {
                    connected.store(false, Ordering::Release);
                    tracing::warn!(%error, "failed to reconnect secure config-server tunnel");
                    time::sleep(RETRY_INTERVAL).await;
                    continue;
                }
            };
            let connection = match web_security::upgrade_client_tunnel(connection).await {
                Ok(connection) => connection,
                Err(error) => {
                    connected.store(false, Ordering::Release);
                    tracing::warn!(%error, "config-server secure handshake failed");
                    time::sleep(RETRY_INTERVAL).await;
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
                tracing::warn!("secure mode requires web secure-tunnel support in the local build");
                time::sleep(RETRY_INTERVAL).await;
                continue;
            }
            tracing::warn!(
                "server supports encryption but the local build is using a legacy tunnel"
            );
        }
        if controller.config.secure_mode {
            connected.store(false, Ordering::Release);
            tracing::warn!("secure mode requires config-server encryption support");
            time::sleep(RETRY_INTERVAL).await;
            continue;
        }

        session.start_heartbeat().await;
        session.wait().await;
        connected.store(false, Ordering::Release);
    }
}

struct WebClientSession {
    rpc: BidirectRpcManager,
    controller: Arc<WebClientController>,
    heartbeat_started: AtomicBool,
    tasks: Mutex<JoinSet<()>>,
}

fn build_heartbeat_request(
    config: &WebClientConfig,
    session_id: uuid::Uuid,
    running_network_instances: Vec<uuid::Uuid>,
    failed_network_instances: Vec<uuid::Uuid>,
) -> HeartbeatRequest {
    HeartbeatRequest {
        machine_id: Some(config.machine_id.into()),
        inst_id: Some(session_id.into()),
        user_token: config.token.clone(),
        easytier_version: config.easytier_version.clone(),
        hostname: config.hostname.clone(),
        report_time: chrono::Local::now().to_rfc3339(),
        device_os: Some(config.device_os.clone()),
        support_config_source: true,
        running_network_instances: running_network_instances
            .into_iter()
            .map(Into::into)
            .collect(),
        failed_network_instances: failed_network_instances
            .into_iter()
            .map(Into::into)
            .collect(),
        support_heartbeat_policy: true,
    }
}

async fn wait_for_next_heartbeat(
    backend: &dyn WebClientBackend,
    observed_generation: usize,
    policy: HeartbeatPolicy,
    elapsed: std::time::Duration,
) {
    let Some(delay) = policy.remaining_interval(elapsed) else {
        return;
    };
    tokio::select! {
        _ = time::sleep(delay) => {}
        _ = backend.wait_for_instance_state_change(observed_generation) => {}
    }
}

impl WebClientSession {
    fn new(tunnel: Box<dyn Tunnel>, controller: Arc<WebClientController>) -> Self {
        let rpc = BidirectRpcManager::new();
        rpc.run_with_tunnel(tunnel);
        controller.backend.register(rpc.rpc_server().registry());
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
        controller: Weak<WebClientController>,
        tasks: &mut JoinSet<()>,
    ) {
        let controller = controller.upgrade().expect("web client controller");
        let session_id = uuid::Uuid::new_v4();
        let controller = Arc::downgrade(&controller);
        let client = rpc
            .rpc_client()
            .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, String::new());

        tasks.spawn(async move {
            let mut heartbeat_policy = HeartbeatPolicy::default();
            loop {
                let heartbeat_started_at = std::time::Instant::now();
                let Some(controller) = controller.upgrade() else {
                    break;
                };
                let observed_generation = controller.backend.instance_state_generation();
                let running_network_instances = match controller.backend.instance_ids().await {
                    Ok(instance_ids) => instance_ids,
                    Err(error) => {
                        tracing::error!(%error, "failed to list config-server instances");
                        break;
                    }
                };
                let request = build_heartbeat_request(
                    &controller.config,
                    session_id,
                    running_network_instances,
                    controller.backend.failed_instance_ids(),
                );

                match client
                    .heartbeat(heartbeat_policy.controller(), request)
                    .await
                {
                    Ok(response) => {
                        tracing::debug!(?response, "config-server heartbeat response");
                        let (next_policy, adjusted) = HeartbeatPolicy::from_response(&response);
                        if adjusted {
                            tracing::warn!(
                                requested_interval_ms = ?response.heartbeat_interval_ms,
                                requested_timeout_ms = ?response.heartbeat_timeout_ms,
                                applied_interval_ms = next_policy.interval.as_millis(),
                                applied_timeout_ms = next_policy.timeout_ms,
                                "config-server heartbeat policy was outside safe bounds"
                            );
                        }
                        heartbeat_policy = next_policy;
                        wait_for_next_heartbeat(
                            controller.backend.as_ref(),
                            observed_generation,
                            heartbeat_policy,
                            heartbeat_started_at.elapsed(),
                        )
                        .await;
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
    use std::{
        future::pending,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;

    use super::*;
    use crate::tunnel::ring::create_ring_tunnel_pair;

    struct StalledThenReadyDialer {
        attempts: AtomicUsize,
    }

    struct ImmediateStateChangeBackend;

    #[async_trait]
    impl WebClientBackend for ImmediateStateChangeBackend {
        fn register(&self, _registry: &ServiceRegistry) {}

        async fn instance_ids(&self) -> anyhow::Result<Vec<uuid::Uuid>> {
            Ok(Vec::new())
        }

        fn failed_instance_ids(&self) -> Vec<uuid::Uuid> {
            Vec::new()
        }

        async fn wait_for_instance_state_change(&self, generation: usize) -> usize {
            generation.wrapping_add(1)
        }
    }

    #[async_trait]
    impl TunnelDialer for StalledThenReadyDialer {
        async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
            if self.attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                return pending().await;
            }

            let (tunnel, _peer) = create_ring_tunnel_pair();
            Ok(tunnel)
        }

        fn remote_url(&self) -> Url {
            "ring://config-server".parse().unwrap()
        }
    }

    #[tokio::test]
    async fn stalled_connection_attempt_times_out_and_allows_redial() {
        let connector = StalledThenReadyDialer {
            attempts: AtomicUsize::new(0),
        };

        let error = connect_config_server(&connector, std::time::Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("connection timed out"));

        connect_config_server(&connector, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn instance_state_change_interrupts_a_long_heartbeat_interval() {
        let policy = HeartbeatPolicy {
            interval: std::time::Duration::from_secs(60),
            timeout_ms: 65_000,
        };

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_next_heartbeat(
                &ImmediateStateChangeBackend,
                0,
                policy,
                std::time::Duration::ZERO,
            ),
        )
        .await
        .expect("instance state change must wake heartbeat before its interval");
    }

    #[test]
    fn endpoint_normalizes_non_websocket_paths() {
        let endpoint =
            ConfigServerEndpoint::parse("udp://example.com/team%2Ftoken", |_| true).unwrap();
        assert_eq!(endpoint.token(), "team/token");
        assert_eq!(endpoint.connect_url().as_str(), "udp://example.com");
    }

    #[test]
    fn endpoint_rejects_token_shorthand() {
        let error = ConfigServerEndpoint::parse("team%2Ftoken", |_| true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("failed to parse config server URL")
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

    #[test]
    fn heartbeat_request_carries_registered_and_failed_instance_ids() {
        let registered = uuid::Uuid::new_v4();
        let failed = uuid::Uuid::new_v4();
        let request = build_heartbeat_request(
            &WebClientConfig {
                token: "token".to_owned(),
                machine_id: uuid::Uuid::new_v4(),
                hostname: "host".to_owned(),
                device_os: DeviceOsInfo::default(),
                easytier_version: "test-version".to_owned(),
                secure_mode: false,
            },
            uuid::Uuid::new_v4(),
            vec![registered],
            vec![failed],
        );

        assert_eq!(
            request
                .running_network_instances
                .into_iter()
                .map(uuid::Uuid::from)
                .collect::<Vec<_>>(),
            vec![registered]
        );
        assert_eq!(
            request
                .failed_network_instances
                .into_iter()
                .map(uuid::Uuid::from)
                .collect::<Vec<_>>(),
            vec![failed]
        );
        assert!(request.support_heartbeat_policy);
    }

    #[test]
    fn heartbeat_policy_uses_safe_defaults_for_legacy_servers() {
        let (policy, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse::default());

        assert!(!adjusted);
        assert_eq!(
            policy.interval,
            std::time::Duration::from_millis(DEFAULT_HEARTBEAT_INTERVAL_MS.into())
        );
        assert_eq!(policy.timeout_ms, DEFAULT_HEARTBEAT_TIMEOUT_MS as i32);
    }

    #[test]
    fn heartbeat_policy_clamps_server_values_and_preserves_timeout_margin() {
        let (minimum, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse {
            heartbeat_interval_ms: Some(1),
            heartbeat_timeout_ms: Some(1),
        });
        assert!(adjusted);
        assert_eq!(
            minimum.interval,
            std::time::Duration::from_millis(MIN_HEARTBEAT_INTERVAL_MS.into())
        );
        assert_eq!(minimum.timeout_ms, 6_000);

        let (maximum, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse {
            heartbeat_interval_ms: Some(u32::MAX),
            heartbeat_timeout_ms: Some(u32::MAX),
        });
        assert!(adjusted);
        assert_eq!(
            maximum.interval,
            std::time::Duration::from_millis(MAX_HEARTBEAT_INTERVAL_MS.into())
        );
        assert_eq!(maximum.timeout_ms, MAX_HEARTBEAT_TIMEOUT_MS as i32);

        let (margin, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse {
            heartbeat_interval_ms: Some(60_000),
            heartbeat_timeout_ms: Some(5_000),
        });
        assert!(adjusted);
        assert_eq!(margin.timeout_ms, 65_000);
    }
}
