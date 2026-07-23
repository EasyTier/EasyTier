use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use cidr::Ipv6Cidr;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    config::peers::PublicIpv6ProviderConfig,
    config::runtime::CoreRuntimeConfigStore,
    peers::public_ipv6::{
        CorePublicIpv6Runtime, PublicIpv6ProviderResolution, resolve_public_ipv6_provider,
    },
};

const DEFAULT_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_CONFIG_RETRIES: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIpv6NdpTarget {
    pub wan_interface: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicIpv6PlatformObservation {
    pub detected_prefix: Option<Ipv6Cidr>,
    pub ndp_target: Option<PublicIpv6NdpTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIpv6NdpDesired {
    pub prefix: Ipv6Cidr,
    pub target: PublicIpv6NdpTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicIpv6ProviderState {
    Disabled,
    Pending(String),
    Active {
        prefix: Ipv6Cidr,
        ndp_target: Option<PublicIpv6NdpTarget>,
    },
}

impl PublicIpv6ProviderState {
    fn from_resolution(
        resolution: PublicIpv6ProviderResolution,
        ndp_target: Option<PublicIpv6NdpTarget>,
    ) -> Self {
        match resolution {
            PublicIpv6ProviderResolution::Disabled => Self::Disabled,
            PublicIpv6ProviderResolution::Pending(error) => Self::Pending(error),
            PublicIpv6ProviderResolution::Active(prefix) => Self::Active { prefix, ndp_target },
        }
    }

    fn advertised_prefix(&self) -> Option<Ipv6Cidr> {
        match self {
            Self::Active { prefix, .. } => Some(*prefix),
            Self::Disabled | Self::Pending(_) => None,
        }
    }

    fn ndp_desired(&self) -> Option<PublicIpv6NdpDesired> {
        match self {
            Self::Active {
                prefix,
                ndp_target: Some(target),
            } => Some(PublicIpv6NdpDesired {
                prefix: *prefix,
                target: target.clone(),
            }),
            Self::Disabled | Self::Pending(_) | Self::Active { .. } => None,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PublicIpv6PlatformError {
    #[error("public IPv6 platform adapter is unavailable")]
    Unavailable,
    #[error("{0}")]
    Failed(String),
}

#[async_trait]
pub trait PublicIpv6ProviderPlatform: Send + Sync + 'static {
    fn inspect(
        &self,
        config: PublicIpv6ProviderConfig,
    ) -> Result<PublicIpv6PlatformObservation, PublicIpv6PlatformError>;

    fn sync_ndp(
        &self,
        desired: Option<PublicIpv6NdpDesired>,
    ) -> Result<(), PublicIpv6PlatformError>;

    /// Waits for a platform state change that requires an immediate retry.
    /// Returns `false` when the event source has closed.
    async fn wait_for_change(&self) -> bool;
}

struct PublicIpv6ProviderTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

pub struct PublicIpv6ProviderService {
    platform: Arc<dyn PublicIpv6ProviderPlatform>,
    runtime_config: CoreRuntimeConfigStore,
    runtime: Arc<CorePublicIpv6Runtime>,
    reconcile_interval: Duration,
    reconcile: Mutex<()>,
    last_state: std::sync::Mutex<Option<PublicIpv6ProviderState>>,
    task: Mutex<Option<PublicIpv6ProviderTask>>,
    closing: AtomicBool,
}

impl PublicIpv6ProviderService {
    pub fn new(
        platform: Arc<dyn PublicIpv6ProviderPlatform>,
        runtime_config: CoreRuntimeConfigStore,
        runtime: Arc<CorePublicIpv6Runtime>,
    ) -> Arc<Self> {
        Self::new_with_interval(
            platform,
            runtime_config,
            runtime,
            DEFAULT_RECONCILE_INTERVAL,
        )
    }

    fn new_with_interval(
        platform: Arc<dyn PublicIpv6ProviderPlatform>,
        runtime_config: CoreRuntimeConfigStore,
        runtime: Arc<CorePublicIpv6Runtime>,
        reconcile_interval: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            platform,
            runtime_config,
            runtime,
            reconcile_interval,
            reconcile: Mutex::new(()),
            last_state: std::sync::Mutex::new(None),
            task: Mutex::new(None),
            closing: AtomicBool::new(false),
        })
    }

    pub async fn reconcile_now(&self) -> bool {
        let _reconcile = self.reconcile.lock().await;
        if self.closing.load(Ordering::Acquire) {
            return false;
        }
        for attempt in 0..MAX_CONFIG_RETRIES {
            let config = self.runtime_config.snapshot().services.public_ipv6_provider;
            let observation = if config.provider_enabled && config.provider_supported {
                match self.platform.inspect(config) {
                    Ok(observation) => Ok(observation),
                    Err(PublicIpv6PlatformError::Unavailable) => return false,
                    Err(PublicIpv6PlatformError::Failed(error)) => Err(error),
                }
            } else {
                Ok(PublicIpv6PlatformObservation::default())
            };
            let (detected_prefix, ndp_target) = match observation {
                Ok(observation) => (Ok(observation.detected_prefix), observation.ndp_target),
                Err(error) => (Err(error), None),
            };
            let next_state = PublicIpv6ProviderState::from_resolution(
                resolve_public_ipv6_provider(config, detected_prefix),
                ndp_target,
            );

            if self.runtime_config.snapshot().services.public_ipv6_provider != config {
                tracing::debug!(
                    attempt = attempt + 1,
                    max_retries = MAX_CONFIG_RETRIES,
                    "public IPv6 provider config changed during reconcile, retrying"
                );
                continue;
            }

            let changed = self
                .runtime
                .set_provider_prefix(next_state.advertised_prefix());
            if let Err(error) = self.platform.sync_ndp(next_state.ndp_desired()) {
                match error {
                    PublicIpv6PlatformError::Unavailable => return false,
                    PublicIpv6PlatformError::Failed(error) => {
                        tracing::warn!(%error, "failed to synchronize public IPv6 NDP state");
                    }
                }
            }
            self.log_state_change(&next_state, changed);
            *self.last_state.lock().unwrap() = Some(next_state);
            return true;
        }

        tracing::warn!(
            max_retries = MAX_CONFIG_RETRIES,
            "skipping public IPv6 provider reconcile because config kept changing"
        );
        true
    }

    pub async fn apply_config(&self) -> bool {
        self.reconcile_now().await
    }

    pub async fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().await;
        let config = self.runtime_config.snapshot().services.public_ipv6_provider;
        if self.closing.load(Ordering::Acquire) || task.is_some() || !config.should_run_reconcile()
        {
            return;
        }

        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let service = Arc::downgrade(self);
        let platform = self.platform.clone();
        let handle = tokio::spawn(async move {
            Self::run(service, platform, task_cancel).await;
        });
        task.replace(PublicIpv6ProviderTask { cancel, handle });
    }

    pub async fn stop(&self) {
        self.closing.store(true, Ordering::Release);
        let task = self.task.lock().await.take();
        if let Some(task) = task {
            task.cancel.cancel();
            if let Err(error) = task.handle.await {
                tracing::warn!(?error, "public IPv6 provider task failed during shutdown");
            }
        }
        let _reconcile = self.reconcile.lock().await;
        if let Err(error) = self.platform.sync_ndp(None)
            && !matches!(error, PublicIpv6PlatformError::Unavailable)
        {
            tracing::warn!(%error, "failed to clean public IPv6 NDP state during shutdown");
        }
    }

    fn log_state_change(&self, next_state: &PublicIpv6ProviderState, changed: bool) {
        let last_state = self.last_state.lock().unwrap();
        if last_state.as_ref() != Some(next_state) {
            match next_state {
                PublicIpv6ProviderState::Disabled if last_state.is_some() => {
                    tracing::info!("public IPv6 provider disabled");
                }
                PublicIpv6ProviderState::Disabled => {}
                PublicIpv6ProviderState::Pending(reason) => {
                    tracing::warn!(%reason, "public IPv6 provider not ready");
                }
                PublicIpv6ProviderState::Active { prefix, ndp_target } => {
                    if let Some(target) = ndp_target {
                        tracing::info!(
                            %prefix,
                            wan_interface = %target.wan_interface,
                            "public IPv6 provider is active with NDP proxy"
                        );
                    } else {
                        tracing::info!(%prefix, "public IPv6 provider is active");
                    }
                }
            }
        } else if changed {
            tracing::info!("public IPv6 provider runtime state changed");
        }
    }

    async fn run(
        service: Weak<Self>,
        platform: Arc<dyn PublicIpv6ProviderPlatform>,
        cancel: CancellationToken,
    ) {
        loop {
            let Some(service) = service.upgrade() else {
                let _ = platform.sync_ndp(None);
                return;
            };
            if !service.reconcile_now().await {
                let _ = service.platform.sync_ndp(None);
                return;
            }

            let interval = service.reconcile_interval;
            drop(service);
            let should_continue = tokio::select! {
                _ = cancel.cancelled() => false,
                _ = crate::foundation::time::sleep(interval) => true,
                changed = platform.wait_for_change() => changed,
            };
            if !should_continue {
                let _ = platform.sync_ndp(None);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::Notify;

    use super::*;
    use crate::{
        config::peers::PeerRuntimeSnapshot,
        config::runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
        peers::context::PeerPublicIpv6State,
    };

    struct RecordingHost {
        observation: StdMutex<Result<PublicIpv6PlatformObservation, PublicIpv6PlatformError>>,
        inspect_calls: AtomicUsize,
        ndp_desired: StdMutex<Vec<Option<PublicIpv6NdpDesired>>>,
        change: Notify,
    }

    impl Default for RecordingHost {
        fn default() -> Self {
            Self {
                observation: StdMutex::new(Ok(PublicIpv6PlatformObservation::default())),
                inspect_calls: AtomicUsize::new(0),
                ndp_desired: StdMutex::new(Vec::new()),
                change: Notify::new(),
            }
        }
    }

    #[async_trait]
    impl PublicIpv6ProviderPlatform for RecordingHost {
        fn inspect(
            &self,
            _config: PublicIpv6ProviderConfig,
        ) -> Result<PublicIpv6PlatformObservation, PublicIpv6PlatformError> {
            self.inspect_calls.fetch_add(1, Ordering::AcqRel);
            self.observation.lock().unwrap().clone()
        }

        async fn wait_for_change(&self) -> bool {
            self.change.notified().await;
            true
        }

        fn sync_ndp(
            &self,
            desired: Option<PublicIpv6NdpDesired>,
        ) -> Result<(), PublicIpv6PlatformError> {
            self.ndp_desired.lock().unwrap().push(desired);
            Ok(())
        }
    }

    fn provider_config(enabled: bool, prefix: Option<Ipv6Cidr>) -> PublicIpv6ProviderConfig {
        PublicIpv6ProviderConfig {
            provider_enabled: enabled,
            configured_prefix: prefix,
            provider_supported: true,
        }
    }

    fn runtime_config(config: PublicIpv6ProviderConfig) -> CoreRuntimeConfigStore {
        let services = CoreRuntimeConfig {
            public_ipv6_provider: config,
            ..Default::default()
        };
        CoreRuntimeConfigStore::new(services, Arc::new(PeerRuntimeSnapshot::default()))
    }

    fn runtime(
        config: PublicIpv6ProviderConfig,
    ) -> (CoreRuntimeConfigStore, Arc<CorePublicIpv6Runtime>) {
        let config = runtime_config(config);
        let runtime = CorePublicIpv6Runtime::new(config.clone(), Arc::new(()));
        (config, runtime)
    }

    async fn wait_for_calls(counter: &AtomicUsize, expected: usize) {
        crate::foundation::time::timeout(Duration::from_secs(1), async {
            while counter.load(Ordering::Acquire) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn starts_only_when_enabled_and_reacts_to_host_changes() {
        let host = Arc::new(RecordingHost::default());
        let (runtime_config, runtime) = runtime(provider_config(false, None));
        let service = PublicIpv6ProviderService::new_with_interval(
            host.clone(),
            runtime_config.clone(),
            runtime,
            Duration::from_secs(60),
        );

        service.start().await;
        assert_eq!(host.inspect_calls.load(Ordering::Acquire), 0);

        runtime_config.update_services(|services| {
            services.public_ipv6_provider =
                provider_config(true, Some("2001:db8::/48".parse().unwrap()));
        });
        service.start().await;
        wait_for_calls(&host.inspect_calls, 1).await;
        host.change.notify_one();
        wait_for_calls(&host.inspect_calls, 2).await;

        service.stop().await;
        assert_eq!(host.ndp_desired.lock().unwrap().last(), Some(&None));
    }

    #[tokio::test]
    async fn does_not_reconcile_or_restart_after_stop() {
        let host = Arc::new(RecordingHost::default());
        let (runtime_config, runtime) = runtime(provider_config(
            true,
            Some("2001:db8::/48".parse().unwrap()),
        ));
        let service = PublicIpv6ProviderService::new_with_interval(
            host.clone(),
            runtime_config,
            runtime,
            Duration::from_secs(60),
        );

        service.stop().await;
        assert!(!service.reconcile_now().await);
        service.start().await;

        assert_eq!(host.inspect_calls.load(Ordering::Acquire), 0);
        assert_eq!(host.ndp_desired.lock().unwrap().as_slice(), &[None]);
    }

    #[tokio::test]
    async fn resolves_observation_and_publishes_ndp_desired_state() {
        let host = Arc::new(RecordingHost::default());
        let prefix = "2001:db8::/48".parse().unwrap();
        let target = PublicIpv6NdpTarget {
            wan_interface: "wan0".to_owned(),
        };
        *host.observation.lock().unwrap() = Ok(PublicIpv6PlatformObservation {
            detected_prefix: Some(prefix),
            ndp_target: Some(target.clone()),
        });
        let (runtime_config, runtime) = runtime(provider_config(true, None));
        let service = PublicIpv6ProviderService::new(host.clone(), runtime_config, runtime.clone());

        assert!(service.reconcile_now().await);

        assert_eq!(runtime.advertised_ipv6_public_addr_prefix(), Some(prefix));
        assert!(runtime.public_ipv6_provider_enabled());
        assert_eq!(
            host.ndp_desired.lock().unwrap().as_slice(),
            &[Some(PublicIpv6NdpDesired { prefix, target })]
        );
    }

    #[tokio::test]
    async fn turns_platform_failure_into_pending_provider_state() {
        let host = Arc::new(RecordingHost::default());
        *host.observation.lock().unwrap() = Err(PublicIpv6PlatformError::Failed(
            "route query failed".to_owned(),
        ));
        let (runtime_config, runtime) = runtime(provider_config(true, None));
        let service = PublicIpv6ProviderService::new(host.clone(), runtime_config, runtime.clone());

        assert!(service.reconcile_now().await);

        assert_eq!(runtime.advertised_ipv6_public_addr_prefix(), None);
        assert!(!runtime.public_ipv6_provider_enabled());
        assert_eq!(host.ndp_desired.lock().unwrap().as_slice(), &[None]);
    }

    struct ReconfiguringHost {
        runtime_config: CoreRuntimeConfigStore,
        replacement: PublicIpv6ProviderConfig,
        inspect_calls: AtomicUsize,
    }

    #[async_trait]
    impl PublicIpv6ProviderPlatform for ReconfiguringHost {
        fn inspect(
            &self,
            _config: PublicIpv6ProviderConfig,
        ) -> Result<PublicIpv6PlatformObservation, PublicIpv6PlatformError> {
            if self.inspect_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                self.runtime_config.update_services(|services| {
                    services.public_ipv6_provider = self.replacement;
                });
            }
            Ok(PublicIpv6PlatformObservation::default())
        }

        fn sync_ndp(
            &self,
            _desired: Option<PublicIpv6NdpDesired>,
        ) -> Result<(), PublicIpv6PlatformError> {
            Ok(())
        }

        async fn wait_for_change(&self) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn retries_when_config_changes_during_platform_inspection() {
        let first = provider_config(true, Some("2001:db8:1::/48".parse().unwrap()));
        let replacement = provider_config(true, Some("2001:db8:2::/48".parse().unwrap()));
        let (runtime_config, runtime) = runtime(first);
        let host = Arc::new(ReconfiguringHost {
            runtime_config: runtime_config.clone(),
            replacement,
            inspect_calls: AtomicUsize::new(0),
        });
        let service = PublicIpv6ProviderService::new(host.clone(), runtime_config, runtime.clone());

        assert!(service.reconcile_now().await);

        assert_eq!(host.inspect_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            runtime.advertised_ipv6_public_addr_prefix(),
            replacement.configured_prefix
        );
    }
}
