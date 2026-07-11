use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

const DEFAULT_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

#[async_trait]
pub trait PublicIpv6ProviderHost: Send + Sync + 'static {
    fn should_run(&self) -> bool;

    async fn prepare(&self);

    /// Applies an explicit configuration change without running periodic
    /// host maintenance such as NDP synchronization.
    async fn apply_config(&self) -> bool;

    /// Reconciles native provider state. Returns `false` when the host has
    /// disappeared and the background task should exit.
    async fn reconcile(&self) -> bool;

    /// Waits for a host-side state change that requires an immediate retry.
    /// Returns `false` when the event source has closed.
    async fn wait_for_change(&self) -> bool;

    fn cleanup(&self);
}

struct PublicIpv6ProviderTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

pub struct PublicIpv6ProviderService {
    host: Arc<dyn PublicIpv6ProviderHost>,
    reconcile_interval: Duration,
    reconcile: Mutex<()>,
    task: Mutex<Option<PublicIpv6ProviderTask>>,
    closing: AtomicBool,
}

impl PublicIpv6ProviderService {
    pub fn new(host: Arc<dyn PublicIpv6ProviderHost>) -> Arc<Self> {
        Self::new_with_interval(host, DEFAULT_RECONCILE_INTERVAL)
    }

    fn new_with_interval(
        host: Arc<dyn PublicIpv6ProviderHost>,
        reconcile_interval: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            host,
            reconcile_interval,
            reconcile: Mutex::new(()),
            task: Mutex::new(None),
            closing: AtomicBool::new(false),
        })
    }

    pub async fn reconcile_now(&self) -> bool {
        let _reconcile = self.reconcile.lock().await;
        self.host.reconcile().await
    }

    pub async fn apply_config(&self) -> bool {
        let _reconcile = self.reconcile.lock().await;
        self.host.apply_config().await
    }

    pub async fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().await;
        if self.closing.load(Ordering::Acquire) || task.is_some() || !self.host.should_run() {
            return;
        }

        self.host.prepare().await;
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let service = Arc::downgrade(self);
        let host = self.host.clone();
        let handle = tokio::spawn(async move {
            Self::run(service, host, task_cancel).await;
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
    }

    async fn run(
        service: Weak<Self>,
        host: Arc<dyn PublicIpv6ProviderHost>,
        cancel: CancellationToken,
    ) {
        loop {
            let Some(service) = service.upgrade() else {
                host.cleanup();
                return;
            };
            if !service.reconcile_now().await {
                service.host.cleanup();
                return;
            }

            let interval = service.reconcile_interval;
            drop(service);
            let should_continue = tokio::select! {
                _ = cancel.cancelled() => false,
                _ = tokio::time::sleep(interval) => true,
                changed = host.wait_for_change() => changed,
            };
            if !should_continue {
                host.cleanup();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    #[derive(Default)]
    struct RecordingHost {
        enabled: AtomicBool,
        reconcile_calls: AtomicUsize,
        cleanup_calls: AtomicUsize,
        change: Notify,
    }

    #[async_trait]
    impl PublicIpv6ProviderHost for RecordingHost {
        fn should_run(&self) -> bool {
            self.enabled.load(Ordering::Acquire)
        }

        async fn reconcile(&self) -> bool {
            self.reconcile_calls.fetch_add(1, Ordering::AcqRel);
            true
        }

        async fn apply_config(&self) -> bool {
            true
        }

        async fn prepare(&self) {}

        async fn wait_for_change(&self) -> bool {
            self.change.notified().await;
            true
        }

        fn cleanup(&self) {
            self.cleanup_calls.fetch_add(1, Ordering::AcqRel);
        }
    }

    async fn wait_for_calls(counter: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
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
        let service =
            PublicIpv6ProviderService::new_with_interval(host.clone(), Duration::from_secs(60));

        service.start().await;
        assert_eq!(host.reconcile_calls.load(Ordering::Acquire), 0);

        host.enabled.store(true, Ordering::Release);
        service.start().await;
        wait_for_calls(&host.reconcile_calls, 1).await;
        host.change.notify_one();
        wait_for_calls(&host.reconcile_calls, 2).await;

        service.stop().await;
        assert_eq!(host.cleanup_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn does_not_restart_after_stop() {
        let host = Arc::new(RecordingHost::default());
        host.enabled.store(true, Ordering::Release);
        let service =
            PublicIpv6ProviderService::new_with_interval(host.clone(), Duration::from_secs(60));

        service.stop().await;
        service.start().await;

        assert_eq!(host.reconcile_calls.load(Ordering::Acquire), 0);
        assert_eq!(host.cleanup_calls.load(Ordering::Acquire), 0);
    }
}
