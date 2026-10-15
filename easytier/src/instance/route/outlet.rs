use std::{
    future::{Future, IntoFuture},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, Weak},
};

use registry::Registry;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{common::netns::NetNS, instance::shared_virtual_nic::SharedVirtualNic};

use super::{
    CleanupIncomplete, PlatformRouteBackend, RouteMgr,
    device::TunDeviceState,
    scope::{RouteInput, RouteScope, RouteScopeLease},
};

type RouteJoinResult = Result<Result<(), CleanupIncomplete>, tokio::task::JoinError>;
type RouteCleanupTask = guarden::task::DetachableTaskFuture<
    guarden::task::TokioHandle,
    dyn Future<Output = RouteJoinResult> + Send,
>;

fn observe_route_task(task: JoinHandle<Result<(), CleanupIncomplete>>) -> RouteCleanupTask {
    let observer: Pin<Box<dyn Future<Output = RouteJoinResult> + Send>> = Box::pin(async move {
        let result = task.await;
        match &result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(?error, "incomplete route outlet cleanup"),
            Err(error) => tracing::warn!(?error, "route outlet task failed"),
        }
        result
    });
    guarden::task::DetachableTask::from_boxed(guarden::task::TokioHandle::default(), observer)
        .into_future()
}

/// One logical NIC owns one writer, independently of its members' runtimes.
/// The writer retains facts and input scopes, never the TUN or a strong NIC ref.
pub(crate) struct RouteOutlet {
    pub devices: Arc<TunDeviceState>,
    inputs: Registry<RouteInput>,
    net_ns: NetNS,
    nic_changes: watch::Sender<u64>,
    cancel: CancellationToken,
    mgr_task: Mutex<Option<RouteCleanupTask>>,
}

impl RouteOutlet {
    pub fn new(net_ns: NetNS) -> Self {
        Self {
            devices: TunDeviceState::new(Arc::new(StdMutex::new(None))),
            inputs: Registry::default(),
            net_ns,
            nic_changes: watch::channel(0).0,
            cancel: CancellationToken::new(),
            mgr_task: Mutex::new(None),
        }
    }

    pub async fn start(&self, nic: Weak<Mutex<SharedVirtualNic>>) -> anyhow::Result<()> {
        let mut task = self.mgr_task.lock().await;
        if task.is_some() {
            return Ok(());
        }
        anyhow::ensure!(!self.cancel.is_cancelled(), "route outlet is closed");
        let backend = PlatformRouteBackend::new(self.net_ns.clone()).await?;
        let manager = RouteMgr::new(
            self.devices.clone(),
            backend,
            self.inputs.clone(),
            self.nic_changes.subscribe(),
            self.cancel.clone(),
        )
        .with_nic(nic);
        *task = Some(observe_route_task(tokio::spawn(manager.run())));
        Ok(())
    }

    pub fn attach(
        &self,
        scope: &RouteScope,
        member_registration: uuid::Uuid,
    ) -> anyhow::Result<RouteScopeLease> {
        scope.attach(&self.inputs, self.devices.clone(), member_registration)
    }

    pub fn invalidate_routes(&self) {
        self.nic_changes.send_modify(|revision| {
            *revision = revision
                .checked_add(1)
                .expect("NIC route revision exhausted")
        });
    }

    pub fn request_shutdown(&self) {
        for input in self.inputs.snapshot() {
            input.revoke();
        }
        self.inputs.close();
        self.cancel.cancel();
    }

    #[cfg(test)]
    async fn wait_for_cleanup(&self, deadline: tokio::time::Instant) -> Option<RouteJoinResult> {
        self.request_shutdown();
        let mut slot = tokio::time::timeout_at(deadline, self.mgr_task.lock())
            .await
            .ok()?;
        let task = slot.as_mut()?;
        match tokio::time::timeout_at(deadline, task).await {
            Ok(result) => {
                slot.take();
                Some(result)
            }
            Err(_) => None,
        }
    }
}

impl Drop for RouteOutlet {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    use tokio::sync::Notify;

    fn runtime() -> RouteOutlet {
        RouteOutlet::new(NetNS::new(None))
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_preserves_ownership_and_completion_is_consumed_once() {
        let runtime = runtime();
        let release = Arc::new(Notify::new());
        let task_release = release.clone();
        let task = tokio::spawn(async move {
            task_release.notified().await;
            Ok(())
        });
        *runtime.mgr_task.lock().await = Some(observe_route_task(task));
        assert!(
            runtime
                .wait_for_cleanup(tokio::time::Instant::now() + Duration::from_millis(20))
                .await
                .is_none()
        );
        assert!(runtime.mgr_task.lock().await.is_some());
        release.notify_one();
        let result = runtime
            .wait_for_cleanup(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(result, Ok(Ok(()))));
        assert!(runtime.mgr_task.lock().await.is_none());
        assert!(
            runtime
                .wait_for_cleanup(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_includes_waiting_for_the_task_slot() {
        let runtime = runtime();
        let held = runtime.mgr_task.lock().await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        assert!(runtime.wait_for_cleanup(deadline).await.is_none());
        assert_eq!(tokio::time::Instant::now(), deadline);
        assert!(runtime.cancel.is_cancelled());
        drop(held);
    }

    #[tokio::test]
    async fn task_failure_is_not_reported_as_success() {
        let runtime = runtime();
        *runtime.mgr_task.lock().await = Some(observe_route_task(tokio::spawn(async {
            panic!("mock manager failure");
            #[allow(unreachable_code)]
            Ok(())
        })));
        let result = runtime
            .wait_for_cleanup(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(result.unwrap_err().is_panic());
        assert!(runtime.mgr_task.lock().await.is_none());
    }

    #[tokio::test]
    async fn host_drop_preserves_the_unfinished_cleanup_observer() {
        let runtime = runtime();
        let release = Arc::new(Notify::new());
        let observed = Arc::new(AtomicBool::new(false));
        let observer_release = release.clone();
        let observer_finished = observed.clone();
        let observer: Pin<Box<dyn Future<Output = RouteJoinResult> + Send>> =
            Box::pin(async move {
                observer_release.notified().await;
                observer_finished.store(true, Ordering::SeqCst);
                Ok(Ok(()))
            });
        *runtime.mgr_task.lock().await = Some(
            guarden::task::DetachableTask::from_boxed(
                guarden::task::TokioHandle::default(),
                observer,
            )
            .into_future(),
        );
        drop(runtime);
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !observed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup observer was dropped instead of handed to its runtime");
    }
}
