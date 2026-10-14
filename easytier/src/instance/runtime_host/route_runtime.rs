#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use std::time::Duration;

use easytier_core::config::runtime::CoreRuntimeConfigStore;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use registry::Registry;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use crate::instance::route::{
    CleanupIncomplete, PlatformRouteBackend, RouteDemand, RouteHandle, RouteMgr,
};

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
type RouteJoinResult = Result<Result<(), CleanupIncomplete>, tokio::task::JoinError>;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
type RouteCleanupTask = guarden::task::DetachableTaskFuture<
    guarden::task::TokioHandle,
    dyn Future<Output = RouteJoinResult> + Send,
>;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
fn observe_route_task(task: JoinHandle<Result<(), CleanupIncomplete>>) -> RouteCleanupTask {
    let observer: Pin<Box<dyn Future<Output = RouteJoinResult> + Send>> = Box::pin(async move {
        let result = task.await;
        match &result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(?error, "incomplete route manager cleanup"),
            Err(error) => tracing::warn!(?error, "route manager task failed"),
        }
        result
    });
    guarden::task::DetachableTask::from_boxed(guarden::task::TokioHandle::default(), observer)
        .into_future()
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub(super) struct NativeRouteRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: CancellationToken,
    routes: Option<Registry<RouteDemand>>,
    handle: Option<RouteHandle>,
    mgr_task: Mutex<Option<RouteCleanupTask>>,
}

#[cfg(not(all(target_os = "linux", feature = "linux-netlink")))]
pub(super) struct NativeRouteRuntime;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
impl NativeRouteRuntime {
    pub(super) fn new(global_ctx: ArcGlobalCtx, cancel: CancellationToken) -> Self {
        let flags = global_ctx.get_flags();
        // Explicitly named NICs use the process-wide shared NIC route authority.
        if flags.no_tun || !flags.dev_name.is_empty() {
            Self {
                global_ctx,
                cancel,
                routes: None,
                handle: None,
                mgr_task: Mutex::new(None),
            }
        } else {
            let routes = Registry::default();
            let handle = RouteHandle::new(routes.clone());
            global_ctx.set_route_handle(Some(handle.clone()));
            Self {
                global_ctx,
                cancel,
                routes: Some(routes),
                handle: Some(handle),
                mgr_task: Mutex::new(None),
            }
        }
    }

    pub(super) fn route_handle(&self) -> Option<RouteHandle> {
        self.handle.clone()
    }

    pub(super) async fn prepare(
        &self,
        runtime_config: CoreRuntimeConfigStore,
    ) -> anyhow::Result<()> {
        let Some(routes) = &self.routes else {
            return Ok(());
        };

        let mut task_slot = self.mgr_task.lock().await;
        anyhow::ensure!(task_slot.is_none(), "route manager is already prepared");
        anyhow::ensure!(!self.cancel.is_cancelled(), "route runtime is stopping");

        let backend = PlatformRouteBackend::new(self.global_ctx.net_ns.clone()).await?;
        anyhow::ensure!(
            !self.cancel.is_cancelled(),
            "route runtime stopped during socket setup"
        );
        let manager = RouteMgr::new(
            self.global_ctx.clone(),
            backend,
            routes.clone(),
            runtime_config,
            self.cancel.clone(),
        );

        let mgr_handle = tokio::spawn(manager.run());
        *task_slot = Some(observe_route_task(mgr_handle));

        Ok(())
    }

    pub(super) fn request_shutdown(&self) {
        if let Some(routes) = &self.routes {
            routes.close();
        }
        self.global_ctx.set_route_handle(None);
        self.cancel.cancel();
    }

    pub(super) async fn shutdown(&self) {
        let _ = self
            .wait_for_cleanup(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
    }

    async fn wait_for_cleanup(&self, deadline: tokio::time::Instant) -> Option<RouteJoinResult> {
        self.request_shutdown();

        let mut slot = match tokio::time::timeout_at(deadline, self.mgr_task.lock()).await {
            Ok(slot) => slot,
            Err(_) => {
                tracing::warn!("route cleanup deadline exceeded waiting for task ownership");
                return None;
            }
        };
        let task = slot.as_mut()?;
        match tokio::time::timeout_at(deadline, task).await {
            Ok(result) => {
                slot.take();
                Some(result)
            }
            Err(_) => {
                // The observer and original manager remain owned by this slot.
                // Host Drop hands the observer to its captured runtime; it does
                // not abort the writer or spawn a competing cleanup writer.
                tracing::warn!("route cleanup still in progress after deadline");
                None
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
impl Drop for NativeRouteRuntime {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

#[cfg(not(all(target_os = "linux", feature = "linux-netlink")))]
impl NativeRouteRuntime {
    pub(super) fn new(_global_ctx: ArcGlobalCtx, _cancel: CancellationToken) -> Self {
        Self
    }

    pub(super) fn route_handle(&self) -> Option<easytier_core::host::route::RouteHandle> {
        None
    }

    pub(super) async fn prepare(
        &self,
        _runtime_config: CoreRuntimeConfigStore,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    pub(super) fn request_shutdown(&self) {}

    pub(super) async fn shutdown(&self) {}
}

#[cfg(all(test, target_os = "linux", feature = "linux-netlink"))]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::Notify;

    fn runtime() -> NativeRouteRuntime {
        NativeRouteRuntime::new(get_mock_global_ctx(), CancellationToken::new())
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
