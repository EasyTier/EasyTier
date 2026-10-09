#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use std::time::Duration;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use registry::Registry;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use crate::instance::route::{
    CleanupIncomplete, PlatformRouteBackend, RouteDemand, RouteHandle, RouteMgr,
};

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub(super) struct NativeRouteRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: CancellationToken,
    routes: Option<Registry<RouteDemand>>,
    handle: Option<RouteHandle>,
    mgr_task: Mutex<Option<JoinHandle<Result<(), CleanupIncomplete>>>>,
}

#[cfg(not(all(target_os = "linux", feature = "linux-netlink")))]
pub(super) struct NativeRouteRuntime;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
impl NativeRouteRuntime {
    pub(super) fn new(global_ctx: ArcGlobalCtx, cancel: CancellationToken) -> Self {
        if global_ctx.get_flags().no_tun {
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

    pub(super) async fn prepare(&self) -> anyhow::Result<()> {
        let Some(routes) = &self.routes else {
            return Ok(());
        };

        let backend = PlatformRouteBackend::new(self.global_ctx.net_ns.clone())?;
        let manager = RouteMgr::new(
            self.global_ctx.clone(),
            backend,
            routes.clone(),
            self.cancel.clone(),
        );

        let mgr_handle = tokio::spawn(manager.run());
        *self.mgr_task.lock().await = Some(mgr_handle);

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
        self.request_shutdown();

        if let Some(mut task) = self.mgr_task.lock().await.take() {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(join_res) => {
                    if let Ok(Err(err)) = join_res {
                        tracing::warn!(?err, "failed or incomplete route manager shutdown cleanup");
                    }
                }
                Err(_) => {
                    tracing::warn!("deadline exceeded while waiting for route manager cleanup");
                }
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

    pub(super) async fn prepare(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub(super) fn request_shutdown(&self) {}

    pub(super) async fn shutdown(&self) {}
}
