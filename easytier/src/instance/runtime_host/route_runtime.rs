use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use std::time::Duration;

use easytier_core::instance::CorePacketPlane;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use anyhow::Context;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio::{sync::Mutex, task::JoinHandle};
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use crate::instance::route::{CleanupIncomplete, PlatformRouteBackend, RouteMgr};

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub(super) struct NativeRouteRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: Mutex<Option<CancellationToken>>,
    mgr_task: Mutex<Option<JoinHandle<Result<(), CleanupIncomplete>>>>,
}

#[cfg(not(all(target_os = "linux", feature = "linux-netlink")))]
pub(super) struct NativeRouteRuntime;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
impl NativeRouteRuntime {
    pub(super) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            cancel: Mutex::new(None),
            mgr_task: Mutex::new(None),
        }
    }

    pub(super) async fn prepare(&self, packet_plane: Arc<CorePacketPlane>) -> anyhow::Result<()> {
        if self.global_ctx.get_flags().no_tun {
            return Ok(());
        }

        let cancel = CancellationToken::new();
        let backend = PlatformRouteBackend::new(self.global_ctx.net_ns.clone())?;

        let manager = RouteMgr::new(self.global_ctx.clone(), backend, cancel.clone());

        // The proxy demand resolves itself in the core's own registry and
        // claims its routes here, so no task relays proxy CIDR updates.
        let handle = manager.handle();
        let proxy_demand = handle
            .register()
            .context("route manager registry is already closed")?;
        packet_plane.proxy_routes().attach_demand(proxy_demand.into_registration());
        self.global_ctx.set_route_handle(Some(handle));

        let mgr_handle = tokio::spawn(manager.run());

        *self.cancel.lock().await = Some(cancel);
        *self.mgr_task.lock().await = Some(mgr_handle);

        Ok(())
    }

    pub(super) async fn shutdown(&self) {
        if let Some(cancel) = self.cancel.lock().await.take() {
            cancel.cancel();
        }
        self.global_ctx.set_route_handle(None);

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

#[cfg(not(all(target_os = "linux", feature = "linux-netlink")))]
impl NativeRouteRuntime {
    pub(super) fn new(_global_ctx: ArcGlobalCtx) -> Self {
        Self
    }

    pub(super) async fn prepare(&self, _packet_plane: Arc<CorePacketPlane>) -> anyhow::Result<()> {
        Ok(())
    }

    pub(super) async fn shutdown(&self) {}
}
