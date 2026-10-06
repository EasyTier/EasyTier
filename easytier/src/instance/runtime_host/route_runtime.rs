use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use std::time::Duration;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use anyhow::Context;
use easytier_core::instance::CorePacketPlane;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio::{sync::Mutex, task::JoinHandle};
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use crate::instance::route::{
    CleanupIncomplete, PlatformRouteBackend, RouteLease, RouteMgr, RouteSet,
};

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
        let manager = RouteMgr::new(
            self.global_ctx.clone(),
            backend,
            cancel.clone(),
        );

        let handle = manager.handle();
        // Register before publishing the handle or starting tasks: no lease
        // means the manager is already stopping.
        let proxy_lease = handle
            .register()
            .context("route manager registry is already closed")?;
        self.global_ctx.set_route_handle(Some(handle.clone()));

        let p_packet_plane = packet_plane.clone();
        let p_cancel = cancel.clone();
        tokio::spawn(async move {
            Self::run_proxy_routes_publisher(p_packet_plane, proxy_lease, p_cancel).await;
        });

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

    /// How often the authoritative proxy CIDR snapshot is re-read.
    ///
    /// The legacy `ProxyCidrMonitor` is disabled on this platform (see
    /// `configure_runtime_core_host_adapters`), so there is no
    /// `ProxyCidrsUpdated` event to wait on; the snapshot is polled instead.
    const PROXY_CIDR_POLL_INTERVAL: Duration = Duration::from_secs(1);

    async fn run_proxy_routes_publisher(
        packet_plane: Arc<CorePacketPlane>,
        lease: RouteLease,
        cancel: CancellationToken,
    ) {
        let mut cur_proxy_cidrs = std::collections::BTreeSet::<cidr::Ipv4Cidr>::new();

        loop {
            let latest = packet_plane.proxy_cidrs().await;
            if latest != cur_proxy_cidrs {
                cur_proxy_cidrs = latest;
                lease.set(Self::route_set(&cur_proxy_cidrs));
            }

            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Self::PROXY_CIDR_POLL_INTERVAL) => {}
            }
        }
    }

    fn route_set(cidrs: &std::collections::BTreeSet<cidr::Ipv4Cidr>) -> RouteSet {
        cidrs.iter().copied().map(cidr::IpCidr::V4).collect()
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
