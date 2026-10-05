use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use std::time::Duration;

use easytier_core::instance::CorePacketPlane;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio::{sync::Mutex, task::JoinHandle};
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use crate::instance::route::{
    CleanupIncomplete, PlatformRouteBackend, RouteLease, RouteMgr,
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
        let backend = PlatformRouteBackend::new()?;
        let default_metric = 65535;
        let manager = RouteMgr::new(
            self.global_ctx.clone(),
            backend,
            cancel.clone(),
            default_metric,
        );

        let handle = manager.handle();
        self.global_ctx.set_route_handle(Some(handle.clone()));

        let proxy_lease = handle.register();
        let p_global_ctx = self.global_ctx.clone();
        let p_packet_plane = packet_plane.clone();
        let p_cancel = cancel.clone();
        tokio::spawn(async move {
            Self::run_proxy_routes_publisher(p_global_ctx, p_packet_plane, proxy_lease, p_cancel)
                .await;
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

    async fn run_proxy_routes_publisher(
        global_ctx: ArcGlobalCtx,
        packet_plane: Arc<CorePacketPlane>,
        lease: RouteLease,
        cancel: CancellationToken,
    ) {
        use crate::common::global_ctx::GlobalCtxEvent;

        let mut cur_proxy_cidrs = std::collections::BTreeSet::<cidr::Ipv4Cidr>::new();
        let mut event_receiver = global_ctx.subscribe();

        if let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await {
            cur_proxy_cidrs = diff.current;
            let set: std::collections::BTreeSet<cidr::IpCidr> = cur_proxy_cidrs
                .iter()
                .copied()
                .map(cidr::IpCidr::V4)
                .collect();
            lease.set(set);
        }

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                res = event_receiver.recv() => {
                    match res {
                        Ok(GlobalCtxEvent::ProxyCidrsUpdated(_, _)) => {
                            if let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await {
                                cur_proxy_cidrs = diff.current;
                                let set: std::collections::BTreeSet<cidr::IpCidr> = cur_proxy_cidrs
                                    .iter()
                                    .copied()
                                    .map(cidr::IpCidr::V4)
                                    .collect();
                                lease.set(set);
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            event_receiver = event_receiver.resubscribe();
                            if let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await {
                                cur_proxy_cidrs = diff.current;
                                let set: std::collections::BTreeSet<cidr::IpCidr> = cur_proxy_cidrs
                                    .iter()
                                    .copied()
                                    .map(cidr::IpCidr::V4)
                                    .collect();
                                lease.set(set);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
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
