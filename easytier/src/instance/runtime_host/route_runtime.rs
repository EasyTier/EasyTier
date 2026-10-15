use easytier_core::config::runtime::CoreRuntimeConfigStore;

use crate::common::global_ctx::ArcGlobalCtx;

/// Instance-owned route input lifetime; the NIC owns the actual route writer.
pub(super) struct NativeRouteRuntime {
    global_ctx: ArcGlobalCtx,
    scope: Option<crate::instance::route::scope::RouteScope>,
}

impl NativeRouteRuntime {
    pub(super) fn new(global_ctx: ArcGlobalCtx) -> Self {
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        let scope = (!global_ctx.get_flags().no_tun).then(|| {
            let scope = crate::instance::route::scope::RouteScope::new(global_ctx.get_id());
            global_ctx.set_route_handle(Some(scope.handle()));
            global_ctx.set_route_scope(Some(scope.clone()));
            scope
        });
        #[cfg(not(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        )))]
        let scope = None;
        Self { global_ctx, scope }
    }

    pub(super) fn route_handle(&self) -> Option<easytier_core::host::route::RouteHandle> {
        self.scope.as_ref().map(|scope| scope.handle())
    }

    pub(super) async fn prepare(
        &self,
        runtime_config: CoreRuntimeConfigStore,
    ) -> anyhow::Result<()> {
        if let Some(scope) = &self.scope {
            scope.prepare(runtime_config)?;
        }
        Ok(())
    }

    pub(super) fn request_shutdown(&self) {
        if let Some(scope) = &self.scope {
            scope.close();
        }
        self.global_ctx.set_route_scope(None);
        self.global_ctx.set_route_handle(None);
    }

    pub(super) async fn shutdown(&self) {
        self.request_shutdown();
        if let Some(scope) = &self.scope {
            match tokio::time::timeout(std::time::Duration::from_secs(5), scope.wait_withdrawn())
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(?error, "route scope cleanup was not confirmed"),
                Err(_) => tracing::warn!("route scope cleanup continues after the host deadline"),
            }
        }
    }
}

impl Drop for NativeRouteRuntime {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}
