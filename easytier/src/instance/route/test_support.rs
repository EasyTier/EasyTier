use std::ops::{Deref, DerefMut};

use easytier_core::{config::runtime::CoreRuntimeConfigStore, host::route::RouteRegistry};
use registry::Registry;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;

use super::{
    CleanupIncomplete, RouteBackend, RouteMgr,
    scope::{RouteScope, RouteScopeLease},
};

/// Existing single-instance cases run through the same outlet/scope model.
pub(crate) struct RouteHarness<B> {
    manager: Option<RouteMgr<B>>,
    pub global_ctx: ArcGlobalCtx,
    pub runtime_config: CoreRuntimeConfigStore,
    scope: RouteScope,
    _lease: RouteScopeLease,
    _nic_changes: watch::Sender<u64>,
}

impl<B: RouteBackend> RouteHarness<B> {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        backend: B,
        routes: RouteRegistry,
        runtime_config: CoreRuntimeConfigStore,
        cancel: CancellationToken,
    ) -> Self {
        let inputs = Registry::default();
        let scope = RouteScope::with_registry(global_ctx.get_id(), routes);
        scope.prepare(runtime_config.clone()).unwrap();
        let lease = scope
            .attach(
                &inputs,
                global_ctx.tun_devices.clone(),
                uuid::Uuid::new_v4(),
            )
            .unwrap();
        scope.mark_ready(scope.attachment().unwrap().id);
        let (nic_changes, changed) = watch::channel(0);
        let manager = RouteMgr::new(
            global_ctx.tun_devices.clone(),
            backend,
            inputs,
            changed,
            cancel,
        );
        Self {
            manager: Some(manager),
            global_ctx,
            runtime_config,
            scope,
            _lease: lease,
            _nic_changes: nic_changes,
        }
    }

    pub fn routes(&self) -> &RouteRegistry {
        self.scope.routes()
    }

    pub async fn run(mut self) -> Result<(), CleanupIncomplete> {
        self.manager.take().unwrap().run().await
    }

    pub async fn perform_shutdown_cleanup(&mut self) -> Result<(), CleanupIncomplete> {
        self.scope.close();
        self.manager
            .as_mut()
            .unwrap()
            .perform_shutdown_cleanup()
            .await
    }
}

impl<B> Deref for RouteHarness<B> {
    type Target = RouteMgr<B>;
    fn deref(&self) -> &Self::Target {
        self.manager.as_ref().unwrap()
    }
}

impl<B> DerefMut for RouteHarness<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.manager.as_mut().unwrap()
    }
}

impl<B> Drop for RouteHarness<B> {
    fn drop(&mut self) {
        self.scope.close();
    }
}
