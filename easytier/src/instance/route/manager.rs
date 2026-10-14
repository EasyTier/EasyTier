use std::collections::{BTreeMap, BTreeSet};

use registry::Registry;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use easytier_core::{
    config::runtime::CoreRuntimeConfigStore,
    host::route::{RouteDemand, RouteHandle, resolve_route_demands},
};

use crate::common::global_ctx::ArcGlobalCtx;

use super::backend::RouteBackend;
use super::device::DeviceFacts;
use super::model::{CleanupIncomplete, DeviceId, RetryState, Route, RouteError};

const DEFAULT_METRIC: u32 = 65535;

pub struct RouteMgr<B> {
    global_ctx: ArcGlobalCtx,
    backend: B,

    /// Independently owned dynamic route declarations.
    routes: Registry<RouteDemand>,
    /// Wakes the reconcile loop when a declaration changes.
    changed: watch::Receiver<()>,
    /// Authoritative manual proxy policy and its existing invalidation signal.
    runtime_config: CoreRuntimeConfigStore,
    config_changed: watch::Receiver<u64>,
    device_changed: watch::Receiver<DeviceFacts>,

    installed: BTreeSet<Route>,
    external: BTreeSet<Route>,
    unknown: BTreeSet<Route>,
    retries: BTreeMap<Route, RetryState>,
    desired: Option<BTreeSet<Route>>,

    current_tun_device: Option<DeviceId>,

    cancel: CancellationToken,
}

impl<B: RouteBackend> RouteMgr<B> {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        backend: B,
        routes: Registry<RouteDemand>,
        runtime_config: CoreRuntimeConfigStore,
        cancel: CancellationToken,
    ) -> Self {
        let changed = routes.subscribe();
        let config_changed = runtime_config.subscribe_service_runtime_changes();
        let device_changed = global_ctx.tun_devices.subscribe();
        Self {
            global_ctx,
            backend,
            routes,
            changed,
            runtime_config,
            config_changed,
            device_changed,
            installed: BTreeSet::new(),
            external: BTreeSet::new(),
            unknown: BTreeSet::new(),
            retries: BTreeMap::new(),
            current_tun_device: None,
            desired: None,
            cancel,
        }
    }

    pub fn handle(&self) -> RouteHandle {
        RouteHandle::new(self.routes.clone())
    }

    fn retire_destroyed_devices(&mut self, facts: &DeviceFacts) {
        self.installed
            .retain(|route| !facts.destroyed(&route.interface));
        self.external
            .retain(|route| !facts.destroyed(&route.interface));
        self.unknown
            .retain(|route| !facts.destroyed(&route.interface));
        self.retries
            .retain(|route, _| !facts.destroyed(&route.interface));
    }

    fn blocked_slots(&self, desired: &BTreeSet<Route>) -> BTreeSet<cidr::IpCidr> {
        self.unknown
            .iter()
            .chain(self.installed.difference(desired))
            .map(|route| route.destination)
            .collect()
    }

    fn batch_interrupted(&self) -> bool {
        self.cancel.is_cancelled()
            || self.changed.has_changed().unwrap_or(true)
            || self.config_changed.has_changed().unwrap_or(true)
            || self.device_changed.has_changed().unwrap_or(true)
    }

    fn record_failure(&mut self, route: Route) {
        let now = tokio::time::Instant::now();
        match self.retries.entry(route) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(RetryState::new(now, 100));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().record_failure(now);
            }
        }
    }

    pub fn next_wakeup_time(&self) -> Option<tokio::time::Instant> {
        if self
            .global_ctx
            .tun_devices
            .snapshot()
            .active
            .is_some_and(|device| !device.ready)
        {
            return None;
        }
        let Some(desired) = &self.desired else {
            return Some(tokio::time::Instant::now());
        };
        let blocked = self.blocked_slots(desired);
        let removals = self
            .installed
            .difference(desired)
            .filter(|route| !self.unknown.contains(*route));
        let additions = desired.difference(&self.installed).filter(|route| {
            !self.external.contains(*route) && !blocked.contains(&route.destination)
        });
        removals
            .chain(additions)
            .map(|route| {
                self.retries
                    .get(route)
                    .map_or_else(tokio::time::Instant::now, |retry| retry.next_retry)
            })
            .min()
    }

    pub async fn run(mut self) -> Result<(), CleanupIncomplete> {
        loop {
            if self.cancel.is_cancelled() {
                break;
            }

            self.reconcile().await;

            if self.cancel.is_cancelled() {
                break;
            }

            let next_wakeup = self.next_wakeup_time();

            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                // Err only after every sender is gone; the manager holds the
                // registry, so this is a defensive exit, not a stop condition.
                changed = self.changed.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                changed = self.config_changed.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                changed = self.device_changed.changed() => {
                    if changed.is_err() { break; }
                }
                _ = async {
                    match next_wakeup {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {}
            }
        }

        self.perform_shutdown_cleanup().await
    }

    pub async fn reconcile(&mut self) {
        // All baselines precede every snapshot read. Inputs arriving during I/O
        // remain pending and stop the obsolete batch after its current result.
        self.changed.mark_unchanged();
        self.config_changed.mark_unchanged();
        self.device_changed.mark_unchanged();
        let device_facts = self.global_ctx.tun_devices.snapshot();
        self.retire_destroyed_devices(&device_facts);
        if device_facts
            .active
            .as_ref()
            .is_some_and(|device| !device.ready)
        {
            // An unready replacement does not revoke the old live device or
            // its installed routes. No ordinary writes until it becomes ready.
            return;
        }
        self.current_tun_device = device_facts.active.map(|device| device.id);

        // 2. Combine dynamic declarations with the current configuration policy.
        let snapshot = self.routes.snapshot();
        let config = self.runtime_config.snapshot();
        let cidrs = resolve_route_demands(&snapshot, config.services.manual_routes.as_ref());

        // 3. Compute desired routes from active slots
        let desired = match &self.current_tun_device {
            Some(dev) => cidrs
                .into_iter()
                .map(|destination| Route {
                    destination,
                    interface: dev.clone(),
                    metric: DEFAULT_METRIC,
                })
                .collect(),
            None => BTreeSet::new(),
        };

        // Scope external_present and retry_tracker to only currently desired routes
        self.external.retain(|r| desired.contains(r));
        self.retries.retain(|route, _| {
            (self.installed.contains(route) && !desired.contains(route))
                || (desired.contains(route)
                    && !self.installed.contains(route)
                    && !self.external.contains(route)
                    && !self.unknown.contains(route))
        });

        self.desired = Some(desired.clone());

        // 5. Calculate diffs
        let now = tokio::time::Instant::now();

        // Routes to remove: in installed, not in desired, not unknown
        let to_remove: Vec<Route> = self
            .installed
            .difference(&desired)
            .filter(|r| !self.unknown.contains(r))
            .filter(|r| {
                if let Some(retry) = self.retries.get(r) {
                    retry.next_retry <= now
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Routes to add: in desired, not in installed, not in external_present, not unknown
        let to_add: Vec<Route> = desired
            .difference(&self.installed)
            .filter(|r| !self.external.contains(r))
            .filter(|r| !self.unknown.contains(r))
            .filter(|r| {
                if let Some(retry) = self.retries.get(r) {
                    retry.next_retry <= now
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // 6. Execute removals
        for route in to_remove {
            if self.batch_interrupted() {
                return;
            }
            match self.backend.remove(&route).await {
                Ok(Some(())) | Ok(None) => {
                    self.installed.remove(&route);
                    self.retries.remove(&route);
                }
                Err(RouteError::Failed(err)) => {
                    tracing::warn!(
                        ?route,
                        ?err,
                        "failed to remove route, will retry with backoff"
                    );
                    self.record_failure(route);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(
                        ?route,
                        ?err,
                        "unknown result during remove; isolating route"
                    );
                    self.unknown.insert(route.clone());
                    self.retries.remove(&route);
                }
            }
        }

        // A failed or uncertain removal blocks replacement of the same
        // destination. A deadline for a blocked addition must not busy-loop.
        let mut blocked = self.blocked_slots(&desired);
        for route in to_add {
            if self.batch_interrupted() {
                return;
            }
            if blocked.contains(&route.destination) {
                continue;
            }

            match self.backend.add(&route).await {
                Ok(Some(actual)) => {
                    self.installed.insert(actual);
                    self.retries.remove(&route);
                }
                Ok(None) => {
                    // Equivalent external route already exists
                    self.external.insert(route.clone());
                    self.retries.remove(&route);
                }
                Err(RouteError::Failed(err)) => {
                    tracing::warn!(?route, ?err, "failed to add route, will retry with backoff");
                    self.record_failure(route);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(?route, ?err, "unknown result during add; isolating route");
                    blocked.insert(route.destination);
                    self.unknown.insert(route.clone());
                    self.retries.remove(&route);
                }
            }
        }
    }

    pub async fn perform_shutdown_cleanup(&mut self) -> Result<(), CleanupIncomplete> {
        // Close the registry before any backend I/O: publishers are revoked
        // synchronously and late declarations are rejected. This does not claim
        // the OS routes below are already cleaned up.
        self.routes.close();

        let device_facts = self.global_ctx.tun_devices.snapshot();
        self.retire_destroyed_devices(&device_facts);

        // Keep responsibility in the manager until each result is confirmed.
        // A dropped cleanup future must retain both unfinished routes and the
        // uncertainty of the request whose result it stopped waiting for.
        let installed: Vec<_> = self.installed.difference(&self.unknown).cloned().collect();
        for route in installed {
            let device_facts = self.global_ctx.tun_devices.snapshot();
            self.retire_destroyed_devices(&device_facts);
            if !self.installed.contains(&route) {
                continue;
            }
            self.unknown.insert(route.clone());
            match self.backend.remove(&route).await {
                Ok(Some(())) | Ok(None) => {
                    self.installed.remove(&route);
                    self.unknown.remove(&route);
                    self.retries.remove(&route);
                }
                Err(RouteError::Failed(err)) => {
                    tracing::error!(
                        ?route,
                        ?err,
                        "failed to remove route during shutdown cleanup"
                    );
                    self.unknown.remove(&route);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(
                        ?route,
                        ?err,
                        "unknown result removing route during shutdown cleanup"
                    );
                }
            }
        }

        // Device destruction may have happened while the final request was in
        // flight. Only owned fd generations prove cascading route removal.
        let device_facts = self.global_ctx.tun_devices.snapshot();
        self.retire_destroyed_devices(&device_facts);
        if self.installed.is_empty() && self.unknown.is_empty() {
            Ok(())
        } else {
            Err(CleanupIncomplete {
                uncleaned_routes: self.installed.difference(&self.unknown).cloned().collect(),
                unknown_routes: self.unknown.iter().cloned().collect(),
                reason: "shutdown cleanup encountered failures or unknown outcomes".to_string(),
            })
        }
    }
}

impl<B> Drop for RouteMgr<B> {
    /// Covers every exit path that does not reach `perform_shutdown_cleanup`:
    /// dropping the manager before running, dropping a `run` future that was
    /// never polled, task abort and unwind. It is synchronous and idempotent:
    /// no I/O, no waiting, no cleanup task. Asynchronous backend cleanup stays
    /// with the host.
    fn drop(&mut self) {
        self.routes.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use cidr::{IpCidr, Ipv4Cidr};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    const TEST_DEVICE_INDEX: u32 = 100;

    fn test_route(cidr: &str) -> Route {
        Route {
            destination: IpCidr::from_str(cidr).unwrap(),
            interface: DeviceId::new(TEST_DEVICE_INDEX, Some(1)),
            metric: 65535,
        }
    }

    fn test_config_store() -> CoreRuntimeConfigStore {
        CoreRuntimeConfigStore::new(
            easytier_core::config::runtime::CoreRuntimeConfig::default(),
            Arc::new(easytier_core::config::peers::PeerRuntimeSnapshot::default()),
        )
    }

    fn test_manager(
        backend: MockRouteBackend,
    ) -> (RouteMgr<MockRouteBackend>, RouteHandle, CancellationToken) {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(TEST_DEVICE_INDEX));
        let cancel_token = CancellationToken::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token.clone(),
        );
        (manager, handle, cancel_token)
    }

    /// Instrumentation that lets a test park the manager inside a backend call
    /// and prove it reached that await, without guessing with sleeps.
    struct PausedOperation {
        /// Reports each route that entered `add` before the pause.
        entered: tokio::sync::mpsc::UnboundedSender<Route>,
        /// Releases one paused `add`.
        release: Arc<tokio::sync::Notify>,
    }

    #[derive(Default)]
    struct MockRouteBackend {
        routes: BTreeSet<Route>,
        add_calls: Vec<Route>,
        remove_calls: Vec<Route>,
        add_error_map: HashMap<Route, RouteError>,
        remove_error_map: HashMap<Route, RouteError>,
        external_present: BTreeSet<Route>,
        /// When set, `add` reports the route and then waits for a release.
        paused_add: Option<PausedOperation>,
        paused_remove: Option<PausedOperation>,
        /// `add` panics for these routes.
        panic_on_add: BTreeSet<Route>,
    }

    impl MockRouteBackend {
        fn new() -> Self {
            Self::default()
        }

        fn paused(
            release: Arc<tokio::sync::Notify>,
        ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<Route>) {
            let (entered, entered_rx) = tokio::sync::mpsc::unbounded_channel();
            let backend = Self {
                paused_add: Some(PausedOperation { entered, release }),
                ..Self::default()
            };
            (backend, entered_rx)
        }
    }

    #[async_trait::async_trait]
    impl RouteBackend for MockRouteBackend {
        async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError> {
            self.add_calls.push(route.clone());
            if self.panic_on_add.contains(route) {
                panic!("mock backend add panic");
            }
            if let Some(paused) = &self.paused_add {
                let _ = paused.entered.send(route.clone());
                paused.release.notified().await;
            }
            if let Some(err) = self.add_error_map.remove(route) {
                return Err(err);
            }
            if self.external_present.contains(route) {
                return Ok(None);
            }
            self.routes.insert(route.clone());
            Ok(Some(route.clone()))
        }

        async fn remove(&mut self, route: &Route) -> Result<Option<()>, RouteError> {
            self.remove_calls.push(route.clone());
            if let Some(paused) = &self.paused_remove {
                let _ = paused.entered.send(route.clone());
                paused.release.notified().await;
            }
            if let Some(err) = self.remove_error_map.remove(route) {
                return Err(err);
            }
            if self.routes.remove(route) {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        }
    }

    #[tokio::test]
    async fn interrupted_cleanup_keeps_pending_and_uncertain_responsibility() {
        let (mut manager, handle, _) = test_manager(MockRouteBackend::new());
        let first = test_route("10.0.0.0/24");
        let second = test_route("10.1.0.0/24");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                first.destination,
                second.destination,
            ])))
            .unwrap();
        manager.reconcile().await;
        let (entered, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        manager.backend.paused_remove = Some(PausedOperation {
            entered,
            release: Arc::new(tokio::sync::Notify::new()),
        });
        let mut cleanup = Box::pin(manager.perform_shutdown_cleanup());
        assert!(futures::poll!(cleanup.as_mut()).is_pending());
        assert_eq!(entered_rx.try_recv().unwrap(), first);
        drop(cleanup);
        assert_eq!(manager.installed, BTreeSet::from([first.clone(), second]));
        assert_eq!(manager.unknown, BTreeSet::from([first]));
        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
    }

    #[tokio::test]
    async fn cleanup_rechecks_device_destruction_after_a_failed_request() {
        let (mut manager, handle, _) = test_manager(MockRouteBackend::new());
        let route = test_route("10.0.0.0/24");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager.reconcile().await;
        let ctx = manager.global_ctx.clone();
        let release = Arc::new(tokio::sync::Notify::new());
        let (entered, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        manager.backend.paused_remove = Some(PausedOperation {
            entered,
            release: release.clone(),
        });
        manager.backend.remove_error_map.insert(
            route.clone(),
            RouteError::Failed(anyhow::anyhow!("device disappeared")),
        );
        let mut cleanup = Box::pin(manager.perform_shutdown_cleanup());
        assert!(futures::poll!(cleanup.as_mut()).is_pending());
        assert_eq!(entered_rx.try_recv().unwrap(), route);
        ctx.set_tun_device_index_for_test(None);
        release.notify_one();
        cleanup.await.unwrap();
        assert!(manager.installed.is_empty());
        assert!(manager.unknown.is_empty());
    }

    #[tokio::test]
    async fn deterministic_cleanup_failure_retains_the_route_for_a_later_attempt() {
        let (mut manager, handle, _) = test_manager(MockRouteBackend::new());
        let route = test_route("10.0.0.0/24");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager.reconcile().await;
        manager.backend.remove_error_map.insert(
            route.clone(),
            RouteError::Failed(anyhow::anyhow!("temporary failure")),
        );
        let report = manager.perform_shutdown_cleanup().await.unwrap_err();
        assert_eq!(report.uncleaned_routes, vec![route.clone()]);
        assert!(report.unknown_routes.is_empty());
        assert_eq!(manager.installed, BTreeSet::from([route]));
        manager.perform_shutdown_cleanup().await.unwrap();
        assert!(manager.installed.is_empty());
        assert!(manager.backend.routes.is_empty());
    }

    #[tokio::test]
    async fn test_first_pass_reconciles_without_waiting() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());

        let mut manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token.clone(),
        );
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .unwrap();

        // Initial reconcile should populate without waiting for notify
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 0); // No routes yet

        // Now add an extra route
        let cidr = IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(7, 7, 7, 7), 32).unwrap());
        reg.replace(RouteDemand::Additional(BTreeSet::from([cidr])))
            .unwrap();

        // Reconcile
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);
        assert_eq!(manager.backend.routes.len(), 1);

        // Cancel and stop
        cancel_token.cancel();
        let cleanup_res = manager.perform_shutdown_cleanup().await;
        assert!(cleanup_res.is_ok());
        assert_eq!(manager.backend.routes.len(), 0);
    }

    #[tokio::test]
    async fn test_already_present_external_route_not_duplicated_nor_removed() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let dev = DeviceId::new(100, Some(1));
        let mut backend = MockRouteBackend::new();

        let fake_ip = Ipv4Addr::new(7, 7, 7, 7);
        let fake_route = Route {
            destination: IpCidr::V4(Ipv4Cidr::new(fake_ip, 32).unwrap()),
            interface: dev.clone(),
            metric: 65535,
        };

        // Mark it external present in backend
        backend.external_present.insert(fake_route.clone());

        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token.clone(),
        );
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                fake_route.destination
            ])))
            .unwrap();

        manager.reconcile().await;
        // Should not be in installed_routes, but in external_present!
        assert!(manager.installed.is_empty());
        assert!(manager.external.contains(&fake_route));

        // Second reconcile: should NOT re-attempt to add!
        let add_calls_count = manager.backend.add_calls.len();
        manager.reconcile().await;
        assert_eq!(manager.backend.add_calls.len(), add_calls_count);

        // Perform shutdown cleanup: should NOT attempt to remove external route!
        let cleanup_res = manager.perform_shutdown_cleanup().await;
        assert!(cleanup_res.is_ok());
        assert!(manager.backend.remove_calls.is_empty());
    }

    #[tokio::test]
    async fn test_device_destruction_retires_routes() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();

        let fake_ip = Ipv4Addr::new(7, 7, 7, 7);
        let cidr = IpCidr::V4(Ipv4Cidr::new(fake_ip, 32).unwrap());

        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(
            global_ctx.clone(),
            backend,
            routes,
            test_config_store(),
            cancel_token,
        );
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([cidr])))
            .unwrap();

        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);

        // Now destroy device 1 and recreate device 2 (new ifindex)
        let dev2 = DeviceId::new(101, Some(2));
        global_ctx.set_tun_device_index_for_test(Some(101));

        manager.reconcile().await;
        // Old routes on dev1 retired, new route on dev2 installed!
        assert_eq!(manager.installed.len(), 1);
        let installed = manager.installed.iter().next().unwrap();
        assert_eq!(installed.interface, dev2);
    }

    #[tokio::test(start_paused = true)]
    async fn stable_state_has_no_polling_deadline() {
        let (mut manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let route = test_route("7.7.7.7/32");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager.reconcile().await;
        assert_eq!(manager.next_wakeup_time(), None);
        assert_eq!(manager.backend.add_calls, vec![route]);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_delay_starts_at_failure_completion_and_survives_notifications() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (mut backend, mut entered) = MockRouteBackend::paused(release.clone());
        let route = test_route("7.7.7.7/32");
        backend.add_error_map.insert(
            route.clone(),
            RouteError::Failed(anyhow::anyhow!("temporary failure")),
        );
        let (mut manager, handle, _cancel) = test_manager(backend);
        let registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        let mut reconcile = Box::pin(manager.reconcile());
        assert!(futures::poll!(reconcile.as_mut()).is_pending());
        assert_eq!(entered.try_recv().unwrap(), route);
        tokio::time::advance(Duration::from_secs(2)).await;
        release.notify_one();
        reconcile.await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        assert_eq!(manager.next_wakeup_time(), Some(deadline));
        registration
            .replace(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager
            .runtime_config
            .update_services(|services| services.dhcp_ipv4 = true);
        manager.reconcile().await;
        assert_eq!(manager.next_wakeup_time(), Some(deadline));
        assert_eq!(manager.retries[&route].attempts, 1);
        assert_eq!(manager.backend.add_calls.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn input_changes_stop_the_remaining_obsolete_additions() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (backend, mut entered) = MockRouteBackend::paused(release.clone());
        let (manager, handle, cancel) = test_manager(backend);
        let first = test_route("10.0.0.0/24");
        let obsolete = test_route("10.1.0.0/24");
        let latest = test_route("10.2.0.0/24");
        let registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                first.destination,
                obsolete.destination,
            ])))
            .unwrap();
        let mut run = Box::pin(manager.run());
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert_eq!(entered.try_recv().unwrap(), first);
        registration
            .replace(RouteDemand::Additional(BTreeSet::from(
                [latest.destination],
            )))
            .unwrap();
        release.notify_one();
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert_eq!(entered.try_recv().unwrap(), latest);
        assert!(entered.try_recv().is_err());
        release.notify_one();
        cancel.cancel();
        run.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn failed_removal_blocks_replacement_without_a_busy_deadline() {
        let (mut manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let old = test_route("7.7.7.7/32");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([old.destination])))
            .unwrap();
        manager.reconcile().await;
        let replacement = manager.global_ctx.tun_devices.attach("new".into(), 101);
        manager
            .global_ctx
            .tun_devices
            .mark_ready(replacement.registration());
        let new = Route {
            interface: replacement.id().clone(),
            ..old.clone()
        };
        manager.backend.remove_error_map.insert(
            old.clone(),
            RouteError::Failed(anyhow::anyhow!("temporary removal failure")),
        );
        manager.retries.insert(
            new.clone(),
            RetryState::new(tokio::time::Instant::now() - Duration::from_secs(1), 100),
        );
        manager.reconcile().await;
        assert_eq!(manager.backend.add_calls, vec![old]);
        assert_eq!(
            manager.next_wakeup_time(),
            Some(tokio::time::Instant::now() + Duration::from_millis(100))
        );
        tokio::time::advance(Duration::from_millis(100)).await;
        manager.reconcile().await;
        assert_eq!(manager.installed, BTreeSet::from([new]));
        assert_eq!(manager.next_wakeup_time(), None);
    }

    #[tokio::test]
    async fn configuration_error_does_not_claim_device_destruction() {
        let (mut manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let route = test_route("7.7.7.7/32");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager.reconcile().await;
        manager
            .global_ctx
            .set_tun_device_error("configuration failed".into());
        manager.reconcile().await;
        assert_eq!(manager.installed, BTreeSet::from([route]));
        assert!(manager.backend.remove_calls.is_empty());
    }

    #[tokio::test]
    async fn unready_replacement_preserves_live_routes_and_selection_removes_them() {
        let (mut manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let route = test_route("7.7.7.7/32");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager.reconcile().await;
        let new = manager.global_ctx.tun_devices.attach("new".into(), 101);
        manager.reconcile().await;
        assert_eq!(manager.installed, BTreeSet::from([route.clone()]));
        assert!(manager.backend.remove_calls.is_empty());
        manager
            .global_ctx
            .tun_devices
            .mark_ready(new.registration());
        manager.reconcile().await;
        assert_eq!(manager.backend.remove_calls, vec![route.clone()]);
        assert_eq!(
            manager.installed,
            BTreeSet::from([Route {
                interface: new.id().clone(),
                ..route
            }])
        );
    }

    #[tokio::test]
    async fn external_interface_routes_are_removed_after_the_fd_claim_closes() {
        let ctx = get_mock_global_ctx();
        let device = ctx
            .tun_devices
            .attach_external("persistent".into(), TEST_DEVICE_INDEX);
        ctx.tun_devices.mark_ready(device.registration());
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(
            ctx,
            MockRouteBackend::new(),
            routes,
            test_config_store(),
            CancellationToken::new(),
        );
        let route = Route {
            interface: device.id().clone(),
            ..test_route("7.7.7.7/32")
        };
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager.reconcile().await;
        drop(device);
        manager.reconcile().await;
        assert!(manager.installed.is_empty());
        assert_eq!(manager.backend.remove_calls, vec![route]);
    }

    #[tokio::test]
    async fn same_index_recreation_retires_only_the_old_instance() {
        let (mut manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let route = test_route("7.7.7.7/32");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        manager.reconcile().await;
        manager.global_ctx.set_tun_device_index_for_test(None);
        // Model the kernel's route cascading when the old interface dies.
        manager.backend.routes.clear();
        manager
            .global_ctx
            .set_tun_device_index_for_test(Some(TEST_DEVICE_INDEX));
        manager.reconcile().await;
        assert_eq!(
            manager.installed,
            BTreeSet::from([Route {
                interface: DeviceId::new(TEST_DEVICE_INDEX, Some(2)),
                ..route
            }])
        );
        assert!(manager.backend.remove_calls.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn device_readiness_wakes_the_manager_without_polling() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (backend, mut entered) = MockRouteBackend::paused(release.clone());
        let (manager, handle, cancel) = test_manager(backend);
        let ctx = manager.global_ctx.clone();
        let new = ctx.tun_devices.attach("new".into(), 101);
        let route = test_route("7.7.7.7/32");
        let _registration = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();
        let mut run = Box::pin(manager.run());
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert!(entered.try_recv().is_err());
        ctx.tun_devices.mark_ready(new.registration());
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert_eq!(
            entered.try_recv().unwrap(),
            Route {
                interface: new.id().clone(),
                ..route
            }
        );
        release.notify_one();
        cancel.cancel();
        run.await.unwrap();
    }

    #[tokio::test]
    async fn test_manager_stop_on_cancellation() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());

        let manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token.clone(),
        );
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([test_route(
                "7.7.7.7/32",
            )
            .destination])))
            .unwrap();

        let join_handle = tokio::spawn(async move { manager.run().await });

        cancel_token.cancel();
        let res = join_handle.await.unwrap();
        assert!(res.is_ok());

        // Normal exit closes the registry before the asynchronous cleanup, so
        // publishers that are still alive lose their authority.
        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(
            reg.replace(RouteDemand::Additional(BTreeSet::from([test_route(
                "8.8.8.8/32"
            )
            .destination])))
                .is_none()
        );
        assert!(reg.get().is_none());
    }

    #[tokio::test]
    async fn test_failed_and_unknown_handling_and_slot_blocking() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let dev = DeviceId::new(100, Some(1));
        let mut backend = MockRouteBackend::new();

        let fake_ip = Ipv4Addr::new(7, 7, 7, 7);
        let route = Route {
            destination: IpCidr::V4(Ipv4Cidr::new(fake_ip, 32).unwrap()),
            interface: dev.clone(),
            metric: 65535,
        };

        // Simulate Unknown error on add
        backend.add_error_map.insert(
            route.clone(),
            RouteError::Unknown(anyhow::anyhow!("timeout")),
        );

        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token.clone(),
        );
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();

        manager.reconcile().await;

        // Route should be in unknown_routes, not in installed
        assert!(manager.installed.is_empty());
        assert!(manager.unknown.contains(&route));

        // Shutdown cleanup should report CleanupIncomplete because of unknown route
        let cleanup_res = manager.perform_shutdown_cleanup().await;
        assert!(cleanup_res.is_err());
        let incomplete = cleanup_res.unwrap_err();
        assert_eq!(incomplete.unknown_routes.len(), 1);
        assert_eq!(incomplete.unknown_routes[0], route);
    }

    #[tokio::test]
    async fn test_external_present_cleared_when_demand_withdrawn() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let dev = DeviceId::new(100, Some(1));
        let mut backend = MockRouteBackend::new();

        let fake_ip = Ipv4Addr::new(7, 7, 7, 7);
        let route = Route {
            destination: IpCidr::V4(Ipv4Cidr::new(fake_ip, 32).unwrap()),
            interface: dev.clone(),
            metric: 65535,
        };

        backend.external_present.insert(route.clone());

        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token,
        );
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();

        manager.reconcile().await;
        assert!(manager.external.contains(&route));

        // Withdraw extra demand
        reg.replace(RouteDemand::Additional(BTreeSet::new()))
            .unwrap();
        manager.reconcile().await;
        // external_present should now be cleared because the route is no longer desired
        assert!(manager.external.is_empty());
    }

    #[tokio::test]
    async fn test_two_independent_leases_sharing_route_and_raii_drop() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();

        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token,
        );

        let cidr = IpCidr::from_str("10.10.10.10/32").unwrap();
        let reg1 = handle
            .register(RouteDemand::Additional(BTreeSet::from([cidr])))
            .unwrap();
        let reg2 = handle
            .register(RouteDemand::Additional(BTreeSet::from([cidr])))
            .unwrap();

        manager.reconcile().await;

        // Merged into 1 route in installed and backend
        assert_eq!(manager.installed.len(), 1);
        assert_eq!(manager.backend.routes.len(), 1);
        assert_eq!(manager.backend.add_calls.len(), 1);

        // 2. Drop reg1 -> route remains installed because reg2 still desires it!
        drop(reg1);
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);
        assert_eq!(manager.backend.routes.len(), 1);

        // 3. Drop reg2 -> route removed from system
        drop(reg2);
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 0);
        assert_eq!(manager.backend.routes.len(), 0);
        assert_eq!(manager.backend.remove_calls.len(), 1);
    }

    #[tokio::test]
    async fn test_ipv6_route_is_reconciled_like_ipv4() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();

        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token,
        );

        let v6_cidr = IpCidr::from_str("fd00::/64").unwrap();
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([v6_cidr])))
            .unwrap();

        manager.reconcile().await;
        assert_eq!(manager.installed, BTreeSet::from([test_route("fd00::/64")]));
        drop(_reg);
        manager.reconcile().await;
        assert!(manager.installed.is_empty());
    }

    #[tokio::test]
    async fn test_normal_shutdown_closes_registry_but_external_leases_survive() {
        let (mut manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([test_route(
                "7.7.7.7/32",
            )
            .destination])))
            .unwrap();

        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);
        assert_eq!(manager.backend.routes.len(), 1);

        let cleanup = manager.perform_shutdown_cleanup().await;
        assert!(cleanup.is_ok());
        assert!(
            manager.backend.routes.is_empty(),
            "OS mock cleanup still runs"
        );

        // The external handle and registration outlive the shutdown, but their
        // authority is revoked.
        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none(),
            "closed registry rejects publishers"
        );
        let remove_calls = manager.backend.remove_calls.len();
        assert!(
            reg.replace(RouteDemand::Additional(BTreeSet::from([test_route(
                "8.8.8.8/32"
            )
            .destination])))
                .is_none()
        );
        assert!(reg.get().is_none());
        drop(reg);
        assert_eq!(
            manager.backend.remove_calls.len(),
            remove_calls,
            "releasing a lease after shutdown must not repeat backend cleanup"
        );
    }

    #[tokio::test]
    async fn test_dropping_manager_before_run_revokes_registration() {
        let (manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([test_route(
                "7.7.7.7/32",
            )
            .destination])))
            .unwrap();

        drop(manager);

        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(
            reg.replace(RouteDemand::Additional(BTreeSet::from([test_route(
                "8.8.8.8/32"
            )
            .destination])))
                .is_none()
        );
        assert!(reg.get().is_none());
    }

    #[tokio::test]
    async fn test_dropping_unpolled_run_future_revokes_registration() {
        let (manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([test_route(
                "7.7.7.7/32",
            )
            .destination])))
            .unwrap();

        // The future owns the manager and is never polled; dropping it must
        // still close the registry.
        let run = manager.run();
        drop(run);

        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(
            reg.replace(RouteDemand::Additional(BTreeSet::from([test_route(
                "8.8.8.8/32"
            )
            .destination])))
                .is_none()
        );
        assert!(reg.get().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_aborting_running_task_revokes_registration() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (backend, mut entered) = MockRouteBackend::paused(release);
        let (manager, handle, _cancel) = test_manager(backend);
        let route = test_route("7.7.7.7/32");
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();

        let task = tokio::spawn(manager.run());
        let adding = tokio::time::timeout(Duration::from_secs(5), entered.recv())
            .await
            .expect("manager never reached the paused backend await")
            .expect("backend hook closed");
        assert_eq!(adding, route);

        task.abort();
        let join = task.await;
        assert!(
            join.unwrap_err().is_cancelled(),
            "wait for the aborted task to finish before asserting"
        );

        // The manager was dropped with the aborted task. This does not claim
        // that the asynchronous OS cleanup ran.
        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(
            reg.replace(RouteDemand::Additional(BTreeSet::from([test_route(
                "8.8.8.8/32"
            )
            .destination])))
                .is_none()
        );
        assert!(reg.get().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_backend_panic_closes_registry() {
        let route = test_route("7.7.7.7/32");
        let mut backend = MockRouteBackend::new();
        backend.panic_on_add.insert(route.clone());
        let (manager, handle, _cancel) = test_manager(backend);
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([route.destination])))
            .unwrap();

        let task = tokio::spawn(manager.run());
        let join = task.await;
        assert!(
            join.unwrap_err().is_panic(),
            "the backend panic must reach the join handle"
        );

        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(
            reg.replace(RouteDemand::Additional(BTreeSet::from([test_route(
                "8.8.8.8/32"
            )
            .destination])))
                .is_none()
        );
        assert!(reg.get().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_lease_update_during_reconcile_is_applied_without_polling() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (backend, mut entered) = MockRouteBackend::paused(release.clone());
        let (manager, handle, cancel) = test_manager(backend);

        let first = test_route("7.7.7.7/32");
        let second = test_route("8.8.8.8/32");
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([first.destination])))
            .unwrap();

        let task = tokio::spawn(manager.run());
        let adding = tokio::time::timeout(Duration::from_secs(5), entered.recv())
            .await
            .expect("manager never reached the paused backend await")
            .expect("backend hook closed");
        assert_eq!(adding, first);

        // Update the source while reconcile is parked inside the backend.
        reg.replace(RouteDemand::Additional(BTreeSet::from([
            first.destination,
            second.destination,
        ])))
        .unwrap();
        release.notify_one();

        // The pending notification drives the next pass immediately; the device
        // poll would only have noticed after one second.
        let adding = tokio::time::timeout(Duration::from_millis(500), entered.recv())
            .await
            .expect("an update during reconcile must not wait for the device poll")
            .expect("backend hook closed");
        assert_eq!(adding, second);
        release.notify_one();

        cancel.cancel();
        let cleanup = task.await.unwrap();
        assert!(cleanup.is_ok());
        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_config_update_during_reconcile_is_applied_without_polling() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (backend, mut entered) = MockRouteBackend::paused(release.clone());
        let (manager, handle, cancel) = test_manager(backend);
        let runtime_config = manager.runtime_config.clone();
        let mut declarations_changed = manager.routes.subscribe();
        let auto = test_route("10.0.0.0/24");
        let manual = test_route("192.168.1.0/24");
        let _auto_reg = handle
            .register(RouteDemand::AutoProxy(BTreeSet::from(["10.0.0.0/24"
                .parse()
                .unwrap()])))
            .unwrap();
        declarations_changed.mark_unchanged();

        let task = tokio::spawn(manager.run());
        let adding = tokio::time::timeout(Duration::from_secs(5), entered.recv())
            .await
            .expect("manager never reached the paused backend await")
            .expect("backend hook closed");
        assert_eq!(adding, auto);

        runtime_config.update_services(|services| {
            services.manual_routes = Some(BTreeSet::from(["192.168.1.0/24".parse().unwrap()]));
        });
        assert!(!declarations_changed.has_changed().unwrap());
        release.notify_one();

        let adding = tokio::time::timeout(Duration::from_millis(500), entered.recv())
            .await
            .expect("configuration changes must wake the manager before the device poll")
            .expect("backend hook closed");
        assert_eq!(adding, manual);
        release.notify_one();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("manager shutdown timed out")
            .unwrap()
            .unwrap();

        // Keeping the configuration authority alive cannot reopen declarations
        // or restart the stopped manager.
        runtime_config.update_services(|services| services.manual_routes = None);
        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_config_update_wakes_an_idle_manager_with_no_registrations() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (backend, mut entered) = MockRouteBackend::paused(release.clone());
        let (manager, _handle, cancel) = test_manager(backend);
        let runtime_config = manager.runtime_config.clone();
        let mut run = Box::pin(manager.run());

        // Empty initial inputs reach the notification wait without backend I/O.
        // Polling explicitly proves that this pass ran before configuration is
        // changed; the paused clock prevents the fallback timer from helping.
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert!(entered.try_recv().is_err());
        runtime_config.update_services(|services| {
            services.manual_routes = Some(BTreeSet::from(["192.168.1.0/24".parse().unwrap()]));
        });
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert_eq!(entered.try_recv().unwrap(), test_route("192.168.1.0/24"));

        release.notify_one();
        cancel.cancel();
        run.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_initial_manual_policy_needs_no_registration() {
        let release = Arc::new(tokio::sync::Notify::new());
        let (backend, mut entered) = MockRouteBackend::paused(release.clone());
        let (manager, _handle, cancel) = test_manager(backend);
        manager.runtime_config.update_services(|services| {
            services.manual_routes = Some(BTreeSet::from(["192.168.1.0/24".parse().unwrap()]));
        });
        assert!(manager.routes.is_empty());
        let task = tokio::spawn(manager.run());
        let adding = tokio::time::timeout(Duration::from_millis(500), entered.recv())
            .await
            .expect("initial configuration must be applied on the first pass")
            .expect("backend hook closed");
        assert_eq!(adding, test_route("192.168.1.0/24"));
        release.notify_one();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("manager shutdown timed out")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_manual_proxy_policy_from_configuration() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());

        let mut manager = RouteMgr::new(
            global_ctx,
            backend,
            routes,
            test_config_store(),
            cancel_token,
        );

        let auto_cidr = Ipv4Cidr::from_str("10.0.0.0/24").unwrap();
        let manual_cidr = Ipv4Cidr::from_str("192.168.1.0/24").unwrap();
        let additional_cidr = IpCidr::from_str("172.16.0.0/24").unwrap();

        let auto_reg = handle
            .register(RouteDemand::AutoProxy(BTreeSet::from([auto_cidr])))
            .unwrap();
        let runtime_config = manager.runtime_config.clone();
        let add_reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([additional_cidr])))
            .unwrap();

        // 1. manual is None: auto + additional
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 2);
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == IpCidr::V4(auto_cidr))
        );
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == additional_cidr)
        );

        // 2. manual is Some([manual_cidr]): manual replaces auto; additional retained
        let calls = (
            manager.backend.add_calls.len(),
            manager.backend.remove_calls.len(),
        );
        runtime_config.update_services(|services| services.dhcp_ipv4 = true);
        manager.reconcile().await;
        assert_eq!(
            calls,
            (
                manager.backend.add_calls.len(),
                manager.backend.remove_calls.len()
            )
        );

        runtime_config.update_services(|services| {
            services.manual_routes = Some(BTreeSet::from([manual_cidr]))
        });
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 2);
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == IpCidr::V4(manual_cidr))
        );
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == additional_cidr)
        );
        assert!(
            !manager
                .installed
                .iter()
                .any(|r| r.destination == IpCidr::V4(auto_cidr))
        );

        // 3. manual is Some(empty): all auto routes suppressed; additional retained
        runtime_config.update_services(|services| services.manual_routes = Some(BTreeSet::new()));
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == additional_cidr)
        );

        // 4. Auto updates while manual is active, then manual reverts to None: uses latest auto
        let auto_cidr2 = Ipv4Cidr::from_str("10.1.0.0/24").unwrap();
        auto_reg
            .replace(RouteDemand::AutoProxy(BTreeSet::from([auto_cidr2])))
            .unwrap();
        runtime_config.update_services(|services| services.manual_routes = None);
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 2);
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == IpCidr::V4(auto_cidr2))
        );
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == additional_cidr)
        );

        // 5. Independent declarations still withdraw on owner drop.
        drop(add_reg);
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);
        assert!(
            manager
                .installed
                .iter()
                .any(|r| r.destination == IpCidr::V4(auto_cidr2))
        );
    }
}
