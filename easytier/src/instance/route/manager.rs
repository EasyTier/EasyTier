use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use cidr::IpCidr;
use registry::Registry;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use easytier_core::host::route::{
    resolve_route_demands, RouteDemand, RouteHandle,
};

use crate::common::global_ctx::ArcGlobalCtx;

use super::backend::RouteBackend;
use super::model::{CleanupIncomplete, DeviceId, RetryState, Route, RouteError};

const DEFAULT_METRIC: u32 = 65535;

pub struct RouteMgr<B> {
    global_ctx: ArcGlobalCtx,
    backend: B,

    /// Live route declarations of all publishers.
    routes: Registry<RouteDemand>,
    /// Wakes the reconcile loop when a declaration changes.
    changed: watch::Receiver<()>,

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
        cancel: CancellationToken,
    ) -> Self {
        let changed = routes.subscribe();
        Self {
            global_ctx,
            backend,
            routes,
            changed,
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

    fn get_tun_device(&self) -> Option<DeviceId> {
        let ifindex = self.global_ctx.get_tun_device_index()?;
        Some(DeviceId::new(ifindex, None))
    }

    pub fn next_wakeup_time(&self) -> tokio::time::Instant {
        let now = tokio::time::Instant::now();
        // 1 second polling interval
        let fallback_deadline = now + Duration::from_secs(1);

        let earliest_retry = self.retries.values().map(|s| s.next_retry).min();

        match earliest_retry {
            Some(inst) => inst.min(fallback_deadline),
            None => fallback_deadline,
        }
    }

    pub async fn run(mut self) -> Result<(), CleanupIncomplete> {
        loop {
            if self.cancel.is_cancelled() {
                break;
            }

            // Confirm the notification baseline before reading: a change that
            // lands during reconcile stays pending for the wait below.
            self.changed.mark_unchanged();
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
                _ = tokio::time::sleep_until(next_wakeup) => {}
            }
        }

        self.perform_shutdown_cleanup().await
    }

    pub async fn reconcile(&mut self) {
        // 1. Read latest device fact and handle interface destruction / recreation
        let device_fact = self.get_tun_device();
        let device_changed = match (&self.current_tun_device, &device_fact) {
            (Some(old_dev), Some(new_dev)) => {
                old_dev.host_instance != new_dev.host_instance || old_dev.ifindex != new_dev.ifindex
            }
            (Some(_), None) => true,
            (None, Some(_)) => true,
            (None, None) => false,
        };

        if device_changed {
            if let Some(old_dev) = &self.current_tun_device {
                let old_ifindex = old_dev.ifindex;
                tracing::info!(
                    ?old_dev,
                    ?device_fact,
                    "TUN device destroyed or recreated, retiring routes via kernel cascading"
                );
                self.installed
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.external
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.unknown
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.retries
                    .retain(|r, _| r.interface.ifindex != old_ifindex);
            }
            self.current_tun_device = device_fact.clone();
            self.desired = None;
        }

        // 2. Resolve demanded CIDRs from snapshot
        let snapshot = self.routes.snapshot();
        let cidrs = match resolve_route_demands(&snapshot) {
            Ok(cidrs) => cidrs,
            Err(err) => {
                tracing::error!(?err, "failed to resolve route demands");
                return;
            }
        };

        for cidr in &cidrs {
            if matches!(cidr, IpCidr::V6(_)) {
                unimplemented!("ipv6 route is not supported yet");
            }
        }

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
        self.retries
            .retain(|r, _| desired.contains(r) || self.installed.contains(r));

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
            if self.cancel.is_cancelled() {
                break;
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
                    self.retries
                        .entry(route)
                        .or_insert_with(|| RetryState::new(now, 100))
                        .record_failure(now);
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

        // 7. Execute additions
        for route in to_add {
            if self.cancel.is_cancelled() {
                break;
            }
            // Check if there is an unknown route with the same destination (slot replacement block)
            if self
                .unknown
                .iter()
                .any(|u| u.destination == route.destination)
            {
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
                    self.retries
                        .entry(route)
                        .or_insert_with(|| RetryState::new(now, 100))
                        .record_failure(now);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(?route, ?err, "unknown result during add; isolating route");
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

        let mut uncleaned_routes = Vec::new();
        let mut newly_unknown = Vec::new();

        // 1. Re-read device fact before cleanup to account for devices that disappeared
        let latest_device = self.get_tun_device();
        if match (&self.current_tun_device, &latest_device) {
            (Some(old_dev), Some(new_dev)) => {
                old_dev.host_instance != new_dev.host_instance || old_dev.ifindex != new_dev.ifindex
            }
            (Some(_), None) => true,
            _ => false,
        } {
            if let Some(old_dev) = &self.current_tun_device {
                let old_ifindex = old_dev.ifindex;
                self.installed
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.unknown
                    .retain(|r| r.interface.ifindex != old_ifindex);
            }
        }

        // 2. Remove all remaining installed routes
        let installed = std::mem::take(&mut self.installed);
        let unknown = std::mem::take(&mut self.unknown);

        for route in installed {
            if unknown.contains(&route) {
                continue;
            }
            match self.backend.remove(&route).await {
                Ok(Some(())) | Ok(None) => {}
                Err(RouteError::Failed(err)) => {
                    tracing::error!(
                        ?route,
                        ?err,
                        "failed to remove route during shutdown cleanup"
                    );
                    uncleaned_routes.push(route);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(
                        ?route,
                        ?err,
                        "unknown result removing route during shutdown cleanup"
                    );
                    newly_unknown.push(route);
                }
            }
        }

        let mut all_unknown: Vec<Route> = unknown.into_iter().collect();
        all_unknown.extend(newly_unknown);

        if uncleaned_routes.is_empty() && all_unknown.is_empty() {
            Ok(())
        } else {
            Err(CleanupIncomplete {
                uncleaned_routes,
                unknown_routes: all_unknown,
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
            interface: DeviceId::new(TEST_DEVICE_INDEX, None),
            metric: 65535,
        }
    }

    fn test_manager(
        backend: MockRouteBackend,
    ) -> (RouteMgr<MockRouteBackend>, RouteHandle, CancellationToken) {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(TEST_DEVICE_INDEX));
        let cancel_token = CancellationToken::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let manager = RouteMgr::new(global_ctx, backend, routes, cancel_token.clone());
        (manager, handle, cancel_token)
    }

    /// Instrumentation that lets a test park the manager inside a backend call
    /// and prove it reached that await, without guessing with sleeps.
    struct PausedAdd {
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
        paused_add: Option<PausedAdd>,
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
                paused_add: Some(PausedAdd { entered, release }),
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
    async fn test_first_pass_reconciles_without_waiting() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());

        let mut manager = RouteMgr::new(global_ctx, backend, routes, cancel_token.clone());
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
        let dev = DeviceId::new(100, None);
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
        let mut manager = RouteMgr::new(global_ctx, backend, routes, cancel_token.clone());
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                fake_route.destination,
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
        let mut manager = RouteMgr::new(global_ctx.clone(), backend, routes, cancel_token);
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([cidr])))
            .unwrap();

        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);

        // Now destroy device 1 and recreate device 2 (new ifindex)
        let dev2 = DeviceId::new(101, None);
        global_ctx.set_tun_device_index_for_test(Some(101));

        manager.reconcile().await;
        // Old routes on dev1 retired, new route on dev2 installed!
        assert_eq!(manager.installed.len(), 1);
        let installed = manager.installed.iter().next().unwrap();
        assert_eq!(installed.interface, dev2);
    }

    #[tokio::test]
    async fn test_manager_stop_on_cancellation() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());

        let manager = RouteMgr::new(global_ctx, backend, routes, cancel_token.clone());
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                test_route("7.7.7.7/32").destination,
            ])))
            .unwrap();

        let join_handle = tokio::spawn(async move { manager.run().await });

        cancel_token.cancel();
        let res = join_handle.await.unwrap();
        assert!(res.is_ok());

        // Normal exit closes the registry before the asynchronous cleanup, so
        // publishers that are still alive lose their authority.
        assert!(handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .is_none());
        assert!(reg
            .replace(RouteDemand::Additional(BTreeSet::from([
                test_route("8.8.8.8/32").destination
            ])))
            .is_none());
        assert!(reg.get().is_none());
    }

    #[tokio::test]
    async fn test_failed_and_unknown_handling_and_slot_blocking() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let dev = DeviceId::new(100, None);
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
        let mut manager = RouteMgr::new(global_ctx, backend, routes, cancel_token.clone());
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                route.destination.clone(),
            ])))
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
        let dev = DeviceId::new(100, None);
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
        let mut manager = RouteMgr::new(global_ctx, backend, routes, cancel_token);
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                route.destination.clone(),
            ])))
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
        let mut manager = RouteMgr::new(global_ctx, backend, routes, cancel_token);

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
    #[should_panic(expected = "ipv6 route is not supported yet")]
    async fn test_ipv6_route_panics_unimplemented() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();

        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());
        let mut manager = RouteMgr::new(global_ctx, backend, routes, cancel_token);

        let v6_cidr = IpCidr::from_str("fd00::/64").unwrap();
        let _reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([v6_cidr])))
            .unwrap();

        manager.reconcile().await;
    }

    #[tokio::test]
    async fn test_normal_shutdown_closes_registry_but_external_leases_survive() {
        let (mut manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                test_route("7.7.7.7/32").destination,
            ])))
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
        assert!(reg
            .replace(RouteDemand::Additional(BTreeSet::from([
                test_route("8.8.8.8/32").destination
            ])))
            .is_none());
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
            .register(RouteDemand::Additional(BTreeSet::from([
                test_route("7.7.7.7/32").destination,
            ])))
            .unwrap();

        drop(manager);

        assert!(handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .is_none());
        assert!(reg
            .replace(RouteDemand::Additional(BTreeSet::from([
                test_route("8.8.8.8/32").destination
            ])))
            .is_none());
        assert!(reg.get().is_none());
    }

    #[tokio::test]
    async fn test_dropping_unpolled_run_future_revokes_registration() {
        let (manager, handle, _cancel) = test_manager(MockRouteBackend::new());
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([
                test_route("7.7.7.7/32").destination,
            ])))
            .unwrap();

        // The future owns the manager and is never polled; dropping it must
        // still close the registry.
        let run = manager.run();
        drop(run);

        assert!(handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .is_none());
        assert!(reg
            .replace(RouteDemand::Additional(BTreeSet::from([
                test_route("8.8.8.8/32").destination
            ])))
            .is_none());
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
        assert!(handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .is_none());
        assert!(reg
            .replace(RouteDemand::Additional(BTreeSet::from([
                test_route("8.8.8.8/32").destination
            ])))
            .is_none());
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

        assert!(handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .is_none());
        assert!(reg
            .replace(RouteDemand::Additional(BTreeSet::from([
                test_route("8.8.8.8/32").destination
            ])))
            .is_none());
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
        assert!(handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .is_none());
    }

    #[tokio::test]
    async fn test_manual_proxy_override_and_conflict_handling() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();
        let routes = Registry::default();
        let handle = RouteHandle::new(routes.clone());

        let mut manager = RouteMgr::new(global_ctx, backend, routes, cancel_token);

        let auto_cidr = Ipv4Cidr::from_str("10.0.0.0/24").unwrap();
        let manual_cidr = Ipv4Cidr::from_str("192.168.1.0/24").unwrap();
        let additional_cidr = IpCidr::from_str("172.16.0.0/24").unwrap();

        let auto_reg = handle
            .register(RouteDemand::AutoProxy(BTreeSet::from([auto_cidr])))
            .unwrap();
        let manual_reg = handle
            .register(RouteDemand::ManualProxy(None))
            .unwrap();
        let add_reg = handle
            .register(RouteDemand::Additional(BTreeSet::from([additional_cidr])))
            .unwrap();

        // 1. manual is None: auto + additional
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 2);
        assert!(manager.installed.iter().any(|r| r.destination == IpCidr::V4(auto_cidr)));
        assert!(manager.installed.iter().any(|r| r.destination == additional_cidr));

        // 2. manual is Some([manual_cidr]): manual replaces auto; additional retained
        manual_reg
            .replace(RouteDemand::ManualProxy(Some(BTreeSet::from([manual_cidr]))))
            .unwrap();
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 2);
        assert!(manager.installed.iter().any(|r| r.destination == IpCidr::V4(manual_cidr)));
        assert!(manager.installed.iter().any(|r| r.destination == additional_cidr));
        assert!(!manager.installed.iter().any(|r| r.destination == IpCidr::V4(auto_cidr)));

        // 3. manual is Some(empty): all auto routes suppressed; additional retained
        manual_reg
            .replace(RouteDemand::ManualProxy(Some(BTreeSet::new())))
            .unwrap();
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);
        assert!(manager.installed.iter().any(|r| r.destination == additional_cidr));

        // 4. Auto updates while manual is active, then manual reverts to None: uses latest auto
        let auto_cidr2 = Ipv4Cidr::from_str("10.1.0.0/24").unwrap();
        auto_reg
            .replace(RouteDemand::AutoProxy(BTreeSet::from([auto_cidr2])))
            .unwrap();
        manual_reg
            .replace(RouteDemand::ManualProxy(None))
            .unwrap();
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 2);
        assert!(manager.installed.iter().any(|r| r.destination == IpCidr::V4(auto_cidr2)));
        assert!(manager.installed.iter().any(|r| r.destination == additional_cidr));

        // 5. Duplicate ManualProxy: resolve error leaves previous installed untouched
        let duplicate_manual = handle
            .register(RouteDemand::ManualProxy(None))
            .unwrap();
        manager.reconcile().await;
        // Previous routes remain installed
        assert_eq!(manager.installed.len(), 2);

        // Dropping duplicate manual restores normal resolution
        drop(duplicate_manual);
        drop(add_reg);
        manager.reconcile().await;
        assert_eq!(manager.installed.len(), 1);
        assert!(manager.installed.iter().any(|r| r.destination == IpCidr::V4(auto_cidr2)));
    }
}
