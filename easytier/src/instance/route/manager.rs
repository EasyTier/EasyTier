use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use cidr::IpCidr;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;
use crate::utils::dirty::DirtyFlag;

use super::backend::RouteBackend;
use super::handle::{RouteHandle, RouteSlot};
use super::model::{CleanupIncomplete, DeviceId, RetryState, Route, RouteError};

/// Helper to stop a route manager task with timeout and cancel-safety.
/// If timeout occurs, the JoinHandle remains in `join_handle` so the caller can wait again.
pub async fn stop_route_mgr(
    cancel_token: &CancellationToken,
    join_handle: &mut Option<tokio::task::JoinHandle<Result<(), CleanupIncomplete>>>,
    deadline: tokio::time::Instant,
) -> Result<(), CleanupIncomplete> {
    cancel_token.cancel();
    let Some(handle) = join_handle.as_mut() else {
        return Ok(());
    };
    match tokio::time::timeout_at(deadline, handle).await {
        Ok(join_res) => {
            let _ = join_handle.take();
            match join_res {
                Ok(manager_res) => manager_res,
                Err(panic_err) => Err(CleanupIncomplete {
                    reason: format!("route manager task terminated abnormally: {panic_err}"),
                    ..Default::default()
                }),
            }
        }
        Err(_) => Err(CleanupIncomplete {
            reason: "deadline exceeded while waiting for stop cleanup; manager task running in background".to_string(),
            ..Default::default()
        }),
    }
}

pub struct RouteMgr<B> {
    global_ctx: ArcGlobalCtx,
    backend: B,

    slots: Arc<Mutex<Vec<Weak<RouteSlot>>>>,
    dirty: Arc<DirtyFlag>,

    installed_routes: BTreeSet<Route>,
    external_present: BTreeSet<Route>,
    unknown_routes: BTreeSet<Route>,
    retry_tracker: BTreeMap<Route, RetryState>,

    current_tun_device: Option<DeviceId>,
    desired_routes_cache: Option<BTreeSet<Route>>,

    cancel_token: CancellationToken,

    default_metric: u32,
}

impl<B: RouteBackend> RouteMgr<B> {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        backend: B,
        cancel_token: CancellationToken,
        default_metric: u32,
    ) -> Self {
        let slots = Arc::new(Mutex::new(Vec::new()));
        let dirty = Arc::new(DirtyFlag::default());
        Self {
            global_ctx,
            backend,
            slots,
            dirty,
            installed_routes: BTreeSet::new(),
            external_present: BTreeSet::new(),
            unknown_routes: BTreeSet::new(),
            retry_tracker: BTreeMap::new(),
            current_tun_device: None,
            desired_routes_cache: None,
            cancel_token,
            default_metric,
        }
    }

    pub fn handle(&self) -> RouteHandle {
        RouteHandle::new(self.slots.clone(), self.dirty.clone())
    }

    fn get_tun_device(&self) -> Option<DeviceId> {
        let ifindex = self.global_ctx.get_tun_device_index()?;
        Some(DeviceId::new(ifindex, None))
    }

    pub fn next_wakeup_time(&self) -> tokio::time::Instant {
        let now = tokio::time::Instant::now();
        // 1 second polling interval
        let fallback_deadline = now + Duration::from_secs(1);

        let earliest_retry = self.retry_tracker.values().map(|s| s.next_retry).min();

        match earliest_retry {
            Some(inst) => inst.min(fallback_deadline),
            None => fallback_deadline,
        }
    }

    pub async fn run(mut self) -> Result<(), CleanupIncomplete> {
        loop {
            if self.cancel_token.is_cancelled() {
                break;
            }

            self.dirty.reset();
            self.reconcile().await;

            if self.cancel_token.is_cancelled() {
                break;
            }

            let next_wakeup = self.next_wakeup_time();

            tokio::select! {
                biased;
                _ = self.cancel_token.cancelled() => break,
                _ = self.dirty.wait() => {}
                _ = tokio::time::sleep_until(next_wakeup) => {}
            }
        }

        self.perform_shutdown_cleanup().await
    }

    pub async fn reconcile(&mut self) {
        // 1. Collect active CIDRs and purge dead slots
        let cidrs: BTreeSet<IpCidr> = {
            let mut slots_guard = self.slots.lock();
            slots_guard.retain(|w| w.strong_count() > 0);
            slots_guard
                .iter()
                .filter_map(Weak::upgrade)
                .flat_map(|slot| slot.read().clone())
                .collect()
        };

        for cidr in &cidrs {
            if matches!(cidr, IpCidr::V6(_)) {
                unimplemented!("ipv6 route is not supported yet");
            }
        }

        // 2. Read latest device fact
        let device_fact = self.get_tun_device();

        // 3. Handle interface destruction / recreation via host_instance and ifindex
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
                self.installed_routes
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.external_present
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.unknown_routes
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.retry_tracker
                    .retain(|r, _| r.interface.ifindex != old_ifindex);
            }
            self.current_tun_device = device_fact.clone();
            self.desired_routes_cache = None;
        }

        // 4. Compute desired routes from active slots
        let desired = match &self.current_tun_device {
            Some(dev) => cidrs
                .into_iter()
                .map(|destination| Route {
                    destination,
                    interface: dev.clone(),
                    metric: self.default_metric,
                })
                .collect(),
            None => BTreeSet::new(),
        };

        // Scope external_present and retry_tracker to only currently desired routes
        self.external_present.retain(|r| desired.contains(r));
        self.retry_tracker
            .retain(|r, _| desired.contains(r) || self.installed_routes.contains(r));

        self.desired_routes_cache = Some(desired.clone());

        // 5. Calculate diffs
        let now = tokio::time::Instant::now();

        // Routes to remove: in installed, not in desired, not unknown
        let to_remove: Vec<Route> = self
            .installed_routes
            .difference(&desired)
            .filter(|r| !self.unknown_routes.contains(r))
            .filter(|r| {
                if let Some(retry) = self.retry_tracker.get(r) {
                    retry.next_retry <= now
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Routes to add: in desired, not in installed, not in external_present, not unknown
        let to_add: Vec<Route> = desired
            .difference(&self.installed_routes)
            .filter(|r| !self.external_present.contains(r))
            .filter(|r| !self.unknown_routes.contains(r))
            .filter(|r| {
                if let Some(retry) = self.retry_tracker.get(r) {
                    retry.next_retry <= now
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // 6. Execute removals
        for route in to_remove {
            if self.cancel_token.is_cancelled() {
                break;
            }
            match self.backend.remove(&route).await {
                Ok(Some(())) | Ok(None) => {
                    self.installed_routes.remove(&route);
                    self.retry_tracker.remove(&route);
                }
                Err(RouteError::Failed(err)) => {
                    tracing::warn!(?route, ?err, "failed to remove route, will retry with backoff");
                    self.retry_tracker
                        .entry(route)
                        .or_insert_with(|| RetryState::new(now, 100))
                        .record_failure(now);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(?route, ?err, "unknown result during remove; isolating route");
                    self.unknown_routes.insert(route.clone());
                    self.retry_tracker.remove(&route);
                }
            }
        }

        // 7. Execute additions
        for route in to_add {
            if self.cancel_token.is_cancelled() {
                break;
            }
            // Check if there is an unknown route with the same destination (slot replacement block)
            if self
                .unknown_routes
                .iter()
                .any(|u| u.destination == route.destination)
            {
                continue;
            }

            match self.backend.add(&route).await {
                Ok(Some(actual)) => {
                    self.installed_routes.insert(actual);
                    self.retry_tracker.remove(&route);
                }
                Ok(None) => {
                    // Equivalent external route already exists
                    self.external_present.insert(route.clone());
                    self.retry_tracker.remove(&route);
                }
                Err(RouteError::Failed(err)) => {
                    tracing::warn!(?route, ?err, "failed to add route, will retry with backoff");
                    self.retry_tracker
                        .entry(route)
                        .or_insert_with(|| RetryState::new(now, 100))
                        .record_failure(now);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(?route, ?err, "unknown result during add; isolating route");
                    self.unknown_routes.insert(route.clone());
                    self.retry_tracker.remove(&route);
                }
            }
        }
    }

    pub async fn perform_shutdown_cleanup(&mut self) -> Result<(), CleanupIncomplete> {
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
                self.installed_routes
                    .retain(|r| r.interface.ifindex != old_ifindex);
                self.unknown_routes
                    .retain(|r| r.interface.ifindex != old_ifindex);
            }
        }

        // 2. Remove all remaining installed routes
        let installed = std::mem::take(&mut self.installed_routes);
        let unknown = std::mem::take(&mut self.unknown_routes);

        for route in installed {
            if unknown.contains(&route) {
                continue;
            }
            match self.backend.remove(&route).await {
                Ok(Some(())) | Ok(None) => {}
                Err(RouteError::Failed(err)) => {
                    tracing::error!(?route, ?err, "failed to remove route during shutdown cleanup");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use cidr::{IpCidr, Ipv4Cidr};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[derive(Default)]
    struct MockRouteBackend {
        routes: BTreeSet<Route>,
        add_calls: Vec<Route>,
        remove_calls: Vec<Route>,
        add_error_map: HashMap<Route, RouteError>,
        remove_error_map: HashMap<Route, RouteError>,
        external_present: BTreeSet<Route>,
    }

    impl MockRouteBackend {
        fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait::async_trait]
    impl RouteBackend for MockRouteBackend {
        async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError> {
            self.add_calls.push(route.clone());
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

        let mut manager = RouteMgr::new(global_ctx, backend, cancel_token.clone(), 65535);
        let handle = manager.handle();
        let lease = handle.register();

        // Initial reconcile should populate without waiting for notify
        manager.reconcile().await;
        assert_eq!(manager.installed_routes.len(), 0); // No routes yet

        // Now add an extra route
        let cidr = IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(7, 7, 7, 7), 32).unwrap());
        lease.set(BTreeSet::from([cidr]));

        // Reconcile
        manager.reconcile().await;
        assert_eq!(manager.installed_routes.len(), 1);
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

        let mut manager = RouteMgr::new(global_ctx, backend, cancel_token.clone(), 65535);
        let handle = manager.handle();
        let lease = handle.register();
        lease.set(BTreeSet::from([fake_route.destination]));

        manager.reconcile().await;
        // Should not be in installed_routes, but in external_present!
        assert!(manager.installed_routes.is_empty());
        assert!(manager.external_present.contains(&fake_route));

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

        let mut manager = RouteMgr::new(global_ctx.clone(), backend, cancel_token, 65535);
        let handle = manager.handle();
        let lease = handle.register();
        lease.set(BTreeSet::from([cidr]));

        manager.reconcile().await;
        assert_eq!(manager.installed_routes.len(), 1);

        // Now destroy device 1 and recreate device 2 (new ifindex)
        let dev2 = DeviceId::new(101, None);
        global_ctx.set_tun_device_index_for_test(Some(101));

        manager.reconcile().await;
        // Old routes on dev1 retired, new route on dev2 installed!
        assert_eq!(manager.installed_routes.len(), 1);
        let installed = manager.installed_routes.iter().next().unwrap();
        assert_eq!(installed.interface, dev2);
    }

    #[tokio::test]
    async fn test_stop_route_mgr_timeout_and_completion() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();

        let manager = RouteMgr::new(global_ctx, backend, cancel_token.clone(), 65535);

        let mut join_handle = Some(tokio::spawn(async move { manager.run().await }));

        // Stop manager
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let res = stop_route_mgr(&cancel_token, &mut join_handle, deadline).await;
        assert!(res.is_ok());
        assert!(join_handle.is_none());
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
        backend
            .add_error_map
            .insert(route.clone(), RouteError::Unknown(anyhow::anyhow!("timeout")));

        let mut manager = RouteMgr::new(global_ctx, backend, cancel_token.clone(), 65535);
        let handle = manager.handle();
        let lease = handle.register();
        lease.set(BTreeSet::from([route.destination.clone()]));

        manager.reconcile().await;

        // Route should be in unknown_routes, not in installed
        assert!(manager.installed_routes.is_empty());
        assert!(manager.unknown_routes.contains(&route));

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

        let mut manager = RouteMgr::new(global_ctx, backend, cancel_token, 65535);
        let handle = manager.handle();
        let lease = handle.register();
        lease.set(BTreeSet::from([route.destination.clone()]));

        manager.reconcile().await;
        assert!(manager.external_present.contains(&route));

        // Withdraw extra demand
        lease.clear();
        manager.reconcile().await;
        // external_present should now be cleared because the route is no longer desired
        assert!(manager.external_present.is_empty());
    }

    #[tokio::test]
    async fn test_two_independent_leases_sharing_route_and_raii_drop() {
        let cancel_token = CancellationToken::new();

        let global_ctx = get_mock_global_ctx();
        global_ctx.set_tun_device_index_for_test(Some(100));
        let backend = MockRouteBackend::new();

        let mut manager = RouteMgr::new(global_ctx, backend, cancel_token, 65535);
        let handle = manager.handle();

        let lease1 = handle.register();
        let lease2 = handle.register();

        let cidr = IpCidr::from_str("10.10.10.10/32").unwrap();
        lease1.set(BTreeSet::from([cidr]));
        lease2.set(BTreeSet::from([cidr]));

        manager.reconcile().await;

        // Merged into 1 route in installed and backend
        assert_eq!(manager.installed_routes.len(), 1);
        assert_eq!(manager.backend.routes.len(), 1);
        assert_eq!(manager.backend.add_calls.len(), 1);

        // 2. Drop lease1 -> route remains installed because lease2 still desires it!
        drop(lease1);
        manager.reconcile().await;
        assert_eq!(manager.installed_routes.len(), 1);
        assert_eq!(manager.backend.routes.len(), 1);

        // 3. Drop lease2 -> route removed from system
        drop(lease2);
        manager.reconcile().await;
        assert_eq!(manager.installed_routes.len(), 0);
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

        let mut manager = RouteMgr::new(global_ctx, backend, cancel_token, 65535);
        let handle = manager.handle();
        let lease = handle.register();

        let v6_cidr = IpCidr::from_str("fd00::/64").unwrap();
        lease.set(BTreeSet::from([v6_cidr]));

        manager.reconcile().await;
    }
}
