use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};

use async_trait::async_trait;
use cidr::Ipv4Inet;
use rand::Rng;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    config::IpPrefix, peers::peer_manager::PeerManagerCore, runtime_config::CoreRuntimeConfigStore,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpIpv4Decision {
    WaitForPeers,
    Unchanged,
    Change {
        previous: Option<Ipv4Inet>,
        next: Option<Ipv4Inet>,
    },
}

#[derive(Debug)]
pub struct DhcpIpv4Allocator {
    default_subnet: Ipv4Inet,
    current: Option<Ipv4Inet>,
}

impl Default for DhcpIpv4Allocator {
    fn default() -> Self {
        Self::new(Ipv4Inet::new(Ipv4Addr::new(10, 126, 126, 0), 24).unwrap())
    }
}

impl DhcpIpv4Allocator {
    pub fn new(default_subnet: Ipv4Inet) -> Self {
        Self {
            default_subnet,
            current: None,
        }
    }

    pub fn current(&self) -> Option<Ipv4Inet> {
        self.current
    }

    pub fn reset(&mut self) {
        self.current = None;
    }

    pub fn commit(&mut self, next: Option<Ipv4Inet>) {
        self.current = next;
    }

    pub fn evaluate(&self, has_routes: bool, used_ipv4: &HashSet<Ipv4Inet>) -> DhcpIpv4Decision {
        if !has_routes {
            return DhcpIpv4Decision::WaitForPeers;
        }

        let subnet = used_ipv4.iter().next().unwrap_or(&self.default_subnet);
        if let Some(current) = self.current
            && current.network() == subnet.network()
            && !used_ipv4.contains(&current)
        {
            return DhcpIpv4Decision::Unchanged;
        }

        let next = subnet.network().iter().find(|candidate| {
            candidate.address() != subnet.first_address()
                && candidate.address() != subnet.last_address()
                && !used_ipv4.contains(candidate)
        });
        if self.current == next {
            return DhcpIpv4Decision::Unchanged;
        }

        DhcpIpv4Decision::Change {
            previous: self.current,
            next,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DhcpIpv4RouteSnapshot {
    pub has_routes: bool,
    pub used_ipv4: HashSet<Ipv4Inet>,
}

#[async_trait]
pub trait DhcpIpv4RouteSource: Send + Sync + 'static {
    async fn dhcp_ipv4_route_snapshot(&self) -> DhcpIpv4RouteSnapshot;
}

#[async_trait]
impl DhcpIpv4RouteSource for PeerManagerCore {
    async fn dhcp_ipv4_route_snapshot(&self) -> DhcpIpv4RouteSnapshot {
        let routes = self.get_route().list_routes().await;
        let has_routes = !routes.is_empty();
        let used_ipv4 = routes
            .into_iter()
            .filter_map(|route| route.ipv4_addr.map(Into::into))
            .collect();
        DhcpIpv4RouteSnapshot {
            has_routes,
            used_ipv4,
        }
    }
}

#[async_trait]
pub trait DhcpIpv4Host: Send + Sync + 'static {
    fn take_interface_closed(&self) -> bool;

    async fn apply_dhcp_ipv4(
        &self,
        previous: Option<Ipv4Inet>,
        next: Option<Ipv4Inet>,
    ) -> DhcpIpv4ApplyOutcome;

    fn publish_dhcp_ipv4(
        &self,
        _previous: Option<Ipv4Inet>,
        _requested: Option<Ipv4Inet>,
        _actual: Option<Ipv4Inet>,
    ) {
    }
}

pub struct DhcpIpv4ApplyPermit {
    _guard: Box<dyn Send>,
}

impl DhcpIpv4ApplyPermit {
    pub fn new(guard: impl Send + 'static) -> Self {
        Self {
            _guard: Box::new(guard),
        }
    }
}

pub struct DhcpIpv4ApplyOutcome {
    pub actual: Option<Ipv4Inet>,
    pub result: anyhow::Result<()>,
    permit: Option<DhcpIpv4ApplyPermit>,
}

impl DhcpIpv4ApplyOutcome {
    pub fn applied(actual: Option<Ipv4Inet>) -> Self {
        Self {
            actual,
            result: Ok(()),
            permit: None,
        }
    }

    pub fn failed(actual: Option<Ipv4Inet>, error: impl Into<anyhow::Error>) -> Self {
        Self {
            actual,
            result: Err(error.into()),
            permit: None,
        }
    }

    pub fn with_permit(mut self, permit: DhcpIpv4ApplyPermit) -> Self {
        self.permit = Some(permit);
        self
    }
}

pub struct DhcpIpv4Service {
    operation: tokio::sync::Mutex<()>,
    allocator: std::sync::Mutex<DhcpIpv4Allocator>,
    route_source: Arc<dyn DhcpIpv4RouteSource>,
    runtime_config: CoreRuntimeConfigStore,
    host: Arc<dyn DhcpIpv4Host>,
}

impl DhcpIpv4Service {
    pub fn new(
        route_source: Arc<dyn DhcpIpv4RouteSource>,
        runtime_config: CoreRuntimeConfigStore,
        host: Arc<dyn DhcpIpv4Host>,
    ) -> Arc<Self> {
        Arc::new(Self {
            operation: tokio::sync::Mutex::new(()),
            allocator: std::sync::Mutex::new(DhcpIpv4Allocator::default()),
            route_source,
            runtime_config,
            host,
        })
    }

    pub fn current(&self) -> Option<Ipv4Inet> {
        self.allocator.lock().unwrap().current()
    }

    pub async fn reconcile_once(&self) -> bool {
        let _operation = self.operation.lock().await;
        if self.host.take_interface_closed() {
            self.allocator.lock().unwrap().reset();
        }
        let snapshot = self.route_source.dhcp_ipv4_route_snapshot().await;
        let decision = self
            .allocator
            .lock()
            .unwrap()
            .evaluate(snapshot.has_routes, &snapshot.used_ipv4);

        let DhcpIpv4Decision::Change { previous, next } = decision else {
            return snapshot.has_routes;
        };
        tracing::debug!(?previous, ?next, "DHCP IPv4 reconciliation applying change");
        let outcome = self.host.apply_dhcp_ipv4(previous, next).await;
        let DhcpIpv4ApplyOutcome {
            actual,
            result,
            permit,
        } = outcome;
        self.runtime_config.update_peer_with(|peer| {
            peer.runtime.core.routes.ipv4 = actual.map(|actual| IpPrefix {
                address: actual.address().into(),
                prefix_len: actual.network_length(),
            });
        });
        match result {
            Ok(()) => {
                self.allocator.lock().unwrap().commit(actual);
                self.host.publish_dhcp_ipv4(previous, next, actual);
            }
            Err(err) => {
                tracing::error!(?previous, ?next, ?actual, ?err, "DHCP IPv4 apply failed");
            }
        }
        drop(permit);
        snapshot.has_routes
    }

    pub fn start(self: &Arc<Self>) -> AbortOnDropHandle<()> {
        let service = self.clone();
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut next_sleep = Duration::ZERO;
            loop {
                crate::foundation::time::sleep(next_sleep).await;
                next_sleep = if service.reconcile_once().await {
                    Duration::from_secs(rand::thread_rng().gen_range(5..10))
                } else {
                    Duration::from_secs(1)
                };
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct StaticRouteSource {
        snapshot: Mutex<DhcpIpv4RouteSnapshot>,
    }

    #[async_trait]
    impl DhcpIpv4RouteSource for StaticRouteSource {
        async fn dhcp_ipv4_route_snapshot(&self) -> DhcpIpv4RouteSnapshot {
            self.snapshot.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct RecordingHost {
        interface_closed: AtomicBool,
        fail_apply: AtomicBool,
        hold_apply_permit: AtomicBool,
        permit_held: Arc<AtomicBool>,
        published_with_permit: AtomicBool,
        runtime_config: Mutex<Option<CoreRuntimeConfigStore>>,
        published_runtime_ipv4: Mutex<Vec<Option<IpPrefix>>>,
        changes: Mutex<Vec<(Option<Ipv4Inet>, Option<Ipv4Inet>)>>,
        published: Mutex<Vec<(Option<Ipv4Inet>, Option<Ipv4Inet>, Option<Ipv4Inet>)>>,
    }

    struct RecordingPermit(Arc<AtomicBool>);

    impl Drop for RecordingPermit {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    #[async_trait]
    impl DhcpIpv4Host for RecordingHost {
        fn take_interface_closed(&self) -> bool {
            self.interface_closed.swap(false, Ordering::AcqRel)
        }

        async fn apply_dhcp_ipv4(
            &self,
            previous: Option<Ipv4Inet>,
            next: Option<Ipv4Inet>,
        ) -> DhcpIpv4ApplyOutcome {
            self.changes.lock().unwrap().push((previous, next));
            let mut outcome = if self.fail_apply.load(Ordering::Acquire) {
                DhcpIpv4ApplyOutcome::failed(None, anyhow::anyhow!("apply failed"))
            } else {
                DhcpIpv4ApplyOutcome::applied(next)
            };
            if self.hold_apply_permit.load(Ordering::Acquire) {
                assert!(!self.permit_held.swap(true, Ordering::AcqRel));
                outcome = outcome.with_permit(DhcpIpv4ApplyPermit::new(RecordingPermit(
                    self.permit_held.clone(),
                )));
            }
            outcome
        }

        fn publish_dhcp_ipv4(
            &self,
            previous: Option<Ipv4Inet>,
            requested: Option<Ipv4Inet>,
            actual: Option<Ipv4Inet>,
        ) {
            self.published_with_permit
                .store(self.permit_held.load(Ordering::Acquire), Ordering::Release);
            if let Some(runtime_config) = self.runtime_config.lock().unwrap().as_ref() {
                self.published_runtime_ipv4.lock().unwrap().push(
                    runtime_config
                        .snapshot()
                        .peer
                        .runtime
                        .core
                        .routes
                        .ipv4
                        .clone(),
                );
            }
            self.published
                .lock()
                .unwrap()
                .push((previous, requested, actual));
        }
    }

    fn service(
        snapshot: DhcpIpv4RouteSnapshot,
        host: Arc<RecordingHost>,
    ) -> (Arc<DhcpIpv4Service>, CoreRuntimeConfigStore) {
        let runtime_config = CoreRuntimeConfigStore::new(
            crate::runtime_config::CoreRuntimeConfig::default(),
            Arc::new(crate::peers::context::PeerRuntimeSnapshot::default()),
        );
        *host.runtime_config.lock().unwrap() = Some(runtime_config.clone());
        let service = DhcpIpv4Service::new(
            Arc::new(StaticRouteSource {
                snapshot: Mutex::new(snapshot),
            }),
            runtime_config.clone(),
            host,
        );
        (service, runtime_config)
    }

    #[test]
    fn waits_until_at_least_one_route_exists() {
        let allocator = DhcpIpv4Allocator::default();

        assert_eq!(
            allocator.evaluate(false, &HashSet::new()),
            DhcpIpv4Decision::WaitForPeers
        );
    }

    #[test]
    fn uses_default_subnet_when_routes_have_no_ipv4() {
        let allocator = DhcpIpv4Allocator::default();

        assert_eq!(
            allocator.evaluate(true, &HashSet::new()),
            DhcpIpv4Decision::Change {
                previous: None,
                next: Some("10.126.126.1/24".parse().unwrap()),
            }
        );
    }

    #[test]
    fn keeps_current_address_when_it_is_free_in_the_selected_subnet() {
        let mut allocator = DhcpIpv4Allocator::default();
        allocator.commit(Some("10.1.2.8/24".parse().unwrap()));
        let used = HashSet::from(["10.1.2.2/24".parse().unwrap()]);

        assert_eq!(allocator.evaluate(true, &used), DhcpIpv4Decision::Unchanged);
    }

    #[test]
    fn selects_first_available_host_after_a_conflict() {
        let mut allocator = DhcpIpv4Allocator::default();
        allocator.commit(Some("10.1.2.1/24".parse().unwrap()));
        let used = HashSet::from([
            "10.1.2.1/24".parse().unwrap(),
            "10.1.2.2/24".parse().unwrap(),
        ]);

        assert_eq!(
            allocator.evaluate(true, &used),
            DhcpIpv4Decision::Change {
                previous: Some("10.1.2.1/24".parse().unwrap()),
                next: Some("10.1.2.3/24".parse().unwrap()),
            }
        );
    }

    #[test]
    fn reset_forgets_the_previous_interface_address() {
        let mut allocator = DhcpIpv4Allocator::default();
        allocator.commit(Some("10.1.2.8/24".parse().unwrap()));

        allocator.reset();

        assert_eq!(allocator.current(), None);
    }

    #[tokio::test]
    async fn service_commits_only_after_host_apply_succeeds() {
        let host = Arc::new(RecordingHost::default());
        let (service, runtime_config) = service(
            DhcpIpv4RouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::new(),
            },
            host.clone(),
        );

        assert!(service.reconcile_once().await);

        assert_eq!(service.current(), Some("10.126.126.1/24".parse().unwrap()));
        assert_eq!(
            *host.changes.lock().unwrap(),
            [(None, Some("10.126.126.1/24".parse().unwrap()))]
        );
        assert_eq!(
            runtime_config.snapshot().peer.runtime.core.routes.ipv4,
            Some(IpPrefix::new("10.126.126.1".parse().unwrap(), 24).unwrap())
        );
        assert_eq!(
            *host.published.lock().unwrap(),
            [(
                None,
                Some("10.126.126.1/24".parse().unwrap()),
                Some("10.126.126.1/24".parse().unwrap())
            )]
        );
    }

    #[tokio::test]
    async fn service_holds_host_permit_through_store_and_event_commit() {
        let host = Arc::new(RecordingHost::default());
        host.hold_apply_permit.store(true, Ordering::Release);
        let (service, _runtime_config) = service(
            DhcpIpv4RouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::new(),
            },
            host.clone(),
        );

        service.reconcile_once().await;

        let expected = Some(IpPrefix::new("10.126.126.1".parse().unwrap(), 24).unwrap());
        assert!(host.published_with_permit.load(Ordering::Acquire));
        assert_eq!(
            host.published_runtime_ipv4.lock().unwrap().as_slice(),
            &[expected]
        );
        assert!(!host.permit_held.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn service_retries_change_when_host_apply_fails() {
        let host = Arc::new(RecordingHost::default());
        host.fail_apply.store(true, Ordering::Release);
        let (service, runtime_config) = service(
            DhcpIpv4RouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::new(),
            },
            host.clone(),
        );

        service.reconcile_once().await;
        service.reconcile_once().await;

        assert_eq!(service.current(), None);
        assert_eq!(host.changes.lock().unwrap().len(), 2);
        assert_eq!(
            runtime_config.snapshot().peer.runtime.core.routes.ipv4,
            None
        );
        assert!(host.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn interface_close_resets_previous_allocation_before_reapply() {
        let host = Arc::new(RecordingHost::default());
        let (service, _runtime_config) = service(
            DhcpIpv4RouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::new(),
            },
            host.clone(),
        );
        service.reconcile_once().await;
        host.interface_closed.store(true, Ordering::Release);

        service.reconcile_once().await;

        assert_eq!(
            host.changes.lock().unwrap().as_slice(),
            [
                (None, Some("10.126.126.1/24".parse().unwrap())),
                (None, Some("10.126.126.1/24".parse().unwrap())),
            ]
        );
    }
}
