use std::{collections::HashSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use cidr::{Inet, Ipv4Inet, Ipv6Inet};
use rand::Rng;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    config::IpPrefix, config::runtime::CoreRuntimeConfigStore, peers::peer_manager::PeerManagerCore,
};

#[cfg(any(feature = "dhcp-ipv4", feature = "dhcp-ipv6"))]
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpDecision<I = Ipv4Inet> {
    WaitForPeers,
    Unchanged,
    Change {
        previous: Option<I>,
        next: Option<I>,
    },
}

// Give an already-addressed peer time to announce its subnet before a fresh
// network's first node falls back to the bootstrap subnet.
const BOOTSTRAP_WAIT_ROUNDS: u32 = 2;

#[derive(Debug)]
pub struct DhcpAllocator<I: Inet> {
    default_subnet: Option<I>,
    current: Option<I>,
    no_address_rounds: u32,
}

impl<I: Inet> Default for DhcpAllocator<I> {
    fn default() -> Self {
        Self {
            default_subnet: None,
            current: None,
            no_address_rounds: 0,
        }
    }
}

impl<I: Inet> DhcpAllocator<I> {
    pub fn new(default_subnet: I) -> Self {
        Self {
            default_subnet: Some(default_subnet),
            current: None,
            no_address_rounds: 0,
        }
    }

    pub fn current(&self) -> Option<I> {
        self.current
    }

    pub fn reset(&mut self) {
        self.current = None;
        self.no_address_rounds = 0;
    }

    pub fn commit(&mut self, next: Option<I>) {
        self.current = next;
    }

    fn evaluate_with(
        &mut self,
        has_routes: bool,
        used: &HashSet<I>,
        usable_subnet: impl Fn(I) -> bool,
        pick: impl FnOnce(I, bool) -> Option<I>,
    ) -> DhcpDecision<I> {
        if !has_routes && self.default_subnet.is_none() {
            return DhcpDecision::WaitForPeers;
        }

        let advertised = used
            .iter()
            .filter(|subnet| usable_subnet(**subnet))
            .min_by_key(|subnet| {
                (
                    self.current
                        .is_none_or(|current| current.network() != subnet.network()),
                    subnet.first_address(),
                    subnet.network_length(),
                )
            });
        let subnet = if let Some(subnet) = advertised {
            self.no_address_rounds = 0;
            *subnet
        } else if let Some(current) = self.current {
            current
        } else {
            let Some(default_subnet) = self.default_subnet else {
                return DhcpDecision::WaitForPeers;
            };
            self.no_address_rounds = self.no_address_rounds.saturating_add(1);
            if self.no_address_rounds <= BOOTSTRAP_WAIT_ROUNDS {
                return DhcpDecision::WaitForPeers;
            }
            default_subnet
        };
        if let Some(current) = self.current
            && current.network() == subnet.network()
            && !used.iter().any(|peer| peer.address() == current.address())
        {
            return DhcpDecision::Unchanged;
        }

        let next = pick(subnet, self.current.is_some());
        if self.current == next {
            return DhcpDecision::Unchanged;
        }

        DhcpDecision::Change {
            previous: self.current,
            next,
        }
    }
}

impl DhcpAllocator<Ipv4Inet> {
    pub fn evaluate(
        &mut self,
        has_routes: bool,
        used: &HashSet<Ipv4Inet>,
    ) -> DhcpDecision<Ipv4Inet> {
        self.evaluate_with_rng(has_routes, used, &mut rand::thread_rng())
    }

    fn evaluate_with_rng(
        &mut self,
        has_routes: bool,
        used: &HashSet<Ipv4Inet>,
        rng: &mut impl Rng,
    ) -> DhcpDecision<Ipv4Inet> {
        self.evaluate_with(
            has_routes,
            used,
            |_| true,
            |subnet, retry| {
                let first = u32::from(subnet.first_address());
                let span = u32::from(subnet.last_address()) - first;
                // Spread simultaneous bootstrap allocations and conflict retries across
                // the subnet. Existing route announcements still detect collisions.
                let offset = if span > 1 && (used.is_empty() || retry) {
                    rng.gen_range(1..span)
                } else {
                    1
                };
                (offset..span).chain(1..offset).find_map(|offset| {
                    let candidate =
                        Ipv4Inet::new((first + offset).into(), subnet.network_length()).ok()?;
                    (!used.contains(&candidate)).then_some(candidate)
                })
            },
        )
    }
}

impl DhcpAllocator<Ipv6Inet> {
    pub fn evaluate(
        &mut self,
        has_routes: bool,
        used: &HashSet<Ipv6Inet>,
    ) -> DhcpDecision<Ipv6Inet> {
        self.evaluate_with_rng(has_routes, used, &mut rand::thread_rng())
    }

    fn evaluate_with_rng(
        &mut self,
        has_routes: bool,
        used: &HashSet<Ipv6Inet>,
        rng: &mut impl Rng,
    ) -> DhcpDecision<Ipv6Inet> {
        let used_ips = used
            .iter()
            .map(|peer| peer.address())
            .collect::<HashSet<_>>();
        self.evaluate_with(
            has_routes,
            used,
            |subnet| crate::config::valid_ipv6_subnet(subnet.network()),
            |subnet, _retry| {
                let first = u128::from(subnet.first_address());
                let span = u128::from(subnet.last_address()) - first;
                if span <= 1 {
                    return None;
                }
                // Reserve the subnet endpoints. In particular, older EasyTier peers
                // flood packets addressed to the last address of an IPv6 subnet.
                let mut offset = rng.gen_range(1..span);
                // There can be at most used_ips.len() occupied candidates. This
                // bound avoids ever walking an entire IPv6 subnet.
                for _ in 0..(used_ips.len() as u128 + 1).min(span - 1) {
                    let candidate =
                        Ipv6Inet::new((first + offset).into(), subnet.network_length()).ok()?;
                    if !used_ips.contains(&candidate.address()) {
                        return Some(candidate);
                    }
                    offset = if offset + 1 == span { 1 } else { offset + 1 };
                }
                None
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DhcpAddresses {
    pub ipv4: Option<Ipv4Inet>,
    pub ipv6: Option<Ipv6Inet>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DhcpRouteSnapshot {
    pub has_routes: bool,
    pub used_ipv4: HashSet<Ipv4Inet>,
    pub used_ipv6: HashSet<Ipv6Inet>,
}

#[async_trait]
pub trait DhcpRouteSource: Send + Sync + 'static {
    async fn dhcp_route_snapshot(&self) -> DhcpRouteSnapshot;
}

#[async_trait]
impl DhcpRouteSource for PeerManagerCore {
    async fn dhcp_route_snapshot(&self) -> DhcpRouteSnapshot {
        let routes = self.get_route().list_routes().await;
        DhcpRouteSnapshot {
            has_routes: !routes.is_empty(),
            used_ipv4: routes
                .iter()
                .filter_map(|route| route.ipv4_addr.map(Into::into))
                .collect(),
            used_ipv6: routes
                .iter()
                .filter_map(|route| route.ipv6_addr.map(Ipv6Inet::from))
                .collect(),
        }
    }
}

#[async_trait]
pub trait DhcpHost: Send + Sync + 'static {
    fn take_interface_closed(&self) -> bool;

    /// Only enabled DHCP families are supplied. The Host merges static addresses
    /// when configuring its interface, without publishing those static snapshots.
    async fn apply_dhcp(&self, next: DhcpAddresses) -> DhcpApplyOutcome;

    fn publish_dhcp(&self, _previous: DhcpAddresses, _actual: DhcpAddresses) {}
}

#[cfg(any(feature = "dhcp-ipv4", feature = "dhcp-ipv6"))]
pub(crate) struct DhcpRuntime {
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

#[cfg(any(feature = "dhcp-ipv4", feature = "dhcp-ipv6"))]
impl DhcpRuntime {
    pub(crate) fn new() -> Self {
        Self {
            task: Mutex::new(None),
        }
    }

    pub(crate) async fn start(
        &self,
        route_source: Arc<dyn DhcpRouteSource>,
        runtime_config: CoreRuntimeConfigStore,
        host: Arc<dyn DhcpHost>,
    ) {
        let mut task = self.task.lock().await;
        if task.is_none() {
            task.replace(DhcpService::new(route_source, runtime_config, host).start());
        }
    }

    pub(crate) async fn stop(&self) {
        self.task.lock().await.take();
    }
}

pub struct DhcpApplyPermit {
    _guard: Box<dyn Send>,
}

impl DhcpApplyPermit {
    pub fn new(guard: impl Send + 'static) -> Self {
        Self {
            _guard: Box::new(guard),
        }
    }
}

pub struct DhcpApplyOutcome {
    pub actual: DhcpAddresses,
    pub result: anyhow::Result<()>,
    permit: Option<DhcpApplyPermit>,
}

impl DhcpApplyOutcome {
    pub fn applied(actual: DhcpAddresses) -> Self {
        Self {
            actual,
            result: Ok(()),
            permit: None,
        }
    }

    pub fn failed(actual: DhcpAddresses, error: impl Into<anyhow::Error>) -> Self {
        Self {
            actual,
            result: Err(error.into()),
            permit: None,
        }
    }

    pub fn with_permit(mut self, permit: DhcpApplyPermit) -> Self {
        self.permit = Some(permit);
        self
    }
}

struct DhcpState {
    ipv4: Option<DhcpAllocator<Ipv4Inet>>,
    ipv6: Option<DhcpAllocator<Ipv6Inet>>,
    needs_apply: bool,
}

impl DhcpState {
    fn current(&self) -> DhcpAddresses {
        DhcpAddresses {
            ipv4: self.ipv4.as_ref().and_then(|allocator| allocator.current()),
            ipv6: self.ipv6.as_ref().and_then(|allocator| allocator.current()),
        }
    }
}

pub struct DhcpService {
    operation: tokio::sync::Mutex<()>,
    state: std::sync::Mutex<DhcpState>,
    route_source: Arc<dyn DhcpRouteSource>,
    runtime_config: CoreRuntimeConfigStore,
    host: Arc<dyn DhcpHost>,
}

impl DhcpService {
    pub fn new(
        route_source: Arc<dyn DhcpRouteSource>,
        runtime_config: CoreRuntimeConfigStore,
        host: Arc<dyn DhcpHost>,
    ) -> Arc<Self> {
        let config = runtime_config.snapshot();
        let ipv4 = config.services.dhcp_ipv4.then(|| {
            DhcpAllocator::new(
                config
                    .services
                    .dhcp_ipv4_cidr
                    .map(|cidr| cidr.first())
                    .unwrap_or_else(|| "10.126.126.0/24".parse().expect("valid bootstrap subnet")),
            )
        });
        let ipv6 = config.services.dhcp_ipv6.then(|| {
            DhcpAllocator::new(
                config
                    .services
                    .dhcp_ipv6_cidr
                    .map(|cidr| cidr.first())
                    .unwrap_or_else(|| {
                        "fd6b:8c2d:91e4::/64"
                            .parse()
                            .expect("valid bootstrap subnet")
                    }),
            )
        });
        Arc::new(Self {
            operation: tokio::sync::Mutex::new(()),
            state: std::sync::Mutex::new(DhcpState {
                ipv4,
                ipv6,
                needs_apply: true,
            }),
            route_source,
            runtime_config,
            host,
        })
    }

    pub fn current(&self) -> DhcpAddresses {
        self.state.lock().unwrap().current()
    }

    pub async fn reconcile_once(&self) -> bool {
        let _operation = self.operation.lock().await;
        let interface_closed = self.host.take_interface_closed();
        let snapshot = self.route_source.dhcp_route_snapshot().await;
        let (previous, next, manage_ipv4, manage_ipv6) = {
            let mut state = self.state.lock().unwrap();
            let previous = state.current();
            let mut next = previous;
            if let Some(allocator) = &mut state.ipv4
                && let DhcpDecision::Change { next: address, .. } =
                    allocator.evaluate(snapshot.has_routes, &snapshot.used_ipv4)
            {
                next.ipv4 = address;
            }
            if let Some(allocator) = &mut state.ipv6
                && let DhcpDecision::Change { next: address, .. } =
                    allocator.evaluate(snapshot.has_routes, &snapshot.used_ipv6)
            {
                next.ipv6 = address;
            }
            if previous == next && !state.needs_apply && !interface_closed {
                return snapshot.has_routes;
            }
            // Also retain the retry on cancellation while awaiting the Host.
            state.needs_apply = true;
            (previous, next, state.ipv4.is_some(), state.ipv6.is_some())
        };
        tracing::debug!(?previous, ?next, "DHCP reconciliation applying change");
        let DhcpApplyOutcome {
            actual,
            result,
            permit,
        } = self.host.apply_dhcp(next).await;
        self.runtime_config.update_peer_with(|peer| {
            if manage_ipv4 {
                peer.runtime.core.routes.ipv4 = actual.ipv4.map(|address| IpPrefix {
                    address: address.address().into(),
                    prefix_len: address.network_length(),
                });
            }
            if manage_ipv6 {
                peer.runtime.core.routes.ipv6 = actual.ipv6.map(|address| IpPrefix {
                    address: address.address().into(),
                    prefix_len: address.network_length(),
                });
            }
        });
        match result {
            Ok(()) => {
                {
                    let mut state = self.state.lock().unwrap();
                    if let Some(allocator) = &mut state.ipv4 {
                        allocator.commit(actual.ipv4);
                    }
                    if let Some(allocator) = &mut state.ipv6 {
                        allocator.commit(actual.ipv6);
                    }
                    state.needs_apply = false;
                }
                self.host.publish_dhcp(previous, actual);
            }
            Err(err) => tracing::error!(?previous, ?next, ?actual, ?err, "DHCP apply failed"),
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

    type Ipv4Allocator = DhcpAllocator<Ipv4Inet>;

    struct StaticRouteSource {
        snapshot: Mutex<DhcpRouteSnapshot>,
    }

    #[async_trait]
    impl DhcpRouteSource for StaticRouteSource {
        async fn dhcp_route_snapshot(&self) -> DhcpRouteSnapshot {
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
        changes: Mutex<Vec<DhcpAddresses>>,
        static_ipv6_patch: Mutex<Option<IpPrefix>>,
        published: Mutex<Vec<(DhcpAddresses, DhcpAddresses)>>,
    }

    struct RecordingPermit(Arc<AtomicBool>);

    impl Drop for RecordingPermit {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    #[async_trait]
    impl DhcpHost for RecordingHost {
        fn take_interface_closed(&self) -> bool {
            self.interface_closed.swap(false, Ordering::AcqRel)
        }

        async fn apply_dhcp(&self, next: DhcpAddresses) -> DhcpApplyOutcome {
            self.changes.lock().unwrap().push(next);
            if let Some(address) = self.static_ipv6_patch.lock().unwrap().take() {
                self.runtime_config
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .update_peer_with(|peer| {
                        peer.runtime.core.routes.ipv6 = Some(address);
                    });
            }
            let mut outcome = if self.fail_apply.load(Ordering::Acquire) {
                DhcpApplyOutcome::failed(DhcpAddresses::default(), anyhow::anyhow!("apply failed"))
            } else {
                DhcpApplyOutcome::applied(next)
            };
            if self.hold_apply_permit.load(Ordering::Acquire) {
                assert!(!self.permit_held.swap(true, Ordering::AcqRel));
                outcome = outcome.with_permit(DhcpApplyPermit::new(RecordingPermit(
                    self.permit_held.clone(),
                )));
            }
            outcome
        }

        fn publish_dhcp(&self, previous: DhcpAddresses, actual: DhcpAddresses) {
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
            self.published.lock().unwrap().push((previous, actual));
        }
    }

    fn service(
        snapshot: DhcpRouteSnapshot,
        host: Arc<RecordingHost>,
        cidr: Option<&str>,
    ) -> (Arc<DhcpService>, CoreRuntimeConfigStore) {
        let (service, runtime_config, routes) = service_with_config(
            host,
            crate::config::runtime::CoreRuntimeConfig {
                dhcp_ipv4: true,
                dhcp_ipv4_cidr: cidr.map(|cidr| cidr.parse().unwrap()),
                ..Default::default()
            },
        );
        *routes.snapshot.lock().unwrap() = snapshot;
        (service, runtime_config)
    }

    fn service_with_config(
        host: Arc<RecordingHost>,
        config: crate::config::runtime::CoreRuntimeConfig,
    ) -> (
        Arc<DhcpService>,
        CoreRuntimeConfigStore,
        Arc<StaticRouteSource>,
    ) {
        let runtime = CoreRuntimeConfigStore::new(config, Arc::new(Default::default()));
        *host.runtime_config.lock().unwrap() = Some(runtime.clone());
        let routes = Arc::new(StaticRouteSource {
            snapshot: Mutex::new(Default::default()),
        });
        (
            DhcpService::new(routes.clone(), runtime.clone(), host),
            runtime,
            routes,
        )
    }

    async fn bootstrap(service: &DhcpService) {
        for _ in 0..=BOOTSTRAP_WAIT_ROUNDS {
            service.reconcile_once().await;
        }
    }

    #[test]
    fn waits_until_at_least_one_route_exists() {
        let mut allocator = Ipv4Allocator::default();

        assert_eq!(
            allocator.evaluate(false, &HashSet::new()),
            DhcpDecision::WaitForPeers
        );
    }

    #[test]
    fn does_not_fall_back_to_a_builtin_subnet_without_assigned_ipv4() {
        let mut allocator = Ipv4Allocator::default();

        assert_eq!(
            allocator.evaluate(true, &HashSet::new()),
            DhcpDecision::WaitForPeers
        );
    }

    #[test]
    fn bootstraps_default_subnet_after_bounded_wait() {
        let mut allocator = Ipv4Allocator::new("10.126.126.0/24".parse().unwrap());

        for _ in 0..2 {
            assert_eq!(
                allocator.evaluate(true, &HashSet::new()),
                DhcpDecision::WaitForPeers
            );
        }
        let DhcpDecision::Change {
            previous: None,
            next: Some(address),
        } = allocator.evaluate(true, &HashSet::new())
        else {
            panic!("expected bootstrap address")
        };
        assert_eq!(
            address.network(),
            "10.126.126.0/24".parse::<Ipv4Inet>().unwrap().network()
        );
        assert_ne!(address.address(), address.first_address());
        assert_ne!(address.address(), address.last_address());
    }

    #[test]
    fn announced_peer_subnet_takes_priority_over_bootstrap_subnet() {
        let mut allocator = Ipv4Allocator::new("10.126.126.0/24".parse().unwrap());
        let used = HashSet::from(["198.18.106.5/24".parse().unwrap()]);

        assert_eq!(
            allocator.evaluate(true, &used),
            DhcpDecision::Change {
                previous: None,
                next: Some("198.18.106.1/24".parse().unwrap()),
            }
        );
    }

    #[test]
    fn keeps_current_address_when_peers_stop_announcing_ipv4() {
        let mut allocator = Ipv4Allocator::new("10.126.126.0/24".parse().unwrap());
        let current = "198.18.106.1/24".parse().unwrap();
        allocator.commit(Some(current));

        for _ in 0..BOOTSTRAP_WAIT_ROUNDS + 2 {
            assert_eq!(
                allocator.evaluate(true, &HashSet::new()),
                DhcpDecision::Unchanged
            );
            assert_eq!(allocator.current(), Some(current));
        }
    }

    #[test]
    fn simultaneous_dhcp_only_peers_resolve_conflicts() {
        use rand::SeedableRng;
        let subnet = "10.126.126.0/24".parse().unwrap();
        let mut allocators = (0..32)
            .map(|_| Ipv4Allocator::new(subnet))
            .collect::<Vec<_>>();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for round in 0..30 {
            // All peers evaluate the same previous-round snapshot before any
            // candidate is published, including simultaneous empty startup.
            let current = allocators
                .iter()
                .map(|allocator| allocator.current())
                .collect::<Vec<_>>();
            let decisions = allocators
                .iter_mut()
                .enumerate()
                .map(|(index, allocator)| {
                    let used = current
                        .iter()
                        .enumerate()
                        .filter_map(|(peer, address)| (peer != index).then_some(*address).flatten())
                        .collect();
                    allocator.evaluate_with_rng(true, &used, &mut rng)
                })
                .collect::<Vec<_>>();
            for (allocator, decision) in allocators.iter_mut().zip(decisions) {
                if let DhcpDecision::Change { next, .. } = decision {
                    allocator.commit(next);
                }
            }
            if round > BOOTSTRAP_WAIT_ROUNDS {
                let addresses = allocators
                    .iter()
                    .filter_map(|allocator| allocator.current())
                    .collect::<HashSet<_>>();
                if addresses.len() == allocators.len() {
                    return;
                }
            }
        }
        panic!("simultaneous allocations did not converge");
    }

    #[test]
    fn keeps_advertised_current_subnet_and_uses_deterministic_fallback() {
        let mut allocator = Ipv4Allocator::default();
        allocator.commit(Some("10.2.0.8/24".parse().unwrap()));
        let used = HashSet::from([
            "10.1.0.2/24".parse().unwrap(),
            "10.2.0.2/24".parse().unwrap(),
        ]);
        for _ in 0..20 {
            assert_eq!(allocator.evaluate(true, &used), DhcpDecision::Unchanged);
        }
        allocator.reset();
        assert_eq!(
            allocator.evaluate(true, &used),
            DhcpDecision::Change {
                previous: None,
                next: Some("10.1.0.1/24".parse().unwrap()),
            }
        );
    }

    #[test]
    fn keeps_current_address_when_it_is_free_in_the_selected_subnet() {
        let mut allocator = Ipv4Allocator::default();
        allocator.commit(Some("10.1.2.8/24".parse().unwrap()));
        let used = HashSet::from(["10.1.2.2/24".parse().unwrap()]);

        assert_eq!(allocator.evaluate(true, &used), DhcpDecision::Unchanged);
    }

    #[test]
    fn selects_an_unused_host_after_a_conflict() {
        let mut allocator = Ipv4Allocator::default();
        allocator.commit(Some("10.1.2.1/24".parse().unwrap()));
        let used = HashSet::from([
            "10.1.2.1/24".parse().unwrap(),
            "10.1.2.2/24".parse().unwrap(),
        ]);

        let DhcpDecision::Change {
            previous,
            next: Some(next),
        } = allocator.evaluate(true, &used)
        else {
            panic!("expected conflict resolution");
        };
        assert_eq!(previous, Some("10.1.2.1/24".parse().unwrap()));
        assert!(!used.contains(&next));
        assert_eq!(next.network(), previous.unwrap().network());
    }

    #[test]
    fn reset_forgets_the_previous_interface_address() {
        let mut allocator = Ipv4Allocator::default();
        allocator.commit(Some("10.1.2.8/24".parse().unwrap()));

        allocator.reset();

        assert_eq!(allocator.current(), None);
    }

    #[tokio::test]
    async fn service_bootstraps_ipv4_when_no_peer_has_one() {
        check_service_bootstrap(true, None).await;
    }

    #[tokio::test]
    async fn service_bootstraps_ipv4_without_other_peers() {
        check_service_bootstrap(false, None).await;
    }

    #[tokio::test]
    async fn service_bootstraps_ipv4_in_configured_subnet() {
        for cidr in [
            "192.168.100.0/24",
            "10.20.0.0/16",
            "192.168.100.0/30",
            "0.0.0.0/0",
        ] {
            for has_routes in [true, false] {
                check_service_bootstrap(has_routes, Some(cidr)).await;
            }
        }
    }

    #[tokio::test]
    async fn service_prefers_peer_subnet_over_configured_bootstrap_subnet() {
        let host = Arc::new(RecordingHost::default());
        let (service, _runtime_config) = service(
            DhcpRouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::from(["10.20.0.1/16".parse().unwrap()]),
                ..Default::default()
            },
            host,
            Some("192.168.100.0/24"),
        );
        service.reconcile_once().await;
        assert_eq!(
            service.current().ipv4,
            Some("10.20.0.2/16".parse().unwrap())
        );
    }

    async fn check_service_bootstrap(has_routes: bool, cidr: Option<&str>) {
        let host = Arc::new(RecordingHost::default());
        let (service, runtime_config) = service(
            DhcpRouteSnapshot {
                has_routes,
                used_ipv4: HashSet::new(),
                ..Default::default()
            },
            host.clone(),
            cidr,
        );

        for _ in 0..BOOTSTRAP_WAIT_ROUNDS {
            assert_eq!(service.reconcile_once().await, has_routes);
        }

        assert_eq!(service.current().ipv4, None);
        assert_eq!(*host.changes.lock().unwrap(), [DhcpAddresses::default()]);
        assert_eq!(
            *host.published.lock().unwrap(),
            [(DhcpAddresses::default(), DhcpAddresses::default())]
        );
        assert!(
            runtime_config
                .snapshot()
                .peer
                .runtime
                .core
                .routes
                .ipv4
                .is_none()
        );

        assert_eq!(service.reconcile_once().await, has_routes);
        let address = service.current().ipv4.expect("bootstrap address");
        assert_eq!(
            address.network(),
            cidr.unwrap_or("10.126.126.0/24")
                .parse::<Ipv4Inet>()
                .unwrap()
                .network()
        );
        assert_ne!(address.address(), address.first_address());
        assert_ne!(address.address(), address.last_address());
        assert_eq!(
            *host.changes.lock().unwrap(),
            [
                DhcpAddresses::default(),
                DhcpAddresses {
                    ipv4: Some(address),
                    ipv6: None,
                }
            ]
        );
        assert_eq!(
            runtime_config.snapshot().peer.runtime.core.routes.ipv4,
            Some(IpPrefix {
                address: address.address().into(),
                prefix_len: address.network_length(),
            })
        );
        assert_eq!(service.reconcile_once().await, has_routes);
        assert_eq!(service.current().ipv4, Some(address));
        assert_eq!(host.changes.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn service_commits_only_after_host_apply_succeeds() {
        let host = Arc::new(RecordingHost::default());
        let (service, runtime_config) = service(
            DhcpRouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::from(["198.18.0.2/24".parse().unwrap()]),
                ..Default::default()
            },
            host.clone(),
            None,
        );

        assert!(service.reconcile_once().await);

        let addresses = DhcpAddresses {
            ipv4: Some("198.18.0.1/24".parse().unwrap()),
            ipv6: None,
        };
        assert_eq!(service.current(), addresses);
        assert_eq!(*host.changes.lock().unwrap(), [addresses]);
        assert_eq!(
            runtime_config.snapshot().peer.runtime.core.routes.ipv4,
            Some(IpPrefix::new("198.18.0.1".parse().unwrap(), 24).unwrap())
        );
        assert_eq!(
            *host.published.lock().unwrap(),
            [(DhcpAddresses::default(), addresses)]
        );
    }

    #[tokio::test]
    async fn service_holds_host_permit_through_store_and_event_commit() {
        let host = Arc::new(RecordingHost::default());
        host.hold_apply_permit.store(true, Ordering::Release);
        let (service, _runtime_config) = service(
            DhcpRouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::from(["198.18.0.2/24".parse().unwrap()]),
                ..Default::default()
            },
            host.clone(),
            None,
        );

        service.reconcile_once().await;

        let expected = Some(IpPrefix::new("198.18.0.1".parse().unwrap(), 24).unwrap());
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
            DhcpRouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::from(["198.18.0.2/24".parse().unwrap()]),
                ..Default::default()
            },
            host.clone(),
            None,
        );

        service.reconcile_once().await;
        service.reconcile_once().await;

        assert_eq!(service.current().ipv4, None);
        assert_eq!(host.changes.lock().unwrap().len(), 2);
        assert_eq!(
            runtime_config.snapshot().peer.runtime.core.routes.ipv4,
            None
        );
        assert!(host.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn interface_close_reapplies_previous_allocation() {
        let host = Arc::new(RecordingHost::default());
        let (service, _runtime_config) = service(
            DhcpRouteSnapshot {
                has_routes: true,
                used_ipv4: HashSet::from(["198.18.0.2/24".parse().unwrap()]),
                ..Default::default()
            },
            host.clone(),
            None,
        );
        service.reconcile_once().await;
        host.interface_closed.store(true, Ordering::Release);

        service.reconcile_once().await;

        let addresses = DhcpAddresses {
            ipv4: Some("198.18.0.1/24".parse().unwrap()),
            ipv6: None,
        };
        assert_eq!(*host.changes.lock().unwrap(), [addresses, addresses]);
        assert_eq!(
            *host.published.lock().unwrap(),
            [
                (DhcpAddresses::default(), addresses),
                (addresses, addresses)
            ]
        );
    }

    #[tokio::test]
    async fn dual_stack_bootstrap_applies_both_addresses_together() {
        let host = Arc::new(RecordingHost::default());
        let (service, runtime, _) = service_with_config(
            host.clone(),
            crate::config::runtime::CoreRuntimeConfig {
                dhcp_ipv4: true,
                dhcp_ipv6: true,
                ..Default::default()
            },
        );
        bootstrap(&service).await;
        let addresses = service.current();
        assert_eq!(
            addresses.ipv4.unwrap().network(),
            "10.126.126.0/24".parse().unwrap()
        );
        assert_eq!(
            addresses.ipv6.unwrap().network(),
            "fd6b:8c2d:91e4::/64".parse().unwrap()
        );
        let changes = host.changes.lock().unwrap();
        assert_eq!(changes.len(), 2); // First installation, then both leases.
        assert_eq!(changes[1], addresses);
        let config = runtime.snapshot();
        assert_eq!(
            config
                .peer
                .runtime
                .core
                .routes
                .ipv4
                .as_ref()
                .unwrap()
                .address,
            addresses.ipv4.unwrap().address()
        );
        assert_eq!(
            config
                .peer
                .runtime
                .core
                .routes
                .ipv6
                .as_ref()
                .unwrap()
                .address,
            addresses.ipv6.unwrap().address()
        );
    }

    #[tokio::test]
    async fn ipv6_bootstrap_preserves_static_ipv4() {
        for subnet in [
            "fd12:3456::/48",
            "fd12:3456::/64",
            "fd12:3456::/126",
            "2001:db8::/64",
        ] {
            let host = Arc::new(RecordingHost::default());
            let (service, runtime, _) = service_with_config(
                host.clone(),
                crate::config::runtime::CoreRuntimeConfig {
                    dhcp_ipv6: true,
                    dhcp_ipv6_cidr: Some(subnet.parse().unwrap()),
                    ..Default::default()
                },
            );
            let ipv4 = IpPrefix::new("10.0.0.7".parse().unwrap(), 24).unwrap();
            runtime.update_peer_with(|peer| peer.runtime.core.routes.ipv4 = Some(ipv4.clone()));
            bootstrap(&service).await;
            let address = service.current().ipv6.unwrap();
            assert_eq!(address.network(), subnet.parse().unwrap());
            assert_ne!(address.address(), address.first_address());
            assert_ne!(address.address(), address.last_address());
            assert!(service.current().ipv4.is_none());
            assert_eq!(runtime.snapshot().peer.runtime.core.routes.ipv4, Some(ipv4));
        }
    }

    #[tokio::test]
    async fn ipv6_exhaustion_does_not_remove_ipv4_and_recovers_when_an_address_is_free() {
        let host = Arc::new(RecordingHost::default());
        let (service, runtime, routes) = service_with_config(
            host,
            crate::config::runtime::CoreRuntimeConfig {
                dhcp_ipv4: true,
                dhcp_ipv6: true,
                ..Default::default()
            },
        );
        *routes.snapshot.lock().unwrap() = DhcpRouteSnapshot {
            has_routes: true,
            used_ipv4: HashSet::from(["10.20.0.1/24".parse().unwrap()]),
            used_ipv6: HashSet::from([
                "fd12::1/126".parse().unwrap(),
                "fd12::2/126".parse().unwrap(),
            ]),
        };
        service.reconcile_once().await;
        let ipv4 = service.current().ipv4.unwrap();
        assert!(service.current().ipv6.is_none());
        assert!(runtime.snapshot().peer.runtime.core.routes.ipv4.is_some());
        routes
            .snapshot
            .lock()
            .unwrap()
            .used_ipv6
            .remove(&"fd12::2/126".parse().unwrap());
        service.reconcile_once().await;
        assert_eq!(
            service.current(),
            DhcpAddresses {
                ipv4: Some(ipv4),
                ipv6: Some("fd12::2/126".parse().unwrap())
            }
        );
    }

    #[tokio::test]
    async fn interface_recovery_retries_unchanged_dual_stack_leases_after_failure() {
        let host = Arc::new(RecordingHost::default());
        let (service, runtime, _) = service_with_config(
            host.clone(),
            crate::config::runtime::CoreRuntimeConfig {
                dhcp_ipv4: true,
                dhcp_ipv6: true,
                ..Default::default()
            },
        );
        bootstrap(&service).await;
        let addresses = service.current();
        host.interface_closed.store(true, Ordering::Release);
        host.fail_apply.store(true, Ordering::Release);
        service.reconcile_once().await;
        assert_eq!(service.current(), addresses);
        assert!(runtime.snapshot().peer.runtime.core.routes.ipv6.is_none());
        host.fail_apply.store(false, Ordering::Release);
        service.reconcile_once().await;
        assert_eq!(service.current(), addresses);
        assert!(runtime.snapshot().peer.runtime.core.routes.ipv4.is_some());
        assert!(runtime.snapshot().peer.runtime.core.routes.ipv6.is_some());
        let changes = host.changes.lock().unwrap();
        assert_eq!(&changes[2..], &[addresses, addresses]);
    }

    #[tokio::test]
    async fn ipv4_apply_does_not_overwrite_a_concurrent_static_ipv6_patch() {
        let host = Arc::new(RecordingHost::default());
        let (service, runtime, _) = service_with_config(
            host.clone(),
            crate::config::runtime::CoreRuntimeConfig {
                dhcp_ipv4: true,
                ..Default::default()
            },
        );
        let address = IpPrefix::new("fd12::7".parse().unwrap(), 64).unwrap();
        *host.static_ipv6_patch.lock().unwrap() = Some(address.clone());
        service.reconcile_once().await; // Also applies while the allocator waits.
        assert_eq!(host.changes.lock().unwrap().len(), 1);
        assert_eq!(
            runtime.snapshot().peer.runtime.core.routes.ipv6,
            Some(address)
        );
    }

    #[test]
    fn ipv6_simultaneous_conflicts_converge() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let mut allocators = (0..32)
            .map(|_| {
                let mut allocator = DhcpAllocator::<Ipv6Inet>::new("fd12::/64".parse().unwrap());
                allocator.commit(Some("fd12::1/64".parse().unwrap()));
                allocator
            })
            .collect::<Vec<_>>();
        for _ in 0..20 {
            let current = allocators
                .iter()
                .map(|allocator| allocator.current())
                .collect::<Vec<_>>();
            for (index, allocator) in allocators.iter_mut().enumerate() {
                let used = current
                    .iter()
                    .enumerate()
                    .filter_map(|(peer, address)| (peer != index).then_some(*address).flatten())
                    .collect();
                if let DhcpDecision::Change { next, .. } =
                    allocator.evaluate_with_rng(true, &used, &mut rng)
                {
                    allocator.commit(next);
                }
            }
            if allocators
                .iter()
                .filter_map(|allocator| allocator.current())
                .collect::<HashSet<_>>()
                .len()
                == allocators.len()
            {
                return;
            }
        }
        panic!("IPv6 conflicts did not converge");
    }

    #[test]
    fn ipv6_conflict_detection_ignores_advertised_prefix_length() {
        let mut allocator = DhcpAllocator::<Ipv6Inet>::new("fd12::/64".parse().unwrap());
        allocator.commit(Some("fd12::1/64".parse().unwrap()));
        let used = HashSet::from(["fd12::1/80".parse().unwrap(), "fd12::2/64".parse().unwrap()]);
        let DhcpDecision::Change {
            next: Some(next), ..
        } = allocator.evaluate(true, &used)
        else {
            panic!("conflict was missed");
        };
        assert_ne!(
            next.address(),
            "fd12::1".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(next.network_length(), 64);
    }

    #[test]
    fn ipv6_host_routes_reserve_addresses_without_selecting_a_subnet() {
        let mut allocator = DhcpAllocator::<Ipv6Inet>::new("fd12::/126".parse().unwrap());
        let used = HashSet::from([
            "fd12::1/128".parse().unwrap(),
            "fe80::1/64".parse().unwrap(),
        ]);
        for _ in 0..BOOTSTRAP_WAIT_ROUNDS {
            assert_eq!(allocator.evaluate(true, &used), DhcpDecision::WaitForPeers);
        }
        assert_eq!(
            allocator.evaluate(true, &used),
            DhcpDecision::Change {
                previous: None,
                next: Some("fd12::2/126".parse().unwrap()),
            }
        );
        allocator.commit(Some("fd12::1/126".parse().unwrap()));
        assert_eq!(
            allocator.evaluate(true, &used),
            DhcpDecision::Change {
                previous: Some("fd12::1/126".parse().unwrap()),
                next: Some("fd12::2/126".parse().unwrap()),
            }
        );
    }
}
