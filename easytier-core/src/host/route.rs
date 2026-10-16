//! Instance-owned route inputs and freshness-checked native feedback.
//! No backend, task, TUN resource or derived registry lives here.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{Arc, Weak},
};

use cidr::{IpCidr, Ipv4Cidr};
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::config::runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfigStore};

pub type RouteSet = BTreeSet<RouteSpec>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteSpec {
    pub destination: IpCidr,
    pub metric: u32,
    pub table: Option<u32>,
    pub preferred_source: Option<IpAddr>,
    pub action: RouteAction,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceSelector {
    InstanceTun,
    Named(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteAction {
    Unicast {
        device: Option<DeviceSelector>,
        via: Option<IpAddr>,
    },
    Blackhole,
    Unreachable,
}

impl RouteSpec {
    pub fn for_tun(destination: IpCidr) -> Self {
        Self {
            destination,
            metric: 65535,
            table: None,
            preferred_source: None,
            action: RouteAction::Unicast {
                device: Some(DeviceSelector::InstanceTun),
                via: None,
            },
        }
    }

    fn needs_default_device(&self) -> bool {
        matches!(
            self.action,
            RouteAction::Unicast {
                device: Some(DeviceSelector::InstanceTun),
                ..
            }
        )
    }

    fn validate(&self) -> Result<(), RouteInputError> {
        let same_family = |ip: IpAddr| ip.is_ipv4() == self.destination.first_address().is_ipv4();
        if self.preferred_source.is_some_and(|ip| !same_family(ip)) {
            return Err(RouteInputError::InvalidSpec(
                "source address family differs",
            ));
        }
        if let RouteAction::Unicast { device, via } = &self.action {
            if device.is_none() && via.is_none() {
                return Err(RouteInputError::InvalidSpec(
                    "unicast requires a device or gateway",
                ));
            }
            if via.is_some_and(|ip| !same_family(ip)) {
                return Err(RouteInputError::InvalidSpec(
                    "gateway address family differs",
                ));
            }
            if matches!(device, Some(DeviceSelector::Named(name)) if name.is_empty()) {
                return Err(RouteInputError::InvalidSpec("empty device name"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDemand {
    AutoProxy(BTreeSet<Ipv4Cidr>),
    Additional(RouteSet),
}

impl RouteDemand {
    fn validate(&self) -> Result<(), RouteInputError> {
        if let Self::Additional(routes) = self {
            for route in routes {
                route.validate()?;
            }
        }
        Ok(())
    }

    fn needs_default_device(&self) -> bool {
        match self {
            Self::AutoProxy(_) => true,
            Self::Additional(routes) => routes.iter().any(RouteSpec::needs_default_device),
        }
    }
}

/// Allocated once by the owner of each actual physical device generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceEpoch(uuid::Uuid);

impl DeviceEpoch {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}
impl Default for DeviceEpoch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteClaimId(u64);

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteInputError {
    #[error("route input is closed")]
    Closed,
    #[error("invalid route: {0}")]
    InvalidSpec(&'static str),
    #[error("route configuration is already bound")]
    AlreadyBound,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteWaitError {
    #[error("route input is closed")]
    Closed,
    #[error("route declaration was replaced")]
    Superseded,
    #[error("device generation changed")]
    DeviceChanged,
    #[error("an expected device generation is required")]
    DeviceRequired,
    #[error("automatic route is suppressed by manual policy")]
    Suppressed,
    #[error("route rejected: {0}")]
    Rejected(Arc<str>),
    #[error("route executor failed: {0}")]
    Failed(Arc<str>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimRouteStatus {
    Pending,
    Ready,
    Suppressed,
    Rejected(Arc<str>),
    Failed(Arc<str>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstanceRouteStatus {
    Active,
    Draining,
    Drained,
    Failed(Arc<str>),
}

#[derive(Clone)]
struct Feedback {
    stamp: u64,
    instance: InstanceRouteStatus,
    claims: BTreeMap<RouteClaimId, ClaimRouteStatus>,
}

struct InputState {
    closed: bool,
    stamp: u64,
    next_claim: u64,
    claims: BTreeMap<RouteClaimId, Arc<RouteDemand>>,
    config: Option<CoreRuntimeConfigStore>,
    default_nic: Option<uuid::Uuid>,
    device: Option<DeviceEpoch>,
}

impl InputState {
    fn invalidate(&mut self) {
        self.stamp = self
            .stamp
            .checked_add(1)
            .expect("route input revision exhausted");
    }
}

/// Native driver's read/feedback side. Retaining it does not keep the
/// instance's authority open; only InstanceRoutes owns that authority.
pub struct RouteInputs {
    identity: Arc<()>,
    state: Mutex<InputState>,
    feedback: watch::Sender<Feedback>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

/// Raw claims form a coherent collection. Configuration has its own coherent
/// snapshot; no transaction across independent stores is implied.
pub struct RouteInputSnapshot {
    identity: Arc<()>,
    stamp: u64,
    pub closed: bool,
    pub claims: BTreeMap<RouteClaimId, Arc<RouteDemand>>,
    pub config: Option<Arc<CoreInstanceRuntimeConfig>>,
    pub default_nic: Option<uuid::Uuid>,
    pub device: Option<DeviceEpoch>,
}

impl RouteInputSnapshot {
    pub fn effective_routes(&self) -> RouteSet {
        if self.closed {
            return RouteSet::new();
        }
        let manual = self
            .config
            .as_ref()
            .and_then(|config| config.services.manual_routes.as_ref());
        let mut routes = RouteSet::new();
        if let Some(manual) = manual {
            routes.extend(
                manual
                    .iter()
                    .map(|prefix| RouteSpec::for_tun((*prefix).into())),
            );
        }
        for demand in self.claims.values() {
            match demand.as_ref() {
                RouteDemand::AutoProxy(prefixes) if manual.is_none() => {
                    routes.extend(
                        prefixes
                            .iter()
                            .map(|prefix| RouteSpec::for_tun((*prefix).into())),
                    );
                }
                RouteDemand::Additional(additional) => routes.extend(additional.iter().cloned()),
                _ => {}
            }
        }
        routes
    }

    pub fn auto_suppressed(&self) -> bool {
        self.config
            .as_ref()
            .is_some_and(|config| config.services.manual_routes.is_some())
    }
}

/// Unique instance close authority. Drop performs no waiting or OS I/O.
pub struct InstanceRoutes {
    inputs: Arc<RouteInputs>,
    feedback: watch::Receiver<Feedback>,
}

impl InstanceRoutes {
    pub fn new(wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (feedback, receiver) = watch::channel(Feedback {
            stamp: 0,
            instance: InstanceRouteStatus::Active,
            claims: BTreeMap::new(),
        });
        Self {
            inputs: Arc::new(RouteInputs {
                identity: Arc::new(()),
                state: Mutex::new(InputState {
                    closed: false,
                    stamp: 0,
                    next_claim: 0,
                    claims: BTreeMap::new(),
                    config: None,
                    default_nic: None,
                    device: None,
                }),
                feedback,
                wake,
            }),
            feedback: receiver,
        }
    }

    pub fn inputs(&self) -> Arc<RouteInputs> {
        self.inputs.clone()
    }
    pub fn handle(&self) -> RouteHandle {
        RouteHandle {
            inputs: Arc::downgrade(&self.inputs),
        }
    }

    pub fn bind_config(&self, config: CoreRuntimeConfigStore) -> Result<(), RouteInputError> {
        {
            let mut state = self.inputs.state.lock();
            if state.closed {
                return Err(RouteInputError::Closed);
            }
            if state.config.is_some() {
                return Err(RouteInputError::AlreadyBound);
            }
            let weak = Arc::downgrade(&self.inputs);
            config
                .set_route_invalidator(Arc::new(move || {
                    if let Some(inputs) = weak.upgrade() {
                        inputs.invalidate();
                    }
                }))
                .map_err(|_| RouteInputError::AlreadyBound)?;
            state.invalidate();
            state.config = Some(config);
        }
        self.inputs.changed();
        Ok(())
    }

    pub fn request_close(&self) {
        self.inputs.close();
    }

    pub fn bind_default_nic(&self, nic: uuid::Uuid) -> Result<(), RouteInputError> {
        {
            let mut state = self.inputs.state.lock();
            if state.closed {
                return Err(RouteInputError::Closed);
            }
            if let Some(bound) = state.default_nic {
                return if bound == nic {
                    Ok(())
                } else {
                    Err(RouteInputError::AlreadyBound)
                };
            }
            state.invalidate();
            state.default_nic = Some(nic);
        }
        self.inputs.changed();
        Ok(())
    }

    pub async fn wait_drained(&self) -> Result<(), RouteWaitError> {
        let mut feedback = self.feedback.clone();
        loop {
            match &feedback.borrow_and_update().instance {
                InstanceRouteStatus::Drained => return Ok(()),
                InstanceRouteStatus::Failed(error) => {
                    return Err(RouteWaitError::Failed(error.clone()));
                }
                _ => {}
            }
            feedback.changed().await.map_err(|_| {
                RouteWaitError::Failed("route driver disappeared without drain".into())
            })?;
        }
    }
}

impl Drop for InstanceRoutes {
    fn drop(&mut self) {
        self.request_close();
    }
}

impl RouteInputs {
    fn changed(&self) {
        // Watch carries feedback, never raw input or a second refresh queue.
        self.feedback.send_modify(|_| {});
        (self.wake)();
    }

    pub fn invalidate(&self) {
        {
            let mut state = self.state.lock();
            if state.closed {
                return;
            }
            state.invalidate();
        }
        self.changed();
    }

    fn close(&self) {
        let claims = {
            let mut state = self.state.lock();
            if state.closed {
                return;
            }
            state.invalidate();
            state.closed = true;
            let claims = std::mem::take(&mut state.claims);
            self.feedback.send_replace(Feedback {
                stamp: state.stamp,
                instance: InstanceRouteStatus::Draining,
                claims: BTreeMap::new(),
            });
            claims
        };
        drop(claims);
        self.changed();
    }

    /// Native device facts updates serialize calls to this method. No device
    /// resource or namespace is retained by the Core input.
    pub fn set_default_device(
        &self,
        nic: uuid::Uuid,
        device: Option<DeviceEpoch>,
    ) -> Result<(), RouteInputError> {
        {
            let mut state = self.state.lock();
            if state.closed {
                return Err(RouteInputError::Closed);
            }
            if state.default_nic.is_some_and(|bound| bound != nic) {
                return Err(RouteInputError::AlreadyBound);
            }
            if state.default_nic == Some(nic) && state.device == device {
                return Ok(());
            }
            state.invalidate();
            state.default_nic = Some(nic);
            state.device = device;
        }
        self.changed();
        Ok(())
    }

    pub fn snapshot(&self) -> RouteInputSnapshot {
        let (stamp, closed, claims, config, default_nic, device) = {
            let state = self.state.lock();
            (
                state.stamp,
                state.closed,
                state.claims.clone(),
                state.config.clone(),
                state.default_nic,
                state.device,
            )
        };
        RouteInputSnapshot {
            identity: self.identity.clone(),
            stamp,
            closed,
            claims,
            config: config.map(|config| config.snapshot()),
            default_nic,
            device,
        }
    }

    pub fn is_current(&self, snapshot: &RouteInputSnapshot) -> bool {
        Arc::ptr_eq(&self.identity, &snapshot.identity) && self.state.lock().stamp == snapshot.stamp
    }

    /// Reject late worker completion and snapshots from other instances.
    /// The stamp stays private to the driver read/feedback pair.
    pub fn publish_feedback(
        &self,
        snapshot: &RouteInputSnapshot,
        instance: InstanceRouteStatus,
        claims: BTreeMap<RouteClaimId, ClaimRouteStatus>,
    ) -> bool {
        let state = self.state.lock();
        if !Arc::ptr_eq(&self.identity, &snapshot.identity) || state.stamp != snapshot.stamp {
            return false;
        }
        match (state.closed, &instance) {
            (false, InstanceRouteStatus::Active)
            | (
                true,
                InstanceRouteStatus::Draining
                | InstanceRouteStatus::Drained
                | InstanceRouteStatus::Failed(_),
            ) => {}
            _ => return false,
        }
        if matches!(
            self.feedback.borrow().instance,
            InstanceRouteStatus::Drained | InstanceRouteStatus::Failed(_)
        ) {
            return false;
        }
        self.feedback.send_replace(Feedback {
            stamp: state.stamp,
            instance,
            claims,
        });
        true
    }

    pub fn fail(&self, error: Arc<str>) {
        let claims = {
            let mut state = self.state.lock();
            if matches!(
                self.feedback.borrow().instance,
                InstanceRouteStatus::Drained
            ) {
                return;
            }
            state.closed = true;
            state.invalidate();
            self.feedback.send_replace(Feedback {
                stamp: state.stamp,
                instance: InstanceRouteStatus::Failed(error),
                claims: BTreeMap::new(),
            });
            std::mem::take(&mut state.claims)
        };
        drop(claims);
    }
}

#[derive(Clone)]
pub struct RouteHandle {
    inputs: Weak<RouteInputs>,
}

impl RouteHandle {
    pub fn publish(&self, demand: RouteDemand) -> Result<RouteClaim, RouteInputError> {
        demand.validate()?;
        let inputs = self.inputs.upgrade().ok_or(RouteInputError::Closed)?;
        let demand = Arc::new(demand);
        let id = {
            let mut state = inputs.state.lock();
            if state.closed {
                return Err(RouteInputError::Closed);
            }
            let next = state
                .next_claim
                .checked_add(1)
                .ok_or(RouteInputError::InvalidSpec("claim identifiers exhausted"))?;
            state.invalidate();
            state.next_claim = next;
            let id = RouteClaimId(next);
            state.claims.insert(id, demand);
            id
        };
        inputs.changed();
        Ok(RouteClaim {
            inputs: self.inputs.clone(),
            id,
        })
    }
}

pub struct RouteClaim {
    inputs: Weak<RouteInputs>,
    id: RouteClaimId,
}

impl RouteClaim {
    pub fn replace(&self, demand: RouteDemand) -> Result<(), RouteInputError> {
        demand.validate()?;
        let inputs = self.inputs.upgrade().ok_or(RouteInputError::Closed)?;
        let demand = Arc::new(demand);
        loop {
            let current = {
                let state = inputs.state.lock();
                if state.closed {
                    return Err(RouteInputError::Closed);
                }
                state
                    .claims
                    .get(&self.id)
                    .cloned()
                    .ok_or(RouteInputError::Closed)?
            };
            // Route sets can be large. Compare outside the input lock, then
            // recheck publication identity before committing that comparison.
            let unchanged = *current == *demand;
            let old = {
                let mut state = inputs.state.lock();
                if state.closed {
                    return Err(RouteInputError::Closed);
                }
                if !state
                    .claims
                    .get(&self.id)
                    .is_some_and(|value| Arc::ptr_eq(value, &current))
                {
                    continue;
                }
                if unchanged {
                    return Ok(());
                }
                state.invalidate();
                state.claims.insert(self.id, demand)
            };
            drop(old);
            inputs.changed();
            return Ok(());
        }
    }

    pub async fn wait_ready(&self, device: Option<DeviceEpoch>) -> Result<(), RouteWaitError> {
        let inputs = self.inputs.upgrade().ok_or(RouteWaitError::Closed)?;
        let mut feedback = inputs.feedback.subscribe();
        let publication = {
            let state = inputs.state.lock();
            if let InstanceRouteStatus::Failed(error) = &feedback.borrow().instance {
                return Err(RouteWaitError::Failed(error.clone()));
            }
            state
                .claims
                .get(&self.id)
                .cloned()
                .ok_or(RouteWaitError::Closed)?
        };
        if publication.needs_default_device() && device.is_none() {
            return Err(RouteWaitError::DeviceRequired);
        }
        loop {
            {
                let state = inputs.state.lock();
                let status = feedback.borrow_and_update();
                if let InstanceRouteStatus::Failed(error) = &status.instance {
                    return Err(RouteWaitError::Failed(error.clone()));
                }
                if state.closed {
                    return Err(RouteWaitError::Closed);
                }
                if !state
                    .claims
                    .get(&self.id)
                    .is_some_and(|current| Arc::ptr_eq(current, &publication))
                {
                    return Err(RouteWaitError::Superseded);
                }
                if device.is_some() && state.device != device {
                    return Err(RouteWaitError::DeviceChanged);
                }
                if status.stamp == state.stamp {
                    match status.claims.get(&self.id) {
                        Some(ClaimRouteStatus::Ready) => return Ok(()),
                        Some(ClaimRouteStatus::Suppressed) => {
                            return Err(RouteWaitError::Suppressed);
                        }
                        Some(ClaimRouteStatus::Rejected(error)) => {
                            return Err(RouteWaitError::Rejected(error.clone()));
                        }
                        Some(ClaimRouteStatus::Failed(error)) => {
                            return Err(RouteWaitError::Failed(error.clone()));
                        }
                        _ => {}
                    }
                }
            }
            feedback
                .changed()
                .await
                .map_err(|_| RouteWaitError::Failed("route driver disappeared".into()))?;
        }
    }
}

impl Drop for RouteClaim {
    fn drop(&mut self) {
        let Some(inputs) = self.inputs.upgrade() else {
            return;
        };
        let old = {
            let mut state = inputs.state.lock();
            if state.closed {
                return;
            }
            state.invalidate();
            state.claims.remove(&self.id)
        };
        drop(old);
        inputs.changed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{peers::PeerRuntimeSnapshot, runtime::CoreRuntimeConfig};
    use futures::FutureExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config() -> CoreRuntimeConfigStore {
        CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        )
    }
    fn auto(prefix: &str) -> RouteDemand {
        RouteDemand::AutoProxy(BTreeSet::from([prefix.parse().unwrap()]))
    }
    fn additional(prefix: &str) -> RouteDemand {
        RouteDemand::Additional(BTreeSet::from([RouteSpec::for_tun(
            prefix.parse().unwrap(),
        )]))
    }
    fn owner() -> InstanceRoutes {
        InstanceRoutes::new(Arc::new(|| {}))
    }
    fn ready(inputs: &RouteInputs) {
        let snapshot = inputs.snapshot();
        let feedback = snapshot
            .claims
            .keys()
            .map(|id| (*id, ClaimRouteStatus::Ready))
            .collect();
        assert!(inputs.publish_feedback(&snapshot, InstanceRouteStatus::Active, feedback));
    }

    #[test]
    fn manual_policy_is_local_and_keeps_latest_auto_and_additional() {
        let owner = owner();
        let store = config();
        owner.bind_config(store.clone()).unwrap();
        let auto = owner.handle().publish(auto("10.50.0.0/24")).unwrap();
        let _extra = owner.handle().publish(additional("198.18.0.1/32")).unwrap();
        let inputs = owner.inputs();
        assert_eq!(inputs.snapshot().effective_routes().len(), 2);
        store.update_services(|services| services.manual_routes = Some(BTreeSet::new()));
        assert!(inputs.snapshot().auto_suppressed());
        assert_eq!(
            inputs.snapshot().effective_routes(),
            RouteSet::from([RouteSpec::for_tun("198.18.0.1/32".parse().unwrap())])
        );
        auto.replace(RouteDemand::AutoProxy(BTreeSet::from(["10.51.0.0/24"
            .parse()
            .unwrap()])))
            .unwrap();
        store.update_services(|services| {
            services.manual_routes = Some(BTreeSet::from(["10.52.0.0/24".parse().unwrap()]))
        });
        assert!(
            inputs
                .snapshot()
                .effective_routes()
                .contains(&RouteSpec::for_tun("10.52.0.0/24".parse().unwrap()))
        );
        store.update_services(|services| services.manual_routes = None);
        assert!(
            inputs
                .snapshot()
                .effective_routes()
                .contains(&RouteSpec::for_tun("10.51.0.0/24".parse().unwrap()))
        );
        assert!(!inputs.snapshot().auto_suppressed());
    }

    #[tokio::test]
    async fn late_ready_is_rejected_after_claim_config_device_and_os_invalidation() {
        let owner = owner();
        let inputs = owner.inputs();
        let store = config();
        owner.bind_config(store.clone()).unwrap();
        let epoch = DeviceEpoch::new();
        inputs
            .set_default_device(uuid::Uuid::new_v4(), Some(epoch))
            .unwrap();
        let claim = owner.handle().publish(additional("198.18.0.1/32")).unwrap();
        ready(&inputs);
        claim.wait_ready(Some(epoch)).await.unwrap();
        let old = inputs.snapshot();
        claim.replace(additional("198.18.0.2/32")).unwrap();
        assert!(
            !inputs.publish_feedback(
                &old,
                InstanceRouteStatus::Active,
                old.claims
                    .keys()
                    .map(|id| (*id, ClaimRouteStatus::Ready))
                    .collect()
            )
        );
        assert!(claim.wait_ready(Some(epoch)).now_or_never().is_none());
        ready(&inputs);
        store.update_services(|services| services.dhcp_ipv4 = true);
        assert!(claim.wait_ready(Some(epoch)).now_or_never().is_none());
        ready(&inputs);
        store.update_peer(Arc::new(PeerRuntimeSnapshot::default()));
        claim.wait_ready(Some(epoch)).await.unwrap();
        inputs.invalidate();
        assert!(claim.wait_ready(Some(epoch)).now_or_never().is_none());
        ready(&inputs);
        inputs
            .set_default_device(
                inputs.snapshot().default_nic.unwrap(),
                Some(DeviceEpoch::new()),
            )
            .unwrap();
        assert_eq!(
            claim.wait_ready(Some(epoch)).await,
            Err(RouteWaitError::DeviceChanged)
        );
    }

    #[tokio::test]
    async fn waiter_captures_publication_and_requires_exact_device_epoch() {
        let owner = owner();
        let inputs = owner.inputs();
        let epoch = DeviceEpoch::new();
        inputs
            .set_default_device(uuid::Uuid::new_v4(), Some(epoch))
            .unwrap();
        let claim = owner.handle().publish(additional("198.18.0.1/32")).unwrap();
        assert_eq!(
            claim.wait_ready(None).await,
            Err(RouteWaitError::DeviceRequired)
        );
        let waiting = claim.wait_ready(Some(epoch));
        futures::pin_mut!(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        claim.replace(additional("198.18.0.2/32")).unwrap();
        assert_eq!(waiting.await, Err(RouteWaitError::Superseded));
        ready(&inputs);
        claim.wait_ready(Some(epoch)).await.unwrap();
        let snapshot = inputs.snapshot();
        let waiting = claim.wait_ready(Some(epoch));
        claim.replace(additional("198.18.0.2/32")).unwrap();
        assert!(
            inputs.is_current(&snapshot),
            "equal replacement preserves publication and Ready"
        );
        waiting.await.unwrap();
    }

    #[tokio::test]
    async fn close_revokes_stale_handles_but_retains_driver_state_until_explicit_drain() {
        let owner = owner();
        let inputs = owner.inputs();
        let handle = owner.handle();
        let claim = handle.publish(additional("198.18.0.1/32")).unwrap();
        let weak = Arc::downgrade(&inputs);
        owner.request_close();
        assert!(matches!(
            handle.publish(auto("10.50.0.0/24")),
            Err(RouteInputError::Closed)
        ));
        assert_eq!(
            claim.replace(additional("198.18.0.2/32")),
            Err(RouteInputError::Closed)
        );
        assert_eq!(
            claim.wait_ready(Some(DeviceEpoch::new())).await,
            Err(RouteWaitError::Closed)
        );
        assert!(owner.wait_drained().now_or_never().is_none());
        let closed = inputs.snapshot();
        assert!(closed.closed);
        assert!(closed.claims.is_empty());
        assert!(inputs.publish_feedback(&closed, InstanceRouteStatus::Drained, BTreeMap::new()));
        inputs.fail("late failure".into());
        assert!(!inputs.publish_feedback(&closed, InstanceRouteStatus::Draining, BTreeMap::new()));
        owner.wait_drained().await.unwrap();
        drop(owner);
        drop(inputs);
        assert!(
            weak.upgrade().is_none(),
            "handle/claim must not keep input/config alive"
        );
        assert!(matches!(
            handle.publish(auto("10.50.0.0/24")),
            Err(RouteInputError::Closed)
        ));
    }

    #[tokio::test]
    async fn failures_and_suppression_are_not_ready_or_drained() {
        let owner = owner();
        let inputs = owner.inputs();
        let epoch = DeviceEpoch::new();
        inputs
            .set_default_device(uuid::Uuid::new_v4(), Some(epoch))
            .unwrap();
        let claim = owner.handle().publish(auto("10.50.0.0/24")).unwrap();
        let snapshot = inputs.snapshot();
        let statuses = snapshot
            .claims
            .keys()
            .map(|id| (*id, ClaimRouteStatus::Suppressed))
            .collect();
        inputs.publish_feedback(&snapshot, InstanceRouteStatus::Active, statuses);
        assert_eq!(
            claim.wait_ready(Some(epoch)).await,
            Err(RouteWaitError::Suppressed)
        );
        inputs.fail("worker terminated".into());
        assert_eq!(
            claim.wait_ready(Some(epoch)).await,
            Err(RouteWaitError::Failed("worker terminated".into()))
        );
        assert_eq!(
            owner.wait_drained().await,
            Err(RouteWaitError::Failed("worker terminated".into()))
        );
    }

    #[test]
    fn invalid_replace_preserves_input_and_cross_instance_feedback_is_rejected() {
        let owner = owner();
        let inputs = owner.inputs();
        let claim = owner.handle().publish(additional("198.18.0.1/32")).unwrap();
        let before = inputs.snapshot();
        let mut invalid = RouteSpec::for_tun("198.18.0.2/32".parse().unwrap());
        invalid.preferred_source = Some("::1".parse().unwrap());
        assert!(matches!(
            claim.replace(RouteDemand::Additional(RouteSet::from([invalid]))),
            Err(RouteInputError::InvalidSpec(_))
        ));
        assert!(inputs.is_current(&before));
        let other = super::tests::owner();
        let _claim = other.handle().publish(additional("198.18.0.1/32")).unwrap();
        assert!(!other.inputs().is_current(&before));
        assert!(!other.inputs().publish_feedback(
            &before,
            InstanceRouteStatus::Active,
            BTreeMap::new()
        ));
    }

    #[test]
    fn binding_is_once_per_instance_and_rebinding_cannot_revoke_an_active_epoch() {
        let owner = owner();
        let inputs = owner.inputs();
        let nic = uuid::Uuid::new_v4();
        owner.bind_default_nic(nic).unwrap();
        let epoch = DeviceEpoch::new();
        inputs.set_default_device(nic, Some(epoch)).unwrap();
        let snapshot = inputs.snapshot();
        owner.bind_default_nic(nic).unwrap();
        assert!(inputs.is_current(&snapshot));
        assert_eq!(inputs.snapshot().device, Some(epoch));
        assert_eq!(
            owner.bind_default_nic(uuid::Uuid::new_v4()),
            Err(RouteInputError::AlreadyBound)
        );
        assert_eq!(
            inputs.set_default_device(uuid::Uuid::new_v4(), Some(epoch)),
            Err(RouteInputError::AlreadyBound)
        );
        assert!(inputs.is_current(&snapshot));
    }

    #[test]
    fn concurrent_equal_replacements_commit_one_actual_publication_change() {
        let owner = owner();
        let inputs = owner.inputs();
        let claim = Arc::new(owner.handle().publish(additional("198.18.0.1/32")).unwrap());
        let before = inputs.snapshot();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let threads = (0..2)
            .map(|_| {
                let claim = claim.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    claim.replace(additional("198.18.0.2/32")).unwrap();
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        let after = inputs.snapshot();
        assert_eq!(after.stamp, before.stamp + 1);
        assert_eq!(after.claims.len(), 1);
        assert_eq!(
            after.claims.values().next().unwrap().as_ref(),
            &additional("198.18.0.2/32")
        );
    }

    #[test]
    fn callbacks_run_outside_input_lock_and_drop_revokes_synchronously() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(Weak::<RouteInputs>::new()));
        let callback_inputs = observed.clone();
        let callback_wakes = wakes.clone();
        let owner = InstanceRoutes::new(Arc::new(move || {
            callback_wakes.fetch_add(1, Ordering::Relaxed);
            if let Some(inputs) = callback_inputs.lock().upgrade() {
                assert!(inputs.state.try_lock().is_some());
            }
        }));
        *observed.lock() = Arc::downgrade(&owner.inputs);
        let inputs = owner.inputs();
        let claim = owner.handle().publish(auto("10.50.0.0/24")).unwrap();
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        drop(claim);
        assert!(inputs.snapshot().claims.is_empty());
        assert_eq!(wakes.load(Ordering::Relaxed), 2);
        drop(owner);
        assert!(inputs.snapshot().closed);
        assert_eq!(wakes.load(Ordering::Relaxed), 3);
    }
}
