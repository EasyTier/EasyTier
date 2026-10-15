//! Route declaration models and resolution rules for per-instance route registries.
//!
//! [`Registry<RouteDemand>`] holds independently owned dynamic declarations.
//! The route manager combines these with manual proxy policy read directly from
//! the instance's runtime configuration.

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::sync::Arc;

use cidr::{IpCidr, Ipv4Cidr};
use registry::{Registration, Registry};
use tokio::sync::watch;

/// A concrete direct-route request. The manager supplies the selected device;
/// the producer supplies the destination and a nonzero Linux route metric.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteSpec {
    pub destination: IpCidr,
    pub metric: NonZeroU32,
}

impl RouteSpec {
    pub const fn new(destination: IpCidr, metric: NonZeroU32) -> Self {
        Self {
            destination,
            metric,
        }
    }
}

/// Ordinary proxy / DNS routes use the existing metric 65535.
impl From<IpCidr> for RouteSpec {
    fn from(destination: IpCidr) -> Self {
        Self::new(destination, NonZeroU32::new(65535).unwrap())
    }
}

/// One publisher's complete set of direct-route requests.
pub type RouteSet = BTreeSet<RouteSpec>;

/// Route intent declared by an individual producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDemand {
    /// Proxy CIDRs announced by reachable peers.
    AutoProxy(BTreeSet<Ipv4Cidr>),
    /// Additional routes that must always be present (e.g. DNS fake-IP).
    Additional(RouteSet),
}

impl RouteDemand {
    pub fn additional(destinations: impl IntoIterator<Item = IpCidr>) -> Self {
        Self::Additional(destinations.into_iter().map(RouteSpec::from).collect())
    }
}

/// Last acknowledged or verified routes on the selected, ready device.
/// This is route-domain feedback, not a registry membership notification or
/// a guarantee against arbitrary subsequent changes by external OS writers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteStatus {
    /// Identifies the selected fd claim, including persistent TUN attachments.
    pub device_registration: Option<u64>,
    pub ready: RouteSet,
    pub closed: bool,
}

/// Owner-side route declarations and independently published OS feedback.
/// Producers receive only [`RouteHandle`]; only the domain manager publishes
/// feedback and closes this facade. The generic Registry remains unchanged.
#[derive(Clone, Debug)]
pub struct RouteRegistry {
    declarations: Registry<RouteDemand>,
    status: watch::Sender<Arc<RouteStatus>>,
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self {
            declarations: Registry::default(),
            status: watch::channel(Arc::new(RouteStatus::default())).0,
        }
    }
}

impl RouteRegistry {
    pub fn snapshot(&self) -> Vec<Arc<RouteDemand>> {
        self.declarations.snapshot()
    }
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.declarations.subscribe()
    }
    pub fn len(&self) -> usize {
        self.declarations.len()
    }
    pub fn is_empty(&self) -> bool {
        self.declarations.is_empty()
    }

    /// A closed status is terminal, even if an older reconciliation finishes.
    pub fn publish_status(&self, status: RouteStatus) {
        self.status.send_if_modified(|current| {
            if current.closed || **current == status {
                return false;
            }
            *current = Arc::new(status);
            true
        });
    }

    pub fn close(&self) {
        self.publish_status(RouteStatus {
            closed: true,
            ..RouteStatus::default()
        });
        self.declarations.close();
    }
}

/// Lightweight, cloneable handle for registering route publishers.
///
/// RouteHandle exposes only registration capability, preventing producers
/// from closing the underlying registry.
#[derive(Clone, Debug)]
pub struct RouteHandle {
    routes: Registry<RouteDemand>,
    status: watch::Receiver<Arc<RouteStatus>>,
}

impl RouteHandle {
    /// Wraps an existing route registry.
    pub fn new(routes: RouteRegistry) -> Self {
        Self {
            routes: routes.declarations,
            status: routes.status.subscribe(),
        }
    }

    /// Registers a new route demand. Returns `None` if the registry is closed.
    pub fn register(&self, demand: RouteDemand) -> Option<Registration<RouteDemand>> {
        self.routes.register(demand)
    }

    pub fn status(&self) -> Arc<RouteStatus> {
        self.status.borrow().clone()
    }

    /// Waits for acknowledged / verified destinations on this exact fd claim,
    /// at the requested metric or a lower effective metric from another source.
    /// Callers supply their business deadline and retain their registration.
    pub async fn wait_ready(
        &self,
        required: &RouteSet,
        device_registration: u64,
    ) -> Result<(), RouteRuntimeClosed> {
        let mut status = self.status.clone();
        loop {
            let snapshot = status.borrow_and_update().clone();
            if snapshot.closed {
                return Err(RouteRuntimeClosed);
            }
            if snapshot.device_registration == Some(device_registration)
                && required.iter().all(|request| {
                    snapshot
                        .ready
                        .range(RouteSpec::new(request.destination, NonZeroU32::MIN)..=*request)
                        .next()
                        .is_some()
                })
            {
                return Ok(());
            }
            status.changed().await.map_err(|_| RouteRuntimeClosed)?;
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("route runtime closed before routes became ready")]
pub struct RouteRuntimeClosed;

/// Resolves dynamic declarations and authoritative manual policy into a route set.
///
/// Rules:
/// 1. `Additional` routes are always merged into the result.
/// 2. `Some(routes)` replaces the entire auto-proxy group, including when empty.
/// 3. `None` allows all `AutoProxy` declarations to contribute.
/// 4. Overlapping requests for one destination use the lowest metric. Removing
///    that contribution exposes the next remaining request for the same slot.
pub fn resolve_route_demands(
    demands: &[Arc<RouteDemand>],
    manual_routes: Option<&BTreeSet<Ipv4Cidr>>,
) -> RouteSet {
    let mut result = RouteSet::new();

    for demand in demands {
        match demand.as_ref() {
            RouteDemand::Additional(routes) => {
                result.extend(routes.iter().copied());
            }
            RouteDemand::AutoProxy(_) => {}
        }
    }

    match manual_routes {
        Some(manual_routes) => {
            for &cidr in manual_routes {
                result.insert(IpCidr::V4(cidr).into());
            }
        }
        None => {
            for demand in demands {
                if let RouteDemand::AutoProxy(auto_routes) = demand.as_ref() {
                    for &cidr in auto_routes {
                        result.insert(IpCidr::V4(cidr).into());
                    }
                }
            }
        }
    }

    // RouteSpec is ordered by destination, then metric. Keep one effective
    // request per destination, with an explicit deterministic cost policy.
    let mut destinations = BTreeSet::new();
    result.retain(|route| destinations.insert(route.destination));
    result
}

/// Legacy helper for CIDR monitor fallback: manual routes take precedence over
/// peer routes.
pub fn resolve_proxy_cidrs(
    peer_routes: BTreeSet<Ipv4Cidr>,
    manual_routes: Option<BTreeSet<Ipv4Cidr>>,
) -> BTreeSet<Ipv4Cidr> {
    manual_routes.unwrap_or(peer_routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn declaration_membership_and_wrong_device_do_not_mean_ready() {
        let routes = RouteRegistry::default();
        let handle = RouteHandle::new(routes.clone());
        let required = RouteSet::from([ip("10.0.0.1/32")]);
        let _registration = handle
            .register(RouteDemand::Additional(required.clone()))
            .unwrap();
        let mut ready = Box::pin(handle.wait_ready(&required, 2));
        assert!(futures::poll!(ready.as_mut()).is_pending());
        routes.publish_status(RouteStatus {
            device_registration: Some(1),
            ready: required.clone(),
            closed: false,
        });
        assert!(futures::poll!(ready.as_mut()).is_pending());
        routes.publish_status(RouteStatus {
            device_registration: Some(2),
            ready: required.clone(),
            closed: false,
        });
        ready.await.unwrap();
    }

    #[tokio::test]
    async fn close_wakes_waiters_and_rejects_late_ready_publication() {
        let routes = RouteRegistry::default();
        let handle = RouteHandle::new(routes.clone());
        let required = RouteSet::from([ip("10.0.0.1/32")]);
        let mut ready = Box::pin(handle.wait_ready(&required, 1));
        assert!(futures::poll!(ready.as_mut()).is_pending());
        routes.close();
        routes.publish_status(RouteStatus {
            device_registration: Some(1),
            ready: required.clone(),
            closed: false,
        });
        assert!(ready.await.is_err());
        assert!(handle.status().closed);
        assert!(handle.status().ready.is_empty());
        assert!(
            handle
                .register(RouteDemand::Additional(RouteSet::new()))
                .is_none()
        );
    }

    fn v4(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> RouteSpec {
        s.parse::<IpCidr>().unwrap().into()
    }

    #[tokio::test]
    async fn overlapping_metrics_select_the_lowest_and_withdrawal_exposes_the_next() {
        let low = RouteSpec::new("::/0".parse().unwrap(), NonZeroU32::new(5).unwrap());
        let ordinary = ip("::/0");
        let routes = RouteRegistry::default();
        let handle = RouteHandle::new(routes.clone());
        let _ordinary = handle
            .register(RouteDemand::Additional(RouteSet::from([ordinary])))
            .unwrap();
        let preferred = handle
            .register(RouteDemand::Additional(RouteSet::from([low])))
            .unwrap();
        assert_eq!(
            resolve_route_demands(&routes.snapshot(), None),
            RouteSet::from([low])
        );
        routes.publish_status(RouteStatus {
            device_registration: Some(1),
            ready: RouteSet::from([low]),
            closed: false,
        });
        handle
            .wait_ready(&RouteSet::from([ordinary]), 1)
            .await
            .unwrap();
        drop(preferred);
        assert_eq!(
            resolve_route_demands(&routes.snapshot(), None),
            RouteSet::from([ordinary])
        );
    }

    #[test]
    fn resolve_demands_without_manual_unions_auto_and_additional() {
        let demands = vec![
            Arc::new(RouteDemand::AutoProxy(BTreeSet::from([v4("10.1.0.0/16")]))),
            Arc::new(RouteDemand::AutoProxy(BTreeSet::from([v4("10.2.0.0/16")]))),
            Arc::new(RouteDemand::Additional(BTreeSet::from([ip("10.3.0.0/16")]))),
        ];

        let resolved = resolve_route_demands(&demands, None);
        assert_eq!(
            resolved,
            BTreeSet::from([ip("10.1.0.0/16"), ip("10.2.0.0/16"), ip("10.3.0.0/16")])
        );
    }

    #[test]
    fn resolve_demands_deduplicates_overlapping_sources() {
        let demands = vec![
            Arc::new(RouteDemand::AutoProxy(BTreeSet::from([v4("10.1.0.0/16")]))),
            Arc::new(RouteDemand::AutoProxy(BTreeSet::from([v4("10.1.0.0/16")]))),
            Arc::new(RouteDemand::Additional(BTreeSet::from([
                ip("10.1.0.0/16"),
                ip("10.3.0.0/16"),
            ]))),
        ];

        let resolved = resolve_route_demands(&demands, None);
        assert_eq!(
            resolved,
            BTreeSet::from([ip("10.1.0.0/16"), ip("10.3.0.0/16")])
        );
    }

    #[test]
    fn resolve_demands_with_manual_some_overrides_auto_and_keeps_additional() {
        let demands = vec![
            Arc::new(RouteDemand::AutoProxy(BTreeSet::from([v4("10.1.0.0/16")]))),
            Arc::new(RouteDemand::Additional(BTreeSet::from([ip("10.3.0.0/16")]))),
        ];

        let manual = BTreeSet::from([v4("192.168.1.0/24")]);
        let resolved = resolve_route_demands(&demands, Some(&manual));
        assert_eq!(
            resolved,
            BTreeSet::from([ip("192.168.1.0/24"), ip("10.3.0.0/16")])
        );
    }

    #[test]
    fn resolve_demands_with_manual_empty_suppresses_auto_and_keeps_additional() {
        let demands = vec![
            Arc::new(RouteDemand::AutoProxy(BTreeSet::from([v4("10.1.0.0/16")]))),
            Arc::new(RouteDemand::Additional(BTreeSet::from([ip("10.3.0.0/16")]))),
        ];

        let resolved = resolve_route_demands(&demands, Some(&BTreeSet::new()));
        assert_eq!(resolved, BTreeSet::from([ip("10.3.0.0/16")]));
    }

    #[test]
    fn resolve_proxy_cidrs_rules() {
        let peer = BTreeSet::from([v4("10.1.0.0/16")]);
        let manual = BTreeSet::from([v4("192.168.1.0/24")]);

        assert_eq!(resolve_proxy_cidrs(peer.clone(), None), peer);
        assert_eq!(
            resolve_proxy_cidrs(peer.clone(), Some(manual.clone())),
            manual
        );
        assert_eq!(
            resolve_proxy_cidrs(peer, Some(BTreeSet::new())),
            BTreeSet::new()
        );
    }
}
