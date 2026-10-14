//! Route declaration models and resolution rules for per-instance route registries.
//!
//! [`Registry<RouteDemand>`] holds independently owned dynamic declarations.
//! The route manager combines these with manual proxy policy read directly from
//! the instance's runtime configuration.

use std::collections::BTreeSet;
use std::sync::Arc;

use cidr::{IpCidr, Ipv4Cidr};
use registry::{Registration, Registry};

/// One publisher's set of route destinations.
pub type RouteSet = BTreeSet<IpCidr>;

/// Route intent declared by an individual producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDemand {
    /// Proxy CIDRs announced by reachable peers.
    AutoProxy(BTreeSet<Ipv4Cidr>),
    /// Additional routes that must always be present (e.g. DNS fake-IP).
    Additional(RouteSet),
}

/// Lightweight, cloneable handle for registering route publishers.
///
/// RouteHandle exposes only registration capability, preventing producers
/// from closing the underlying registry.
#[derive(Clone, Debug)]
pub struct RouteHandle {
    routes: Registry<RouteDemand>,
}

impl RouteHandle {
    /// Wraps an existing route registry.
    pub fn new(routes: Registry<RouteDemand>) -> Self {
        Self { routes }
    }

    /// Registers a new route demand. Returns `None` if the registry is closed.
    pub fn register(&self, demand: RouteDemand) -> Option<Registration<RouteDemand>> {
        self.routes.register(demand)
    }
}

/// Resolves dynamic declarations and authoritative manual policy into a route set.
///
/// Rules:
/// 1. `Additional` routes are always merged into the result.
/// 2. `Some(routes)` replaces the entire auto-proxy group, including when empty.
/// 3. `None` allows all `AutoProxy` declarations to contribute.
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
                result.insert(IpCidr::V4(cidr));
            }
        }
        None => {
            for demand in demands {
                if let RouteDemand::AutoProxy(auto_routes) = demand.as_ref() {
                    for &cidr in auto_routes {
                        result.insert(IpCidr::V4(cidr));
                    }
                }
            }
        }
    }

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

    fn v4(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpCidr {
        s.parse().unwrap()
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
