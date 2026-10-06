//! The proxy CIDR demand of one instance, and the registry its producers write
//! into.
//!
//! Two producers contribute a layer each:
//! - the route table announces the proxy CIDRs of reachable peers;
//! - the runtime config declares `services.manual_routes`.
//!
//! Neither producer knows the other, and neither applies the resolution rule:
//! each holds a [`ProxyCidrSlot`] and publishes its own layer at its commit
//! point. The registry resolves the layers and pushes the result into the
//! instance's route manager, which holds it as one claim among its demands.
//! Dropping a slot withdraws that producer's layer and republishes what is
//! left, so the claim never outlives the layers behind it.

use std::collections::BTreeSet;
use std::sync::Arc;

use cidr::{IpCidr, Ipv4Cidr};
use parking_lot::Mutex;
use registry::{Registration, Registry};

/// The route manager's demand type: what a claim asks to be routed.
pub type RouteSet = BTreeSet<IpCidr>;

/// The resolution rule: a declared manual set takes over the demand outright;
/// without one the peer routes are in charge.
pub(crate) fn resolve_proxy_cidrs(
    peer_routes: BTreeSet<Ipv4Cidr>,
    manual_routes: Option<BTreeSet<Ipv4Cidr>>,
) -> BTreeSet<Ipv4Cidr> {
    manual_routes.unwrap_or(peer_routes)
}

/// One producer's contribution to the proxy CIDR demand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProxyCidrLayer {
    /// Proxy CIDRs announced by reachable peers.
    Peer(BTreeSet<Ipv4Cidr>),
    /// `services.manual_routes`: `Some` takes over the demand outright (an
    /// empty set means "proxy nothing"), `None` leaves the peer layer in
    /// charge.
    Manual(Option<BTreeSet<Ipv4Cidr>>),
}

/// Per-instance registry of proxy CIDR layers.
///
/// Cloning shares the same registry, including its route-manager claim.
#[derive(Clone)]
pub struct ProxyRouteRegistry {
    layers: Registry<ProxyCidrLayer>,
    /// The claim this registry holds in the route manager's registry.
    /// Present once the route manager has attached.
    demand: Arc<Mutex<Option<Registration<RouteSet>>>>,
}

impl Default for ProxyRouteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyRouteRegistry {
    pub fn new() -> Self {
        Self {
            layers: Registry::default(),
            demand: Arc::new(Mutex::new(None)),
        }
    }

    /// Takes one producer's layer; the returned slot keeps it live.
    pub(crate) fn register(&self, layer: ProxyCidrLayer) -> Option<ProxyCidrSlot> {
        Some(ProxyCidrSlot {
            registry: self.clone(),
            layer: Some(self.layers.register(layer)?),
        })
    }

    /// Hands this registry the claim it fills in the route manager. The
    /// current resolution is published right away, so the manager starts from
    /// the demand as it stands.
    pub fn attach_demand(&self, demand: Registration<RouteSet>) {
        let mut slot = self.demand.lock();
        *slot = Some(demand);
        Self::push(&slot, self.resolved());
    }

    /// Publishes a producer's new layer value together with the resolution
    /// that follows from it.
    ///
    /// Resolving outside the lock would let two producers interleave — each
    /// reading a state that already includes the other's write — and land the
    /// older resolution last.
    fn publish(&self, layer: &Registration<ProxyCidrLayer>, value: ProxyCidrLayer) {
        let slot = self.demand.lock();
        let _ = layer.replace(value);
        Self::push(&slot, self.resolved());
    }

    /// Republishes the resolution as it stands, without touching any layer.
    fn publish_resolved(&self) {
        let slot = self.demand.lock();
        Self::push(&slot, self.resolved());
    }

    fn push(slot: &Option<Registration<RouteSet>>, resolved: RouteSet) {
        if let Some(demand) = slot.as_ref() {
            let _ = demand.replace(resolved);
        }
    }

    /// The resolved proxy CIDR set.
    ///
    /// A manual layer that declares a set replaces the peer layers entirely;
    /// with no such layer the peer layers are unioned.
    pub fn resolved(&self) -> RouteSet {
        let layers = self.layers.snapshot();
        let peer_routes: BTreeSet<Ipv4Cidr> = layers
            .iter()
            .filter_map(|layer| match &**layer {
                ProxyCidrLayer::Peer(routes) => Some(routes.iter().copied()),
                ProxyCidrLayer::Manual(_) => None,
            })
            .flatten()
            .collect();
        let resolved = match layers.iter().rev().find_map(|layer| match &**layer {
            ProxyCidrLayer::Manual(routes) => Some(routes.clone()),
            ProxyCidrLayer::Peer(_) => None,
        }) {
            Some(manual_routes) => resolve_proxy_cidrs(peer_routes, manual_routes),
            None => peer_routes,
        };
        resolved.into_iter().map(IpCidr::V4).collect()
    }
}

/// One producer's live layer.
///
/// Publishing goes through the registry so the resolution and the route
/// manager's claim are updated together.
pub(crate) struct ProxyCidrSlot {
    registry: ProxyRouteRegistry,
    layer: Option<Registration<ProxyCidrLayer>>,
}

impl ProxyCidrSlot {
    pub(crate) fn publish(&self, value: ProxyCidrLayer) {
        let Some(layer) = &self.layer else {
            return;
        };
        self.registry.publish(layer, value);
    }
}

impl Drop for ProxyCidrSlot {
    fn drop(&mut self) {
        // Withdrawing the layer is not enough: the claim the manager holds was
        // pushed, so the resolution has to be pushed again without it.
        drop(self.layer.take());
        self.registry.publish_resolved();
    }
}

impl std::fmt::Debug for ProxyCidrSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCidrSlot").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidrs(values: &[&str]) -> BTreeSet<Ipv4Cidr> {
        values.iter().map(|v| v.parse().unwrap()).collect()
    }

    fn v4(set: &[&str]) -> RouteSet {
        cidrs(set).into_iter().map(IpCidr::V4).collect()
    }

    #[test]
    fn manual_layer_replaces_peer_layers() {
        let registry = ProxyRouteRegistry::new();
        let peer = registry
            .register(ProxyCidrLayer::Peer(cidrs(&["10.1.2.0/24"])))
            .unwrap();
        assert_eq!(registry.resolved(), v4(&["10.1.2.0/24"]));

        let manual = registry
            .register(ProxyCidrLayer::Manual(Some(cidrs(&["192.168.0.0/16"]))))
            .unwrap();
        assert_eq!(registry.resolved(), v4(&["192.168.0.0/16"]));

        manual.publish(ProxyCidrLayer::Manual(None));
        assert_eq!(registry.resolved(), v4(&["10.1.2.0/24"]));

        manual.publish(ProxyCidrLayer::Manual(Some(BTreeSet::new())));
        assert!(registry.resolved().is_empty());

        drop(peer);
        assert!(registry.resolved().is_empty());
    }

    #[test]
    fn peer_layers_are_unioned_and_withdrawn_with_their_slot() {
        let registry = ProxyRouteRegistry::new();
        let peer_a = registry
            .register(ProxyCidrLayer::Peer(cidrs(&["10.1.2.0/24"])))
            .unwrap();
        let _peer_b = registry
            .register(ProxyCidrLayer::Peer(cidrs(&["10.1.3.0/24"])))
            .unwrap();
        assert_eq!(registry.resolved(), v4(&["10.1.2.0/24", "10.1.3.0/24"]));

        drop(peer_a);
        assert_eq!(registry.resolved(), v4(&["10.1.3.0/24"]));
    }

    #[test]
    fn publishing_updates_the_attached_demand() {
        let registry = ProxyRouteRegistry::new();
        let demand = Registry::<RouteSet>::default();
        let registration = demand.register(RouteSet::new()).unwrap();
        let mut changed = demand.subscribe();

        registry.attach_demand(registration);
        let peer = registry
            .register(ProxyCidrLayer::Peer(cidrs(&["10.1.2.0/24"])))
            .unwrap();
        peer.publish(ProxyCidrLayer::Peer(cidrs(&["10.1.3.0/24"])));

        assert!(changed.has_changed().unwrap());
        let claimed: RouteSet = demand
            .snapshot()
            .iter()
            .flat_map(|set| set.iter().copied())
            .collect();
        assert_eq!(claimed, v4(&["10.1.3.0/24"]));
    }
}
