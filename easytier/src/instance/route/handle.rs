use std::collections::BTreeSet;

use cidr::IpCidr;
use registry::{Registration, Registry};

/// One publisher's set of route destinations.
pub type RouteSet = BTreeSet<IpCidr>;

/// Lightweight, cloneable handle for registering route publishers.
///
/// Different publishers do NOT share routing state with each other. Each
/// registered publisher acquires an independent `RouteLease` backed by its own
/// private entry in the manager's registry.
#[derive(Clone, Debug)]
pub struct RouteHandle(Registry<RouteSet>);

impl RouteHandle {
    pub(super) fn new(routes: Registry<RouteSet>) -> Self {
        Self(routes)
    }

    /// Registers a new publisher source.
    ///
    /// Returns `None` once the manager has closed its registry: the manager is
    /// stopping, so the publisher must not be started.
    pub fn register(&self) -> Option<RouteLease> {
        self.0.register(RouteSet::new()).map(RouteLease)
    }
}

/// RAII route lease held by a publisher.
///
/// When the lease is dropped, its entry is withdrawn from the manager's
/// registry and the manager is notified immediately.
#[derive(Debug)]
pub struct RouteLease(Registration<RouteSet>);

impl RouteLease {
    /// Replaces this publisher's complete route set.
    ///
    /// Late declarations are discarded after the manager closed the registry.
    pub fn set(&self, cidrs: RouteSet) {
        let _ = self.0.replace(cidrs);
    }

    /// Withdraws this publisher's routes while keeping the lease alive.
    pub fn clear(&self) {
        self.set(RouteSet::new());
    }

    /// Returns this publisher's current declaration.
    pub fn list(&self) -> RouteSet {
        self.0.get().map(|set| (*set).clone()).unwrap_or_default()
    }
}
