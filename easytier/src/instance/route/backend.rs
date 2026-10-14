use std::collections::BTreeSet;

use super::model::{Route, RouteError};

#[async_trait::async_trait]
pub trait RouteBackend: Send + 'static {
    /// Add a route to the system.
    /// - Ok(Some(route)): Successfully created by this manager (record in `installed_routes`).
    /// - Ok(None): Equivalent entry already present in system, not created by us (record in `external_present`).
    /// - Err(RouteError::Failed(err)): Deterministic failure (track retry with backoff).
    /// - Err(RouteError::Unknown(err)): Unknown outcome (isolate in `unknown_routes`, never blind retry).
    async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError>;

    /// Remove a route from the system.
    /// - Ok(Some(())): Successfully removed by this manager (remove from `installed_routes`).
    /// - Ok(None): Exact target already absent (remove from `installed_routes`).
    /// - Err(RouteError::Failed(err)): Deterministic failure (track retry with backoff).
    /// - Err(RouteError::Unknown(err)): Unknown outcome (isolate in `unknown_routes`, report on stop).
    async fn remove(&mut self, route: &Route) -> Result<Option<()>, RouteError>;

    /// Read-only, complete inspection of the supplied physical route keys.
    /// Returns only matching input routes; application device generations do
    /// not participate in OS lookup. Presence never establishes ownership.
    /// An error must not be interpreted as evidence that any route is absent.
    async fn existing(&mut self, routes: &BTreeSet<Route>) -> Result<BTreeSet<Route>, RouteError>;
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
#[path = "linux.rs"]
mod linux;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub use linux::PlatformRouteBackend;
