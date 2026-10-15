use std::collections::BTreeSet;

use super::model::{OsRoute, RouteError};

#[async_trait::async_trait]
pub trait RouteBackend: Send + 'static {
    /// OS add with exclusive creation. EEXIST is returned without inspecting,
    /// adopting, replacing or otherwise interpreting the existing route.
    async fn add(&mut self, route: &OsRoute) -> Result<(), RouteError>;

    /// OS delete with the supplied parameters. OS errors, including absence,
    /// are returned to the caller without ownership or retry policy.
    async fn remove(&mut self, route: &OsRoute) -> Result<(), RouteError>;

    /// Read-only query of matching OS routes. No application identities or
    /// ownership claims are accepted or inferred.
    async fn existing(
        &mut self,
        routes: &BTreeSet<OsRoute>,
    ) -> Result<BTreeSet<OsRoute>, RouteError>;
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
#[path = "linux.rs"]
mod linux;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub use linux::PlatformRouteBackend;
