pub mod backend;
pub(crate) mod device;
mod inputs;
pub mod manager;
pub mod model;
#[cfg(all(
    target_os = "linux",
    feature = "linux-netlink",
    feature = "tun",
    not(mobile)
))]
pub(crate) mod outlet;
pub(crate) mod projection;
pub(crate) mod scope;
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub use backend::PlatformRouteBackend;
pub use backend::RouteBackend;

pub use easytier_core::host::route::{
    RouteDemand, RouteHandle, RouteSet, RouteSpec, resolve_proxy_cidrs, resolve_route_demands,
};
pub use manager::RouteMgr;
pub use model::{CleanupIncomplete, DeviceId, OsRoute, Route, RouteError};
