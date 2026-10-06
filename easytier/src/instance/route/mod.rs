pub mod backend;
pub mod manager;
pub mod model;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub use backend::PlatformRouteBackend;
pub use backend::RouteBackend;

pub use easytier_core::host::route::{
    resolve_proxy_cidrs, resolve_route_demands, RouteDemand, RouteHandle, RouteSet,
};
pub use manager::RouteMgr;
pub use model::{CleanupIncomplete, DeviceId, Route, RouteError};
