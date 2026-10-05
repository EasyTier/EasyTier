pub mod backend;
pub mod handle;
pub mod manager;
pub mod model;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub use backend::PlatformRouteBackend;
pub use backend::RouteBackend;

pub use handle::{RouteHandle, RouteLease, RouteSlot};
pub use manager::{RouteMgr, stop_route_mgr};
pub use model::{CleanupIncomplete, DeviceId, Route, RouteError};
