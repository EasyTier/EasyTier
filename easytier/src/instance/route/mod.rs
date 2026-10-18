//! Native control of one network domain. Production backend dispatch is static.

use std::{collections::BTreeSet, future::Future, net::IpAddr, num::NonZeroU32};

use cidr::IpCidr;

pub(crate) mod device;
mod linux;
mod manager;
#[cfg(feature = "tun")]
pub(crate) mod runtime;

pub(crate) use linux::PlatformRouteBackend;
#[cfg(feature = "tun")]
pub(crate) use manager::RouteController;

pub(crate) const METRIC_DIRECT: NonZeroU32 = NonZeroU32::new(65535).unwrap();
pub(crate) const METRIC_PUBLIC_IPV6_DEFAULT: NonZeroU32 = NonZeroU32::new(5).unwrap();

pub(crate) fn validate_tun_spec(
    spec: &easytier_core::host::route::RouteSpec,
) -> Result<NonZeroU32, &'static str> {
    use easytier_core::host::route::{DeviceSelector, RouteAction};
    if !matches!(
        &spec.action,
        RouteAction::Unicast {
            device: Some(DeviceSelector::InstanceTun),
            via: None
        }
    ) {
        return Err("only directly attached instance TUN routes are supported");
    }
    if spec.table.is_some_and(|table| table != 254) {
        return Err("non-main route tables are not supported yet");
    }
    NonZeroU32::new(spec.metric).ok_or("Linux route metric must be nonzero")
}

/// Resolved parameters for the initially supported, static, directly attached
/// unicast route. Device generations and application ownership stay outside.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OsRoute {
    pub table: u32,
    pub destination: IpCidr,
    pub metric: NonZeroU32,
    pub ifindex: u32,
    pub preferred_source: Option<IpAddr>,
}

/// Linux TOS=0 / source-selector=::/0, single-nexthop CREATE|EXCL slot.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OsRouteSlotKey {
    table: u32,
    destination: IpCidr,
    metric: NonZeroU32,
}

impl OsRoute {
    pub(crate) fn slot(&self) -> OsRouteSlotKey {
        OsRouteSlotKey {
            table: self.table,
            destination: self.destination,
            metric: self.metric,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RouteError {
    #[error("route operation failed: {0}")]
    Failed(anyhow::Error),
    #[error("route operation outcome is unknown: {0}")]
    Unknown(anyhow::Error),
}

impl RouteError {
    pub(crate) fn is_errno(&self, errno: i32) -> bool {
        matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(errno)))
    }
}

// Private test seam. Production uses the single concrete platform backend;
// there is no vtable or boxed future in its request path.
trait RouteBackend: Send + 'static {
    fn add(&mut self, route: &OsRoute) -> impl Future<Output = Result<(), RouteError>> + Send;
    fn remove(&mut self, route: &OsRoute) -> impl Future<Output = Result<(), RouteError>> + Send;
    fn existing(
        &mut self,
        routes: &BTreeSet<OsRoute>,
    ) -> impl Future<Output = Result<BTreeSet<OsRoute>, RouteError>> + Send;
}
