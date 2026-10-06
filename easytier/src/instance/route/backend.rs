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
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
#[derive(Default, Clone)]
pub struct PlatformRouteBackend;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
impl PlatformRouteBackend {
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self)
    }
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
fn add_ipv4_route(
    ifindex: u32,
    v4: cidr::Ipv4Cidr,
    metric: u32,
) -> Result<Option<()>, crate::common::error::Error> {
    use crate::common::error::Error;
    use crate::common::ifcfg::netlink::{message_request, send_netlink_req_and_wait_ack};
    use crate::common::ifcfg::netlink_wire::{
        NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, RTM_NEWROUTE, RouteMessageBuilder,
        RouteType,
    };
    use nix::libc;
    use std::net::IpAddr;

    let message = RouteMessageBuilder::new(libc::AF_INET as u8)
        .destination(IpAddr::V4(v4.first_address()), v4.network_length())
        .oif(ifindex)
        .priority(metric)
        .table(libc::RT_TABLE_MAIN.into())
        .static_protocol()
        .universe_scope()
        .route_type(RouteType::Unicast)
        .build();
    let request = message_request(
        RTM_NEWROUTE,
        NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST,
        &message,
    )?;
    match send_netlink_req_and_wait_ack(request) {
        Ok(()) => Ok(Some(())),
        Err(Error::IOError(ref e)) if e.raw_os_error() == Some(libc::EEXIST) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
fn remove_ipv4_route(
    ifindex: u32,
    v4: cidr::Ipv4Cidr,
) -> Result<Option<()>, crate::common::error::Error> {
    use crate::common::error::Error;
    use crate::common::ifcfg::netlink::{message_request, send_netlink_req_and_wait_ack};
    use crate::common::ifcfg::netlink_wire::{
        NLM_F_ACK, NLM_F_REQUEST, RTM_DELROUTE, RouteMessageBuilder, RouteType,
    };
    use nix::libc;
    use std::net::IpAddr;

    let message = RouteMessageBuilder::new(libc::AF_INET as u8)
        .destination(IpAddr::V4(v4.first_address()), v4.network_length())
        .oif(ifindex)
        .table(libc::RT_TABLE_MAIN.into())
        .static_protocol()
        .universe_scope()
        .route_type(RouteType::Unicast)
        .build();
    let request = message_request(RTM_DELROUTE, NLM_F_ACK | NLM_F_REQUEST, &message)?;
    match send_netlink_req_and_wait_ack(request) {
        Ok(()) => Ok(Some(())),
        Err(Error::IOError(ref e))
            if e.raw_os_error() == Some(libc::ESRCH) || e.raw_os_error() == Some(libc::ENOENT) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
#[async_trait::async_trait]
impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError> {
        let v4 = match route.destination {
            cidr::IpCidr::V4(v4) => v4,
            cidr::IpCidr::V6(_) => unimplemented!("ipv6 route is not supported yet"),
        };
        let ifindex = route.interface.ifindex;
        let metric = route.metric;
        let route_clone = route.clone();

        tokio::task::spawn_blocking(move || add_ipv4_route(ifindex, v4, metric))
            .await
            .map_err(|e| RouteError::Unknown(e.into()))?
            .map(|res| res.map(|_| route_clone))
            .map_err(|e| RouteError::Failed(e.into()))
    }

    async fn remove(&mut self, route: &Route) -> Result<Option<()>, RouteError> {
        let v4 = match route.destination {
            cidr::IpCidr::V4(v4) => v4,
            cidr::IpCidr::V6(_) => unimplemented!("ipv6 route is not supported yet"),
        };
        let ifindex = route.interface.ifindex;

        tokio::task::spawn_blocking(move || remove_ipv4_route(ifindex, v4))
            .await
            .map_err(|e| RouteError::Unknown(e.into()))?
            .map_err(|e| RouteError::Failed(e.into()))
    }
}
