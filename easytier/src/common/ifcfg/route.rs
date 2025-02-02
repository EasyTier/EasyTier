use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Network address of the destination. `0.0.0.0` with a prefix of `0` is considered a default route.
    pub destination: IpAddr,

    /// Length of network prefix in the destination address.
    pub prefix: u8,

    /// The address of the next hop of this route.
    ///
    /// On macOS, this must be `Some` if ifindex is `None`
    pub gateway: Option<IpAddr>,

    /// The index of the local interface through which the next hop of this route may be reached.
    ///
    /// On macOS, this must be `Some` if gateway is `None`
    pub ifindex: Option<u32>,

    #[cfg(target_os = "linux")]
    /// The routing table this route belongs to.
    pub table: u8,

    /// Network address of the source.
    #[cfg(target_os = "linux")]
    pub source: Option<IpAddr>,

    /// Prefix length of the source address.
    #[cfg(target_os = "linux")]
    pub source_prefix: u8,

    /// Source address hint. Does not influence routing.
    #[cfg(target_os = "linux")]
    pub source_hint: Option<IpAddr>,

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    /// The route metric offset value for this route.
    pub metric: Option<u32>,

    #[cfg(target_os = "windows")]
    /// Luid of the local interface through which the next hop of this route may be reached.
    ///
    /// If luid is specified, ifindex is optional.
    pub luid: Option<u64>,
}

impl Route {
    /// Create a route that matches a given destination network.
    ///
    /// Either the gateway or interface should be set before attempting to add to a routing table.
    pub fn new(destination: IpAddr, prefix: u8) -> Self {
        Self {
            destination,
            prefix,
            gateway: None,
            ifindex: None,
            #[cfg(target_os = "linux")]
            // default to main table
            table: 254,
            #[cfg(target_os = "linux")]
            source: None,
            #[cfg(target_os = "linux")]
            source_prefix: 0,
            #[cfg(target_os = "linux")]
            source_hint: None,
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            metric: None,
            #[cfg(target_os = "windows")]
            luid: None,
        }
    }

    /// Set the next next hop gateway for this route.
    pub fn with_gateway(mut self, gateway: IpAddr) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Set the index of the local interface through which the next hop of this route should be reached.
    pub fn with_ifindex(mut self, ifindex: u32) -> Self {
        self.ifindex = Some(ifindex);
        self
    }

    /// Set table the route will be installed in.
    #[cfg(target_os = "linux")]
    pub fn with_table(mut self, table: u8) -> Self {
        self.table = table;
        self
    }

    /// Set source.
    #[cfg(target_os = "linux")]
    pub fn with_source(mut self, source: IpAddr, prefix: u8) -> Self {
        self.source = Some(source);
        self.source_prefix = prefix;
        self
    }

    /// Set source hint.
    #[cfg(target_os = "linux")]
    pub fn with_source_hint(mut self, hint: IpAddr) -> Self {
        self.source_hint = Some(hint);
        self
    }

    /// Set route metric.
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Set luid of the local interface through which the next hop of this route should be reached.
    #[cfg(target_os = "windows")]
    pub fn with_luid(mut self, luid: u64) -> Self {
        self.luid = Some(luid);
        self
    }

    /// Get the netmask covering the network portion of the destination address.
    pub fn mask(&self) -> IpAddr {
        match self.destination {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(
                u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0),
            )),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(
                u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0),
            )),
        }
    }
}
