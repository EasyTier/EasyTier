use std::net::IpAddr;

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
