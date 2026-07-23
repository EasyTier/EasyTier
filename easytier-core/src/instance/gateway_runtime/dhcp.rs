#[cfg(feature = "dhcp-ipv4")]
#[path = "dhcp_enabled.rs"]
mod selected;

#[cfg(not(feature = "dhcp-ipv4"))]
#[path = "dhcp_disabled.rs"]
mod selected;

pub(in crate::instance) use selected::DhcpIpv4Runtime;
