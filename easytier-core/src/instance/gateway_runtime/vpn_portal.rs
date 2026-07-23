#[cfg(feature = "vpn-portal")]
#[path = "vpn_portal_enabled.rs"]
mod selected;

#[cfg(not(feature = "vpn-portal"))]
#[path = "vpn_portal_disabled.rs"]
mod selected;

pub(in crate::instance) use selected::VpnPortalRuntime;
