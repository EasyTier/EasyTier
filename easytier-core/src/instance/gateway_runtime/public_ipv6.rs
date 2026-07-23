#[cfg(feature = "public-ipv6-provider")]
#[path = "public_ipv6_enabled.rs"]
mod selected;

#[cfg(not(feature = "public-ipv6-provider"))]
#[path = "public_ipv6_disabled.rs"]
mod selected;

pub(in crate::instance) use selected::PublicIpv6ProviderRuntime;
