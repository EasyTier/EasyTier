pub(crate) mod composition;
pub(crate) mod config;
pub mod dns_server;
pub(crate) mod host;
#[allow(clippy::module_inception)]
pub mod instance;
pub(crate) mod management;
pub(crate) mod udp_hole_punch;

pub(crate) mod listeners;

pub(crate) mod public_ipv6_provider;

pub(crate) mod proxy_cidrs_monitor;

#[cfg(feature = "tun")]
pub mod virtual_nic;

#[cfg(any(all(windows, feature = "tun"), test))]
pub(crate) mod windows_udp_broadcast;
