#[cfg(feature = "proxy-cidr-monitor")]
#[path = "proxy_cidr_monitor_enabled.rs"]
mod selected;

#[cfg(not(feature = "proxy-cidr-monitor"))]
#[path = "proxy_cidr_monitor_disabled.rs"]
mod selected;

pub(in crate::instance) use selected::ProxyCidrMonitorRuntime;
