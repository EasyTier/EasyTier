pub mod cidr_monitor;
pub(crate) mod cidr_table;
pub mod icmp_host;
#[cfg(feature = "proxy-packet")]
pub(crate) mod proxy_acl;
#[cfg(feature = "proxy-packet")]
pub(crate) mod service;
#[cfg(feature = "proxy-packet")]
pub mod traits;
#[cfg_attr(not(feature = "wrapped-transport"), allow(dead_code))]
pub mod wrapped_transport;

#[cfg(feature = "proxy-packet")]
pub(crate) mod icmp_proxy_engine;
#[cfg(feature = "proxy-packet")]
pub(crate) mod icmp_proxy_service;
#[cfg(feature = "proxy-packet")]
pub(crate) mod ip_reassembler;
#[cfg(feature = "proxy-packet")]
pub mod tcp_proxy_engine;
#[cfg(feature = "proxy-packet")]
pub(crate) mod tcp_proxy_service;
#[cfg(feature = "proxy-packet")]
pub(crate) mod tcp_socket_connector;
#[cfg(feature = "proxy-packet")]
pub(crate) mod udp_proxy_engine;
#[cfg(feature = "proxy-packet")]
pub(crate) mod udp_proxy_service;
#[cfg(feature = "proxy-packet")]
pub(crate) mod udp_socket_runtime;
#[cfg(feature = "proxy-packet")]
pub(crate) mod wrapped_tcp_proxy;
#[cfg(feature = "proxy-packet")]
pub(crate) mod wrapped_transport_destination;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ProxyHostPolicy {
    pub force_exit_node: bool,
    pub smoltcp_available: bool,
    pub requires_smoltcp: bool,
    pub icmp_failure_is_fatal: bool,
}

impl From<&crate::instance::CoreInstanceHostConfig> for ProxyHostPolicy {
    fn from(host: &crate::instance::CoreInstanceHostConfig) -> Self {
        Self {
            force_exit_node: host.force_exit_node,
            smoltcp_available: host.smoltcp_available,
            requires_smoltcp: host.requires_smoltcp,
            icmp_failure_is_fatal: host.icmp_failure_is_fatal,
        }
    }
}
