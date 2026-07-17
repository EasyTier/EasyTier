use serde::{Deserialize, Serialize};

pub mod cidr_monitor;
pub(crate) mod cidr_table;
#[cfg(feature = "proxy-packet")]
pub(crate) mod proxy_acl;
#[cfg(feature = "proxy-packet")]
pub mod runtime;
#[cfg(feature = "proxy-packet")]
pub(crate) mod service;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRuntimeConfig {
    pub enable_exit_node: bool,
    pub no_tun: bool,
    pub forward_by_system: bool,
    pub force_smoltcp: bool,
    pub icmp_failure_is_fatal: bool,
    pub udp_response_ipv4_mtu: usize,
}

impl ProxyRuntimeConfig {
    pub fn should_start(self, has_proxy_networks: bool) -> bool {
        if !has_proxy_networks && !self.enable_exit_node && !self.no_tun {
            return false;
        }

        !self.forward_by_system || self.no_tun
    }
}

impl Default for ProxyRuntimeConfig {
    fn default() -> Self {
        Self {
            enable_exit_node: false,
            no_tun: false,
            forward_by_system: false,
            force_smoltcp: false,
            icmp_failure_is_fatal: false,
            udp_response_ipv4_mtu: 1280,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyRuntimeConfig;

    #[test]
    fn proxy_startup_policy_preserves_runtime_modes() {
        assert!(!ProxyRuntimeConfig::default().should_start(false));
        assert!(ProxyRuntimeConfig::default().should_start(true));
        assert!(
            ProxyRuntimeConfig {
                enable_exit_node: true,
                ..Default::default()
            }
            .should_start(false)
        );
        assert!(
            ProxyRuntimeConfig {
                no_tun: true,
                ..Default::default()
            }
            .should_start(false)
        );
    }

    #[test]
    fn proxy_startup_policy_preserves_system_forwarding_rules() {
        assert!(
            !ProxyRuntimeConfig {
                forward_by_system: true,
                ..Default::default()
            }
            .should_start(true)
        );
        assert!(
            !ProxyRuntimeConfig {
                enable_exit_node: true,
                forward_by_system: true,
                ..Default::default()
            }
            .should_start(false)
        );
        assert!(
            ProxyRuntimeConfig {
                no_tun: true,
                forward_by_system: true,
                ..Default::default()
            }
            .should_start(false)
        );
    }

    #[test]
    fn proxy_runtime_defaults_preserve_udp_mtu() {
        assert_eq!(ProxyRuntimeConfig::default().udp_response_ipv4_mtu, 1280);
    }
}
