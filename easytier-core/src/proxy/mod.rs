pub mod cidr_monitor;
pub mod cidr_table;
pub mod proxy_acl;
#[cfg(feature = "proxy-packet")]
pub mod runtime;

#[cfg(feature = "proxy-packet")]
pub mod ip_reassembler;
#[cfg(feature = "proxy-smoltcp-stack")]
pub mod smoltcp_stack;
#[cfg(feature = "proxy-packet")]
pub mod tcp_proxy_engine;
#[cfg(feature = "proxy-packet")]
pub mod tcp_proxy_service;
#[cfg(feature = "proxy-smoltcp-stack")]
pub mod tokio_smoltcp;
#[cfg(feature = "proxy-packet")]
pub mod udp_proxy_engine;
#[cfg(feature = "proxy-packet")]
pub mod udp_proxy_service;
#[cfg(feature = "proxy-packet")]
pub mod wrapped_tcp_proxy;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyStartupContext {
    pub has_proxy_cidrs: bool,
    pub already_started: bool,
    pub enable_exit_node: bool,
    pub no_tun: bool,
    pub forward_by_system: bool,
}

impl ProxyStartupContext {
    pub fn should_start(self) -> bool {
        if (!self.has_proxy_cidrs || self.already_started) && !self.enable_exit_node && !self.no_tun
        {
            return false;
        }

        !self.forward_by_system || self.no_tun
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyStartupContext;

    #[test]
    fn proxy_startup_policy_preserves_runtime_modes() {
        assert!(!ProxyStartupContext::default().should_start());
        assert!(
            ProxyStartupContext {
                has_proxy_cidrs: true,
                ..Default::default()
            }
            .should_start()
        );
        assert!(
            ProxyStartupContext {
                enable_exit_node: true,
                ..Default::default()
            }
            .should_start()
        );
        assert!(
            ProxyStartupContext {
                no_tun: true,
                ..Default::default()
            }
            .should_start()
        );
    }

    #[test]
    fn proxy_startup_policy_preserves_restart_and_system_forwarding_rules() {
        assert!(
            !ProxyStartupContext {
                has_proxy_cidrs: true,
                already_started: true,
                ..Default::default()
            }
            .should_start()
        );
        assert!(
            !ProxyStartupContext {
                has_proxy_cidrs: true,
                forward_by_system: true,
                ..Default::default()
            }
            .should_start()
        );
        assert!(
            !ProxyStartupContext {
                enable_exit_node: true,
                forward_by_system: true,
                ..Default::default()
            }
            .should_start()
        );
        assert!(
            ProxyStartupContext {
                already_started: true,
                no_tun: true,
                forward_by_system: true,
                ..Default::default()
            }
            .should_start()
        );
    }
}
