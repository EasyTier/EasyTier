use easytier_core::gateway::dhcp::{DhcpAddresses, DhcpApplyOutcome, DhcpApplyPermit, DhcpHost};

#[cfg(feature = "tun")]
use super::tun_common::NativeDhcpHost;
#[cfg(not(feature = "tun"))]
use super::tun_runtime::NativeDhcpHost;
use crate::common::global_ctx::GlobalCtxEvent;

impl NativeDhcpHost {
    pub(super) fn current(&self) -> DhcpAddresses {
        DhcpAddresses {
            ipv4: self
                .global_ctx
                .config
                .get_dhcp()
                .then(|| self.global_ctx.get_ipv4())
                .flatten(),
            ipv6: self
                .global_ctx
                .config
                .get_dhcpv6()
                .then(|| self.global_ctx.get_ipv6())
                .flatten(),
        }
    }

    #[cfg(all(feature = "tun", not(mobile)))]
    pub(super) fn with_static_addresses(&self, mut addresses: DhcpAddresses) -> DhcpAddresses {
        if !self.global_ctx.config.get_dhcp() {
            addresses.ipv4 = self.global_ctx.config.get_ipv4();
        }
        if !self.global_ctx.config.get_dhcpv6() {
            addresses.ipv6 = self.global_ctx.config.get_ipv6();
        }
        addresses
    }

    pub(super) fn set_addresses(&self, addresses: DhcpAddresses) {
        // A static configuration patch uses a different operation lock. Never
        // write a previously read static address back over such a patch.
        if self.global_ctx.config.get_dhcp() {
            self.global_ctx.set_ipv4(addresses.ipv4);
        }
        if self.global_ctx.config.get_dhcpv6() {
            self.global_ctx.set_ipv6(addresses.ipv6);
        }
    }

    pub(super) fn ensure_open(&self) -> anyhow::Result<()> {
        if self.cancel.is_cancelled() {
            anyhow::bail!("instance is closing; DHCP update cancelled");
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DhcpHost for NativeDhcpHost {
    fn take_interface_closed(&self) -> bool {
        self.take_closed()
    }

    async fn apply_dhcp(&self, next: DhcpAddresses) -> DhcpApplyOutcome {
        let permit = self.operation.clone().lock_owned().await;
        let result = self.apply(next).await;
        let outcome = match result {
            Ok(()) => DhcpApplyOutcome::applied(self.current()),
            Err(error) => DhcpApplyOutcome::failed(self.current(), error),
        };
        outcome.with_permit(DhcpApplyPermit::new(permit))
    }

    fn publish_dhcp(&self, previous: DhcpAddresses, actual: DhcpAddresses) {
        if self.global_ctx.config.get_dhcp() && previous.ipv4 != actual.ipv4 {
            self.global_ctx.issue_event(if actual.ipv4.is_none() {
                GlobalCtxEvent::DhcpIpv4Conflicted(previous.ipv4)
            } else {
                GlobalCtxEvent::DhcpIpv4Changed(previous.ipv4, actual.ipv4)
            });
        }
        if self.global_ctx.config.get_dhcpv6() && previous.ipv6 != actual.ipv6 {
            self.global_ctx.issue_event(if actual.ipv6.is_none() {
                GlobalCtxEvent::DhcpIpv6Conflicted(previous.ipv6)
            } else {
                GlobalCtxEvent::DhcpIpv6Changed(previous.ipv6, actual.ipv6)
            });
        }
    }
}
