use std::sync::Arc;

use easytier_core::{
    config::peers::PublicIpv6ProviderConfig,
    peers::public_ipv6::provider::{
        PublicIpv6NdpDesired, PublicIpv6PlatformError, PublicIpv6PlatformObservation,
        PublicIpv6ProviderPlatform,
    },
};

use super::wait_for_public_ipv6_provider_reconcile_event;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};

pub(super) struct RuntimePublicIpv6ProviderPlatform {
    global_ctx: std::sync::Weak<crate::common::global_ctx::GlobalCtx>,
    event_receiver: tokio::sync::Mutex<tokio::sync::broadcast::Receiver<GlobalCtxEvent>>,
}

impl RuntimePublicIpv6ProviderPlatform {
    pub(super) fn new(global_ctx: &ArcGlobalCtx) -> Arc<Self> {
        Arc::new(Self {
            global_ctx: Arc::downgrade(global_ctx),
            event_receiver: tokio::sync::Mutex::new(global_ctx.subscribe()),
        })
    }
}

#[async_trait::async_trait]
impl PublicIpv6ProviderPlatform for RuntimePublicIpv6ProviderPlatform {
    fn inspect(
        &self,
        config: PublicIpv6ProviderConfig,
    ) -> Result<PublicIpv6PlatformObservation, PublicIpv6PlatformError> {
        let Some(global_ctx) = self.global_ctx.upgrade() else {
            return Err(PublicIpv6PlatformError::Unavailable);
        };
        let _ = (global_ctx, config);
        Ok(PublicIpv6PlatformObservation::default())
    }

    fn sync_ndp(
        &self,
        desired: Option<PublicIpv6NdpDesired>,
    ) -> Result<(), PublicIpv6PlatformError> {
        let _ = desired;
        Ok(())
    }

    async fn wait_for_change(&self) -> bool {
        let mut event_receiver = self.event_receiver.lock().await;
        wait_for_public_ipv6_provider_reconcile_event(&mut event_receiver).await
    }
}

pub(crate) fn runtime_public_ipv6_provider_platform(
    global_ctx: &ArcGlobalCtx,
) -> Arc<dyn PublicIpv6ProviderPlatform> {
    RuntimePublicIpv6ProviderPlatform::new(global_ctx)
}

#[cfg(test)]
mod tests {
    use easytier_core::config::peers::PublicIpv6ProviderConfig;

    #[test]
    fn public_ipv6_provider_platform_check_reports_linux_only() {
        let err = PublicIpv6ProviderConfig {
            provider_enabled: true,
            configured_prefix: None,
            provider_supported: false,
        }
        .validate()
        .unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("Linux"), "{msg}");
        assert!(msg.contains("ipv6-public-addr-auto"), "{msg}");
    }
}
