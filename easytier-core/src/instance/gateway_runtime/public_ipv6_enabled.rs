use std::sync::Arc;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    peers::public_ipv6::{
        CorePublicIpv6Runtime,
        provider::{PublicIpv6ProviderPlatform, PublicIpv6ProviderService},
    },
};

pub(in crate::instance) struct PublicIpv6ProviderRuntime {
    service: Option<Arc<PublicIpv6ProviderService>>,
    runtime_config: CoreRuntimeConfigStore,
}

impl PublicIpv6ProviderRuntime {
    pub(in crate::instance) fn new(
        host: Option<Arc<dyn PublicIpv6ProviderPlatform>>,
        runtime_config: CoreRuntimeConfigStore,
        public_ipv6: Arc<CorePublicIpv6Runtime>,
    ) -> Self {
        let service = host
            .map(|host| PublicIpv6ProviderService::new(host, runtime_config.clone(), public_ipv6));
        Self {
            service,
            runtime_config,
        }
    }

    pub(in crate::instance) async fn validate_before_start(&self) -> anyhow::Result<()> {
        let config = self.runtime_config.snapshot().services.public_ipv6_provider;
        config.validate().map_err(anyhow::Error::new)?;
        if config.provider_enabled && self.service.is_none() {
            anyhow::bail!("public IPv6 provider is enabled but no host adapter was provided");
        }
        if let Some(service) = &self.service {
            service.apply_config().await;
        }
        Ok(())
    }

    pub(in crate::instance) async fn start(&self) {
        if let Some(service) = &self.service {
            service.start().await;
        }
    }

    pub(in crate::instance) async fn stop(&self) {
        if let Some(service) = &self.service {
            service.stop().await;
        }
    }

    pub(in crate::instance) async fn reconcile(&self) -> bool {
        let Some(service) = &self.service else {
            return false;
        };
        let applied = service.apply_config().await;
        service.start().await;
        applied
    }
}
