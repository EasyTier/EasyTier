use std::sync::Arc;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    peers::public_ipv6::{CorePublicIpv6Runtime, provider::PublicIpv6ProviderPlatform},
};

pub(in crate::instance) struct PublicIpv6ProviderRuntime;

impl PublicIpv6ProviderRuntime {
    pub(in crate::instance) fn new(
        _host: Option<Arc<dyn PublicIpv6ProviderPlatform>>,
        _runtime_config: CoreRuntimeConfigStore,
        _public_ipv6: Arc<CorePublicIpv6Runtime>,
    ) -> Self {
        Self
    }

    pub(in crate::instance) async fn validate_before_start(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub(in crate::instance) async fn start(&self) {}

    pub(in crate::instance) async fn stop(&self) {}
}
