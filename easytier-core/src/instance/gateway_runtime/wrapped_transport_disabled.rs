use crate::instance::CoreInstanceHost;

use super::WrappedTransportRuntimeInputs;

pub(in crate::instance) struct WrappedTransportRuntime;

impl WrappedTransportRuntime {
    pub(in crate::instance) fn new<H>(inputs: WrappedTransportRuntimeInputs<H>) -> Self
    where
        H: CoreInstanceHost,
    {
        let WrappedTransportRuntimeInputs {
            peer_manager: _,
            runtime_config: _,
            engines: _,
            host: _,
            protected_tcp_ports: _,
            running_listeners: _,
            cidr_table: _,
            socket_context: _,
        } = inputs;
        Self
    }

    pub(in crate::instance) fn is_available(&self) -> bool {
        false
    }

    pub(in crate::instance) fn proxy_cloned(
        &self,
    ) -> Option<std::sync::Arc<crate::gateway::proxy::wrapped_transport::WrappedTransportProxyModule>>
    {
        None
    }

    pub(in crate::instance) async fn start(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub(in crate::instance) async fn stop(&self) {}
}
