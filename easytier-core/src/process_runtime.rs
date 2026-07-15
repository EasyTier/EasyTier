//! Process-scoped portable resources shared by core instances.

use std::sync::Arc;

use crate::{
    connectivity::{
        manual::{
            ManualConnectorHost, ManualConnectorOptions, ManualEndpointResolver,
            ManualTunnelConnector,
        },
        protocol::ClientProtocolUpgrader,
    },
    socket::{dns::DnsResolver, tcp::VirtualTcpSocketFactory},
    tunnel::ring::RingTunnelRegistry,
};

/// Owns portable resources whose identity is shared across core instances in
/// one host process.
///
/// Native and Go composition roots pass this handle around, but never receive
/// the internal managers it owns.
#[derive(Default)]
pub struct CoreProcessRuntime {
    ring_registry: Arc<RingTunnelRegistry>,
}

impl CoreProcessRuntime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn ring_registry(&self) -> Arc<RingTunnelRegistry> {
        self.ring_registry.clone()
    }

    pub fn manual_connector<H>(
        &self,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        endpoint_resolver: Arc<dyn ManualEndpointResolver>,
        protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
        options: ManualConnectorOptions,
    ) -> ManualTunnelConnector<H>
    where
        H: ManualConnectorHost,
    {
        ManualTunnelConnector::new(host, dns, endpoint_resolver, protocol, options)
            .with_ring_registry(self.ring_registry())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instances_share_ring_state_only_through_the_process_runtime() {
        let runtime = CoreProcessRuntime::new();

        assert!(Arc::ptr_eq(
            &runtime.ring_registry(),
            &runtime.ring_registry()
        ));
        assert!(!Arc::ptr_eq(
            &runtime.ring_registry(),
            &CoreProcessRuntime::new().ring_registry()
        ));
    }
}
