//! Native UDP hole-punch platform adapter.
//!
//! Peer selection, signaling, RPC registration, socket/session ownership and
//! lifecycle live in `easytier-core`. Native only supplies OS port mapping.

use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::connectivity::hole_punch::port_mapping::{
    ActiveUdpPortMapping, UdpPortMappingAttemptError, UdpPortMappingBackend,
    UdpPortMappingEstablished, UdpPortMappingEventSink, UdpPortMappingLifecycle,
    UdpPortMappingPlatform,
};

use crate::common::{
    global_ctx::{GlobalCtx, GlobalCtxEvent},
    netns::NetNS,
    upnp,
};

struct RuntimeUdpHolePunchPlatform {
    net_ns: NetNS,
}

#[async_trait]
impl UdpPortMappingPlatform for RuntimeUdpHolePunchPlatform {
    async fn establish_udp_port_mapping(
        &self,
        backend: UdpPortMappingBackend,
        local_listener: &url::Url,
    ) -> Result<Box<dyn ActiveUdpPortMapping>, UdpPortMappingAttemptError> {
        upnp::establish_udp_port_mapping(self.net_ns.clone(), backend, local_listener.clone()).await
    }

    fn spawn_udp_port_mapping_lifecycle(
        &self,
        local_listener: url::Url,
        lifecycle: UdpPortMappingLifecycle,
    ) {
        upnp::spawn_udp_port_mapping_lifecycle(self.net_ns.clone(), local_listener, lifecycle);
    }
}

impl UdpPortMappingEventSink for GlobalCtx {
    fn publish_udp_port_mapping_established(&self, event: UdpPortMappingEstablished) {
        self.issue_event(GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener: event.local_listener,
            mapped_listener: event.mapped_listener,
            backend: event.backend.name().to_string(),
        });
    }
}

pub(crate) fn runtime_udp_hole_punch_platform(net_ns: NetNS) -> Arc<dyn UdpPortMappingPlatform> {
    Arc::new(RuntimeUdpHolePunchPlatform { net_ns })
}
