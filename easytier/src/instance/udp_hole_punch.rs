//! Native UDP hole-punch platform adapter.
//!
//! Peer selection, signaling, RPC registration, socket/session ownership and
//! lifecycle live in `easytier-core`. Native only supplies OS port mapping.

use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::hole_punch::udp::{
    ActiveUdpPortMapping, UdpPortMappingAttemptError, UdpPortMappingBackend,
    UdpPortMappingEstablished, UdpPortMappingLifecycle, UdpPortMappingPlatform,
};

use crate::common::{
    global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    upnp,
};

struct RuntimeUdpHolePunchPlatform {
    global_ctx: ArcGlobalCtx,
}

#[async_trait]
impl UdpPortMappingPlatform for RuntimeUdpHolePunchPlatform {
    async fn establish_udp_port_mapping(
        &self,
        backend: UdpPortMappingBackend,
        local_listener: &url::Url,
    ) -> Result<Box<dyn ActiveUdpPortMapping>, UdpPortMappingAttemptError> {
        upnp::establish_udp_port_mapping(self.global_ctx.clone(), backend, local_listener.clone())
            .await
    }

    fn spawn_udp_port_mapping_lifecycle(
        &self,
        local_listener: url::Url,
        lifecycle: UdpPortMappingLifecycle,
    ) {
        upnp::spawn_udp_port_mapping_lifecycle(self.global_ctx.clone(), local_listener, lifecycle);
    }

    fn publish_udp_port_mapping_established(&self, event: UdpPortMappingEstablished) {
        self.global_ctx
            .issue_event(GlobalCtxEvent::ListenerPortMappingEstablished {
                local_listener: event.local_listener,
                mapped_listener: event.mapped_listener,
                backend: event.backend.name().to_string(),
            });
    }
}

pub(crate) fn runtime_udp_hole_punch_platform(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn UdpPortMappingPlatform> {
    Arc::new(RuntimeUdpHolePunchPlatform { global_ctx })
}
