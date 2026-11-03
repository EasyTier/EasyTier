//! Native UDP hole-punch platform adapter.
//!
//! Peer selection, signaling, RPC registration, socket/session ownership and
//! lifecycle live in `easytier-core`. Native only supplies OS port mapping.

use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::connectivity::hole_punch::port_mapping::{
    ActiveUdpPortMapping, UdpPortMappingAttemptError, UdpPortMappingBackend,
    UdpPortMappingLifecycle, UdpPortMappingPlatform,
};

use crate::common::{netns::NetNS, upnp};

struct RuntimeUdpHolePunchPlatform {
    netns: NetNS,
}

#[async_trait]
impl UdpPortMappingPlatform for RuntimeUdpHolePunchPlatform {
    async fn establish_udp_port_mapping(
        &self,
        backend: UdpPortMappingBackend,
        local_listener: &url::Url,
    ) -> Result<Box<dyn ActiveUdpPortMapping>, UdpPortMappingAttemptError> {
        upnp::establish_udp_port_mapping(self.netns.clone(), backend, local_listener.clone()).await
    }

    fn spawn_udp_port_mapping_lifecycle(
        &self,
        local_listener: url::Url,
        lifecycle: UdpPortMappingLifecycle,
    ) {
        upnp::spawn_udp_port_mapping_lifecycle(self.netns.clone(), local_listener, lifecycle);
    }
}

pub(crate) fn runtime_udp_hole_punch_platform(netns: NetNS) -> Arc<dyn UdpPortMappingPlatform> {
    Arc::new(RuntimeUdpHolePunchPlatform { netns })
}
