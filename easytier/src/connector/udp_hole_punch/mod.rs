//! Native UDP hole-punch platform adapter.
//!
//! Peer selection, signaling, RPC registration, socket/session ownership and
//! lifecycle live in `easytier-core`. Native only supplies OS port mapping.

use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::{
    hole_punch::udp::UdpPortMappingLease, instance::udp_hole_punch::UdpHolePunchPlatform,
};

use crate::common::{global_ctx::ArcGlobalCtx, upnp};

#[cfg(test)]
pub(crate) mod common;

struct RuntimeUdpHolePunchPlatform {
    global_ctx: ArcGlobalCtx,
}

#[async_trait]
impl UdpHolePunchPlatform for RuntimeUdpHolePunchPlatform {
    async fn start_udp_port_mapping(
        &self,
        local_listener: &url::Url,
    ) -> anyhow::Result<Option<Box<dyn UdpPortMappingLease>>> {
        Ok(
            upnp::start_udp_port_mapping(&self.global_ctx, local_listener)
                .await?
                .map(|lease| Box::new(lease) as Box<dyn UdpPortMappingLease>),
        )
    }
}

pub(crate) fn runtime_udp_hole_punch_platform(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn UdpHolePunchPlatform> {
    Arc::new(RuntimeUdpHolePunchPlatform { global_ctx })
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use crate::{
        common::stun::MockStunInfoCollector,
        peers::{peer_manager::PeerManager, tests::create_mock_peer_manager},
        proto::common::NatType,
    };

    pub fn replace_stun_info_collector(peer_manager: Arc<PeerManager>, udp_nat_type: NatType) {
        peer_manager
            .get_global_ctx()
            .replace_stun_info_collector(Box::new(MockStunInfoCollector { udp_nat_type }));
    }

    pub async fn create_mock_peer_manager_with_mock_stun(
        udp_nat_type: NatType,
    ) -> Arc<PeerManager> {
        let peer_manager = create_mock_peer_manager().await;
        let mut flags = peer_manager.get_global_ctx().get_flags();
        flags.disable_upnp = true;
        peer_manager.get_global_ctx().set_flags(flags);
        replace_stun_info_collector(peer_manager.clone(), udp_nat_type);
        peer_manager
    }
}
