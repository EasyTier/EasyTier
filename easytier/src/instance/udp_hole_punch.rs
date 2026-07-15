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
