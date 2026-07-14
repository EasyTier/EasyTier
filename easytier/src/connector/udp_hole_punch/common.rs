//! Native socket-runtime test helpers.

use std::sync::Arc;

use easytier_core::instance::udp_hole_punch::CoreUdpHolePunchRuntime;

use crate::{
    connector::{
        core_instance::runtime_socket_context,
        runtime::{RuntimeConnectorHost, runtime_connector_host},
    },
    peers::peer_manager::PeerManager,
};

use super::runtime_udp_hole_punch_platform;

pub(crate) type RuntimeUdpHolePunchRuntime = CoreUdpHolePunchRuntime<RuntimeConnectorHost>;

pub(crate) fn runtime_udp_hole_punch_runtime(
    peer_manager: &Arc<PeerManager>,
) -> Arc<RuntimeUdpHolePunchRuntime> {
    let global_ctx = peer_manager.get_global_ctx();
    Arc::new(CoreUdpHolePunchRuntime::new(
        runtime_connector_host(global_ctx.clone()),
        peer_manager.core(),
        global_ctx.get_stun_info_collector(),
        runtime_udp_hole_punch_platform(global_ctx.clone()),
        runtime_socket_context(&global_ctx),
    ))
}
