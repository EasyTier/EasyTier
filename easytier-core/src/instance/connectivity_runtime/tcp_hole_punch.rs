#[cfg(feature = "tcp-hole-punch")]
#[path = "tcp_hole_punch_enabled.rs"]
mod selected;

#[cfg(not(feature = "tcp-hole-punch"))]
#[path = "tcp_hole_punch_disabled.rs"]
mod selected;

use std::sync::Arc;

use crate::{
    connectivity::{
        hole_punch::tcp::TcpHolePunchHost, protocol::ClientProtocolUpgrader, stun::StunInfoProvider,
    },
    peers::peer_manager::PeerManagerCore,
    socket::{SocketContext, tcp::VirtualTcpSocketFactory},
};

pub(in crate::instance) use selected::TcpHolePunchRuntime;

#[allow(dead_code)]
pub(in crate::instance) struct TcpHolePunchRuntimeInputs<H>
where
    H: TcpHolePunchHost,
{
    pub(in crate::instance) peer_manager: Arc<PeerManagerCore>,
    pub(in crate::instance) host: Arc<H>,
    pub(in crate::instance) stun: Arc<dyn StunInfoProvider>,
    pub(in crate::instance) socket_context: SocketContext,
    pub(in crate::instance) client_protocol:
        Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
}
