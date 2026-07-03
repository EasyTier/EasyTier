mod common;
mod listener;
mod model;
mod packet;
mod policy;
mod runtime;
mod server;
mod socket_array;
mod task;

pub use common::{BLACKLIST_TIMEOUT_SEC, BackOff, UdpNatType, UdpPunchClientMethod};
pub use listener::{
    MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS, ReusableUdpPunchListener, can_reuse_port_mapping_listener,
    can_reuse_public_listener, select_reusable_port_mapping_listener_idx,
    select_reusable_public_listener_idx, should_create_public_listener,
    should_retry_public_listener_selection,
};
pub use model::P2pPolicyFlags;
pub use packet::{HOLE_PUNCH_PACKET_BODY_LEN, hole_punch_packet_tid, new_hole_punch_packet};
pub use policy::{should_background_p2p_with_peer, should_try_p2p_with_peer};
pub use runtime::{
    SelectPunchListener, SelectPunchListenerResponse, SendPunchPacketBothEasySym,
    SendPunchPacketBothEasySymResponse, SendPunchPacketCone, SendPunchPacketEasySym,
    SendPunchPacketHardSym, SendPunchPacketHardSymResponse, UdpHolePunchInbound,
    UdpHolePunchPeerSource, UdpHolePunchRuntime, UdpHolePunchSignalError, UdpHolePunchSignaling,
    UdpHolePunchTunnelSink, UdpPortMappingLease, UdpPunchAcceptor, UdpPunchConnCounter,
    UdpPunchListener, UdpPunchSocket, UdpPunchSocketFactory, UdpResolvedPublicAddr,
};
pub use server::{SelectedUdpPunchListener, UdpHolePunchServerCommon};
pub use server::{send_cone_hole_punch_packets, send_symmetric_hole_punch_packet};
pub use socket_array::{PunchedUdpSocket, UdpSocketArray};
pub use task::{UdpPunchCandidate, UdpPunchTaskInfo, collect_udp_punch_tasks};

const fn udp_packet_len(body_len: u16) -> usize {
    crate::packet::UDP_TUNNEL_HEADER_SIZE + body_len as usize
}
