mod common;
mod model;
mod packet;
mod policy;
mod runtime;
mod socket_array;

pub use common::{BLACKLIST_TIMEOUT_SEC, BackOff, UdpNatType, UdpPunchClientMethod};
pub use model::{P2pPolicyFlags, UdpPunchCandidate};
pub use packet::{HOLE_PUNCH_PACKET_BODY_LEN, hole_punch_packet_tid, new_hole_punch_packet};
pub use policy::{should_background_p2p_with_peer, should_try_p2p_with_peer};
pub use runtime::{
    SelectPunchListener, SelectPunchListenerResponse, SendPunchPacketBothEasySym,
    SendPunchPacketBothEasySymResponse, SendPunchPacketCone, SendPunchPacketEasySym,
    SendPunchPacketHardSym, SendPunchPacketHardSymResponse, UdpHolePunchInbound,
    UdpHolePunchPeerSource, UdpHolePunchRuntime, UdpHolePunchSignalError, UdpHolePunchSignaling,
    UdpHolePunchTunnelSink, UdpPortMappingLease, UdpPunchAcceptor, UdpPunchConnCounter,
    UdpPunchListener, UdpPunchSocket, UdpPunchSocketFactory,
};
pub use socket_array::{PunchedUdpSocket, UdpSocketArray};

const fn udp_packet_len(body_len: u16) -> usize {
    crate::packet::UDP_TUNNEL_HEADER_SIZE + body_len as usize
}
