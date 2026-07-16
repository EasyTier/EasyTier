mod layer;
mod listener;
mod packet;
mod session;
mod virtual_socket;

#[cfg(test)]
mod tests;

const UDP_SESSION_RESEND_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
const UDP_SESSION_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const UDP_SESSION_QUEUE_CAPACITY: usize = 128;

pub use layer::{UdpSessionDialer, UdpSessionLayer};
pub use listener::{UdpSessionAcceptKind, UdpSessionSocketListener, accept_udp_session};
pub use packet::{
    UdpSessionPacketError, extract_dst_addr_from_v4_hole_punch_packet,
    extract_v6_hole_punch_packet, is_stun_packet, new_sack_packet, new_syn_packet,
    new_v4_hole_punch_packet, new_v6_hole_punch_packet, parse_quic_initial_dcid,
    parse_udp_session_datagram,
};
pub use session::{
    UdpSession, UdpSessionConnectError, UdpSessionConnectRequest, UdpSessionConnector,
    UdpSessionKind, UdpSessionLayerControl, UdpSessionListenRequest, UdpSessionListener,
    UdpSessionProtocol, UdpSessionRecvMeta, UdpSessionSocket,
};
pub(crate) use session::{
    UdpSessionCleanup, UdpSessionCodec, UdpSessionDatagram, UdpSessionOutbound,
    UdpSessionTunnelParts,
};
pub use virtual_socket::{
    NoopUdpSessionStunResponder, PreferredIpv6Source, UdpBindOptions, UdpSessionStunResponder,
    UdpSocketPurpose, UdpSocketRecvMeta, UdpSocketSendMeta, VirtualUdpSocket,
    VirtualUdpSocketFactory, send_v4_hole_punch_control_packet, send_v6_hole_punch_control_packet,
};
