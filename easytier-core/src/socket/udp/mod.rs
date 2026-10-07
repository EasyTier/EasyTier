mod layer;
mod listener;
mod packet;
mod session;
mod virtual_socket;

#[cfg(test)]
mod tests;

const UDP_SESSION_RESEND_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
const UDP_SESSION_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
// Shorter queues bound retained datagrams while preserving the ring's control reserve.
const UDP_SESSION_QUEUE_CAPACITY: usize = if cfg!(feature = "low-memory") {
    32
} else {
    128
};

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
    MAX_UDP_DATAGRAM_SIZE, MAX_UDP_SESSION_DATAGRAM_SIZE, NoopUdpSessionStunResponder,
    PreferredIpv6Source, UdpBindOptions, UdpSessionStunResponder, UdpSocketDatagram,
    UdpSocketPurpose, UdpSocketRecvMeta, UdpSocketSendMeta, VirtualUdpSocket,
    VirtualUdpSocketFactory, send_v4_hole_punch_control_packet, send_v6_hole_punch_control_packet,
};

#[cfg(test)]
mod queue_tests {
    use futures::{SinkExt as _, StreamExt as _};

    use super::{UDP_SESSION_QUEUE_CAPACITY, session::create_udp_session_rings};
    use crate::{packet::ZCPacket, socket::udp::session::UdpSessionOutbound};

    #[test]
    fn session_capacity_matches_memory_profile() {
        assert_eq!(
            UDP_SESSION_QUEUE_CAPACITY,
            if cfg!(feature = "low-memory") {
                32
            } else {
                128
            }
        );
        assert!(UDP_SESSION_QUEUE_CAPACITY >= 8);
    }

    #[tokio::test]
    async fn session_outbound_queue_waits_for_capacity_without_losing_packets() {
        let mut rings = create_udp_session_rings();
        for _ in 0..UDP_SESSION_QUEUE_CAPACITY {
            let packet = UdpSessionOutbound::TunnelPacket(ZCPacket::new_with_payload(b"queued"));
            assert!(rings.session_send_tx.force_send(packet).is_ok());
        }
        let mut pending = Box::pin(rings.session_send_tx.send(UdpSessionOutbound::TunnelPacket(
            ZCPacket::new_with_payload(b"after-capacity"),
        )));
        assert!(futures::poll!(&mut pending).is_pending());
        assert!(matches!(
            rings.session_send_rx.next().await,
            Some(Ok(UdpSessionOutbound::TunnelPacket(packet))) if packet.payload() == b"queued"
        ));
        pending.await.unwrap();

        for _ in 1..UDP_SESSION_QUEUE_CAPACITY {
            assert!(matches!(
                rings.session_send_rx.next().await,
                Some(Ok(UdpSessionOutbound::TunnelPacket(packet))) if packet.payload() == b"queued"
            ));
        }
        assert!(matches!(
            rings.session_send_rx.next().await,
            Some(Ok(UdpSessionOutbound::TunnelPacket(packet))) if packet.payload() == b"after-capacity"
        ));
    }
}
