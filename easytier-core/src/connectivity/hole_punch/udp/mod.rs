mod binding;
mod client;
mod common;
mod connector;
mod packet;
mod punch_listener;
mod rpc;
mod runtime;
mod server;
mod socket_array;
mod task;

pub(crate) use binding::CoreUdpHolePunchService;
pub(crate) use client::{
    UdpBothEasySymPunchClient, UdpHolePunchClientError, UdpSymToConePunchClient, punch_cone_to_cone,
};
pub(crate) use common::{BLACKLIST_TIMEOUT_SEC, UdpNatType, UdpPunchClientMethod};
pub(crate) use connector::{UdpHolePunchConnector, UdpSymPunchLock};
pub(crate) use packet::{HOLE_PUNCH_PACKET_BODY_LEN, hole_punch_packet_tid, new_hole_punch_packet};
pub(crate) use punch_listener::{
    MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS, ReusableUdpPunchListener, can_reuse_port_mapping_listener,
    can_reuse_public_listener, select_reusable_port_mapping_listener_idx,
    select_reusable_public_listener_idx, should_create_public_listener,
    should_retry_public_listener_selection,
};
pub(crate) use runtime::{
    ProtocolUdpHolePunchTransportSink, SelectPunchListener, SelectPunchListenerResponse,
    SendPunchPacketBothEasySym, SendPunchPacketBothEasySymResponse, SendPunchPacketCone,
    SendPunchPacketEasySym, SendPunchPacketHardSym, SendPunchPacketHardSymResponse,
    UdpHolePunchInbound, UdpHolePunchPeerSource, UdpHolePunchRuntime, UdpHolePunchSignalError,
    UdpHolePunchSignaling, UdpHolePunchTransportSink, UdpHolePunchTunnelSink, UdpPunchAcceptor,
    UdpPunchConnCounter, UdpPunchListener, UdpPunchSocket, UdpResolvedPublicAddr,
    should_blacklist_signal_error,
};
pub(crate) use server::UdpHolePunchServer;
pub(crate) use socket_array::UdpSocketArray;
pub(crate) use task::{UdpPunchCandidate, UdpPunchTaskInfo, collect_udp_punch_tasks};

const fn udp_packet_len(body_len: u16) -> usize {
    crate::packet::UDP_TUNNEL_HEADER_SIZE + body_len as usize
}
