use crate::{
    config::PeerId,
    proto::common::{NatType, PeerFeatureFlag},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct P2pPolicyFlags {
    pub disable_udp_hole_punching: bool,
    pub disable_sym_hole_punching: bool,
    pub lazy_p2p: bool,
    pub disable_p2p: bool,
    pub need_p2p: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPunchCandidate {
    pub peer_id: PeerId,
    pub udp_nat_type: NatType,
    pub feature_flag: Option<PeerFeatureFlag>,
    pub has_direct_connection: bool,
    pub has_recent_traffic: bool,
}
