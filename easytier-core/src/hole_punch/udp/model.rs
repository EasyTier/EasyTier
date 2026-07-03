#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct P2pPolicyFlags {
    pub disable_udp_hole_punching: bool,
    pub disable_sym_hole_punching: bool,
    pub lazy_p2p: bool,
    pub disable_p2p: bool,
    pub need_p2p: bool,
}
