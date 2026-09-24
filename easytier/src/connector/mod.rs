pub mod udp_hole_punch {
    #[cfg(test)]
    pub mod tests {
        use crate::peers::peer_manager::PeerManager;
        use crate::proto::common::NatType;
        use std::sync::Arc;

        pub fn replace_stun_info_collector(_peer_mgr: Arc<PeerManager>, _udp_nat_type: NatType) {}
    }
}
