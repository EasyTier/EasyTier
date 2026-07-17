use std::{sync::Arc, time::Duration};

use crate::{
    connectivity::{
        direct::DirectConnectorHost, hole_punch::tcp::TcpHolePunchHost, stun::StunSocketMapper,
    },
    peers::peer_conn::PeerConnId,
    socket::udp::VirtualUdpSocketFactory,
};

use super::{CoreHostAdapters, CoreInstance, PeerRelaySessionSnapshot};

impl<H> CoreHostAdapters<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    #[doc(hidden)]
    pub fn replace_stun_provider(
        &mut self,
        provider: Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>>,
    ) {
        self.stun_override = Some(provider);
    }
}

impl<H> CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    #[doc(hidden)]
    pub async fn connected_peers(&self) -> Vec<crate::config::PeerId> {
        self.peer_manager
            .get_peer_map()
            .list_peers_with_conn()
            .await
    }

    #[doc(hidden)]
    pub async fn admit_client_tunnel_for_test(
        &self,
        tunnel: Box<dyn crate::tunnel::Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(crate::config::PeerId, PeerConnId), crate::peers::error::Error> {
        self.peer_manager
            .add_client_tunnel(tunnel, is_directly_connected)
            .await
    }

    #[doc(hidden)]
    pub async fn relay_route_has_static_key_for_test(
        &self,
        peer_id: crate::config::PeerId,
    ) -> bool {
        self.peer_manager
            .get_peer_map()
            .get_route_peer_info(peer_id)
            .await
            .is_some_and(|info| !info.noise_static_pubkey.is_empty())
    }

    #[doc(hidden)]
    pub fn relay_session_snapshot_for_test(
        &self,
        peer_id: crate::config::PeerId,
    ) -> PeerRelaySessionSnapshot {
        let relay = self.peer_manager.get_relay_peer_map();
        PeerRelaySessionSnapshot {
            has_state: relay.has_state(peer_id),
            has_session: relay.has_session_without_touch(peer_id),
        }
    }

    #[doc(hidden)]
    pub fn evict_idle_relay_sessions_for_test(&self, idle: Duration) {
        self.peer_manager
            .get_relay_peer_map()
            .evict_idle_sessions(idle);
    }

    #[doc(hidden)]
    pub fn evict_unused_peer_sessions_for_test(&self, idle: Duration) {
        self.peer_manager
            .get_peer_session_store()
            .evict_unused_sessions_idle(idle);
    }
}
