use std::sync::Arc;

pub use easytier_core::peers::relay_peer_map::{RelayPeerMap, RelayPeerState, RelayRouteTransport};

use crate::{
    common::{PeerId, global_ctx::ArcGlobalCtx},
    peers::{foreign_network_client::ForeignNetworkClient, peer_map::PeerMap},
};
use easytier_core::peers::peer_session::PeerSessionStore;

pub(crate) fn new_relay_peer_map(
    peer_map: Arc<PeerMap>,
    foreign_network_client: Option<Arc<ForeignNetworkClient>>,
    global_ctx: ArcGlobalCtx,
    my_peer_id: PeerId,
    peer_session_store: Arc<PeerSessionStore>,
) -> Arc<RelayPeerMap> {
    easytier_core::peers::relay_peer_map::new_relay_peer_map(
        peer_map,
        foreign_network_client,
        global_ctx,
        my_peer_id,
        peer_session_store,
    )
}
