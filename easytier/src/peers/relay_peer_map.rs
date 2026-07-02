use std::sync::Arc;

pub use easytier_core::peers::relay_peer_map::{RelayPeerMap, RelayPeerState, RelayRouteTransport};

use crate::{
    common::{PeerId, error::Error, global_ctx::ArcGlobalCtx},
    peers::{
        foreign_network_client::ForeignNetworkClient, peer_map::PeerMap,
        peer_session::PeerSessionStore, route_trait::NextHopPolicy,
    },
    proto::peer_rpc::RoutePeerInfo,
    tunnel::packet_def::ZCPacket,
};

struct RuntimeRelayRouteTransport {
    peer_map: Arc<PeerMap>,
    foreign_network_client: Option<Arc<ForeignNetworkClient>>,
}

fn core_error_from_runtime(err: Error) -> easytier_core::peers::error::Error {
    match err {
        Error::WaitRespError(msg) => easytier_core::peers::error::Error::WaitRespError(msg),
        Error::SecretKeyError(msg) => easytier_core::peers::error::Error::SecretKeyError(msg),
        Error::PeerNoConnectionError(peer_id) => {
            easytier_core::peers::error::Error::PeerNoConnectionError(peer_id)
        }
        Error::RouteError(msg) => easytier_core::peers::error::Error::RouteError(msg),
        Error::NotFound => easytier_core::peers::error::Error::NotFound,
        Error::TunnelError(err) => easytier_core::peers::error::Error::Tunnel(err),
        err => easytier_core::peers::error::Error::Other(anyhow::anyhow!(err)),
    }
}

#[async_trait::async_trait]
impl RelayRouteTransport for RuntimeRelayRouteTransport {
    async fn get_route_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        self.peer_map.get_route_peer_info(peer_id).await
    }

    async fn send_msg_to_next_hop(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), easytier_core::peers::error::Error> {
        let Some(next_hop) = self.peer_map.get_gateway_peer_id(dst_peer_id, policy).await else {
            return Err(easytier_core::peers::error::Error::RouteError(Some(
                format!("next hop not found in route for peer {dst_peer_id:?}"),
            )));
        };
        if self.peer_map.has_peer(next_hop) {
            self.peer_map
                .send_msg_directly(msg, next_hop)
                .await
                .map_err(core_error_from_runtime)
        } else if let Some(foreign_network_client) = &self.foreign_network_client {
            foreign_network_client
                .send_msg(msg, next_hop)
                .await
                .map_err(core_error_from_runtime)
        } else {
            Err(easytier_core::peers::error::Error::RouteError(Some(
                format!("next hop not found in direct peer map: {next_hop:?}"),
            )))
        }
    }
}

pub(crate) fn new_relay_peer_map(
    peer_map: Arc<PeerMap>,
    foreign_network_client: Option<Arc<ForeignNetworkClient>>,
    global_ctx: ArcGlobalCtx,
    my_peer_id: PeerId,
    peer_session_store: Arc<PeerSessionStore>,
) -> Arc<RelayPeerMap> {
    RelayPeerMap::new(
        Arc::new(RuntimeRelayRouteTransport {
            peer_map,
            foreign_network_client,
        }),
        global_ctx,
        my_peer_id,
        peer_session_store,
    )
}
