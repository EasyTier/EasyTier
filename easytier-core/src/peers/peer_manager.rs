use std::sync::Arc;

use crate::{config::PeerId, packet::ZCPacket};

use super::{
    error::Error, foreign_network_client::ForeignNetworkClient, peer_map::PeerMap,
    relay_peer_map::RelayPeerMap, route_trait::NextHopPolicy,
    traffic_metrics::TrafficMetricRecorder,
};

pub fn get_next_hop_policy(is_latency_first: bool) -> NextHopPolicy {
    if is_latency_first {
        NextHopPolicy::LeastCost
    } else {
        NextHopPolicy::LeastHop
    }
}

pub async fn send_msg_internal(
    peers: &PeerMap,
    foreign_network_client: &Arc<ForeignNetworkClient>,
    relay_peer_map: &Arc<RelayPeerMap>,
    direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
    msg: ZCPacket,
    dst_peer_id: PeerId,
) -> Result<(), Error> {
    let policy = get_next_hop_policy(msg.peer_manager_header().unwrap().is_latency_first());
    let is_latency_first = msg.peer_manager_header().unwrap().is_latency_first();
    let packet_type = msg.peer_manager_header().unwrap().packet_type;
    let msg_len = msg.buf_len() as u64;
    let latency_first_gateway = if is_latency_first {
        peers
            .get_gateway_peer_id(dst_peer_id, policy.clone())
            .await
            .filter(|gateway| *gateway != dst_peer_id)
    } else {
        None
    };
    let send_result = if let Some(gateway) = latency_first_gateway
        && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
    {
        relay_peer_map
            .send_msg(msg, dst_peer_id, policy)
            .await
            .map_err(Error::from)
    } else if peers.has_peer(dst_peer_id) {
        peers.send_msg_directly(msg, dst_peer_id).await
    } else if foreign_network_client.has_next_hop(dst_peer_id) {
        foreign_network_client.send_msg(msg, dst_peer_id).await
    } else if let Some(gateway) = peers.get_gateway_peer_id(dst_peer_id, policy.clone()).await {
        if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
            relay_peer_map
                .send_msg(msg, dst_peer_id, policy)
                .await
                .map_err(Error::from)
        } else {
            tracing::warn!(
                ?gateway,
                ?dst_peer_id,
                "cannot send msg to peer through gateway"
            );
            Err(Error::RouteError(None))
        }
    } else if foreign_network_client.has_next_hop(dst_peer_id) {
        // check foreign network again. so in happy path we can avoid extra check
        foreign_network_client.send_msg(msg, dst_peer_id).await
    } else {
        tracing::debug!(?dst_peer_id, "no gateway for peer");
        Err(Error::RouteError(None))
    };

    if send_result.is_ok()
        && let Some(metrics) = direct_tx_metrics
    {
        metrics.record_tx(dst_peer_id, packet_type, msg_len).await;
    }

    send_result
}
