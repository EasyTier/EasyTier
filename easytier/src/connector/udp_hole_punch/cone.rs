use std::sync::Arc;

use easytier_core::hole_punch::udp::{UdpHolePunchClientError, punch_cone_to_cone};

use crate::{
    common::PeerId,
    connector::udp_hole_punch::common::{RuntimeUdpHolePunchRuntime, RuntimeUdpPunchSocket},
    connector::udp_hole_punch::{handle_signal_result, signaling::PeerRpcUdpHolePunchSignaling},
    peers::peer_manager::PeerManager,
    proto::{
        common::Void,
        peer_rpc::SendPunchPacketConeRequest,
        rpc_types::{self, controller::BaseController},
    },
    tunnel::Tunnel,
};

use super::common::PunchHoleServerCommon;

pub(crate) struct PunchConeHoleServer {
    common: Arc<PunchHoleServerCommon>,
}

impl PunchConeHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        Self { common }
    }

    #[tracing::instrument(skip(self), ret, err)]
    pub(crate) async fn send_punch_packet_cone(
        &self,
        _: BaseController,
        request: SendPunchPacketConeRequest,
    ) -> Result<Void, rpc_types::error::Error> {
        let listener_addr = request.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone request missing listener_mapped_addr"
        ))?;
        let listener_addr = std::net::SocketAddr::from(listener_addr);
        let listener = self
            .common
            .find_listener(&listener_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_for_cone failed to find listener"
            ))?;

        let dest_addr = request.dest_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone request missing dest_addr"
        ))?;
        let dest_addr = std::net::SocketAddr::from(dest_addr);
        easytier_core::hole_punch::udp::send_cone_hole_punch_packets(
            Arc::new(RuntimeUdpPunchSocket::new(listener)),
            &easytier_core::hole_punch::udp::SendPunchPacketCone {
                listener_mapped_addr: listener_addr,
                dest_addr,
                transaction_id: request.transaction_id,
                packet_count_per_batch: request.packet_count_per_batch,
                packet_batch_count: request.packet_batch_count,
                packet_interval_ms: request.packet_interval_ms,
            },
        )
        .await
        .map_err(anyhow::Error::from)?;

        Ok(Void::default())
    }
}

pub(crate) struct PunchConeHoleClient {
    peer_mgr: Arc<PeerManager>,
    signaling: PeerRpcUdpHolePunchSignaling,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl PunchConeHoleClient {
    pub(crate) fn new(
        peer_mgr: Arc<PeerManager>,
        blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    ) -> Self {
        Self {
            peer_mgr: peer_mgr.clone(),
            signaling: PeerRpcUdpHolePunchSignaling::new(peer_mgr),
            blacklist,
        }
    }

    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

        let runtime = Arc::new(RuntimeUdpHolePunchRuntime::new(
            self.peer_mgr.get_global_ctx(),
        ));
        let signaling = Arc::new(self.signaling.clone());
        match punch_cone_to_cone(runtime, signaling, dst_peer_id).await {
            Ok(ret) => Ok(ret),
            Err(UdpHolePunchClientError::Signaling(err)) => {
                Err(
                    handle_signal_result::<()>(Err(err), dst_peer_id, &self.blacklist)
                        .unwrap_err()
                        .into(),
                )
            }
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use crate::{
        common::upnp::{
            reset_udp_port_mapping_attempts_for_test, udp_port_mapping_attempts_for_test,
        },
        connector::udp_hole_punch::{
            UdpHolePunchConnector, cone::PunchConeHoleClient,
            tests::create_mock_peer_manager_with_mock_stun,
        },
        peers::tests::{connect_peer_manager, wait_route_appear, wait_route_appear_with_cost},
        proto::common::NatType,
    };

    #[tokio::test]
    async fn hole_punching_cone() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        println!("{:?}", p_a.list_routes().await);

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a.run_as_client().await.unwrap();
        hole_punching_c.run_as_server().await.unwrap();

        hole_punching_a.client.run_immediately().await;

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
        println!("{:?}", p_a.list_routes().await);
    }

    #[tokio::test]
    async fn cone_hole_punch_does_not_create_upnp_mapping_before_listener_rpc_succeeds() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_upnp = false;
        p_a.get_global_ctx().set_flags(flags);

        reset_udp_port_mapping_attempts_for_test();

        let ret = PunchConeHoleClient::new(p_a.clone(), Arc::new(timedmap::TimedMap::new()))
            .do_hole_punching(p_c.my_peer_id())
            .await;

        assert!(ret.is_err());
        assert_eq!(udp_port_mapping_attempts_for_test(), 0);
    }
}
