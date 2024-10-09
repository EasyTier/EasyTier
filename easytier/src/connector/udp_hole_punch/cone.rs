use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use tokio::net::UdpSocket;

use crate::{
    common::{scoped_task::ScopedTask, stun::StunInfoCollectorTrait, PeerId},
    connector::udp_hole_punch::common::{
        try_connect_with_socket, UdpSocketArray, HOLE_PUNCH_PACKET_BODY_LEN,
    },
    peers::peer_manager::PeerManager,
    proto::{
        common::Void,
        peer_rpc::{
            SelectPunchListenerRequest, SendPunchPacketConeRequest, UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{udp::new_hole_punch_packet, Tunnel},
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
        let dest_ip = dest_addr.ip();
        if dest_ip.is_unspecified() || dest_ip.is_multicast() {
            return Err(anyhow::anyhow!(
                "send_punch_packet_for_cone dest_ip is malformed, {:?}",
                request
            )
            .into());
        }

        for _ in 0..request.packet_batch_count {
            tracing::info!(?request, "sending hole punching packet");

            for _ in 0..request.packet_count_per_batch {
                let udp_packet =
                    new_hole_punch_packet(request.transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
                if let Err(e) = listener.send_to(&udp_packet.into_bytes(), &dest_addr).await {
                    tracing::error!(?e, "failed to send hole punch packet to dest addr");
                }
            }
            tokio::time::sleep(Duration::from_millis(request.packet_interval_ms as u64)).await;
        }

        Ok(Void::default())
    }
}

pub(crate) struct PunchConeHoleClient {
    peer_mgr: Arc<PeerManager>,
}

impl PunchConeHoleClient {
    pub(crate) fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self { peer_mgr }
    }

    #[tracing::instrument(skip(self))]
    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        tracing::info!(?dst_peer_id, "start hole punching");
        let tid = rand::random();

        let global_ctx = self.peer_mgr.get_global_ctx();
        let udp_array = UdpSocketArray::new(1, global_ctx.net_ns.clone());
        let local_socket = {
            let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
            Arc::new(UdpSocket::bind("0.0.0.0:0").await?)
        };

        let local_addr = local_socket
            .local_addr()
            .with_context(|| anyhow::anyhow!("failed to get local port from udp array"))?;
        let local_port = local_addr.port();

        drop(local_socket);
        let local_mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(local_port)
            .await
            .with_context(|| "failed to get udp port mapping")?;

        let local_socket = {
            let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
            Arc::new(UdpSocket::bind(local_addr).await?)
        };

        // client -> server: tell server the mapped port, server will return the mapped address of listening port.
        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let resp = rpc_stub
            .select_punch_listener(
                BaseController::default(),
                SelectPunchListenerRequest { force_new: false },
            )
            .await
            .with_context(|| "failed to select punch listener")?;
        let remote_mapped_addr = resp.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "select_punch_listener response missing listener_mapped_addr"
        ))?;

        tracing::debug!(
            ?local_mapped_addr,
            ?remote_mapped_addr,
            "hole punch got remote listener"
        );

        udp_array.add_new_socket(local_socket).await?;
        udp_array.add_intreast_tid(tid);
        let send_from_local = || async {
            udp_array
                .send_with_all(
                    &new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes(),
                    remote_mapped_addr.clone().into(),
                )
                .await
                .with_context(|| "failed to send hole punch packet from local")
        };

        send_from_local().await?;

        let scoped_punch_task: ScopedTask<()> = tokio::spawn(async move {
            if let Err(e) = rpc_stub
                .send_punch_packet_cone(
                    BaseController {
                        timeout_ms: 4000,
                        ..Default::default()
                    },
                    SendPunchPacketConeRequest {
                        listener_mapped_addr: Some(remote_mapped_addr.into()),
                        dest_addr: Some(local_mapped_addr.into()),
                        transaction_id: tid,
                        packet_count_per_batch: 2,
                        packet_batch_count: 5,
                        packet_interval_ms: 400,
                    },
                )
                .await
            {
                tracing::error!(?e, "failed to call remote send punch packet");
            }
        })
        .into();

        // server: will send some punching resps, total 10 packets.
        // client: use the socket to create UdpTunnel with UdpTunnelConnector
        // NOTICE: UdpTunnelConnector will ignore the punching resp packet sent by remote.
        let mut finish_time: Option<Instant> = None;
        while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
            tokio::time::sleep(Duration::from_millis(200)).await;

            if finish_time.is_none() && (*scoped_punch_task).is_finished() {
                finish_time = Some(Instant::now());
            }

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::debug!("no punched socket found, send some more hole punch packets");
                send_from_local().await?;
                continue;
            };

            tracing::debug!(?socket, ?tid, "punched socket found, try connect with it");

            for _ in 0..2 {
                match try_connect_with_socket(socket.socket.clone(), remote_mapped_addr.into())
                    .await
                {
                    Ok(tunnel) => {
                        tracing::info!(?tunnel, "hole punched");
                        return Ok(Some(tunnel));
                    }
                    Err(e) => {
                        tracing::error!(?e, "failed to connect with socket");
                    }
                }
            }
        }

        return Ok(None);
    }
}

#[cfg(test)]
pub mod tests {

    use crate::{
        connector::udp_hole_punch::{
            tests::create_mock_peer_manager_with_mock_stun, UdpHolePunchConnector,
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
}
