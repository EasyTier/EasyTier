use std::sync::Arc;

use easytier_core::hole_punch::udp::{
    SendPunchPacketBothEasySym, UdpBothEasySymPunchClient, UdpBothEasySymPunchServer,
    UdpHolePunchClientError, UdpHolePunchServerCommon,
};

use crate::{
    common::PeerId,
    connector::udp_hole_punch::common::{
        RuntimeUdpHolePunchRuntime, RuntimeUdpHolePunchTunnelSink,
    },
    connector::udp_hole_punch::{handle_signal_result, signaling::PeerRpcUdpHolePunchSignaling},
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse},
        rpc_types,
    },
    tunnel::Tunnel,
};

use super::common::UdpNatType;

type CoreBothEasySymServer =
    UdpBothEasySymPunchServer<RuntimeUdpHolePunchRuntime, RuntimeUdpHolePunchTunnelSink>;
type CoreServerCommon =
    UdpHolePunchServerCommon<RuntimeUdpHolePunchRuntime, RuntimeUdpHolePunchTunnelSink>;

pub(crate) struct PunchBothEasySymHoleServer {
    core_server: CoreBothEasySymServer,
}

impl PunchBothEasySymHoleServer {
    pub(crate) fn new(common: Arc<CoreServerCommon>) -> Self {
        Self {
            core_server: UdpBothEasySymPunchServer::new(common),
        }
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self), ret, err)]
    pub(crate) async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySymRequest,
    ) -> Result<SendPunchPacketBothEasySymResponse, rpc_types::error::Error> {
        let public_ips = request
            .public_ip
            .ok_or(anyhow::anyhow!("public_ip is required"))?;

        let response = self
            .core_server
            .send_punch_packet_both_easy_sym(SendPunchPacketBothEasySym {
                transaction_id: request.transaction_id,
                public_ip: public_ips.into(),
                dst_port_num: request.dst_port_num,
                udp_socket_count: request.udp_socket_count,
                wait_time_ms: request.wait_time_ms,
            })
            .await?;

        Ok(SendPunchPacketBothEasySymResponse {
            is_busy: response.is_busy,
            base_mapped_addr: response.base_mapped_addr.map(Into::into),
        })
    }
}

pub(crate) struct PunchBothEasySymHoleClient {
    core_client:
        UdpBothEasySymPunchClient<RuntimeUdpHolePunchRuntime, PeerRpcUdpHolePunchSignaling>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl std::fmt::Debug for PunchBothEasySymHoleClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchBothEasySymHoleClient")
            .finish_non_exhaustive()
    }
}

impl PunchBothEasySymHoleClient {
    pub(crate) fn new(
        peer_mgr: Arc<PeerManager>,
        blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    ) -> Self {
        let runtime = Arc::new(RuntimeUdpHolePunchRuntime::new(peer_mgr.get_global_ctx()));
        let signaling = Arc::new(PeerRpcUdpHolePunchSignaling::new(peer_mgr));
        Self {
            core_client: UdpBothEasySymPunchClient::new(runtime, signaling),
            blacklist,
        }
    }

    #[tracing::instrument(ret)]
    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        my_nat_info: UdpNatType,
        peer_nat_info: UdpNatType,
        is_busy: &mut bool,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

        match self
            .core_client
            .do_hole_punching(dst_peer_id, my_nat_info, peer_nat_info, is_busy)
            .await
        {
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
    use std::{
        sync::{Arc, atomic::AtomicU32},
        time::Duration,
    };

    use tokio::net::UdpSocket;

    use crate::connector::udp_hole_punch::RUN_TESTING;
    use crate::{
        connector::udp_hole_punch::{
            UdpHolePunchConnector, tests::create_mock_peer_manager_with_mock_stun,
        },
        peers::tests::{connect_peer_manager, wait_route_appear},
        proto::common::NatType,
        tunnel::common::tests::wait_for_condition,
    };
    use easytier_core::hole_punch::udp::apply_peer_easy_sym_port_offset;

    #[test]
    fn easy_sym_remote_port_offset_preserves_old_proto_cast_semantics() {
        assert_eq!(apply_peer_easy_sym_port_offset(65530, true), 14);
        assert_eq!(apply_peer_easy_sym_port_offset(10, false), 0);
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(hole_punch)]
    async fn hole_punching_easy_sym(#[values("true", "false")] is_inc: bool) {
        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(if is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(if !is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        // 144 + DST_PORT_OFFSET = 164
        let udp1 = Arc::new(UdpSocket::bind("0.0.0.0:40164").await.unwrap());
        // 144 - DST_PORT_OFFSET = 124
        let udp2 = Arc::new(UdpSocket::bind("0.0.0.0:40124").await.unwrap());
        let udps = [udp1, udp2];

        let counter = Arc::new(AtomicU32::new(0));

        // all these sockets should receive hole punching packet
        for udp in udps.iter().map(Arc::clone) {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (len, addr) = udp.recv_from(&mut buf).await.unwrap();
                println!(
                    "got predictable punch packet, {:?} {:?} {:?}",
                    len,
                    addr,
                    udp.local_addr()
                );
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
        }

        hole_punching_a.client.run_immediately().await;
        let udp_len = udps.len();
        wait_for_condition(
            || async { counter.load(std::sync::atomic::Ordering::Relaxed) == udp_len as u32 },
            Duration::from_secs(30),
        )
        .await;
    }
}
