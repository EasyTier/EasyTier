use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use easytier_core::hole_punch::udp::{UdpBothEasySymPunchClient, UdpHolePunchClientError};
use quanta::Instant;
use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::{PeerId, stun::StunInfoCollectorTrait},
    connector::udp_hole_punch::common::{
        HOLE_PUNCH_PACKET_BODY_LEN, RuntimeUdpHolePunchRuntime, UdpHolePunchListener,
    },
    connector::udp_hole_punch::{handle_signal_result, signaling::PeerRpcUdpHolePunchSignaling},
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse},
        rpc_types,
    },
    tunnel::{Tunnel, udp::new_hole_punch_packet},
};

use super::common::{PunchHoleServerCommon, UdpNatType, UdpSocketArray};

const UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM: usize = 25;
const REMOTE_WAIT_TIME_MS: u64 = 5000;

pub(crate) struct PunchBothEasySymHoleServer {
    common: Arc<PunchHoleServerCommon>,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl PunchBothEasySymHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        Self {
            common,
            task: Mutex::new(None),
        }
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self), ret, err)]
    pub(crate) async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySymRequest,
    ) -> Result<SendPunchPacketBothEasySymResponse, rpc_types::error::Error> {
        tracing::info!("send_punch_packet_both_easy_sym start");
        let busy_resp = Ok(SendPunchPacketBothEasySymResponse {
            is_busy: true,
            ..Default::default()
        });
        let Ok(mut locked_task) = self.task.try_lock() else {
            return busy_resp;
        };
        if locked_task.is_some() && !locked_task.as_ref().unwrap().is_finished() {
            return busy_resp;
        }

        let global_ctx = self.common.get_global_ctx();
        let cur_mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(0)
            .await
            .with_context(|| "failed to get udp port mapping")?;

        tracing::info!("send_punch_packet_hard_sym start");
        let socket_count = request.udp_socket_count as usize;
        let public_ips = request
            .public_ip
            .ok_or(anyhow::anyhow!("public_ip is required"))?;
        let transaction_id = request.transaction_id;

        let udp_array =
            UdpSocketArray::new(socket_count, self.common.get_global_ctx().net_ns.clone());
        udp_array.start().await?;
        udp_array.add_intreast_tid(transaction_id);
        let peer_mgr = self.common.get_peer_mgr();

        let punch_packet =
            new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        let mut punched = vec![];
        let common = self.common.clone();

        let task = tokio::spawn(async move {
            let mut listeners = Vec::new();
            let start_time = Instant::now();
            let wait_time_ms = request.wait_time_ms.min(8000);
            while start_time.elapsed() < Duration::from_millis(wait_time_ms as u64) {
                if let Err(e) = udp_array
                    .send_with_all(
                        &punch_packet,
                        SocketAddr::V4(SocketAddrV4::new(
                            public_ips.into(),
                            request.dst_port_num as u16,
                        )),
                    )
                    .await
                {
                    tracing::error!(?e, "failed to send hole punch packet");
                    break;
                }

                tokio::time::sleep(Duration::from_millis(100)).await;

                if let Some(s) = udp_array.try_fetch_punched_socket(transaction_id) {
                    tracing::info!(?s, ?transaction_id, "got punched socket in both easy sym");
                    assert!(Arc::strong_count(&s.socket) == 1);
                    let Some(port) = s.socket.local_addr().ok().map(|addr| addr.port()) else {
                        tracing::warn!("failed to get local addr from punched socket");
                        continue;
                    };
                    let remote_addr = s.remote_addr;
                    drop(s);

                    let listener =
                        match UdpHolePunchListener::new_ext(peer_mgr.clone(), false, Some(port))
                            .await
                        {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::warn!(?e, "failed to create listener");
                                continue;
                            }
                        };
                    punched.push((listener.get_socket().await, remote_addr));
                    listeners.push(listener);
                }

                // if any listener is punched, we can break the loop
                for l in &listeners {
                    if l.get_conn_count().await > 0 {
                        tracing::info!(?l, "got punched listener");
                        break;
                    }
                }

                if !punched.is_empty() {
                    tracing::debug!(?punched, "got punched socket and keep sending punch packet");
                }

                for p in &punched {
                    let (socket, remote_addr) = p;
                    let send_remote_ret = socket.send_to(&punch_packet, remote_addr).await;
                    tracing::debug!(
                        ?send_remote_ret,
                        ?socket,
                        "send hole punch packet to punched remote"
                    );
                }
            }

            for l in listeners {
                if l.get_conn_count().await > 0 {
                    common.add_listener(l).await;
                }
            }
        });

        *locked_task = Some(AbortOnDropHandle::new(task));
        return Ok(SendPunchPacketBothEasySymResponse {
            is_busy: false,
            base_mapped_addr: Some(cur_mapped_addr.into()),
        });
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
