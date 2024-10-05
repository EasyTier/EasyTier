use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use tokio::sync::Mutex;

use crate::{
    common::{scoped_task::ScopedTask, stun::StunInfoCollectorTrait, PeerId},
    connector::udp_hole_punch::common::{
        try_connect_with_socket, UdpHolePunchListener, HOLE_PUNCH_PACKET_BODY_LEN,
    },
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{
            SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse,
            UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{udp::new_hole_punch_packet, Tunnel},
};

use super::common::{PunchHoleServerCommon, UdpSocketArray};

pub(crate) struct PunchBothEasySymHoleServer {
    common: Arc<PunchHoleServerCommon>,
    task: Mutex<Option<ScopedTask<()>>>,
}

impl PunchBothEasySymHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        Self {
            common,
            task: Mutex::new(None),
        }
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self))]
    pub(crate) async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySymRequest,
    ) -> Result<SendPunchPacketBothEasySymResponse, rpc_types::error::Error> {
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

        let task = tokio::spawn(async move {
            let mut listeners = Vec::new();
            let start_time = Instant::now();
            let wait_time_ms = request.wait_time_ms.min(8000);
            while start_time.elapsed() < Duration::from_millis(wait_time_ms as u64) {
                if let Err(e) = udp_array
                    .send_with_all(
                        &new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN)
                            .into_bytes(),
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
                    tracing::info!(?s, "got punched socket in both easy sym");
                    assert!(Arc::strong_count(&s) == 1);
                    let Some(port) = s.local_addr().ok().map(|addr| addr.port()) else {
                        tracing::warn!("failed to get local addr from punched socket");
                        continue;
                    };
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
                    listeners.push(listener);
                }

                // if any listener is punched, we can break the loop
                for l in &listeners {
                    if l.get_conn_count().await > 0 {
                        tracing::info!(?l, "got punched listener");
                        break;
                    }
                }
            }
        });

        *locked_task = Some(task.into());
        return Ok(SendPunchPacketBothEasySymResponse {
            is_busy: false,
            base_mapped_addr: Some(cur_mapped_addr.into()),
        });
    }
}

#[derive(Debug)]
pub(crate) struct PunchBothEasySymHoleClient {
    peer_mgr: Arc<PeerManager>,
}

impl PunchBothEasySymHoleClient {
    pub(crate) fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self { peer_mgr }
    }

    #[tracing::instrument]
    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
    ) -> Result<Box<dyn Tunnel>, anyhow::Error> {
        const UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM: usize = 25;
        const DST_PORT_OFFSET: u16 = 20;
        const REMOTE_WAIT_TIME_MS: u64 = 5000;

        let udp_array = UdpSocketArray::new(
            UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM,
            self.peer_mgr.get_global_ctx().net_ns.clone(),
        );
        udp_array.start().await?;

        let global_ctx = self.peer_mgr.get_global_ctx();
        let cur_mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(0)
            .await
            .with_context(|| "failed to get udp port mapping")?;
        let my_public_ip = match cur_mapped_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => {
                anyhow::bail!("ipv6 is not supported");
            }
        };
        let is_incremental = true;

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let tid = rand::random();

        let remote_ret = rpc_stub
            .send_punch_packet_both_easy_sym(
                BaseController {
                    timeout_ms: 2000,
                    ..Default::default()
                },
                SendPunchPacketBothEasySymRequest {
                    transaction_id: tid,
                    public_ip: Some(my_public_ip.into()),
                    dst_port_num: if is_incremental {
                        cur_mapped_addr.port().saturating_add(DST_PORT_OFFSET)
                    } else {
                        cur_mapped_addr.port().saturating_sub(DST_PORT_OFFSET)
                    } as u32,
                    udp_socket_count: UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM as u32,
                    wait_time_ms: REMOTE_WAIT_TIME_MS as u32,
                },
            )
            .await?;
        if remote_ret.is_busy {
            anyhow::bail!("remote is busy");
        }

        let mut remote_mapped_addr = remote_ret
            .base_mapped_addr
            .ok_or(anyhow::anyhow!("remote_mapped_addr is required"))?;

        let now = Instant::now();
        remote_mapped_addr.port = if is_incremental {
            remote_mapped_addr
                .port
                .saturating_add(DST_PORT_OFFSET as u32)
        } else {
            remote_mapped_addr
                .port
                .saturating_sub(DST_PORT_OFFSET as u32)
        };
        tracing::debug!(
            ?remote_mapped_addr,
            ?remote_ret,
            "start send hole punch packet for both easy sym"
        );

        while now.elapsed().as_millis() < (REMOTE_WAIT_TIME_MS + 1000).into() {
            udp_array
                .send_with_all(
                    &new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes(),
                    remote_mapped_addr.into(),
                )
                .await?;

            tokio::time::sleep(Duration::from_millis(100)).await;

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::trace!(
                    ?remote_mapped_addr,
                    ?tid,
                    "no punched socket found, send some more hole punch packets"
                );
                continue;
            };

            tracing::info!(
                ?socket,
                ?remote_mapped_addr,
                ?tid,
                "got punched socket in both easy sym"
            );

            for _ in 0..2 {
                match try_connect_with_socket(socket.clone(), remote_mapped_addr.into()).await {
                    Ok(tunnel) => {
                        return Ok(tunnel);
                    }
                    Err(e) => {
                        tracing::error!(?e, "failed to connect with socket");
                        continue;
                    }
                }
            }
            udp_array.add_new_socket(socket).await?;
        }

        anyhow::bail!("failed to punch hole for both easy sym");
    }
}
