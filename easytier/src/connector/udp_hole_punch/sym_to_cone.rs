use std::{
    net::Ipv4Addr,
    ops::{Div, Mul},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use rand::{seq::SliceRandom, Rng};
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::Level;

use crate::{
    common::{scoped_task::ScopedTask, stun::StunInfoCollectorTrait, PeerId},
    connector::udp_hole_punch::common::{
        send_symmetric_hole_punch_packet, try_connect_with_socket, HOLE_PUNCH_PACKET_BODY_LEN,
    },
    defer,
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{
            SelectPunchListenerRequest, SendPunchPacketEasySymRequest,
            SendPunchPacketHardSymRequest, SendPunchPacketHardSymResponse,
            UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{udp::new_hole_punch_packet, Tunnel},
};

use super::common::{PunchHoleServerCommon, UdpSocketArray};

const UDP_ARRAY_SIZE_FOR_HARD_SYM: usize = 84;

pub(crate) struct PunchSymToConeHoleServer {
    common: Arc<PunchHoleServerCommon>,

    shuffled_port_vec: Arc<Vec<u16>>,
}

impl PunchSymToConeHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        let mut shuffled_port_vec: Vec<u16> = (1..=65535).collect();
        shuffled_port_vec.shuffle(&mut rand::thread_rng());

        Self {
            common,
            shuffled_port_vec: Arc::new(shuffled_port_vec),
        }
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self))]
    pub(crate) async fn send_punch_packet_easy_sym(
        &self,
        request: SendPunchPacketEasySymRequest,
    ) -> Result<(), rpc_types::error::Error> {
        tracing::info!("send_punch_packet_hard_sym start");

        let listener_addr = request.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_hard_sym request missing listener_addr"
        ))?;
        let listener_addr = std::net::SocketAddr::from(listener_addr);
        let listener = self
            .common
            .find_listener(&listener_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_hard_sym failed to find listener"
            ))?;

        let public_ips = request
            .public_ips
            .into_iter()
            .map(|ip| std::net::Ipv4Addr::from(ip))
            .collect::<Vec<_>>();
        if public_ips.len() == 0 {
            tracing::warn!("send_punch_packet_hard_sym got zero len public ip");
            return Err(
                anyhow::anyhow!("send_punch_packet_hard_sym got zero len public ip").into(),
            );
        }

        let transaction_id = request.transaction_id;
        let base_port_num = request.base_port_num;
        let max_port_num = request.max_port_num.max(1);
        let is_incremental = request.is_incremental;

        let port_start = if is_incremental {
            base_port_num.saturating_add(1)
        } else {
            base_port_num.saturating_sub(max_port_num)
        };

        let port_end = if is_incremental {
            base_port_num.saturating_add(max_port_num)
        } else {
            base_port_num.saturating_sub(1)
        };

        if port_end <= port_start {
            return Err(anyhow::anyhow!("send_punch_packet_hard_sym invalid port range").into());
        }

        let ports = (port_start..=port_end)
            .map(|x| x as u16)
            .collect::<Vec<_>>();
        send_symmetric_hole_punch_packet(
            &ports,
            listener,
            transaction_id,
            &public_ips,
            0,
            ports.len(),
        )
        .await
        .with_context(|| "failed to send symmetric hole punch packet")?;

        Ok(())
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self))]
    pub(crate) async fn send_punch_packet_hard_sym(
        &self,
        request: SendPunchPacketHardSymRequest,
    ) -> Result<SendPunchPacketHardSymResponse, rpc_types::error::Error> {
        tracing::info!("try_punch_symmetric start");

        let listener_addr = request.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "try_punch_symmetric request missing listener_addr"
        ))?;
        let listener_addr = std::net::SocketAddr::from(listener_addr);
        let listener = self
            .common
            .find_listener(&listener_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_for_cone failed to find listener"
            ))?;

        let public_ips = request
            .public_ips
            .into_iter()
            .map(|ip| std::net::Ipv4Addr::from(ip))
            .collect::<Vec<_>>();
        if public_ips.len() == 0 {
            tracing::warn!("try_punch_symmetric got zero len public ip");
            return Err(anyhow::anyhow!("try_punch_symmetric got zero len public ip").into());
        }

        let transaction_id = request.transaction_id;
        let last_port_index = request.port_index as usize;

        let round = std::cmp::max(request.round, 1);

        // send max k1 packets if we are predicting the dst port
        let max_k1: u32 = 180;
        // send max k2 packets if we are sending to random port
        let mut max_k2: u32 = rand::thread_rng().gen_range(600..800);
        if round > 2 {
            max_k2 = max_k2.mul(2).div(round).max(max_k1);
        }

        let next_port_index = send_symmetric_hole_punch_packet(
            &self.shuffled_port_vec,
            listener.clone(),
            transaction_id,
            &public_ips,
            last_port_index,
            max_k2 as usize,
        )
        .await
        .with_context(|| "failed to send symmetric hole punch packet randomly")?;

        return Ok(SendPunchPacketHardSymResponse {
            next_port_index: next_port_index as u32,
        });
    }
}

pub(crate) struct PunchSymToConeHoleClient {
    peer_mgr: Arc<PeerManager>,
    udp_array: RwLock<Option<Arc<UdpSocketArray>>>,
    try_direct_connect: AtomicBool,
}

impl PunchSymToConeHoleClient {
    pub(crate) fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            peer_mgr,
            udp_array: RwLock::new(None),
            try_direct_connect: AtomicBool::new(true),
        }
    }

    async fn prepare_udp_array(&self) -> Result<Arc<UdpSocketArray>, anyhow::Error> {
        let rlocked = self.udp_array.read().await;
        if let Some(udp_array) = rlocked.clone() {
            return Ok(udp_array);
        }

        drop(rlocked);
        let mut wlocked = self.udp_array.write().await;
        if let Some(udp_array) = wlocked.clone() {
            return Ok(udp_array);
        }

        let udp_array = Arc::new(UdpSocketArray::new(
            UDP_ARRAY_SIZE_FOR_HARD_SYM,
            self.peer_mgr.get_global_ctx().net_ns.clone(),
        ));
        udp_array.start().await?;
        wlocked.replace(udp_array.clone());
        Ok(udp_array)
    }

    pub(crate) async fn clear_udp_array(&self) {
        let mut wlocked = self.udp_array.write().await;
        wlocked.take();
    }

    #[tracing::instrument(err(level = Level::ERROR), skip(self))]
    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        round: u32,
        last_port_idx: &mut usize,
    ) -> Result<Box<dyn Tunnel>, anyhow::Error> {
        let udp_array = self.prepare_udp_array().await?;
        let global_ctx = self.peer_mgr.get_global_ctx();

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

        // try direct connect first
        if self.try_direct_connect.load(Ordering::Relaxed) {
            if let Ok(tunnel) = try_connect_with_socket(
                Arc::new(UdpSocket::bind("0.0.0.0:0").await?),
                remote_mapped_addr.into(),
            )
            .await
            {
                return Ok(tunnel);
            }
        }

        let stun_info = global_ctx.get_stun_info_collector().get_stun_info();
        let public_ips: Vec<Ipv4Addr> = stun_info
            .public_ip
            .iter()
            .map(|x| x.parse().unwrap())
            .collect();
        if public_ips.is_empty() {
            return Err(anyhow::anyhow!("failed to get public ips"));
        }

        let tid = rand::thread_rng().gen();
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        udp_array.add_intreast_tid(tid);
        defer! { udp_array.remove_intreast_tid(tid);}
        udp_array
            .send_with_all(&packet, remote_mapped_addr.into())
            .await?;

        let port_index = *last_port_idx as u32;
        let scoped_punch_task: ScopedTask<Option<u32>> = tokio::spawn(async move {
            match rpc_stub
                .send_punch_packet_hard_sym(
                    BaseController {
                        timeout_ms: 4000,
                        trace_id: 0,
                    },
                    SendPunchPacketHardSymRequest {
                        listener_mapped_addr: remote_mapped_addr.clone().into(),
                        public_ips: public_ips.clone().into_iter().map(|x| x.into()).collect(),
                        transaction_id: tid,
                        round,
                        port_index,
                    },
                )
                .await
            {
                Err(e) => {
                    tracing::error!(?e, "failed to send punch packet for hard sym");
                    None
                }
                Ok(resp) => Some(resp.next_port_index),
            }
        })
        .into();

        // no matter what the result is, we should check if we received any hole punching packet
        let mut ret_tunnel: Option<Box<dyn Tunnel>> = None;
        let mut finish_time: Option<Instant> = None;
        while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
            tokio::time::sleep(Duration::from_millis(200)).await;

            if finish_time.is_none() && (*scoped_punch_task).is_finished() {
                finish_time = Some(Instant::now());
            }

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::debug!("no punched socket found, wait for more time");
                continue;
            };

            // if hole punched but tunnel creation failed, need to retry entire process.
            match try_connect_with_socket(socket.clone(), remote_mapped_addr.into()).await {
                Ok(tunnel) => {
                    ret_tunnel.replace(tunnel);
                    break;
                }
                Err(e) => {
                    tracing::error!(?e, "failed to connect with socket");
                    udp_array.add_new_socket(socket).await?;
                    continue;
                }
            }
        }

        let punch_task_result = scoped_punch_task.await;
        if let Ok(Some(next_port_idx)) = punch_task_result {
            *last_port_idx = next_port_idx as usize;
        }

        if let Some(tunnel) = ret_tunnel {
            Ok(tunnel)
        } else {
            anyhow::bail!(
                "failed to hole punch, punch task result: {:?}",
                punch_task_result
            )
        }
    }
}
