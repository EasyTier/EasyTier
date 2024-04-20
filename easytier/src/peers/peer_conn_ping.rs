use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{BytesMut};
use tokio::{sync::broadcast, task::JoinSet, time::timeout};

use crate::{
    common::{error::Error, PeerId},
    tunnel::{
        mpsc::MpscTunnelSender,
        packet_def::{PacketType, ZCPacket},
        stats::WindowLatency,
        TunnelError,
    },
};

pub struct PeerConnPinger {
    my_peer_id: PeerId,
    peer_id: PeerId,
    sink: MpscTunnelSender,
    ctrl_sender: broadcast::Sender<ZCPacket>,
    latency_stats: Arc<WindowLatency>,
    loss_rate_stats: Arc<AtomicU32>,
    tasks: JoinSet<Result<(), TunnelError>>,
}

impl std::fmt::Debug for PeerConnPinger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnPinger")
            .field("my_peer_id", &self.my_peer_id)
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

impl PeerConnPinger {
    pub fn new(
        my_peer_id: PeerId,
        peer_id: PeerId,
        sink: MpscTunnelSender,
        ctrl_sender: broadcast::Sender<ZCPacket>,
        latency_stats: Arc<WindowLatency>,
        loss_rate_stats: Arc<AtomicU32>,
    ) -> Self {
        Self {
            my_peer_id,
            peer_id,
            sink,
            tasks: JoinSet::new(),
            latency_stats,
            ctrl_sender,
            loss_rate_stats,
        }
    }

    fn new_ping_packet(my_node_id: PeerId, peer_id: PeerId, seq: u32) -> ZCPacket {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&seq.to_le_bytes());
        let mut packet = ZCPacket::new_with_payload(buf);
        packet.fill_peer_manager_hdr(my_node_id, peer_id, PacketType::Ping as u8);
        packet
    }

    async fn do_pingpong_once(
        my_node_id: PeerId,
        peer_id: PeerId,
        sink: &mut MpscTunnelSender,
        receiver: &mut broadcast::Receiver<ZCPacket>,
        seq: u32,
    ) -> Result<u128, Error> {
        // should add seq here. so latency can be calculated more accurately
        let req = Self::new_ping_packet(my_node_id, peer_id, seq);
        sink.send(req).await?;

        let now = std::time::Instant::now();
        // wait until we get a pong packet in ctrl_resp_receiver
        let resp = timeout(Duration::from_secs(1), async {
            loop {
                match receiver.recv().await {
                    Ok(p) => {
                        let payload = p.payload();
                        let Ok(seq_buf) = payload[0..4].try_into() else {
                            tracing::debug!("pingpong recv invalid packet, continue");
                            continue;
                        };
                        let resp_seq = u32::from_le_bytes(seq_buf);
                        if resp_seq == seq {
                            break;
                        }
                    }
                    Err(e) => {
                        return Err(Error::WaitRespError(format!(
                            "wait ping response error: {:?}",
                            e
                        )));
                    }
                }
            }
            Ok(())
        })
        .await;

        tracing::trace!(?resp, "wait ping response done");

        if resp.is_err() {
            return Err(Error::WaitRespError(
                "wait ping response timeout".to_owned(),
            ));
        }

        if resp.as_ref().unwrap().is_err() {
            return Err(resp.unwrap().err().unwrap());
        }

        Ok(now.elapsed().as_micros())
    }

    pub async fn pingpong(&mut self) {
        let sink = self.sink.clone();
        let my_node_id = self.my_peer_id;
        let peer_id = self.peer_id;
        let latency_stats = self.latency_stats.clone();

        let (ping_res_sender, mut ping_res_receiver) = tokio::sync::mpsc::channel(100);

        let stopped = Arc::new(AtomicU32::new(0));

        // generate a pingpong task every 200ms
        let mut pingpong_tasks = JoinSet::new();
        let ctrl_resp_sender = self.ctrl_sender.clone();
        let stopped_clone = stopped.clone();
        self.tasks.spawn(async move {
            let mut req_seq = 0;
            loop {
                let receiver = ctrl_resp_sender.subscribe();
                let ping_res_sender = ping_res_sender.clone();

                if stopped_clone.load(Ordering::Relaxed) != 0 {
                    return Ok(());
                }

                while pingpong_tasks.len() > 5 {
                    pingpong_tasks.join_next().await;
                }

                let mut sink = sink.clone();
                pingpong_tasks.spawn(async move {
                    let mut receiver = receiver.resubscribe();
                    let pingpong_once_ret = Self::do_pingpong_once(
                        my_node_id,
                        peer_id,
                        &mut sink,
                        &mut receiver,
                        req_seq,
                    )
                    .await;

                    if let Err(e) = ping_res_sender.send(pingpong_once_ret).await {
                        tracing::info!(?e, "pingpong task send result error, exit..");
                    };
                });

                req_seq = req_seq.wrapping_add(1);
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });

        // one with 1% precision
        let loss_rate_stats_1 = WindowLatency::new(100);
        // one with 20% precision, so we can fast fail this conn.
        let loss_rate_stats_20 = WindowLatency::new(5);

        let mut counter: u64 = 0;

        while let Some(ret) = ping_res_receiver.recv().await {
            counter += 1;

            if let Ok(lat) = ret {
                latency_stats.record_latency(lat as u32);

                loss_rate_stats_1.record_latency(0);
                loss_rate_stats_20.record_latency(0);
            } else {
                loss_rate_stats_1.record_latency(1);
                loss_rate_stats_20.record_latency(1);
            }

            let loss_rate_20: f64 = loss_rate_stats_20.get_latency_us();
            let loss_rate_1: f64 = loss_rate_stats_1.get_latency_us();

            tracing::trace!(
                ?ret,
                ?self,
                ?loss_rate_1,
                ?loss_rate_20,
                "pingpong task recv pingpong_once result"
            );

            if (counter > 5 && loss_rate_20 > 0.74) || (counter > 150 && loss_rate_1 > 0.20) {
                tracing::warn!(
                    ?ret,
                    ?self,
                    ?loss_rate_1,
                    ?loss_rate_20,
                    "pingpong loss rate too high, closing"
                );
                break;
            }

            self.loss_rate_stats
                .store((loss_rate_1 * 100.0) as u32, Ordering::Relaxed);
        }

        stopped.store(1, Ordering::Relaxed);
        ping_res_receiver.close();
    }
}
