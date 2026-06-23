use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use rand::{Rng, thread_rng};
use tokio::{
    sync::broadcast,
    task::JoinSet,
    time::{Interval, timeout},
};
use tracing::Instrument;

use crate::{
    common::{PeerId, error::Error},
    peers::traffic_metrics::AggregateTrafficMetrics,
    tunnel::{
        TunnelError,
        mpsc::MpscTunnelSender,
        packet_def::{PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
    },
};

const DEFAULT_MAX_HEARTBEAT_INTERVAL_SECS: u64 = 32;
const DEFAULT_MAX_MISSED_HEARTBEATS: u32 = 5;
const DEFAULT_PONG_TIMEOUT_SECS: u64 = 2;

#[derive(Clone, Copy, Debug)]
pub struct PeerConnPingConfig {
    pub max_heartbeat_interval: Duration,
    pub max_missed_heartbeats: u32,
    pub pong_timeout: Duration,
}

impl PeerConnPingConfig {
    pub fn new(
        max_heartbeat_interval_secs: u32,
        max_missed_heartbeats: u32,
        pong_timeout_secs: u32,
    ) -> Self {
        let max_heartbeat_interval_secs = if max_heartbeat_interval_secs == 0 {
            DEFAULT_MAX_HEARTBEAT_INTERVAL_SECS
        } else {
            u64::from(max_heartbeat_interval_secs)
        };
        let max_missed_heartbeats = if max_missed_heartbeats == 0 {
            DEFAULT_MAX_MISSED_HEARTBEATS
        } else {
            max_missed_heartbeats
        };
        let pong_timeout_secs = if pong_timeout_secs == 0 {
            DEFAULT_PONG_TIMEOUT_SECS
        } else {
            u64::from(pong_timeout_secs)
        };

        Self {
            max_heartbeat_interval: Duration::from_secs(max_heartbeat_interval_secs.max(1)),
            max_missed_heartbeats: max_missed_heartbeats.max(1),
            pong_timeout: Duration::from_secs(pong_timeout_secs.max(1)),
        }
    }
}

struct PingIntervalController {
    throughput: Arc<Throughput>,
    loss_counter: Arc<AtomicU32>,

    interval: Interval,

    logic_time: u64,
    last_send_logic_time: u64,

    backoff_idx: i32,
    max_heartbeat_interval_secs: u64,

    last_throughput: Throughput,
}

impl std::fmt::Debug for PingIntervalController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingIntervalController")
            .field("throughput", &self.throughput)
            .field("loss_counter", &self.loss_counter)
            .field("logic_time", &self.logic_time)
            .field("last_send_logic_time", &self.last_send_logic_time)
            .field("backoff_idx", &self.backoff_idx)
            .field(
                "max_heartbeat_interval_secs",
                &self.max_heartbeat_interval_secs,
            )
            .field("last_throughput", &self.last_throughput)
            .finish()
    }
}

impl PingIntervalController {
    fn new(
        throughput: Arc<Throughput>,
        loss_counter: Arc<AtomicU32>,
        config: PeerConnPingConfig,
    ) -> Self {
        let last_throughput = (*throughput).clone();

        Self {
            throughput,
            loss_counter,
            interval: tokio::time::interval(Duration::from_secs(1)),
            logic_time: 0,
            last_send_logic_time: 0,

            backoff_idx: 0,
            max_heartbeat_interval_secs: config.max_heartbeat_interval.as_secs().max(1),

            last_throughput,
        }
    }

    async fn tick(&mut self) {
        self.interval.tick().await;
        self.logic_time += 1;
    }

    fn tx_increase(&self) -> bool {
        self.throughput.tx_packets() > self.last_throughput.tx_packets()
    }

    fn rx_increase(&self) -> bool {
        self.throughput.rx_packets() > self.last_throughput.rx_packets()
    }

    fn should_send_ping(&mut self) -> bool {
        if self.loss_counter.load(Ordering::Relaxed) > 0 {
            self.backoff_idx = 0;
        } else if self.tx_increase() && !self.rx_increase() {
            // if tx increase but rx not increase, we should do pingpong more frequently
            self.backoff_idx = 0;
        }

        self.last_throughput = (*self.throughput).clone();

        let cur_interval_secs = 1u64
            .checked_shl(self.backoff_idx.max(0) as u32)
            .unwrap_or(u64::MAX)
            .min(self.max_heartbeat_interval_secs);
        if (self.logic_time - self.last_send_logic_time) < cur_interval_secs {
            return false;
        }

        if cur_interval_secs < self.max_heartbeat_interval_secs {
            self.backoff_idx += 1;
        }

        // use this makes two peers not pingpong at the same time
        if cur_interval_secs >= self.max_heartbeat_interval_secs / 4
            && self.backoff_idx > 0
            && thread_rng().gen_bool(0.2)
        {
            self.backoff_idx -= 1;
        }

        self.last_send_logic_time = self.logic_time;
        true
    }
}

pub struct PeerConnPinger {
    my_peer_id: PeerId,
    peer_id: PeerId,
    sink: MpscTunnelSender,
    ctrl_sender: broadcast::Sender<ZCPacket>,
    latency_stats: Arc<WindowLatency>,
    loss_rate_stats: Arc<AtomicU32>,
    throughput_stats: Arc<Throughput>,
    control_metrics: AggregateTrafficMetrics,
    config: PeerConnPingConfig,
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        my_peer_id: PeerId,
        peer_id: PeerId,
        sink: MpscTunnelSender,
        ctrl_sender: broadcast::Sender<ZCPacket>,
        latency_stats: Arc<WindowLatency>,
        loss_rate_stats: Arc<AtomicU32>,
        throughput_stats: Arc<Throughput>,
        control_metrics: AggregateTrafficMetrics,
        config: PeerConnPingConfig,
    ) -> Self {
        Self {
            my_peer_id,
            peer_id,
            sink,
            tasks: JoinSet::new(),
            latency_stats,
            ctrl_sender,
            loss_rate_stats,
            throughput_stats,
            control_metrics,
            config,
        }
    }

    fn new_ping_packet(my_node_id: PeerId, peer_id: PeerId, seq: u32) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&seq.to_le_bytes());
        packet.fill_peer_manager_hdr(my_node_id, peer_id, PacketType::Ping as u8);
        packet
    }

    async fn do_pingpong_once(
        my_node_id: PeerId,
        peer_id: PeerId,
        sink: &MpscTunnelSender,
        control_metrics: &AggregateTrafficMetrics,
        receiver: &mut broadcast::Receiver<ZCPacket>,
        seq: u32,
        pong_timeout: Duration,
    ) -> Result<u128, Error> {
        // should add seq here. so latency can be calculated more accurately
        let req = Self::new_ping_packet(my_node_id, peer_id, seq);
        let req_len = req.buf_len() as u64;
        sink.send(req).await?;
        control_metrics.record_tx(req_len);

        let now = std::time::Instant::now();
        // wait until we get a pong packet in ctrl_resp_receiver
        let resp = timeout(pong_timeout, async {
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
        let control_metrics = self.control_metrics.clone();
        let my_node_id = self.my_peer_id;
        let peer_id = self.peer_id;
        let latency_stats = self.latency_stats.clone();

        let (ping_res_sender, mut ping_res_receiver) = tokio::sync::mpsc::channel(100);

        // one with 1% precision
        let loss_rate_stats_1 = WindowLatency::new(100);
        // disconnect the connection if configured pingpong attempts are lost consecutively
        let loss_counter = Arc::new(AtomicU32::new(0));

        let stopped = Arc::new(AtomicU32::new(0));

        // the controller checks whether to generate a pingpong task once per second
        let mut pingpong_tasks = JoinSet::new();
        let ctrl_resp_sender = self.ctrl_sender.clone();
        let stopped_clone = stopped.clone();
        let config = self.config;
        let mut controller = PingIntervalController::new(
            self.throughput_stats.clone(),
            loss_counter.clone(),
            config,
        );
        self.tasks.spawn(
            async move {
                let mut req_seq = 0;
                loop {
                    controller.tick().await;

                    if stopped_clone.load(Ordering::Relaxed) != 0 {
                        return Ok(());
                    }

                    while pingpong_tasks.len() > 5 {
                        pingpong_tasks.join_next().await;
                    }

                    if !controller.should_send_ping() {
                        continue;
                    }

                    tracing::debug!(
                        "pingpong controller send pingpong task, seq: {}, node_id: {}, controller: {:?}",
                        req_seq,
                        my_node_id,
                        controller,
                    );

                    let sink = sink.clone();
                    let control_metrics = control_metrics.clone();
                    let receiver = ctrl_resp_sender.subscribe();
                    let ping_res_sender = ping_res_sender.clone();
                    pingpong_tasks.spawn(async move {
                        let mut receiver = receiver.resubscribe();
                        let pingpong_once_ret = Self::do_pingpong_once(
                            my_node_id,
                            peer_id,
                            &sink,
                            &control_metrics,
                            &mut receiver,
                            req_seq,
                            config.pong_timeout,
                        )
                        .await;

                        if let Err(e) = ping_res_sender.send(pingpong_once_ret).await {
                            tracing::info!(?e, "pingpong task send result error, exit..");
                        };
                    });

                    req_seq = req_seq.wrapping_add(1);
                }
            }
            .instrument(tracing::info_span!(
                "pingpong_controller",
                ?my_node_id,
                ?peer_id
            )),
        );

        let throughput = self.throughput_stats.clone();
        let mut last_rx_packets = throughput.rx_packets();

        while let Some(ret) = ping_res_receiver.recv().await {
            if let Ok(lat) = ret {
                latency_stats.record_latency(lat as u32);

                loss_rate_stats_1.record_latency(0);
            } else {
                loss_rate_stats_1.record_latency(1);
                loss_counter.fetch_add(1, Ordering::Relaxed);
            }

            let loss_rate_1: f64 = loss_rate_stats_1.get_latency_us();

            tracing::trace!(
                ?ret,
                ?self,
                ?loss_rate_1,
                "pingpong task recv pingpong_once result"
            );

            let current_rx_packets = throughput.rx_packets();
            if last_rx_packets != current_rx_packets {
                // if we receive some packet from peers, reset the counter to avoid conn close.
                // conn will close only if configured pingpong attempts are lost consecutively
                // after no packet received.
                loss_counter.store(0, Ordering::Relaxed);
            }

            tracing::debug!(
                "loss_counter: {:?}, loss_rate_1: {}, cur_rx_packets: {}, last_rx: {}, node_id: {}",
                loss_counter,
                loss_rate_1,
                current_rx_packets,
                last_rx_packets,
                my_node_id
            );

            if loss_counter.load(Ordering::Relaxed) >= self.config.max_missed_heartbeats {
                tracing::warn!(
                    ?ret,
                    ?self,
                    ?loss_rate_1,
                    ?loss_counter,
                    ?last_rx_packets,
                    ?current_rx_packets,
                    "pingpong loss too much pingpong packet and no other ingress packets, closing the connection",
                );
                break;
            }

            last_rx_packets = throughput.rx_packets();
            self.loss_rate_stats
                .store((loss_rate_1 * 100.0) as u32, Ordering::Relaxed);
        }

        stopped.store(1, Ordering::Relaxed);
        ping_res_receiver.close();
    }
}
