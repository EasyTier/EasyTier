use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use rand::{Rng, thread_rng};
use tokio::{
    sync::{broadcast, mpsc::error::TrySendError},
    task::JoinSet,
};

use crate::{
    config::PeerId,
    foundation::time::{Interval, interval, timeout},
    packet::{PacketType, ZCPacket},
    peers::{conn::peer_conn_liveness::PeerConnLiveness, context::ArcPeerContext, error::Error},
    tunnel::{
        mpsc::MpscTunnelSender,
        stats::{Throughput, WindowLatency},
    },
};

#[derive(Debug)]
enum PingResponse {
    Pong(u128),
    LivenessEcho,
}

struct PingIntervalController {
    throughput: Arc<Throughput>,
    loss_counter: Arc<AtomicU32>,

    interval: Interval,

    logic_time: u64,
    last_send_logic_time: u64,

    backoff_idx: i32,
    max_backoff_idx: i32,

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
            .field("max_backoff_idx", &self.max_backoff_idx)
            .field("last_throughput", &self.last_throughput)
            .finish()
    }
}

impl PingIntervalController {
    fn new(throughput: Arc<Throughput>, loss_counter: Arc<AtomicU32>) -> Self {
        let last_throughput = (*throughput).clone();

        Self {
            throughput,
            loss_counter,
            interval: interval(Duration::from_secs(1)),
            logic_time: 0,
            last_send_logic_time: 0,

            backoff_idx: 0,
            max_backoff_idx: 5,

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

        if (self.logic_time - self.last_send_logic_time) < (1 << self.backoff_idx) {
            return false;
        }

        self.backoff_idx = std::cmp::min(self.backoff_idx + 1, self.max_backoff_idx);

        // use this makes two peers not pingpong at the same time
        if self.backoff_idx > self.max_backoff_idx - 2 && thread_rng().gen_bool(0.2) {
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
    context: ArcPeerContext,
    network_name: String,
    liveness: PeerConnLiveness,
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
    pub(super) fn new(
        my_peer_id: PeerId,
        peer_id: PeerId,
        sink: MpscTunnelSender,
        ctrl_sender: broadcast::Sender<ZCPacket>,
        latency_stats: Arc<WindowLatency>,
        loss_rate_stats: Arc<AtomicU32>,
        throughput_stats: Arc<Throughput>,
        context: ArcPeerContext,
        network_name: String,
        liveness: PeerConnLiveness,
    ) -> Self {
        Self {
            my_peer_id,
            peer_id,
            sink,
            latency_stats,
            ctrl_sender,
            loss_rate_stats,
            throughput_stats,
            context,
            network_name,
            liveness,
        }
    }

    fn new_ping_packet(my_node_id: PeerId, peer_id: PeerId, seq: u32) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&seq.to_le_bytes());
        packet.fill_peer_manager_hdr(my_node_id, peer_id, PacketType::Ping as u8);
        packet
    }

    async fn do_pingpong_once(
        &self,
        receiver: &mut broadcast::Receiver<ZCPacket>,
        seq: u32,
        liveness_token: Option<u8>,
    ) -> Result<PingResponse, Error> {
        // should add seq here. so latency can be calculated more accurately
        let req = Self::new_ping_packet(self.my_peer_id, self.peer_id, seq);
        let req_len = req.buf_len() as u64;
        self.sink.send(req).await?;
        self.context.record_control_tx(&self.network_name, req_len);

        let now = Instant::now();
        let wait_for_pong = async {
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
        };
        let resp = timeout(Duration::from_secs(2), async {
            if let Some(token) = liveness_token {
                tokio::select! {
                    ret = wait_for_pong => ret.map(|()| PingResponse::Pong(now.elapsed().as_micros())),
                    () = self.liveness.wait_for_echo(token) => Ok(PingResponse::LivenessEcho),
                }
            } else {
                wait_for_pong
                    .await
                    .map(|()| PingResponse::Pong(now.elapsed().as_micros()))
            }
        })
        .await;

        tracing::trace!(?resp, "wait ping response done");

        if resp.is_err() {
            return Err(Error::WaitRespError(
                "wait ping response timeout".to_owned(),
            ));
        }

        resp.unwrap()
    }

    pub async fn pingpong(&mut self) {
        let my_node_id = self.my_peer_id;

        // one with 1% precision
        let loss_rate_stats_1 = WindowLatency::new(100);
        // disconnect the connection if lost 5 pingpong consecutively
        let loss_counter = Arc::new(AtomicU32::new(0));

        let (trigger_sender, mut trigger_receiver) = tokio::sync::mpsc::channel(1);
        let mut controller_tasks = JoinSet::new();
        let throughput = self.throughput_stats.clone();
        let controller_loss_counter = loss_counter.clone();
        controller_tasks.spawn(async move {
            let mut controller = PingIntervalController::new(throughput, controller_loss_counter);
            loop {
                controller.tick().await;
                if !controller.should_send_ping() {
                    continue;
                }
                match trigger_sender.try_send(()) {
                    Ok(()) | Err(TrySendError::Full(())) => {}
                    Err(TrySendError::Closed(())) => break,
                }
            }
        });

        let mut req_seq = 0u32;
        while trigger_receiver.recv().await.is_some() {
            tracing::debug!(
                "pingpong controller send pingpong task, seq: {}, node_id: {}",
                req_seq,
                my_node_id,
            );

            let liveness_token = (loss_counter.load(Ordering::Relaxed) > 0)
                .then(|| self.liveness.start_probe())
                .flatten();
            let mut receiver = self.ctrl_sender.subscribe();
            let ret = self
                .do_pingpong_once(&mut receiver, req_seq, liveness_token)
                .await;
            req_seq = req_seq.wrapping_add(1);

            if let Ok(response) = &ret {
                if let PingResponse::Pong(lat) = response {
                    self.latency_stats.record_latency(*lat as u32);
                }
                if let Some(token) = liveness_token {
                    self.liveness.finish_probe(token);
                }
                loss_rate_stats_1.record_latency(0);
                loss_counter.store(0, Ordering::Relaxed);
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

            tracing::debug!(
                "loss_counter: {:?}, loss_rate_1: {}, node_id: {}",
                loss_counter,
                loss_rate_1,
                my_node_id
            );

            if loss_counter.load(Ordering::Relaxed) >= 5 {
                tracing::warn!(
                    ?ret,
                    ?self,
                    ?loss_rate_1,
                    ?loss_counter,
                    "too many consecutive pingpong failures, closing the connection",
                );
                break;
            }

            self.loss_rate_stats
                .store((loss_rate_1 * 100.0) as u32, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};

    use super::*;
    use crate::{
        packet::PacketType,
        peers::conn::peer_conn_liveness::PeerConnLiveness,
        peers::test_support::NoopPeerContext,
        tunnel::{
            Tunnel, filter::TunnelWithFilter, mpsc::MpscTunnel, ring::create_ring_tunnel_pair,
        },
    };

    #[tokio::test(flavor = "current_thread")]
    async fn ingress_traffic_does_not_mask_failed_round_trips() {
        let (local_tunnel, _remote_tunnel) = create_ring_tunnel_pair();
        let tunnel = MpscTunnel::new(local_tunnel, None);
        let (ctrl_sender, _) = broadcast::channel(16);
        let throughput = Arc::new(Throughput::new());
        let mut pinger = PeerConnPinger::new(
            1,
            2,
            tunnel.get_sink(),
            ctrl_sender,
            Arc::new(WindowLatency::new(15)),
            Arc::new(AtomicU32::new(0)),
            throughput.clone(),
            Arc::new(NoopPeerContext::default()),
            "test".to_owned(),
            PeerConnLiveness::new(),
        );

        let ingress = tokio::spawn(async move {
            loop {
                crate::foundation::time::sleep(Duration::from_millis(100)).await;
                throughput.record_rx_bytes(1);
            }
        });

        let result = timeout(Duration::from_secs(12), pinger.pingpong()).await;
        ingress.abort();

        assert!(
            result.is_ok(),
            "unrelated ingress traffic kept a failed round-trip alive"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echoed_business_traffic_keeps_connection_alive_when_pongs_are_lost() {
        let local_liveness = PeerConnLiveness::new();
        let remote_liveness = PeerConnLiveness::new();
        local_liveness.set_enabled(true);
        remote_liveness.set_enabled(true);

        let (local_transport, remote_transport) = create_ring_tunnel_pair();
        let local_transport = TunnelWithFilter::new(local_transport, local_liveness.clone());
        let mut local_tunnel = MpscTunnel::new(local_transport, None);
        let mut local_stream = local_tunnel.get_stream();
        let local_reader =
            tokio::spawn(async move { while local_stream.next().await.is_some() {} });

        let remote_transport = TunnelWithFilter::new(remote_transport, remote_liveness);
        let (mut remote_stream, mut remote_sink) = remote_transport.split();
        let remote = tokio::spawn(async move {
            while let Some(Ok(_packet)) = remote_stream.next().await {
                let mut reply = ZCPacket::new_with_payload(b"business traffic");
                reply.fill_peer_manager_hdr(2, 1, PacketType::Data as u8);
                remote_sink.send(reply).await.unwrap();
            }
        });

        let (ctrl_sender, _) = broadcast::channel(16);
        let mut pinger = PeerConnPinger::new(
            1,
            2,
            local_tunnel.get_sink(),
            ctrl_sender,
            Arc::new(WindowLatency::new(15)),
            Arc::new(AtomicU32::new(0)),
            Arc::new(Throughput::new()),
            Arc::new(NoopPeerContext::default()),
            "test".to_owned(),
            local_liveness,
        );

        let result = timeout(Duration::from_secs(12), pinger.pingpong()).await;
        remote.abort();
        local_reader.abort();

        assert!(
            result.is_err(),
            "matching business-packet echoes did not keep the connection alive"
        );
    }
}
