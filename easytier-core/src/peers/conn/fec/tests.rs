use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use easytier_proto::peer_rpc::PeerConnFecStats;
use futures::{Sink, StreamExt, task::AtomicWaker};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::{
    config::FecConfig,
    foundation::time::{Duration, Instant, sleep, timeout},
    packet::{PacketType, ZCPacket},
    proto::common::TunnelInfo,
    tunnel::{SplitTunnel, Tunnel, TunnelError, filter::TunnelFilter},
};

use super::{FEATURE, FORCE_PEER_FEATURE, FecInstanceBudget, PeerConnFec, PeerConnFecIo, wire};

fn config() -> FecConfig {
    FecConfig {
        enabled: true,
        ..FecConfig::default()
    }
}

fn prepared(config: FecConfig) -> PeerConnFec {
    PeerConnFec::new(config, true, Some(Arc::new(FecInstanceBudget::default())))
}

fn active(config: FecConfig) -> PeerConnFec {
    let enabled = config.enabled;
    let fec = prepared(config);
    fec.set_remote_features(&[FEATURE.to_owned()]);
    assert_eq!(fec.info().tx_active, enabled);
    fec
}

fn stats(fec: &PeerConnFec) -> PeerConnFecStats {
    fec.info().stats.unwrap()
}

fn packet(id: u8, len: usize) -> ZCPacket {
    let mut packet = ZCPacket::new_with_payload(&vec![id; len - 16]);
    packet.fill_peer_manager_hdr(11, 22, PacketType::Data as u8);
    packet
}

fn control() -> ZCPacket {
    let mut packet = packet(99, 100);
    packet.fill_peer_manager_hdr(11, 22, PacketType::NoiseHandshakeMsg3 as u8);
    packet
}

fn send(fec: &PeerConnFec, packet: ZCPacket, now: Instant) -> ZCPacket {
    let pending = fec.prepare_send(packet, now);
    assert!(pending.accepted.is_some());
    fec.on_accepted(pending.accepted, now);
    pending.packet
}

fn repairs(fec: &PeerConnFec, now: Instant) -> Vec<ZCPacket> {
    let mut packets = Vec::new();
    while let Some(pending) = fec.next_repair(now) {
        fec.on_accepted(pending.accepted, now);
        packets.push(pending.packet);
    }
    packets
}

fn warmup_without_loss(fec: &PeerConnFec, now: Instant) {
    for id in 0..512 {
        send(fec, packet(id as u8, 100), now);
    }
    for batch in 1..=6 {
        fec.receive(
            super::feedback::Report {
                highest: 511,
                samples: batch * 64,
                lost: 0,
            }
            .encode(),
            now,
        );
    }
    assert_eq!(
        fec.info().tx_parameters.unwrap().current_repair_percent,
        Some(0)
    );
}

fn delivered(fec: &PeerConnFec, frame: &ZCPacket, now: Instant) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    if let Some(received) = fec.receive(frame.clone(), now) {
        packets.push(received.packet.tunnel_payload().to_vec());
    }
    while let Some(received) = fec.take_received() {
        packets.push(received.packet.tunnel_payload().to_vec());
    }
    packets
}

#[derive(Default)]
struct Probe {
    blocked: AtomicBool,
    fail: AtomicBool,
    starts: AtomicUsize,
    flush_polls: AtomicUsize,
    flush_wake: AtomicWaker,
}

impl Probe {
    fn unblock(&self) {
        self.blocked.store(false, Ordering::Release);
        self.flush_wake.wake();
    }
}

struct TestSink {
    sent: mpsc::UnboundedSender<ZCPacket>,
    probe: Arc<Probe>,
}

impl Sink<ZCPacket> for TestSink {
    type Error = TunnelError;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, packet: ZCPacket) -> Result<(), Self::Error> {
        self.probe.starts.fetch_add(1, Ordering::AcqRel);
        self.sent.send(packet).map_err(|_| TunnelError::Shutdown)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.probe.flush_polls.fetch_add(1, Ordering::Relaxed);
        self.probe.flush_wake.register(cx.waker());
        if self.probe.blocked.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        if self.probe.fail.load(Ordering::Acquire) {
            return Poll::Ready(Err(TunnelError::Shutdown));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct TestTunnel(Mutex<Option<SplitTunnel>>);

impl Tunnel for TestTunnel {
    fn split(&self) -> SplitTunnel {
        self.0.lock().take().unwrap()
    }
    fn info(&self) -> Option<TunnelInfo> {
        None
    }
}

#[derive(Default)]
struct FilterProbe {
    sent: AtomicUsize,
    received: AtomicUsize,
}

impl TunnelFilter for FilterProbe {
    type FilterOutput = ();
    fn filter_output(&self) {}
    fn before_send(&self, packet: ZCPacket) -> Option<ZCPacket> {
        self.sent.fetch_add(1, Ordering::Relaxed);
        Some(packet)
    }
    fn after_received(
        &self,
        packet: crate::tunnel::StreamItem,
    ) -> Option<crate::tunnel::StreamItem> {
        self.received.fetch_add(1, Ordering::Relaxed);
        Some(packet)
    }
}

fn io(
    fec: Arc<PeerConnFec>,
    probe: Arc<Probe>,
    filter: Arc<FilterProbe>,
) -> (
    PeerConnFecIo,
    mpsc::UnboundedSender<ZCPacket>,
    mpsc::UnboundedReceiver<ZCPacket>,
) {
    let (incoming, received) = mpsc::unbounded_channel();
    let (sent, outgoing) = mpsc::unbounded_channel();
    let stream = futures::stream::unfold(received, |mut received| async move {
        received.recv().await.map(|packet| (Ok(packet), received))
    });
    let tunnel = TestTunnel(Mutex::new(Some((
        Box::pin(stream),
        Box::pin(TestSink { sent, probe }),
    ))));
    (
        PeerConnFecIo::new(Box::new(tunnel), filter, fec),
        incoming,
        outgoing,
    )
}

async fn next_frame(outgoing: &mut mpsc::UnboundedReceiver<ZCPacket>) -> ZCPacket {
    timeout(Duration::from_secs(1), outgoing.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn handshake_controls_pass_while_early_fec_waits_before_receive_filters() {
    let tx = active(config());
    let frame = send(&tx, packet(4, 1000), Instant::now());
    let fec = Arc::new(prepared(config()));
    let filter = Arc::new(FilterProbe::default());
    let (mut io, incoming, _outgoing) = io(fec.clone(), Arc::new(Probe::default()), filter.clone());
    let mut stream = io.get_stream();
    incoming.send(frame.clone()).unwrap();
    incoming.send(control()).unwrap();
    let handshake = stream.next().await.unwrap().unwrap();
    assert_eq!(
        handshake.peer_manager_header().unwrap().packet_type,
        PacketType::NoiseHandshakeMsg3 as u8
    );
    assert_eq!(filter.received.load(Ordering::Relaxed), 1);
    assert!(
        timeout(Duration::from_millis(1), stream.next())
            .await
            .is_err()
    );
    fec.set_remote_features(&[FEATURE.to_owned()]);
    let business = timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(business.tunnel_payload(), packet(4, 1000).tunnel_payload());
    assert_eq!(filter.received.load(Ordering::Relaxed), 2);
    incoming.send(frame).unwrap();
    assert!(
        timeout(Duration::from_millis(1), stream.next())
            .await
            .is_err()
    );
    assert_eq!(filter.received.load(Ordering::Relaxed), 2);
    io.close();
}

#[tokio::test]
async fn blocked_sink_close_and_failed_send_release_all_resources() {
    for blocked in [false, true] {
        let budget = Arc::new(FecInstanceBudget::default());
        let fec = Arc::new(PeerConnFec::new(config(), true, Some(budget.clone())));
        fec.set_remote_features(&[FEATURE.to_owned()]);
        let probe = Arc::new(Probe::default());
        probe.blocked.store(blocked, Ordering::Release);
        probe.fail.store(!blocked, Ordering::Release);
        let (mut io, _incoming, mut outgoing) =
            io(fec.clone(), probe, Arc::new(FilterProbe::default()));
        let sender = io.get_sink();
        sender.send(packet(9, 1000)).await.unwrap();
        next_frame(&mut outgoing).await;
        if blocked {
            fec.close();
        }
        timeout(Duration::from_secs(1), async {
            while budget.used_bytes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(stats(&fec).tx_source_packets, 0);
        assert_eq!(fec.info().tx_reason, "closed");
        io.close();
    }
}

#[test]
fn initial_burst_protects_an_isolated_packet_without_waiting() {
    let now = Instant::now();
    let tx = active(config());
    let rx = active(FecConfig::default());
    let original = packet(7, 80);
    let source = send(&tx, original.clone(), now);
    let parity = repairs(&tx, now);
    assert_eq!(parity.len(), 1);
    assert_eq!(
        delivered(&rx, &parity[0], now),
        vec![original.tunnel_payload().to_vec()]
    );
    assert!(delivered(&rx, &source, now).is_empty());
    assert_eq!(stats(&rx).recovered_packets, 1);
    assert!(!rx.info().tx_active);
}

#[test]
fn later_repairs_recover_a_burst_across_overlapping_windows() {
    let now = Instant::now();
    let tx = active(FecConfig {
        max_repair_percent: 100,
        ..config()
    });
    let rx = active(config());
    let mut expected = Vec::new();
    let mut output = Vec::new();
    for id in 0..20 {
        let original = packet(id, 500 + id as usize * 13);
        expected.push(original.tunnel_payload().to_vec());
        let source = send(&tx, original, now);
        let parity = repairs(&tx, now);
        // Erase both source and repair during a short outage, then resume.
        if id >= 3 {
            output.extend(delivered(&rx, &source, now));
            for repair in parity {
                output.extend(delivered(&rx, &repair, now));
            }
        }
    }
    expected.sort();
    output.sort();
    assert_eq!(output, expected);
    assert_eq!(stats(&rx).recovered_packets, 3);
}

#[test]
fn mixed_lengths_obey_the_actual_byte_budget_and_window_bound() {
    let now = Instant::now();
    let tx = active(config());
    for id in 0..2048 {
        let len = [80, 1200, 128, 900][id % 4];
        let source = send(&tx, packet(id as u8, len), now);
        assert!(source.tunnel_payload().len() + 8 <= 1400);
        for repair in repairs(&tx, now) {
            assert!(repair.tunnel_payload().len() + 8 <= 1400);
        }
        let stats = stats(&tx);
        assert!(stats.tx_repair_bytes * 100 <= 2800 * 100 + stats.tx_source_baseline_bytes * 30);
        assert!(stats.tx_window_packets <= 64);
        assert!(stats.memory_bytes <= super::budget::CONNECTION_LIMIT as u64);
    }
    assert!(stats(&tx).tx_repair_packets > 100);
    assert!(stats(&tx).no_credit_repairs > 0);
    tx.maintain(now + Duration::from_millis(101));
    assert_eq!(stats(&tx).tx_window_packets, 0);
    tx.close();
    assert_eq!(stats(&tx).memory_bytes, 0);
}

#[test]
fn feedback_changes_only_the_local_rate_and_rejects_unaccepted_sequences() {
    use super::feedback::Report;
    let now = Instant::now();
    let tx = active(config());
    for id in 0..128 {
        send(&tx, packet(id, 100), now);
    }
    let pending = tx.prepare_send(packet(128, 100), now);
    let report = Report {
        highest: 128,
        samples: 96,
        lost: 4,
    };
    // The peer may have received start_send while our flush is still pending.
    tx.receive(report.encode(), now);
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(30)
    );
    tx.on_accepted(pending.accepted, now);
    tx.receive(report.encode(), now);
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(25)
    );
    tx.receive(report.encode(), now);
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(25)
    );
    assert_eq!(tx.config.max_repair_percent, 30);
    for id in 129..1024 {
        send(&tx, packet(id as u8, 100), now);
    }
    for sample in (160..960).step_by(64) {
        tx.receive(
            Report {
                highest: 1023,
                samples: sample,
                lost: 4,
            }
            .encode(),
            now,
        );
    }
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(0)
    );
    tx.receive(
        Report {
            highest: 1023,
            samples: 1000,
            lost: 45,
        }
        .encode(),
        now,
    );
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(10)
    );
    // A feedback packet is consumed here and never becomes business traffic.
    assert!(tx.take_received().is_none());
}

#[test]
fn feedback_updates_after_the_coding_window_expires() {
    use super::feedback::Report;
    let now = Instant::now();
    let tx = active(config());
    let rx = active(FecConfig::default());
    for id in 0..512 {
        send(&tx, packet(id as u8, 100), now);
    }
    for batch in 1..=6 {
        tx.receive(
            Report {
                highest: 511,
                samples: batch * 64,
                lost: 0,
            }
            .encode(),
            now,
        );
    }
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(0)
    );
    let later = now + Duration::from_secs(1);
    tx.maintain(later);
    assert_eq!(stats(&tx).tx_window_packets, 0);

    let report = Report {
        highest: 511,
        samples: 448,
        lost: 32,
    };
    tx.receive(report.encode(), later);
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(10)
    );
    tx.receive(report.encode(), later);
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(10)
    );

    // A subsequent isolated source uses the feedback even though none of the
    // earlier source payloads remain available for coding.
    let original = packet(99, 100);
    let expected = original.tunnel_payload().to_vec();
    send(&tx, original, later);
    let parity = repairs(&tx, later);
    assert_eq!(parity.len(), 1);
    assert_eq!(delivered(&rx, &parity[0], later), vec![expected]);
    assert_eq!(stats(&rx).recovered_packets, 1);
}

#[test]
fn idle_repairs_protect_sparse_packets_and_burst_tails_after_warmup() {
    for burst in [1, 10] {
        let now = Instant::now();
        let tx = active(config());
        let rx = active(FecConfig::default());
        warmup_without_loss(&tx, now);
        for second in 1..=60 {
            let at = now + Duration::from_secs(second);
            let mut expected = Vec::new();
            for id in 0..burst {
                let original = packet(id as u8, 100);
                expected = original.tunnel_payload().to_vec();
                let source = send(&tx, original, at);
                if id + 1 != burst {
                    assert_eq!(delivered(&rx, &source, at), vec![expected.clone()]);
                }
                assert!(repairs(&tx, at).is_empty());
            }
            assert!(repairs(&tx, at + Duration::from_millis(4)).is_empty());
            let tail = at + Duration::from_millis(5);
            let parity = repairs(&tx, tail);
            assert_eq!(parity.len(), 1);
            assert_eq!(delivered(&rx, &parity[0], tail), vec![expected]);
            assert!(repairs(&tx, tail + Duration::from_millis(50)).is_empty());
            assert!(tx.repair_deadline().is_none());
            assert!(stats(&tx).tx_repair_bytes <= 1400 * second);
        }
        assert_eq!(stats(&rx).recovered_packets, 60);
        assert_eq!(stats(&tx).tx_repair_packets, 60);
    }
}

#[test]
fn idle_credit_limits_large_packets_and_cancels_expired_opportunities() {
    let now = Instant::now();
    let tx = active(config());
    warmup_without_loss(&tx, now);
    for tick in 0..100 {
        let at = now + Duration::from_secs(1) + Duration::from_millis(tick * 20);
        send(&tx, packet(tick as u8, 1200), at);
        repairs(&tx, at);
        let tail = at + Duration::from_millis(5);
        repairs(&tx, tail);
        if let Some(deadline) = tx.repair_deadline() {
            assert!(deadline > tail);
            assert!(deadline < at + Duration::from_millis(100));
        }
        assert!(stats(&tx).tx_repair_bytes <= (1400 * (1005 + tick * 20)) / 1000);
    }
    assert!(stats(&tx).tx_repair_packets > 0);
    assert!(stats(&tx).tx_repair_packets < 10);
    tx.maintain(now + Duration::from_secs(4));
    assert_eq!(stats(&tx).tx_window_packets, 0);
    assert!(tx.repair_deadline().is_none());
    assert!(repairs(&tx, now + Duration::from_secs(60)).is_empty());
}

#[test]
fn adaptive_byte_rate_accounts_for_mixed_packet_padding() {
    use super::feedback::Report;
    let now = Instant::now();
    for (mixed, cap, expected) in [(false, 30, 9), (true, 30, 17), (true, 10, 10)] {
        let tx = active(FecConfig {
            max_repair_percent: cap,
            ..config()
        });
        for id in 0..1024 {
            let len = if mixed && id % 2 == 0 { 100 } else { 1000 };
            send(&tx, packet(id as u8, len), now);
        }
        for batch in 1..=10 {
            tx.receive(
                Report {
                    highest: 1023,
                    samples: batch * 100,
                    lost: batch * 5,
                }
                .encode(),
                now,
            );
        }
        // Same 5% packet loss; the mixed stream needs almost twice the byte
        // rate because each equation includes padding up to a 1000-byte peer.
        assert_eq!(
            tx.info().tx_parameters.unwrap().current_repair_percent,
            Some(expected)
        );
    }
}

#[test]
fn cumulative_feedback_survives_a_lost_report() {
    let now = Instant::now();
    let tx = active(config());
    let rx = active(FecConfig::default());
    for batch in 0..2 {
        let at = now + Duration::from_millis(batch * 250);
        for id in 0..256 {
            let source = send(&tx, packet(id as u8, 100), at);
            if id % 10 != 0 {
                delivered(&rx, &source, at);
            }
        }
        let feedback = rx.next_feedback(at + Duration::from_millis(201)).unwrap();
        if batch == 1 {
            tx.receive(feedback.packet, at + Duration::from_millis(202));
        }
    }
    assert_eq!(
        tx.info().tx_parameters.unwrap().current_repair_percent,
        Some(25)
    );
    assert!(stats(&rx).loss_packets > 40);
    assert!(rx.next_feedback(now + Duration::from_secs(10)).is_none());
}

#[test]
fn force_peer_and_capability_failures_preserve_directional_policy() {
    let fec = prepared(FecConfig {
        force_peer: true,
        ..FecConfig::default()
    });
    let mut features = Vec::new();
    fec.append_features(&mut features);
    assert_eq!(features, [FEATURE, FORCE_PEER_FEATURE]);
    fec.set_remote_features(&[FEATURE.to_owned()]);
    assert!(!fec.info().tx_active);
    let receiver = prepared(FecConfig::default());
    receiver.set_remote_features(&features);
    assert!(receiver.info().tx_active);
    assert!(receiver.info().peer_requested);
    assert!(!receiver.config.enabled);
    let mut response = Vec::new();
    receiver.append_features(&mut response);
    assert_eq!(response, [FEATURE]);

    let invalid = prepared(FecConfig {
        max_repair_percent: 0,
        ..FecConfig::default()
    });
    invalid.set_remote_features(&features);
    assert_eq!(invalid.info().tx_reason, "invalid_config");
    assert!(invalid.info().rx_active);
    let unsupported = prepared(config());
    unsupported.set_remote_features(&[]);
    assert_eq!(unsupported.info().tx_reason, "remote_unsupported");
    assert_eq!(stats(&unsupported).memory_bytes, 0);
    let unavailable = PeerConnFec::new(config(), true, Some(Arc::new(FecInstanceBudget::new(0))));
    assert!(!unavailable.advertised());
    assert_eq!(stats(&unavailable).memory_bytes, 0);
    receiver.close();
    receiver.set_remote_features(&features);
    assert_eq!(receiver.info().tx_reason, "closed");
    assert_eq!(stats(&receiver).memory_bytes, 0);
}

#[test]
fn early_business_is_bounded_until_the_existing_handshake_finishes() {
    let now = Instant::now();
    let tx = active(config());
    let rx = prepared(FecConfig::default());
    for id in 0..96 {
        assert!(rx.receive(send(&tx, packet(id, 1000), now), now).is_none());
        assert!(rx.take_received().is_none());
    }
    assert!(stats(&rx).rx_queue_drops > 0);
    assert!(rx.next_feedback(now + Duration::from_secs(1)).is_none());
    rx.set_remote_features(&[FEATURE.to_owned()]);
    let mut count = 0;
    while rx.take_received().is_some() {
        count += 1;
    }
    assert_eq!(count, 64);
    rx.close();
    assert_eq!(stats(&rx).memory_bytes, 0);
}

#[tokio::test(start_paused = true)]
async fn repairs_interleave_even_when_the_business_queue_stays_full() {
    let fec = Arc::new(active(FecConfig {
        max_repair_percent: 100,
        ..config()
    }));
    let filter = Arc::new(FilterProbe::default());
    let (mut io, _incoming, mut outgoing) =
        io(fec.clone(), Arc::new(Probe::default()), filter.clone());
    let sink = io.get_sink();
    // All 32 originals are waiting before the writer first runs.
    for id in 0..32 {
        sink.send(packet(id, 1000)).await.unwrap();
    }
    for _ in 0..16 {
        assert_eq!(
            next_frame(&mut outgoing)
                .await
                .peer_manager_header()
                .unwrap()
                .packet_type,
            wire::SOURCE
        );
        assert_eq!(
            next_frame(&mut outgoing)
                .await
                .peer_manager_header()
                .unwrap()
                .packet_type,
            wire::REPAIR
        );
    }
    assert!(stats(&fec).tx_repair_packets >= 16);
    assert!(filter.sent.load(Ordering::Relaxed) <= 32);
    io.close();
}

#[tokio::test]
async fn idle_writer_sends_one_tail_repair_without_more_business_packets() {
    let fec = Arc::new(active(config()));
    warmup_without_loss(&fec, Instant::now() - Duration::from_secs(1));
    let (mut io, _incoming, mut outgoing) = io(
        fec.clone(),
        Arc::new(Probe::default()),
        Arc::new(FilterProbe::default()),
    );
    io.get_sink().send(packet(1, 100)).await.unwrap();
    assert_eq!(
        wire::decode(&next_frame(&mut outgoing).await)
            .unwrap()
            .header
            .kind,
        wire::SOURCE
    );
    assert_eq!(
        wire::decode(&next_frame(&mut outgoing).await)
            .unwrap()
            .header
            .kind,
        wire::REPAIR
    );
    assert!(
        timeout(Duration::from_millis(30), outgoing.recv())
            .await
            .is_err()
    );
    assert_eq!(stats(&fec).tx_repair_packets, 1);
    io.close();
}

#[tokio::test(start_paused = true)]
async fn tail_deadline_does_not_spin_while_a_control_send_is_blocked() {
    let fec = Arc::new(active(config()));
    warmup_without_loss(&fec, Instant::now() - Duration::from_secs(1));
    let probe = Arc::new(Probe::default());
    let (mut io, _incoming, mut outgoing) =
        io(fec.clone(), probe.clone(), Arc::new(FilterProbe::default()));
    io.get_sink().send(packet(1, 100)).await.unwrap();
    next_frame(&mut outgoing).await;
    probe.blocked.store(true, Ordering::Release);
    io.get_sink().send(control()).await.unwrap();
    next_frame(&mut outgoing).await;
    let polls = probe.flush_polls.load(Ordering::Relaxed);
    sleep(Duration::from_millis(200)).await;
    assert_eq!(stats(&fec).tx_repair_packets, 0);
    assert_eq!(stats(&fec).tx_window_packets, 0);
    assert_eq!(probe.starts.load(Ordering::Acquire), 2);
    assert!(probe.flush_polls.load(Ordering::Relaxed) - polls < 10);
    assert!(fec.repair_deadline().is_none());
    io.close();
}

#[tokio::test]
async fn cache_expiry_runs_while_downstream_and_sink_flush_are_paused() {
    let fec = Arc::new(active(config()));
    let probe = Arc::new(Probe::default());
    probe.blocked.store(true, Ordering::Release);
    let (mut io, incoming, mut outgoing) =
        io(fec.clone(), probe.clone(), Arc::new(FilterProbe::default()));
    let mut stream = io.get_stream();
    io.get_sink().send(packet(8, 1000)).await.unwrap();
    next_frame(&mut outgoing).await;
    let tx = active(config());
    for id in 0..40 {
        incoming
            .send(send(&tx, packet(id, 1000), Instant::now()))
            .unwrap();
        assert!(stream.next().await.unwrap().is_ok());
    }
    assert_eq!(stats(&fec).rx_window_packets, 40);
    assert!(fec.feedback_deadline().is_some());
    let polls = probe.flush_polls.load(Ordering::Relaxed);
    sleep(Duration::from_millis(250)).await;
    assert_eq!(stats(&fec).rx_window_packets, 0);
    assert_eq!(probe.starts.load(Ordering::Acquire), 1);
    assert_eq!(stats(&fec).tx_source_packets, 0);
    assert!(probe.flush_polls.load(Ordering::Relaxed) - polls < 50);
    probe.unblock();
    timeout(Duration::from_secs(1), async {
        while stats(&fec).tx_source_packets == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(stats(&fec).tx_source_packets, 1);
    io.close();
}
