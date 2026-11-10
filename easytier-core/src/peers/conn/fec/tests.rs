use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{Sink, SinkExt, StreamExt, task::AtomicWaker};

use crate::{
    config::{
        peers::PeerRuntimeSnapshot,
        runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    },
    foundation::time::{Duration, Instant, sleep, timeout},
    packet::{PacketType, ZCPacket},
    peers::context::{CorePeerContext, CorePeerContextAdapters, PeerContext},
    proto::common::{Flags, TunnelInfo},
    socket::udp::{UdpSession, UdpSessionKind, VirtualUdpSocket},
    tunnel::{
        SplitTunnel, StreamItem, Tunnel, TunnelError, ZCPacketStream,
        filter::{EmptyFilter, TunnelFilter, TunnelWithFilter},
        udp::UdpTunnelUpgrader,
    },
};

use super::{ENABLED_FEATURE, FEATURE, MAX_SYMBOL_SIZE, PeerConnFec, PeerConnFecIo, codec, wire};

struct LoopbackSocket(tokio::net::UdpSocket);

#[async_trait]
impl VirtualUdpSocket for LoopbackSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.0.send_to(data, addr).await
    }

    async fn recv_from(&self, data: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(data).await
    }
}

async fn udp_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let left = Arc::new(LoopbackSocket(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ));
    let right = Arc::new(LoopbackSocket(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ));
    let left_addr = left.local_addr().unwrap();
    let right_addr = right.local_addr().unwrap();
    let make = |socket, remote| {
        let session =
            UdpSession::identity_standalone(socket, remote, UdpSessionKind::Quic).unwrap();
        UdpTunnelUpgrader::new(TunnelInfo {
            tunnel_type: "udp".to_owned(),
            ..Default::default()
        })
        .upgrade(session)
        .unwrap()
    };
    (make(left, right_addr), make(right, left_addr))
}

fn active_io(tunnel: Box<dyn Tunnel>) -> (PeerConnFecIo, Arc<PeerConnFec>) {
    let fec = Arc::new(PeerConnFec::new(
        &Flags {
            enable_udp_fec: true,
            ..Default::default()
        },
        None,
    ));
    fec.set_remote_features(&[FEATURE.to_owned()]);
    (PeerConnFecIo::new(tunnel, EmptyFilter, fec.clone()), fec)
}

fn source(id: u8, len: usize) -> ZCPacket {
    let mut packet = ZCPacket::new_with_payload(&vec![id; len]);
    packet.fill_peer_manager_hdr(11, 22, PacketType::Data as u8);
    packet
}

fn marker() -> ZCPacket {
    let mut packet = ZCPacket::new_with_payload(b"end");
    packet.fill_peer_manager_hdr(11, 22, PacketType::Ping as u8);
    packet
}

async fn next(stream: &mut Pin<Box<dyn ZCPacketStream>>) -> ZCPacket {
    timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("UDP delivery did not complete")
        .expect("UDP receive stream closed")
        .unwrap()
}

async fn wait_until(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(2), async {
        while !ready() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("FEC state did not reach the expected condition");
}

struct DropSources(Vec<u64>);

impl TunnelFilter for DropSources {
    type FilterOutput = ();

    fn before_send(&self, packet: ZCPacket) -> Option<ZCPacket> {
        if let Some((id, _)) = wire::parse_source(&packet, MAX_SYMBOL_SIZE)
            && self.0.contains(&id)
        {
            return None;
        }
        Some(packet)
    }

    fn filter_output(&self) {}
}

#[tokio::test]
async fn udp_tail_repair_recovers_an_isolated_complete_peer_packet() {
    let (left, right) = udp_pair().await;
    let left = Box::new(TunnelWithFilter::new(left, DropSources(vec![0])));
    let (left_io, left_fec) = active_io(left);
    let (mut right_io, right_fec) = active_io(right);
    let mut stream = right_io.get_stream();
    let mut original = source(37, 73);
    original
        .mut_peer_manager_header()
        .unwrap()
        .set_encrypted(true);
    original.mut_peer_manager_header().unwrap().len.set(51);
    left_io.get_sink().send(original.clone()).await.unwrap();

    assert_eq!(
        next(&mut stream).await.tunnel_payload(),
        original.tunnel_payload()
    );
    assert_eq!(right_fec.stats().rx_sources, 0);
    assert_eq!(right_fec.stats().recovered, 1);
    wait_until(|| left_fec.stats().tx_repairs == 1).await;
    assert_eq!(left_fec.stats().tx_sources, 1);
}

#[tokio::test]
async fn udp_fec_metrics_accumulate_across_connections() {
    let contexts = ["fec-left", "fec-right"].map(|network_name| {
        let mut snapshot = PeerRuntimeSnapshot::default();
        snapshot.runtime.network_identity.network_name = network_name.to_owned();
        CorePeerContext::new(
            CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(snapshot)),
            Arc::new(()),
            CorePeerContextAdapters {
                stun_info_source: None,
                events: Arc::new(()),
                credential_storage: None,
            },
        )
    });
    let snapshot = |context: &CorePeerContext| {
        let expected_labels = crate::foundation::stats::LabelSet::new()
            .with_label("network_name", context.network_name());
        context
            .stats_manager()
            .get_all_metrics()
            .into_iter()
            .map(|metric| {
                assert_eq!(metric.labels, expected_labels);
                (metric.name_str(), metric.value)
            })
            .collect::<BTreeMap<_, _>>()
    };
    let original = source(37, 73);
    let peer_bytes = original.tunnel_payload().len() as u64;
    let source_bytes = peer_bytes + wire::SOURCE_HEADER_SIZE as u64;
    let repair_bytes = peer_bytes + 2 + wire::REPAIR_HEADER_SIZE as u64;
    let mut accepted_repairs = 0;

    for round in 1..=2 {
        let (left, right) = udp_pair().await;
        let left = Box::new(TunnelWithFilter::new(left, DropSources(vec![0])));
        let [left_fec, right_fec] = contexts.each_ref().map(|context| {
            let fec = Arc::new(PeerConnFec::new(
                &Flags {
                    enable_udp_fec: true,
                    ..Default::default()
                },
                context.udp_fec_metrics(),
            ));
            fec.set_remote_features(&[FEATURE.to_owned()]);
            fec
        });
        let left_io = PeerConnFecIo::new(left, EmptyFilter, left_fec.clone());
        let mut right_io = PeerConnFecIo::new(right, EmptyFilter, right_fec.clone());
        let mut stream = right_io.get_stream();

        left_io.get_sink().send(original.clone()).await.unwrap();
        assert_eq!(
            next(&mut stream).await.tunnel_payload(),
            original.tunnel_payload()
        );
        left_io.get_sink().send(original.clone()).await.unwrap();
        assert_eq!(
            next(&mut stream).await.tunnel_payload(),
            original.tunnel_payload()
        );
        wait_until(|| left_fec.stats().tx_sources == 2).await;
        accepted_repairs += left_fec.stats().tx_repairs;

        let [left_metrics, right_metrics] = contexts.each_ref().map(snapshot);
        assert_eq!(left_metrics.len(), 9);
        assert_eq!(right_metrics.len(), 9);
        assert_eq!(left_metrics["udp_fec_source_packets_tx"], 2 * round);
        assert_eq!(
            left_metrics["udp_fec_source_bytes_tx"],
            2 * round * source_bytes
        );
        assert_eq!(left_metrics["udp_fec_repair_packets_tx"], accepted_repairs);
        assert_eq!(
            left_metrics["udp_fec_repair_bytes_tx"],
            accepted_repairs * repair_bytes
        );
        assert_eq!(left_metrics["udp_fec_source_packets_rx"], 0);
        assert_eq!(left_metrics["udp_fec_packets_recovered"], 0);
        assert_eq!(right_metrics["udp_fec_source_packets_tx"], 0);
        assert_eq!(right_metrics["udp_fec_source_packets_rx"], round);
        assert_eq!(
            right_metrics["udp_fec_source_bytes_rx"],
            round * source_bytes
        );
        assert_eq!(right_metrics["udp_fec_repair_packets_rx"], round);
        assert_eq!(
            right_metrics["udp_fec_repair_bytes_rx"],
            round * repair_bytes
        );
        assert_eq!(right_metrics["udp_fec_packets_recovered"], round);
        drop((stream, left_io, right_io, left_fec, right_fec));
        assert_eq!(snapshot(&contexts[0]), left_metrics);
        assert_eq!(snapshot(&contexts[1]), right_metrics);
        assert!(contexts[1].stats_manager().export_prometheus().contains(
            format!("udp_fec_packets_recovered{{network_name=\"fec-right\"}} {round}").as_str()
        ));
    }
}

#[tokio::test]
async fn udp_framed_data_can_overtake_plain_handshake_without_changing_the_parser() {
    for requested in [false, true] {
        let (left, right) = udp_pair().await;
        let (_left_stream, mut sink) = left.split();
        let fec = Arc::new(PeerConnFec::new(&Flags::default(), None));
        assert!(fec.state.lock().rx.is_none());
        let mut io = PeerConnFecIo::new(right, EmptyFilter, fec.clone());
        let mut stream = io.get_stream();
        let original = source(42, 80);
        let mut handshake = marker();
        handshake.mut_peer_manager_header().unwrap().packet_type = PacketType::HandShake as u8;
        // Model reordering across the final handshake. While waiting, the FEC
        // frame must be queued and the plain handshake must pass unchanged.
        sink.send(wire::wrap_source(0, &original)).await.unwrap();
        sink.send(handshake.clone()).await.unwrap();
        assert_eq!(
            next(&mut stream).await.tunnel_payload(),
            handshake.tunnel_payload()
        );
        assert_eq!(fec.state.lock().rx.as_ref().unwrap().early.len(), 1);
        let mut features = vec![FEATURE.to_owned()];
        if requested {
            features.push(ENABLED_FEATURE.to_owned());
        }
        fec.set_remote_features(&features);
        assert_eq!(fec.stats().active, requested);
        if requested {
            assert_eq!(
                next(&mut stream).await.tunnel_payload(),
                original.tunnel_payload()
            );
        } else {
            assert!(fec.state.lock().rx.is_none());
        }
        // A late plain handshake is still plain after activation or rejection.
        sink.send(handshake.clone()).await.unwrap();
        assert_eq!(
            next(&mut stream).await.tunnel_payload(),
            handshake.tunnel_payload()
        );
        let mut invalid = marker();
        invalid.mut_peer_manager_header().unwrap().packet_type = 0xc0;
        sink.send(invalid).await.unwrap();
        sink.send(marker()).await.unwrap();
        assert_eq!(
            next(&mut stream).await.tunnel_payload(),
            marker().tunnel_payload()
        );
        assert_eq!(fec.stats().invalid_packets, 1);
        assert_eq!(fec.stats().rx_sources, u64::from(requested));
    }
}

#[tokio::test]
async fn udp_recovery_accepts_the_largest_symbol_that_fits_the_session() {
    let (left, right) = udp_pair().await;
    let left = Box::new(TunnelWithFilter::new(left, DropSources(vec![0])));
    let (left_io, left_fec) = active_io(left);
    let (mut right_io, right_fec) = active_io(right);
    let mut stream = right_io.get_stream();
    let original = source(
        63,
        MAX_SYMBOL_SIZE - 2 - crate::packet::PEER_MANAGER_HEADER_SIZE,
    );
    left_io.get_sink().send(original.clone()).await.unwrap();
    assert_eq!(
        next(&mut stream).await.tunnel_payload(),
        original.tunnel_payload()
    );
    assert_eq!(right_fec.stats().recovered, 1);
    wait_until(|| left_fec.stats().tx_repairs == 1).await;
    assert_eq!(
        left_fec.stats().tx_repair_bytes as usize,
        MAX_SYMBOL_SIZE + wire::REPAIR_HEADER_SIZE
    );
}

#[tokio::test]
async fn udp_continuous_sources_recover_losses_across_overlapping_windows() {
    let (left, right) = udp_pair().await;
    // The first full batch has more losses than its two repairs can recover.
    // Repairs covering the next batch must still include these older sources.
    let left = Box::new(TunnelWithFilter::new(left, DropSources(vec![0, 1, 2, 20])));
    let (left_io, left_fec) = active_io(left);
    let (mut right_io, right_fec) = active_io(right);
    let mut stream = right_io.get_stream();
    let originals: BTreeMap<_, _> = (0..30u8)
        .map(|id| (id, source(id, 40 + usize::from(id) * 7)))
        .collect();
    for packet in originals.values() {
        left_io.get_sink().send(packet.clone()).await.unwrap();
    }
    let mut received = BTreeMap::new();
    for _ in 0..originals.len() {
        let packet = next(&mut stream).await;
        let id = packet.payload()[0];
        assert!(
            received.insert(id, packet).is_none(),
            "duplicate delivery {id}"
        );
    }
    for (id, packet) in received {
        assert_eq!(packet.tunnel_payload(), originals[&id].tunnel_payload());
    }
    assert_eq!(right_fec.stats().recovered, 4);
    wait_until(|| left_fec.stats().tx_sources == 30 && left_fec.stats().tx_repairs >= 6).await;
    assert!(left_fec.stats().tx_repairs <= 30);
}

#[tokio::test]
async fn udp_reordered_originals_and_late_recovered_duplicates_deliver_once() {
    let (left, right) = udp_pair().await;
    let (_left_stream, mut sink) = left.split();
    let (mut right_io, fec) = active_io(right);
    let mut stream = right_io.get_stream();
    let originals: Vec<_> = (0..3u8)
        .map(|id| source(id, 50 + usize::from(id)))
        .collect();
    let symbols: Vec<_> = originals
        .iter()
        .map(|packet| {
            let peer = packet.tunnel_payload();
            let mut symbol = (peer.len() as u16).to_le_bytes().to_vec();
            symbol.extend_from_slice(peer);
            symbol
        })
        .collect();
    sink.send(wire::wrap_source(2, &originals[2]))
        .await
        .unwrap();
    sink.send(wire::wrap_source(1, &originals[1]))
        .await
        .unwrap();
    let repair = codec::encode_repair(7, symbols.iter().map(Vec::as_slice));
    sink.send(wire::wrap_repair(0, 3, 7, &repair))
        .await
        .unwrap();
    sink.send(wire::wrap_source(0, &originals[0]))
        .await
        .unwrap();
    sink.send(wire::wrap_source(1, &originals[1]))
        .await
        .unwrap();
    sink.send(marker()).await.unwrap();

    let mut seen = [false; 3];
    for _ in 0..3 {
        let packet = next(&mut stream).await;
        let id = usize::from(packet.payload()[0]);
        assert!(!seen[id], "source {id} delivered twice");
        seen[id] = true;
        assert_eq!(packet.tunnel_payload(), originals[id].tunnel_payload());
    }
    assert_eq!(
        next(&mut stream).await.tunnel_payload(),
        marker().tunnel_payload()
    );
    assert_eq!(seen, [true; 3]);
    assert_eq!(fec.stats().recovered, 1);
    assert_eq!(fec.stats().duplicates, 2);
}

#[tokio::test]
async fn udp_receive_cache_expires_while_downstream_stops_polling() {
    let (left, right) = udp_pair().await;
    let (_left_stream, mut sink) = left.split();
    let (mut right_io, fec) = active_io(right);
    let mut stream = right_io.get_stream();
    let original = source(1, 64);
    sink.send(wire::wrap_source(1, &original)).await.unwrap();
    assert_eq!(
        next(&mut stream).await.tunnel_payload(),
        original.tunnel_payload()
    );
    assert_eq!(
        fec.state
            .lock()
            .rx
            .as_ref()
            .unwrap()
            .decoder
            .active_symbols(),
        1
    );

    // No receive polling is needed for the writer's maintenance timer.
    wait_until(|| {
        fec.state
            .lock()
            .rx
            .as_ref()
            .unwrap()
            .decoder
            .active_symbols()
            == 0
    })
    .await;
    assert!(fec.deadline().is_none());
    right_io.close();
    assert!(
        timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .is_none()
    );
    assert!(fec.state.lock().rx.is_none());
    assert!(!fec.stats().active);
}

#[derive(Default)]
struct WriteGate {
    started: AtomicUsize,
    released: AtomicBool,
    waker: AtomicWaker,
}

struct ControlledTunnel {
    gate: Arc<WriteGate>,
    fail: bool,
}

struct ControlledSink {
    gate: Arc<WriteGate>,
    fail: bool,
}

impl Sink<ZCPacket> for ControlledSink {
    type Error = TunnelError;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), TunnelError>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _: ZCPacket) -> Result<(), TunnelError> {
        self.gate.started.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(TunnelError::Shutdown)
        } else {
            Ok(())
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TunnelError>> {
        self.gate.waker.register(cx.waker());
        if self.gate.released.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), TunnelError>> {
        Poll::Ready(Ok(()))
    }
}

impl Tunnel for ControlledTunnel {
    fn split(&self) -> SplitTunnel {
        (
            Box::pin(futures::stream::pending::<StreamItem>()),
            Box::pin(ControlledSink {
                gate: self.gate.clone(),
                fail: self.fail,
            }),
        )
    }

    fn info(&self) -> Option<TunnelInfo> {
        None
    }
}

#[tokio::test]
async fn blocked_flush_maintains_receive_cache_without_repeating_start_send() {
    let gate = Arc::new(WriteGate::default());
    let (mut io, fec) = active_io(Box::new(ControlledTunnel {
        gate: gate.clone(),
        fail: false,
    }));
    assert!(
        fec.receive(wire::wrap_source(0, &source(9, 32)), Instant::now())
            .is_some()
    );
    io.get_sink().send(source(1, 32)).await.unwrap();
    wait_until(|| gate.started.load(Ordering::SeqCst) == 1).await;
    wait_until(|| {
        fec.state
            .lock()
            .rx
            .as_ref()
            .unwrap()
            .decoder
            .active_symbols()
            == 0
    })
    .await;
    assert_eq!(gate.started.load(Ordering::SeqCst), 1);
    assert_eq!(fec.stats().tx_sources, 0);

    gate.released.store(true, Ordering::SeqCst);
    gate.waker.wake();
    wait_until(|| fec.stats().tx_sources == 1).await;
    io.close();
    assert!(fec.state.lock().rx.is_none());
}

#[tokio::test]
async fn failed_write_closes_receive_stream_and_does_not_commit_source() {
    let gate = Arc::new(WriteGate::default());
    let (mut io, fec) = active_io(Box::new(ControlledTunnel {
        gate: gate.clone(),
        fail: true,
    }));
    let mut stream = io.get_stream();
    let sender = io.get_sink();
    sender.send(source(1, 32)).await.unwrap();
    assert!(
        timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(gate.started.load(Ordering::SeqCst), 1);
    assert_eq!(fec.stats().tx_sources, 0);
    assert!(fec.state.lock().rx.is_none());
    assert!(sender.send(source(2, 32)).await.is_err());
}
