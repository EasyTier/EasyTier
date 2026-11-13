//! Connection-local UDP erasure recovery. Original data is delivered without
//! waiting for a coding batch; repair packets cover a bounded sliding window.

mod codec;
mod io;
mod send;
mod wire;

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;

#[cfg(test)]
mod bench;

use std::collections::VecDeque;

use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::{
    foundation::{
        stats::{CounterHandle, LabelSet, LabelType, MetricName, StatsManager},
        time::Instant,
    },
    packet::{PacketType, UDP_TUNNEL_HEADER_SIZE, ZCPacket},
    proto::{common::Flags, core_peer::peer::PeerConnFecStats},
    socket::udp::MAX_UDP_SESSION_DATAGRAM_SIZE,
};

pub(crate) use io::PeerConnFecIo;

pub(crate) const FEATURE: &str = "udp-fec-v1";
const ENABLED_FEATURE: &str = "udp-fec-enabled";
const KCP_FEATURE: &str = "udp-fec-kcp";
const QUIC_FEATURE: &str = "udp-fec-quic";
// A passive endpoint and forwarded traffic need not use the local TUN MTU.
// Bound the actual frame by the UDP session limit, not by the local MTU.
// This is a datagram limit, not a guarantee about the underlay path MTU.
const MAX_SYMBOL_SIZE: usize =
    MAX_UDP_SESSION_DATAGRAM_SIZE - UDP_TUNNEL_HEADER_SIZE - wire::REPAIR_HEADER_SIZE;
const DELIVERY_WINDOW: usize = 1024;
const EARLY_PACKET_LIMIT: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Waiting,
    Active,
    Disabled,
    Closed,
}

struct DeliveryWindow {
    highest: Option<u64>,
    ids: Box<[Option<u64>]>,
}

impl DeliveryWindow {
    fn new() -> Self {
        Self {
            highest: None,
            ids: vec![None; DELIVERY_WINDOW].into_boxed_slice(),
        }
    }

    fn insert(&mut self, id: u64) -> bool {
        if self
            .highest
            .is_some_and(|highest| id < highest.saturating_sub((DELIVERY_WINDOW - 1) as u64))
        {
            return false;
        }
        let slot = id as usize % DELIVERY_WINDOW;
        if self.ids[slot] == Some(id) {
            return false;
        }
        self.ids[slot] = Some(id);
        self.highest = Some(self.highest.map_or(id, |highest| highest.max(id)));
        true
    }
}

struct Rx {
    decoder: codec::Decoder,
    delivered: DeliveryWindow,
    early: VecDeque<(Instant, ZCPacket)>,
}

impl Rx {
    fn new() -> Self {
        Self {
            decoder: codec::Decoder::new(MAX_SYMBOL_SIZE),
            delivered: DeliveryWindow::new(),
            early: VecDeque::new(),
        }
    }
}

struct State {
    phase: Phase,
    rx: Option<Rx>,
    encode_kcp: bool,
    encode_quic: bool,
    stats: PeerConnFecStats,
    metrics: Option<PeerConnFecMetrics>,
}

pub(crate) struct PeerConnFecMetrics {
    tx_sources: CounterHandle,
    tx_source_bytes: CounterHandle,
    tx_repairs: CounterHandle,
    tx_repair_bytes: CounterHandle,
    rx_sources: CounterHandle,
    rx_source_bytes: CounterHandle,
    rx_repairs: CounterHandle,
    rx_repair_bytes: CounterHandle,
    recovered: CounterHandle,
}

impl PeerConnFecMetrics {
    pub(crate) fn new(stats_manager: &StatsManager, network_name: String) -> Self {
        let labels = LabelSet::new().with_label_type(LabelType::NetworkName(network_name));
        let counter = |name| stats_manager.get_counter(name, labels.clone());
        Self {
            tx_sources: counter(MetricName::UdpFecSourcePacketsTx),
            tx_source_bytes: counter(MetricName::UdpFecSourceBytesTx),
            tx_repairs: counter(MetricName::UdpFecRepairPacketsTx),
            tx_repair_bytes: counter(MetricName::UdpFecRepairBytesTx),
            rx_sources: counter(MetricName::UdpFecSourcePacketsRx),
            rx_source_bytes: counter(MetricName::UdpFecSourceBytesRx),
            rx_repairs: counter(MetricName::UdpFecRepairPacketsRx),
            rx_repair_bytes: counter(MetricName::UdpFecRepairBytesRx),
            recovered: counter(MetricName::UdpFecPacketsRecovered),
        }
    }
}

pub(crate) struct PeerConnFec {
    state: Mutex<State>,
    writer_wake: Notify,
    reader_wake: AtomicWaker,
    local_features: Vec<String>,
}

impl PeerConnFec {
    pub(crate) fn new(flags: &Flags, metrics: Option<PeerConnFecMetrics>) -> Self {
        let mut local_features = vec![FEATURE.to_owned()];
        for (enabled, feature) in [
            (flags.enable_udp_fec, ENABLED_FEATURE),
            (flags.enable_udp_fec_kcp, KCP_FEATURE),
            (flags.enable_udp_fec_quic, QUIC_FEATURE),
        ] {
            if enabled {
                local_features.push(feature.to_owned());
            }
        }
        Self {
            state: Mutex::new(State {
                phase: Phase::Waiting,
                // Every UDP connection can negotiate FEC, but ordinary
                // connections do not allocate a decoder or delivery window.
                rx: None,
                encode_kcp: flags.enable_udp_fec_kcp,
                encode_quic: flags.enable_udp_fec_quic,
                stats: PeerConnFecStats::default(),
                metrics,
            }),
            writer_wake: Notify::new(),
            reader_wake: AtomicWaker::new(),
            local_features,
        }
    }

    pub(crate) fn local_features(&self) -> &[String] {
        &self.local_features
    }

    pub(crate) fn set_remote_features(&self, features: &[String]) {
        let mut state = self.state.lock();
        if state.phase != Phase::Waiting {
            return;
        }
        // Capability is independent of policy. Either endpoint can request
        // bidirectional protection, but an older peer must never see FEC frames.
        let supports = features.iter().any(|feature| feature == FEATURE);
        let requested = self
            .local_features
            .iter()
            .chain(features)
            .any(|feature| feature == ENABLED_FEATURE);
        if supports && requested {
            state.phase = Phase::Active;
            state.rx.get_or_insert_with(Rx::new);
            state.encode_kcp |= features.iter().any(|feature| feature == KCP_FEATURE);
            state.encode_quic |= features.iter().any(|feature| feature == QUIC_FEATURE);
            state.stats.active = true;
        } else {
            state.phase = Phase::Disabled;
            state.rx = None;
        }
        drop(state);
        self.writer_wake.notify_one();
        self.reader_wake.wake();
    }

    pub(crate) fn stats(&self) -> PeerConnFecStats {
        self.state.lock().stats
    }

    fn active(&self) -> bool {
        self.state.lock().phase == Phase::Active
    }

    fn should_encode(&self, packet: &ZCPacket) -> bool {
        let Some(header) = packet.peer_manager_header() else {
            return false;
        };
        let state = self.state.lock();
        state.phase == Phase::Active
            && match header.packet_type {
                kind if kind == PacketType::Data as u8 => true,
                kind if kind == PacketType::KcpSrc as u8 || kind == PacketType::KcpDst as u8 => {
                    state.encode_kcp
                }
                kind if kind == PacketType::QuicSrc as u8 || kind == PacketType::QuicDst as u8 => {
                    state.encode_quic
                }
                _ => false,
            }
    }

    fn closed(&self) -> bool {
        self.state.lock().phase == Phase::Closed
    }

    fn close(&self) {
        let mut state = self.state.lock();
        state.phase = Phase::Closed;
        state.stats.active = false;
        state.rx = None;
        drop(state);
        self.reader_wake.wake();
        self.writer_wake.notify_one();
    }

    fn deadline(&self) -> Option<Instant> {
        let state = self.state.lock();
        let rx = state.rx.as_ref()?;
        rx.decoder
            .deadline()
            .into_iter()
            .chain(
                rx.early
                    .front()
                    .map(|(at, _)| *at + codec::RECOVERY_LIFETIME),
            )
            .min()
    }

    fn expire(&self, now: Instant) {
        let mut state = self.state.lock();
        if let Some(rx) = state.rx.as_mut() {
            rx.decoder.expire(now);
            while rx
                .early
                .front()
                .is_some_and(|(at, _)| *at + codec::RECOVERY_LIFETIME <= now)
            {
                rx.early.pop_front();
            }
        }
    }

    fn receive(&self, packet: ZCPacket, now: Instant) -> Option<ZCPacket> {
        let mut state = self.state.lock();
        if wire::classify(&packet) == wire::FrameKind::Invalid {
            state.stats.invalid_packets += 1;
            return None;
        }
        let result = match state.phase {
            Phase::Active => Self::decode(&mut state, packet, now),
            Phase::Waiting => {
                // A datagram may overtake the last handshake packet. Keep a
                // bounded queue while allowing handshake/control packets through.
                if packet.tunnel_payload().len()
                    <= MAX_UDP_SESSION_DATAGRAM_SIZE - UDP_TUNNEL_HEADER_SIZE
                {
                    let rx = state.rx.get_or_insert_with(Rx::new);
                    if rx.early.len() < EARLY_PACKET_LIMIT {
                        rx.early.push_back((now, packet));
                    }
                }
                None
            }
            Phase::Disabled | Phase::Closed => None,
        };
        drop(state);
        self.writer_wake.notify_one();
        result
    }

    fn decode(state: &mut State, packet: ZCPacket, now: Instant) -> Option<ZCPacket> {
        let rx = state.rx.as_mut()?;
        rx.decoder.expire(now);
        if wire::classify(&packet) == wire::FrameKind::Source {
            let Some((id, peer)) = wire::parse_source(&packet, MAX_SYMBOL_SIZE) else {
                state.stats.invalid_packets += 1;
                return None;
            };
            state.stats.rx_sources += 1;
            if let Some(metrics) = &state.metrics {
                metrics.rx_sources.inc();
                metrics
                    .rx_source_bytes
                    .add(packet.tunnel_payload().len() as u64);
            }
            rx.decoder.source(id, peer, now);
            if rx.delivered.insert(id) {
                wire::restore_peer(peer)
            } else {
                state.stats.duplicates += 1;
                None
            }
        } else {
            let Some((first, count, repair, symbol)) = wire::parse_repair(&packet, MAX_SYMBOL_SIZE)
            else {
                state.stats.invalid_packets += 1;
                return None;
            };
            state.stats.rx_repairs += 1;
            if let Some(metrics) = &state.metrics {
                metrics.rx_repairs.inc();
                metrics
                    .rx_repair_bytes
                    .add(packet.tunnel_payload().len() as u64);
            }
            rx.decoder.repair(first, count, repair, symbol, now);
            None
        }
    }

    fn take_received(&self, now: Instant) -> Option<ZCPacket> {
        let mut state = self.state.lock();
        if state.phase != Phase::Active {
            return None;
        }
        loop {
            let rx = state.rx.as_mut()?;
            rx.decoder.expire(now);
            while let Some((id, peer, _)) = rx.decoder.take_recovered() {
                let Some(packet) = wire::restore_peer(peer) else {
                    continue;
                };
                if rx.delivered.insert(id) {
                    state.stats.recovered += 1;
                    if let Some(metrics) = &state.metrics {
                        metrics.recovered.inc();
                    }
                    return Some(packet);
                }
            }
            let (at, packet) = rx.early.pop_front()?;
            if at + codec::RECOVERY_LIFETIME <= now {
                continue;
            }
            if let Some(packet) = Self::decode(&mut state, packet, at) {
                return Some(packet);
            }
        }
    }
}
