use std::collections::VecDeque;

use crate::{
    foundation::time::{Duration, Instant},
    packet::ZCPacket,
};

use super::{codec, wire};

const BATCH_SIZE: usize = 10;
const BATCH_DELAY: Duration = Duration::from_millis(20);
const SOURCE_LIFETIME: Duration = Duration::from_millis(100);

struct Source {
    id: u64,
    symbol: Vec<u8>,
    accepted_at: Instant,
}

pub(super) struct Tx {
    max_symbol_len: usize,
    sources: VecDeque<Source>,
    next_source: u64,
    next_repair: u32,
    exhausted: bool,
    batch_sources: usize,
    batch_repairs: usize,
    batch_started: Option<Instant>,
}

impl Tx {
    pub fn new(max_symbol_len: usize) -> Self {
        Self {
            max_symbol_len: max_symbol_len.min(u16::MAX as usize + 2),
            sources: VecDeque::with_capacity(codec::WINDOW),
            next_source: 0,
            next_repair: 0,
            exhausted: false,
            batch_sources: 0,
            batch_repairs: 0,
            batch_started: None,
        }
    }

    /// Preparing a source does not consume its ID or repair allowance. The
    /// writer commits it only after the underlying sink accepts the frame.
    pub fn prepare(&self, packet: &ZCPacket) -> Option<(u64, ZCPacket)> {
        packet.peer_manager_header()?;
        let peer = packet.tunnel_payload();
        if self.exhausted
            || self.next_source == u64::MAX
            || peer.len() + 2 > self.max_symbol_len
            || !wire::eligible_peer(peer)
        {
            return None;
        }
        Some((
            self.next_source,
            wire::wrap_source(self.next_source, packet),
        ))
    }

    pub fn accepted(&mut self, id: u64, peer: &[u8], now: Instant) {
        debug_assert_eq!(id, self.next_source);
        debug_assert!(self.batch_sources < BATCH_SIZE);
        self.expire(now);
        let mut symbol = Vec::with_capacity(peer.len() + 2);
        symbol.extend_from_slice(&(peer.len() as u16).to_le_bytes());
        symbol.extend_from_slice(peer);
        if self.sources.len() == codec::WINDOW {
            self.sources.pop_front();
        }
        self.sources.push_back(Source {
            id,
            symbol,
            accepted_at: now,
        });
        self.next_source = id + 1;
        self.batch_sources += 1;
        self.batch_started.get_or_insert(now);
    }

    pub fn repairs_due(&self, now: Instant) -> bool {
        self.batch_sources == BATCH_SIZE
            || self.batch_sources / 5 > self.batch_repairs
            || self
                .batch_started
                .is_some_and(|start| start + BATCH_DELAY <= now)
    }

    pub fn take_repairs(&mut self, now: Instant) -> Vec<ZCPacket> {
        self.expire(now);
        if !self.repairs_due(now) {
            return Vec::new();
        }
        let finished = self.batch_sources == BATCH_SIZE
            || self
                .batch_started
                .is_some_and(|start| start + BATCH_DELAY <= now);
        let total = if finished {
            // Preserve prompt tail protection without waiting for more sources.
            self.batch_sources.div_ceil(5)
        } else {
            // Spend each whole repair allowance as soon as it is available.
            self.batch_sources / 5
        };
        let count = total - self.batch_repairs;
        self.batch_repairs = total;
        if finished {
            self.batch_sources = 0;
            self.batch_repairs = 0;
            self.batch_started = None;
        }
        let Some(first) = self.sources.front().map(|source| source.id) else {
            return Vec::new();
        };
        let Some(next_repair) = self.next_repair.checked_add(count as u32) else {
            self.exhausted = true;
            self.sources.clear();
            self.batch_sources = 0;
            self.batch_repairs = 0;
            self.batch_started = None;
            return Vec::new();
        };
        let mut repairs = Vec::with_capacity(count);
        for repair in self.next_repair..next_repair {
            let symbol = codec::encode_repair(
                repair,
                self.sources.iter().map(|source| source.symbol.as_slice()),
            );
            repairs.push(wire::wrap_repair(
                first,
                self.sources.len(),
                repair,
                &symbol,
            ));
        }
        self.next_repair = next_repair;
        repairs
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.batch_started
            .map(|start| start + BATCH_DELAY)
            .into_iter()
            .chain(
                self.sources
                    .front()
                    .map(|source| source.accepted_at + SOURCE_LIFETIME),
            )
            .min()
    }

    pub fn expiry_deadline(&self) -> Option<Instant> {
        self.sources
            .front()
            .map(|source| source.accepted_at + SOURCE_LIFETIME)
    }

    pub fn expire(&mut self, now: Instant) {
        while self
            .sources
            .front()
            .is_some_and(|source| source.accepted_at + SOURCE_LIFETIME <= now)
        {
            self.sources.pop_front();
        }
    }

    #[cfg(test)]
    pub fn cached_bytes(&self) -> usize {
        self.sources
            .iter()
            .map(|source| source.symbol.capacity())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketType;

    fn source(value: u8) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&[value; 32]);
        packet.fill_peer_manager_hdr(11, 22, PacketType::Data as u8);
        packet
    }

    fn accept(tx: &mut Tx, value: u8, now: Instant) {
        let packet = source(value);
        let (id, _) = tx.prepare(&packet).unwrap();
        tx.accepted(id, packet.tunnel_payload(), now);
    }

    #[test]
    fn source_is_immediate_and_batch_deadline_does_not_slide() {
        let mut tx = Tx::new(1400);
        let now = Instant::now();
        let packet = source(1);
        let (id, frame) = tx.prepare(&packet).unwrap();
        assert_eq!(
            wire::parse_source(&frame, 1400).unwrap(),
            (id, packet.tunnel_payload())
        );
        assert_eq!(tx.deadline(), None);
        assert_eq!(tx.prepare(&packet).unwrap().0, id);
        tx.accepted(id, packet.tunnel_payload(), now);
        accept(&mut tx, 2, now + Duration::from_millis(19));
        assert_eq!(tx.deadline(), Some(now + BATCH_DELAY));
        assert!(tx.take_repairs(now + Duration::from_millis(19)).is_empty());
        assert_eq!(tx.take_repairs(now + BATCH_DELAY).len(), 1);
        assert!(tx.take_repairs(now + BATCH_DELAY).is_empty());
        assert!(tx.take_repairs(now + Duration::from_millis(99)).is_empty());
    }

    #[test]
    fn new_sources_determine_repair_count_while_windows_overlap() {
        let mut tx = Tx::new(1400);
        let now = Instant::now();
        for batch in 0..3 {
            for index in 0..BATCH_SIZE {
                accept(&mut tx, (batch * BATCH_SIZE + index) as u8, now);
            }
            let repairs = tx.take_repairs(now);
            assert_eq!(repairs.len(), 2);
            for repair in repairs {
                let (first, count, _, _) = wire::parse_repair(&repair, 1400).unwrap();
                assert_eq!(count, ((batch + 1) * BATCH_SIZE).min(codec::WINDOW));
                assert_eq!(
                    first,
                    ((batch + 1) * BATCH_SIZE).saturating_sub(codec::WINDOW) as u64
                );
            }
        }
        accept(&mut tx, 31, now);
        let repairs = tx.take_repairs(now + BATCH_DELAY);
        assert_eq!(repairs.len(), 1);
        assert_eq!(
            wire::parse_repair(&repairs[0], 1400).unwrap().1,
            codec::WINDOW
        );
    }

    #[test]
    fn expiry_limits_history_and_does_not_create_idle_repairs() {
        let mut tx = Tx::new(1400);
        let now = Instant::now();
        accept(&mut tx, 1, now);
        assert_eq!(tx.take_repairs(now + BATCH_DELAY).len(), 1);
        tx.expire(now + SOURCE_LIFETIME);
        assert_eq!(tx.cached_bytes(), 0);
        assert_eq!(tx.deadline(), None);
        assert!(tx.take_repairs(now + SOURCE_LIFETIME).is_empty());
        accept(&mut tx, 2, now + SOURCE_LIFETIME);
        let repair = tx.take_repairs(now + SOURCE_LIFETIME + BATCH_DELAY);
        assert_eq!(wire::parse_repair(&repair[0], 1400).unwrap().0, 1);
        assert_eq!(wire::parse_repair(&repair[0], 1400).unwrap().1, 1);
    }

    #[test]
    fn repair_recovers_before_the_batch_is_full_at_the_same_total_cost() {
        let mut tx = Tx::new(1400);
        let mut rx = codec::Decoder::new(1400);
        let now = Instant::now();
        let mut sent = 0;
        for id in 0..BATCH_SIZE {
            let at = now + Duration::from_millis(id as u64);
            let packet = source(id as u8);
            tx.accepted(id as u64, packet.tunnel_payload(), at);
            if id != 0 {
                rx.source(id as u64, packet.tunnel_payload(), at);
            }
            let repairs = tx.take_repairs(at);
            assert_eq!(repairs.len(), usize::from(id == 4 || id == 9));
            sent += repairs.len();
            for repair in repairs {
                let (first, count, sequence, symbol) = wire::parse_repair(&repair, 1400).unwrap();
                rx.repair(first, count, sequence, symbol, at);
            }
            if id == 4 {
                let (recovered, peer, _) = rx.take_recovered().unwrap();
                assert_eq!(recovered, 0);
                assert_eq!(peer, source(0).tunnel_payload());
            } else {
                assert!(rx.take_recovered().is_none());
            }
        }
        assert_eq!(sent, 2);
        assert!(tx.take_repairs(now + BATCH_DELAY).is_empty());
    }

    #[test]
    fn timeout_only_completes_the_unsent_tail_allowance() {
        for sources in 1..BATCH_SIZE {
            let mut tx = Tx::new(1400);
            let now = Instant::now();
            let mut sent = 0;
            for id in 0..sources {
                let at = now + Duration::from_millis(id as u64);
                accept(&mut tx, id as u8, at);
                sent += tx.take_repairs(at).len();
            }
            assert_eq!(sent, sources / 5);
            sent += tx.take_repairs(now + BATCH_DELAY).len();
            assert_eq!(sent, sources.div_ceil(5));
            assert_eq!(tx.batch_sources, 0);
            assert!(tx.take_repairs(now + BATCH_DELAY * 2).is_empty());
        }
    }

    #[test]
    fn early_repair_id_exhaustion_clears_the_pending_batch() {
        let mut tx = Tx::new(1400);
        let now = Instant::now();
        tx.next_repair = u32::MAX;
        for id in 0..5 {
            accept(&mut tx, id, now);
        }
        assert!(tx.take_repairs(now).is_empty());
        assert!(tx.exhausted);
        assert_eq!(tx.cached_bytes(), 0);
        assert_eq!(tx.deadline(), None);
        assert!(tx.prepare(&source(6)).is_none());
    }

    #[test]
    fn delayed_writer_drops_expired_work_and_never_wraps_source_ids() {
        let mut tx = Tx::new(1400);
        let now = Instant::now();
        accept(&mut tx, 1, now);
        assert!(tx.take_repairs(now + SOURCE_LIFETIME).is_empty());
        assert_eq!(tx.deadline(), None);
        tx.next_source = u64::MAX - 1;
        accept(&mut tx, 2, now + SOURCE_LIFETIME);
        assert!(tx.prepare(&source(3)).is_none());
        assert_eq!(
            tx.take_repairs(now + SOURCE_LIFETIME + BATCH_DELAY).len(),
            1
        );
    }

    #[test]
    fn partial_batch_rounding_and_exhausted_repair_ids_are_bounded() {
        let now = Instant::now();
        let mut tx = Tx::new(1400);
        for value in 0..6 {
            accept(&mut tx, value, now);
        }
        assert_eq!(tx.take_repairs(now + BATCH_DELAY).len(), 2);
        assert!(tx.take_repairs(now + BATCH_DELAY).is_empty());

        tx.next_repair = u32::MAX;
        accept(&mut tx, 7, now + BATCH_DELAY);
        assert!(tx.take_repairs(now + BATCH_DELAY + BATCH_DELAY).is_empty());
        assert_eq!(tx.cached_bytes(), 0);
        assert_eq!(tx.deadline(), None);
        assert!(tx.prepare(&source(8)).is_none());
    }

    #[test]
    fn oversized_and_control_packets_do_not_consume_source_ids() {
        let packet = source(1);
        let tx = Tx::new(packet.tunnel_payload().len() + 1);
        assert!(tx.prepare(&packet).is_none());
        let tx = Tx::new(1400);
        let mut control = packet;
        control.mut_peer_manager_header().unwrap().packet_type = PacketType::Ping as u8;
        assert!(tx.prepare(&control).is_none());
        assert_eq!(tx.prepare(&source(2)).unwrap().0, 0);
    }
}
