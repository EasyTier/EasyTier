use std::{collections::VecDeque, sync::Arc};

use crate::{
    config::FecConfig,
    foundation::time::{Duration, Instant},
    packet::{FEC_MAX_OVERHEAD, UDP_TUNNEL_HEADER_SIZE, ZCPacket},
};

use super::{
    budget::{Account, Reservation},
    codec::{self, WINDOW},
    feedback::Report,
    stats::{Counters, add},
    wire::{self, Header},
};

const WINDOW_LIFETIME: Duration = Duration::from_millis(100);
const TAIL_DELAY: Duration = Duration::from_millis(5);
const MIN_REPORT_SAMPLES: u64 = 32;
const LOSS_WINDOW_SAMPLES: u64 = 256;
const REPORT_HISTORY_CAPACITY: usize = (LOSS_WINDOW_SAMPLES / MIN_REPORT_SAMPLES) as usize + 1;

struct Source {
    id: u64,
    symbol: Vec<u8>,
    accepted_at: Instant,
    _reservation: Reservation,
}

pub(super) enum Accepted {
    Source { bytes: usize, sequence: u64 },
    Repair { bytes: usize, sequence: u64 },
    Feedback { bytes: usize },
}

pub(super) struct PendingSend {
    pub packet: ZCPacket,
    pub accepted: Option<Accepted>,
    pub reservation: Option<Reservation>,
}

impl PendingSend {
    pub fn passthrough(packet: ZCPacket) -> Self {
        Self {
            packet,
            accepted: None,
            reservation: None,
        }
    }
}

pub(super) struct Tx {
    config: FecConfig,
    account: Arc<Account>,
    stats: Arc<Counters>,
    sources: VecDeque<Source>,
    // Feedback can arrive after the coding window expires. Retain only recent
    // lengths for the byte-rate estimate, independently of source payloads.
    source_lengths: VecDeque<usize>,
    pending: Option<Source>,
    next_source: u64,
    next_sequence: u64,
    next_repair: u32,
    highest_accepted: Option<u64>,
    repair_due: bool,
    // Hundredths of a byte. Only accepted sources refill this bounded bucket.
    credit: u64,
    credit_limit: u64,
    // Only an uncovered tail can spend this absolute allowance. Bulk repairs
    // continue to use source-byte credit, even when the writer stays busy.
    tail_credit: u64,
    tail_credit_updated: Option<Instant>,
    tail_deadline: Option<Instant>,
    rate: u32,
    report: Report,
    report_history: VecDeque<Report>,
    _reservation: Reservation,
}

impl Tx {
    pub fn new(
        config: FecConfig,
        account: Arc<Account>,
        stats: Arc<Counters>,
    ) -> anyhow::Result<Self> {
        let reservation = account
            .reserve(
                WINDOW * (std::mem::size_of::<Source>() + std::mem::size_of::<usize>())
                    + REPORT_HISTORY_CAPACITY * std::mem::size_of::<Report>()
                    + 4096,
            )
            .ok_or_else(|| anyhow::anyhow!("FEC transmit state budget exhausted"))?;
        let credit_limit = u64::from(config.udp_payload_mtu) * 2 * 100;
        let rate = config.max_repair_percent;
        let mut report_history = VecDeque::with_capacity(REPORT_HISTORY_CAPACITY);
        report_history.push_back(Report::default());
        Ok(Self {
            config,
            account,
            stats,
            sources: VecDeque::with_capacity(WINDOW),
            source_lengths: VecDeque::with_capacity(WINDOW),
            pending: None,
            next_source: 0,
            next_sequence: 0,
            next_repair: 0,
            highest_accepted: None,
            repair_due: false,
            credit: credit_limit,
            credit_limit,
            tail_credit: 0,
            tail_credit_updated: None,
            tail_deadline: None,
            rate,
            report: Report::default(),
            report_history,
            _reservation: reservation,
        })
    }

    pub fn active_symbols(&self) -> usize {
        self.sources.len() + usize::from(self.pending.is_some())
    }
    pub fn rate(&self) -> u32 {
        self.rate
    }

    pub fn prepare(&mut self, packet: ZCPacket, now: Instant) -> PendingSend {
        let payload = packet.tunnel_payload();
        if !wire::eligible_peer(payload) {
            add(&self.stats.bypass_ineligible, 1);
            return PendingSend::passthrough(packet);
        }
        if payload.len() > self.config.udp_payload_mtu as usize - FEC_MAX_OVERHEAD {
            add(&self.stats.bypass_oversize, 1);
            return PendingSend::passthrough(packet);
        }
        self.on_deadline(now);
        if self.pending.is_some() || self.next_source == u64::MAX || self.next_sequence == u64::MAX
        {
            return PendingSend::passthrough(packet);
        }
        if self.sources.len() == WINDOW {
            self.sources.pop_front();
        }
        let bytes = wire::OVERHEAD + payload.len();
        let Some(mut reservation) = self.account.reserve(payload.len() + 2 + 64 + bytes + 64)
        else {
            add(&self.stats.resource_drops, 1);
            return PendingSend::passthrough(packet);
        };
        let source = self.next_source;
        let sequence = self.next_sequence;
        let encoded = wire::encode(
            Header {
                kind: wire::SOURCE,
                sequence,
                source,
                repair: 0,
                count: 0,
            },
            payload,
        );
        let mut symbol = Vec::with_capacity(payload.len() + 2);
        symbol.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        symbol.extend_from_slice(payload);
        let frame_reservation = reservation.split(bytes + 64);
        self.pending = Some(Source {
            id: source,
            symbol,
            accepted_at: now,
            _reservation: reservation,
        });
        self.next_source += 1;
        self.next_sequence += 1;
        PendingSend {
            packet: encoded,
            accepted: Some(Accepted::Source { bytes, sequence }),
            reservation: Some(frame_reservation),
        }
    }

    pub fn on_accepted(&mut self, accepted: Accepted, now: Instant) {
        match accepted {
            Accepted::Source { bytes, sequence } => {
                let Some(mut source) = self.pending.take() else {
                    return;
                };
                let baseline = source.symbol.len() - 2 + UDP_TUNNEL_HEADER_SIZE;
                self.credit =
                    (self.credit + baseline as u64 * u64::from(self.rate)).min(self.credit_limit);
                if self.source_lengths.len() == WINDOW {
                    self.source_lengths.pop_front();
                }
                self.source_lengths.push_back(source.symbol.len());
                source.accepted_at = now;
                self.sources.push_back(source);
                self.highest_accepted = Some(sequence);
                self.repair_due = true;
                self.tail_credit_updated.get_or_insert(now);
                self.tail_deadline = Some(now + TAIL_DELAY);
                add(&self.stats.tx_source_packets, 1);
                add(&self.stats.tx_source_bytes, bytes);
                add(&self.stats.tx_source_baseline_bytes, baseline);
            }
            Accepted::Repair { bytes, sequence } => {
                self.highest_accepted = Some(sequence);
                add(&self.stats.tx_repair_packets, 1);
                add(&self.stats.tx_repair_bytes, bytes);
            }
            Accepted::Feedback { .. } => unreachable!("feedback belongs to the connection"),
        }
    }

    pub fn next_repair(&mut self, now: Instant) -> Option<PendingSend> {
        self.on_deadline(now);
        if self.pending.is_some() || self.sources.is_empty() {
            return None;
        }
        let due = std::mem::take(&mut self.repair_due);
        let tail_due = self.tail_deadline.is_some_and(|deadline| now >= deadline);
        if !due && !tail_due {
            return None;
        }
        let len = self.sources.iter().map(|s| s.symbol.len()).max()?;
        let bytes = wire::OVERHEAD + len;
        let cost = bytes as u64 * 100;
        let tail = !(due && self.rate != 0 && self.credit >= cost);
        if tail {
            if due {
                add(&self.stats.no_credit_repairs, 1);
            }
            if !tail_due {
                return None;
            }
            self.tail_deadline = None;
            let updated = self.tail_credit_updated.replace(now).unwrap_or(now);
            let elapsed = now
                .saturating_duration_since(updated)
                .min(Duration::from_secs(2));
            let refill =
                u64::from(self.config.udp_payload_mtu) * elapsed.as_nanos() as u64 / 10_000_000;
            self.tail_credit = (self.tail_credit + refill).min(self.credit_limit);
            if self.tail_credit < cost {
                // Wait only while the newest source remains recoverable. This
                // deadline is never part of maintenance during a blocked send.
                let wait_ns = ((cost - self.tail_credit) * 10_000_000)
                    .div_ceil(u64::from(self.config.udp_payload_mtu));
                let ready = now + Duration::from_nanos(wait_ns);
                let expires = self.sources.back()?.accepted_at + WINDOW_LIFETIME;
                self.tail_deadline = (ready < expires).then_some(ready);
                add(&self.stats.no_credit_repairs, 1);
                return None;
            }
        }
        if self.next_sequence == u64::MAX {
            return None;
        }
        // Admission precedes coding. No queued repair can expire after wasting
        // encoding work. A repair covers the newest source and consumes its
        // tail opportunity as well as any immediate repair opportunity.
        let Some(mut reservation) = self.account.reserve(len + bytes + 128) else {
            add(&self.stats.resource_drops, 1);
            return None;
        };
        let vector = codec::encode_repair(
            self.next_repair,
            self.sources.iter().map(|s| s.symbol.as_slice()),
        );
        let sequence = self.next_sequence;
        let packet = wire::encode(
            Header {
                kind: wire::REPAIR,
                sequence,
                source: self.sources.front()?.id,
                repair: self.next_repair,
                count: self.sources.len() as u8,
            },
            &vector,
        );
        self.next_repair = self.next_repair.wrapping_add(1);
        self.next_sequence += 1;
        if tail {
            self.tail_credit -= cost;
        } else {
            self.credit -= cost;
        }
        self.tail_deadline = None;
        Some(PendingSend {
            packet,
            accepted: Some(Accepted::Repair { bytes, sequence }),
            reservation: Some(reservation.split(bytes + 64)),
        })
    }

    /// A report is an untrusted statistical hint, bounded by locally accepted
    /// sequence numbers and the configured byte budget. It cannot affect routes.
    pub fn apply_report(&mut self, report: Report) {
        if self
            .highest_accepted
            .is_none_or(|highest| report.highest > highest)
            || report.highest < self.report.highest
            || report.samples <= self.report.samples
            || report.samples > report.highest + 1
            || report.lost < self.report.lost
        {
            return;
        }
        let samples = report.samples - self.report.samples;
        let lost = report.lost - self.report.lost;
        if samples < MIN_REPORT_SAMPLES || lost > samples {
            return;
        }
        let Some(symbol_len) = self.source_lengths.iter().copied().max() else {
            return;
        };
        // Keep at least one loss-estimation window, aligned to cumulative
        // report boundaries. A small clean batch must not erase recent loss.
        while self.report_history.len() > 1
            && report.samples - self.report_history[1].samples >= LOSS_WINDOW_SAMPLES
        {
            self.report_history.pop_front();
        }
        let oldest = self.report_history.front().unwrap();
        let recent_samples = report.samples - oldest.samples;
        let recent_lost = report.lost - oldest.lost;
        // No useful parity estimate is available when all settled samples were
        // lost. Retain the rate; existing PeerConn liveness owns link failure.
        let target = if lost == samples {
            self.rate
        } else if recent_lost == 0 {
            0
        } else {
            // Loss is measured in packets, but credit is measured in bytes.
            // A repair is padded to the largest symbol, so mixed packet sizes
            // need more byte credit for the same number of repair equations.
            let baseline: usize = self
                .source_lengths
                .iter()
                .map(|len| len - 2 + UDP_TUNNEL_HEADER_SIZE)
                .sum();
            let received = u128::from(recent_samples - recent_lost);
            let numerator = (u128::from(recent_lost) * 125 + received * 2)
                * (wire::OVERHEAD + symbol_len) as u128
                * self.source_lengths.len() as u128;
            numerator
                .div_ceil(received * baseline as u128)
                .min(u128::from(self.config.max_repair_percent)) as u32
        };
        self.report = report;
        self.report_history.push_back(report);
        self.rate = if target > self.rate {
            (self.rate + 10).min(target)
        } else {
            self.rate.saturating_sub(5).max(target)
        };
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.sources
            .front()
            .map(|s| s.accepted_at + WINDOW_LIFETIME)
    }

    pub fn repair_deadline(&self) -> Option<Instant> {
        self.tail_deadline
    }

    pub fn on_deadline(&mut self, now: Instant) {
        while self
            .sources
            .front()
            .is_some_and(|s| now >= s.accepted_at + WINDOW_LIFETIME)
        {
            self.sources.pop_front();
        }
        if self.sources.is_empty() {
            self.repair_due = false;
            self.tail_deadline = None;
        }
    }
}
