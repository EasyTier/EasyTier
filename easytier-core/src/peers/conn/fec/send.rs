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
    pending: Option<Source>,
    next_source: u64,
    next_sequence: u64,
    next_repair: u32,
    highest_accepted: Option<u64>,
    repair_due: bool,
    // Hundredths of a byte. Only accepted sources refill this bounded bucket.
    credit: u64,
    credit_limit: u64,
    rate: u32,
    report: Report,
    _reservation: Reservation,
}

impl Tx {
    pub fn new(
        config: FecConfig,
        account: Arc<Account>,
        stats: Arc<Counters>,
    ) -> anyhow::Result<Self> {
        let reservation = account
            .reserve(WINDOW * std::mem::size_of::<Source>() + 4096)
            .ok_or_else(|| anyhow::anyhow!("FEC transmit state budget exhausted"))?;
        let credit_limit = u64::from(config.udp_payload_mtu) * 2 * 100;
        let rate = config.max_repair_percent;
        Ok(Self {
            config,
            account,
            stats,
            sources: VecDeque::with_capacity(WINDOW),
            pending: None,
            next_source: 0,
            next_sequence: 0,
            next_repair: 0,
            highest_accepted: None,
            repair_due: false,
            credit: credit_limit,
            credit_limit,
            rate,
            report: Report::default(),
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
                source.accepted_at = now;
                self.sources.push_back(source);
                self.highest_accepted = Some(sequence);
                self.repair_due = true;
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
        if self.pending.is_some() || !self.repair_due || self.sources.is_empty() {
            return None;
        }
        self.repair_due = false;
        let len = self.sources.iter().map(|s| s.symbol.len()).max()?;
        let bytes = wire::OVERHEAD + len;
        if self.rate == 0 || self.credit < bytes as u64 * 100 {
            add(&self.stats.no_credit_repairs, 1);
            return None;
        }
        if self.next_sequence == u64::MAX {
            return None;
        }
        // Admission precedes coding. No queued repair can expire after wasting
        // encoding work, and at most one repair follows each accepted source.
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
        self.credit -= bytes as u64 * 100;
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
        if samples < 32 || lost > samples {
            return;
        }
        self.report = report;
        // No useful parity estimate is available when all settled samples were
        // lost. Retain the rate; existing PeerConn liveness owns link failure.
        if lost == samples {
            return;
        }
        let target = if lost == 0 {
            0
        } else {
            let Some(symbol_len) = self.sources.iter().map(|source| source.symbol.len()).max()
            else {
                return;
            };
            // Loss is measured in packets, but credit is measured in bytes.
            // A repair is padded to the largest symbol, so mixed packet sizes
            // need more byte credit for the same number of repair equations.
            let baseline: usize = self
                .sources
                .iter()
                .map(|source| source.symbol.len() - 2 + UDP_TUNNEL_HEADER_SIZE)
                .sum();
            let received = u128::from(samples - lost);
            let numerator = (u128::from(lost) * 125 + received * 2)
                * (wire::OVERHEAD + symbol_len) as u128
                * self.sources.len() as u128;
            numerator
                .div_ceil(received * baseline as u128)
                .min(u128::from(self.config.max_repair_percent)) as u32
        };
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
        }
    }
}
