use std::sync::Arc;

use reed_solomon_erasure::galois_8::{div, mul, mul_slice_xor};

use crate::{
    foundation::time::{Duration, Instant},
    packet::PEER_MANAGER_HEADER_SIZE,
};

use super::{
    budget::{Account, Reservation},
    stats::{Counters, add},
    wire,
};

pub(super) const WINDOW: usize = 64;
const RECEIVE_WINDOW: usize = 256;
const EQUATION_LIMIT: usize = 64;
pub(super) const RECOVERY_LIFETIME: Duration = Duration::from_millis(200);

/// Derive a nonzero coefficient independently for each position in a repair.
/// The wrapping operations and constants are part of the v1 wire format.
pub(super) fn coefficient(repair: u32, index: usize) -> u8 {
    let mut value = ((repair as u64) << 32) | index as u64;
    value = value.wrapping_add(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^= value >> 31;
    (value % 255 + 1) as u8
}

/// The caller reserves the output allocation before encoding. Symbols contain
/// a little-endian u16 peer length followed by the complete peer packet.
pub(super) fn encode_repair<'a, I>(repair: u32, sources: I) -> Vec<u8>
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: Clone,
{
    let sources = sources.into_iter();
    let len = sources.clone().map(<[u8]>::len).max().unwrap_or(0);
    let mut output = vec![0; len];
    for (index, source) in sources.enumerate() {
        mul_slice_xor(
            coefficient(repair, index),
            source,
            &mut output[..source.len()],
        );
    }
    output
}

struct Symbol {
    data: Vec<u8>,
    original: bool,
    pending: bool,
    _reservation: Reservation,
}

#[derive(Default)]
struct Slot {
    id: Option<u64>,
    first: Option<Instant>,
    expired: bool,
    symbol: Option<Symbol>,
}

struct Row {
    coefficients: [u8; RECEIVE_WINDOW],
    data: Vec<u8>,
    first: Instant,
    reservation: Reservation,
}

#[derive(Clone, Copy)]
enum Failure {
    Resource,
    Protocol,
}

impl Row {
    fn pivot(&self) -> Option<usize> {
        self.coefficients.iter().position(|&value| value != 0)
    }

    fn add_data(&mut self, factor: u8, data: &[u8]) -> Result<(), Failure> {
        if self.data.len() < data.len() {
            let extra = data.len() - self.data.len();
            if !self.reservation.grow(extra) {
                return Err(Failure::Resource);
            }
            self.data.reserve_exact(extra);
            self.data.resize(data.len(), 0);
        }
        mul_slice_xor(factor, data, &mut self.data[..data.len()]);
        Ok(())
    }

    fn add_row(&mut self, factor: u8, row: &Row) -> Result<(), Failure> {
        self.add_data(factor, &row.data)?;
        mul_slice_xor(factor, &row.coefficients, &mut self.coefficients);
        // A combination must not extend the lifetime of its oldest evidence.
        self.first = self.first.min(row.first);
        Ok(())
    }

    fn normalize(&mut self, pivot: usize) {
        let factor = div(1, self.coefficients[pivot]);
        for value in &mut self.coefficients {
            *value = mul(*value, factor);
        }
        for value in &mut self.data {
            *value = mul(*value, factor);
        }
    }
}

/// Incremental reduced-row elimination with fixed metadata and lazy payloads.
/// Column numbers are receive-window slots; a slot is never reused while a
/// row still refers to its old, unknown source.
pub(super) struct Decoder {
    account: Arc<Account>,
    stats: Arc<Counters>,
    slots: Box<[Slot]>,
    rows: Vec<Row>,
    highest: Option<u64>,
    _reservation: Reservation,
}

impl Decoder {
    pub fn new(account: Arc<Account>, stats: Arc<Counters>) -> anyhow::Result<Self> {
        let bytes = RECEIVE_WINDOW * std::mem::size_of::<Slot>()
            + EQUATION_LIMIT * std::mem::size_of::<Row>()
            + 128;
        let reservation = account
            .reserve(bytes)
            .ok_or_else(|| anyhow::anyhow!("FEC decoder metadata budget exhausted"))?;
        Ok(Self {
            account,
            stats,
            slots: (0..RECEIVE_WINDOW).map(|_| Slot::default()).collect(),
            rows: Vec::with_capacity(EQUATION_LIMIT),
            highest: None,
            _reservation: reservation,
        })
    }

    pub fn active_symbols(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.symbol.is_some())
            .count()
    }

    pub fn equations(&self) -> usize {
        self.rows.len()
    }

    fn discard_slot(&mut self, slot: usize) {
        // Clearing only this column would turn an equation containing an
        // unknown, evicted symbol into a different (and incorrect) equation.
        self.rows.retain(|row| row.coefficients[slot] == 0);
        if self.slots[slot].symbol.take().is_some() {
            add(&self.stats.cache_evictions, 1);
        }
        self.slots[slot] = Slot::default();
    }

    fn advance(&mut self, id: u64) -> bool {
        if let Some(highest) = self.highest {
            if id < highest.saturating_sub((RECEIVE_WINDOW - 1) as u64) {
                return false;
            }
            if id <= highest {
                return true;
            }
        }
        self.highest = Some(id);
        let minimum = id.saturating_sub((RECEIVE_WINDOW - 1) as u64);
        for slot in 0..RECEIVE_WINDOW {
            if self.slots[slot].id.is_some_and(|old| old < minimum) {
                self.discard_slot(slot);
            }
        }
        true
    }

    fn slot(&mut self, id: u64, now: Instant) -> Option<usize> {
        if !self.advance(id) {
            return None;
        }
        let index = id as usize % RECEIVE_WINDOW;
        if self.slots[index].id != Some(id) {
            self.discard_slot(index);
            self.slots[index].id = Some(id);
            self.slots[index].first = Some(now);
        }
        (!self.slots[index].expired).then_some(index)
    }

    fn failed(&mut self, failure: Failure) {
        self.rows.clear();
        match failure {
            Failure::Resource => add(&self.stats.resource_drops, 1),
            Failure::Protocol => {
                add(&self.stats.protocol_errors, 1);
                // Original sources remain useful after a bad equation. Any
                // values derived from equations may share the corrupt input.
                for slot in &mut self.slots {
                    if slot.symbol.as_ref().is_some_and(|symbol| !symbol.original) {
                        slot.symbol = None;
                    }
                }
            }
        }
    }

    pub fn source(&mut self, id: u64, peer: &[u8], now: Instant) {
        let Some(slot) = self.slot(id, now) else {
            return;
        };
        if let Some(symbol) = &mut self.slots[slot].symbol {
            if symbol.data[2..] == *peer {
                symbol.original = true;
                symbol.pending = false;
                return;
            }
            self.failed(Failure::Protocol);
            if self.slots[slot].symbol.is_some() {
                return;
            }
        }
        let Some(reservation) = self.account.reserve(peer.len() + 2 + 128) else {
            add(&self.stats.resource_drops, 1);
            return;
        };
        let mut data = Vec::with_capacity(peer.len() + 2);
        data.extend_from_slice(&(peer.len() as u16).to_le_bytes());
        data.extend_from_slice(peer);
        self.slots[slot].symbol = Some(Symbol {
            data,
            original: true,
            pending: false,
            _reservation: reservation,
        });
        if let Err(failure) = self.substitute(slot).and_then(|()| self.recover()) {
            self.failed(failure);
        }
    }

    pub fn repair(&mut self, first: u64, count: usize, repair: u32, data: &[u8], now: Instant) {
        let Some(last) = first.checked_add(count.saturating_sub(1) as u64) else {
            add(&self.stats.protocol_errors, 1);
            return;
        };
        if count == 0 || count > WINDOW {
            add(&self.stats.protocol_errors, 1);
            return;
        }
        self.advance(last);
        if first
            < last
                .max(self.highest.unwrap())
                .saturating_sub((RECEIVE_WINDOW - 1) as u64)
        {
            add(&self.stats.window_drops, 1);
            return;
        }
        // A window containing expired evidence cannot resurrect old recovery
        // work. Delivery deduplication outlives these decoder slots.
        for id in first..=last {
            if self.slot(id, now).is_none() {
                return;
            }
        }
        let Some(reservation) = self.account.reserve(data.len() + 128) else {
            add(&self.stats.resource_drops, 1);
            return;
        };
        let mut row = Row {
            coefficients: [0; RECEIVE_WINDOW],
            data: data.to_vec(),
            first: now,
            reservation,
        };
        for (index, id) in (first..=last).enumerate() {
            let slot = id as usize % RECEIVE_WINDOW;
            let factor = coefficient(repair, index);
            row.first = row.first.min(self.slots[slot].first.unwrap());
            if let Some(symbol) = &self.slots[slot].symbol {
                if let Err(failure) = row.add_data(factor, &symbol.data) {
                    self.failed(failure);
                    return;
                }
            } else {
                row.coefficients[slot] = factor;
            }
        }
        if let Err(failure) = self.insert(row).and_then(|()| self.recover()) {
            self.failed(failure);
        }
    }

    fn insert(&mut self, mut row: Row) -> Result<(), Failure> {
        for existing in &self.rows {
            let pivot = existing.pivot().unwrap();
            let factor = row.coefficients[pivot];
            if factor != 0 {
                row.add_row(factor, existing)?;
            }
        }
        let Some(pivot) = row.pivot() else {
            if row.data.iter().any(|&value| value != 0) {
                return Err(Failure::Protocol);
            }
            add(&self.stats.duplicate_packets, 1);
            return Ok(());
        };
        row.normalize(pivot);
        for existing in &mut self.rows {
            let factor = existing.coefficients[pivot];
            if factor != 0 {
                existing.add_row(factor, &row)?;
            }
        }
        if self.rows.len() == EQUATION_LIMIT {
            let oldest = self
                .rows
                .iter()
                .enumerate()
                .min_by_key(|(_, row)| row.first)
                .unwrap()
                .0;
            self.rows.remove(oldest);
            add(&self.stats.cache_evictions, 1);
        }
        let index = self
            .rows
            .binary_search_by_key(&pivot, |row| row.pivot().unwrap())
            .unwrap_err();
        self.rows.insert(index, row);
        Ok(())
    }

    fn substitute(&mut self, slot: usize) -> Result<(), Failure> {
        if self.rows.iter().all(|row| row.coefficients[slot] == 0) {
            return Ok(());
        }
        // An arriving source may replace a pivot. Move rows out, substitute,
        // and reinsert so collisions with later pivots are eliminated again.
        // This uses fixed stack metadata, without cloning any symbol payload.
        let mut rows: [Option<Row>; EQUATION_LIMIT] = std::array::from_fn(|_| self.rows.pop());
        for row in rows.iter_mut().rev().filter_map(Option::take) {
            let mut row = row;
            let factor = row.coefficients[slot];
            if factor != 0 {
                row.add_data(factor, &self.slots[slot].symbol.as_ref().unwrap().data)?;
                row.coefficients[slot] = 0;
            }
            self.insert(row)?;
        }
        Ok(())
    }

    fn recover(&mut self) -> Result<(), Failure> {
        // The rows are reduced against every pivot, so a singleton's column
        // already vanishes from all other rows. No recursive solve is needed.
        let mut index = 0;
        while index < self.rows.len() {
            let pivot = self.rows[index].pivot().unwrap();
            if self.rows[index]
                .coefficients
                .iter()
                .filter(|&&value| value != 0)
                .count()
                != 1
            {
                index += 1;
                continue;
            }
            let mut row = self.rows.remove(index);
            let Some(len) = peer_length(&row.data) else {
                return Err(Failure::Protocol);
            };
            row.data.truncate(len + 2);
            self.slots[pivot].symbol = Some(Symbol {
                data: row.data,
                original: false,
                pending: true,
                _reservation: row.reservation,
            });
        }
        Ok(())
    }

    /// The returned peer bytes borrow the cache; only the packet being handed
    /// downstream needs a copy, never the complete coding window.
    pub fn take_recovered(&mut self) -> Option<(u64, &[u8], Instant)> {
        for slot in &mut self.slots {
            let Some(symbol) = &mut slot.symbol else {
                continue;
            };
            if symbol.pending {
                symbol.pending = false;
                return Some((slot.id.unwrap(), &symbol.data[2..], slot.first.unwrap()));
            }
        }
        None
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.slots
            .iter()
            .filter(|slot| !slot.expired)
            .filter_map(|slot| slot.first.map(|first| first + RECOVERY_LIFETIME))
            .chain(self.rows.iter().map(|row| row.first + RECOVERY_LIFETIME))
            .min()
    }

    pub fn expire(&mut self, now: Instant) {
        self.rows.retain(|row| row.first + RECOVERY_LIFETIME > now);
        for index in 0..RECEIVE_WINDOW {
            if !self.slots[index].expired
                && self.slots[index]
                    .first
                    .is_some_and(|first| first + RECOVERY_LIFETIME <= now)
            {
                self.rows.retain(|row| row.coefficients[index] == 0);
                self.slots[index].symbol = None;
                self.slots[index].expired = true;
                add(&self.stats.expired_symbols, 1);
            }
        }
    }
}

fn peer_length(symbol: &[u8]) -> Option<usize> {
    if symbol.len() < PEER_MANAGER_HEADER_SIZE + 2 {
        return None;
    }
    let len = u16::from_le_bytes(symbol[..2].try_into().unwrap()) as usize;
    if len < PEER_MANAGER_HEADER_SIZE
        || len + 2 > symbol.len()
        || !wire::eligible_peer(&symbol[2..2 + len])
        || symbol[2 + len..].iter().any(|&value| value != 0)
    {
        return None;
    }
    Some(len)
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
