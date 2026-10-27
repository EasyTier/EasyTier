use std::{collections::VecDeque, sync::Arc};

use bytes::{Buf as _, BytesMut};

use crate::{
    foundation::time::Instant,
    packet::{FEC_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType},
};

use super::{
    Received,
    budget::{Account, Reservation},
    codec::Decoder,
    stats::{Counters, add},
    wire,
};

const DELIVERY_WINDOW: usize = 1024;
const OUTPUT_LIMIT: usize = 64;

struct Delivery {
    ids: Box<[Option<u64>]>,
    highest: Option<u64>,
}

impl Delivery {
    fn old(&self, id: u64) -> bool {
        self.highest
            .is_some_and(|highest| id < highest.saturating_sub((DELIVERY_WINDOW - 1) as u64))
    }

    fn contains(&self, id: u64) -> bool {
        self.ids[id as usize % DELIVERY_WINDOW] == Some(id)
    }

    fn insert(&mut self, id: u64) {
        self.highest = Some(self.highest.map_or(id, |highest| highest.max(id)));
        self.ids[id as usize % DELIVERY_WINDOW] = Some(id);
    }
}

pub(super) struct Rx {
    account: Arc<Account>,
    stats: Arc<Counters>,
    delivered: Delivery,
    restored: VecDeque<Received>,
    decoder: Decoder,
    _reservation: Reservation,
}

impl Rx {
    pub fn new(account: Arc<Account>, stats: Arc<Counters>) -> anyhow::Result<Self> {
        // Delivery identity outlives the smaller, expiring decoder cache. A
        // delayed original must not repeat a packet that was already repaired.
        let bytes = DELIVERY_WINDOW * std::mem::size_of::<Option<u64>>()
            + OUTPUT_LIMIT * std::mem::size_of::<Received>()
            + 128;
        let reservation = account
            .reserve(bytes)
            .ok_or_else(|| anyhow::anyhow!("FEC receive window budget exhausted"))?;
        let decoder = Decoder::new(account.clone(), stats.clone())?;
        Ok(Self {
            account,
            stats,
            delivered: Delivery {
                ids: vec![None; DELIVERY_WINDOW].into_boxed_slice(),
                highest: None,
            },
            restored: VecDeque::with_capacity(OUTPUT_LIMIT),
            decoder,
            _reservation: reservation,
        })
    }

    pub fn active_symbols(&self) -> usize {
        self.decoder.active_symbols()
    }

    pub fn equations(&self) -> usize {
        self.decoder.equations()
    }

    pub fn take_received(&mut self) -> Option<Received> {
        self.restored.pop_front()
    }

    pub fn queue_received(&mut self, received: Received) {
        if self.restored.len() == OUTPUT_LIMIT {
            add(&self.stats.rx_queue_drops, 1);
        } else {
            self.restored.push_back(received);
        }
    }

    pub fn receive(&mut self, packet: ZCPacket, now: Instant) -> Option<Received> {
        self.expire(now);
        let Some(fragment) = wire::decode(&packet) else {
            add(&self.stats.protocol_errors, 1);
            return None;
        };
        let frame_bytes = packet.tunnel_payload().len() + UDP_TUNNEL_HEADER_SIZE;
        match fragment.header.kind {
            wire::SOURCE => {
                add(&self.stats.rx_source_packets, 1);
                add(&self.stats.rx_source_bytes, frame_bytes);
                if !wire::eligible_peer(fragment.payload) {
                    add(&self.stats.protocol_errors, 1);
                    return None;
                }
                let id = fragment.header.source;
                if self.delivered.old(id) {
                    add(&self.stats.window_drops, 1);
                    return None;
                }
                if self.delivered.contains(id) {
                    add(&self.stats.duplicate_packets, 1);
                    self.decoder.source(id, fragment.payload, now);
                    self.collect_recovered(now);
                    return None;
                }
                // A UDP buffer can retain its full backing allocation after
                // truncation. Keep that charge until the adapter yields it.
                let Some(reservation) = self
                    .account
                    .reserve(packet.buf_len().max(wire::MAX_MTU + 1) + 128)
                else {
                    add(&self.stats.resource_drops, 1);
                    return None;
                };
                self.delivered.insert(id);
                self.decoder.source(id, fragment.payload, now);
                self.collect_recovered(now);
                let mut bytes = packet.payload_bytes();
                bytes.advance(FEC_HEADER_SIZE);
                Some(Received {
                    packet: ZCPacket::new_from_buf(bytes, ZCPacketType::DummyTunnel),
                    _reservation: reservation,
                })
            }
            wire::REPAIR => {
                add(&self.stats.rx_repair_packets, 1);
                add(&self.stats.rx_repair_bytes, frame_bytes);
                let Some(_reservation) = self
                    .account
                    .reserve(packet.buf_len().max(wire::MAX_MTU + 1) + 128)
                else {
                    add(&self.stats.resource_drops, 1);
                    return None;
                };
                self.decoder.repair(
                    fragment.header.source,
                    fragment.header.count as usize,
                    fragment.header.repair,
                    fragment.payload,
                    now,
                );
                self.collect_recovered(now);
                None
            }
            _ => {
                add(&self.stats.protocol_errors, 1);
                None
            }
        }
    }

    fn collect_recovered(&mut self, now: Instant) {
        while let Some((id, peer, first)) = self.decoder.take_recovered() {
            if self.delivered.old(id) || self.delivered.contains(id) {
                continue;
            }
            if self.restored.len() == OUTPUT_LIMIT {
                add(&self.stats.rx_queue_drops, 1);
                continue;
            }
            let Some(reservation) = self.account.reserve(peer.len() + 128) else {
                add(&self.stats.resource_drops, 1);
                continue;
            };
            let packet = ZCPacket::new_from_buf(BytesMut::from(peer), ZCPacketType::DummyTunnel);
            self.restored.push_back(Received {
                packet,
                _reservation: reservation,
            });
            self.delivered.insert(id);
            add(&self.stats.recovered_packets, 1);
            add(&self.stats.recovered_bytes, peer.len());
            let elapsed = now.saturating_duration_since(first).as_micros();
            let bucket = [1000, 2000, 5000, 10000, 20000]
                .iter()
                .position(|&bound| elapsed <= bound)
                .unwrap_or(5);
            add(&self.stats.recovery_latency_buckets[bucket], 1);
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.decoder.deadline()
    }

    pub fn expire(&mut self, now: Instant) {
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.decoder.expire(now);
        }
    }
}
