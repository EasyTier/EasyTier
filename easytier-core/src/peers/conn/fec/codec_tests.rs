use std::{collections::BTreeMap, sync::atomic::Ordering};

use super::super::{budget::FecInstanceBudget, recv::Rx, wire::Header};
use super::*;
use crate::packet::{PacketType, ZCPacket};

fn peer(id: usize, len: usize) -> Vec<u8> {
    let mut packet = ZCPacket::new_with_payload(&vec![id as u8; len - PEER_MANAGER_HEADER_SIZE]);
    packet.fill_peer_manager_hdr(11, 22, PacketType::Data as u8);
    packet.tunnel_payload().to_vec()
}

fn symbol(peer: &[u8]) -> Vec<u8> {
    let mut symbol = (peer.len() as u16).to_le_bytes().to_vec();
    symbol.extend_from_slice(peer);
    symbol
}

fn decoder() -> (Decoder, Arc<FecInstanceBudget>) {
    let budget = Arc::new(FecInstanceBudget::default());
    let decoder =
        Decoder::new(Account::new(budget.clone()), Arc::new(Counters::default())).unwrap();
    (decoder, budget)
}

fn drain(decoder: &mut Decoder, recovered: &mut BTreeMap<u64, Vec<u8>>) {
    while let Some((id, peer, _)) = decoder.take_recovered() {
        assert!(recovered.insert(id, peer.to_vec()).is_none());
    }
}

fn assert_reduced(decoder: &Decoder) {
    let mut previous = None;
    for (index, row) in decoder.rows.iter().enumerate() {
        let pivot = row.pivot().unwrap();
        assert!(previous.is_none_or(|previous| previous < pivot));
        assert_eq!(row.coefficients[pivot], 1);
        for (other_index, other) in decoder.rows.iter().enumerate() {
            if other_index != index {
                assert_eq!(other.coefficients[pivot], 0);
            }
        }
        previous = Some(pivot);
    }
}

#[test]
fn sliding_repairs_recover_multiple_losses_across_overlapping_windows() {
    let now = Instant::now();
    let (mut decoder, budget) = decoder();
    let peers: Vec<_> = (0..180).map(|id| peer(id, 96 + id % 17 * 47)).collect();
    let symbols: Vec<_> = peers.iter().map(|peer| symbol(peer)).collect();
    let lost = [18, 19, 55, 65, 66, 127, 170];
    let mut recovered = BTreeMap::new();
    for id in 0..peers.len() {
        let time = now + Duration::from_micros(id as u64 * 100);
        if !lost.contains(&id) {
            decoder.source(id as u64, &peers[id], time);
        }
        if id % 3 == 2 {
            let first = (id + 1).saturating_sub(WINDOW);
            let repair = id as u32 / 3;
            let data = encode_repair(repair, symbols[first..=id].iter().map(Vec::as_slice));
            decoder.repair(first as u64, id + 1 - first, repair, &data, time);
        }
        assert_reduced(&decoder);
        drain(&mut decoder, &mut recovered);
    }
    assert_eq!(recovered.len(), lost.len());
    for id in lost {
        assert_eq!(recovered[&(id as u64)], peers[id]);
    }
    assert_eq!(decoder.stats.protocol_errors.load(Ordering::Relaxed), 0);
    drop(decoder);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn repair_first_and_original_pivot_replacement_keep_unique_pivots() {
    let now = Instant::now();
    let (mut decoder, _) = decoder();
    let peers: Vec<_> = (0..4).map(|id| peer(id, 67 + id * 30)).collect();
    let symbols: Vec<_> = peers.iter().map(|peer| symbol(peer)).collect();
    for repair in [1, 2] {
        let data = encode_repair(repair, symbols.iter().map(Vec::as_slice));
        decoder.repair(0, peers.len(), repair, &data, now);
    }
    assert_eq!(decoder.rows.len(), 2);
    assert_eq!(decoder.rows[0].pivot(), Some(0));
    decoder.source(0, &peers[0], now + Duration::from_millis(1));
    assert_reduced(&decoder);
    decoder.source(3, &peers[3], now + Duration::from_millis(2));
    assert_reduced(&decoder);
    let mut recovered = BTreeMap::new();
    drain(&mut decoder, &mut recovered);
    assert_eq!(
        recovered,
        BTreeMap::from([(1, peers[1].clone()), (2, peers[2].clone())])
    );
}

#[test]
fn wrapping_slots_drop_rows_containing_evicted_unknowns() {
    let now = Instant::now();
    let (mut decoder, _) = decoder();
    let old: Vec<_> = (0..3).map(|id| symbol(&peer(id, 100))).collect();
    let data = encode_repair(1, old.iter().map(Vec::as_slice));
    decoder.repair(0, old.len(), 1, &data, now);
    assert_eq!(decoder.equations(), 1);
    let peers = [peer(256, 160), peer(257, 230)];
    decoder.source(256, &peers[0], now);
    assert_eq!(decoder.equations(), 0);
    let symbols: Vec<_> = peers.iter().map(|peer| symbol(peer)).collect();
    let data = encode_repair(2, symbols.iter().map(Vec::as_slice));
    decoder.repair(256, 2, 2, &data, now);
    let mut recovered = BTreeMap::new();
    drain(&mut decoder, &mut recovered);
    assert_eq!(recovered, BTreeMap::from([(257, peers[1].clone())]));
    assert_eq!(decoder.stats.protocol_errors.load(Ordering::Relaxed), 0);
}

#[test]
fn receive_cache_expires_without_restarting_from_late_repairs() {
    let now = Instant::now();
    let (mut decoder, budget) = decoder();
    let metadata = budget.used_bytes();
    let peers = [peer(0, 100), peer(1, 130), peer(2, 140)];
    let symbols: Vec<_> = peers.iter().map(|peer| symbol(peer)).collect();
    decoder.source(0, &peers[0], now);
    let data = encode_repair(2, symbols.iter().map(Vec::as_slice));
    decoder.repair(0, 3, 2, &data, now);
    assert_eq!(decoder.equations(), 1);
    assert_eq!(decoder.deadline(), Some(now + RECOVERY_LIFETIME));
    decoder.expire(now + RECOVERY_LIFETIME);
    assert_eq!(decoder.active_symbols(), 0);
    assert_eq!(decoder.equations(), 0);
    assert_eq!(decoder.deadline(), None);
    assert_eq!(budget.used_bytes(), metadata);
    decoder.repair(0, 3, 2, &data, now + RECOVERY_LIFETIME);
    decoder.source(1, &peers[1], now + RECOVERY_LIFETIME);
    assert_eq!(decoder.active_symbols(), 0);
    assert_eq!(decoder.equations(), 0);
}

#[test]
fn malformed_recovered_lengths_types_and_padding_preserve_originals() {
    for corrupt in 0..3 {
        let now = Instant::now();
        let (mut decoder, _) = decoder();
        let original = peer(0, 100);
        decoder.source(0, &original, now);
        let mut bad = symbol(&peer(1, 60));
        match corrupt {
            0 => bad[..2].copy_from_slice(&u16::MAX.to_le_bytes()),
            1 => bad[2 + 8] = PacketType::FecRepair as u8,
            _ => bad.push(1),
        }
        let data = encode_repair(9, [bad.as_slice()]);
        decoder.repair(1, 1, 9, &data, now);
        assert_eq!(decoder.stats.protocol_errors.load(Ordering::Relaxed), 1);
        assert_eq!(decoder.equations(), 0);
        assert_eq!(decoder.active_symbols(), 1);
        assert_eq!(
            decoder.slots[0].symbol.as_ref().unwrap().data,
            symbol(&original)
        );
        assert!(decoder.take_recovered().is_none());
    }
}

#[test]
fn valid_zero_padding_is_removed_from_recovered_peer() {
    let now = Instant::now();
    let (mut decoder, _) = decoder();
    let original = peer(4, 79);
    let mut padded = symbol(&original);
    padded.resize(900, 0);
    let data = encode_repair(11, [padded.as_slice()]);
    decoder.repair(4, 1, 11, &data, now);
    let (id, recovered, _) = decoder.take_recovered().unwrap();
    assert_eq!(id, 4);
    assert_eq!(recovered, original);
}

#[test]
fn payload_allocations_are_lazy_budgeted_and_completely_released() {
    let now = Instant::now();
    let (decoder, budget) = decoder();
    let metadata = budget.used_bytes();
    assert!(metadata < 128 * 1024);
    drop(decoder);
    assert_eq!(budget.used_bytes(), 0);
    let budget = Arc::new(FecInstanceBudget::new(metadata + 64));
    let stats = Arc::new(Counters::default());
    let mut decoder = Decoder::new(Account::new(budget.clone()), stats.clone()).unwrap();
    decoder.source(0, &peer(0, 100), now);
    let data = encode_repair(1, [symbol(&peer(1, 100)).as_slice()]);
    decoder.repair(1, 1, 1, &data, now);
    assert_eq!(decoder.active_symbols(), 0);
    assert_eq!(decoder.equations(), 0);
    assert_eq!(stats.resource_drops.load(Ordering::Relaxed), 2);
    assert_eq!(budget.used_bytes(), metadata);
    drop(decoder);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn repeated_and_out_of_order_repairs_stay_bounded() {
    let now = Instant::now();
    let (mut decoder, budget) = decoder();
    let symbols: Vec<_> = (0..320).map(|id| symbol(&peer(id, 90 + id % 5))).collect();
    for first in (0..256).step_by(2) {
        let repair = first as u32;
        let data = encode_repair(
            repair,
            symbols[first..first + WINDOW].iter().map(Vec::as_slice),
        );
        decoder.repair(first as u64, WINDOW, repair, &data, now);
        decoder.repair(first as u64, WINDOW, repair, &data, now);
        assert!(decoder.active_symbols() <= RECEIVE_WINDOW);
        assert!(decoder.equations() <= EQUATION_LIMIT);
        assert_reduced(&decoder);
    }
    let data = encode_repair(999, symbols[..WINDOW].iter().map(Vec::as_slice));
    decoder.repair(0, WINDOW, 999, &data, now);
    assert_eq!(decoder.stats.window_drops.load(Ordering::Relaxed), 1);
    assert_eq!(decoder.stats.protocol_errors.load(Ordering::Relaxed), 0);
    assert!(budget.used_bytes() < 256 * 1024);
    drop(decoder);
    assert_eq!(budget.used_bytes(), 0);
}

fn source_frame(id: u64, peer: &[u8]) -> ZCPacket {
    wire::encode(
        Header {
            kind: wire::SOURCE,
            sequence: id,
            source: id,
            repair: 0,
            count: 0,
        },
        peer,
    )
}

fn repair_frame(first: u64, peers: &[Vec<u8>], repair: u32) -> ZCPacket {
    let symbols: Vec<_> = peers.iter().map(|peer| symbol(peer)).collect();
    let data = encode_repair(repair, symbols.iter().map(Vec::as_slice));
    wire::encode(
        Header {
            kind: wire::REPAIR,
            sequence: repair as u64,
            source: first,
            repair,
            count: peers.len() as u8,
        },
        &data,
    )
}

#[test]
fn original_delivery_is_immediate_and_deduplicated_after_cache_expiry() {
    let now = Instant::now();
    let budget = Arc::new(FecInstanceBudget::default());
    let stats = Arc::new(Counters::default());
    let mut rx = Rx::new(Account::new(budget.clone()), stats.clone()).unwrap();
    let original = peer(0, 100);
    let received = rx.receive(source_frame(0, &original), now).unwrap();
    assert_eq!(received.packet.tunnel_payload(), original);
    drop(received);
    let repaired = peer(1, 123);
    rx.receive(repair_frame(1, std::slice::from_ref(&repaired), 1), now);
    let received = rx.take_received().unwrap();
    assert_eq!(received.packet.tunnel_payload(), repaired);
    drop(received);
    rx.expire(now + RECOVERY_LIFETIME);
    assert_eq!(rx.active_symbols(), 0);
    assert!(
        rx.receive(source_frame(0, &original), now + RECOVERY_LIFETIME)
            .is_none()
    );
    assert!(
        rx.receive(source_frame(1, &repaired), now + RECOVERY_LIFETIME)
            .is_none()
    );
    assert_eq!(stats.duplicate_packets.load(Ordering::Relaxed), 2);
    let late = peer(2, 167);
    assert!(
        rx.receive(source_frame(2, &late), now + RECOVERY_LIFETIME)
            .is_some()
    );
    drop(rx);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn recovered_output_queue_is_bounded_and_does_not_lose_original_cache() {
    let now = Instant::now();
    let budget = Arc::new(FecInstanceBudget::default());
    let stats = Arc::new(Counters::default());
    let mut rx = Rx::new(Account::new(budget.clone()), stats.clone()).unwrap();
    for id in 0..70 {
        rx.receive(repair_frame(id, &[peer(id as usize, 100)], id as u32), now);
    }
    let mut count = 0;
    while rx.take_received().is_some() {
        count += 1;
    }
    assert_eq!(count, 64);
    assert_eq!(stats.rx_queue_drops.load(Ordering::Relaxed), 6);
    assert_eq!(rx.active_symbols(), 70);
    // A repaired packet dropped by the output queue is still deliverable if
    // its original subsequently arrives; only actual delivery sets the bitmap.
    assert!(rx.receive(source_frame(69, &peer(69, 100)), now).is_some());
    drop(rx);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn coefficients_and_repair_match_independent_wire_vectors() {
    // These vectors use independent shift/XOR multiplication modulo 0x11d,
    // rather than deriving expectations with the production encoder.
    for (repair, expected) in [
        (0, [251, 96, 221, 124]),
        (1, [197, 248, 175, 4]),
        (42, [46, 32, 75, 211]),
        (u32::MAX, [183, 160, 52, 224]),
    ] {
        assert_eq!(
            std::array::from_fn::<_, 4, _>(|index| coefficient(repair, index)),
            expected
        );
    }
    let sources: [&[u8]; 3] = [
        &[0x04, 0x00, 0x01, 0x02, 0x03, 0x04],
        &[0x03, 0x00, 0xff, 0x80, 0x11],
        &[0x05, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a],
    ];
    assert_eq!(encode_repair(42, sources), [162, 0, 234, 241, 60, 188, 94]);

    let mut first = vec![0; 16];
    first[8] = PacketType::Data as u8;
    first.extend_from_slice(&[0xa0, 0xa1]);
    let mut second = vec![0; 16];
    second[8] = PacketType::Data as u8;
    second.extend_from_slice(&[0xb0, 0xb1, 0xb2, 0xb3]);
    let (mut decoder, _) = decoder();
    let now = Instant::now();
    decoder.source(7, &first, now);
    decoder.repair(
        7,
        2,
        42,
        &[
            60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 180, 186, 195, 227,
        ],
        now,
    );
    let (id, recovered, _) = decoder.take_recovered().unwrap();
    assert_eq!(id, 8);
    assert_eq!(recovered, second);
}
