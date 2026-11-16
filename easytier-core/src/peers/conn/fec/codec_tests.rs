use std::collections::BTreeMap;

use crate::packet::{PacketType, ZCPacket};

use super::*;

const MAX_SYMBOL_LEN: usize = 1402;

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

fn repair(repair: u32, peers: &[Vec<u8>]) -> Vec<u8> {
    let symbols: Vec<_> = peers.iter().map(|peer| symbol(peer)).collect();
    encode_repair(repair, symbols.iter().map(Vec::as_slice))
}

fn drain(decoder: &mut Decoder, recovered: &mut BTreeMap<u64, Vec<u8>>) {
    while let Some((id, peer, _)) = decoder.take_recovered() {
        assert!(recovered.insert(id, peer.to_vec()).is_none());
    }
}

fn assert_reduced(decoder: &Decoder) {
    assert!(decoder.active_symbols() <= RECEIVE_WINDOW);
    assert!(decoder.equations() <= EQUATION_LIMIT);
    let mut previous = None;
    for (index, row) in decoder.rows.iter().enumerate() {
        let pivot = row.pivot().unwrap();
        assert!(previous.is_none_or(|previous| previous < pivot));
        assert_eq!(row.coefficients[pivot], 1);
        assert!(row.data.len() <= decoder.max_symbol_len);
        for (other_index, other) in decoder.rows.iter().enumerate() {
            if other_index != index {
                assert_eq!(other.coefficients[pivot], 0);
            }
        }
        previous = Some(pivot);
    }
}

#[test]
fn coefficient_and_repair_wire_vectors() {
    for (repair, expected) in [
        (0, [251, 96, 221, 124]),
        (1, [197, 248, 175, 4]),
        (42, [46, 32, 75, 211]),
        (u32::MAX, [183, 160, 52, 224]),
    ] {
        assert_eq!(
            std::array::from_fn::<_, 4, _>(|i| coefficient(repair, i)),
            expected
        );
        assert!((0..WINDOW).all(|i| coefficient(repair, i) != 0));
    }
    let sources: [&[u8]; 3] = [
        &[4, 0, 1, 2, 3, 4],
        &[3, 0, 255, 128, 17],
        &[5, 0, 18, 52, 86, 120, 154],
    ];
    assert_eq!(encode_repair(42, sources), [162, 0, 234, 241, 60, 188, 94]);
    assert!(encode_repair(42, std::iter::empty::<&[u8]>()).is_empty());
}

#[test]
fn overlapping_windows_recover_losses_across_ring_turns() {
    let peers: Vec<_> = (0..180).map(|id| peer(id, 96 + id % 17 * 47)).collect();
    let losses = [18, 19, 55, 65, 66, 127, 170];
    let start = Instant::now();
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    let mut recovered = BTreeMap::new();
    for id in 0..peers.len() {
        let now = start + Duration::from_micros(id as u64 * 100);
        if !losses.contains(&id) {
            decoder.source(id as u64, &peers[id], now);
        }
        if id % 3 == 2 {
            let first = (id + 1).saturating_sub(WINDOW);
            decoder.repair(
                first as u64,
                id + 1 - first,
                id as u32,
                &repair(id as u32, &peers[first..=id]),
                now,
            );
        }
        assert_reduced(&decoder);
        drain(&mut decoder, &mut recovered);
    }
    assert_eq!(recovered.len(), losses.len());
    for id in losses {
        assert_eq!(recovered[&(id as u64)], peers[id]);
    }
}

#[test]
fn originals_arriving_at_pivots_rebuild_reduced_rows() {
    let peers: Vec<_> = (0..4).map(|id| peer(id, 67 + id * 30)).collect();
    let now = Instant::now();
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    for repair_id in [1, 2] {
        decoder.repair(0, 4, repair_id, &repair(repair_id, &peers), now);
    }
    assert_eq!(decoder.equations(), 2);
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
fn dependent_rows_do_not_consume_equation_capacity() {
    let peers = [peer(0, 100), peer(1, 200)];
    let now = Instant::now();
    let data = repair(1, &peers);
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    for _ in 0..100 {
        decoder.repair(0, 2, 1, &data, now);
    }
    assert_eq!(decoder.equations(), 1);
    assert!(decoder.take_recovered().is_none());
    decoder.source(0, &peers[0], now);
    let (id, recovered, _) = decoder.take_recovered().unwrap();
    assert_eq!(id, 1);
    assert_eq!(recovered, peers[1]);
    assert_eq!(decoder.equations(), 0);
}

#[test]
fn equation_limit_evicts_rows_without_fabricating_solutions() {
    let peers: Vec<_> = (0..100).map(|id| peer(id, 100)).collect();
    let now = Instant::now();
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    for first in 0..99 {
        decoder.repair(
            first as u64,
            2,
            7,
            &repair(7, &peers[first..first + 2]),
            now,
        );
        assert_reduced(&decoder);
        assert!(decoder.take_recovered().is_none());
    }
    assert_eq!(decoder.equations(), EQUATION_LIMIT);
}

#[test]
fn ring_eviction_discards_equations_with_unknown_old_columns() {
    let now = Instant::now();
    let peers = [peer(0, 100), peer(1, 120), peer(2, 140)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.repair(0, 3, 1, &repair(1, &peers), now);
    assert_eq!(decoder.equations(), 1);
    decoder.source(128, &peers[0], now);
    assert_eq!(decoder.equations(), 0);
    decoder.repair(128, 2, 2, &repair(2, &peers[..2]), now);
    let (id, recovered, _) = decoder.take_recovered().unwrap();
    assert_eq!(id, 129);
    assert_eq!(recovered, peers[1]);
    assert!(decoder.take_recovered().is_none());
}

#[test]
fn large_id_advances_and_u64_boundary_preserve_only_receive_window() {
    let now = Instant::now();
    let data = peer(0, 100);
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    for id in 0..128 {
        decoder.source(id, &data, now);
    }
    assert_eq!(decoder.active_symbols(), 128);
    decoder.source(254, &data, now);
    assert_eq!(decoder.active_symbols(), 2);
    decoder.source(382, &data, now);
    assert_eq!(decoder.active_symbols(), 1);
    decoder.source(u64::MAX - 1, &data, now);
    decoder.source(u64::MAX, &data, now);
    decoder.source(u64::MAX - 127, &data, now);
    decoder.source(u64::MAX - 128, &data, now);
    assert_eq!(decoder.active_symbols(), 3);
    assert_eq!(decoder.highest, Some(u64::MAX));
    assert_reduced(&decoder);
}

#[test]
fn duplicate_original_suppresses_only_its_pending_recovery() {
    let now = Instant::now();
    let peers = [peer(0, 100), peer(1, 200)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    for id in 0..2 {
        decoder.repair(
            id,
            1,
            1,
            &repair(1, &peers[id as usize..id as usize + 1]),
            now,
        );
    }
    decoder.source(0, &peers[0], now + Duration::from_millis(10));
    let (id, recovered, first) = decoder.take_recovered().unwrap();
    assert_eq!(id, 1);
    assert_eq!(recovered, peers[1]);
    assert_eq!(first, now);
    assert!(decoder.take_recovered().is_none());
    assert_eq!(decoder.deadline(), Some(now + RECOVERY_LIFETIME));
}

#[test]
fn elapsed_sources_and_repairs_cannot_revive_expired_ids() {
    let now = Instant::now();
    let peers = [peer(0, 100), peer(1, 120)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.source(0, &peers[0], now);
    decoder.repair(0, 2, 1, &repair(1, &peers), now);
    let later = now + RECOVERY_LIFETIME;
    // Ingress must enforce expiry even if the caller has not run its timer.
    decoder.source(0, &peers[0], later);
    decoder.repair(0, 2, 2, &repair(2, &peers), later);
    assert_eq!(decoder.active_symbols(), 0);
    assert_eq!(decoder.equations(), 0);
    assert!(decoder.take_recovered().is_none());
    assert_eq!(decoder.deadline(), None);
    decoder.repair(128, 1, 1, &repair(1, &peers[..1]), later);
    assert_eq!(decoder.take_recovered().unwrap().0, 128);
    decoder.source(0, &peers[0], later);
    assert_eq!(decoder.active_symbols(), 1);
}

#[test]
fn elimination_and_recovered_symbols_keep_earliest_evidence_deadline() {
    let now = Instant::now();
    let peers = [peer(0, 80), peer(1, 120), peer(2, 160)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.repair(0, 2, 1, &repair(1, &peers[..2]), now);
    decoder.repair(
        1,
        2,
        2,
        &repair(2, &peers[1..]),
        now + Duration::from_millis(100),
    );
    assert!(decoder.rows.iter().all(|row| row.first == now));
    decoder.source(0, &peers[0], now + Duration::from_millis(150));
    let mut ids = Vec::new();
    while let Some((id, recovered, first)) = decoder.take_recovered() {
        assert_eq!(recovered, peers[id as usize]);
        assert_eq!(first, now);
        ids.push(id);
    }
    assert_eq!(ids, [1, 2]);
    decoder.expire(now + RECOVERY_LIFETIME);
    assert_eq!(decoder.active_symbols(), 0);
    assert_eq!(decoder.deadline(), None);
}

#[test]
fn expiry_drops_whole_rows_and_preserves_unrelated_fresh_sources() {
    let now = Instant::now();
    let peers = [peer(0, 100), peer(1, 120)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.repair(0, 2, 1, &repair(1, &peers), now);
    decoder.source(3, &peers[0], now + Duration::from_millis(100));
    decoder.expire(now + RECOVERY_LIFETIME);
    assert_eq!(decoder.equations(), 0);
    assert_eq!(decoder.active_symbols(), 1);
    assert!(decoder.take_recovered().is_none());
    assert_eq!(decoder.deadline(), Some(now + Duration::from_millis(300)));
    decoder.repair(0, 2, 2, &repair(2, &peers), now + RECOVERY_LIFETIME);
    assert_eq!(decoder.equations(), 0);
}

#[test]
fn invalid_lengths_padding_and_packet_types_never_escape_decoder() {
    let now = Instant::now();
    let original = peer(0, 100);
    let mut invalid = vec![symbol(&peer(1, 100)); 4];
    invalid[0][..2].copy_from_slice(&u16::MAX.to_le_bytes());
    invalid[1][..2].copy_from_slice(&1u16.to_le_bytes());
    invalid[2].push(1);
    invalid[3][2 + 8] = PacketType::Ping as u8;
    for data in invalid {
        let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
        decoder.source(0, &original, now);
        let encoded = encode_repair(1, [data.as_slice()]);
        decoder.repair(1, 1, 1, &encoded, now);
        assert_eq!(decoder.active_symbols(), 1);
        assert_eq!(decoder.equations(), 0);
        assert!(decoder.take_recovered().is_none());
    }
}

#[test]
fn zero_padding_is_valid_and_not_delivered() {
    let now = Instant::now();
    let expected = peer(1, 80);
    let mut data = symbol(&expected);
    data.resize(900, 0);
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.repair(1, 1, 7, &encode_repair(7, [data.as_slice()]), now);
    let (id, recovered, _) = decoder.take_recovered().unwrap();
    assert_eq!(id, 1);
    assert_eq!(recovered, expected);
}

#[test]
fn malformed_input_cannot_advance_window_or_allocate_payloads() {
    let now = Instant::now();
    let expected = peer(0, 100);
    let mut decoder = Decoder::new(102);
    decoder.source(0, &expected, now);
    decoder.source(1000, &peer(1, 101), now);
    decoder.source(1000, &[], now);
    decoder.repair(1000, 0, 1, &[0; 100], now);
    decoder.repair(1000, WINDOW + 1, 1, &[0; 100], now);
    decoder.repair(1000, 1, 1, &[0; 103], now);
    decoder.repair(1000, 1, 1, &[0; 17], now);
    decoder.repair(u64::MAX, 2, 1, &[0; 100], now);
    assert_eq!(decoder.highest, Some(0));
    assert_eq!(decoder.active_symbols(), 1);
    assert_eq!(decoder.equations(), 0);
}

#[test]
fn contradictory_equation_discards_pending_derivations_but_not_originals() {
    let now = Instant::now();
    let peers = [peer(0, 100), peer(1, 120), peer(2, 100)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.source(0, &peers[0], now);
    decoder.repair(1, 1, 1, &repair(1, &peers[1..2]), now);
    assert_eq!(decoder.active_symbols(), 2);
    decoder.repair(0, 1, 1, &repair(1, &peers[2..]), now);
    assert_eq!(decoder.active_symbols(), 1);
    assert!(decoder.take_recovered().is_none());
    assert!(decoder.slots[0].symbol.as_ref().unwrap().original);
}

#[test]
fn conflicting_originals_retire_the_id_without_using_either_value() {
    let now = Instant::now();
    let peers = [peer(0, 100), peer(1, 100)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.source(0, &peers[0], now);
    decoder.source(0, &peers[1], now);
    decoder.source(0, &peers[0], now);
    decoder.repair(0, 2, 1, &repair(1, &peers), now);
    assert_eq!(decoder.active_symbols(), 0);
    assert_eq!(decoder.equations(), 0);
    assert!(decoder.take_recovered().is_none());
}

#[test]
fn original_overrides_conflicting_pending_recovery() {
    let now = Instant::now();
    let peers = [peer(0, 100), peer(1, 100), peer(2, 160)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.repair(0, 1, 1, &repair(1, &peers[..1]), now);
    decoder.source(0, &peers[1], now);
    assert!(decoder.take_recovered().is_none());
    decoder.repair(0, 2, 2, &repair(2, &peers[1..]), now);
    let (id, recovered, _) = decoder.take_recovered().unwrap();
    assert_eq!(id, 1);
    assert_eq!(recovered, peers[2]);
}

#[test]
fn overlapping_different_lengths_extend_rows_before_elimination() {
    let now = Instant::now();
    let peers = [peer(0, 1000), peer(1, 80), peer(2, 200)];
    let mut decoder = Decoder::new(MAX_SYMBOL_LEN);
    decoder.repair(1, 2, 1, &repair(1, &peers[1..]), now);
    decoder.repair(0, 3, 2, &repair(2, &peers), now);
    decoder.source(1, &peers[1], now);
    assert_reduced(&decoder);
    let mut recovered = BTreeMap::new();
    drain(&mut decoder, &mut recovered);
    assert_eq!(
        recovered,
        BTreeMap::from([(0, peers[0].clone()), (2, peers[2].clone())])
    );
}
