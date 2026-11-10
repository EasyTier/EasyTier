//! Deterministic offline comparison; no sockets, congestion model or CPU clock.

use std::{path::PathBuf, time::Instant as WallInstant};

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde_json::{Value, json};

use crate::{
    foundation::time::{Duration, Instant},
    packet::{PacketType, ZCPacket},
};

use super::{codec::Decoder, send::Tx, wire};

struct Input {
    at_ms: u64,
    packet: ZCPacket,
}

struct Outcome {
    delivered_ms: Vec<Option<u64>>,
    source_lost: Vec<bool>,
    repairs: usize,
    repairs_lost: usize,
    source_symbol_bytes: usize,
    repair_symbol_bytes: usize,
    source_wire_bytes: usize,
    repair_wire_bytes: usize,
    encode_wall_ns: u128,
    decode_wall_ns: u128,
    tx_payload_capacity_peak: usize,
    rx_payload_capacity_peak: usize,
    rx_symbols_peak: usize,
    rx_equations_peak: usize,
}

impl Outcome {
    fn new(input: &[Input]) -> Self {
        Self {
            delivered_ms: vec![None; input.len()],
            source_lost: vec![false; input.len()],
            repairs: 0,
            repairs_lost: 0,
            source_symbol_bytes: input
                .iter()
                .map(|i| i.packet.tunnel_payload().len() + 2)
                .sum(),
            repair_symbol_bytes: 0,
            source_wire_bytes: 0,
            repair_wire_bytes: 0,
            encode_wall_ns: 0,
            decode_wall_ns: 0,
            tx_payload_capacity_peak: 0,
            rx_payload_capacity_peak: 0,
            rx_symbols_peak: 0,
            rx_equations_peak: 0,
        }
    }

    fn source(&mut self, id: usize, at: u64, wire_bytes: usize, lost: bool) {
        self.source_wire_bytes += wire_bytes;
        self.source_lost[id] = lost;
        if !lost {
            self.delivered_ms[id] = Some(at);
        }
    }

    fn repaired(&mut self, id: usize, peer: &[u8], at: u64, input: &[Input]) {
        assert_eq!(peer, input[id].packet.tunnel_payload());
        self.delivered_ms[id].get_or_insert(at);
    }

    fn report(self, case: &str, seed: u64, codec: &str, input: &[Input]) -> Value {
        let delivered = self.delivered_ms.iter().flatten().count();
        let timely: Vec<_> = [20, 50, 100]
            .into_iter()
            .map(|deadline| {
                let count = self
                    .delivered_ms
                    .iter()
                    .zip(input)
                    .filter(|(at, source)| at.is_some_and(|at| at - source.at_ms <= deadline))
                    .count();
                json!({"deadline_ms": deadline, "delivered": count,
                    "fraction_of_scheduled": count as f64 / input.len() as f64})
            })
            .collect();
        json!({
            "case": case, "seed": seed, "codec": codec,
            "scheduled": input.len(), "last_source_ms": input.last().unwrap().at_ms,
            "source_lost": self.source_lost.iter().filter(|lost| **lost).count(),
            "delivered": delivered, "final_fraction_of_scheduled": delivered as f64 / input.len() as f64,
            "recovered": self.source_lost.iter().zip(&self.delivered_ms)
                .filter(|(lost, at)| **lost && at.is_some()).count(),
            "timely": timely, "repairs": self.repairs, "repairs_lost": self.repairs_lost,
            "source_symbol_bytes": self.source_symbol_bytes,
            "repair_symbol_bytes": self.repair_symbol_bytes,
            "total_symbol_bytes": self.source_symbol_bytes + self.repair_symbol_bytes,
            "source_wire_bytes": self.source_wire_bytes, "repair_wire_bytes": self.repair_wire_bytes,
            "total_wire_bytes": self.source_wire_bytes + self.repair_wire_bytes,
            "encode_wall_ns": self.encode_wall_ns, "decode_wall_ns": self.decode_wall_ns,
            "tx_payload_vec_capacity_peak": self.tx_payload_capacity_peak,
            "rx_payload_vec_capacity_peak": self.rx_payload_capacity_peak,
            "rx_symbols_peak": self.rx_symbols_peak, "rx_equations_peak": self.rx_equations_peak,
        })
    }
}

fn inputs(case: &str) -> Vec<Input> {
    let sparse = case == "sparse";
    (0..if sparse { 120 } else { 600 })
        .map(|id| {
            let len = if sparse {
                200
            } else if (case == "mixed" && id % 2 == 0)
                || (case == "mixed_batches" && (id / 10) % 2 == 1)
            {
                80
            } else {
                1200
            };
            let payload: Vec<_> = (0..len).map(|offset| (id + offset) as u8).collect();
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.fill_peer_manager_hdr(11, 22, PacketType::Data as u8);
            Input {
                at_ms: id as u64 * if sparse { 50 } else { 1 },
                packet,
            }
        })
        .collect()
}

fn lost(case: &str, seed: u64, repair: bool, id: usize, at_ms: u64) -> bool {
    if case == "burst_loss" {
        // An eight-millisecond outage every 100ms affects both frame kinds.
        return (at_ms + seed) % 100 < 8;
    }
    // Source IDs and repair ordinals share their masks across both codecs.
    let mut value = seed
        ^ (id as u64).wrapping_mul(0x9e3779b97f4a7c15)
        ^ if repair { 0xd1b54a32d192ed03 } else { 0 };
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    (value ^ (value >> 31)).is_multiple_of(10)
}

fn observe_decoder(out: &mut Outcome, decoder: &Decoder) {
    out.rx_payload_capacity_peak = out.rx_payload_capacity_peak.max(decoder.cached_bytes());
    out.rx_symbols_peak = out.rx_symbols_peak.max(decoder.active_symbols());
    out.rx_equations_peak = out.rx_equations_peak.max(decoder.equations());
}

fn drain(decoder: &mut Decoder, out: &mut Outcome, input: &[Input], at: u64) {
    while let Some((id, peer, _)) = decoder.take_recovered() {
        out.repaired(id as usize, peer, at, input);
    }
}

fn sliding(case: &str, seed: u64, input: &[Input]) -> Outcome {
    let mut out = Outcome::new(input);
    let mut tx = Tx::new(1400);
    let mut decoder = Decoder::new(1400);
    let base = Instant::now();
    let mut next = 0;
    for at in 0..=input.last().unwrap().at_ms + 300 {
        let now = base + Duration::from_millis(at);
        if next < input.len() && input[next].at_ms == at {
            let start = WallInstant::now();
            let (id, frame) = tx.prepare(&input[next].packet).unwrap();
            tx.accepted(id, input[next].packet.tunnel_payload(), now);
            out.encode_wall_ns += start.elapsed().as_nanos();
            assert_eq!(id as usize, next);
            let missing = lost(case, seed, false, next, at);
            out.source(next, at, frame.tunnel_payload().len(), missing);
            if !missing {
                let start = WallInstant::now();
                let (id, peer) = wire::parse_source(&frame, 1400).unwrap();
                decoder.source(id, peer, now);
                drain(&mut decoder, &mut out, input, at);
                out.decode_wall_ns += start.elapsed().as_nanos();
            }
            next += 1;
        }
        out.tx_payload_capacity_peak = out.tx_payload_capacity_peak.max(tx.cached_bytes());
        if tx.repairs_due(now) {
            let start = WallInstant::now();
            let repairs = tx.take_repairs(now);
            out.encode_wall_ns += start.elapsed().as_nanos();
            for frame in repairs {
                let (first, count, repair, data) = wire::parse_repair(&frame, 1400).unwrap();
                out.repair_symbol_bytes += data.len();
                out.repair_wire_bytes += frame.tunnel_payload().len();
                let missing = lost(case, seed, true, out.repairs, at);
                out.repairs += 1;
                out.repairs_lost += usize::from(missing);
                if !missing {
                    let start = WallInstant::now();
                    decoder.repair(first, count, repair, data, now);
                    drain(&mut decoder, &mut out, input, at);
                    out.decode_wall_ns += start.elapsed().as_nanos();
                    observe_decoder(&mut out, &decoder);
                }
            }
        }
        observe_decoder(&mut out, &decoder);
        if tx.deadline().is_some_and(|deadline| deadline <= now) {
            let start = WallInstant::now();
            tx.expire(now);
            out.encode_wall_ns += start.elapsed().as_nanos();
        }
        if decoder.deadline().is_some_and(|deadline| deadline <= now) {
            let start = WallInstant::now();
            decoder.expire(now);
            out.decode_wall_ns += start.elapsed().as_nanos();
        }
    }
    out
}

fn block(case: &str, seed: u64, input: &[Input]) -> Outcome {
    let mut out = Outcome::new(input);
    // Cache the ten fixed block layouts outside the measured coding work.
    let codecs: Vec<_> = (1usize..=10)
        .map(|k| ReedSolomon::new(k, k.div_ceil(5)).unwrap())
        .collect();
    let mut sources = Vec::<Vec<u8>>::new();
    let mut received = Vec::<Option<Vec<u8>>>::new();
    let mut first = 0;
    let mut next = 0;
    let mut batch_started = None;
    for at in 0..=input.last().unwrap().at_ms + 300 {
        if next < input.len() && input[next].at_ms == at {
            let start = WallInstant::now();
            let peer = input[next].packet.tunnel_payload();
            let mut symbol = Vec::with_capacity(peer.len() + 2);
            symbol.extend_from_slice(&(peer.len() as u16).to_le_bytes());
            symbol.extend_from_slice(peer);
            sources.push(symbol);
            batch_started.get_or_insert(at);
            out.encode_wall_ns += start.elapsed().as_nanos();
            let missing = lost(case, seed, false, next, at);
            out.source(next, at, peer.len() + wire::SOURCE_HEADER_SIZE, missing);
            let start = WallInstant::now();
            received.push((!missing).then(|| sources.last().unwrap().clone()));
            out.decode_wall_ns += start.elapsed().as_nanos();
            next += 1;
        }
        out.tx_payload_capacity_peak = out
            .tx_payload_capacity_peak
            .max(sources.iter().map(Vec::capacity).sum());
        out.rx_payload_capacity_peak = out
            .rx_payload_capacity_peak
            .max(received.iter().flatten().map(Vec::capacity).sum());
        out.rx_symbols_peak = out.rx_symbols_peak.max(received.iter().flatten().count());
        if sources.len() != 10 && batch_started.is_none_or(|start| start + 20 > at) {
            continue;
        }
        let k = sources.len();
        let r = k.div_ceil(5);
        let len = sources.iter().map(Vec::len).max().unwrap();
        let start = WallInstant::now();
        for source in &mut sources {
            source.resize(len, 0);
        }
        sources.extend((0..r).map(|_| vec![0; len]));
        codecs[k - 1].encode(&mut sources).unwrap();
        out.encode_wall_ns += start.elapsed().as_nanos();
        out.tx_payload_capacity_peak = out
            .tx_payload_capacity_peak
            .max(sources[..k].iter().map(Vec::capacity).sum());
        for symbol in &sources[k..] {
            out.repair_symbol_bytes += symbol.len();
            out.repair_wire_bytes += wire::REPAIR_HEADER_SIZE + symbol.len();
            let missing = lost(case, seed, true, out.repairs, at);
            out.repairs += 1;
            out.repairs_lost += usize::from(missing);
            let start = WallInstant::now();
            received.push((!missing).then(|| symbol.clone()));
            out.decode_wall_ns += start.elapsed().as_nanos();
        }
        let start = WallInstant::now();
        for symbol in received.iter_mut().flatten() {
            symbol.resize(len, 0);
        }
        if received.iter().flatten().count() >= k {
            codecs[k - 1].reconstruct_data(&mut received).unwrap();
            for (index, symbol) in received[..k].iter().enumerate() {
                let symbol = symbol.as_ref().unwrap();
                let len = u16::from_le_bytes(symbol[..2].try_into().unwrap()) as usize;
                out.repaired(first + index, &symbol[2..2 + len], at, input);
            }
        }
        out.decode_wall_ns += start.elapsed().as_nanos();
        out.rx_payload_capacity_peak = out
            .rx_payload_capacity_peak
            .max(received.iter().flatten().map(Vec::capacity).sum());
        out.rx_symbols_peak = out
            .rx_symbols_peak
            .max(received[..k].iter().flatten().count());
        out.rx_equations_peak = out
            .rx_equations_peak
            .max(received[k..].iter().flatten().count());
        // All zero-delay frame arrivals are complete. No later block covers
        // these sources, so keeping a failed block cannot recover more data.
        sources.clear();
        received.clear();
        first = next;
        batch_started = None;
    }
    out
}

#[test]
#[ignore = "offline coding comparison; set FEC_BENCH_OUTPUT to save JSON"]
fn compare_block_and_sliding_recovery() {
    let output = PathBuf::from(std::env::var_os("FEC_BENCH_OUTPUT").expect("set FEC_BENCH_OUTPUT"));
    let mut results = Vec::new();
    for case in [
        "sustained",
        "sparse",
        "mixed",
        "mixed_batches",
        "burst_loss",
    ] {
        let input = inputs(case);
        for seed in [17, 41, 97] {
            let rs = block(case, seed, &input);
            let rlc = sliding(case, seed, &input);
            assert_eq!(rs.repairs, rlc.repairs);
            assert_eq!(rs.source_lost, rlc.source_lost);
            assert_eq!(rs.repairs_lost, rlc.repairs_lost);
            assert_eq!(rs.source_wire_bytes, rlc.source_wire_bytes);
            results.push(rs.report(case, seed, "independent_block_rs", &input));
            results.push(rlc.report(case, seed, "sliding_rlc", &input));
        }
    }
    let report = json!({
        "contract": {
            "input": "600 payloads at 1ms: sustained/burst 1200B, mixed alternates 80/1200B, mixed_batches alternates ten1200B then ten80B; sparse 120 payloads of 200B at 50ms; complete peer packets add 16B",
            "schedule": "sources immediate; RLC emits one repair per five sources with ceil(new_sources/5) total at ten sources or20ms; RS repairs independent blocks at ten sources or20ms with the same total count; RLC uses production Tx W20 age100ms",
            "network": "zero propagation/serialization delay; deterministic 10% frame loss, or 8ms outage per100ms; source IDs and repair ordinals share loss masks; no queue/congestion model",
            "delivery": "all scheduled input is denominator; inclusive deadlines from scheduled source time; final after300ms drain; every recovered peer packet verified byte-for-byte",
            "wire": "modeled bytes from the independent FEC header through coding payload, excludes UDP tunnel header, IP/UDP/Ethernet and encryption; source adds9B to complete peer, repair adds14B to symbol (symbol includes2B length); RS assigned same envelope, not a deployed RS wire protocol",
            "symbols": "source bytes are unpadded length-prefixed input once; repair bytes include actual padded equations; excludes repeated coding reads and temporary RS padding of source shards",
            "compute": "summed std::time::Instant elapsed wall nanoseconds around sender/receiver work, includes harness allocation/verification but not loss generation or JSON; excludes RS layout construction; not process CPU or virtual network latency; single run, no significance claim",
            "cache": "sampled sender source-cache and receiver symbol/equation Vec capacities at event boundaries; excludes metadata, allocator overhead, coding-library scratch and emitted repair vectors for both codecs; decoder symbol/equation counts are separately reported; not RSS or total peak allocation",
            "limits": "component recovery/coding diagnostic only; no sockets, transport negotiation, MTU, encryption, TCP, congestion, or end-to-end product performance validation"
        },
        "results": results
    });
    std::fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
