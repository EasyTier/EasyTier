use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};

use easytier::tunnel::packet_def::ZCPacket;

const PAYLOAD_SIZES: &[usize] = &[1280, 4096];

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn bench_payload_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload_bytes");
    for &size in PAYLOAD_SIZES {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("{size}"), &data, |b, data| {
            b.iter_batched(
                || ZCPacket::new_with_payload(black_box(data)),
                |p| black_box(p).payload_bytes(),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_tunnel_payload_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("tunnel_payload_bytes");
    for &size in PAYLOAD_SIZES {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("{size}"), &data, |b, data| {
            b.iter_batched(
                || ZCPacket::new_with_payload(black_box(data)),
                |p| black_box(p).tunnel_payload_bytes(),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn criterion_config() -> Criterion {
    let measurement_secs = env_parse("PACKET_BYTES_MEASUREMENT_SECS", 10u64);
    let warmup_secs = env_parse("PACKET_BYTES_WARMUP_SECS", 3u64);
    let sample_size = env_parse("PACKET_BYTES_SAMPLE_SIZE", 10usize).max(10);

    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .warm_up_time(Duration::from_secs(warmup_secs))
        .sample_size(sample_size)
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_payload_bytes, bench_tunnel_payload_bytes
}
criterion_main!(benches);
