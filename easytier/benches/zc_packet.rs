use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use easytier::tunnel::packet_def::{ZCPacket, ZCPacketType};

fn bench_new_with_payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("zc_new_with_payload");
    for size in [64usize, 1500] {
        let payload = vec![0xabu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            b.iter(|| {
                std::hint::black_box(ZCPacket::new_with_payload(std::hint::black_box(payload)));
            });
        });
    }
    group.finish();
}

fn bench_new_for_foreign_network(c: &mut Criterion) {
    let payload = vec![0xabu8; 64];
    let foreign_packet = ZCPacket::new_with_payload(&payload);
    let network_name = "bench-network".to_string();

    c.bench_function("zc_new_for_foreign_network_64b", |b| {
        b.iter(|| {
            std::hint::black_box(ZCPacket::new_for_foreign_network(
                std::hint::black_box(&network_name),
                42,
                std::hint::black_box(&foreign_packet),
            ));
        });
    });
}

fn bench_convert_type(c: &mut Criterion) {
    let payload = vec![0xabu8; 64];
    let packet = ZCPacket::new_with_payload(&payload);

    c.bench_function("zc_convert_type_tcp_64b", |b| {
        b.iter(|| {
            let p = std::hint::black_box(packet.clone());
            std::hint::black_box(p.convert_type(ZCPacketType::TCP));
        });
    });
}

criterion_group!(
    benches,
    bench_new_with_payload,
    bench_new_for_foreign_network,
    bench_convert_type
);
criterion_main!(benches);
