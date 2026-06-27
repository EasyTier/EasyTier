use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use easytier::common::acl_processor::{AclProcessor, PacketInfo};
use easytier::proto::acl::*;
use std::net::{IpAddr, Ipv4Addr};

fn make_acl_config() -> Acl {
    let mut acl_config = Acl::default();
    let mut acl_v1 = AclV1::default();

    let mut chain = Chain {
        name: "bench_inbound".to_string(),
        chain_type: ChainType::Inbound as i32,
        enabled: true,
        ..Default::default()
    };

    chain.rules.push(Rule {
        name: "allow_all".to_string(),
        priority: 100,
        enabled: true,
        action: Action::Allow as i32,
        protocol: Protocol::Any as i32,
        ..Default::default()
    });

    acl_v1.chains.push(chain);
    acl_config.acl_v1 = Some(acl_v1);
    acl_config
}

fn make_packet_info() -> PacketInfo {
    PacketInfo {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: Some(12345),
        dst_port: Some(80),
        protocol: Protocol::Tcp,
        packet_size: 1024,
        src_groups: Arc::new(vec![]),
        dst_groups: Arc::new(vec![]),
    }
}

fn bench_cache_hit_single(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let processor = rt.block_on(async { AclProcessor::new(make_acl_config()) });
    let packet_info = make_packet_info();

    // Prime the cache
    let _ = processor.process_packet(&packet_info, ChainType::Inbound);

    c.bench_function("acl_cache_hit_1t", |b| {
        b.iter(|| {
            std::hint::black_box(processor.process_packet(&packet_info, ChainType::Inbound));
        });
    });
}

fn bench_cache_hit_multi(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("acl_cache_hit_multi");
    for threads in [2, 4, 8] {
        let processor = Arc::new(rt.block_on(async { AclProcessor::new(make_acl_config()) }));
        let packet_info = Arc::new(make_packet_info());

        // Prime the cache
        let _ = processor.process_packet(&packet_info, ChainType::Inbound);

        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    use std::sync::Barrier;
                    use std::thread;

                    let barrier = Arc::new(Barrier::new(threads + 1));
                    let per_thread = (iters / threads as u64) as usize;
                    let mut handles = Vec::with_capacity(threads);

                    for _ in 0..threads {
                        let processor = Arc::clone(&processor);
                        let packet_info = Arc::clone(&packet_info);
                        let barrier = Arc::clone(&barrier);
                        handles.push(thread::spawn(move || {
                            barrier.wait();
                            for _ in 0..per_thread {
                                std::hint::black_box(
                                    processor.process_packet(&packet_info, ChainType::Inbound),
                                );
                            }
                        }));
                    }

                    let start = std::time::Instant::now();
                    barrier.wait();
                    for handle in handles {
                        handle.join().unwrap();
                    }
                    start.elapsed()
                });
            },
        );
    }
    group.finish();
}

fn bench_unique_rule_match(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let processor = rt.block_on(async { AclProcessor::new(make_acl_config()) });

    c.bench_function("acl_unique_rule_match_1t", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let mut packet_info = make_packet_info();
            packet_info.src_port = Some((1024 + (i % 60_000)) as u16);
            packet_info.src_ip = IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            std::hint::black_box(processor.process_packet(&packet_info, ChainType::Inbound));
            i = i.wrapping_add(1);
        });
    });
}

criterion_group!(
    benches,
    bench_cache_hit_single,
    bench_cache_hit_multi,
    bench_unique_rule_match
);
criterion_main!(benches);
