//! CPU hotspot benchmark for hotpath profiling.
//!
//! Builds two no-tun EasyTier instances connected via an in-process ring
//! tunnel, lets routes converge, then floods data-plane packets through
//! `send_msg_by_ip` so that `hotpath-cpu` / samply can collect meaningful
//! CPU samples.
//!
//! Build & run:
//!   cargo run --profile hotpath --features hotpath,hotpath-cpu \
//!     --example cpu_hotspot_ring
//!
//! Prerequisites: hotpath-samply + samply must be installed and on PATH.
//! See bench/006-hotpath-cpu-top.md for install instructions.
//!
//! Then in another terminal:
//!   hotpath console

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use bytes::BytesMut;

use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::instance::instance::Instance;
use easytier::tunnel::packet_def::ZCPacket;
use easytier::tunnel::ring::RingTunnelConnector;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(feature = "hotpath", hotpath::main)]
async fn main() {
    let duration = std::env::var("HOTPATH_BENCH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30u64);

    let pkt_size: usize = std::env::var("HOTPATH_PKT_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1400);

    let mut inst_a = Instance::new(no_tun_config("hot-a", "10.144.144.1"));
    let mut inst_b = Instance::new(no_tun_config("hot-b", "10.144.144.2"));

    inst_a.run().await.expect("inst_a run");
    inst_b.run().await.expect("inst_b run");

    let ring_url = format!("ring://{}", inst_a.id());
    inst_b
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(ring_url.parse().unwrap()));

    let dst: IpAddr = "10.144.144.2".parse().unwrap();
    let src = "10.144.144.1";

    let converged = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let a = inst_a.get_peer_manager().list_routes().await;
            let b = inst_b.get_peer_manager().list_routes().await;
            if a.len() >= 1 && b.len() >= 1 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .is_ok();

    if !converged {
        eprintln!("warning: routes did not converge within 15s");
    }

    println!(
        "cpu_hotspot_ring: flooding {}s, pkt_size={} (converged={})",
        duration, pkt_size, converged
    );

    let pm = inst_a.get_peer_manager();
    let send_pkt = make_data_packet(src, "10.144.144.2", pkt_size);

    let sender_task = tokio::spawn(async move {
        let mut sent: u64 = 0;
        let start = Instant::now();
        loop {
            let pkt = send_pkt.clone();
            let _ = pm.send_msg_by_ip(pkt, dst, false).await;
            sent += 1;
            if sent % 10000 == 0 {
                let elapsed = start.elapsed().as_secs_f64();
                let pps = sent as f64 / elapsed;
                let mbps = pps * pkt_size as f64 * 8.0 / 1_000_000.0;
                println!("sent {} pkts ({:.0} pps, {:.0} Mbps)", sent, pps, mbps);
            }
        }
    });

    tokio::time::sleep(Duration::from_secs(duration)).await;
    sender_task.abort();

    println!("cpu_hotspot_ring: done");
}

fn make_data_packet(src: &str, dst: &str, total_size: usize) -> ZCPacket {
    use std::net::Ipv4Addr;

    let hdr_len = 28;
    let payload_len = total_size.saturating_sub(hdr_len);
    let ip_total_len = (hdr_len + payload_len) as u16;

    let mut buf = BytesMut::with_capacity(total_size);

    buf.extend_from_slice(&[
        0x45,
        0x00,
        (ip_total_len >> 8) as u8,
        (ip_total_len & 0xff) as u8,
        0x00,
        0x00,
        0x40,
        0x00,
        0x40,
        0x11,
        0x00,
        0x00,
    ]);
    let src: Ipv4Addr = src.parse().unwrap();
    buf.extend_from_slice(&src.octets());
    let dst: Ipv4Addr = dst.parse().unwrap();
    buf.extend_from_slice(&dst.octets());

    let udp_len = (8 + payload_len) as u16;
    buf.extend_from_slice(&[
        0x30,
        0x39,
        0xD4,
        0x31,
        (udp_len >> 8) as u8,
        (udp_len & 0xff) as u8,
        0x00,
        0x00,
    ]);

    buf.resize(total_size, 0xAA);

    ZCPacket::new_with_payload(&buf)
}

fn no_tun_config(name: &str, ipv4: &str) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(name.to_owned());
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    let mut flags = config.get_flags();
    flags.no_tun = true;
    config.set_flags(flags);
    config
}
