use atomic_shim::AtomicU64;
use std::sync::atomic::Ordering;

use easytier_proto::peer_rpc::PeerConnFecStats;

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        #[derive(Default)]
        pub(super) struct Counters {
            $(pub $name: AtomicU64,)*
            pub recovery_latency_buckets: [AtomicU64; 6],
        }

        impl Counters {
            pub fn snapshot(&self) -> PeerConnFecStats {
                PeerConnFecStats {
                    $($name: self.$name.load(Ordering::Relaxed),)*
                    recovery_latency_buckets: self.recovery_latency_buckets.iter()
                        .map(|bucket| bucket.load(Ordering::Relaxed)).collect(),
                    ..PeerConnFecStats::default()
                }
            }
        }
    };
}

counters!(
    tx_source_packets,
    tx_source_bytes,
    tx_source_baseline_bytes,
    tx_repair_packets,
    tx_repair_bytes,
    rx_source_packets,
    rx_source_bytes,
    rx_repair_packets,
    rx_repair_bytes,
    recovered_packets,
    recovered_bytes,
    duplicate_packets,
    expired_symbols,
    window_drops,
    protocol_errors,
    bypass_oversize,
    bypass_ineligible,
    no_credit_repairs,
    rx_queue_drops,
    resource_drops,
    cache_evictions,
    tx_feedback_packets,
    tx_feedback_bytes,
    rx_feedback_packets,
    rx_feedback_bytes,
);

pub(super) fn add(counter: &AtomicU64, value: usize) {
    counter.fetch_add(value as u64, Ordering::Relaxed);
}
