use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

pub struct WindowLatency {
    latency_us_window: Vec<AtomicU32>,
    latency_us_window_index: AtomicU32,
    latency_us_window_size: u32,

    sum: AtomicU32,
    count: AtomicU32,
}

impl std::fmt::Debug for WindowLatency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowLatency")
            .field("count", &self.count)
            .field("window_size", &self.latency_us_window_size)
            .field("window_latency", &self.get_latency_us::<u32>())
            .finish()
    }
}

impl WindowLatency {
    pub fn new(window_size: u32) -> Self {
        Self {
            latency_us_window: (0..window_size).map(|_| AtomicU32::new(0)).collect(),
            latency_us_window_index: AtomicU32::new(0),
            latency_us_window_size: window_size,

            sum: AtomicU32::new(0),
            count: AtomicU32::new(0),
        }
    }

    pub fn record_latency(&self, latency_us: u32) {
        let index = self.latency_us_window_index.fetch_add(1, Relaxed);
        if self.count.load(Relaxed) < self.latency_us_window_size {
            self.count.fetch_add(1, Relaxed);
        }

        let index = index % self.latency_us_window_size;
        let old_lat = self.latency_us_window[index as usize].swap(latency_us, Relaxed);

        if old_lat < latency_us {
            self.sum.fetch_add(latency_us - old_lat, Relaxed);
        } else {
            self.sum.fetch_sub(old_lat - latency_us, Relaxed);
        }
    }

    pub fn get_latency_us<T: From<u32> + std::ops::Div<Output = T>>(&self) -> T {
        let count = self.count.load(Relaxed);
        let sum = self.sum.load(Relaxed);
        if count == 0 {
            0.into()
        } else {
            (T::from(sum)) / T::from(count)
        }
    }
}

#[derive(Debug)]
pub struct Throughput {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
}

impl Clone for Throughput {
    fn clone(&self) -> Self {
        Self {
            tx_bytes: AtomicU64::new(self.tx_bytes()),
            rx_bytes: AtomicU64::new(self.rx_bytes()),
            tx_packets: AtomicU64::new(self.tx_packets()),
            rx_packets: AtomicU64::new(self.rx_packets()),
        }
    }
}

impl Default for Throughput {
    fn default() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
        }
    }
}

impl Throughput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Relaxed)
    }

    pub fn tx_packets(&self) -> u64 {
        self.tx_packets.load(Relaxed)
    }

    pub fn rx_packets(&self) -> u64 {
        self.rx_packets.load(Relaxed)
    }

    pub fn record_tx_bytes(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Relaxed);
        self.tx_packets.fetch_add(1, Relaxed);
    }

    pub fn record_rx_bytes(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Relaxed);
        self.rx_packets.fetch_add(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::Throughput;
    use std::sync::Arc;

    #[test]
    fn throughput_records_concurrent_tx_and_rx() {
        const THREADS: usize = 8;
        const RECORDS_PER_THREAD: usize = 10_000;
        const TX_BYTES_PER_RECORD: u64 = 3;
        const RX_BYTES_PER_RECORD: u64 = 7;

        let throughput = Arc::new(Throughput::new());

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let throughput = Arc::clone(&throughput);
                scope.spawn(move || {
                    for _ in 0..RECORDS_PER_THREAD {
                        throughput.record_tx_bytes(TX_BYTES_PER_RECORD);
                        throughput.record_rx_bytes(RX_BYTES_PER_RECORD);
                    }
                });
            }
        });

        let expected_packets = (THREADS * RECORDS_PER_THREAD) as u64;
        assert_eq!(throughput.tx_packets(), expected_packets);
        assert_eq!(throughput.rx_packets(), expected_packets);
        assert_eq!(
            throughput.tx_bytes(),
            expected_packets * TX_BYTES_PER_RECORD
        );
        assert_eq!(
            throughput.rx_bytes(),
            expected_packets * RX_BYTES_PER_RECORD
        );
    }
}
