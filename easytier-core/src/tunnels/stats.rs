use std::sync::atomic::{AtomicU32, AtomicU64};

pub struct WindowLatency {
    latency_us_window: Vec<AtomicU32>,
    latency_us_window_index: AtomicU32,
    latency_us_window_size: AtomicU32,
}

impl WindowLatency {
    pub fn new(window_size: u32) -> Self {
        Self {
            latency_us_window: (0..window_size).map(|_| AtomicU32::new(0)).collect(),
            latency_us_window_index: AtomicU32::new(0),
            latency_us_window_size: AtomicU32::new(window_size),
        }
    }

    pub fn record_latency(&self, latency_us: u32) {
        let index = self
            .latency_us_window_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let index = index
            % self
                .latency_us_window_size
                .load(std::sync::atomic::Ordering::Relaxed);
        self.latency_us_window[index as usize]
            .store(latency_us, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_latency_us<T: From<u32> + std::ops::Div<Output = T>>(&self) -> T {
        let window_size = self
            .latency_us_window_size
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut sum = 0;
        let mut count = 0;
        for i in 0..window_size {
            if i >= self
                .latency_us_window_index
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                break;
            }
            sum += self.latency_us_window[i as usize].load(std::sync::atomic::Ordering::Relaxed);
            count += 1;
        }

        if count == 0 {
            0.into()
        } else {
            (T::from(sum)) / T::from(count)
        }
    }
}

pub struct Throughput {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,

    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
}

impl Throughput {
    pub fn new() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),

            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
        }
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn tx_packets(&self) -> u64 {
        self.tx_packets.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn rx_packets(&self) -> u64 {
        self.rx_packets.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn record_tx_bytes(&self, bytes: u64) {
        self.tx_bytes
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        self.tx_packets
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_rx_bytes(&self, bytes: u64) {
        self.rx_bytes
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        self.rx_packets
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
