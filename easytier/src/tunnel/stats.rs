use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

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

#[derive(Default, Copy, Clone, Debug)]
pub struct Throughput {
    tx_bytes: u64,
    rx_bytes: u64,

    tx_packets: u64,
    rx_packets: u64,
}

impl Throughput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes
    }

    pub fn tx_packets(&self) -> u64 {
        self.tx_packets
    }

    pub fn rx_packets(&self) -> u64 {
        self.rx_packets
    }

    pub fn record_tx_bytes(&self, bytes: u64) {
        #[allow(invalid_reference_casting)]
        unsafe {
            *(&self.tx_bytes as *const u64 as *mut u64) += bytes;
            *(&self.tx_packets as *const u64 as *mut u64) += 1;
        }
    }

    pub fn record_rx_bytes(&self, bytes: u64) {
        #[allow(invalid_reference_casting)]
        unsafe {
            *(&self.rx_bytes as *const u64 as *mut u64) += bytes;
            *(&self.rx_packets as *const u64 as *mut u64) += 1;
        }
    }
}
