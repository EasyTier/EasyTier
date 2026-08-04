use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;

use crate::foundation::time;

#[async_trait::async_trait]
pub(crate) trait ByteLimiter: Send + Sync {
    async fn consume(&self, bytes: u64);

    fn try_consume(&self, bytes: u64) -> bool;
}

#[async_trait::async_trait]
impl ByteLimiter for () {
    async fn consume(&self, _bytes: u64) {}

    fn try_consume(&self, _bytes: u64) -> bool {
        true
    }
}

pub(crate) type ArcByteLimiter = Arc<dyn ByteLimiter>;

const MIN_FILL_RATE: u64 = 8_196;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Token Bucket rate limiter with on-demand refill.
pub struct TokenBucket {
    state: Mutex<BucketState>,
    config: BucketConfig,
    stop_notifier: Notify,
    stopped: AtomicBool,
}

struct BucketState {
    available_tokens: u64,
    last_refill: Instant,
    refill_remainder: u64,
}

#[derive(Clone, Copy)]
pub struct BucketConfig {
    capacity: u64,
    fill_rate: u64,
}

impl BucketConfig {
    pub fn new(capacity: u64, fill_rate: u64) -> Self {
        Self {
            capacity,
            fill_rate,
        }
    }

    pub fn with_default_capacity(fill_rate: u64) -> Self {
        let fill_rate = fill_rate.max(MIN_FILL_RATE);
        Self::new(fill_rate, fill_rate)
    }
}

impl TokenBucket {
    pub fn new(capacity: u64, bps: u64) -> Arc<Self> {
        Self::new_from_cfg(BucketConfig::new(capacity, bps))
    }

    /// Creates a new Token Bucket rate limiter
    ///
    /// # Arguments
    /// * `capacity` - Bucket capacity in bytes
    /// * `bps` - Bandwidth limit in bytes per second
    pub fn new_from_cfg(mut config: BucketConfig) -> Arc<Self> {
        config.capacity = config.capacity.max(1);
        config.fill_rate = config.fill_rate.max(1);

        Arc::new(Self {
            state: Mutex::new(BucketState {
                available_tokens: config.capacity,
                last_refill: Instant::now(),
                refill_remainder: 0,
            }),
            config,
            stop_notifier: Notify::new(),
            stopped: AtomicBool::new(false),
        })
    }

    /// Refill tokens based on elapsed time since last refill.
    /// Called while holding the bucket state lock.
    fn refill(&self, state: &mut BucketState, now: Instant) {
        let elapsed_nanos = now.saturating_duration_since(state.last_refill).as_nanos();
        if elapsed_nanos == 0 {
            return;
        }

        state.last_refill = now;
        if state.available_tokens == self.config.capacity {
            state.refill_remainder = 0;
            return;
        }

        let generated = (self.config.fill_rate as u128)
            .saturating_mul(elapsed_nanos)
            .saturating_add(state.refill_remainder as u128);
        let tokens_to_add = generated / NANOS_PER_SECOND;
        let refill_remainder = generated % NANOS_PER_SECOND;
        let available_capacity = self.config.capacity - state.available_tokens;

        if tokens_to_add >= available_capacity as u128 {
            state.available_tokens = self.config.capacity;
            state.refill_remainder = 0;
        } else {
            state.available_tokens += tokens_to_add as u64;
            state.refill_remainder = refill_remainder as u64;
        }
    }

    /// Attempt to consume tokens without blocking
    ///
    /// # Returns
    /// `true` if tokens were consumed, `false` if insufficient tokens
    pub fn try_consume(&self, tokens: u64) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return true;
        }
        // Fast path for oversized packets
        if tokens > self.config.capacity {
            return false;
        }

        let mut state = self.state.lock();
        self.refill(&mut state, Instant::now());
        if state.available_tokens < tokens {
            return false;
        }

        state.available_tokens -= tokens;
        true
    }

    /// Consume tokens, sleeping until they become available.
    pub async fn consume(&self, tokens: u64) {
        let mut remaining = tokens;
        while remaining > 0 {
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let chunk = remaining.min(self.config.capacity);
            self.consume_chunk(chunk).await;
            remaining -= chunk;
        }
    }

    async fn consume_chunk(&self, tokens: u64) {
        loop {
            let stopped = self.stop_notifier.notified();
            if self.stopped.load(Ordering::Acquire) {
                return;
            }

            let sleep_dur = {
                let mut state = self.state.lock();
                self.refill(&mut state, Instant::now());
                if state.available_tokens >= tokens {
                    state.available_tokens -= tokens;
                    return;
                }

                let deficit = tokens - state.available_tokens;
                let required = deficit as u128 * NANOS_PER_SECOND;
                let remaining = required - state.refill_remainder as u128;
                let sleep_nanos = remaining
                    .div_ceil(self.config.fill_rate as u128)
                    .min(u64::MAX as u128) as u64;
                Duration::from_nanos(sleep_nanos.max(1_000_000))
            };

            tokio::select! {
                _ = time::sleep(sleep_dur) => {}
                _ = stopped => {}
            }
        }
    }

    async fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stop_notifier.notify_waiters();
    }
}

#[async_trait::async_trait]
impl ByteLimiter for TokenBucket {
    async fn consume(&self, bytes: u64) {
        TokenBucket::consume(self, bytes).await;
    }

    fn try_consume(&self, bytes: u64) -> bool {
        TokenBucket::try_consume(self, bytes)
    }
}

pub struct TokenBucketManager {
    buckets: Arc<DashMap<String, Arc<TokenBucket>>>,
    retain_task: StdMutex<Option<AbortOnDropHandle<()>>>,
}

impl Default for TokenBucketManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenBucketManager {
    /// Creates a new TokenBucketManager
    pub fn new() -> Self {
        let buckets = Arc::new(DashMap::new());

        let buckets_clone = buckets.clone();
        let retain_task = tokio::spawn(async move {
            loop {
                // Retain only buckets that are still in use
                let old_len = buckets_clone.len();
                buckets_clone.retain(|_, bucket| Arc::<TokenBucket>::strong_count(bucket) > 1);
                buckets_clone.shrink_to_fit();
                // Sleep for a while before next retention check
                time::sleep(Duration::from_secs(5)).await;
                tracing::info!(
                    "Retained buckets: {} ({} dropped)",
                    buckets_clone.len(),
                    old_len.saturating_sub(buckets_clone.len())
                );
            }
        });

        Self {
            buckets,
            retain_task: StdMutex::new(Some(AbortOnDropHandle::new(retain_task))),
        }
    }

    /// Get or create a token bucket for the given key
    pub fn get_or_create(&self, key: &str, cfg: BucketConfig) -> Arc<TokenBucket> {
        self.buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new_from_cfg(cfg))
            .clone()
    }

    pub async fn stop(&self) {
        let retain_task = self.retain_task.lock().unwrap().take();
        if let Some(retain_task) = retain_task {
            retain_task.abort();
            let _ = retain_task.await;
        }
        let buckets = self
            .buckets
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        for bucket in buckets {
            bucket.stop().await;
        }
        self.buckets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep, timeout};

    #[test]
    fn bucket_config_uses_one_second_default_capacity() {
        let config = BucketConfig::with_default_capacity(100_000);

        assert_eq!(config.capacity, 100_000);
        assert_eq!(config.fill_rate, 100_000);
    }

    #[test]
    fn bucket_config_default_capacity_fits_regular_packets() {
        let config = BucketConfig::with_default_capacity(8_196);

        assert_eq!(config.capacity, 8_196);
        assert_eq!(config.fill_rate, 8_196);
    }

    #[test]
    fn bucket_config_preserves_explicit_capacity() {
        let config = BucketConfig::new(200_000, 100_000);

        assert_eq!(config.capacity, 200_000);
        assert_eq!(config.fill_rate, 100_000);
    }

    /// Test initial state after creation
    #[tokio::test]
    async fn test_initial_state() {
        let bucket = TokenBucket::new(1000, 1000);

        // Should have full capacity initially
        assert!(bucket.try_consume(1000));
        assert!(!bucket.try_consume(1)); // Should be empty now
    }

    /// Test token consumption behavior
    #[tokio::test]
    async fn test_consumption() {
        let bucket = TokenBucket::new(1500, 1000);

        // First packet should succeed
        assert!(bucket.try_consume(1000));

        // Second packet should fail (only 500 left)
        assert!(!bucket.try_consume(600));

        // Should be able to take remaining tokens
        assert!(bucket.try_consume(500));
    }

    #[tokio::test]
    async fn stop_releases_waiting_consumers() {
        let bucket = TokenBucket::new(1, 1);
        assert!(bucket.try_consume(1));
        let waiting = tokio::spawn({
            let bucket = bucket.clone();
            async move { bucket.consume(1).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());

        bucket.stop().await;

        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("stopped limiter should release consumers")
            .unwrap();
        assert!(bucket.try_consume(u64::MAX));
    }

    /// Test lazy refill functionality
    #[tokio::test]
    async fn test_refill() {
        let bucket = TokenBucket::new(1_000_000, 10_000);

        // Drain the bucket
        assert!(bucket.try_consume(1_000_000));

        // Wait for time to pass (tokens accumulate lazily on next consume)
        sleep(Duration::from_millis(25)).await;
        let tokens = {
            let mut state = bucket.state.lock();
            bucket.refill(&mut state, Instant::now());
            state.available_tokens
        };
        assert!(tokens > 0, "Expected some refilled tokens");
        assert!(
            tokens < bucket.config.capacity,
            "Bucket unexpectedly refilled to capacity: {}",
            tokens
        );
    }

    #[test]
    fn test_refill_preserves_fractional_tokens() {
        let bucket = TokenBucket::new(100, 100);
        let start = Instant::now();
        let mut state = bucket.state.lock();
        state.available_tokens = 0;
        state.last_refill = start;
        state.refill_remainder = 0;

        for step in 1..=10 {
            bucket.refill(&mut state, start + Duration::from_millis(step * 15));
        }

        assert_eq!(state.available_tokens, 15);
        assert_eq!(state.refill_remainder, 0);
    }

    #[test]
    fn test_refill_preserves_submicrosecond_time() {
        let bucket = TokenBucket::new(100, 1_000_000);
        let start = Instant::now();
        let mut state = bucket.state.lock();
        state.available_tokens = 0;
        state.last_refill = start;
        state.refill_remainder = 0;

        for step in 1..=10 {
            bucket.refill(&mut state, start + Duration::from_nanos(step * 1_500));
        }

        assert_eq!(state.available_tokens, 15);
        assert_eq!(state.refill_remainder, 0);
    }

    #[test]
    fn test_refill_discards_excess_credit_at_capacity() {
        let bucket = TokenBucket::new(10, 10);
        let start = Instant::now();
        let mut state = bucket.state.lock();
        state.available_tokens = 0;
        state.last_refill = start;

        let refill_time = start + Duration::from_secs(2);
        bucket.refill(&mut state, refill_time);
        assert_eq!(state.available_tokens, 10);
        assert_eq!(state.refill_remainder, 0);

        state.available_tokens = 0;
        bucket.refill(&mut state, refill_time);
        assert_eq!(state.available_tokens, 0);
    }

    /// Test capacity enforcement
    #[tokio::test]
    async fn test_capacity_limit() {
        let bucket = TokenBucket::new(500, 1000);

        // Wait longer than refill interval
        sleep(Duration::from_millis(50)).await;

        // Should not exceed capacity despite time passed
        assert!(bucket.try_consume(500));
        assert!(!bucket.try_consume(1));
    }

    /// Test high load with concurrent access
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_access() {
        let bucket = TokenBucket::new(10_000, 1);
        let mut handles = vec![];

        // Spawn 100 tasks to consume tokens concurrently
        for _ in 0..100 {
            let bucket = bucket.clone();
            handles.push(tokio::spawn(async move {
                let mut consumed = 0;
                for _ in 0..100 {
                    if bucket.try_consume(10) {
                        consumed += 10;
                    }
                }
                consumed
            }));
        }

        // Wait for all tasks to complete
        let mut consumed = 0;
        for handle in handles {
            consumed += handle.await.unwrap();
        }

        assert_eq!(consumed, 10_000);
        assert_eq!(bucket.state.lock().available_tokens, 0);
    }

    /// Test behavior when packet size exceeds capacity
    #[tokio::test]
    async fn test_oversized_packet() {
        let bucket = TokenBucket::new(1500, 1000);

        // Packet larger than capacity should be rejected
        assert!(!bucket.try_consume(1600));

        // Regular packets should still work
        assert!(bucket.try_consume(1000));
    }

    #[tokio::test]
    async fn test_zero_fill_rate_is_normalized() {
        let bucket = TokenBucket::new(1000, 0);

        assert_eq!(bucket.config.fill_rate, 1);
    }

    #[tokio::test]
    async fn test_consume_oversized_packet_in_chunks() {
        let bucket = TokenBucket::new(10, 1_000_000);

        timeout(Duration::from_millis(100), bucket.consume(25))
            .await
            .expect("oversized consume should be split into capacity-sized chunks");
    }

    /// Test refill precision after elapsed time.
    #[test]
    fn test_refill_precision() {
        let bucket = TokenBucket::new(10_000, 10_000);
        let start = Instant::now();
        let mut state = bucket.state.lock();
        state.available_tokens = 100;
        state.last_refill = start;
        state.refill_remainder = 0;

        bucket.refill(&mut state, start + Duration::from_micros(1_234));

        assert_eq!(state.available_tokens, 112);
        assert_eq!(state.refill_remainder, 340_000_000);
    }
}
