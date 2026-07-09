use atomic_shim::AtomicU64;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio_util::task::AbortOnDropHandle;

use crate::proto::common::LimiterConfig;

/// Token Bucket rate limiter using atomic operations
pub struct TokenBucket {
    available_tokens: AtomicU64, // Current token count (atomic)
    last_refill_time: AtomicU64, // Last refill time as micros since epoch
    config: BucketConfig,        // Immutable configuration
    start_time: Instant,         // Bucket creation time
}

#[derive(Clone, Copy)]
pub struct BucketConfig {
    capacity: u64,
    fill_rate: u64,
}

impl From<LimiterConfig> for BucketConfig {
    fn from(cfg: LimiterConfig) -> Self {
        let burst_rate = 1.max(cfg.burst_rate.unwrap_or(1));
        let fill_rate = 8196.max(cfg.bps.unwrap_or(u64::MAX / burst_rate));
        BucketConfig {
            capacity: burst_rate * fill_rate,
            fill_rate,
        }
    }
}

impl TokenBucket {
    pub fn new(capacity: u64, bps: u64) -> Arc<Self> {
        Self::new_from_cfg(BucketConfig {
            capacity,
            fill_rate: bps,
        })
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
            available_tokens: AtomicU64::new(config.capacity),
            last_refill_time: AtomicU64::new(0),
            config,
            start_time: Instant::now(),
        })
    }

    fn elapsed_micros(&self) -> u64 {
        self.start_time.elapsed().as_micros() as u64
    }

    /// Refill tokens based on elapsed time since last refill.
    /// Called on-demand — no background task needed.
    fn refill_on_demand(&self) {
        loop {
            let prev_time = self.last_refill_time.load(Ordering::Acquire);
            let now_micros = self.elapsed_micros();

            let elapsed_micros = now_micros.saturating_sub(prev_time);
            let tokens_to_add = self.config.fill_rate as u128 * elapsed_micros as u128 / 1_000_000;

            if tokens_to_add == 0 {
                return;
            }
            let tokens_to_add = tokens_to_add.min(self.config.capacity as u128) as u64;

            // Try to claim this time window
            if self
                .last_refill_time
                .compare_exchange_weak(prev_time, now_micros, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                // Another thread already advanced the time; retry
                continue;
            }

            // We won the CAS — add tokens without exceeding capacity
            let mut current = self.available_tokens.load(Ordering::Relaxed);
            loop {
                let new = current
                    .saturating_add(tokens_to_add)
                    .min(self.config.capacity);
                match self.available_tokens.compare_exchange_weak(
                    current,
                    new,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
            return;
        }
    }

    /// Attempt to consume tokens without blocking
    ///
    /// # Returns
    /// `true` if tokens were consumed, `false` if insufficient tokens
    pub fn try_consume(&self, tokens: u64) -> bool {
        // Fast path for oversized packets
        if tokens > self.config.capacity {
            return false;
        }

        self.refill_on_demand();

        let mut current = self.available_tokens.load(Ordering::Relaxed);
        loop {
            if current < tokens {
                return false;
            }

            let new = current - tokens;
            match self.available_tokens.compare_exchange_weak(
                current,
                new,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Consume tokens, sleeping until they become available.
    pub async fn consume(&self, tokens: u64) {
        let mut remaining = tokens;
        while remaining > 0 {
            let chunk = remaining.min(self.config.capacity);
            self.consume_chunk(chunk).await;
            remaining -= chunk;
        }
    }

    async fn consume_chunk(&self, tokens: u64) {
        loop {
            self.refill_on_demand();

            let mut current = self.available_tokens.load(Ordering::Relaxed);
            loop {
                if current < tokens {
                    break;
                }
                match self.available_tokens.compare_exchange_weak(
                    current,
                    current - tokens,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    Err(actual) => current = actual,
                }
            }

            // Sleep for the deficit, with a 1ms floor to avoid busy polling.
            let deficit = tokens - current;
            let sleep_micros = deficit as u128 * 1_000_000 / self.config.fill_rate as u128;
            let sleep_micros = sleep_micros.min(u64::MAX as u128) as u64;
            let sleep_dur = Duration::from_micros(sleep_micros.max(1_000));
            tokio::time::sleep(sleep_dur).await;
        }
    }
}

pub struct TokenBucketManager {
    buckets: Arc<DashMap<String, Arc<TokenBucket>>>,

    retain_task: AbortOnDropHandle<()>,
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
                tokio::time::sleep(Duration::from_secs(5)).await;
                tracing::info!(
                    "Retained buckets: {} ({} dropped)",
                    buckets_clone.len(),
                    old_len.saturating_sub(buckets_clone.len())
                );
            }
        });

        Self {
            buckets,
            retain_task: AbortOnDropHandle::new(retain_task),
        }
    }

    /// Get or create a token bucket for the given key
    pub fn get_or_create(&self, key: &str, cfg: BucketConfig) -> Arc<TokenBucket> {
        self.buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new_from_cfg(cfg))
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        connector::udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        peers::{
            foreign_network_manager::tests::create_mock_peer_manager_for_foreign_network,
            tests::connect_peer_manager,
        },
        proto::common::NatType,
        tunnel::common::tests::wait_for_condition,
    };

    use super::*;
    use tokio::time::{Duration, sleep, timeout};

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

    /// Test lazy refill functionality
    #[tokio::test]
    async fn test_refill() {
        let bucket = TokenBucket::new(1_000_000, 10_000);

        // Drain the bucket
        assert!(bucket.try_consume(1_000_000));

        // Wait for time to pass (tokens accumulate lazily on next consume)
        sleep(Duration::from_millis(25)).await;
        bucket.refill_on_demand();

        let tokens = bucket.available_tokens.load(Ordering::Relaxed);
        assert!(tokens > 0, "Expected some refilled tokens");
        assert!(
            tokens < bucket.config.capacity,
            "Bucket unexpectedly refilled to capacity: {}",
            tokens
        );
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
    #[tokio::test]
    async fn test_concurrent_access() {
        let bucket = TokenBucket::new(10_000, 1_000_000);
        let mut handles = vec![];

        // Spawn 100 tasks to consume tokens concurrently
        for _ in 0..100 {
            let bucket = bucket.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = bucket.try_consume(10);
                }
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify we didn't exceed capacity
        let tokens_left = bucket.available_tokens.load(Ordering::Relaxed);
        assert!(
            tokens_left <= 10_000,
            "Tokens exceeded capacity: {}",
            tokens_left
        );
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

    /// Test refill precision after elapsed time
    #[tokio::test]
    async fn test_refill_precision() {
        let bucket = TokenBucket::new(10_000, 10_000);

        // Drain most tokens
        assert!(bucket.try_consume(9900));
        let tokens_before = bucket.available_tokens.load(Ordering::Relaxed);
        let refill_time_before = bucket.last_refill_time.load(Ordering::Acquire);

        // Wait for tokens to accumulate
        sleep(Duration::from_millis(1)).await;
        bucket.refill_on_demand();

        let refill_time_after = bucket.last_refill_time.load(Ordering::Acquire);
        let elapsed_micros = refill_time_after.saturating_sub(refill_time_before);
        let expected_refill = (10_000u128 * elapsed_micros as u128 / 1_000_000).min(9_900) as u64;
        let expected_tokens = tokens_before + expected_refill;
        let tokens_after = bucket.available_tokens.load(Ordering::Relaxed);

        assert_eq!(tokens_after, expected_tokens);
    }

    #[tokio::test]
    async fn test_token_bucket_free() {
        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        for i in 0..10 {
            let pma_net1 = create_mock_peer_manager_for_foreign_network(&format!("net{}", i)).await;

            connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
            wait_for_condition(
                || async { pma_net1.list_routes().await.len() == 1 },
                Duration::from_secs(5),
            )
            .await;
            println!("net{}", i);
            println!(
                "buckets: {}",
                pm_center1
                    .get_global_ctx()
                    .token_bucket_manager()
                    .buckets
                    .len()
            );

            drop(pma_net1);
            wait_for_condition(
                || async {
                    pm_center1
                        .get_foreign_network_manager()
                        .list_foreign_networks()
                        .await
                        .foreign_networks
                        .is_empty()
                },
                Duration::from_secs(5),
            )
            .await;
        }

        // wait token bucket empty
        wait_for_condition(
            || async {
                pm_center1
                    .get_global_ctx()
                    .token_bucket_manager()
                    .buckets
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }
}
