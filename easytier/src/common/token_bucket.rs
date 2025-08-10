use atomic_shim::AtomicU64;
use dashmap::DashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;

use crate::common::scoped_task::ScopedTask;
use crate::proto::common::LimiterConfig;

/// Token Bucket rate limiter using atomic operations
pub struct TokenBucket {
    available_tokens: AtomicU64, // Current token count (atomic)
    last_refill_time: AtomicU64, // Last refill time as micros since epoch
    config: BucketConfig,        // Immutable configuration
    refill_task: Mutex<Option<ScopedTask<()>>>, // Background refill task
    start_time: Instant,         // Bucket creation time
}

#[derive(Clone, Copy)]
pub struct BucketConfig {
    capacity: u64,             // Maximum token capacity
    fill_rate: u64,            // Tokens added per second
    refill_interval: Duration, // Time between refill operations
}

impl From<LimiterConfig> for BucketConfig {
    fn from(cfg: LimiterConfig) -> Self {
        let burst_rate = 1.max(cfg.burst_rate.unwrap_or(1));
        let fill_rate = 8196.max(cfg.bps.unwrap_or(u64::MAX / burst_rate));
        let refill_interval = cfg
            .fill_duration_ms
            .map(|x| Duration::from_millis(1.max(x)))
            .unwrap_or(Duration::from_millis(10));
        BucketConfig {
            capacity: burst_rate * fill_rate,
            fill_rate,
            refill_interval,
        }
    }
}

impl TokenBucket {
    pub fn new(capacity: u64, bps: u64, refill_interval: Duration) -> Arc<Self> {
        let config = BucketConfig {
            capacity,
            fill_rate: bps,
            refill_interval,
        };
        Self::new_from_cfg(config)
    }

    /// Creates a new Token Bucket rate limiter
    ///
    /// # Arguments
    /// * `capacity` - Bucket capacity in bytes
    /// * `bps` - Bandwidth limit in bytes per second
    /// * `refill_interval` - Refill interval (recommended 10-50ms)
    pub fn new_from_cfg(config: BucketConfig) -> Arc<Self> {
        // Create Arc instance with placeholder task
        let arc_self = Arc::new(Self {
            available_tokens: AtomicU64::new(config.capacity),
            last_refill_time: AtomicU64::new(0),
            config,
            refill_task: Mutex::new(None),
            start_time: std::time::Instant::now(),
        });

        // Start background refill task
        let weak_bucket = Arc::downgrade(&arc_self);
        let refill_interval = arc_self.config.refill_interval;
        let refill_task = tokio::spawn(async move {
            let mut interval = time::interval(refill_interval);
            loop {
                interval.tick().await;
                let Some(bucket) = weak_bucket.upgrade() else {
                    break;
                };
                bucket.refill();
            }
        });

        // Replace placeholder task with actual one
        arc_self
            .refill_task
            .lock()
            .unwrap()
            .replace(refill_task.into());
        arc_self
    }

    /// Internal refill method (called only by background task)
    fn refill(&self) {
        let now_micros = self.elapsed_micros();
        let prev_time = self.last_refill_time.swap(now_micros, Ordering::Acquire);

        // Calculate elapsed time in seconds
        let elapsed_secs = (now_micros.saturating_sub(prev_time)) as f64 / 1_000_000.0;

        // Calculate tokens to add
        let tokens_to_add = (self.config.fill_rate as f64 * elapsed_secs) as u64;
        if tokens_to_add == 0 {
            return;
        }

        // Add tokens without exceeding capacity
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
    }

    /// Calculate microseconds since bucket creation
    fn elapsed_micros(&self) -> u64 {
        self.start_time.elapsed().as_micros() as u64
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
}

pub struct TokenBucketManager {
    buckets: Arc<DashMap<String, Arc<TokenBucket>>>,

    retain_task: ScopedTask<()>,
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
                buckets_clone.retain(|_, bucket| Arc::<TokenBucket>::strong_count(bucket) > 1);
                // Sleep for a while before next retention check
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        Self {
            buckets,
            retain_task: retain_task.into(),
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
    use tokio::time::{sleep, Duration};

    /// Test initial state after creation
    #[tokio::test]
    async fn test_initial_state() {
        let bucket = TokenBucket::new(1000, 1000, Duration::from_millis(10));

        // Should have full capacity initially
        assert!(bucket.try_consume(1000));
        assert!(!bucket.try_consume(1)); // Should be empty now
    }

    /// Test token consumption behavior
    #[tokio::test]
    async fn test_consumption() {
        let bucket = TokenBucket::new(1500, 1000, Duration::from_millis(10));

        // First packet should succeed
        assert!(bucket.try_consume(1000));

        // Second packet should fail (only 500 left)
        assert!(!bucket.try_consume(600));

        // Should be able to take remaining tokens
        assert!(bucket.try_consume(500));
    }

    /// Test background refill functionality
    #[tokio::test]
    async fn test_refill() {
        let bucket = TokenBucket::new(1000, 1000, Duration::from_millis(10));

        // Drain the bucket
        assert!(bucket.try_consume(1000));
        assert!(!bucket.try_consume(1));

        // Wait for refill (1 refill interval + buffer)
        sleep(Duration::from_millis(25)).await;

        // Should have approximately 20 tokens (1000 tokens/s * 0.02s)
        assert!(bucket.try_consume(15));
        assert!(!bucket.try_consume(10)); // But not full capacity
    }

    /// Test capacity enforcement
    #[tokio::test]
    async fn test_capacity_limit() {
        let bucket = TokenBucket::new(500, 1000, Duration::from_millis(10));

        // Wait longer than refill interval
        sleep(Duration::from_millis(50)).await;

        // Should not exceed capacity despite time passed
        assert!(bucket.try_consume(500));
        assert!(!bucket.try_consume(1));
    }

    /// Test high load with concurrent access
    #[tokio::test]
    async fn test_concurrent_access() {
        let bucket = TokenBucket::new(10_000, 1_000_000, Duration::from_millis(10));
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
        let bucket = TokenBucket::new(1500, 1000, Duration::from_millis(10));

        // Packet larger than capacity should be rejected
        assert!(!bucket.try_consume(1600));

        // Regular packets should still work
        assert!(bucket.try_consume(1000));
    }

    /// Test refill precision with small intervals
    #[tokio::test]
    async fn test_refill_precision() {
        let bucket = TokenBucket::new(10_000, 10_000, Duration::from_micros(100)); // 100μs interval

        // Drain most tokens
        assert!(bucket.try_consume(9900));

        // Wait for multiple refills
        sleep(Duration::from_millis(1)).await;

        // Should have accumulated about 100 tokens (10,000 tokens/s * 0.001s)
        let tokens = bucket.available_tokens.load(Ordering::Relaxed);
        assert!(
            (100..=200).contains(&tokens),
            "Unexpected token count: {}",
            tokens
        );
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
