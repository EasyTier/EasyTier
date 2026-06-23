use std::{
    cmp::Ordering,
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

const VALIDATE_TOKEN_INITIAL_CONCURRENCY: usize = 8;
const VALIDATE_TOKEN_MIN_CONCURRENCY: usize = 2;
const VALIDATE_TOKEN_MAX_CONCURRENCY: usize = 64;
const VALIDATE_TOKEN_ADJUST_WINDOW: Duration = Duration::from_secs(1);
const VALIDATE_TOKEN_SLOW_THRESHOLD: Duration = Duration::from_secs(2);
const WEBHOOK_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

struct AdaptiveValidateLimiter {
    state: Mutex<AdaptiveValidateLimiterState>,
}

impl fmt::Debug for AdaptiveValidateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdaptiveValidateLimiter")
            .field("state", &self.lock_state())
            .finish_non_exhaustive()
    }
}

struct AdaptiveValidateLimiterState {
    limit: usize,
    in_flight: usize,
    waiters: VecDeque<oneshot::Sender<AdaptiveValidateGrant>>,
    window_started_at: Instant,
    samples: usize,
    slow_samples: usize,
    failures: usize,
    had_queue: bool,
}

impl fmt::Debug for AdaptiveValidateLimiterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdaptiveValidateLimiterState")
            .field("limit", &self.limit)
            .field("in_flight", &self.in_flight)
            .field("waiters", &self.waiters.len())
            .field("window_started_at", &self.window_started_at)
            .field("samples", &self.samples)
            .field("slow_samples", &self.slow_samples)
            .field("failures", &self.failures)
            .field("had_queue", &self.had_queue)
            .finish()
    }
}

struct AdaptiveValidatePermit {
    limiter: Arc<AdaptiveValidateLimiter>,
    started_at: Instant,
    completed: bool,
}

struct AdaptiveValidateGrant {
    limiter: Arc<AdaptiveValidateLimiter>,
    active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitAdjustment {
    Unchanged,
    Increased,
    Decreased,
}

impl AdaptiveValidateLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(AdaptiveValidateLimiterState::new(Instant::now())),
        })
    }

    async fn acquire(self: &Arc<Self>) -> AdaptiveValidatePermit {
        loop {
            let receiver = {
                let mut state = self.lock_state();
                state.complete_window_if_due(Instant::now());
                if state.waiters.is_empty() && state.in_flight < state.limit {
                    state.in_flight += 1;
                    return AdaptiveValidatePermit::new(self.clone());
                }

                let (sender, receiver) = oneshot::channel();
                state.had_queue = true;
                state.waiters.push_back(sender);
                self.grant_waiters(&mut state);
                receiver
            };

            if let Ok(grant) = receiver.await {
                return grant.into_permit();
            }
        }
    }

    fn grant_waiters(self: &Arc<Self>, state: &mut AdaptiveValidateLimiterState) {
        while state.in_flight < state.limit {
            let Some(waiter) = state.waiters.pop_front() else {
                break;
            };
            state.in_flight += 1;
            if let Err(mut grant) = waiter.send(AdaptiveValidateGrant::new(self.clone())) {
                grant.disarm();
                state.in_flight -= 1;
            }
        }
    }

    fn record_sample(self: &Arc<Self>, elapsed: Duration, success: bool) {
        let mut state = self.lock_state();
        let adjustment = state.record_sample(Instant::now(), elapsed, success);
        if adjustment == LimitAdjustment::Increased {
            self.grant_waiters(&mut state);
        }
    }

    fn release_slot(self: &Arc<Self>) {
        let mut state = self.lock_state();
        state.in_flight = state.in_flight.saturating_sub(1);
        self.grant_waiters(&mut state);
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, AdaptiveValidateLimiterState> {
        self.state
            .lock()
            .expect("adaptive validate limiter state should not be poisoned")
    }
}

impl AdaptiveValidateLimiterState {
    fn new(now: Instant) -> Self {
        Self {
            limit: VALIDATE_TOKEN_INITIAL_CONCURRENCY,
            in_flight: 0,
            waiters: VecDeque::new(),
            window_started_at: now,
            samples: 0,
            slow_samples: 0,
            failures: 0,
            had_queue: false,
        }
    }

    fn record_sample(&mut self, now: Instant, elapsed: Duration, success: bool) -> LimitAdjustment {
        self.samples += 1;
        if elapsed > VALIDATE_TOKEN_SLOW_THRESHOLD {
            self.slow_samples += 1;
        }
        if !success {
            self.failures += 1;
        }
        self.complete_window_if_due(now)
    }

    fn complete_window_if_due(&mut self, now: Instant) -> LimitAdjustment {
        if now.duration_since(self.window_started_at) < VALIDATE_TOKEN_ADJUST_WINDOW {
            return LimitAdjustment::Unchanged;
        }

        let old_limit = self.limit;
        if self.samples > 0 {
            if self.failures > 0 || self.is_p95_slow() {
                self.limit = (self.limit / 2).max(VALIDATE_TOKEN_MIN_CONCURRENCY);
            } else if self.had_queue {
                self.limit = (self.limit + 1).min(VALIDATE_TOKEN_MAX_CONCURRENCY);
            }
        }

        self.window_started_at = now;
        self.samples = 0;
        self.slow_samples = 0;
        self.failures = 0;
        self.had_queue = false;

        match self.limit.cmp(&old_limit) {
            Ordering::Greater => LimitAdjustment::Increased,
            Ordering::Less => LimitAdjustment::Decreased,
            Ordering::Equal => LimitAdjustment::Unchanged,
        }
    }

    fn is_p95_slow(&self) -> bool {
        self.slow_samples > 0 && self.slow_samples * 20 >= self.samples
    }
}

impl AdaptiveValidatePermit {
    fn new(limiter: Arc<AdaptiveValidateLimiter>) -> Self {
        Self {
            limiter,
            started_at: Instant::now(),
            completed: false,
        }
    }

    fn complete(mut self, success: bool) {
        self.limiter
            .record_sample(self.started_at.elapsed(), success);
        self.completed = true;
    }
}

impl AdaptiveValidateGrant {
    fn new(limiter: Arc<AdaptiveValidateLimiter>) -> Self {
        Self {
            limiter,
            active: true,
        }
    }

    fn into_permit(mut self) -> AdaptiveValidatePermit {
        self.active = false;
        AdaptiveValidatePermit::new(self.limiter.clone())
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for AdaptiveValidateGrant {
    fn drop(&mut self) {
        if self.active {
            self.limiter.release_slot();
        }
    }
}

impl Drop for AdaptiveValidatePermit {
    fn drop(&mut self) {
        if !self.completed {
            self.limiter.record_sample(self.started_at.elapsed(), false);
        }
        self.limiter.release_slot();
    }
}

/// Webhook configuration for external integrations.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub internal_auth_token: Option<String>,
    pub web_instance_id: Option<String>,
    pub web_instance_api_base_url: Option<String>,

    validate_limiter: Arc<AdaptiveValidateLimiter>,
    client: reqwest::Client,
}

impl WebhookConfig {
    pub fn new(
        webhook_url: Option<String>,
        webhook_secret: Option<String>,
        internal_auth_token: Option<String>,
        web_instance_id: Option<String>,
        web_instance_api_base_url: Option<String>,
    ) -> Self {
        WebhookConfig {
            webhook_url,
            webhook_secret,
            internal_auth_token,
            web_instance_id,
            web_instance_api_base_url,
            validate_limiter: AdaptiveValidateLimiter::new(),
            client: reqwest::Client::builder()
                .timeout(WEBHOOK_HTTP_TIMEOUT)
                .build()
                .expect("webhook HTTP client should be valid"),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.webhook_url
            .as_deref()
            .is_some_and(|url| !url.trim().is_empty())
    }

    pub fn has_internal_auth(&self) -> bool {
        self.internal_auth_token.is_some()
    }
}

// --- Request/Response types ---

#[derive(Debug, Serialize)]
pub struct ValidateTokenRequest {
    pub token: String,
    pub machine_id: String,
    pub public_ip: Option<String>,
    pub hostname: String,
    pub version: String,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub os_distribution: Option<String>,
    pub web_instance_id: Option<String>,
    pub web_instance_api_base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted_config_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_config_revision: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ValidateTokenResponse {
    pub valid: bool,
    #[serde(default)]
    pub pre_approved: bool,
    #[serde(default)]
    pub binding_version: u64,
    #[serde(default)]
    pub config_revision: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedNetworkConfig {
    pub instance_id: String,
    pub network_config: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct NodeConnectedRequest {
    pub machine_id: String,
    pub token: String,
    pub user_id: Option<i32>,
    pub hostname: String,
    pub version: String,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub os_distribution: Option<String>,
    pub web_instance_id: Option<String>,
    pub binding_version: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct NodeDisconnectedRequest {
    pub machine_id: String,
    pub token: String,
    pub user_id: Option<i32>,
    pub web_instance_id: Option<String>,
    pub binding_version: Option<u64>,
}

// --- Webhook client ---

impl WebhookConfig {
    fn webhook_base_url(&self) -> anyhow::Result<&str> {
        self.webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| anyhow::anyhow!("webhook_url is not configured"))
    }

    fn webhook_endpoint(&self, path: &str) -> anyhow::Result<String> {
        Ok(format!(
            "{}/{}",
            self.webhook_base_url()?.trim_end_matches('/'),
            path.trim_start_matches('/'),
        ))
    }

    /// Validate a token through the configured webhook endpoint.
    pub async fn validate_token(
        &self,
        req: &ValidateTokenRequest,
    ) -> anyhow::Result<ValidateTokenResponse> {
        self.validate_token_with_http_timeout(req, WEBHOOK_HTTP_TIMEOUT)
            .await
    }

    async fn validate_token_with_http_timeout(
        &self,
        req: &ValidateTokenRequest,
        http_timeout: Duration,
    ) -> anyhow::Result<ValidateTokenResponse> {
        let url = self.webhook_endpoint("validate-token")?;
        let permit = self.validate_limiter.acquire().await;
        let ret = match tokio::time::timeout(http_timeout, async {
            let resp = self
                .client
                .post(&url)
                .header("X-Internal-Auth", self.webhook_auth_secret())
                .json(req)
                .send()
                .await?;

            if !resp.status().is_success() {
                anyhow::bail!("webhook validate-token returned status {}", resp.status());
            }

            Ok(resp.json().await?)
        })
        .await
        {
            Ok(ret) => ret,
            Err(_) => Err(anyhow::anyhow!("webhook validate-token timed out")),
        };
        permit.complete(ret.is_ok());
        ret
    }

    /// Notify the webhook receiver that a node has connected.
    pub async fn notify_node_connected(&self, req: &NodeConnectedRequest) {
        if !self.is_enabled() {
            return;
        }
        let Ok(url) = self.webhook_endpoint("webhook/node-connected") else {
            tracing::warn!("skip node-connected webhook because webhook_url is not configured");
            return;
        };
        let _ = self
            .client
            .post(&url)
            .header("X-Internal-Auth", self.webhook_auth_secret())
            .json(req)
            .send()
            .await;
    }

    /// Notify the webhook receiver that a node has disconnected.
    pub async fn notify_node_disconnected(&self, req: &NodeDisconnectedRequest) {
        if !self.is_enabled() {
            return;
        }
        let Ok(url) = self.webhook_endpoint("webhook/node-disconnected") else {
            tracing::warn!("skip node-disconnected webhook because webhook_url is not configured");
            return;
        };
        let _ = self
            .client
            .post(&url)
            .header("X-Internal-Auth", self.webhook_auth_secret())
            .json(req)
            .send()
            .await;
    }

    fn webhook_auth_secret(&self) -> &str {
        self.webhook_secret
            .as_deref()
            .or(self.internal_auth_token.as_deref())
            .unwrap_or("")
    }
}

pub type SharedWebhookConfig = Arc<WebhookConfig>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};
    use serde_json::json;

    #[test]
    fn adaptive_validate_limiter_increases_under_queue_pressure() {
        let now = Instant::now();
        let mut state = AdaptiveValidateLimiterState::new(now);
        state.had_queue = true;

        for _ in 0..VALIDATE_TOKEN_INITIAL_CONCURRENCY {
            state.record_sample(now, Duration::from_millis(50), true);
        }

        assert_eq!(
            state.complete_window_if_due(now + VALIDATE_TOKEN_ADJUST_WINDOW),
            LimitAdjustment::Increased
        );
        assert_eq!(state.limit, VALIDATE_TOKEN_INITIAL_CONCURRENCY + 1);
    }

    #[test]
    fn adaptive_validate_limiter_does_not_increase_without_queue_pressure() {
        let now = Instant::now();
        let mut state = AdaptiveValidateLimiterState::new(now);

        for _ in 0..VALIDATE_TOKEN_INITIAL_CONCURRENCY {
            state.record_sample(now, Duration::from_millis(50), true);
        }

        assert_eq!(
            state.complete_window_if_due(now + VALIDATE_TOKEN_ADJUST_WINDOW),
            LimitAdjustment::Unchanged
        );
        assert_eq!(state.limit, VALIDATE_TOKEN_INITIAL_CONCURRENCY);
    }

    #[test]
    fn adaptive_validate_limiter_reduces_on_failure() {
        let now = Instant::now();
        let mut state = AdaptiveValidateLimiterState::new(now);

        state.record_sample(now, Duration::from_millis(50), false);

        assert_eq!(
            state.complete_window_if_due(now + VALIDATE_TOKEN_ADJUST_WINDOW),
            LimitAdjustment::Decreased
        );
        assert_eq!(
            state.limit,
            (VALIDATE_TOKEN_INITIAL_CONCURRENCY / 2).max(VALIDATE_TOKEN_MIN_CONCURRENCY)
        );
    }

    #[test]
    fn adaptive_validate_limiter_reduces_on_slow_latency() {
        let now = Instant::now();
        let mut state = AdaptiveValidateLimiterState::new(now);

        state.record_sample(
            now,
            VALIDATE_TOKEN_SLOW_THRESHOLD + Duration::from_millis(1),
            true,
        );

        assert_eq!(
            state.complete_window_if_due(now + VALIDATE_TOKEN_ADJUST_WINDOW),
            LimitAdjustment::Decreased
        );
        assert_eq!(
            state.limit,
            (VALIDATE_TOKEN_INITIAL_CONCURRENCY / 2).max(VALIDATE_TOKEN_MIN_CONCURRENCY)
        );
    }

    #[tokio::test]
    async fn adaptive_validate_limiter_waiter_acquires_after_release() {
        let limiter = AdaptiveValidateLimiter::new();
        let mut permits = Vec::new();
        for _ in 0..VALIDATE_TOKEN_INITIAL_CONCURRENCY {
            permits.push(limiter.acquire().await);
        }

        let waiter_limiter = limiter.clone();
        let waiter = tokio::spawn(async move {
            let permit = waiter_limiter.acquire().await;
            permit.complete(true);
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiter.is_finished());

        permits.pop().unwrap().complete(true);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();

        for permit in permits {
            permit.complete(true);
        }
    }

    #[tokio::test]
    async fn adaptive_validate_limiter_releases_when_permit_is_dropped() {
        let limiter = AdaptiveValidateLimiter::new();
        let mut permits = Vec::new();
        for _ in 0..VALIDATE_TOKEN_INITIAL_CONCURRENCY {
            permits.push(limiter.acquire().await);
        }

        let waiter_limiter = limiter.clone();
        let waiter = tokio::spawn(async move {
            let permit = waiter_limiter.acquire().await;
            permit.complete(true);
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiter.is_finished());

        drop(permits.pop().unwrap());
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();

        for permit in permits {
            permit.complete(true);
        }
    }

    #[tokio::test]
    async fn adaptive_validate_limiter_skips_canceled_waiters() {
        let limiter = AdaptiveValidateLimiter::new();
        let mut permits = Vec::new();
        for _ in 0..VALIDATE_TOKEN_INITIAL_CONCURRENCY {
            permits.push(limiter.acquire().await);
        }

        let waiter_limiter = limiter.clone();
        let waiter = tokio::spawn(async move {
            let permit = waiter_limiter.acquire().await;
            permit.complete(true);
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiter.is_finished());
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());

        permits.pop().unwrap().complete(true);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let state = limiter.lock_state();
        assert_eq!(state.samples, 1);
        assert_eq!(state.failures, 0);
        drop(state);

        for permit in permits {
            permit.complete(true);
        }
    }

    #[test]
    fn adaptive_validate_limiter_releases_dropped_grant_without_failure_sample() {
        let limiter = AdaptiveValidateLimiter::new();
        {
            let mut state = limiter.lock_state();
            state.in_flight = 1;
        }

        drop(AdaptiveValidateGrant::new(limiter.clone()));

        let state = limiter.lock_state();
        assert_eq!(state.in_flight, 0);
        assert_eq!(state.samples, 0);
        assert_eq!(state.failures, 0);
    }

    #[tokio::test]
    async fn adaptive_validate_limiter_wakes_multiple_waiters_in_order() {
        let limiter = AdaptiveValidateLimiter::new();
        let mut permits = Vec::new();
        for _ in 0..VALIDATE_TOKEN_INITIAL_CONCURRENCY {
            permits.push(limiter.acquire().await);
        }

        let (first_acquired_tx, first_acquired_rx) = oneshot::channel();
        let (first_release_tx, first_release_rx) = oneshot::channel();
        let first = {
            let limiter = limiter.clone();
            tokio::spawn(async move {
                let permit = limiter.acquire().await;
                first_acquired_tx.send(()).unwrap();
                first_release_rx.await.unwrap();
                permit.complete(true);
            })
        };
        let (second_acquired_tx, mut second_acquired_rx) = oneshot::channel();
        let second = {
            let limiter = limiter.clone();
            tokio::spawn(async move {
                let permit = limiter.acquire().await;
                second_acquired_tx.send(()).unwrap();
                permit.complete(true);
            })
        };

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!first.is_finished());
        assert!(!second.is_finished());

        permits.pop().unwrap().complete(true);
        tokio::time::timeout(Duration::from_secs(1), first_acquired_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut second_acquired_rx)
                .await
                .is_err()
        );

        first_release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), &mut second_acquired_rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap();

        for permit in permits {
            permit.complete(true);
        }
    }

    #[tokio::test]
    async fn validate_token_http_timeout_starts_after_limiter_permit() {
        let app = Router::new().route(
            "/validate-token",
            post(|| async {
                Json(json!({
                    "valid": true,
                    "config_revision": "rev-1"
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let webhook = WebhookConfig::new(Some(format!("http://{addr}")), None, None, None, None);
        let mut permits = Vec::new();
        for _ in 0..VALIDATE_TOKEN_INITIAL_CONCURRENCY {
            permits.push(webhook.validate_limiter.acquire().await);
        }

        let validate_webhook = webhook.clone();
        let validate = tokio::spawn(async move {
            let req = ValidateTokenRequest {
                token: "token".to_string(),
                machine_id: uuid::Uuid::new_v4().to_string(),
                public_ip: None,
                hostname: String::new(),
                version: String::new(),
                os_type: None,
                os_version: None,
                os_distribution: None,
                web_instance_id: None,
                web_instance_api_base_url: None,
                persisted_config_revision: None,
                applied_config_revision: None,
            };
            validate_webhook
                .validate_token_with_http_timeout(&req, Duration::from_millis(20))
                .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!validate.is_finished());

        permits.pop().unwrap().complete(true);
        let resp = tokio::time::timeout(Duration::from_secs(1), validate)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(resp.valid);

        for permit in permits {
            permit.complete(true);
        }
        server.abort();
    }

    #[test]
    fn validate_token_response_deserializes_config_revision() {
        let resp: ValidateTokenResponse =
            serde_json::from_str(r#"{"valid":true,"config_revision":"rev-1"}"#).unwrap();
        assert!(resp.valid);
        assert_eq!(resp.config_revision, "rev-1");
    }

    #[test]
    fn validate_token_response_allows_missing_config_revision() {
        let resp: ValidateTokenResponse = serde_json::from_str(r#"{"valid":true}"#).unwrap();
        assert!(resp.valid);
        assert!(resp.config_revision.is_empty());
    }
}
