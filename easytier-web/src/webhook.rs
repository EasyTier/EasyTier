use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Webhook configuration for external integrations.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub internal_auth_token: Option<String>,
    pub web_instance_id: Option<String>,
    pub web_instance_api_base_url: Option<String>,

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
            client: reqwest::Client::new(),
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
}

#[derive(Debug, Deserialize)]
pub struct ValidateTokenResponse {
    pub valid: bool,
    #[serde(default)]
    pub pre_approved: bool,
    #[serde(default)]
    pub binding_version: u64,
    pub managed_network_configs: Vec<ManagedNetworkConfig>,
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
        let url = self.webhook_endpoint("validate-token")?;
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
