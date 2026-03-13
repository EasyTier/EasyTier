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
        self.webhook_url.is_some()
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
    pub hostname: String,
    pub version: String,
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
    pub network_config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct NodeConnectedRequest {
    pub machine_id: String,
    pub token: String,
    pub hostname: String,
    pub version: String,
    pub web_instance_id: Option<String>,
    pub binding_version: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct NodeDisconnectedRequest {
    pub machine_id: String,
    pub web_instance_id: Option<String>,
    pub binding_version: Option<u64>,
}

// --- Webhook client ---

impl WebhookConfig {
    /// Validate a token through the configured webhook endpoint.
    pub async fn validate_token(
        &self,
        req: &ValidateTokenRequest,
    ) -> anyhow::Result<ValidateTokenResponse> {
        let url = format!(
            "{}/validate-token",
            self.webhook_url.as_ref().unwrap().trim_end_matches('/')
        );
        let resp = self
            .client
            .post(&url)
            .header("X-Internal-Auth", self.internal_auth_secret())
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
        let url = format!(
            "{}/webhook/node-connected",
            self.webhook_url.as_ref().unwrap().trim_end_matches('/')
        );
        let _ = self
            .client
            .post(&url)
            .header("X-Internal-Auth", self.internal_auth_secret())
            .json(req)
            .send()
            .await;
    }

    /// Notify the webhook receiver that a node has disconnected.
    pub async fn notify_node_disconnected(&self, req: &NodeDisconnectedRequest) {
        if !self.is_enabled() {
            return;
        }
        let url = format!(
            "{}/webhook/node-disconnected",
            self.webhook_url.as_ref().unwrap().trim_end_matches('/')
        );
        let _ = self
            .client
            .post(&url)
            .header("X-Internal-Auth", self.internal_auth_secret())
            .json(req)
            .send()
            .await;
    }

    fn internal_auth_secret(&self) -> &str {
        // Prefer internal_auth_token for token-authenticated management requests,
        // falling back to webhook_secret for backward compatibility.
        self.internal_auth_token
            .as_deref()
            .or(self.webhook_secret.as_deref())
            .unwrap_or("")
    }
}

pub type SharedWebhookConfig = Arc<WebhookConfig>;
