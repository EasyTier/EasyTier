use std::{
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{
    common::global_ctx::ArcGlobalCtx,
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelError},
};

use super::{
    create_direct_connector,
    resolver::{ConnectorResolver, ResolvedCandidate},
};

pub struct ManagedConnector {
    source_url: url::Url,
    resolver: Box<dyn ConnectorResolver>,
    candidates: Arc<RwLock<Vec<ResolvedCandidate>>>,
    last_refresh: RwLock<Instant>,
    ip_version: IpVersion,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
}

impl std::fmt::Debug for ManagedConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedConnector")
            .field("source_url", &self.source_url)
            .field("resolver", &self.resolver)
            .field("ip_version", &self.ip_version)
            .finish()
    }
}

impl ManagedConnector {
    pub fn new(
        source_url: url::Url,
        resolver: Box<dyn ConnectorResolver>,
        ip_version: IpVersion,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        Self {
            source_url,
            resolver,
            candidates: Arc::new(RwLock::new(Vec::new())),
            last_refresh: RwLock::new(Instant::now()),
            ip_version,
            bind_addrs: Vec::new(),
            global_ctx,
        }
    }

    async fn maybe_refresh(&self) {
        let refresh_secs = self.resolver.refresh_interval_secs();
        if refresh_secs >= u64::MAX {
            if !self.candidates.read().await.is_empty() {
                return;
            }
        }

        let elapsed = self.last_refresh.read().await.elapsed();
        if elapsed.as_secs() < refresh_secs && !self.candidates.read().await.is_empty() {
            return;
        }

        match self.resolver.resolve().await {
            Ok(new_candidates) => {
                if new_candidates.is_empty() {
                    tracing::warn!(
                        "Resolver returned empty candidate list for {}, keeping old candidates",
                        self.source_url
                    );
                    return;
                }
                let mut candidates = self.candidates.write().await;
                *candidates = new_candidates;
                *self.last_refresh.write().await = Instant::now();
                tracing::debug!(
                    "Refreshed candidates for {}: {} candidates",
                    self.source_url,
                    candidates.len()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to refresh connector {}: {:?}, keeping old candidates",
                    self.source_url,
                    e
                );
            }
        }
    }

    async fn pick_candidate(&self) -> Result<ResolvedCandidate, TunnelError> {
        let candidates = self.candidates.read().await;
        if candidates.is_empty() {
            return Err(TunnelError::InvalidAddr(format!(
                "no candidates available for {}",
                self.source_url
            )));
        }
        let idx = rand::random::<usize>() % candidates.len();
        Ok(candidates[idx].clone())
    }
}

#[async_trait]
impl TunnelConnector for ManagedConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        self.maybe_refresh().await;

        let candidate = self.pick_candidate().await?;
        let candidate_url = candidate.url;

        tracing::info!(
            "ManagedConnector [{}]: connecting via candidate {}",
            self.source_url,
            candidate_url
        );

        let mut connector =
            create_direct_connector(&candidate_url, &self.global_ctx, self.ip_version)
                .await
                .map_err(|e| TunnelError::InvalidAddr(format!("create direct connector: {}", e)))?;

        if !self.bind_addrs.is_empty() {
            connector.set_bind_addrs(self.bind_addrs.clone());
        }

        connector.connect().await
    }

    fn remote_url(&self) -> url::Url {
        self.source_url.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}
