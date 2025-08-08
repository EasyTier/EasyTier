use std::sync::Arc;

use crate::{
    common::{
        error::Error,
        global_ctx::GlobalCtx,
    },
    connector::{
        manual::ManualConnectorManager,
        multi_connector::MultiConnector,
    },
};

pub struct ConnectorAllocator;

impl ConnectorAllocator {
    /// Allocate and resolve different URL schemes to appropriate connectors
    pub async fn allocate_and_resolve(
        target_url: &str,
        conn_manager: &Arc<ManualConnectorManager>,
        global_ctx: &Arc<GlobalCtx>,
    ) -> Result<usize, Error> {
        tracing::info!(
            target_url = %target_url,
            "ConnectorAllocator: Starting URL scheme allocation"
        );

        // Parse scheme from URL
        if let Some((scheme, _)) = target_url.split_once("://") {
            match scheme.to_lowercase().as_str() {
                "txt" => {
                    tracing::info!(
                        target_url = %target_url,
                        scheme = %scheme,
                        "ConnectorAllocator: Routing to MultiConnector for TXT resolution"
                    );
                    MultiConnector::resolve_txt_domain(target_url, conn_manager, global_ctx).await
                }
                "srv" => {
                    tracing::info!(
                        target_url = %target_url,
                        scheme = %scheme,
                        "ConnectorAllocator: Routing to MultiConnector for SRV resolution"
                    );
                    MultiConnector::resolve_srv_domain(target_url, conn_manager, global_ctx).await
                }
                _ => {
                    tracing::info!(
                        target_url = %target_url,
                        scheme = %scheme,
                        "ConnectorAllocator: Routing to direct connector addition"
                    );
                    // Route to direct connector addition for all other schemes (tcp, udp, http, etc.)
                    match conn_manager.add_connector_by_url(target_url).await {
                        Ok(_) => Ok(1),
                        Err(e) => Err(e)
                    }
                }
            }
        } else {
            tracing::error!(
                target_url = %target_url,
                "ConnectorAllocator: Invalid URL format, no scheme found"
            );
            Err(anyhow::anyhow!("Invalid URL format: {}", target_url).into())
        }
    }
}
