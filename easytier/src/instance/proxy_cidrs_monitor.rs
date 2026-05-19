use std::collections::BTreeSet;
use std::sync::{Arc, Weak};
use std::time::Instant;

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::peers::peer_manager::PeerManager;
use tokio_util::task::AbortOnDropHandle;

/// ProxyCidrsMonitor monitors changes in proxy CIDRs from peer routes
/// and emits GlobalCtxEvent::ProxyCidrsUpdated with added/removed diffs.
pub struct ProxyCidrsMonitor {
    peer_mgr: Weak<PeerManager>,
    global_ctx: ArcGlobalCtx,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::ConfigLoader;

    #[tokio::test]
    async fn diff_proxy_cidrs_includes_local_routes() {
        let peer_mgr = crate::peers::tests::create_mock_peer_manager().await;
        let global_ctx = peer_mgr.get_global_ctx();
        let local_route = "10.6.0.0/16 via 100.88.88.1".parse().unwrap();
        global_ctx.config.set_local_routes(vec![local_route]);

        let (_, added, removed) =
            ProxyCidrsMonitor::diff_proxy_cidrs(&peer_mgr, &global_ctx, &BTreeSet::new()).await;

        assert_eq!(added, vec!["10.6.0.0/16".parse().unwrap()]);
        assert!(removed.is_empty());
    }
}

impl ProxyCidrsMonitor {
    pub fn new(peer_mgr: Arc<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            peer_mgr: Arc::downgrade(&peer_mgr),
            global_ctx,
        }
    }

    /// Collects current proxy_cidrs from peer routes, VPN portal config, manual routes,
    /// and local route config.
    /// This is a static function that can be used for initial sync or recovery after Lagged errors.
    pub async fn diff_proxy_cidrs(
        peer_mgr: &PeerManager,
        global_ctx: &ArcGlobalCtx,
        cur_proxy_cidrs: &BTreeSet<cidr::Ipv4Cidr>,
    ) -> (
        BTreeSet<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
    ) {
        let mut proxy_cidrs = if let Some(routes) = global_ctx.config.get_routes() {
            // If manual routes exist, override entire proxy_cidrs
            routes.into_iter().collect()
        } else {
            // Collect proxy_cidrs from routes
            let mut proxy_cidrs = peer_mgr.list_proxy_cidrs().await;

            // Add VPN portal cidr to proxy_cidrs
            if let Some(vpn_cfg) = global_ctx.config.get_vpn_portal_config() {
                proxy_cidrs.insert(vpn_cfg.client_cidr);
            }

            proxy_cidrs
        };

        proxy_cidrs.extend(
            global_ctx
                .config
                .get_local_routes()
                .into_iter()
                .map(|route| route.cidr),
        );

        // Calculate diff
        if cur_proxy_cidrs == &proxy_cidrs {
            return (proxy_cidrs, Vec::new(), Vec::new());
        }
        let added = proxy_cidrs.difference(cur_proxy_cidrs).cloned().collect();
        let removed = cur_proxy_cidrs.difference(&proxy_cidrs).cloned().collect();

        (proxy_cidrs, added, removed)
    }

    /// Starts monitoring proxy_cidrs changes and emits events with diffs
    pub fn start(self) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::new();
            let mut last_update = None::<Instant>;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let Some(peer_mgr) = self.peer_mgr.upgrade() else {
                    tracing::warn!("peer manager dropped, stopping ProxyCidrsMonitor");
                    break;
                };

                // Check if route info has been updated
                let last_update_time = peer_mgr.get_route_peer_info_last_update_time().await;
                if last_update == Some(last_update_time) {
                    continue;
                }
                last_update = Some(last_update_time);

                let (new_proxy_cidrs, added, removed) =
                    Self::diff_proxy_cidrs(peer_mgr.as_ref(), &self.global_ctx, &cur_proxy_cidrs)
                        .await;

                cur_proxy_cidrs = new_proxy_cidrs;

                if added.is_empty() && removed.is_empty() {
                    continue;
                }
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ProxyCidrsUpdated(added, removed));
            }
        }))
    }
}
