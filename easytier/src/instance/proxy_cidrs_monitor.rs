use std::collections::BTreeSet;
use std::sync::{Arc, Weak};
use std::time::Instant;

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::common::scoped_task::ScopedTask;
use crate::peers::peer_manager::PeerManager;

/// ProxyCidrsMonitor monitors changes in proxy CIDRs from peer routes
/// and emits GlobalCtxEvent::ProxyCidrsUpdated with added/removed diffs.
pub struct ProxyCidrsMonitor {
    peer_mgr: Weak<PeerManager>,
    global_ctx: ArcGlobalCtx,
}

impl ProxyCidrsMonitor {
    pub fn new(peer_mgr: Arc<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            peer_mgr: Arc::downgrade(&peer_mgr),
            global_ctx,
        }
    }

    /// Collects current proxy_cidrs from peer routes, VPN portal config, and manual routes.
    /// This is a static function that can be used for initial sync or recovery after Lagged errors.
    pub async fn diff_proxy_cidrs(
        peer_mgr: &PeerManager,
        global_ctx: &ArcGlobalCtx,
        cur_proxy_cidrs: &mut BTreeSet<cidr::Ipv4Cidr>,
    ) -> (Vec<cidr::Ipv4Cidr>, Vec<cidr::Ipv4Cidr>) {
        // Collect proxy_cidrs from routes
        let mut proxy_cidrs = BTreeSet::new();
        let routes = peer_mgr.list_routes().await;
        for r in routes {
            for cidr in r.proxy_cidrs {
                let Ok(cidr) = cidr.parse::<cidr::Ipv4Cidr>() else {
                    continue;
                };
                proxy_cidrs.insert(cidr);
            }
        }

        // Add VPN portal cidr to proxy_cidrs
        if let Some(vpn_cfg) = global_ctx.config.get_vpn_portal_config() {
            proxy_cidrs.insert(vpn_cfg.client_cidr);
        }

        // If has manual routes, override entire proxy_cidrs
        if let Some(routes) = global_ctx.config.get_routes() {
            proxy_cidrs = routes.into_iter().collect();
        }

        // Calculate diff
        if cur_proxy_cidrs == &proxy_cidrs {
            return (Vec::new(), Vec::new());
        }
        let added: Vec<cidr::Ipv4Cidr> = proxy_cidrs.difference(cur_proxy_cidrs).cloned().collect();
        let removed: Vec<cidr::Ipv4Cidr> =
            cur_proxy_cidrs.difference(&proxy_cidrs).cloned().collect();

        *cur_proxy_cidrs = proxy_cidrs;

        (added, removed)
    }

    /// Starts monitoring proxy_cidrs changes and emits events with diffs
    pub fn start(self) -> ScopedTask<()> {
        ScopedTask::from(tokio::spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::new();
            let mut last_update = Instant::now();

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let Some(peer_mgr) = self.peer_mgr.upgrade() else {
                    tracing::warn!("peer manager dropped, stopping ProxyCidrsMonitor");
                    break;
                };

                // Check if route info has been updated
                let last_update_time = peer_mgr.get_route_peer_info_last_update_time().await;
                if last_update == last_update_time {
                    continue;
                }
                last_update = last_update_time;

                let (added, removed) = Self::diff_proxy_cidrs(
                    peer_mgr.as_ref(),
                    &self.global_ctx,
                    &mut cur_proxy_cidrs,
                )
                .await;

                if added.is_empty() && removed.is_empty() {
                    continue;
                }
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ProxyCidrsUpdated(added, removed));
            }
        }))
    }
}
