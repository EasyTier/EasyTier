use std::collections::BTreeMap;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProxyRoute {
    pub cidr: cidr::Ipv4Cidr,
    pub metric: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::ConfigLoader;

    #[tokio::test]
    async fn diff_proxy_routes_includes_local_route_metrics() {
        let peer_mgr = crate::peers::tests::create_mock_peer_manager().await;
        let global_ctx = peer_mgr.get_global_ctx();
        let local_route = "10.6.0.0/16 via 100.88.88.1 metric 100".parse().unwrap();
        global_ctx.config.set_local_routes(vec![local_route]);

        let (_, added, removed) =
            ProxyCidrsMonitor::diff_proxy_routes(&peer_mgr, &global_ctx, &BTreeMap::new()).await;

        assert_eq!(
            added,
            vec![ProxyRoute {
                cidr: "10.6.0.0/16".parse().unwrap(),
                metric: Some(100),
            }]
        );
        assert!(removed.is_empty());
    }

    #[tokio::test]
    async fn diff_proxy_routes_removes_local_routes() {
        let peer_mgr = crate::peers::tests::create_mock_peer_manager().await;
        let global_ctx = peer_mgr.get_global_ctx();
        let mut current = BTreeMap::new();
        current.insert("10.6.0.0/16".parse().unwrap(), Some(100));

        let (_, added, removed) =
            ProxyCidrsMonitor::diff_proxy_routes(&peer_mgr, &global_ctx, &current).await;

        assert!(added.is_empty());
        assert_eq!(
            removed,
            vec![ProxyRoute {
                cidr: "10.6.0.0/16".parse().unwrap(),
                metric: Some(100),
            }]
        );
    }
}

impl ProxyCidrsMonitor {
    pub fn new(peer_mgr: Arc<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            peer_mgr: Arc::downgrade(&peer_mgr),
            global_ctx,
        }
    }

    fn route_metric_to_cost(metric: Option<u32>) -> Option<i32> {
        metric.and_then(|metric| match i32::try_from(metric) {
            Ok(cost) => Some(cost),
            Err(_) => {
                tracing::warn!(
                    metric,
                    "local route metric is too large for system route cost"
                );
                None
            }
        })
    }

    fn insert_proxy_route(
        routes: &mut BTreeMap<cidr::Ipv4Cidr, Option<i32>>,
        cidr: cidr::Ipv4Cidr,
        metric: Option<i32>,
    ) {
        routes
            .entry(cidr)
            .and_modify(|current| {
                *current = match (*current, metric) {
                    (Some(current), Some(metric)) => Some(current.min(metric)),
                    (None, Some(metric)) => Some(metric),
                    (Some(current), None) => Some(current),
                    (None, None) => None,
                };
            })
            .or_insert(metric);
    }

    fn proxy_route_diff(
        current: &BTreeMap<cidr::Ipv4Cidr, Option<i32>>,
        next: &BTreeMap<cidr::Ipv4Cidr, Option<i32>>,
    ) -> (Vec<ProxyRoute>, Vec<ProxyRoute>) {
        let removed = current
            .iter()
            .filter_map(|(cidr, metric)| {
                (next.get(cidr) != Some(metric)).then_some(ProxyRoute {
                    cidr: *cidr,
                    metric: *metric,
                })
            })
            .collect();
        let added = next
            .iter()
            .filter_map(|(cidr, metric)| {
                (current.get(cidr) != Some(metric)).then_some(ProxyRoute {
                    cidr: *cidr,
                    metric: *metric,
                })
            })
            .collect();
        (added, removed)
    }

    fn proxy_route_cidrs(routes: &[ProxyRoute]) -> Vec<cidr::Ipv4Cidr> {
        routes.iter().map(|route| route.cidr).collect()
    }

    /// Collects current proxy routes from peer routes, VPN portal config, manual routes,
    /// and local route config.
    /// This is a static function that can be used for initial sync or recovery after Lagged errors.
    pub(crate) async fn diff_proxy_routes(
        peer_mgr: &PeerManager,
        global_ctx: &ArcGlobalCtx,
        cur_proxy_routes: &BTreeMap<cidr::Ipv4Cidr, Option<i32>>,
    ) -> (
        BTreeMap<cidr::Ipv4Cidr, Option<i32>>,
        Vec<ProxyRoute>,
        Vec<ProxyRoute>,
    ) {
        let proxy_cidrs = if let Some(routes) = global_ctx.config.get_routes() {
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

        let mut proxy_routes = BTreeMap::new();
        for cidr in proxy_cidrs {
            Self::insert_proxy_route(&mut proxy_routes, cidr, None);
        }
        for route in global_ctx.config.get_local_routes() {
            Self::insert_proxy_route(
                &mut proxy_routes,
                route.cidr,
                Self::route_metric_to_cost(route.metric),
            );
        }

        // Calculate diff
        if cur_proxy_routes == &proxy_routes {
            return (proxy_routes, Vec::new(), Vec::new());
        }
        let (added, removed) = Self::proxy_route_diff(cur_proxy_routes, &proxy_routes);

        (proxy_routes, added, removed)
    }

    /// Starts monitoring proxy_cidrs changes and emits events with diffs
    pub fn start(self) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut cur_proxy_routes = BTreeMap::new();
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

                let (new_proxy_routes, added, removed) =
                    Self::diff_proxy_routes(peer_mgr.as_ref(), &self.global_ctx, &cur_proxy_routes)
                        .await;

                cur_proxy_routes = new_proxy_routes;

                if added.is_empty() && removed.is_empty() {
                    continue;
                }
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ProxyCidrsUpdated(
                        Self::proxy_route_cidrs(&added),
                        Self::proxy_route_cidrs(&removed),
                    ));
            }
        }))
    }
}
