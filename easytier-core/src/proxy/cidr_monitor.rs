use std::{collections::BTreeSet, sync::Arc, time::Duration};

use cidr::Ipv4Cidr;
use tokio_util::task::AbortOnDropHandle;

use crate::peers::peer_manager::PeerManagerCore;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyCidrConfigSnapshot {
    pub manual_routes: Option<BTreeSet<Ipv4Cidr>>,
    pub vpn_portal_cidr: Option<Ipv4Cidr>,
}

pub trait ProxyCidrMonitorHost: Send + Sync + 'static {
    fn config_snapshot(&self) -> ProxyCidrConfigSnapshot;
    fn emit_updated(&self, added: Vec<Ipv4Cidr>, removed: Vec<Ipv4Cidr>);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyCidrDiff {
    pub current: BTreeSet<Ipv4Cidr>,
    pub added: Vec<Ipv4Cidr>,
    pub removed: Vec<Ipv4Cidr>,
}

pub fn resolve_proxy_cidrs(
    mut peer_routes: BTreeSet<Ipv4Cidr>,
    config: ProxyCidrConfigSnapshot,
) -> BTreeSet<Ipv4Cidr> {
    if let Some(manual_routes) = config.manual_routes {
        return manual_routes;
    }
    if let Some(vpn_portal_cidr) = config.vpn_portal_cidr {
        peer_routes.insert(vpn_portal_cidr);
    }
    peer_routes
}

pub fn diff_proxy_cidrs(
    previous: &BTreeSet<Ipv4Cidr>,
    current: BTreeSet<Ipv4Cidr>,
) -> ProxyCidrDiff {
    let added = current.difference(previous).copied().collect();
    let removed = previous.difference(&current).copied().collect();
    ProxyCidrDiff {
        current,
        added,
        removed,
    }
}

pub async fn collect_proxy_cidrs(
    peer_manager: &PeerManagerCore,
    config: ProxyCidrConfigSnapshot,
) -> BTreeSet<Ipv4Cidr> {
    let peer_routes = peer_manager.get_route().list_proxy_cidrs().await;
    resolve_proxy_cidrs(peer_routes, config)
}

pub async fn collect_proxy_cidr_diff(
    peer_manager: &PeerManagerCore,
    host: &dyn ProxyCidrMonitorHost,
    previous: &BTreeSet<Ipv4Cidr>,
) -> ProxyCidrDiff {
    let current = collect_proxy_cidrs(peer_manager, host.config_snapshot()).await;
    diff_proxy_cidrs(previous, current)
}

pub struct ProxyCidrMonitor {
    peer_manager: std::sync::Weak<PeerManagerCore>,
    host: Arc<dyn ProxyCidrMonitorHost>,
}

impl ProxyCidrMonitor {
    pub fn new(peer_manager: &Arc<PeerManagerCore>, host: Arc<dyn ProxyCidrMonitorHost>) -> Self {
        Self {
            peer_manager: Arc::downgrade(peer_manager),
            host,
        }
    }

    pub fn start(self) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut current = BTreeSet::new();
            let mut last_update = None;

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(peer_manager) = self.peer_manager.upgrade() else {
                    break;
                };
                let update = peer_manager
                    .get_route()
                    .get_peer_info_last_update_time()
                    .await;
                if last_update == Some(update) {
                    continue;
                }
                last_update = Some(update);

                let diff =
                    collect_proxy_cidr_diff(peer_manager.as_ref(), self.host.as_ref(), &current)
                        .await;
                current = diff.current;
                if !diff.added.is_empty() || !diff.removed.is_empty() {
                    self.host.emit_updated(diff.added, diff.removed);
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidrs(values: &[&str]) -> BTreeSet<Ipv4Cidr> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn manual_routes_override_peer_and_vpn_routes() {
        let resolved = resolve_proxy_cidrs(
            cidrs(&["10.0.0.0/8"]),
            ProxyCidrConfigSnapshot {
                manual_routes: Some(cidrs(&["192.0.2.0/24"])),
                vpn_portal_cidr: Some("198.51.100.0/24".parse().unwrap()),
            },
        );
        assert_eq!(resolved, cidrs(&["192.0.2.0/24"]));
    }

    #[test]
    fn dynamic_routes_merge_vpn_and_report_ordered_diff() {
        let current = resolve_proxy_cidrs(
            cidrs(&["10.0.0.0/8"]),
            ProxyCidrConfigSnapshot {
                manual_routes: None,
                vpn_portal_cidr: Some("192.0.2.0/24".parse().unwrap()),
            },
        );
        let diff = diff_proxy_cidrs(&cidrs(&["10.0.0.0/8", "172.16.0.0/12"]), current);

        assert_eq!(diff.current, cidrs(&["10.0.0.0/8", "192.0.2.0/24"]));
        assert_eq!(diff.added, vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(diff.removed, vec!["172.16.0.0/12".parse().unwrap()]);
    }
}
