use std::{collections::BTreeSet, sync::Arc, time::Duration};

use cidr::Ipv4Cidr;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    peers::peer_manager::PeerManagerCore,
    runtime_config::{CoreInstanceRuntimeConfig, CoreRuntimeConfigStore},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProxyCidrConfigSnapshot {
    pub manual_routes: Option<BTreeSet<Ipv4Cidr>>,
    pub vpn_portal_cidr: Option<Ipv4Cidr>,
}

impl From<&CoreInstanceRuntimeConfig> for ProxyCidrConfigSnapshot {
    fn from(config: &CoreInstanceRuntimeConfig) -> Self {
        Self {
            manual_routes: config.services.manual_routes.clone(),
            vpn_portal_cidr: config.peer.vpn_portal_cidr,
        }
    }
}

pub trait ProxyCidrMonitorHost: Send + Sync + 'static {
    fn emit_updated(&self, added: Vec<Ipv4Cidr>, removed: Vec<Ipv4Cidr>);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyCidrDiff {
    pub current: BTreeSet<Ipv4Cidr>,
    pub added: Vec<Ipv4Cidr>,
    pub removed: Vec<Ipv4Cidr>,
}

pub(crate) fn resolve_proxy_cidrs(
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

pub(crate) fn diff_proxy_cidrs(
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

pub(crate) async fn collect_proxy_cidrs(
    peer_manager: &PeerManagerCore,
    config: &CoreInstanceRuntimeConfig,
) -> BTreeSet<Ipv4Cidr> {
    let peer_routes = peer_manager.get_route().list_proxy_cidrs().await;
    resolve_proxy_cidrs_from_runtime(peer_routes, config)
}

fn resolve_proxy_cidrs_from_runtime(
    peer_routes: BTreeSet<Ipv4Cidr>,
    config: &CoreInstanceRuntimeConfig,
) -> BTreeSet<Ipv4Cidr> {
    resolve_proxy_cidrs(peer_routes, config.into())
}

pub(crate) async fn collect_proxy_cidr_diff(
    peer_manager: &PeerManagerCore,
    runtime_config: &CoreRuntimeConfigStore,
    previous: &BTreeSet<Ipv4Cidr>,
) -> ProxyCidrDiff {
    let config = runtime_config.snapshot();
    collect_proxy_cidr_diff_from_snapshot(peer_manager, config.as_ref(), previous).await
}

async fn collect_proxy_cidr_diff_from_snapshot(
    peer_manager: &PeerManagerCore,
    config: &CoreInstanceRuntimeConfig,
    previous: &BTreeSet<Ipv4Cidr>,
) -> ProxyCidrDiff {
    let current = collect_proxy_cidrs(peer_manager, config).await;
    diff_proxy_cidrs(previous, current)
}

pub(crate) struct ProxyCidrMonitor {
    peer_manager: std::sync::Weak<PeerManagerCore>,
    runtime_config: CoreRuntimeConfigStore,
    host: Arc<dyn ProxyCidrMonitorHost>,
}

impl ProxyCidrMonitor {
    pub(crate) fn new(
        peer_manager: &Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        host: Arc<dyn ProxyCidrMonitorHost>,
    ) -> Self {
        Self {
            peer_manager: Arc::downgrade(peer_manager),
            runtime_config,
            host,
        }
    }

    pub(crate) fn start(self) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut current = BTreeSet::new();
            let mut last_update = None;
            let mut last_runtime_config: Option<Arc<CoreInstanceRuntimeConfig>> = None;

            loop {
                crate::foundation::time::sleep(Duration::from_secs(1)).await;
                let Some(peer_manager) = self.peer_manager.upgrade() else {
                    break;
                };
                let update = peer_manager
                    .get_route()
                    .get_peer_info_last_update_time()
                    .await;
                let runtime_config = self.runtime_config.snapshot();
                let runtime_config_changed = last_runtime_config
                    .as_ref()
                    .map(|previous| !Arc::ptr_eq(previous, &runtime_config))
                    .unwrap_or(true);
                if last_update == Some(update) && !runtime_config_changed {
                    continue;
                }
                last_update = Some(update);
                last_runtime_config = Some(runtime_config.clone());

                let diff = collect_proxy_cidr_diff_from_snapshot(
                    peer_manager.as_ref(),
                    runtime_config.as_ref(),
                    &current,
                )
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
    use crate::{
        peers::context::PeerRuntimeSnapshot,
        runtime_config::{CoreInstanceRuntimeConfig, CoreRuntimeConfig},
    };

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

    #[test]
    fn runtime_store_update_changes_the_monitor_config_snapshot() {
        let mut initial_peer = PeerRuntimeSnapshot::default();
        initial_peer.vpn_portal_cidr = Some("198.51.100.0/24".parse().unwrap());
        let store = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig {
                manual_routes: Some(cidrs(&["192.0.2.0/24"])),
                ..Default::default()
            },
            Arc::new(initial_peer),
        );
        let initial = store.snapshot();

        let mut updated_peer = PeerRuntimeSnapshot::default();
        updated_peer.vpn_portal_cidr = Some("203.0.113.0/24".parse().unwrap());
        store.replace(CoreInstanceRuntimeConfig {
            services: CoreRuntimeConfig::default(),
            peer: Arc::new(updated_peer),
        });
        let updated = store.snapshot();

        assert_eq!(
            resolve_proxy_cidrs_from_runtime(cidrs(&["10.0.0.0/8"]), initial.as_ref()),
            cidrs(&["192.0.2.0/24"])
        );
        assert_eq!(
            resolve_proxy_cidrs_from_runtime(cidrs(&["10.0.0.0/8"]), updated.as_ref()),
            cidrs(&["10.0.0.0/8", "203.0.113.0/24"])
        );
    }
}
