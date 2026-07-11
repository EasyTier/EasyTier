use std::{collections::BTreeSet, sync::Arc};

use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    peers::peer_manager::PeerManager,
};
use easytier_core::proxy::cidr_monitor::{
    ProxyCidrConfigSnapshot, ProxyCidrMonitorHost, collect_proxy_cidr_diff,
};

struct RuntimeProxyCidrMonitorHost {
    global_ctx: ArcGlobalCtx,
}

impl RuntimeProxyCidrMonitorHost {
    fn snapshot(global_ctx: &ArcGlobalCtx) -> ProxyCidrConfigSnapshot {
        ProxyCidrConfigSnapshot {
            manual_routes: global_ctx
                .config
                .get_routes()
                .map(|routes| routes.into_iter().collect()),
            vpn_portal_cidr: global_ctx
                .config
                .get_vpn_portal_config()
                .map(|config| config.client_cidr),
        }
    }
}

impl ProxyCidrMonitorHost for RuntimeProxyCidrMonitorHost {
    fn config_snapshot(&self) -> ProxyCidrConfigSnapshot {
        Self::snapshot(&self.global_ctx)
    }

    fn emit_updated(&self, added: Vec<cidr::Ipv4Cidr>, removed: Vec<cidr::Ipv4Cidr>) {
        self.global_ctx
            .issue_event(GlobalCtxEvent::ProxyCidrsUpdated(added, removed));
    }
}

pub(crate) fn runtime_proxy_cidr_monitor_host(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn ProxyCidrMonitorHost> {
    Arc::new(RuntimeProxyCidrMonitorHost { global_ctx })
}

pub struct ProxyCidrsMonitor;

impl ProxyCidrsMonitor {
    pub async fn diff_proxy_cidrs(
        peer_manager: &PeerManager,
        global_ctx: &ArcGlobalCtx,
        current: &BTreeSet<cidr::Ipv4Cidr>,
    ) -> (
        BTreeSet<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
        Vec<cidr::Ipv4Cidr>,
    ) {
        let host = RuntimeProxyCidrMonitorHost {
            global_ctx: global_ctx.clone(),
        };
        let diff = collect_proxy_cidr_diff(peer_manager.core().as_ref(), &host, current).await;
        (diff.current, diff.added, diff.removed)
    }
}
