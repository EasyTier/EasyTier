use std::{collections::BTreeSet, sync::Arc};

use easytier_core::proxy::cidr_monitor::{
    ProxyCidrConfigSnapshot, ProxyCidrMonitor as CoreProxyCidrMonitor, ProxyCidrMonitorHost,
    collect_proxy_cidr_diff,
};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    peers::peer_manager::PeerManager,
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

pub struct ProxyCidrsMonitor {
    inner: CoreProxyCidrMonitor,
}

impl ProxyCidrsMonitor {
    pub fn new(peer_manager: Arc<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        let host = Arc::new(RuntimeProxyCidrMonitorHost { global_ctx });
        Self {
            inner: CoreProxyCidrMonitor::new(&peer_manager.core(), host),
        }
    }

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

    pub fn start(self) -> AbortOnDropHandle<()> {
        self.inner.start()
    }
}
