use std::sync::Arc;

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use easytier_core::proxy::cidr_monitor::{ProxyCidrConfigSnapshot, ProxyCidrMonitorHost};

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
