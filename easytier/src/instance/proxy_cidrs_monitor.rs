use std::sync::Arc;

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use easytier_core::gateway::proxy::cidr_monitor::ProxyCidrMonitorHost;

struct RuntimeProxyCidrMonitorHost {
    global_ctx: ArcGlobalCtx,
}

impl ProxyCidrMonitorHost for RuntimeProxyCidrMonitorHost {
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
