use std::sync::Arc;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    gateway::vpn_portal::{
        VpnPortalEventSink, VpnPortalHost, VpnPortalInfoSnapshot, VpnPortalModule,
    },
    peers::peer_manager::PeerManagerCore,
};

pub(in crate::instance) struct VpnPortalRuntime {
    module: Arc<VpnPortalModule>,
}

impl VpnPortalRuntime {
    pub(in crate::instance) fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        host: Option<Arc<dyn VpnPortalHost>>,
        events: Option<Arc<dyn VpnPortalEventSink>>,
    ) -> Self {
        Self {
            module: VpnPortalModule::new(
                peer_manager,
                runtime_config,
                host,
                events.unwrap_or_else(|| Arc::new(())),
            ),
        }
    }

    pub(in crate::instance) fn is_available(&self) -> bool {
        true
    }

    pub(in crate::instance) async fn start(&self) -> anyhow::Result<()> {
        self.module.start().await
    }

    pub(in crate::instance) async fn stop(&self) {
        self.module.stop().await;
    }

    pub(in crate::instance) async fn info(&self) -> VpnPortalInfoSnapshot {
        self.module.info_snapshot().await
    }
}
