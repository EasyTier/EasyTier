use std::sync::Arc;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    gateway::vpn_portal::{VpnPortalEventSink, VpnPortalHost},
    peers::peer_manager::PeerManagerCore,
};

pub(in crate::instance) struct VpnPortalRuntime;

impl VpnPortalRuntime {
    pub(in crate::instance) fn new(
        _peer_manager: Arc<PeerManagerCore>,
        _runtime_config: CoreRuntimeConfigStore,
        _host: Option<Arc<dyn VpnPortalHost>>,
        _events: Option<Arc<dyn VpnPortalEventSink>>,
    ) -> Self {
        Self
    }

    pub(in crate::instance) fn is_available(&self) -> bool {
        false
    }

    pub(in crate::instance) async fn start(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub(in crate::instance) async fn stop(&self) {}
}
