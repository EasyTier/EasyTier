use crate::{
    config::runtime::CoreInstanceRuntimeConfig,
    gateway::vpn_portal::{PortalClientConfig, PortalInfoSnapshot},
    instance::{CoreInstance, CoreInstanceHost},
};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub async fn vpn_portal_info(&self) -> PortalInfoSnapshot {
        self.vpn_portal.info_snapshot().await
    }

    /// Replaces the VPN portal client set at runtime without restarting the
    /// instance. Untouched clients keep their established sessions.
    ///
    /// The caller supplies the runtime snapshot the new set is validated
    /// against, so a combined configuration patch is judged by its final
    /// state rather than the currently running one.
    #[cfg(feature = "vpn-portal")]
    pub(crate) async fn update_vpn_portal_clients(
        &self,
        clients: Vec<PortalClientConfig>,
        runtime: &CoreInstanceRuntimeConfig,
    ) -> anyhow::Result<Vec<PortalClientConfig>> {
        self.vpn_portal.update_clients(clients, runtime).await
    }
}
