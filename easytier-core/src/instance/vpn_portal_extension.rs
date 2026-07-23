use crate::{
    gateway::vpn_portal::VpnPortalInfoSnapshot,
    instance::{CoreInstance, CoreInstanceHost},
};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub async fn vpn_portal_info(&self) -> VpnPortalInfoSnapshot {
        self.vpn_portal.info().await
    }
}
