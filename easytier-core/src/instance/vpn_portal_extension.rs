use crate::{
    gateway::vpn_portal::PortalInfoSnapshot,
    instance::{CoreInstance, CoreInstanceHost},
};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub async fn vpn_portal_info(&self) -> PortalInfoSnapshot {
        self.vpn_portal.info_snapshot().await
    }
}
