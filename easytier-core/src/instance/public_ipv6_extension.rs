use crate::instance::{CoreInstance, CoreInstanceHost};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub async fn reconcile_public_ipv6_provider(&self) -> bool {
        self.public_ipv6_provider.reconcile().await
    }
}
