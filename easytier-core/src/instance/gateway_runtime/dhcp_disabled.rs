use std::sync::Arc;

use crate::{
    gateway::dhcp::DhcpIpv4Host,
    instance::{CoreInstance, CoreInstanceHost, CoreInstanceState},
};

pub(in crate::instance) struct DhcpIpv4Runtime;

impl DhcpIpv4Runtime {
    pub(in crate::instance) fn new() -> Self {
        Self
    }

    pub(in crate::instance) async fn stop(&self) {}

    pub(in crate::instance) async fn start<H>(
        &self,
        instance: &CoreInstance<H>,
        _host: Option<Arc<dyn DhcpIpv4Host>>,
    ) -> anyhow::Result<()>
    where
        H: CoreInstanceHost,
    {
        let _operation = instance.operation.lock().await;
        let state = instance.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("DHCP IPv4 cannot start from core instance state {state:?}");
        }
        Ok(())
    }
}
