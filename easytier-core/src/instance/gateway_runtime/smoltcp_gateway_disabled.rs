use std::marker::PhantomData;

use crate::{
    config::{gateway::PortForwardConfig, runtime::CoreRuntimeConfigStore},
    instance::CoreInstanceHost,
};

use super::SmoltcpGatewayRuntimeInputs;

pub(in crate::instance) struct SmoltcpGatewayRuntime<H> {
    host: PhantomData<fn() -> H>,
}

impl<H> SmoltcpGatewayRuntime<H>
where
    H: CoreInstanceHost,
{
    pub(in crate::instance) fn new(_inputs: SmoltcpGatewayRuntimeInputs<H>) -> Self {
        Self { host: PhantomData }
    }

    pub(in crate::instance) async fn start(
        &self,
        runtime_config: &CoreRuntimeConfigStore,
    ) -> anyhow::Result<()> {
        let gateway = &runtime_config.snapshot().services.gateway;
        if gateway.socks5_bind.is_some() || !gateway.port_forwards.is_empty() {
            anyhow::bail!("this build does not include the smoltcp gateway");
        }
        Ok(())
    }

    pub(in crate::instance) async fn stop(&self) {}

    pub(in crate::instance) async fn reload_port_forwards(
        &self,
        port_forwards: &[PortForwardConfig],
    ) -> anyhow::Result<()> {
        if !port_forwards.is_empty() {
            anyhow::bail!("this build does not include the smoltcp gateway");
        }
        Ok(())
    }
}
