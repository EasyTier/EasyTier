use std::marker::PhantomData;

use crate::instance::CoreInstanceHost;

use super::PacketProxyRuntimeInputs;

pub(in crate::instance) struct PacketProxyRuntime<H> {
    host: PhantomData<fn() -> H>,
}

impl<H> PacketProxyRuntime<H>
where
    H: CoreInstanceHost,
{
    pub(in crate::instance) fn new(_inputs: PacketProxyRuntimeInputs<H>) -> Self {
        Self { host: PhantomData }
    }

    pub(in crate::instance) fn is_started(&self) -> bool {
        false
    }

    pub(in crate::instance) async fn start(&self) -> anyhow::Result<()> {
        anyhow::bail!("this build does not include packet proxy services")
    }

    pub(in crate::instance) async fn stop(&self) {}
}
