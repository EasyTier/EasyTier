use std::sync::Arc;

use crate::{
    gateway::proxy::cidr_monitor::ProxyCidrMonitorHost,
    instance::{CoreInstance, CoreInstanceHost, CoreInstanceState},
};

pub(in crate::instance) struct ProxyCidrMonitorRuntime;

impl ProxyCidrMonitorRuntime {
    pub(in crate::instance) fn new(_host: Option<Arc<dyn ProxyCidrMonitorHost>>) -> Self {
        Self
    }

    pub(in crate::instance) fn has_host(&self) -> bool {
        false
    }

    pub(in crate::instance) async fn stop(&self) {}

    pub(in crate::instance) async fn start<H>(
        &self,
        instance: &CoreInstance<H>,
    ) -> anyhow::Result<()>
    where
        H: CoreInstanceHost,
    {
        let _operation = instance.operation.lock().await;
        let state = instance.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy CIDR monitor cannot start from core instance state {state:?}");
        }
        Ok(())
    }
}
