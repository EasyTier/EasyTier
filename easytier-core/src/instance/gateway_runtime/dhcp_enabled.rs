use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    gateway::dhcp::{DhcpIpv4Host, DhcpIpv4RouteSource, DhcpIpv4Service},
    instance::{CoreInstance, CoreInstanceHost, CoreInstanceState},
};

pub(in crate::instance) struct DhcpIpv4Runtime {
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl DhcpIpv4Runtime {
    pub(in crate::instance) fn new() -> Self {
        Self {
            task: Mutex::new(None),
        }
    }

    pub(in crate::instance) async fn stop(&self) {
        self.task.lock().await.take();
    }

    pub(in crate::instance) async fn start<H>(
        &self,
        instance: &CoreInstance<H>,
        host: Option<Arc<dyn DhcpIpv4Host>>,
    ) -> anyhow::Result<()>
    where
        H: CoreInstanceHost,
    {
        let _operation = instance.operation.lock().await;
        let state = instance.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("DHCP IPv4 cannot start from core instance state {state:?}");
        }
        if !instance.runtime_config.snapshot().services.dhcp_ipv4 {
            return Ok(());
        }
        let host = host.ok_or_else(|| {
            anyhow::anyhow!("DHCP IPv4 is enabled but no host adapter was provided")
        })?;
        let mut task = self.task.lock().await;
        if task.is_some() {
            return Ok(());
        }
        if instance.cancel.is_cancelled() {
            anyhow::bail!("DHCP IPv4 start cancelled");
        }

        let route_source: Arc<dyn DhcpIpv4RouteSource> = instance.peer_manager.clone();
        task.replace(
            DhcpIpv4Service::new(route_source, instance.runtime_config.clone(), host).start(),
        );
        if instance.cancel.is_cancelled() {
            task.take();
            anyhow::bail!("DHCP IPv4 start cancelled");
        }
        Ok(())
    }
}
