use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    gateway::proxy::cidr_monitor::{ProxyCidrMonitor, ProxyCidrMonitorHost},
    instance::{CoreInstance, CoreInstanceHost, CoreInstanceState},
};

pub(in crate::instance) struct ProxyCidrMonitorRuntime {
    host: Option<Arc<dyn ProxyCidrMonitorHost>>,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl ProxyCidrMonitorRuntime {
    pub(in crate::instance) fn new(host: Option<Arc<dyn ProxyCidrMonitorHost>>) -> Self {
        Self {
            host,
            task: Mutex::new(None),
        }
    }

    pub(in crate::instance) fn has_host(&self) -> bool {
        self.host.is_some()
    }

    pub(in crate::instance) async fn stop(&self) {
        self.task.lock().await.take();
    }

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
        let Some(host) = &self.host else {
            return Ok(());
        };
        let mut task = self.task.lock().await;
        if task.is_some() {
            return Ok(());
        }
        if instance.cancel.is_cancelled() {
            anyhow::bail!("proxy CIDR monitor start cancelled");
        }

        task.replace(
            ProxyCidrMonitor::new(
                &instance.peer_manager,
                instance.runtime_config.clone(),
                host.clone(),
            )
            .start(),
        );
        if instance.cancel.is_cancelled() {
            task.take();
            anyhow::bail!("proxy CIDR monitor start cancelled");
        }
        Ok(())
    }
}
