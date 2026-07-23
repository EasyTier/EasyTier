use std::sync::Arc;

use crate::{
    gateway::proxy::wrapped_transport::{WrappedTransportEngines, WrappedTransportProxyModule},
    instance::CoreInstanceHost,
};

use super::WrappedTransportRuntimeInputs;

pub(in crate::instance) struct WrappedTransportRuntime {
    proxy: Option<Arc<WrappedTransportProxyModule>>,
}

impl WrappedTransportRuntime {
    pub(in crate::instance) fn new<H>(inputs: WrappedTransportRuntimeInputs<H>) -> Self
    where
        H: CoreInstanceHost,
    {
        let WrappedTransportRuntimeInputs {
            peer_manager,
            runtime_config,
            engines,
            host,
            protected_tcp_ports,
            running_listeners,
            cidr_table,
            socket_context,
        } = inputs;
        let WrappedTransportEngines { kcp, quic } = engines;
        Self {
            proxy: WrappedTransportProxyModule::new(
                peer_manager,
                runtime_config,
                kcp,
                quic,
                host,
                protected_tcp_ports,
                running_listeners,
                cidr_table,
                socket_context,
            ),
        }
    }

    pub(in crate::instance) fn is_available(&self) -> bool {
        self.proxy.is_some()
    }

    #[allow(dead_code)]
    pub(in crate::instance) fn proxy(&self) -> Option<&Arc<WrappedTransportProxyModule>> {
        self.proxy.as_ref()
    }

    pub(in crate::instance) fn proxy_cloned(&self) -> Option<Arc<WrappedTransportProxyModule>> {
        self.proxy.clone()
    }

    pub(in crate::instance) async fn start(&self) -> anyhow::Result<()> {
        match &self.proxy {
            Some(proxy) => proxy.start().await,
            None => Ok(()),
        }
    }

    pub(in crate::instance) async fn stop(&self) {
        if let Some(proxy) = &self.proxy {
            proxy.stop().await;
        }
    }
}
