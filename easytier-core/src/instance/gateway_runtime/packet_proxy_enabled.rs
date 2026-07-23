use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{
    gateway::proxy::{service::CoreProxyModule, tcp_proxy_engine::TcpNatEntrySnapshot},
    instance::CoreInstanceHost,
};

use super::PacketProxyRuntimeInputs;

pub(in crate::instance) struct PacketProxyRuntime<H>
where
    H: CoreInstanceHost,
{
    proxy: Arc<CoreProxyModule<H>>,
    started: AtomicBool,
}

impl<H> PacketProxyRuntime<H>
where
    H: CoreInstanceHost,
{
    pub(in crate::instance) fn new(inputs: PacketProxyRuntimeInputs<H>) -> Self {
        let PacketProxyRuntimeInputs {
            peer_manager,
            host,
            protected_tcp_ports,
            running_listeners,
            runtime_config,
            cidr_table,
            tcp_socket_context,
            udp_socket_context,
            icmp_socket_context,
            icmp_host,
        } = inputs;
        Self {
            proxy: CoreProxyModule::new(
                peer_manager,
                host,
                protected_tcp_ports,
                running_listeners,
                runtime_config,
                cidr_table,
                tcp_socket_context,
                udp_socket_context,
                icmp_socket_context,
                icmp_host,
            ),
            started: AtomicBool::new(false),
        }
    }

    pub(in crate::instance) fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    pub(in crate::instance) async fn start(&self) -> anyhow::Result<()> {
        self.started.store(true, Ordering::Release);
        if let Err(error) = self.proxy.start().await {
            self.proxy.stop().await;
            self.started.store(false, Ordering::Release);
            return Err(anyhow::Error::new(error));
        }
        Ok(())
    }

    pub(in crate::instance) async fn stop(&self) {
        if self.started.swap(false, Ordering::AcqRel) {
            self.proxy.stop().await;
        }
    }

    pub(in crate::instance) fn tcp_entry_snapshots(&self) -> Vec<TcpNatEntrySnapshot> {
        self.proxy.tcp_entry_snapshots()
    }
}
