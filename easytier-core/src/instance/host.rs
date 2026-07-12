//! Composition root for a core instance driven by host-owned I/O handles.

use std::sync::Arc;

use crate::{
    connectivity::host::{
        DirectConnectorEnvironment, HostConnectorAdapter, HostConnectorSocketBackend,
    },
    hole_punch::tcp::TcpHolePunchEnvironment,
    socket::host::{
        HostSocketRuntime,
        dns::{HostDnsIo, HostDnsResolver},
        packet::{HostPacketIo, HostPacketSink, HostPacketSinkHandle},
    },
};

use super::{CoreInstance, CoreInstanceAdapters, PortableCoreInstanceConfig};

/// A portable core instance and the shared scheduler bridge for its host I/O.
///
/// Socket, listener, DNS, and packet adapters must use the same runtime so one
/// host completion notification can wake every kind of pending core task.
pub struct HostCoreInstance<B, E>
where
    B: HostConnectorSocketBackend,
    E: DirectConnectorEnvironment + TcpHolePunchEnvironment,
{
    socket_runtime: HostSocketRuntime,
    instance: Arc<CoreInstance<HostConnectorAdapter<B, E>>>,
}

impl<B, E> HostCoreInstance<B, E>
where
    B: HostConnectorSocketBackend,
    E: DirectConnectorEnvironment + TcpHolePunchEnvironment,
{
    pub fn new<D, P>(
        config: PortableCoreInstanceConfig,
        socket_backend: Arc<B>,
        environment: Arc<E>,
        dns_io: Arc<D>,
        packet_io: Arc<P>,
        packet_sink: HostPacketSinkHandle,
    ) -> anyhow::Result<Self>
    where
        D: HostDnsIo,
        P: HostPacketIo,
    {
        let socket_runtime = HostSocketRuntime::new();
        let host = Arc::new(HostConnectorAdapter::new(
            socket_runtime.clone(),
            socket_backend,
            environment,
        ));
        let dns = Arc::new(HostDnsResolver::new(socket_runtime.clone(), dns_io));
        let packet_sink = Arc::new(HostPacketSink::new(
            socket_runtime.clone(),
            packet_io,
            packet_sink,
        ));
        let adapters = CoreInstanceAdapters {
            host,
            dns: dns.clone(),
            dns_records: dns,
            protocol: None,
            manual_events: None,
            listener: None,
            accepted_transport_handler: None,
            udp_hole_punch: None,
            runtime_config: None,
            transport_proxy: None,
            proxy: None,
            proxy_cidr_runtime: None,
            proxy_cidr_monitor: None,
            public_ipv6_provider: None,
        };
        let instance = Arc::new(CoreInstance::new_portable(adapters, config, packet_sink)?);

        Ok(Self {
            socket_runtime,
            instance,
        })
    }

    pub fn instance(&self) -> &Arc<CoreInstance<HostConnectorAdapter<B, E>>> {
        &self.instance
    }

    pub fn notify_host_completions(&self) {
        self.socket_runtime.notify_completions();
    }
}
