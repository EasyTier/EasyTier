//! Composition root for a core instance driven by host-owned I/O handles.

#[cfg(target_os = "wasi")]
pub mod wasi;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    connectivity::host::{
        HostConnectorAdapter, HostConnectorSocketBackend,
        environment::{HostConnectorEnvironmentServices, HostConnectorEnvironmentSnapshot},
    },
    socket::host::{
        HostSocketRuntime,
        dns::{HostDnsIo, HostDnsResolver},
        environment::{HostConnectorEnvironmentIo, HostConnectorEnvironmentServiceAdapter},
        packet::{HostPacketIo, HostPacketSink, HostPacketSinkHandle},
    },
};

use super::{CoreInstance, CoreInstanceAdapters, PortableCoreInstanceConfig};

pub const HOST_CORE_INSTANCE_CONFIG_VERSION: u32 = 8;

/// Versioned payload accepted by host-driven instance frontends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCoreInstanceCreateConfig {
    pub version: u32,
    pub instance: PortableCoreInstanceConfig,
    pub environment: HostConnectorEnvironmentSnapshot,
}

impl HostCoreInstanceCreateConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != HOST_CORE_INSTANCE_CONFIG_VERSION {
            anyhow::bail!(
                "unsupported host core instance config version: {}",
                self.version
            );
        }
        Ok(())
    }
}

/// A portable core instance and the shared scheduler bridge for its host I/O.
///
/// Socket, listener, DNS, and packet adapters must use the same runtime so one
/// host completion notification can wake every kind of pending core task.
pub struct HostCoreInstance<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    socket_runtime: HostSocketRuntime,
    instance: Arc<CoreInstance<HostConnectorAdapter<B, E>>>,
}

impl<B, E> HostCoreInstance<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    /// Composes adapters under a caller-provided completion runtime.
    ///
    /// Any asynchronous environment implementation must use this same runtime.
    pub fn new_with_runtime<D, P>(
        config: PortableCoreInstanceConfig,
        socket_runtime: HostSocketRuntime,
        socket_backend: Arc<B>,
        environment_snapshot: HostConnectorEnvironmentSnapshot,
        environment_services: Arc<E>,
        dns_io: Arc<D>,
        packet_io: Arc<P>,
        packet_sink: HostPacketSinkHandle,
    ) -> anyhow::Result<Self>
    where
        D: HostDnsIo,
        P: HostPacketIo,
    {
        let host = Arc::new(HostConnectorAdapter::new(
            socket_runtime.clone(),
            socket_backend,
            environment_snapshot,
            environment_services,
        ));
        let dns = Arc::new(HostDnsResolver::new(socket_runtime.clone(), dns_io));
        let packet_sink = Arc::new(HostPacketSink::new(
            socket_runtime.clone(),
            packet_io,
            packet_sink,
        ));
        let adapters = CoreInstanceAdapters {
            host,
            stun_projection: None,
            dns: dns.clone(),
            listener_dns: None,
            dns_records: dns,
            ring_registry: Arc::new(crate::tunnel::ring::RingTunnelRegistry::default()),
            protocol: None,
            manual_events: None,
            external_listener_factory: None,
            listener_events: None,
            server_protocol: None,
            accepted_tunnel_events: None,
            udp_hole_punch_platform: None,
            #[cfg(feature = "proxy-packet")]
            icmp_proxy_host: None,
            proxy_cidr_monitor: None,
            public_ipv6_provider: None,
            vpn_portal: None,
            vpn_portal_events: None,
            #[cfg(feature = "proxy-smoltcp-stack")]
            gateway_events: None,
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

impl<B, I> HostCoreInstance<B, HostConnectorEnvironmentServiceAdapter<I>>
where
    B: HostConnectorSocketBackend,
    I: HostConnectorEnvironmentIo,
{
    /// Composes environment operations with every other host adapter under one
    /// completion runtime.
    pub fn new_with_environment_io<D, P>(
        config: PortableCoreInstanceConfig,
        socket_backend: Arc<B>,
        environment_snapshot: HostConnectorEnvironmentSnapshot,
        environment_io: Arc<I>,
        dns_io: Arc<D>,
        packet_io: Arc<P>,
        packet_sink: HostPacketSinkHandle,
    ) -> anyhow::Result<Self>
    where
        D: HostDnsIo,
        P: HostPacketIo,
    {
        let socket_runtime = HostSocketRuntime::new();
        let services = Arc::new(HostConnectorEnvironmentServiceAdapter::new(
            socket_runtime.clone(),
            environment_io,
        ));
        Self::new_with_runtime(
            config,
            socket_runtime,
            socket_backend,
            environment_snapshot,
            services,
            dns_io,
            packet_io,
            packet_sink,
        )
    }
}

#[cfg(target_os = "wasi")]
pub type WasiHostCoreInstance = HostCoreInstance<
    crate::socket::host::wasi_backend::WasiHostSocketBackend,
    HostConnectorEnvironmentServiceAdapter<
        crate::socket::host::environment::wasi::WasiHostConnectorEnvironmentIo,
    >,
>;

#[cfg(target_os = "wasi")]
pub fn new_wasi_host_core_instance(
    config: PortableCoreInstanceConfig,
    environment_snapshot: HostConnectorEnvironmentSnapshot,
    packet_sink: HostPacketSinkHandle,
) -> anyhow::Result<WasiHostCoreInstance> {
    use crate::socket::host::{
        dns::wasi::WasiHostDnsIo, environment::wasi::WasiHostConnectorEnvironmentIo,
        packet::wasi::WasiHostPacketIo, wasi_backend::WasiHostSocketBackend,
    };

    HostCoreInstance::new_with_environment_io(
        config,
        Arc::new(WasiHostSocketBackend::default()),
        environment_snapshot,
        Arc::new(WasiHostConnectorEnvironmentIo),
        Arc::new(WasiHostDnsIo),
        Arc::new(WasiHostPacketIo),
        packet_sink,
    )
}
