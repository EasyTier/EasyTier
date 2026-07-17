//! Composition root for a core instance driven by host-owned I/O handles.

#[cfg(target_os = "wasi")]
pub mod wasi;

use serde::{Deserialize, Serialize};

use crate::connectivity::host::environment::HostConnectorEnvironmentSnapshot;

use super::CoreInstanceConfig;

pub(super) const WASI_CORE_INSTANCE_CONFIG_VERSION: u32 = 13;

/// Versioned payload accepted by host-driven instance frontends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct WasiCoreInstanceCreateConfig {
    pub version: u32,
    pub instance: CoreInstanceConfig,
    pub environment: HostConnectorEnvironmentSnapshot,
}

impl WasiCoreInstanceCreateConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != WASI_CORE_INSTANCE_CONFIG_VERSION {
            anyhow::bail!(
                "unsupported host core instance config version: {}",
                self.version
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "wasi")]
pub(super) type WasiCore = super::CoreInstance<
    crate::connectivity::host::HostConnectorAdapter<
        crate::host::wasi_backend::WasiHostSocketBackend,
        crate::host::environment::HostConnectorEnvironmentServiceAdapter<
            crate::host::environment::wasi::WasiHostConnectorEnvironmentIo,
        >,
    >,
>;

#[cfg(target_os = "wasi")]
pub(super) struct WasiCoreRuntime {
    socket_runtime: crate::host::HostSocketRuntime,
    core: std::sync::Arc<WasiCore>,
}

#[cfg(target_os = "wasi")]
impl WasiCoreRuntime {
    pub(super) fn core(&self) -> &std::sync::Arc<WasiCore> {
        &self.core
    }

    pub(super) fn notify_host_completions(&self) {
        self.socket_runtime.notify_completions();
    }
}

#[cfg(target_os = "wasi")]
pub(super) fn new_wasi_core_runtime(
    config: CoreInstanceConfig,
    process_runtime: std::sync::Arc<crate::process_runtime::CoreProcessRuntime>,
    environment_snapshot: HostConnectorEnvironmentSnapshot,
    packet_sink: crate::host::packet::HostPacketSinkHandle,
) -> anyhow::Result<WasiCoreRuntime> {
    use std::sync::Arc;

    use crate::host::{
        HostSocketRuntime,
        dns::{HostDnsResolver, wasi::WasiHostDnsIo},
        environment::{
            HostConnectorEnvironmentServiceAdapter, wasi::WasiHostConnectorEnvironmentIo,
        },
        packet::{HostPacketSink, wasi::WasiHostPacketIo},
        wasi_backend::WasiHostSocketBackend,
    };
    use crate::{
        connectivity::host::HostConnectorAdapter,
        instance::{CoreHostAdapters, CoreInstance},
    };

    let socket_runtime = HostSocketRuntime::new();
    let environment_services = Arc::new(HostConnectorEnvironmentServiceAdapter::new(
        socket_runtime.clone(),
        Arc::new(WasiHostConnectorEnvironmentIo),
    ));
    let host = Arc::new(HostConnectorAdapter::new(
        socket_runtime.clone(),
        Arc::new(WasiHostSocketBackend::default()),
        environment_snapshot,
        environment_services,
    ));
    let dns = Arc::new(HostDnsResolver::new(
        socket_runtime.clone(),
        Arc::new(WasiHostDnsIo),
    ));
    let packet_sink = Arc::new(HostPacketSink::new(
        socket_runtime.clone(),
        Arc::new(WasiHostPacketIo),
        packet_sink,
    ));
    let adapters = CoreHostAdapters::new(host, dns, packet_sink, process_runtime);
    let core = CoreInstance::new(config, adapters)?;

    Ok(WasiCoreRuntime {
        socket_runtime,
        core,
    })
}
