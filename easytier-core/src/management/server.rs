use std::sync::Arc;

use cidr::IpCidr;

use crate::{
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, ProcessRuntimeProvider},
    },
    process_runtime::{CoreProcessRuntime, ProtectedTcpPortLease},
    proto::rpc_types::error::Error,
    rpc::{
        service_registry::ServiceRegistry,
        standalone::{RpcServerHook, StandAloneServer},
    },
    socket::SocketListener,
    tunnel::Tunnel,
};

#[cfg(feature = "management")]
use super::{ConfigFileStorage, InstanceMutationHooks, LoggerControl, register_management_rpc};
use super::{InstanceManager, ManagementRpcServerHook, register_read_only_management_rpc};

struct ManagementListener<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    server: StandAloneServer<L>,
    process_runtime: Arc<CoreProcessRuntime>,
}

impl<L> ManagementListener<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    fn new(listener: L, process_runtime: Arc<CoreProcessRuntime>) -> Self {
        Self {
            server: StandAloneServer::new(listener),
            process_runtime,
        }
    }

    fn set_whitelist(&mut self, whitelist: Option<Vec<IpCidr>>) {
        let hook: Arc<dyn RpcServerHook> = Arc::new(ManagementRpcServerHook::new(whitelist));
        self.server.set_hook(hook);
    }

    async fn serve(&mut self) -> crate::proto::rpc_types::error::Result<()> {
        let process_runtime = self.process_runtime.clone();
        let binding_guard = protect_tcp_port(&process_runtime, &self.server.listener_url())?;
        self.server
            .serve_with_bound_listener(binding_guard, move |url| {
                protect_tcp_port(&process_runtime, url)
            })
            .await
    }

    fn set_rx_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.server.set_rx_timeout(timeout);
    }

    fn registry(&self) -> &ServiceRegistry {
        self.server.registry()
    }
}

impl<L> Drop for ManagementListener<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    fn drop(&mut self) {
        self.server.registry().unregister_all();
    }
}

fn protect_tcp_port(
    process_runtime: &CoreProcessRuntime,
    url: &url::Url,
) -> Result<Option<ProtectedTcpPortLease>, Error> {
    match (url.scheme(), url.port()) {
        ("tcp", Some(0) | None) => Err(anyhow::anyhow!(
            "management TCP listener requires a concrete protected port before binding"
        )
        .into()),
        ("tcp", Some(port)) => Ok(Some(process_runtime.protect_tcp_port(port))),
        _ => Ok(None),
    }
}

#[cfg(feature = "management")]
pub struct ManagementServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    listener: ManagementListener<L>,
}

#[cfg(feature = "management")]
impl<L> ManagementServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn new<F, H>(
        listener: L,
        instances: Arc<InstanceManager<F>>,
        hooks: Arc<dyn InstanceMutationHooks>,
        storage: Arc<dyn ConfigFileStorage>,
        logger: Arc<dyn LoggerControl>,
    ) -> Self
    where
        F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()> + ProcessRuntimeProvider,
        F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
        H: CoreInstanceHost,
    {
        let server = ManagementListener::new(listener, instances.process_runtime());
        register_management_rpc(instances, server.registry(), hooks, storage, logger);
        Self { listener: server }
    }

    /// Enables CIDR authorization for IP-based management transports.
    /// Non-IP local transports intentionally keep the server default.
    pub fn set_whitelist(&mut self, whitelist: Option<Vec<IpCidr>>) {
        self.listener.set_whitelist(whitelist);
    }

    pub async fn serve(&mut self) -> crate::proto::rpc_types::error::Result<()> {
        self.listener.serve().await
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.listener.set_rx_timeout(timeout);
        self
    }

    pub fn set_rx_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.listener.set_rx_timeout(timeout);
    }

    pub fn registry(&self) -> &ServiceRegistry {
        self.listener.registry()
    }
}

pub struct ReadOnlyManagementServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    listener: ManagementListener<L>,
}

impl<L> ReadOnlyManagementServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn new<F, H>(listener: L, instances: Arc<InstanceManager<F>>) -> Self
    where
        F: InstanceFactory<Instance = CoreInstance<H>> + ProcessRuntimeProvider,
        H: CoreInstanceHost,
    {
        let server = ManagementListener::new(listener, instances.process_runtime());
        register_read_only_management_rpc(instances, server.registry());
        Self { listener: server }
    }

    pub fn set_whitelist(&mut self, whitelist: Option<Vec<IpCidr>>) {
        self.listener.set_whitelist(whitelist);
    }

    pub async fn serve(&mut self) -> crate::proto::rpc_types::error::Result<()> {
        self.listener.serve().await
    }

    pub fn set_rx_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.listener.set_rx_timeout(timeout);
    }
}
