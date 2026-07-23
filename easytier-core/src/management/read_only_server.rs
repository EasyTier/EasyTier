use std::sync::Arc;

use cidr::IpCidr;

use crate::{
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
    process_runtime::{CoreProcessRuntime, ProtectedTcpPortLease},
    proto::rpc_types::error::Error,
    rpc::standalone::{RpcServerHook, StandAloneServer},
    socket::SocketListener,
    tunnel::Tunnel,
};

use super::{ManagedInstanceSet, ManagementRpcServerHook, register_read_only_management_rpc};

pub struct ReadOnlyManagementServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    server: StandAloneServer<L>,
    process_runtime: Arc<CoreProcessRuntime>,
}

impl<L> ReadOnlyManagementServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn new<F, H>(listener: L, instances: Arc<ManagedInstanceSet<F>>) -> Self
    where
        F: InstanceFactory<Instance = CoreInstance<H>>,
        H: CoreInstanceHost,
    {
        let process_runtime = instances.process_runtime();
        let server = StandAloneServer::new(listener);
        register_read_only_management_rpc(instances.manager(), server.registry());
        Self {
            server,
            process_runtime,
        }
    }

    pub fn set_whitelist(&mut self, whitelist: Option<Vec<IpCidr>>) {
        let hook: Arc<dyn RpcServerHook> = Arc::new(ManagementRpcServerHook::new(whitelist));
        self.server.set_hook(hook);
    }

    pub async fn serve(&mut self) -> crate::proto::rpc_types::error::Result<()> {
        let process_runtime = self.process_runtime.clone();
        let binding_guard = protect_tcp_port(&process_runtime, &self.server.listener_url())?;
        self.server
            .serve_with_bound_listener(binding_guard, move |url| {
                protect_tcp_port(&process_runtime, url)
            })
            .await
    }

    pub fn set_rx_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.server.set_rx_timeout(timeout);
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

impl<L> Drop for ReadOnlyManagementServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    fn drop(&mut self) {
        self.server.registry().unregister_all();
    }
}
