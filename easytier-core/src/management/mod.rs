//! Process-level management over the canonical Instance collection.

#[cfg(all(feature = "management", any(test, target_os = "wasi")))]
mod forwarded_rpc;
#[cfg(feature = "management")]
mod full;
mod instance_rpc;
mod rpc_server_hook;
mod selector;
mod server;

use std::sync::Arc;

use crate::{
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
    rpc::service_registry::ServiceRegistry,
};
#[cfg(all(feature = "management", target_os = "wasi"))]
use easytier_proto::api::config::ConfigRpcServer;
use easytier_proto::api::instance::{ConnectorManageRpcServer, PeerManageRpcServer};

pub use crate::instance::manager::{
    ConfigFileControl, ConfigFilePermission, DaemonGuard, InstanceManager, ProcessRuntimeProvider,
};
#[cfg(all(feature = "management", target_os = "wasi"))]
pub(crate) use forwarded_rpc::{
    ManagementRpcForwarder, register_forwarded_instance_management_rpc,
};
#[cfg(all(feature = "management", target_os = "wasi"))]
pub(crate) use full::WebClientBackend;
#[cfg(feature = "management")]
pub use full::remote_client;
#[cfg(feature = "management")]
pub use full::{
    ConfigFileStorage, ConfigServerEndpoint, InstanceMutationHooks, InstanceMutationResult,
    LoggerControl, LoggerManagementRpc, ProcessManagement, ProcessManagementRpc,
    UnsupportedConfigFileStorage, UnsupportedLoggerControl, WebClient, WebClientConfig,
    apply_config_patch, call_instance_json_rpc, call_management_json_rpc, config_source_from_rpc,
    config_source_to_rpc, log_level_name, network_instance_running_info, parse_log_level,
    register_instance_management_rpc, register_management_rpc,
};
pub use instance_rpc::InstanceManagementRpc;
pub use rpc_server_hook::ManagementRpcServerHook;
pub use selector::{
    ManagementInstance, ManagementSelector, resolve_instance, resolve_management_instance,
    resolve_optional_instance_by_name,
};
#[cfg(feature = "management")]
pub use server::ManagementServer;
pub use server::ReadOnlyManagementServer;
/// Registers the read-only status surface used by compact native nodes.
pub fn register_read_only_management_rpc<F, H>(
    manager: Arc<InstanceManager<F>>,
    registry: &ServiceRegistry,
) where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    let rpc = InstanceManagementRpc::<F>::new(manager);
    registry.register(PeerManageRpcServer::new(rpc.clone()), "");
    registry.register(ConnectorManageRpcServer::new(rpc), "");
}

#[cfg(target_os = "wasi")]
pub(crate) fn register_bound_management_rpc<H>(
    instance: Arc<CoreInstance<H>>,
    registry: &ServiceRegistry,
) where
    H: CoreInstanceHost,
{
    let rpc = instance_rpc::bound_rpc(instance);
    registry.register(PeerManageRpcServer::new(rpc.clone()), "");
    registry.register(ConnectorManageRpcServer::new(rpc.clone()), "");
    #[cfg(feature = "management")]
    registry.register(ConfigRpcServer::new(rpc), "");
}
