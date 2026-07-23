//! Process-level management over the canonical Instance collection.

#[cfg(feature = "management")]
mod full;
mod instance_rpc;
mod managed_instances;
mod read_only_server;
mod rpc_server_hook;
mod selector;

use std::sync::Arc;

use crate::{
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    rpc::service_registry::ServiceRegistry,
};
use easytier_proto::api::instance::{ConnectorManageRpcServer, PeerManageRpcServer};

#[cfg(feature = "management")]
pub use full::remote_client;
#[cfg(feature = "management")]
pub use full::{
    ConfigFileStorage, ConfigServerEndpoint, InstanceMutationHooks, InstanceMutationResult,
    LoggerControl, LoggerManagementRpc, ManagementServer, ProcessManagement, ProcessManagementRpc,
    UnsupportedConfigFileStorage, UnsupportedLoggerControl, WebClient, WebClientConfig,
    apply_config_patch, call_instance_json_rpc, call_management_json_rpc, config_source_from_rpc,
    config_source_to_rpc, log_level_name, network_instance_running_info, parse_log_level,
    register_instance_management_rpc, register_management_rpc,
};
pub use instance_rpc::InstanceManagementRpc;
pub use managed_instances::{
    ConfigFileControl, ConfigFilePermission, DaemonGuard, ManagedInstanceSet,
    ProcessRuntimeProvider,
};
pub use read_only_server::ReadOnlyManagementServer;
pub use rpc_server_hook::ManagementRpcServerHook;
pub use selector::{
    ManagementInstance, ManagementSelector, resolve_instance, resolve_management_instance,
    resolve_optional_instance_by_name,
};
/// Registers the read-only status surface used by compact native nodes.
pub fn register_read_only_management_rpc<F, H>(
    manager: Arc<InstanceManager<F>>,
    registry: &ServiceRegistry,
) where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    let rpc = InstanceManagementRpc::<F, H>::new(manager);
    registry.register(PeerManageRpcServer::new(rpc.clone()), "");
    registry.register(ConnectorManageRpcServer::new(rpc), "");
}
