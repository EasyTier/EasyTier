mod compiled;
mod config_patch;
mod instance_info;
mod logger_rpc;
pub(super) mod packet_proxy;
mod process_rpc;
pub mod remote_client;
mod server;
mod web_client;

use std::sync::Arc;

use easytier_proto::{
    api::{
        logger::{LoggerRpc, LoggerRpcServer},
        manage::WebClientServiceServer,
    },
    rpc_types::controller::BaseController,
};

use crate::{
    config::toml::ConfigSource,
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    rpc::service_registry::ServiceRegistry,
};

use super::{
    ConfigFileControl, ConfigFilePermission, DaemonGuard, ManagedInstanceSet,
    ManagementRpcServerHook, resolve_optional_instance_by_name,
};

pub use compiled::register_instance_management_rpc;
pub use config_patch::apply_config_patch;
pub use instance_info::network_instance_running_info;
pub use logger_rpc::{
    LoggerControl, LoggerManagementRpc, UnsupportedLoggerControl, log_level_name, parse_log_level,
};
pub use process_rpc::{
    ConfigFileStorage, InstanceMutationHooks, InstanceMutationResult, ProcessManagement,
    ProcessManagementRpc, UnsupportedConfigFileStorage,
};
pub use server::ManagementServer;
pub use web_client::{ConfigServerEndpoint, WebClient, WebClientConfig};

pub use super::instance_rpc::full::call_instance_json_rpc;

pub fn config_source_from_rpc(source: i32) -> Option<ConfigSource> {
    match easytier_proto::api::manage::ConfigSource::try_from(source).ok() {
        Some(easytier_proto::api::manage::ConfigSource::Web) => Some(ConfigSource::Web),
        Some(easytier_proto::api::manage::ConfigSource::User) => Some(ConfigSource::User),
        _ => None,
    }
}

pub fn config_source_to_rpc(source: ConfigSource) -> i32 {
    match source {
        ConfigSource::User => easytier_proto::api::manage::ConfigSource::User as i32,
        ConfigSource::Web => easytier_proto::api::manage::ConfigSource::Web as i32,
    }
}

/// Registers the complete process-level management surface once.
pub fn register_management_rpc<F, H>(
    instances: Arc<ManagedInstanceSet<F>>,
    registry: &ServiceRegistry,
    hooks: Arc<dyn InstanceMutationHooks>,
    storage: Arc<dyn ConfigFileStorage>,
    logger: Arc<dyn LoggerControl>,
) where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    register_instance_management_rpc(instances.manager(), registry);
    registry.register(LoggerRpcServer::new(LoggerManagementRpc::new(logger)), "");
    registry.register(
        WebClientServiceServer::new(ProcessManagementRpc::<F, H>::new(instances, hooks, storage)),
        "",
    );
}

pub async fn call_management_json_rpc<F, H>(
    manager: &Arc<InstanceManager<F>>,
    logger: Arc<dyn LoggerControl>,
    service_name: &str,
    method_name: &str,
    domain_name: Option<&str>,
    payload: serde_json::Value,
) -> crate::proto::rpc_types::error::Result<serde_json::Value>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    if service_name == "api.manage.WebClientService" {
        return Err(anyhow::anyhow!(
            "service {service_name} is not exposed through FFI/JNI generic RPC"
        )
        .into());
    }
    if service_name == "api.logger.LoggerRpcService" {
        return LoggerRpc::json_call_method(
            &LoggerManagementRpc::new(logger),
            BaseController::default(),
            method_name,
            payload,
        )
        .await;
    }
    call_instance_json_rpc(manager, service_name, method_name, domain_name, payload).await
}
