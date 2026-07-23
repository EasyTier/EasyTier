use std::sync::Arc;

use easytier_proto::{
    api::{
        config::ConfigRpcServer,
        instance::{
            AclManageRpcServer, ConnectorManageRpcServer, CredentialManageRpcServer,
            MappedListenerManageRpcServer, PeerManageRpcServer, PortForwardManageRpcServer,
            StatsRpcServer, VpnPortalRpcServer,
        },
    },
    peer_rpc::PeerCenterRpcServer,
};

use super::super::instance_rpc::InstanceManagementRpc;
use crate::{
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    rpc::service_registry::ServiceRegistry,
};

/// Registers each Instance-targeted management protocol Interface once for
/// the complete process-level Instance collection.
pub fn register_instance_management_rpc<F, H>(
    manager: Arc<InstanceManager<F>>,
    registry: &ServiceRegistry,
) where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    let rpc = InstanceManagementRpc::<F, H>::new(manager.clone());
    registry.register(PeerManageRpcServer::new(rpc.clone()), "");
    registry.register(ConnectorManageRpcServer::new(rpc.clone()), "");
    registry.register(MappedListenerManageRpcServer::new(rpc.clone()), "");
    registry.register(VpnPortalRpcServer::new(rpc.clone()), "");
    super::packet_proxy::register(manager.clone(), registry);
    registry.register(AclManageRpcServer::new(rpc.clone()), "");
    registry.register(PortForwardManageRpcServer::new(rpc.clone()), "");
    registry.register(StatsRpcServer::new(rpc.clone()), "");
    registry.register(ConfigRpcServer::new(rpc.clone()), "");
    registry.register(CredentialManageRpcServer::new(rpc.clone()), "");
    registry.register(PeerCenterRpcServer::new(rpc), "");
}
