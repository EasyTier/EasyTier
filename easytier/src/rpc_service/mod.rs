mod acl_manage;
mod api;
mod config;
mod connector_manage;
mod mapped_listener_manage;
mod peer_manage;
mod port_forward_manage;
mod proxy;
mod stats;
mod vpn_portal;

pub mod instance_manage;
pub mod logger;

pub type ApiRpcServer = self::api::ApiRpcServer;

pub trait InstanceRpcService: Sync + Send {
    fn get_peer_manage_service(
        &self,
    ) -> &dyn crate::proto::api::instance::PeerManageRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
    fn get_connector_manage_service(
        &self,
    ) -> &dyn crate::proto::api::instance::ConnectorManageRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
    fn get_mapped_listener_manage_service(
        &self,
    ) -> &dyn crate::proto::api::instance::MappedListenerManageRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
    fn get_vpn_portal_service(
        &self,
    ) -> &dyn crate::proto::api::instance::VpnPortalRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
    fn get_proxy_service(
        &self,
        client_type: &str,
    ) -> Option<
        std::sync::Arc<
            dyn crate::proto::api::instance::TcpProxyRpc<
                    Controller = crate::proto::rpc_types::controller::BaseController,
                > + Send
                + Sync,
        >,
    >;
    fn get_acl_manage_service(
        &self,
    ) -> &dyn crate::proto::api::instance::AclManageRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
    fn get_port_forward_manage_service(
        &self,
    ) -> &dyn crate::proto::api::instance::PortForwardManageRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
    fn get_stats_service(
        &self,
    ) -> &dyn crate::proto::api::instance::StatsRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
    fn get_config_service(
        &self,
    ) -> &dyn crate::proto::api::config::ConfigRpc<
        Controller = crate::proto::rpc_types::controller::BaseController,
    >;
}

fn get_instance_service(
    instance_manager: &std::sync::Arc<crate::instance_manager::NetworkInstanceManager>,
    identifier: &Option<crate::proto::api::instance::InstanceIdentifier>,
) -> Result<std::sync::Arc<dyn InstanceRpcService>, anyhow::Error> {
    use crate::proto::api;
    let selector = identifier.as_ref().and_then(|s| s.selector.as_ref());

    let id = if let Some(api::instance::instance_identifier::Selector::Id(id)) = selector {
        (*id).into()
    } else {
        let ids = instance_manager.filter_network_instance(|_, i| {
            if let Some(api::instance::instance_identifier::Selector::InstanceSelector(selector)) =
                selector
            {
                if let Some(name) = selector.name.as_ref() {
                    if i.get_inst_name() != *name {
                        return false;
                    }
                }
            }
            true
        });
        match ids.len() {
            0 => return Err(anyhow::anyhow!("No instance matches the selector")),
            1 => ids[0],
            _ => {
                return Err(anyhow::anyhow!(
                    "{} instances match the selector, please specify the instance ID",
                    ids.len()
                ))
            }
        }
    };

    instance_manager
        .get_instance_service(&id)
        .ok_or_else(|| anyhow::anyhow!("Instance not found or API service not available"))
}
