use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    rpc_service::instance_manage::InstanceManageRpcService, web_client::WebClientHooks,
};

pub struct Controller {
    token: String,
    hostname: String,
    manager: Arc<NetworkInstanceManager>,
    hooks: Arc<dyn WebClientHooks>,
}

impl Controller {
    pub fn new(
        token: String,
        hostname: String,
        manager: Arc<NetworkInstanceManager>,
        hooks: Arc<dyn WebClientHooks>,
    ) -> Self {
        Controller {
            token,
            hostname,
            manager,
            hooks,
        }
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.manager.list_network_instance_ids()
    }

    pub fn token(&self) -> String {
        self.token.clone()
    }

    pub fn hostname(&self) -> String {
        self.hostname.clone()
    }

    pub fn get_rpc_service(&self) -> InstanceManageRpcService {
        InstanceManageRpcService::new(self.manager.clone(), self.hooks.clone())
    }

    pub(super) fn notify_manager_stopping(&self) {
        self.manager.notify_stop_check();
    }
}
