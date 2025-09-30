use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    rpc_service::instance_manage::InstanceManageRpcService,
};

pub struct Controller {
    token: String,
    hostname: String,
    manager: Arc<NetworkInstanceManager>,
}

impl Controller {
    pub fn new(token: String, hostname: String, manager: Arc<NetworkInstanceManager>) -> Self {
        Controller {
            token,
            hostname,
            manager,
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
        InstanceManageRpcService::new(self.manager.clone())
    }
}
