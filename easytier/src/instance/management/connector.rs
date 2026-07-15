use std::sync::{Arc, Weak};

use easytier_core::connectivity::manual::ManualConnectorStatus;

use crate::{
    proto::{
        api::instance::{
            Connector, ConnectorManageRpc, ConnectorStatus, ListConnectorRequest,
            ListConnectorResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    utils::weak_upgrade,
};

use crate::instance::composition::NativeCoreInstance;

fn connector_snapshots_to_api(
    snapshots: Vec<easytier_core::connectivity::manual::ManualConnectorSnapshot>,
) -> Vec<Connector> {
    let mut connectors = Vec::with_capacity(snapshots.len());
    for connector in snapshots {
        let status = match connector.status {
            ManualConnectorStatus::Connected => ConnectorStatus::Connected,
            ManualConnectorStatus::Disconnected => ConnectorStatus::Disconnected,
            ManualConnectorStatus::Connecting => ConnectorStatus::Connecting,
        };
        connectors.insert(
            0,
            Connector {
                url: Some(connector.url.into()),
                status: status.into(),
            },
        );
    }
    connectors
}

#[derive(Clone)]
pub struct InstanceConnectorManagementRpc(Weak<NativeCoreInstance>);

impl InstanceConnectorManagementRpc {
    pub(crate) fn new(core_instance: &Arc<NativeCoreInstance>) -> Self {
        Self(Arc::downgrade(core_instance))
    }
}

#[async_trait::async_trait]
impl ConnectorManageRpc for InstanceConnectorManagementRpc {
    type Controller = BaseController;

    async fn list_connector(
        &self,
        _: BaseController,
        _request: ListConnectorRequest,
    ) -> Result<ListConnectorResponse, rpc_types::error::Error> {
        let core_instance = weak_upgrade(&self.0)?;
        Ok(ListConnectorResponse {
            connectors: connector_snapshots_to_api(core_instance.list_connectors()),
        })
    }
}
