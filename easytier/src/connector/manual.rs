use std::sync::{Arc, Weak};

use easytier_core::connectivity::manual::ManualConnectorStatus;
#[cfg(test)]
use easytier_core::connectivity::manual::{
    ManualConnectorManager as CoreManualConnectorManager, discovery::CoreManualEndpointResolver,
};

use crate::{
    common::error::Error,
    proto::{
        api::instance::{
            Connector, ConnectorManageRpc, ConnectorStatus, ListConnectorRequest,
            ListConnectorResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    utils::weak_upgrade,
};

#[cfg(test)]
use crate::{common::global_ctx::ArcGlobalCtx, peers::peer_manager::PeerManager};

use super::core_instance::RuntimeCoreInstance;
#[cfg(test)]
use super::{
    core_instance::{
        runtime_core_instance_adapters_with_ring_registry, runtime_endpoint_discovery_config,
        runtime_manual_options,
    },
    runtime::RuntimeConnectorHost,
};

#[cfg(test)]
type CoreConnectorManager = CoreManualConnectorManager<RuntimeConnectorHost>;

enum PortableManualOwner {
    #[cfg(test)]
    Standalone(Arc<CoreConnectorManager>),
    Instance(Arc<RuntimeCoreInstance>),
}

impl PortableManualOwner {
    fn add_connector(&self, url: url::Url) -> anyhow::Result<()> {
        match self {
            #[cfg(test)]
            Self::Standalone(manager) => manager.add_connector(url),
            Self::Instance(instance) => instance.add_connector(url),
        }
    }

    fn remove_connector(&self, url: &url::Url) -> bool {
        match self {
            #[cfg(test)]
            Self::Standalone(manager) => manager.remove_connector(url),
            Self::Instance(instance) => instance.remove_connector(url),
        }
    }

    fn clear_connectors(&self) {
        match self {
            #[cfg(test)]
            Self::Standalone(manager) => manager.clear_connectors(),
            Self::Instance(instance) => instance.clear_connectors(),
        }
    }

    fn list_connectors(&self) -> Vec<easytier_core::connectivity::manual::ManualConnectorSnapshot> {
        match self {
            #[cfg(test)]
            Self::Standalone(manager) => manager.list_connectors(),
            Self::Instance(instance) => instance.list_connectors(),
        }
    }
}

pub struct ManualConnectorManager {
    portable: PortableManualOwner,
}

impl ManualConnectorManager {
    #[cfg(test)]
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let adapters = runtime_core_instance_adapters_with_ring_registry(
            global_ctx.clone(),
            peer_manager.ring_registry(),
        );
        let endpoint_resolver = Arc::new(CoreManualEndpointResolver::new(
            adapters.host.clone(),
            adapters.dns.clone(),
            adapters.dns_records.clone(),
            runtime_endpoint_discovery_config(&global_ctx),
        ));
        let core_manager = Arc::new(CoreManualConnectorManager::new_with_events(
            peer_manager.core(),
            adapters.host,
            adapters.dns,
            endpoint_resolver,
            adapters
                .protocol
                .expect("native runtime should provide optional protocol upgrades"),
            adapters.ring_registry,
            runtime_manual_options(&global_ctx),
            adapters.manual_events.unwrap(),
        ));
        core_manager.start();

        Self::new_with_portable_owner(PortableManualOwner::Standalone(core_manager))
    }

    pub(crate) fn new_with_core_instance(core_instance: Arc<RuntimeCoreInstance>) -> Self {
        Self::new_with_portable_owner(PortableManualOwner::Instance(core_instance))
    }

    fn new_with_portable_owner(portable: PortableManualOwner) -> Self {
        Self { portable }
    }
}

impl ManualConnectorManager {
    pub fn add_connector_url(&self, url: url::Url) {
        tracing::info!(%url, "add_connector");
        self.portable
            .add_connector(url)
            .expect("core manual connector URL should be valid");
    }

    pub async fn add_connector_by_url(&self, url: url::Url) -> Result<(), Error> {
        self.portable.add_connector(url)?;
        Ok(())
    }

    pub async fn remove_connector(&self, url: url::Url) -> Result<(), Error> {
        tracing::info!("remove_connector: {}", url);
        if self.portable.remove_connector(&url) {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub async fn clear_connectors(&self) {
        self.portable.clear_connectors();
    }

    pub async fn list_connectors(&self) -> Vec<Connector> {
        connector_snapshots_to_api(self.portable.list_connectors())
    }
}

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
pub struct ConnectorManagerRpcService(Weak<RuntimeCoreInstance>);

impl ConnectorManagerRpcService {
    pub(crate) fn new(core_instance: &Arc<RuntimeCoreInstance>) -> Self {
        Self(Arc::downgrade(core_instance))
    }
}

#[async_trait::async_trait]
impl ConnectorManageRpc for ConnectorManagerRpcService {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use easytier_core::tunnel::ring::RingTunnelRegistry;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::{
        common::config::ConfigLoader,
        instance::listeners::ListenerManager,
        peers::tests::{
            create_mock_peer_manager, create_mock_peer_manager_with_ring_registry,
            wait_route_appear,
        },
        set_global_var,
        tunnel::common::tests::wait_for_condition,
    };

    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn core_tcp_connector_and_listener_form_peer_connection() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);

        let server = create_mock_peer_manager().await;
        server
            .get_global_ctx()
            .config
            .set_listeners(vec!["tcp://127.0.0.1:0".parse().unwrap()]);
        let mut listener_manager = ListenerManager::new(server.get_global_ctx(), server.core());
        listener_manager.prepare_listeners().await.unwrap();
        listener_manager.run().await.unwrap();

        wait_for_condition(
            || {
                let server = server.clone();
                async move {
                    server
                        .get_global_ctx()
                        .get_running_listeners()
                        .into_iter()
                        .any(|url| url.scheme() == "tcp")
                }
            },
            Duration::from_secs(2),
        )
        .await;
        let listener_url = server
            .get_global_ctx()
            .get_running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "tcp")
            .expect("TCP listener should start");

        let client = create_mock_peer_manager().await;
        let mut flags = client.get_global_ctx().get_flags();
        flags.bind_device = false;
        client.get_global_ctx().set_flags(flags);
        let connector_manager =
            ManualConnectorManager::new(client.get_global_ctx(), client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        wait_route_appear(client.clone(), server.clone())
            .await
            .unwrap();
        assert!(
            client
                .core()
                .get_peer_map()
                .is_client_url_alive(&listener_url)
        );
        assert!(
            client
                .core()
                .has_directly_connected_conn(server.my_peer_id())
        );

        let server_peer_id = server.my_peer_id();
        let first_conn_id = client
            .core()
            .get_peer_map()
            .get_peer_default_conn_id(server_peer_id)
            .await
            .unwrap();
        client
            .core()
            .close_peer_conn(server_peer_id, &first_conn_id)
            .await
            .unwrap();
        wait_for_condition(
            || {
                let client = client.clone();
                async move {
                    client
                        .core()
                        .get_peer_map()
                        .get_peer_default_conn_id(server_peer_id)
                        .await
                        .is_some_and(|conn_id| conn_id != first_conn_id)
                }
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(
            client
                .core()
                .get_peer_map()
                .is_client_url_alive(&listener_url)
        );

        assert!(
            connector_manager
                .list_connectors()
                .await
                .iter()
                .any(|connector| {
                    connector.url.as_ref().is_some_and(|url| {
                        url.url == listener_url.as_str()
                            && connector.status == ConnectorStatus::Connected as i32
                    })
                })
        );
        connector_manager
            .remove_connector(listener_url.clone())
            .await
            .unwrap();
        assert!(
            !connector_manager
                .list_connectors()
                .await
                .iter()
                .any(|connector| {
                    connector
                        .url
                        .as_ref()
                        .is_some_and(|url| url.url == listener_url.as_str())
                })
        );
        assert!(
            connector_manager
                .remove_connector(listener_url.clone())
                .await
                .is_err()
        );

        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();
        connector_manager.clear_connectors().await;
        assert!(
            !connector_manager
                .list_connectors()
                .await
                .iter()
                .any(|connector| {
                    connector
                        .url
                        .as_ref()
                        .is_some_and(|url| url.url == listener_url.as_str())
                })
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn core_ring_connector_and_listener_form_peer_connection() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);

        let ring_registry = Arc::new(RingTunnelRegistry::default());
        let server = create_mock_peer_manager_with_ring_registry(ring_registry.clone()).await;
        let mut listener_manager = ListenerManager::new_with_ring_registry(
            server.get_global_ctx(),
            server.core(),
            ring_registry.clone(),
        );
        listener_manager.prepare_listeners().await.unwrap();
        listener_manager.run().await.unwrap();
        let listener_url = server
            .get_global_ctx()
            .get_running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "ring")
            .expect("Ring listener should start");

        let client = create_mock_peer_manager_with_ring_registry(ring_registry).await;
        let connector_manager =
            ManualConnectorManager::new(client.get_global_ctx(), client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        wait_route_appear(client.clone(), server.clone())
            .await
            .unwrap();
        assert!(
            client
                .core()
                .get_peer_map()
                .is_client_url_alive(&listener_url)
        );
        assert!(
            client
                .core()
                .has_directly_connected_conn(server.my_peer_id())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn core_unix_connector_and_listener_form_peer_connection() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);
        let listener_url: url::Url = format!(
            "unix:///tmp/easytier-core-manual-{}.sock",
            uuid::Uuid::new_v4()
        )
        .parse()
        .unwrap();

        let server = create_mock_peer_manager().await;
        server
            .get_global_ctx()
            .config
            .set_listeners(vec![listener_url.clone()]);
        let mut listener_manager = ListenerManager::new(server.get_global_ctx(), server.core());
        listener_manager.prepare_listeners().await.unwrap();
        listener_manager.run().await.unwrap();

        let client = create_mock_peer_manager().await;
        let connector_manager =
            ManualConnectorManager::new(client.get_global_ctx(), client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        wait_route_appear(client.clone(), server.clone())
            .await
            .unwrap();
        assert!(
            client
                .core()
                .get_peer_map()
                .is_client_url_alive(&listener_url)
        );
        assert!(
            client
                .core()
                .has_directly_connected_conn(server.my_peer_id())
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn core_http_discovery_connects_through_resolved_tcp_endpoint() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);

        let server = create_mock_peer_manager().await;
        server
            .get_global_ctx()
            .config
            .set_listeners(vec!["tcp://127.0.0.1:0".parse().unwrap()]);
        let mut listener_manager = ListenerManager::new(server.get_global_ctx(), server.core());
        listener_manager.prepare_listeners().await.unwrap();
        listener_manager.run().await.unwrap();
        wait_for_condition(
            || {
                let server = server.clone();
                async move {
                    server
                        .get_global_ctx()
                        .get_running_listeners()
                        .into_iter()
                        .any(|url| url.scheme() == "tcp")
                }
            },
            Duration::from_secs(2),
        )
        .await;
        let target_url = server
            .get_global_ctx()
            .get_running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "tcp")
            .unwrap();

        let discovery_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let discovery_url: url::Url =
            format!("http://{}", discovery_listener.local_addr().unwrap())
                .parse()
                .unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = discovery_listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let client = create_mock_peer_manager().await;
        let mut flags = client.get_global_ctx().get_flags();
        flags.bind_device = false;
        client.get_global_ctx().set_flags(flags);
        let connector_manager =
            ManualConnectorManager::new(client.get_global_ctx(), client.clone());
        connector_manager
            .add_connector_by_url(discovery_url.clone())
            .await
            .unwrap();

        wait_route_appear(client.clone(), server.clone())
            .await
            .unwrap();
        assert!(
            client
                .core()
                .get_peer_map()
                .is_client_url_alive(&discovery_url)
        );
        assert!(
            client
                .core()
                .has_directly_connected_conn(server.my_peer_id())
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn core_udp_connector_and_listener_form_peer_connection() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);

        let server = create_mock_peer_manager().await;
        server
            .get_global_ctx()
            .config
            .set_listeners(vec!["udp://127.0.0.1:0".parse().unwrap()]);
        let mut listener_manager = ListenerManager::new(server.get_global_ctx(), server.core());
        listener_manager.prepare_listeners().await.unwrap();
        listener_manager.run().await.unwrap();

        wait_for_condition(
            || {
                let server = server.clone();
                async move {
                    server
                        .get_global_ctx()
                        .get_running_listeners()
                        .into_iter()
                        .any(|url| url.scheme() == "udp")
                }
            },
            Duration::from_secs(2),
        )
        .await;
        let listener_url = server
            .get_global_ctx()
            .get_running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "udp")
            .expect("UDP listener should start");

        let client = create_mock_peer_manager().await;
        let mut flags = client.get_global_ctx().get_flags();
        flags.bind_device = false;
        client.get_global_ctx().set_flags(flags);
        let connector_manager =
            ManualConnectorManager::new(client.get_global_ctx(), client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        wait_route_appear(client.clone(), server.clone())
            .await
            .unwrap();
        assert!(
            client
                .core()
                .get_peer_map()
                .is_client_url_alive(&listener_url)
        );
        assert!(
            client
                .core()
                .has_directly_connected_conn(server.my_peer_id())
        );

        let server_peer_id = server.my_peer_id();
        let first_conn_id = client
            .core()
            .get_peer_map()
            .get_peer_default_conn_id(server_peer_id)
            .await
            .unwrap();
        client
            .core()
            .close_peer_conn(server_peer_id, &first_conn_id)
            .await
            .unwrap();
        wait_for_condition(
            || {
                let client = client.clone();
                async move {
                    client
                        .core()
                        .get_peer_map()
                        .get_peer_default_conn_id(server_peer_id)
                        .await
                        .is_some_and(|conn_id| conn_id != first_conn_id)
                }
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(
            client
                .core()
                .get_peer_map()
                .is_client_url_alive(&listener_url)
        );

        assert!(
            connector_manager
                .list_connectors()
                .await
                .iter()
                .any(|connector| {
                    connector.url.as_ref().is_some_and(|url| {
                        url.url == listener_url.as_str()
                            && connector.status == ConnectorStatus::Connected as i32
                    })
                })
        );
        connector_manager
            .remove_connector(listener_url.clone())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let removed = !connector_manager
                    .list_connectors()
                    .await
                    .iter()
                    .any(|connector| {
                        connector
                            .url
                            .as_ref()
                            .is_some_and(|url| url.url == listener_url.as_str())
                    });
                if removed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
