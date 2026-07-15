use std::sync::{Arc, Weak};

use easytier_core::connectivity::manual::ManualConnectorStatus;

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

use super::core_instance::RuntimeCoreInstance;

pub struct ManualConnectorManager {
    core_instance: Arc<RuntimeCoreInstance>,
}

impl ManualConnectorManager {
    pub(crate) fn new_with_core_instance(core_instance: Arc<RuntimeCoreInstance>) -> Self {
        Self { core_instance }
    }
}

impl ManualConnectorManager {
    pub fn add_connector_url(&self, url: url::Url) {
        tracing::info!(%url, "add_connector");
        self.core_instance
            .add_connector(url)
            .expect("core manual connector URL should be valid");
    }

    pub async fn add_connector_by_url(&self, url: url::Url) -> Result<(), Error> {
        self.core_instance.add_connector(url)?;
        Ok(())
    }

    pub async fn remove_connector(&self, url: url::Url) -> Result<(), Error> {
        tracing::info!("remove_connector: {}", url);
        if self.core_instance.remove_connector(&url) {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub async fn clear_connectors(&self) {
        self.core_instance.clear_connectors();
    }

    pub async fn list_connectors(&self) -> Vec<Connector> {
        connector_snapshots_to_api(self.core_instance.list_connectors())
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
        common::{config::ConfigLoader, global_ctx::tests::get_mock_global_ctx},
        connector::core_instance::build_portable_test_core_instance,
        set_global_var,
        tunnel::common::tests::wait_for_condition,
    };

    use super::*;

    async fn build_instance(
        listeners: Vec<url::Url>,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> (
        Arc<RuntimeCoreInstance>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        let global_ctx = get_mock_global_ctx();
        global_ctx.config.set_listeners(listeners);
        let mut flags = global_ctx.get_flags();
        flags.bind_device = false;
        global_ctx.set_flags(flags);
        let (instance, packet_receiver) =
            build_portable_test_core_instance(global_ctx, ring_registry).unwrap();
        instance.start().await.unwrap();
        (instance, packet_receiver)
    }

    async fn build_client(
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> (
        Arc<RuntimeCoreInstance>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        build_instance(Vec::new(), ring_registry).await
    }

    async fn wait_peer_connection_ready(
        client: Arc<RuntimeCoreInstance>,
        server: Arc<RuntimeCoreInstance>,
    ) {
        let client_peer_id = client.peer_id();
        let server_peer_id = server.peer_id();
        wait_for_condition(
            || {
                let client = client.clone();
                let server = server.clone();
                async move {
                    client.connected_peers().await.contains(&server_peer_id)
                        && server.connected_peers().await.contains(&client_peer_id)
                        && client
                            .route_snapshots()
                            .await
                            .iter()
                            .any(|route| route.peer_id == server_peer_id)
                        && server
                            .route_snapshots()
                            .await
                            .iter()
                            .any(|route| route.peer_id == client_peer_id)
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    async fn wait_connector_connected(manager: &ManualConnectorManager, url: &url::Url) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if manager.list_connectors().await.iter().any(|connector| {
                    connector.url.as_ref().is_some_and(|connector_url| {
                        connector_url.url == url.as_str()
                            && connector.status == ConnectorStatus::Connected as i32
                    })
                }) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("manual connector should become connected");
    }

    async fn peer_snapshot(
        client: &RuntimeCoreInstance,
        peer_id: u32,
    ) -> easytier_core::peers::peer_manager::PeerSnapshot {
        client
            .peer_snapshots()
            .await
            .into_iter()
            .find(|peer| peer.peer_id == peer_id)
            .expect("connected peer snapshot should exist")
    }

    async fn peer_default_conn_id(
        client: &RuntimeCoreInstance,
        peer_id: u32,
    ) -> Option<uuid::Uuid> {
        client
            .peer_snapshots()
            .await
            .into_iter()
            .find(|peer| peer.peer_id == peer_id)
            .and_then(|peer| peer.default_conn_id)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn core_tcp_connector_and_listener_form_peer_connection() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);

        let (server, _server_packets) = build_instance(
            vec!["tcp://127.0.0.1:0".parse().unwrap()],
            Arc::new(RingTunnelRegistry::default()),
        )
        .await;
        let listener_url = server
            .running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "tcp")
            .expect("TCP listener should start");

        let (client, _client_packets) = build_client(Arc::new(RingTunnelRegistry::default())).await;
        let connector_manager = ManualConnectorManager::new_with_core_instance(client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        let server_peer_id = server.peer_id();
        wait_peer_connection_ready(client.clone(), server.clone()).await;
        wait_connector_connected(&connector_manager, &listener_url).await;
        assert!(
            !peer_snapshot(&client, server_peer_id)
                .await
                .directly_connected_conns
                .is_empty()
        );

        let first_conn_id = peer_snapshot(&client, server_peer_id)
            .await
            .default_conn_id
            .unwrap();
        client
            .close_peer_conn(server_peer_id, &first_conn_id)
            .await
            .unwrap();
        wait_for_condition(
            || {
                let client = client.clone();
                async move {
                    peer_default_conn_id(&client, server_peer_id)
                        .await
                        .is_some_and(|conn_id| conn_id != first_conn_id)
                }
            },
            Duration::from_secs(3),
        )
        .await;

        wait_connector_connected(&connector_manager, &listener_url).await;
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
        let (server, _server_packets) = build_instance(Vec::new(), ring_registry.clone()).await;
        let listener_url = server
            .running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "ring")
            .expect("Ring listener should start");

        let (client, _client_packets) = build_client(ring_registry).await;
        let connector_manager = ManualConnectorManager::new_with_core_instance(client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        let server_peer_id = server.peer_id();
        wait_peer_connection_ready(client.clone(), server.clone()).await;
        wait_connector_connected(&connector_manager, &listener_url).await;
        assert!(
            !peer_snapshot(&client, server_peer_id)
                .await
                .directly_connected_conns
                .is_empty()
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

        let (server, _server_packets) = build_instance(
            vec![listener_url.clone()],
            Arc::new(RingTunnelRegistry::default()),
        )
        .await;

        let (client, _client_packets) = build_client(Arc::new(RingTunnelRegistry::default())).await;
        let connector_manager = ManualConnectorManager::new_with_core_instance(client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        let server_peer_id = server.peer_id();
        wait_peer_connection_ready(client.clone(), server.clone()).await;
        wait_connector_connected(&connector_manager, &listener_url).await;
        assert!(
            !peer_snapshot(&client, server_peer_id)
                .await
                .directly_connected_conns
                .is_empty()
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn core_http_discovery_connects_through_resolved_tcp_endpoint() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);

        let (server, _server_packets) = build_instance(
            vec!["tcp://127.0.0.1:0".parse().unwrap()],
            Arc::new(RingTunnelRegistry::default()),
        )
        .await;
        let target_url = server
            .running_listeners()
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

        let (client, _client_packets) = build_client(Arc::new(RingTunnelRegistry::default())).await;
        let connector_manager = ManualConnectorManager::new_with_core_instance(client.clone());
        connector_manager
            .add_connector_by_url(discovery_url.clone())
            .await
            .unwrap();

        let server_peer_id = server.peer_id();
        wait_peer_connection_ready(client.clone(), server.clone()).await;
        wait_connector_connected(&connector_manager, &discovery_url).await;
        assert!(
            !peer_snapshot(&client, server_peer_id)
                .await
                .directly_connected_conns
                .is_empty()
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn core_udp_connector_and_listener_form_peer_connection() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 10);

        let (server, _server_packets) = build_instance(
            vec!["udp://127.0.0.1:0".parse().unwrap()],
            Arc::new(RingTunnelRegistry::default()),
        )
        .await;
        let listener_url = server
            .running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "udp")
            .expect("UDP listener should start");

        let (client, _client_packets) = build_client(Arc::new(RingTunnelRegistry::default())).await;
        let connector_manager = ManualConnectorManager::new_with_core_instance(client.clone());
        connector_manager
            .add_connector_by_url(listener_url.clone())
            .await
            .unwrap();

        let server_peer_id = server.peer_id();
        wait_peer_connection_ready(client.clone(), server.clone()).await;
        wait_connector_connected(&connector_manager, &listener_url).await;
        assert!(
            !peer_snapshot(&client, server_peer_id)
                .await
                .directly_connected_conns
                .is_empty()
        );
        let first_conn_id = peer_snapshot(&client, server_peer_id)
            .await
            .default_conn_id
            .unwrap();
        client
            .close_peer_conn(server_peer_id, &first_conn_id)
            .await
            .unwrap();
        wait_for_condition(
            || {
                let client = client.clone();
                async move {
                    peer_default_conn_id(&client, server_peer_id)
                        .await
                        .is_some_and(|conn_id| conn_id != first_conn_id)
                }
            },
            Duration::from_secs(3),
        )
        .await;

        wait_connector_connected(&connector_manager, &listener_url).await;
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
