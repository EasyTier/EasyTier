use std::{
    collections::BTreeSet,
    future::Future,
    sync::{Arc, Weak},
    time::Duration,
};

use dashmap::DashSet;
use easytier_core::{
    connectivity::manual::{
        ManualConnectivityEvent, ManualConnectivityEventSink,
        ManualConnectorManager as CoreManualConnectorManager, ManualConnectorOptions,
        ManualConnectorStatus,
    },
    socket::{dns::DnsResolver, tcp::TcpBindOptions, udp::UdpBindOptions},
};
use quanta::Instant;
use tokio::{sync::mpsc, task::JoinSet, time::timeout};

use crate::{
    common::{
        PeerId,
        dns::{RuntimeDnsResolver, socket_addrs},
        join_joinset_background,
    },
    peers::peer_conn::PeerConnId,
    proto::{
        api::instance::{
            Connector, ConnectorManageRpc, ConnectorStatus, ListConnectorRequest,
            ListConnectorResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{IpVersion, TunnelConnector, TunnelScheme, matches_scheme},
    utils::weak_upgrade,
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    peers::peer_manager::PeerManager,
    use_global_var,
};

use super::{
    create_connector_by_url, protocol::RuntimeClientProtocolUpgrader, runtime::RuntimeConnectorHost,
};

type ConnectorMap = Arc<DashSet<url::Url>>;
type CoreConnectorManager = CoreManualConnectorManager<RuntimeConnectorHost>;

#[derive(Debug, Clone)]
struct ReconnResult {
    dead_url: String,
    peer_id: PeerId,
    conn_id: PeerConnId,
}

struct ConnectorManagerData {
    connectors: ConnectorMap,
    reconnecting: DashSet<url::Url>,
    peer_manager: Weak<PeerManager>,
    alive_conn_urls: Arc<DashSet<url::Url>>,
    // user removed connector urls
    removed_conn_urls: Arc<DashSet<url::Url>>,
    net_ns: NetNS,
    global_ctx: ArcGlobalCtx,
}

struct GlobalCtxManualConnectivityEventSink {
    global_ctx: ArcGlobalCtx,
}

impl ManualConnectivityEventSink for GlobalCtxManualConnectivityEventSink {
    fn emit(&self, event: ManualConnectivityEvent) {
        match event {
            ManualConnectivityEvent::Connecting { url } => {
                self.global_ctx.issue_event(GlobalCtxEvent::Connecting(url));
            }
            ManualConnectivityEvent::ConnectError {
                url,
                ip_version,
                error,
            } => {
                self.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                    url.to_string(),
                    format!("{ip_version:?}"),
                    error,
                ));
            }
        }
    }
}

pub struct ManualConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<ConnectorManagerData>,
    core_manager: Arc<CoreConnectorManager>,
    tasks: JoinSet<()>,
}

impl ManualConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        use crate::common::config::ConfigLoader;

        let connectors = Arc::new(DashSet::new());
        let tasks = JoinSet::new();
        let flags = global_ctx.config.get_flags();
        let core_options = ManualConnectorOptions {
            reconnect_interval: Duration::from_millis(use_global_var!(
                MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS
            )),
            connect_timeout: Duration::from_secs(2),
            websocket_connect_timeout: Duration::from_secs(20),
            bind_device: flags.bind_device,
            allow_interface_bind: !cfg!(any(
                target_os = "android",
                target_os = "ios",
                all(target_os = "macos", feature = "macos-ne"),
                target_env = "ohos"
            )),
            tcp_bind: TcpBindOptions::default().with_socket_mark(flags.socket_mark),
            udp_bind: UdpBindOptions::direct_connect().with_socket_mark(flags.socket_mark),
        };
        let core_manager = Arc::new(CoreManualConnectorManager::new_with_events(
            peer_manager.core(),
            Arc::new(RuntimeConnectorHost::new(global_ctx.clone())),
            Arc::new(RuntimeDnsResolver::new()) as Arc<dyn DnsResolver>,
            Arc::new(RuntimeClientProtocolUpgrader::new(global_ctx.clone())),
            core_options,
            Arc::new(GlobalCtxManualConnectivityEventSink {
                global_ctx: global_ctx.clone(),
            }),
        ));

        let mut ret = Self {
            global_ctx: global_ctx.clone(),
            data: Arc::new(ConnectorManagerData {
                connectors,
                reconnecting: DashSet::new(),
                peer_manager: Arc::downgrade(&peer_manager),
                alive_conn_urls: Arc::new(DashSet::new()),
                removed_conn_urls: Arc::new(DashSet::new()),
                net_ns: global_ctx.net_ns.clone(),
                global_ctx,
            }),
            core_manager,
            tasks,
        };

        ret.tasks
            .spawn(Self::conn_mgr_reconn_routine(ret.data.clone()));

        ret
    }

    fn reconnect_timeout(dead_url: &url::Url) -> Duration {
        let use_long_timeout = matches_scheme!(
            dead_url,
            TunnelScheme::Http | TunnelScheme::Https | TunnelScheme::Txt | TunnelScheme::Srv
        ) || matches!(dead_url.scheme(), "ws" | "wss");

        Duration::from_secs(if use_long_timeout { 20 } else { 2 })
    }

    fn remaining_budget(started_at: Instant, total_timeout: Duration) -> Option<Duration> {
        let remaining = total_timeout.checked_sub(started_at.elapsed())?;
        (!remaining.is_zero()).then_some(remaining)
    }

    fn emit_connect_error(
        data: &ConnectorManagerData,
        dead_url: &url::Url,
        ip_version: IpVersion,
        error: &Error,
    ) {
        data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
            dead_url.to_string(),
            format!("{:?}", ip_version),
            format!("{:#?}", error),
        ));
    }

    fn reconnect_timeout_error(stage: &str, duration: Duration) -> Error {
        Error::AnyhowError(anyhow::anyhow!("{} timeout after {:?}", stage, duration))
    }

    async fn with_reconnect_timeout<T, F>(
        stage: &'static str,
        started_at: Instant,
        total_timeout: Duration,
        fut: F,
    ) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        let remaining = Self::remaining_budget(started_at, total_timeout)
            .ok_or_else(|| Self::reconnect_timeout_error(stage, started_at.elapsed()))?;
        timeout(remaining, fut)
            .await
            .map_err(|_| Self::reconnect_timeout_error(stage, remaining))?
    }
}

impl ManualConnectorManager {
    fn core_owns_scheme(url: &url::Url) -> bool {
        match url.scheme() {
            "tcp" | "udp" => true,
            "ws" | "wss" => cfg!(feature = "websocket"),
            "wg" => cfg!(feature = "wireguard"),
            "quic" => cfg!(feature = "quic"),
            "faketcp" => cfg!(feature = "faketcp"),
            _ => false,
        }
    }

    pub fn add_connector<T>(&self, connector: T)
    where
        T: TunnelConnector + 'static,
    {
        let url = connector.remote_url();
        tracing::info!("add_connector: {}", url);
        if Self::core_owns_scheme(&url) {
            self.core_manager
                .add_connector(url)
                .expect("core manual connector URL should be valid");
        } else {
            self.data.connectors.insert(url);
        }
    }

    pub async fn add_connector_by_url(&self, url: url::Url) -> Result<(), Error> {
        if Self::core_owns_scheme(&url) {
            self.core_manager.add_connector(url)?;
            return Ok(());
        }
        self.data.connectors.insert(url);
        Ok(())
    }

    pub async fn remove_connector(&self, url: url::Url) -> Result<(), Error> {
        tracing::info!("remove_connector: {}", url);
        if Self::core_owns_scheme(&url) && self.core_manager.remove_connector(&url) {
            return Ok(());
        }
        let url = url.into();
        if !self
            .list_connectors()
            .await
            .iter()
            .any(|x| x.url.as_ref() == Some(&url))
        {
            return Err(Error::NotFound);
        }
        self.data.removed_conn_urls.insert(url.into());
        Ok(())
    }

    pub async fn clear_connectors(&self) {
        self.core_manager.clear_connectors();
        for url in self.data.connectors.iter() {
            self.data.removed_conn_urls.insert(url.key().clone());
        }
        for url in self.data.reconnecting.iter() {
            self.data.removed_conn_urls.insert(url.key().clone());
        }
    }

    pub async fn list_connectors(&self) -> Vec<Connector> {
        let dead_urls: BTreeSet<url::Url> = Self::collect_dead_conns(self.data.clone())
            .await
            .into_iter()
            .collect();

        let mut ret = Vec::new();

        for item in self.data.connectors.iter() {
            let conn_url = item.key().clone();
            let mut status = ConnectorStatus::Connected;
            if dead_urls.contains(&conn_url) {
                status = ConnectorStatus::Disconnected;
            }
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: status.into(),
                },
            );
        }

        let reconnecting_urls: BTreeSet<url::Url> =
            self.data.reconnecting.iter().map(|x| x.clone()).collect();

        for conn_url in reconnecting_urls {
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: ConnectorStatus::Connecting.into(),
                },
            );
        }

        for connector in self.core_manager.list_connectors() {
            let status = match connector.status {
                ManualConnectorStatus::Connected => ConnectorStatus::Connected,
                ManualConnectorStatus::Disconnected => ConnectorStatus::Disconnected,
                ManualConnectorStatus::Connecting => ConnectorStatus::Connecting,
            };
            ret.insert(
                0,
                Connector {
                    url: Some(connector.url.into()),
                    status: status.into(),
                },
            );
        }

        ret
    }

    async fn conn_mgr_reconn_routine(data: Arc<ConnectorManagerData>) {
        tracing::warn!("conn_mgr_routine started");
        let mut reconn_interval = tokio::time::interval(std::time::Duration::from_millis(
            use_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS),
        ));
        let (reconn_result_send, mut reconn_result_recv) = mpsc::channel(100);
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "connector_reconnect_tasks".to_string());

        loop {
            tokio::select! {
                _ = reconn_interval.tick() => {
                    let dead_urls = Self::collect_dead_conns(data.clone()).await;
                    if dead_urls.is_empty() {
                        continue;
                    }
                    for dead_url in dead_urls {
                        let data_clone = data.clone();
                        let sender = reconn_result_send.clone();
                        data.connectors.remove(&dead_url).unwrap();
                        let insert_succ = data.reconnecting.insert(dead_url.clone());
                        assert!(insert_succ);

                        tasks.lock().unwrap().spawn(async move {
                            let reconn_ret = Self::conn_reconnect(data_clone.clone(), dead_url.clone() ).await;
                            let _ = sender.send(reconn_ret).await;

                            data_clone.reconnecting.remove(&dead_url).unwrap();
                            data_clone.connectors.insert(dead_url.clone());
                        });
                    }
                    tracing::info!("reconn_interval tick, done");
                }

                ret = reconn_result_recv.recv() => {
                    tracing::warn!("reconn_tasks done, reconn result: {:?}", ret);
                }
            }
        }
    }

    fn handle_remove_connector(data: Arc<ConnectorManagerData>) {
        let remove_later = DashSet::new();
        for it in data.removed_conn_urls.iter() {
            let url = it.key();
            if data.connectors.remove(url).is_some() {
                tracing::warn!("connector: {}, removed", url);
                continue;
            } else if data.reconnecting.contains(url) {
                tracing::warn!("connector: {}, reconnecting, remove later.", url);
                remove_later.insert(url.clone());
                continue;
            } else {
                tracing::warn!("connector: {}, not found", url);
            }
        }
        data.removed_conn_urls.clear();
        for it in remove_later.iter() {
            data.removed_conn_urls.insert(it.key().clone());
        }
    }

    async fn collect_dead_conns(data: Arc<ConnectorManagerData>) -> BTreeSet<url::Url> {
        Self::handle_remove_connector(data.clone());
        let mut ret = BTreeSet::new();
        let Some(pm) = data.peer_manager.upgrade() else {
            tracing::warn!("peer manager is gone, exit");
            return ret;
        };
        for url in data.connectors.iter().map(|x| x.key().clone()) {
            if !pm.get_peer_map().is_client_url_alive(&url)
                && !pm.get_foreign_network_client().is_client_url_alive(&url)
            {
                ret.insert(url.clone());
            }
        }
        ret
    }

    async fn conn_reconnect_with_ip_version(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
        ip_version: IpVersion,
        started_at: Instant,
        total_timeout: Duration,
    ) -> Result<ReconnResult, Error> {
        let connector = Self::with_reconnect_timeout(
            "resolve",
            started_at,
            total_timeout,
            create_connector_by_url(dead_url.as_str(), &data.global_ctx, ip_version),
        )
        .await?;

        data.global_ctx
            .issue_event(GlobalCtxEvent::Connecting(connector.remote_url()));
        tracing::info!("reconnect try connect... conn: {:?}", connector);
        let Some(pm) = data.peer_manager.upgrade() else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "peer manager is gone, cannot reconnect"
            )));
        };

        let tunnel = Self::with_reconnect_timeout(
            "connect",
            started_at,
            total_timeout,
            pm.connect_tunnel(connector),
        )
        .await?;

        let (peer_id, conn_id) = Self::with_reconnect_timeout(
            "handshake",
            started_at,
            total_timeout,
            pm.add_client_tunnel_with_peer_id_hint(tunnel, true, None),
        )
        .await?;

        tracing::info!("reconnect succ: {} {} {}", peer_id, conn_id, dead_url);
        Ok(ReconnResult {
            dead_url: dead_url.to_string(),
            peer_id,
            conn_id,
        })
    }

    async fn conn_reconnect(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
    ) -> Result<ReconnResult, Error> {
        tracing::info!("reconnect: {}", dead_url);

        let mut ip_versions = vec![];
        if matches_scheme!(
            dead_url,
            TunnelScheme::Ring | TunnelScheme::Txt | TunnelScheme::Srv
        ) {
            ip_versions.push(IpVersion::Both);
        } else {
            let converted_dead_url =
                match crate::common::idn::convert_idn_to_ascii(dead_url.clone()) {
                    Ok(url) => url,
                    Err(error) => {
                        let error: Error = error.into();
                        Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                        return Err(error);
                    }
                };
            let addrs = match Self::with_reconnect_timeout(
                "resolve",
                Instant::now(),
                Self::reconnect_timeout(&dead_url),
                socket_addrs(&converted_dead_url, || Some(1000)),
            )
            .await
            {
                Ok(addrs) => addrs,
                Err(error) => {
                    Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                    return Err(error);
                }
            };
            tracing::info!(?addrs, ?dead_url, "get ip from url done");
            let mut has_ipv4 = false;
            let mut has_ipv6 = false;
            for addr in addrs {
                if addr.is_ipv4() {
                    if !has_ipv4 {
                        ip_versions.insert(0, IpVersion::V4);
                    }
                    has_ipv4 = true;
                } else if addr.is_ipv6() {
                    if !has_ipv6 {
                        ip_versions.push(IpVersion::V6);
                    }
                    has_ipv6 = true;
                }
            }
        }

        let mut reconn_ret = Err(Error::AnyhowError(anyhow::anyhow!(
            "cannot get ip from url"
        )));
        for ip_version in ip_versions {
            let started_at = Instant::now();
            let ret = Self::conn_reconnect_with_ip_version(
                data.clone(),
                dead_url.clone(),
                ip_version,
                started_at,
                Self::reconnect_timeout(&dead_url),
            )
            .await;
            tracing::info!("reconnect: {} done, ret: {:?}", dead_url, ret);

            match ret {
                Ok(result) => return Ok(result),
                Err(error) => {
                    Self::emit_connect_error(&data, &dead_url, ip_version, &error);
                    reconn_ret = Err(error);
                }
            }
        }

        reconn_ret
    }
}

#[derive(Clone)]
pub struct ConnectorManagerRpcService(pub Weak<ManualConnectorManager>);

#[async_trait::async_trait]
impl ConnectorManageRpc for ConnectorManagerRpcService {
    type Controller = BaseController;

    async fn list_connector(
        &self,
        _: BaseController,
        _request: ListConnectorRequest,
    ) -> Result<ListConnectorResponse, rpc_types::error::Error> {
        let mut ret = ListConnectorResponse::default();
        let connectors = weak_upgrade(&self.0)?.list_connectors().await;
        ret.connectors = connectors;
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        common::config::ConfigLoader,
        instance::listeners::ListenerManager,
        peers::tests::{create_mock_peer_manager, wait_route_appear},
        set_global_var,
        tunnel::{Tunnel, TunnelError, common::tests::wait_for_condition},
    };

    use super::*;

    #[test]
    fn core_owns_enabled_ip_protocols_only() {
        assert!(ManualConnectorManager::core_owns_scheme(
            &"tcp://127.0.0.1".parse().unwrap()
        ));
        assert!(ManualConnectorManager::core_owns_scheme(
            &"udp://127.0.0.1".parse().unwrap()
        ));
        for (url, enabled) in [
            ("ws://127.0.0.1", cfg!(feature = "websocket")),
            ("wss://127.0.0.1", cfg!(feature = "websocket")),
            ("wg://127.0.0.1", cfg!(feature = "wireguard")),
            ("quic://127.0.0.1", cfg!(feature = "quic")),
            ("faketcp://127.0.0.1", cfg!(feature = "faketcp")),
        ] {
            assert_eq!(
                ManualConnectorManager::core_owns_scheme(&url.parse().unwrap()),
                enabled,
                "unexpected core ownership for {url}"
            );
        }
        assert!(!ManualConnectorManager::core_owns_scheme(
            &"http://127.0.0.1".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn reconnect_timeout_reports_exhausted_budget_for_stage() {
        let started_at = Instant::now() - Duration::from_millis(50);
        let err = ManualConnectorManager::with_reconnect_timeout(
            "resolve",
            started_at,
            Duration::from_millis(1),
            async { Ok::<(), Error>(()) },
        )
        .await
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("resolve timeout after"));
    }

    #[tokio::test]
    async fn reconnect_timeout_reports_stage_timeout_with_remaining_budget() {
        let err = ManualConnectorManager::with_reconnect_timeout(
            "handshake",
            Instant::now(),
            Duration::from_millis(10),
            async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<(), Error>(())
            },
        )
        .await
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("handshake timeout after"));
    }

    #[tokio::test]
    async fn reconnect_timeout_preserves_success_within_budget() {
        let result = ManualConnectorManager::with_reconnect_timeout(
            "connect",
            Instant::now(),
            Duration::from_millis(50),
            async { Ok::<_, Error>(123_u32) },
        )
        .await
        .unwrap();

        assert_eq!(result, 123);
    }

    #[tokio::test]
    async fn test_reconnect_with_connecting_addr() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 1);

        let peer_mgr = create_mock_peer_manager().await;
        let mgr = ManualConnectorManager::new(peer_mgr.get_global_ctx(), peer_mgr);

        struct MockConnector {}
        #[async_trait::async_trait]
        impl TunnelConnector for MockConnector {
            fn remote_url(&self) -> url::Url {
                url::Url::parse("tcp://aa.com").unwrap()
            }
            async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Err(TunnelError::InvalidPacket("fake error".into()))
            }
        }

        mgr.add_connector(MockConnector {});

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

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
        assert!(client.get_peer_map().is_client_url_alive(&listener_url));
        assert!(client.has_directly_connected_conn(server.my_peer_id()));

        let server_peer_id = server.my_peer_id();
        let first_conn_id = client
            .get_peer_map()
            .get_peer_default_conn_id(server_peer_id)
            .await
            .unwrap();
        client
            .close_peer_conn(server_peer_id, &first_conn_id)
            .await
            .unwrap();
        wait_for_condition(
            || {
                let client = client.clone();
                async move {
                    client
                        .get_peer_map()
                        .get_peer_default_conn_id(server_peer_id)
                        .await
                        .is_some_and(|conn_id| conn_id != first_conn_id)
                }
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(client.get_peer_map().is_client_url_alive(&listener_url));

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
        assert!(client.get_peer_map().is_client_url_alive(&listener_url));
        assert!(client.has_directly_connected_conn(server.my_peer_id()));

        let server_peer_id = server.my_peer_id();
        let first_conn_id = client
            .get_peer_map()
            .get_peer_default_conn_id(server_peer_id)
            .await
            .unwrap();
        client
            .close_peer_conn(server_peer_id, &first_conn_id)
            .await
            .unwrap();
        wait_for_condition(
            || {
                let client = client.clone();
                async move {
                    client
                        .get_peer_map()
                        .get_peer_default_conn_id(server_peer_id)
                        .await
                        .is_some_and(|conn_id| conn_id != first_conn_id)
                }
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(client.get_peer_map().is_client_url_alive(&listener_url));

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
