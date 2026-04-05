use std::{
    collections::BTreeSet,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use dashmap::DashSet;
use tokio::{sync::mpsc, task::JoinSet, time::timeout};

use crate::{
    common::{dns::socket_addrs, join_joinset_background, PeerId},
    peers::peer_conn::PeerConnId,
    proto::{
        api::instance::{
            Connector, ConnectorManageRpc, ConnectorStatus, ListConnectorRequest,
            ListConnectorResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{matches_scheme, IpVersion, TunnelConnector, TunnelScheme},
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

use super::create_connector_by_url;

type ConnectorMap = Arc<DashSet<url::Url>>;

#[derive(Debug, Clone)]
struct ReconnResult {
    dead_url: String,
    peer_id: PeerId,
    conn_id: PeerConnId,
}

/// Errors that can occur during each stage of a manual reconnect attempt.
///
/// Each variant identifies the stage (resolve / connect / handshake) and
/// whether the failure was a timeout or an inner error, so log consumers
/// can immediately tell where the reconnect got stuck.
#[derive(Debug, thiserror::Error)]
enum ConnectError {
    // Resolve/Connect inner errors use Debug ({0:?}) for richer context.
    #[error("resolve failed: {0:?}")]
    ResolveFailed(Error),
    #[error("resolve timeout after {}", humantime::format_duration(*.0))]
    ResolveTimeout(Duration),
    #[error("connect failed: {0:?}")]
    ConnectFailed(Error),
    #[error("connect timeout after {}", humantime::format_duration(*.0))]
    ConnectTimeout(Duration),
    // Handshake errors (from peer_conn) already have readable Display.
    #[error("handshake failed: {0}")]
    HandshakeFailed(Error),
    #[error("handshake timeout after {}", humantime::format_duration(*.0))]
    HandshakeTimeout(Duration),
    #[error("connect failed: peer manager is gone")]
    PeerManagerGone,
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

pub struct ManualConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<ConnectorManagerData>,
    tasks: JoinSet<()>,
}

impl ManualConnectorManager {
    fn reconnect_timeout(dead_url: &url::Url) -> Duration {
        let use_long_timeout = matches_scheme!(
            dead_url,
            TunnelScheme::Http | TunnelScheme::Https | TunnelScheme::Txt | TunnelScheme::Srv
        ) || matches!(dead_url.scheme(), "ws" | "wss");

        Duration::from_secs(if use_long_timeout { 20 } else { 2 })
    }

    /// Returns the remaining time in the budget, or `None` if exhausted.
    fn remaining_budget(started_at: Instant, total_timeout: Duration) -> Option<Duration> {
        total_timeout.checked_sub(started_at.elapsed())
    }

    fn emit_connect_error(
        data: &ConnectorManagerData,
        dead_url: &url::Url,
        ip_version: IpVersion,
        error: &ConnectError,
    ) {
        data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
            dead_url.to_string(),
            format!("{:?}", ip_version),
            error.to_string(),
        ));
    }

    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let connectors = Arc::new(DashSet::new());
        let tasks = JoinSet::new();

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
            tasks,
        };

        ret.tasks
            .spawn(Self::conn_mgr_reconn_routine(ret.data.clone()));

        ret
    }

    pub fn add_connector<T>(&self, connector: T)
    where
        T: TunnelConnector + 'static,
    {
        tracing::info!("add_connector: {}", connector.remote_url());
        self.data.connectors.insert(connector.remote_url());
    }

    pub async fn add_connector_by_url(&self, url: url::Url) -> Result<(), Error> {
        self.data.connectors.insert(url);
        Ok(())
    }

    pub async fn remove_connector(&self, url: url::Url) -> Result<(), Error> {
        tracing::info!("remove_connector: {}", url);
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
        self.list_connectors().await.iter().for_each(|x| {
            if let Some(url) = &x.url {
                self.data.removed_conn_urls.insert(url.clone().into());
            }
        });
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
                && !pm
                    .get_foreign_network_client()
                    .get_peer_map()
                    .is_client_url_alive(&url)
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
    ) -> Result<ReconnResult, ConnectError> {
        // Stage 1: Resolve — create connector (involves DNS internally)
        let remaining = Self::remaining_budget(started_at, total_timeout)
            .ok_or(ConnectError::ResolveTimeout(started_at.elapsed()))?;
        let connector = match timeout(
            remaining,
            create_connector_by_url(dead_url.as_str(), &data.global_ctx, ip_version),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(ConnectError::ResolveFailed(e)),
            Err(_) => return Err(ConnectError::ResolveTimeout(remaining)),
        };

        data.global_ctx
            .issue_event(GlobalCtxEvent::Connecting(connector.remote_url()));
        tracing::info!("reconnect try connect... conn: {:?}", connector);
        let Some(pm) = data.peer_manager.upgrade() else {
            return Err(ConnectError::PeerManagerGone);
        };

        // Stage 2: Connect — transport-layer connect
        let remaining = Self::remaining_budget(started_at, total_timeout)
            .ok_or(ConnectError::ConnectTimeout(started_at.elapsed()))?;
        let tunnel = match timeout(remaining, pm.connect_tunnel(connector)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return Err(ConnectError::ConnectFailed(e)),
            Err(_) => return Err(ConnectError::ConnectTimeout(remaining)),
        };

        // Stage 3: Handshake — noise handshake + peer registration
        let remaining = Self::remaining_budget(started_at, total_timeout)
            .ok_or(ConnectError::HandshakeTimeout(started_at.elapsed()))?;
        let (peer_id, conn_id) = match timeout(
            remaining,
            pm.add_client_tunnel_with_peer_id_hint(tunnel, true, None),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(ConnectError::HandshakeFailed(e)),
            Err(_) => return Err(ConnectError::HandshakeTimeout(remaining)),
        };

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
    ) -> Result<ReconnResult, ConnectError> {
        tracing::info!("reconnect: {}", dead_url);

        let total_timeout = Self::reconnect_timeout(&dead_url);
        let started_at = Instant::now();

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
                        let error = ConnectError::ResolveFailed(error.into());
                        Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                        return Err(error);
                    }
                };
            let remaining = total_timeout.saturating_sub(started_at.elapsed());
            if remaining.is_zero() {
                let error = ConnectError::ResolveTimeout(started_at.elapsed());
                Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                return Err(error);
            }
            let addrs =
                match timeout(remaining, socket_addrs(&converted_dead_url, || Some(1000))).await {
                    Ok(Ok(addrs)) => addrs,
                    Ok(Err(error)) => {
                        let error = ConnectError::ResolveFailed(error);
                        Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                        return Err(error);
                    }
                    Err(_) => {
                        let error = ConnectError::ResolveTimeout(started_at.elapsed());
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

        let mut reconn_ret = Err(ConnectError::ResolveFailed(Error::AnyhowError(
            anyhow::anyhow!("cannot get ip from url"),
        )));
        for ip_version in ip_versions {
            let ret = Self::conn_reconnect_with_ip_version(
                data.clone(),
                dead_url.clone(),
                ip_version,
                started_at,
                total_timeout,
            )
            .await;
            tracing::info!("reconnect: {} done, ret: {:?}", dead_url, ret);

            match ret {
                Ok(result) => {
                    reconn_ret = Ok(result);
                    break;
                }
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
        peers::tests::create_mock_peer_manager,
        set_global_var,
        tunnel::{Tunnel, TunnelError},
    };

    use super::*;

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
}
