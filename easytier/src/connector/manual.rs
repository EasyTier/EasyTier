use std::{
    collections::BTreeSet,
    sync::{Arc, Weak},
};

use anyhow::Context;
use dashmap::DashSet;
use tokio::{
    sync::{
        broadcast::{error::RecvError, Receiver},
        mpsc,
    },
    task::JoinSet,
    time::timeout,
};

use crate::{
    common::{dns::socket_addrs, join_joinset_background, PeerId},
    peers::peer_conn::PeerConnId,
    proto::{
        cli::{
            ConnectorManageAction, ListConnectorResponse, ManageConnectorResponse, PeerConnInfo,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{IpVersion, TunnelConnector},
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    peers::peer_manager::PeerManager,
    proto::cli::{
        Connector, ConnectorManageRpc, ConnectorStatus, ListConnectorRequest,
        ManageConnectorRequest,
    },
    use_global_var,
};

use super::create_connector_by_url;

type ConnectorMap = Arc<DashSet<String>>;

#[derive(Debug, Clone)]
struct ReconnResult {
    dead_url: String,
    peer_id: PeerId,
    conn_id: PeerConnId,
}

struct ConnectorManagerData {
    connectors: ConnectorMap,
    reconnecting: DashSet<String>,
    peer_manager: Weak<PeerManager>,
    alive_conn_urls: Arc<DashSet<String>>,
    // user removed connector urls
    removed_conn_urls: Arc<DashSet<String>>,
    net_ns: NetNS,
    global_ctx: ArcGlobalCtx,
}

pub struct ManualConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<ConnectorManagerData>,
    tasks: JoinSet<()>,
}

impl ManualConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let connectors = Arc::new(DashSet::new());
        let tasks = JoinSet::new();
        let event_subscriber = global_ctx.subscribe();

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
        ret.tasks.spawn(Self::conn_mgr_handle_event_routine(
            ret.data.clone(),
            event_subscriber,
        ));

        ret
    }

    pub fn add_connector<T>(&self, connector: T)
    where
        T: TunnelConnector + 'static,
    {
        tracing::info!("add_connector: {}", connector.remote_url());
        self.data.connectors.insert(connector.remote_url().into());
    }

    pub async fn add_connector_by_url(&self, url: &str) -> Result<(), Error> {
        self.data.connectors.insert(url.to_owned());
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
        self.data.removed_conn_urls.insert(url.to_string());
        Ok(())
    }

    pub async fn list_connectors(&self) -> Vec<Connector> {
        let conn_urls: BTreeSet<String> = self
            .data
            .connectors
            .iter()
            .map(|x| x.key().clone())
            .collect();

        let dead_urls: BTreeSet<String> = Self::collect_dead_conns(self.data.clone())
            .await
            .into_iter()
            .collect();

        let mut ret = Vec::new();

        for conn_url in conn_urls {
            let mut status = ConnectorStatus::Connected;
            if dead_urls.contains(&conn_url) {
                status = ConnectorStatus::Disconnected;
            }
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.parse().unwrap()),
                    status: status.into(),
                },
            );
        }

        let reconnecting_urls: BTreeSet<String> =
            self.data.reconnecting.iter().map(|x| x.clone()).collect();

        for conn_url in reconnecting_urls {
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.parse().unwrap()),
                    status: ConnectorStatus::Connecting.into(),
                },
            );
        }

        ret
    }

    async fn conn_mgr_handle_event_routine(
        data: Arc<ConnectorManagerData>,
        mut event_recv: Receiver<GlobalCtxEvent>,
    ) {
        loop {
            match event_recv.recv().await {
                Ok(event) => {
                    Self::handle_event(&event, &data).await;
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("event_recv lagged: {}, rebuild alive conn list", n);
                    event_recv = event_recv.resubscribe();
                    data.alive_conn_urls.clear();
                    let Some(pm) = data.peer_manager.upgrade() else {
                        tracing::warn!("peer manager is gone, exit");
                        break;
                    };
                    for x in pm.get_peer_map().get_alive_conns().iter().map(|x| {
                        x.tunnel
                            .clone()
                            .unwrap_or_default()
                            .remote_addr
                            .unwrap_or_default()
                            .to_string()
                    }) {
                        data.alive_conn_urls.insert(x);
                    }
                    continue;
                }
                Err(RecvError::Closed) => {
                    tracing::warn!("event_recv closed, exit");
                    break;
                }
            }
        }
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

    async fn handle_event(event: &GlobalCtxEvent, data: &ConnectorManagerData) {
        let need_add_alive = |conn_info: &PeerConnInfo| conn_info.is_client;
        match event {
            GlobalCtxEvent::PeerConnAdded(conn_info) => {
                if !need_add_alive(conn_info) {
                    return;
                }
                let addr = conn_info.tunnel.as_ref().unwrap().remote_addr.clone();
                data.alive_conn_urls.insert(addr.unwrap().to_string());
                tracing::warn!("peer conn added: {:?}", conn_info);
            }

            GlobalCtxEvent::PeerConnRemoved(conn_info) => {
                if !need_add_alive(conn_info) {
                    return;
                }
                let addr = conn_info.tunnel.as_ref().unwrap().remote_addr.clone();
                data.alive_conn_urls.remove(&addr.unwrap().to_string());
                tracing::warn!("peer conn removed: {:?}", conn_info);
            }

            _ => {}
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

    async fn collect_dead_conns(data: Arc<ConnectorManagerData>) -> BTreeSet<String> {
        Self::handle_remove_connector(data.clone());
        let all_urls: BTreeSet<String> = data.connectors.iter().map(|x| x.key().clone()).collect();
        let mut ret = BTreeSet::new();
        for url in all_urls.iter() {
            if !data.alive_conn_urls.contains(url) {
                ret.insert(url.clone());
            }
        }
        ret
    }

    async fn conn_reconnect_with_ip_version(
        data: Arc<ConnectorManagerData>,
        dead_url: String,
        ip_version: IpVersion,
    ) -> Result<ReconnResult, Error> {
        let connector =
            create_connector_by_url(&dead_url, &data.global_ctx.clone(), ip_version).await?;

        data.global_ctx
            .issue_event(GlobalCtxEvent::Connecting(connector.remote_url().clone()));
        tracing::info!("reconnect try connect... conn: {:?}", connector);
        let Some(pm) = data.peer_manager.upgrade() else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "peer manager is gone, cannot reconnect"
            )));
        };

        let (peer_id, conn_id) = pm.try_direct_connect(connector).await?;
        tracing::info!("reconnect succ: {} {} {}", peer_id, conn_id, dead_url);
        Ok(ReconnResult {
            dead_url,
            peer_id,
            conn_id,
        })
    }

    async fn conn_reconnect(
        data: Arc<ConnectorManagerData>,
        dead_url: String,
    ) -> Result<ReconnResult, Error> {
        tracing::info!("reconnect: {}", dead_url);

        let mut ip_versions = vec![];
        let u = url::Url::parse(&dead_url)
            .with_context(|| format!("failed to parse connector url {:?}", dead_url))?;
        if u.scheme() == "ring" || u.scheme() == "txt" || u.scheme() == "srv" {
            ip_versions.push(IpVersion::Both);
        } else {
            let addrs = match socket_addrs(&u, || Some(1000)).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                        dead_url.clone(),
                        format!("{:?}", IpVersion::Both),
                        format!("{:?}", e),
                    ));
                    return Err(Error::AnyhowError(anyhow::anyhow!(
                        "get ip from url failed: {:?}",
                        e
                    )));
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
            let use_long_timeout = dead_url.starts_with("http")
                || dead_url.starts_with("srv")
                || dead_url.starts_with("txt");
            let ret = timeout(
                // allow http connector to wait longer
                std::time::Duration::from_secs(if use_long_timeout { 20 } else { 2 }),
                Self::conn_reconnect_with_ip_version(data.clone(), dead_url.clone(), ip_version),
            )
            .await;
            tracing::info!("reconnect: {} done, ret: {:?}", dead_url, ret);

            match ret {
                Ok(Ok(_)) => {
                    // 外层和内层都成功：解包并跳出
                    reconn_ret = ret.unwrap();
                    break;
                }
                Ok(Err(e)) => {
                    // 外层成功，内层失败
                    reconn_ret = Err(e);
                }
                Err(e) => {
                    // 外层失败
                    reconn_ret = Err(e.into());
                }
            }

            // 发送事件（只有在未 break 时才执行）
            data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                dead_url.clone(),
                format!("{:?}", ip_version),
                format!("{:?}", reconn_ret),
            ));
        }

        reconn_ret
    }
}

#[derive(Clone)]
pub struct ConnectorManagerRpcService(pub Arc<ManualConnectorManager>);

#[async_trait::async_trait]
impl ConnectorManageRpc for ConnectorManagerRpcService {
    type Controller = BaseController;

    async fn list_connector(
        &self,
        _: BaseController,
        _request: ListConnectorRequest,
    ) -> Result<ListConnectorResponse, rpc_types::error::Error> {
        let mut ret = ListConnectorResponse::default();
        let connectors = self.0.list_connectors().await;
        ret.connectors = connectors;
        Ok(ret)
    }

    async fn manage_connector(
        &self,
        _: BaseController,
        req: ManageConnectorRequest,
    ) -> Result<ManageConnectorResponse, rpc_types::error::Error> {
        let url: url::Url = req.url.ok_or(anyhow::anyhow!("url is empty"))?.into();
        if req.action == ConnectorManageAction::Remove as i32 {
            self.0
                .remove_connector(url.clone())
                .await
                .with_context(|| format!("remove connector failed: {:?}", url))?;
            return Ok(ManageConnectorResponse::default());
        } else {
            self.0
                .add_connector_by_url(url.as_str())
                .await
                .with_context(|| format!("add connector failed: {:?}", url))?;
        }
        Ok(ManageConnectorResponse::default())
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
