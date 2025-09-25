use std::{
    collections::BTreeSet,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use anyhow::Context;
use dashmap::{DashMap, DashSet};
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

impl ReconnResult {
    // 检查结果是否表示远程服务器更新（而不是实际的重连结果）
    fn is_remote_server_update(&self) -> bool {
        self.peer_id == 0 && self.conn_id == uuid::Uuid::nil()
    }

    // 创建一个表示远程服务器更新的结果
    fn remote_server_update(dead_url: String) -> Self {
        Self {
            dead_url,
            peer_id: 0,
            conn_id: uuid::Uuid::nil(),
        }
    }
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
    // 用于存储远程服务器URL的映射，key为remote_server_url，value为原始dead_url
    remote_server_urls: Arc<DashMap<String, String>>,
    // 记录上次更新远程服务器配置的时间
    last_remote_update: Arc<DashMap<String, Instant>>,
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
                remote_server_urls: Arc::new(DashMap::new()),
                last_remote_update: Arc::new(DashMap::new()),
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

    // 添加一个新的方法，用于注册远程服务器URL
    pub async fn add_remote_server_url(
        &self,
        remote_server_url: String,
        dead_url: String,
    ) -> Result<(), Error> {
        self.data
            .remote_server_urls
            .insert(remote_server_url.clone(), dead_url);
        // 初始化更新时间
        self.data
            .last_remote_update
            .insert(remote_server_url, Instant::now());
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
                    // 检查是否有远程服务器需要更新配置
                    Self::check_and_update_remote_servers(&data).await;

                    let dead_urls = Self::collect_dead_conns(data.clone()).await;
                    if dead_urls.is_empty() {
                        continue;
                    }
                    for dead_url in dead_urls {
                        // 再次检查这个dead_url是否仍然存在于connectors中
                        // 如果是远程服务器更新导致的dead_url，可能已经不存在了
                        if !data.connectors.contains(&dead_url) {
                            tracing::info!("Skipping reconnect for removed peer: {}", dead_url);
                            continue;
                        }

                        // 检查这个dead_url是否是远程服务器URL，如果是则跳过重连
                        let is_remote_server_url = data.remote_server_urls.iter().any(|entry| {
                            *entry.value() == dead_url
                        });

                        if is_remote_server_url {
                            tracing::info!("Skipping reconnect for remote server URL: {}", dead_url);
                            continue;
                        }
                        
                        let data_clone = data.clone();
                        let sender = reconn_result_send.clone();
                        data.connectors.remove(&dead_url);
                        let insert_succ = data.reconnecting.insert(dead_url.clone());
                        assert!(insert_succ);

                        tasks.lock().unwrap().spawn(async move {
                            let reconn_ret = Self::conn_reconnect(data_clone.clone(), dead_url.clone() ).await;
                            let is_remote_update = if let Ok(ref result) = reconn_ret {
                                result.is_remote_server_update()
                            } else {
                                false
                            };
                            let is_ok = reconn_ret.is_ok();
                            let _ = sender.send(reconn_ret).await;

                            if is_remote_update {
                                // 远程服务器更新，不需要重新插入URL
                                data_clone.reconnecting.remove(&dead_url);
                                tracing::info!("Remote server URL updated, not re-adding to connectors: {}", dead_url);
                            } else {
                                // 普通重连或重连失败，需要清理状态
                                data_clone.reconnecting.remove(&dead_url);
                                if is_ok {
                                    // 重连成功，不需要重新插入URL
                                    tracing::info!("Peer reconnected successfully, not re-adding to connectors: {}", dead_url);
                                } else {
                                    // 重连失败，重新插入URL以便稍后重试
                                    data_clone.connectors.insert(dead_url.clone());
                                    tracing::info!("Peer reconnection failed, re-adding to connectors for retry: {}", dead_url);
                                }
                            }
                        });
                    }
                    tracing::info!("reconn_interval tick, done");
                }

                ret = reconn_result_recv.recv() => {
                    if let Some(result) = ret {
                        match result {
                            Ok(reconn_result) => {
                                let is_remote_update = reconn_result.is_remote_server_update();
                                // 检查是否是特殊的远程服务器更新结果
                                if is_remote_update {
                                    tracing::info!("reconn_tasks done, remote server URL updated successfully");
                                } else {
                                    tracing::info!("reconn_tasks done, reconn result: Ok({:?})", reconn_result);
                                }
                            }
                            Err(e) => {
                                tracing::warn!("reconn_tasks done, reconn result: Err({:?})", e);
                            }
                        }
                    }
                }
            }
        }
    }

    // 检查并更新远程服务器配置
    async fn check_and_update_remote_servers(data: &Arc<ConnectorManagerData>) {
        let mut to_update = Vec::new();

        // 检查所有远程服务器URL是否需要更新（例如每5分钟检查一次）
        for entry in data.remote_server_urls.iter() {
            let remote_server_url = entry.key();
            let dead_url = entry.value();

            // 检查是否需要更新（例如超过5分钟未更新）
            let should_update = if let Some(last_update) = data.last_remote_update.get(remote_server_url) {
                last_update.elapsed() > Duration::from_secs(300) // 5分钟
            } else {
                true
            };

            if should_update {
                to_update.push((remote_server_url.clone(), dead_url.clone()));
            }
        }

        // 更新需要更新的远程服务器配置
        for (remote_server_url, dead_url) in to_update {
            tracing::info!("Checking for updates from remote server: {}", remote_server_url);

            match Self::fetch_peers_from_remote_server(&remote_server_url).await {
                Ok(new_peer_urls) => {
                    tracing::info!("Successfully fetched {} peers from remote server", new_peer_urls.len());

                    // 更新时间戳
                    data.last_remote_update.insert(remote_server_url.clone(), Instant::now());

                    // 检查是否有变化
                    let current_peers: BTreeSet<String> = data.connectors.iter()
                        .map(|x| x.key().clone())
                        .filter(|url| url.starts_with(&dead_url)) // 只检查与当前dead_url相关的peers
                        .collect();

                    let new_peers: BTreeSet<String> = new_peer_urls.iter().cloned().collect();

                    if current_peers != new_peers {
                        tracing::info!("Remote server peers configuration changed, updating...");

                        // 移除旧的peers（与dead_url相关的）
                        let to_remove: Vec<String> = data.connectors.iter()
                            .map(|x| x.key().clone())
                            .filter(|url| url.starts_with(&dead_url))
                            .collect();

                        for url in to_remove {
                            data.connectors.remove(&url);
                            // 同时清理相关的alive_conn_urls和reconnecting状态
                            data.alive_conn_urls.remove(&url);
                            data.reconnecting.remove(&url);
                        }

                        // 清理dead_url本身的状态（这可能是一个标记URL，不是实际的peer）
                        data.alive_conn_urls.remove(&dead_url);
                        data.reconnecting.remove(&dead_url);

                        // 添加新的peers
                        for peer_url in &new_peers {
                            data.connectors.insert(peer_url.clone());
                            // 确保新添加的peers没有在alive_conn_urls或reconnecting中被标记为dead
                            data.alive_conn_urls.remove(peer_url);
                            data.reconnecting.remove(peer_url);
                            tracing::info!("Added new peer from remote server: {}", peer_url);
                        }

                        tracing::info!("Updated peers from remote server. Old: {:?}, New: {:?}", current_peers, new_peers);

                        // 强制触发一次重连检查，确保新配置生效
                        data.global_ctx.issue_event(GlobalCtxEvent::Connecting(url::Url::parse(&dead_url).unwrap_or_else(|_| "invalid://url".parse().unwrap())));
                    } else {
                        tracing::info!("No changes in remote server peers configuration");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch peers from remote server {}: {:?}", remote_server_url, e);
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
            // 不要将远程服务器URL标记为dead
            let is_remote_server_url = data.remote_server_urls.iter().any(|entry| {
                *entry.value() == *url
            });

            if is_remote_server_url {
                continue;
            }

            if !data.alive_conn_urls.contains(url) {
                ret.insert(url.clone());
            }
        }
        ret
    }

    // 从远程服务器获取新的peers配置
    async fn fetch_peers_from_remote_server(remote_server_url: &str) -> Result<Vec<String>, Error> {
        // 解析URL，格式为 method:url
        let parts: Vec<&str> = remote_server_url.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "Invalid remote server url format: {}, expected format: method:url", 
                remote_server_url
            )));
        }

        let method = parts[0].to_uppercase(); // 转换为大写，确保方法名正确
        let url = parts[1];
        
        // 发起HTTP请求获取peers列表
        let client = reqwest::Client::new();
        let request_builder = client.request(
            method.parse().map_err(|_| Error::AnyhowError(anyhow::anyhow!(
                "Invalid HTTP method: {}", method
            )))?,
            url,
        );

        let response = request_builder
            .send()
            .await
            .map_err(|e| Error::AnyhowError(anyhow::anyhow!(
                "Failed to request remote server {}: {}",
                remote_server_url,
                e
            )))?;

        let status = response.status();
        let resp_text = response
            .text()
            .await
            .map_err(|e| Error::AnyhowError(anyhow::anyhow!(
                "Failed to read response from remote server {}: {}",
                remote_server_url,
                e
            )))?;

        // 检查HTTP状态码
        if !status.is_success() {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "Remote server returned non-success status {}: {}",
                status,
                resp_text
            )));
        }

        tracing::debug!("Remote server response: {}", resp_text);

        // 尝试解析JSON响应
        // 首先尝试解析为PeerConfig数组
        if let Ok(peers) = serde_json::from_str::<Vec<crate::common::config::PeerConfig>>(&resp_text) {
            let peer_urls: Vec<String> = peers.into_iter().map(|p| p.uri.to_string()).collect();
            return Ok(peer_urls);
        }

        // 如果失败，尝试解析为字符串数组（URL列表）
        if let Ok(urls) = serde_json::from_str::<Vec<String>>(&resp_text) {
            // 验证每个URL是否有效
            for url_str in &urls {
                url::Url::parse(url_str).map_err(|e| Error::AnyhowError(anyhow::anyhow!(
                    "Invalid URL in peer list: {}: {}", url_str, e
                )))?;
            }
            return Ok(urls);
        }

        // 如果还失败，尝试解析为单个字符串（单个URL）
        if let Ok(url_str) = serde_json::from_str::<String>(&resp_text) {
            url::Url::parse(&url_str).map_err(|e| Error::AnyhowError(anyhow::anyhow!(
                "Invalid URL: {}: {}", url_str, e
            )))?;
            return Ok(vec![url_str]);
        }

        // 所有解析都失败了
        Err(Error::AnyhowError(anyhow::anyhow!(
            "Failed to parse peer list from remote server {}. Response: {}", 
            remote_server_url, 
            resp_text
        )))
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

        // 检查是否是远程服务器URL，如果是则从远程服务器获取新的peers
        if let Some(remote_server_url) = data.remote_server_urls.get(&dead_url) {
            tracing::info!("Fetching new peers from remote server: {}", remote_server_url.value());
            match Self::fetch_peers_from_remote_server(remote_server_url.value()).await {
                Ok(peer_urls) => {
                    tracing::info!("Successfully fetched {} peers from remote server", peer_urls.len());

                    // 移除旧的连接器
                    data.connectors.remove(&dead_url);
                    // 同时清理相关的alive_conn_urls和reconnecting状态
                    data.alive_conn_urls.remove(&dead_url);
                    data.reconnecting.remove(&dead_url);

                    // 添加新的peers
                    for peer_url in peer_urls {
                        data.connectors.insert(peer_url.clone());
                        // 确保新添加的peers没有在alive_conn_urls或reconnecting中被标记为dead
                        data.alive_conn_urls.remove(&peer_url);
                        data.reconnecting.remove(&peer_url);
                        tracing::info!("Added new peer from remote server: {}", peer_url);
                    }

                    // 更新时间戳
                    data.last_remote_update.insert(remote_server_url.key().clone(), Instant::now());

                    // 对于远程服务器URL更新，我们返回Ok表示处理成功
                    // 这样可以避免在日志中出现不必要的错误信息
                    tracing::info!("Remote server peers updated successfully");
                    return Ok(ReconnResult::remote_server_update(dead_url));
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch peers from remote server {}: {:?}", remote_server_url.value(), e);
                    // 继续使用原始URL尝试连接
                }
            }
        }

        let actual_dead_url = dead_url.clone();
        let mut ip_versions = vec![];
        let u = url::Url::parse(&actual_dead_url)
            .with_context(|| format!("failed to parse connector url {:?}", actual_dead_url))?;
        if u.scheme() == "ring" || u.scheme() == "txt" || u.scheme() == "srv" {
            ip_versions.push(IpVersion::Both);
        } else {
            let addrs = match socket_addrs(&u, || Some(1000)).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                        actual_dead_url.clone(),
                        format!("{:?}", IpVersion::Both),
                        format!("{:?}", e),
                    ));
                    return Err(Error::AnyhowError(anyhow::anyhow!(
                        "get ip from url failed: {:?}",
                        e
                    )));
                }
            };
            tracing::info!(?addrs, ?actual_dead_url, "get ip from url done");
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
            let use_long_timeout = actual_dead_url.starts_with("http")
                || actual_dead_url.starts_with("srv")
                || actual_dead_url.starts_with("txt");
            let ret = timeout(
                // allow http connector to wait longer
                std::time::Duration::from_secs(if use_long_timeout { 20 } else { 2 }),
                Self::conn_reconnect_with_ip_version(
                    data.clone(),
                    actual_dead_url.clone(),
                    ip_version,
                ),
            )
            .await;
            tracing::info!("reconnect: {} done, ret: {:?}", actual_dead_url, ret);

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
                actual_dead_url.clone(),
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