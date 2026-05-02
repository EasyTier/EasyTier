use std::{collections::HashMap, sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::{sync::Mutex, time::interval};

use crate::{
    common::error::Error,
    connector::manual::ManualConnectorManager,
    tunnel::IpVersion,
};

/// 动态发现的连接器类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DynamicConnectorType {
    Http,
    Txt,
    Srv,
}

/// 动态连接器的元数据
#[derive(Debug, Clone)]
struct DynamicConnectorMeta {
    source_url: url::Url,
    connector_type: DynamicConnectorType,
    ip_version: IpVersion,
    last_refresh_time: std::time::Instant,
    refresh_interval: Duration,
}

/// 全局动态连接器管理器（单例）
pub struct GlobalDynamicConnectorManager {
    /// 所有动态连接器配置: source_url -> meta
    connectors: DashMap<url::Url, DynamicConnectorMeta>,
    /// 上次刷新时获取的节点列表: source_url -> Vec<node_url>
    cached_nodes: DashMap<url::Url, Vec<url::Url>>,
    /// ManualConnectorManager 引用（可能有多个实例）
    manual_managers: DashMap<String, Arc<ManualConnectorManager>>,
    /// 刷新任务句柄（只有一个）
    refresh_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 是否正在运行
    is_running: Mutex<bool>,
}

impl GlobalDynamicConnectorManager {
    /// 获取或创建全局单例
    pub fn get_instance() -> &'static Arc<Self> {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<Arc<GlobalDynamicConnectorManager>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            Arc::new(Self {
                connectors: DashMap::new(),
                cached_nodes: DashMap::new(),
                manual_managers: DashMap::new(),
                refresh_task: Mutex::new(None),
                is_running: Mutex::new(false),
            })
        })
    }

    /// 注册一个 ManualConnectorManager 实例
    pub fn register_manual_manager(&self, instance_id: String, manager: Arc<ManualConnectorManager>) {
        tracing::info!("Registering ManualConnectorManager for instance: {}", instance_id);
        self.manual_managers.insert(instance_id, manager);
    }

    /// 注销一个 ManualConnectorManager 实例
    pub fn unregister_manual_manager(&self, instance_id: &str) {
        tracing::info!("Unregistering ManualConnectorManager for instance: {}", instance_id);
        self.manual_managers.remove(instance_id);
    }

    /// 添加一个动态连接器源
    pub async fn add_dynamic_connector(
        &self,
        source_url: url::Url,
        connector_type: DynamicConnectorType,
        ip_version: IpVersion,
        refresh_interval_secs: u64,
    ) -> Result<(), Error> {
        let meta = DynamicConnectorMeta {
            source_url: source_url.clone(),
            connector_type,
            ip_version,
            last_refresh_time: std::time::Instant::now(),
            refresh_interval: Duration::from_secs(refresh_interval_secs),
        };

        tracing::info!(
            "Adding dynamic connector: {:?} from {}",
            connector_type,
            source_url
        );

        self.connectors.insert(source_url.clone(), meta);

        // 立即执行一次刷新
        self.refresh_single_connector(&source_url).await?;

        // 启动或确保后台刷新任务正在运行
        self.ensure_refresh_task_running().await;

        Ok(())
    }

    /// 移除动态连接器源
    pub async fn remove_dynamic_connector(&self, source_url: &url::Url) -> Result<(), Error> {
        tracing::info!("Removing dynamic connector: {}", source_url);

        // 移除缓存的节点（从所有实例中）
        if let Some((_, old_nodes)) = self.cached_nodes.remove(source_url) {
            for (_instance_id, manager) in self.manual_managers.iter() {
                for node_url in &old_nodes {
                    let _ = manager.remove_connector(node_url.clone()).await;
                }
            }
        }

        // 移除配置
        self.connectors.remove(source_url);

        // 如果没有更多动态连接器，停止刷新任务
        if self.connectors.is_empty() {
            self.stop_refresh_task().await;
        }

        Ok(())
    }

    /// 确保刷新任务正在运行
    async fn ensure_refresh_task_running(&self) {
        let mut is_running = self.is_running.lock().await;
        if *is_running {
            return;
        }

        tracing::info!("Starting global dynamic connector refresh task");
        *is_running = true;
        drop(is_running);

        let instance = Self::get_instance().clone();
        let handle = tokio::spawn(async move {
            instance.refresh_loop().await;
        });

        let mut task_lock = self.refresh_task.lock().await;
        *task_lock = Some(handle);
    }

    /// 停止刷新任务
    async fn stop_refresh_task(&self) {
        let mut is_running = self.is_running.lock().await;
        if !*is_running {
            return;
        }

        tracing::info!("Stopping global dynamic connector refresh task");
        *is_running = false;

        let mut task_lock = self.refresh_task.lock().await;
        if let Some(handle) = task_lock.take() {
            handle.abort();
        }
    }

    /// 主刷新循环
    async fn refresh_loop(&self) {
        let mut interval = interval(Duration::from_secs(300));

        loop {
            interval.tick().await;

            // 检查是否应该继续运行
            {
                let is_running = self.is_running.lock().await;
                if !*is_running {
                    tracing::info!("Global refresh task stopped");
                    break;
                }
            }

            tracing::debug!("Running global dynamic connector refresh");

            // 刷新所有注册的动态连接器
            let source_urls: Vec<_> = self.connectors.iter().map(|entry| entry.key().clone()).collect();
            
            for source_url in source_urls {
                if let Err(e) = self.refresh_single_connector(&source_url).await {
                    tracing::warn!(
                        "Failed to refresh dynamic connector {}: {:?}",
                        source_url,
                        e
                    );
                }
            }
        }
    }

    /// 刷新单个连接器
    async fn refresh_single_connector(&self, source_url: &url::Url) -> Result<(), Error> {
        let meta = match self.connectors.get(source_url) {
            Some(meta) => meta.clone(),
            None => return Err(Error::NotFound),
        };

        tracing::debug!("Refreshing dynamic connector: {}", source_url);

        // 根据类型获取新的节点列表
        let new_nodes = match meta.connector_type {
            DynamicConnectorType::Http => {
                Self::fetch_http_nodes(source_url, meta.ip_version).await?
            }
            DynamicConnectorType::Txt => {
                Self::fetch_txt_nodes(source_url, meta.ip_version).await?
            }
            DynamicConnectorType::Srv => {
                Self::fetch_srv_nodes(source_url, meta.ip_version).await?
            }
        };

        if new_nodes.is_empty() {
            tracing::warn!(
                "No nodes fetched from {}, keeping existing connections",
                source_url
            );
            return Ok(());
        }

        // 获取旧的节点列表
        let old_nodes = self
            .cached_nodes
            .get(source_url)
            .map(|v| v.clone())
            .unwrap_or_default();

        // 计算需要添加和移除的节点
        let old_set: std::collections::HashSet<_> = old_nodes.iter().collect();
        let new_set: std::collections::HashSet<_> = new_nodes.iter().collect();

        let to_add: Vec<_> = new_nodes
            .iter()
            .filter(|n| !old_set.contains(n))
            .cloned()
            .collect();

        let to_remove: Vec<_> = old_nodes
            .iter()
            .filter(|n| !new_set.contains(n))
            .cloned()
            .collect();

        // 为所有注册的实例添加/移除节点
        for (_instance_id, manager) in self.manual_managers.iter() {
            // 添加新节点
            for node_url in &to_add {
                tracing::info!("Adding new node from dynamic source: {}", node_url);
                if let Err(e) = manager.add_connector_by_url(node_url.clone()).await {
                    tracing::warn!("Failed to add connector {}: {:?}", node_url, e);
                }
            }

            // 移除旧节点
            for node_url in &to_remove {
                tracing::info!("Removing old node from dynamic source: {}", node_url);
                if let Err(e) = manager.remove_connector(node_url.clone()).await {
                    tracing::warn!("Failed to remove connector {}: {:?}", node_url, e);
                }
            }
        }

        // 更新缓存
        tracing::info!(
            "Refreshed {}: added {} nodes, removed {} nodes, total {} nodes",
            source_url,
            to_add.len(),
            to_remove.len(),
            new_nodes.len()
        );

        self.cached_nodes.insert(source_url.clone(), new_nodes);

        // 更新最后刷新时间
        if let mut meta = self.connectors.get_mut(source_url) {
            meta.last_refresh_time = std::time::Instant::now();
        }

        Ok(())
    }

    // ========== 节点获取方法 ==========

    async fn fetch_http_nodes(
        source_url: &url::Url,
        _ip_version: IpVersion,
    ) -> Result<Vec<url::Url>, Error> {
        use http_req::request::{Request, RedirectPolicy};

        // 注意：这里需要一个默认的 global_ctx 来获取 network_name
        // 简化处理：使用空字符串或从 URL 中提取
        let network_name = "default";

        let res = Request::new(source_url.as_str())
            .method(http_req::request::Method::GET)
            .header("User-Agent", format!("easytier/{}", crate::VERSION).as_str())
            .header("X-Network-Name", network_name)
            .redirect_policy(RedirectPolicy::Limit(5))
            .send()
            .map_err(|e| Error::InvalidUrl(format!("HTTP request failed: {:?}", e)))?;

        if res.status_code() != 200 {
            return Err(Error::InvalidUrl(format!(
                "HTTP request failed with status: {}",
                res.status_code()
            )));
        }

        let body = String::from_utf8_lossy(&res.body());
        let urls = body
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .filter_map(|line| url::Url::parse(line).ok())
            .collect::<Vec<_>>();

        tracing::debug!("Fetched {} URLs from HTTP: {}", urls.len(), source_url);
        Ok(urls)
    }

    async fn fetch_txt_nodes(
        source_url: &url::Url,
        _ip_version: IpVersion,
    ) -> Result<Vec<url::Url>, Error> {
        use trust_dns_resolver::TokioAsyncResolver;

        let domain = source_url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("No host in TXT URL".to_string()))?;

        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| Error::InvalidUrl(format!("DNS resolver creation failed: {:?}", e)))?;

        let lookup = resolver
            .txt_lookup(domain)
            .await
            .map_err(|e| Error::InvalidUrl(format!("TXT lookup failed: {:?}", e)))?;

        let txt_data = lookup
            .iter()
            .next()
            .ok_or_else(|| Error::InvalidUrl("No TXT record found".to_string()))?
            .to_string();

        let urls = txt_data
            .split(" ")
            .filter_map(|s| url::Url::parse(s.trim()).ok())
            .collect::<Vec<_>>();

        tracing::debug!("Fetched {} URLs from TXT: {}", urls.len(), source_url);
        Ok(urls)
    }

    async fn fetch_srv_nodes(
        source_url: &url::Url,
        _ip_version: IpVersion,
    ) -> Result<Vec<url::Url>, Error> {
        use trust_dns_resolver::TokioAsyncResolver;
        use crate::tunnel::IpScheme;
        use strum::IntoEnumIterator;

        let domain = source_url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("No host in SRV URL".to_string()))?;

        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| Error::InvalidUrl(format!("DNS resolver creation failed: {:?}", e)))?;

        let mut urls = Vec::new();

        // 查询所有协议的 SRV 记录
        for protocol in IpScheme::iter() {
            let srv_domain = format!("_easytier._{}.{}", protocol, domain);

            match resolver.srv_lookup(&srv_domain).await {
                Ok(lookup) => {
                    for record in lookup.iter() {
                        if record.port() == 0 {
                            continue;
                        }
                        let url_str = format!(
                            "{}://{}:{}",
                            protocol,
                            record.target().to_utf8(),
                            record.port()
                        );
                        if let Ok(url) = url::Url::parse(&url_str) {
                            urls.push(url);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("SRV lookup failed for {}: {:?}", srv_domain, e);
                }
            }
        }

        tracing::debug!("Fetched {} URLs from SRV: {}", urls.len(), source_url);
        Ok(urls)
    }
}
