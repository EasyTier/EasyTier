use std::sync::Arc;
use tokio::time::{sleep, Duration};
use clap::Parser;

/// EasyTier 动态节点发现插件
#[derive(Parser, Debug)]
#[command(name = "easytier-node-discovery")]
#[command(about = "Dynamic node discovery plugin for EasyTier")]
struct Args {
    /// 节点配置源 URL (http://, txt://, srv://)
    #[arg(long)]
    config_url: String,

    /// EasyTier API 端点
    #[arg(long, default_value = "http://127.0.0.1:15888")]
    api_endpoint: String,

    /// 刷新间隔（秒）
    #[arg(long, default_value = "300")]
    interval: u64,

    /// EasyTier 实例名称
    #[arg(long, default_value = "default")]
    instance_name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    
    tracing::info!("Starting EasyTier Node Discovery Plugin");
    tracing::info!("Config URL: {}", args.config_url);
    tracing::info!("API Endpoint: {}", args.api_endpoint);
    tracing::info!("Refresh Interval: {}s", args.interval);
    tracing::info!("Instance Name: {}", args.instance_name);

    // 创建节点管理器
    let manager = NodeDiscoveryManager::new(
        args.config_url.parse()?,
        args.api_endpoint,
        args.instance_name,
        args.interval,
    );

    // 运行主循环
    manager.run().await
}

struct NodeDiscoveryManager {
    config_url: url::Url,
    api_endpoint: String,
    instance_name: String,
    interval: u64,
    current_nodes: std::collections::HashSet<String>,
    http_client: reqwest::Client,
}

impl NodeDiscoveryManager {
    fn new(
        config_url: url::Url,
        api_endpoint: String,
        instance_name: String,
        interval: u64,
    ) -> Self {
        Self {
            config_url,
            api_endpoint,
            instance_name,
            interval,
            current_nodes: std::collections::HashSet::new(),
            http_client: reqwest::Client::new(),
        }
    }

    async fn run(mut self) -> anyhow::Result<()> {
        // 首次立即执行
        if let Err(e) = self.sync_nodes().await {
            tracing::warn!("Initial sync failed: {:?}", e);
        }

        // 定期刷新
        loop {
            sleep(Duration::from_secs(self.interval)).await;
            
            if let Err(e) = self.sync_nodes().await {
                tracing::warn!("Sync failed: {:?}, keeping existing nodes", e);
            }
        }
    }

    async fn sync_nodes(&mut self) -> anyhow::Result<()> {
        tracing::debug!("Syncing nodes from {}", self.config_url);

        // 获取新的节点列表
        let new_nodes = self.fetch_nodes().await?;
        
        if new_nodes.is_empty() {
            tracing::warn!("No nodes fetched, keeping existing connections");
            return Ok(());
        }

        // 计算差异
        let to_add: Vec<_> = new_nodes.difference(&self.current_nodes).cloned().collect();
        let to_remove: Vec<_> = self.current_nodes.difference(&new_nodes).cloned().collect();

        // 添加新节点
        for node_url in &to_add {
            if let Err(e) = self.add_connector(node_url).await {
                tracing::warn!("Failed to add connector {}: {:?}", node_url, e);
            } else {
                tracing::info!("Added connector: {}", node_url);
            }
        }

        // 移除旧节点
        for node_url in &to_remove {
            if let Err(e) = self.remove_connector(node_url).await {
                tracing::warn!("Failed to remove connector {}: {:?}", node_url, e);
            } else {
                tracing::info!("Removed connector: {}", node_url);
            }
        }

        // 更新当前节点列表
        self.current_nodes = new_nodes;

        tracing::info!(
            "Sync complete: added {}, removed {}, total {}",
            to_add.len(),
            to_remove.len(),
            self.current_nodes.len()
        );

        Ok(())
    }

    async fn fetch_nodes(&self) -> anyhow::Result<std::collections::HashSet<String>> {
        match self.config_url.scheme() {
            "http" | "https" => self.fetch_http_nodes().await,
            "txt" => self.fetch_txt_nodes().await,
            "srv" => self.fetch_srv_nodes().await,
            _ => Err(anyhow::anyhow!("Unsupported scheme: {}", self.config_url.scheme())),
        }
    }

    async fn fetch_http_nodes(&self) -> anyhow::Result<std::collections::HashSet<String>> {
        let response = self.http_client
            .get(self.config_url.as_str())
            .header("User-Agent", format!("easytier-node-discovery/{}", env!("CARGO_PKG_VERSION")))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP request failed: {}", response.status()));
        }

        let body = response.text().await?;
        let nodes = body
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .filter(|line| line.starts_with("tcp://") || line.starts_with("udp://") || 
                           line.starts_with("ws://") || line.starts_with("wss://") ||
                           line.starts_with("quic://") || line.starts_with("wg://"))
            .collect();

        Ok(nodes)
    }

    async fn fetch_txt_nodes(&self) -> anyhow::Result<std::collections::HashSet<String>> {
        use trust_dns_resolver::TokioAsyncResolver;

        let domain = self.config_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No host in TXT URL"))?;

        let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
        let lookup = resolver.txt_lookup(domain).await?;

        let txt_data = lookup
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No TXT record found"))?
            .to_string();

        let nodes = txt_data
            .split(" ")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(nodes)
    }

    async fn fetch_srv_nodes(&self) -> anyhow::Result<std::collections::HashSet<String>> {
        use trust_dns_resolver::TokioAsyncResolver;
        use strum::IntoEnumIterator;

        let domain = self.config_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("No host in SRV URL"))?;

        let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
        let mut nodes = std::collections::HashSet::new();

        // 查询所有协议的 SRV 记录
        for protocol in ["tcp", "udp", "ws", "wss", "quic"] {
            let srv_domain = format!("_easytier._{}.{}", protocol, domain);
            
            if let Ok(lookup) = resolver.srv_lookup(&srv_domain).await {
                for record in lookup.iter() {
                    if record.port() == 0 {
                        continue;
                    }
                    let url = format!(
                        "{}://{}:{}",
                        protocol,
                        record.target().to_utf8(),
                        record.port()
                    );
                    nodes.insert(url);
                }
            }
        }

        Ok(nodes)
    }

    async fn add_connector(&self, node_url: &str) -> anyhow::Result<()> {
        let api_url = format!("{}/api/v1/instance/connector/add", self.api_endpoint);
        
        let response = self.http_client
            .post(&api_url)
            .json(&serde_json::json!({
                "url": node_url
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("API request failed: {}", response.status()));
        }

        Ok(())
    }

    async fn remove_connector(&self, node_url: &str) -> anyhow::Result<()> {
        let api_url = format!("{}/api/v1/instance/connector/remove", self.api_endpoint);
        
        let response = self.http_client
            .post(&api_url)
            .json(&serde_json::json!({
                "url": node_url
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("API request failed: {}", response.status()));
        }

        Ok(())
    }
}
