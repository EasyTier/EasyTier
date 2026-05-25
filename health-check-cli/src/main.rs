use std::time::{Duration, Instant};
use anyhow::Context;
use clap::{Parser, Subcommand};
use easytier::{
    common::{
        config::{ConfigFileControl, ConfigLoader, NetworkIdentity, PeerConfig, TomlConfigLoader},
    },
    instance_manager::NetworkInstanceManager,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

// ============================================================
// CLI 参数定义
// ============================================================

#[derive(Parser, Debug)]
#[command(name = "health-check")]
#[command(about = "EasyTier 节点健康检查工具", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // 以下为兼容旧版单节点检测的参数（无子命令时使用）
    /// 服务器地址，格式：协议://IP:端口 (例如: tcp://192.168.1.1:11010)
    #[arg(short = 's', long)]
    server: Option<String>,

    /// 网络名称
    #[arg(short = 'n', long)]
    network_name: Option<String>,

    /// 网络密码
    #[arg(short = 'p', long)]
    network_secret: Option<String>,

    /// 超时时间（秒），默认 30 秒
    #[arg(short = 't', long, default_value = "30")]
    timeout: u64,

    /// 启用详细日志
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 单节点检测（与旧版兼容）
    Check {
        /// 服务器地址
        #[arg(short = 's', long)]
        server: String,
        /// 网络名称
        #[arg(short = 'n', long)]
        network_name: String,
        /// 网络密码
        #[arg(short = 'p', long)]
        network_secret: String,
        /// 超时时间（秒）
        #[arg(short = 't', long, default_value = "30")]
        timeout: u64,
        /// 启用详细日志
        #[arg(short = 'v', long)]
        verbose: bool,
        /// 以 JSON 格式输出结果
        #[arg(long)]
        json: bool,
    },
    /// 批量检测模式：从 API 获取节点列表，逐个检测并上报结果
    Batch {
        /// EasyTierWork API 基础地址 (例如: https://your-api.workers.dev)
        #[arg(long)]
        api_url: String,
        /// JWT 认证令牌
        #[arg(long)]
        jwt_token: String,
        /// 每个节点的超时时间（秒）
        #[arg(short = 't', long, default_value = "30")]
        timeout: u64,
        /// 启用详细日志
        #[arg(short = 'v', long)]
        verbose: bool,
        /// 检测间隔（秒），0 表示只执行一次
        #[arg(long, default_value = "60")]
        interval: u64,
    },
}

// ============================================================
// 数据结构
// ============================================================

/// 从 API 获取的节点信息
#[derive(Debug, Deserialize, Clone)]
struct ApiNode {
    id: i64,
    node_name: String,
    user_email: String,
    connections: Vec<ApiConnection>,
    report_token: String,
    network_name: Option<String>,
    network_token: Option<String>,
    is_enabled: i32,
    status: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ApiConnection {
    #[serde(rename = "type")]
    conn_type: String,
    ip: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct ApiNodesResponse {
    nodes: Vec<ApiNode>,
}

/// 单个节点的检测结果
#[derive(Debug, Serialize, Clone)]
struct CheckResult {
    node_id: i64,
    node_name: String,
    is_online: bool,
    connection_count: u32,
    latency_ms: u64,
    check_time: String,
    error: Option<String>,
}

/// 批量上报到 /api/monitor/report 的数据
#[derive(Debug, Serialize)]
struct MonitorReportRequest {
    results: Vec<MonitorNodeResult>,
}

#[derive(Debug, Serialize, Clone)]
struct MonitorNodeResult {
    node_name: String,
    email: String,
    token: String,
    is_online: bool,
    connection_count: u32,
    latency_ms: u64,
    check_time: String,
    error: Option<String>,
}

// ============================================================
// 主函数
// ============================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // 设置全局 panic hook
    std::panic::set_hook(Box::new(|panic_info| {
        let payload = panic_info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        if msg.contains("interface list") || msg.contains("pnet_datalink")
            || msg.contains("Unable to get interface") || msg.contains("buffer size")
        {
            eprintln!("网络接口枚举失败: {}", msg);
            std::process::exit(1);
        } else {
            eprintln!("捕获到 panic: {}", msg);
            if let Some(location) = panic_info.location() {
                eprintln!("位置: {}:{}:{}", location.file(), location.line(), location.column());
            }
        }
    }));

    match cli.command {
        Some(Commands::Check { server, network_name, network_secret, timeout, verbose, json }) => {
            run_single_check(&server, &network_name, &network_secret, timeout, verbose, json).await;
        }
        Some(Commands::Batch { api_url, jwt_token, timeout, verbose, interval }) => {
            run_batch_mode(&api_url, &jwt_token, timeout, verbose, interval).await;
        }
        None => {
            // 兼容旧版：无子命令时使用顶层参数
            if let (Some(server), Some(network_name), Some(network_secret)) =
                (cli.server, cli.network_name, cli.network_secret)
            {
                run_single_check(&server, &network_name, &network_secret, cli.timeout, cli.verbose, false).await;
            } else {
                eprintln!("错误：请使用子命令 check 或 batch，或提供 --server, --network-name, --network-secret 参数");
                eprintln!("使用 --help 查看帮助信息");
                std::process::exit(1);
            }
        }
    }
}

// ============================================================
// 单节点检测模式
// ============================================================

async fn run_single_check(server: &str, network_name: &str, network_secret: &str, timeout: u64, verbose: bool, json_output: bool) {
    let log_level = if verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_line_number(false)
        .init();

    let start = Instant::now();
    match run_health_check(server, network_name, network_secret, timeout, verbose).await {
        Ok((is_online, conn_count)) => {
            if json_output {
                let result = CheckResult {
                    node_id: 0,
                    node_name: "single_check".to_string(),
                    is_online,
                    connection_count: conn_count,
                    latency_ms: start.elapsed().as_millis() as u64,
                    check_time: chrono::Utc::now().to_rfc3339(),
                    error: None,
                };
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                // 兼容旧版输出格式：是否在线 当前连接数 占用带宽 阶梯带宽 已用流量
                println!("{} {} 0 0 0", if is_online { 1 } else { 0 }, conn_count);
            }
            std::process::exit(0);
        }
        Err(e) => {
            if json_output {
                let result = CheckResult {
                    node_id: 0,
                    node_name: "single_check".to_string(),
                    is_online: false,
                    connection_count: 0,
                    latency_ms: start.elapsed().as_millis() as u64,
                    check_time: chrono::Utc::now().to_rfc3339(),
                    error: Some(e.to_string()),
                };
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                if verbose { error!("健康检查失败: {}", e); }
                println!("0 0 0 0 0");
            }
            std::process::exit(1);
        }
    }
}

// ============================================================
// 批量检测模式
// ============================================================

async fn run_batch_mode(api_url: &str, jwt_token: &str, timeout: u64, verbose: bool, interval: u64) {
    let log_level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_line_number(false)
        .init();

    info!("启动批量检测模式");
    info!("API 地址: {}", api_url);
    info!("检测间隔: {}s", interval);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("创建 HTTP 客户端失败");

    loop {
        info!("========== 开始新一轮检测 ==========");

        // 1. 从 API 获取节点列表
        let nodes = match fetch_nodes(&client, api_url, jwt_token).await {
            Ok(nodes) => nodes,
            Err(e) => {
                error!("获取节点列表失败: {}", e);
                if interval == 0 { std::process::exit(1); }
                tokio::time::sleep(Duration::from_secs(interval)).await;
                continue;
            }
        };

        info!("获取到 {} 个节点", nodes.len());

        // 过滤出已启用的节点
        let enabled_nodes: Vec<_> = nodes.iter()
            .filter(|n| n.is_enabled == 1)
            .collect();

        info!("其中 {} 个已启用节点需要检测", enabled_nodes.len());

        // 2. 逐个检测节点
        let mut results: Vec<MonitorNodeResult> = Vec::new();

        for node in &enabled_nodes {
            let result = check_single_node(node, timeout, verbose).await;
            info!(
                "节点 {} ({}): {}",
                node.node_name,
                node.id,
                if result.is_online { "在线" } else { "离线" }
            );
            results.push(result);
        }

        // 3. 批量上报结果
        if !results.is_empty() {
            match report_results(&client, api_url, jwt_token, &results).await {
                Ok(()) => info!("上报 {} 个节点结果成功", results.len()),
                Err(e) => error!("上报结果失败: {}", e),
            }
        }

        info!("========== 本轮检测完成 ==========");

        if interval == 0 {
            break;
        }

        info!("等待 {}s 后开始下一轮...", interval);
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

/// 从 EasyTierWork API 获取所有节点
async fn fetch_nodes(client: &reqwest::Client, api_url: &str, jwt_token: &str) -> anyhow::Result<Vec<ApiNode>> {
    let url = format!("{}/api/nodes/all", api_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
        .with_context(|| format!("请求 {} 失败", url))?;

    if !resp.status().is_success() {
        anyhow::bail!("API 返回错误状态: {}", resp.status());
    }

    let body: ApiNodesResponse = resp.json().await
        .with_context(|| "解析节点列表 JSON 失败")?;

    Ok(body.nodes)
}

/// 检测单个节点
async fn check_single_node(node: &ApiNode, timeout: u64, verbose: bool) -> MonitorNodeResult {
    let start = Instant::now();

    // 获取连接信息
    let (server_url, network_name, network_secret) = match extract_node_info(node) {
        Some(info) => info,
        None => {
            return MonitorNodeResult {
                node_name: node.node_name.clone(),
                email: node.user_email.clone(),
                token: node.report_token.clone(),
                is_online: false,
                connection_count: 0,
                latency_ms: 0,
                check_time: chrono::Utc::now().to_rfc3339(),
                error: Some("缺少连接信息或网络密码".to_string()),
            };
        }
    };

    // 执行健康检查
    match run_health_check(&server_url, &network_name, &network_secret, timeout, verbose).await {
        Ok((is_online, conn_count)) => {
            MonitorNodeResult {
                node_name: node.node_name.clone(),
                email: node.user_email.clone(),
                token: node.report_token.clone(),
                is_online,
                connection_count: conn_count,
                latency_ms: start.elapsed().as_millis() as u64,
                check_time: chrono::Utc::now().to_rfc3339(),
                error: None,
            }
        }
        Err(e) => {
            MonitorNodeResult {
                node_name: node.node_name.clone(),
                email: node.user_email.clone(),
                token: node.report_token.clone(),
                is_online: false,
                connection_count: 0,
                latency_ms: start.elapsed().as_millis() as u64,
                check_time: chrono::Utc::now().to_rfc3339(),
                error: Some(e.to_string()),
            }
        }
    }
}

/// 从节点信息中提取连接参数
fn extract_node_info(node: &ApiNode) -> Option<(String, String, String)> {
    let conn = node.connections.first()?;
    let network_secret = node.network_token.as_ref().filter(|s| !s.is_empty())?;
    let network_name = node.network_name.clone().unwrap_or_else(|| "default".to_string());

    let protocol = conn.conn_type.to_lowercase();
    let server_url = format!("{}://{}:{}", protocol, conn.ip, conn.port);

    Some((server_url, network_name, network_secret.clone()))
}

/// 上报检测结果到 EasyTierWork API
async fn report_results(
    client: &reqwest::Client,
    api_url: &str,
    jwt_token: &str,
    results: &[MonitorNodeResult],
) -> anyhow::Result<()> {
    let url = format!("{}/api/monitor/report", api_url.trim_end_matches('/'));
    let body = MonitorReportRequest {
        results: results.to_vec(),
    };

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", jwt_token))
        .json(&body)
        .send()
        .await
        .with_context(|| "上报检测结果失败")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("上报返回错误 {}: {}", status, text);
    }

    Ok(())
}

// ============================================================
// 核心健康检查逻辑（复用原有实现）
// ============================================================

async fn run_health_check(server: &str, network_name: &str, network_secret: &str, timeout: u64, verbose: bool) -> anyhow::Result<(bool, u32)> {
    let cfg = create_config(server, network_name, network_secret)
        .with_context(|| "创建配置失败")?;

    let inst_id = cfg.get_id();
    let instance_mgr = NetworkInstanceManager::new();

    let start_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        instance_mgr.run_network_instance(cfg.clone(), true, ConfigFileControl::STATIC_CONFIG)
    }));

    let _instance_handle = match start_result {
        Ok(handle) => handle.with_context(|| "启动网络实例失败")?,
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic during instance startup".to_string()
            };
            if msg.contains("interface") || msg.contains("pnet_datalink") {
                return Err(anyhow::anyhow!("网络接口枚举失败: {}", msg));
            } else {
                return Err(anyhow::anyhow!("启动网络实例时发生panic: {}", msg));
            }
        }
    };

    let _cleanup = CleanupGuard {
        instance_mgr: &instance_mgr,
        inst_id,
    };

    let timeout_dur = Duration::from_secs(timeout);
    let start_time = Instant::now();
    let max_startup_wait = Duration::from_secs(30);

    info!("等待实例启动...");
    while start_time.elapsed() < max_startup_wait && start_time.elapsed() < timeout_dur {
        if instance_mgr.get_network_info(&inst_id).await.is_some() {
            info!("实例启动成功");
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    if instance_mgr.get_network_info(&inst_id).await.is_none() {
        return Err(anyhow::anyhow!("实例启动超时"));
    }

    info!("开始健康检查，超时时间: {} 秒", timeout);

    while start_time.elapsed() < timeout_dur {
        match test_node_healthy(inst_id, &instance_mgr).await {
            Ok(conn_count) => {
                info!("节点在线，连接数: {}", conn_count);
                return Ok((true, conn_count));
            }
            Err(e) => {
                if verbose {
                    warn!("健康检查尝试失败: {}", e);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(anyhow::anyhow!("健康检查超时"))
}

fn create_config(
    server_uri: &str,
    network_name: &str,
    network_secret: &str,
) -> anyhow::Result<TomlConfigLoader> {
    let cfg = TomlConfigLoader::default();

    cfg.set_peers(vec![PeerConfig {
        uri: server_uri
            .parse()
            .with_context(|| format!("无效的服务器地址: {}", server_uri))?,
    }]);

    cfg.set_id(uuid::Uuid::new_v4());

    cfg.set_network_identity(NetworkIdentity::new(
        network_name.to_string(),
        network_secret.to_string(),
    ));

    cfg.set_hostname(Some("HealthCheckCLI".to_string()));

    let mut flags = cfg.get_flags();
    flags.no_tun = true;
    flags.disable_p2p = true;
    flags.disable_udp_hole_punching = true;
    flags.bind_device = false;
    flags.use_smoltcp = true;
    flags.enable_ipv6 = false;
    flags.proxy_forward_by_system = false;
    flags.accept_dns = false;
    flags.private_mode = true;
    flags.latency_first = false;
    flags.enable_exit_node = false;
    cfg.set_flags(flags);

    cfg.set_stun_servers(Some(vec![
        "stun.miwifi.com".to_string(),
        "stun.chat.bilibili.com".to_string(),
        "stun.hitv.com".to_string(),
        "stun.nextcloud.com".to_string(),
    ]));

    cfg.set_stun_servers_v6(Some(vec![]));

    Ok(cfg)
}

async fn test_node_healthy(
    inst_id: uuid::Uuid,
    instance_mgr: &NetworkInstanceManager,
) -> anyhow::Result<u32> {
    let Some(instance) = instance_mgr.get_network_info(&inst_id).await else {
        anyhow::bail!("健康检查节点未启动");
    };

    if !instance.running {
        anyhow::bail!("健康检查节点未运行");
    }

    if let Some(err) = instance.error_msg {
        anyhow::bail!("健康检查节点有错误: {}", err);
    }

    let p = instance.peer_route_pairs;
    let Some(dst_node) = p.iter().find(|x| {
        x.route.as_ref().is_some_and(|route| {
            !route.feature_flag.as_ref().map(|f| f.is_public_server).unwrap_or(false)
                && route.hostname != "HealthCheckCLI"
        }) && x.peer.as_ref().is_some_and(|p| !p.conns.is_empty())
    }) else {
        anyhow::bail!("目标节点不在线");
    };

    let Some(_peer_info) = &dst_node.peer else {
        anyhow::bail!("目标节点 peer 信息未找到");
    };

    let peer_id = _peer_info.peer_id;
    let conn_count = if let Some(summary) = instance.foreign_network_summary {
        summary
            .info_map
            .get(&peer_id)
            .map(|x| x.network_count)
            .unwrap_or(0)
    } else {
        0
    };

    Ok(conn_count)
}

struct CleanupGuard<'a> {
    instance_mgr: &'a NetworkInstanceManager,
    inst_id: uuid::Uuid,
}

impl<'a> Drop for CleanupGuard<'a> {
    fn drop(&mut self) {
        let _ = self.instance_mgr.delete_network_instance(vec![self.inst_id]);
    }
}