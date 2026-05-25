use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::common::scoped_task::ScopedTask;
use crate::common::stats_manager::{LabelSet, MetricName, StatsManager};
use crate::common::policy_container::PolicyContainer;
use crate::proto::api::manage::ReportConfig;

/// 上报请求体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    /// 节点名称
    pub node_name: String,
    /// 用户邮箱
    pub email: String,
    /// 上报Token
    pub token: String,
    /// 当前带宽（Mbps）
    pub current_bandwidth: f64,
    /// 本次上报的流量增量（GB）
    pub reported_traffic: f64,
    /// 当前连接数
    pub connection_count: u32,
    /// 每月重置日期
    pub reset_date: u32,
    /// 当前状态
    pub status: String,
    /// 网络数量
    pub network_count: Option<u32>,
    /// 中转带宽（bps）
    pub relay_bandwidth: Option<u64>,
    /// 是否支持中转
    pub allow_relay: Option<bool>,
    /// 是否仅当前网络
    pub current_network_only: Option<bool>,
    /// 是否被策略限速
    pub is_limited: Option<bool>,
    /// 当前策略限速带宽（Mbps）
    pub limited_bandwidth: Option<f64>,
    /// 策略激活状态
    pub active_policies: Option<Vec<ActivePolicyInfo>>,
}

/// 激活的策略信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivePolicyInfo {
    /// 策略动作
    pub action: String,
    /// 流量阈值（GB）
    pub threshold_gb: f64,
}

/// 上报响应（兼容 EasyTierWork 返回格式，Work返回 {"message": "上报成功"} 不含 success 字段）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResponse {
    /// 是否成功（默认 true，兼容不返回此字段的服务端）
    #[serde(default = "default_true")]
    pub success: bool,
    /// 消息
    pub message: Option<String>,
}

fn default_true() -> bool { true }

/// 上报管理器
pub struct ReportManager {
    /// 上报配置
    config: Arc<RwLock<Option<ReportConfig>>>,
    /// 统计管理器引用
    stats_manager: Arc<StatsManager>,
    /// 网络名称
    network_name: String,
    /// 节点名称
    node_name: String,
    /// 用户邮箱
    email: String,
    /// 上次上报的流量（用于计算增量）
    last_reported_traffic: Arc<RwLock<u64>>,
    /// HTTP客户端
    http_client: reqwest::Client,
    /// 策略容器引用（用于直接读取策略状态）
    policy_container: Arc<std::sync::RwLock<Option<std::sync::Weak<PolicyContainer>>>>,
    /// 后台任务
    background_task: ScopedTask<()>,
}

impl ReportManager {
    /// 创建新的上报管理器
    pub fn new(
        config: Option<ReportConfig>,
        stats_manager: Arc<StatsManager>,
        network_name: String,
        node_name: String,
        email: String,
    ) -> Arc<Self> {
        let config_arc = Arc::new(RwLock::new(config));
        let last_reported_traffic = Arc::new(RwLock::new(0u64));
        let policy_container: Arc<std::sync::RwLock<Option<std::sync::Weak<PolicyContainer>>>> =
            Arc::new(std::sync::RwLock::new(None));

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // 创建后台任务的弱引用结构
        let config_weak = Arc::downgrade(&config_arc);
        let stats_manager_weak = Arc::downgrade(&stats_manager);
        let last_reported_traffic_weak = Arc::downgrade(&last_reported_traffic);
        let policy_container_clone = policy_container.clone();
        let network_name_clone = network_name.clone();
        let node_name_clone = node_name.clone();
        let email_clone = email.clone();
        let http_client_clone = http_client.clone();

        let background_task = tokio::spawn(async move {
            Self::run_background_report(
                config_weak,
                stats_manager_weak,
                last_reported_traffic_weak,
                http_client_clone,
                network_name_clone,
                node_name_clone,
                email_clone,
                policy_container_clone,
            ).await;
        });

        Arc::new(Self {
            config: config_arc,
            stats_manager,
            network_name,
            node_name,
            email,
            last_reported_traffic,
            http_client,
            policy_container,
            background_task: background_task.into(),
        })
    }

    /// 设置策略容器引用（在 launcher 中设置）
    pub fn set_policy_container(&self, container: Arc<PolicyContainer>) {
        *self.policy_container.write().unwrap() = Some(Arc::downgrade(&container));
    }

    /// 后台上报任务
    async fn run_background_report(
        config: std::sync::Weak<RwLock<Option<ReportConfig>>>,
        stats_manager: std::sync::Weak<StatsManager>,
        last_reported_traffic: std::sync::Weak<RwLock<u64>>,
        http_client: reqwest::Client,
        network_name: String,
        node_name: String,
        email: String,
        policy_container: Arc<std::sync::RwLock<Option<std::sync::Weak<PolicyContainer>>>>,
    ) {
        loop {
            let Some(cfg_arc) = config.upgrade() else { break; };
            let cfg = cfg_arc.read().await;
            let Some(ref report_config) = *cfg else {
                drop(cfg);
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            };

            let heartbeat_interval = report_config.heartbeat_interval_minutes.max(1) as u64;

            // 获取所有端点
            let endpoints: Vec<(String, String)> = if !report_config.endpoints.is_empty() {
                report_config.endpoints.iter()
                    .map(|e| (e.url.clone(), e.secret.clone()))
                    .collect()
            } else {
                report_config.report_urls.iter()
                    .map(|url| (url.clone(), report_config.report_token.clone()))
                    .collect()
            };

            drop(cfg);

            // 等待心跳间隔
            tokio::time::sleep(Duration::from_secs(heartbeat_interval * 60)).await;

            // 收集数据
            let Some(stats_mgr) = stats_manager.upgrade() else { break; };
            let Some(last_traffic_arc) = last_reported_traffic.upgrade() else { break; };

            // 从 StatsManager 获取真实流量数据
            let label_set = LabelSet::new()
                .with_label("network_name", network_name.to_string());

            let tx_bytes = stats_mgr
                .get_metric(MetricName::TrafficBytesTx, &label_set)
                .map(|m| m.value)
                .unwrap_or(0);
            let rx_bytes = stats_mgr
                .get_metric(MetricName::TrafficBytesRx, &label_set)
                .map(|m| m.value)
                .unwrap_or(0);
            let total_bytes = tx_bytes + rx_bytes;

            // 获取连接数（从packets指标推算，或使用peer count）
            let connection_count = stats_mgr.get_all_metrics().iter()
                .filter(|m| m.name == MetricName::TrafficPacketsTx && m.value > 0)
                .count() as u32;

            // 计算当前带宽（基于上次上报以来的流量/时间）
            let mut last_traffic = last_traffic_arc.write().await;
            let traffic_delta = total_bytes.saturating_sub(*last_traffic);
            *last_traffic = total_bytes;
            drop(last_traffic);

            let reported_traffic_gb = traffic_delta as f64 / (1024.0 * 1024.0 * 1024.0);
            let current_bandwidth = (traffic_delta as f64 * 8.0)
                / (heartbeat_interval as f64 * 60.0)
                / (1024.0 * 1024.0); // Mbps

            // 从 PolicyContainer 直接读取策略状态
            let (is_limited, limited_bandwidth, active_policies, allow_relay) =
                Self::read_policy_state(&policy_container);

            // 向所有端点上报
            for (url, token) in &endpoints {
                let full_url = if url.ends_with("/api/report") {
                    url.clone()
                } else if url.ends_with('/') {
                    format!("{}api/report", url)
                } else {
                    format!("{}/api/report", url)
                };

                let report_request = ReportRequest {
                    node_name: node_name.clone(),
                    email: email.clone(),
                    token: token.clone(),
                    current_bandwidth,
                    reported_traffic: reported_traffic_gb,
                    connection_count,
                    reset_date: 1,
                    status: "online".to_string(),
                    network_count: Some(1),
                    relay_bandwidth: None,
                    allow_relay: Some(allow_relay),
                    current_network_only: Some(false),
                    is_limited: Some(is_limited),
                    limited_bandwidth,
                    active_policies: active_policies.clone(),
                };

                match Self::send_report(&http_client, &full_url, &report_request).await {
                    Ok(response) => {
                        if response.success {
                            tracing::info!(
                                "Reported to {}: traffic={:.3}GB, bw={:.2}Mbps, conns={}",
                                full_url, reported_traffic_gb, current_bandwidth, connection_count
                            );
                        } else {
                            tracing::warn!("Report to {} failed: {:?}", full_url, response.message);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to report to {}: {}", full_url, e);
                    }
                }
            }
        }
    }

    /// 从 PolicyContainer 读取策略状态（同步，无 await）
    fn read_policy_state(
        policy_container: &std::sync::RwLock<Option<std::sync::Weak<PolicyContainer>>>,
    ) -> (bool, Option<f64>, Option<Vec<ActivePolicyInfo>>, bool) {
        let guard = policy_container.read().unwrap();
        let container = match guard.as_ref().and_then(|w| w.upgrade()) {
            Some(c) => c,
            None => return (false, None, None, true),
        };
        drop(guard);

        let manager = match container.get_flow_policy_manager_sync() {
            Some(m) => m,
            None => return (false, None, None, true),
        };

        let is_limited = manager.should_limit_bandwidth().is_some();
        let limited_bandwidth = if is_limited {
            // 获取策略配置中的限速带宽
            manager.get_active_policies().iter()
                .find(|(action, _)| *action == crate::proto::api::manage::FlowPolicyAction::LimitBandwidth)
                .and_then(|(_, rule)| rule.bandwidth_limit_mbps)
        } else {
            None
        };
        let allow_relay = !manager.should_disable_relay();
        let active_policies: Vec<ActivePolicyInfo> = manager.get_active_policies().iter()
            .map(|(action, rule)| ActivePolicyInfo {
                action: format!("{:?}", action),
                threshold_gb: rule.traffic_threshold_gb,
            })
            .collect();

        (
            is_limited,
            limited_bandwidth,
            if active_policies.is_empty() { None } else { Some(active_policies) },
            allow_relay,
        )
    }

    /// 发送上报请求
    async fn send_report(
        http_client: &reqwest::Client,
        url: &str,
        request: &ReportRequest,
    ) -> Result<ReportResponse, Box<dyn std::error::Error + Send + Sync>> {
        let response = http_client.post(url).json(request).send().await?;
        if response.status().is_success() {
            Ok(response.json::<ReportResponse>().await?)
        } else {
            Ok(ReportResponse {
                success: false,
                message: Some(format!("HTTP {}", response.status())),
            })
        }
    }

    /// 更新配置
    pub async fn update_config(&self, new_config: Option<ReportConfig>) {
        *self.config.write().await = new_config;
    }

    /// 手动触发上报
    pub async fn trigger_report(&self, _reset_date: u32) {
        tracing::info!("Manual report trigger (will report on next heartbeat cycle)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_report_manager_creation() {
        let stats_manager = Arc::new(StatsManager::new());
        let config = Some(ReportConfig {
            endpoints: vec![
                crate::proto::api::manage::ReportEndpoint {
                    url: "http://example.com".to_string(),
                    secret: "test_secret".to_string(),
                }
            ],
            report_token: "test_token".to_string(),
            heartbeat_interval_minutes: 5,
            report_urls: vec![],
        });

        let _manager = ReportManager::new(
            config,
            stats_manager,
            "test_network".to_string(),
            "test_node".to_string(),
            "test@example.com".to_string(),
        );
    }

    #[test]
    fn test_report_request_serialization() {
        let request = ReportRequest {
            node_name: "test_node".to_string(),
            email: "test@example.com".to_string(),
            token: "test_token".to_string(),
            current_bandwidth: 50.5,
            reported_traffic: 0.5,
            connection_count: 5,
            reset_date: 1,
            status: "online".to_string(),
            network_count: Some(2),
            relay_bandwidth: Some(1000000),
            allow_relay: Some(true),
            current_network_only: Some(false),
            is_limited: Some(false),
            limited_bandwidth: None,
            active_policies: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test_node"));
        assert!(json.contains("test@example.com"));
    }
}
