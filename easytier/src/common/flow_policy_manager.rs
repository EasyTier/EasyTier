use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::interval;

use crate::common::scoped_task::ScopedTask;
use crate::common::stats_manager::{LabelSet, MetricName, StatsManager};
use crate::common::token_bucket::TokenBucket;
use crate::proto::api::manage::{
    BandwidthLimitConfig, FlowPolicyAction, FlowPolicyConfig, FlowPolicyRule,
    PolicyStateInfo, TrafficStatsInfo,
};

/// 流量统计数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    /// 总发送字节数
    pub tx_bytes: u64,
    /// 总接收字节数
    pub rx_bytes: u64,
    /// 总字节数（发送+接收）
    pub total_bytes: u64,
    /// 上次重置时间（Unix时间戳）
    pub last_reset_time: u64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            tx_bytes: 0,
            rx_bytes: 0,
            total_bytes: 0,
            last_reset_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

impl TrafficStats {
    /// 重置统计数据
    pub fn reset(&mut self) {
        self.tx_bytes = 0;
        self.rx_bytes = 0;
        self.total_bytes = 0;
        self.last_reset_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// 添加流量数据
    pub fn add_traffic(&mut self, tx_bytes: u64, rx_bytes: u64) {
        self.tx_bytes += tx_bytes;
        self.rx_bytes += rx_bytes;
        self.total_bytes = self.tx_bytes + self.rx_bytes;
    }

    /// 获取总流量（GB）
    pub fn total_gb(&self) -> f64 {
        self.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

/// 当前激活的策略状态
#[derive(Debug, Clone)]
pub struct ActivePolicy {
    /// 策略规则
    pub rule: FlowPolicyRule,
    /// 带宽限制器（如果策略是限制带宽）
    pub bandwidth_limiter: Option<Arc<TokenBucket>>,
}

/// 白名单管理器
#[derive(Debug, Clone, Default)]
pub struct WhitelistNetworks {
    /// 白名单网络集合
    pub networks: HashSet<String>,
}

impl WhitelistNetworks {
    pub fn new(networks: Vec<String>) -> Self {
        Self {
            networks: networks.into_iter().collect(),
        }
    }

    pub fn contains(&self, network_name: &str) -> bool {
        self.networks.is_empty() || self.networks.contains(network_name)
    }

    pub fn clear(&mut self) {
        self.networks.clear();
    }
}

/// 流量策略管理器
pub struct FlowPolicyManager {
    /// 流量策略配置
    config: Arc<RwLock<Option<FlowPolicyConfig>>>,
    /// 流量统计数据
    traffic_stats: Arc<RwLock<TrafficStats>>,
    /// 当前激活的策略
    active_policies: Arc<DashMap<FlowPolicyAction, ActivePolicy>>,
    /// 白名单网络
    whitelist_networks: Arc<RwLock<WhitelistNetworks>>,
    /// 带宽限制配置
    bandwidth_limit: Arc<RwLock<Option<BandwidthLimitConfig>>>,
    /// 直接带宽限制器（非策略触发，配置即生效）
    direct_bandwidth_limiter: Arc<std::sync::RwLock<Option<Arc<TokenBucket>>>>,
    /// 统计管理器引用
    stats_manager: Arc<StatsManager>,
    /// 网络名称
    network_name: String,
    /// 后台任务
    background_task: ScopedTask<()>,
}

impl FlowPolicyManager {
    /// 创建新的流量策略管理器
    pub fn new(
        config: Option<FlowPolicyConfig>,
        stats_manager: Arc<StatsManager>,
        network_name: String,
    ) -> Arc<Self> {
        let config_arc = Arc::new(RwLock::new(config.clone()));
        let traffic_stats = Arc::new(RwLock::new(TrafficStats::default()));
        let active_policies = Arc::new(DashMap::new());
        let whitelist_networks = Arc::new(RwLock::new(WhitelistNetworks::default()));
        let bandwidth_limit = Arc::new(RwLock::new(None));

        // 创建后台任务的弱引用结构
        let config_weak = Arc::downgrade(&config_arc);
        let traffic_stats_weak = Arc::downgrade(&traffic_stats);
        let active_policies_weak = Arc::downgrade(&active_policies);
        let whitelist_weak = Arc::downgrade(&whitelist_networks);
        let bandwidth_limit_weak = Arc::downgrade(&bandwidth_limit);
        let stats_manager_weak = Arc::downgrade(&stats_manager);
        let network_name_clone = network_name.clone();

        let background_task = tokio::spawn(async move {
            Self::run_background_tasks_static(
                config_weak,
                traffic_stats_weak,
                active_policies_weak,
                whitelist_weak,
                bandwidth_limit_weak,
                stats_manager_weak,
                network_name_clone,
            ).await;
        });

        Arc::new(Self {
            config: config_arc,
            traffic_stats,
            active_policies,
            whitelist_networks,
            bandwidth_limit,
            direct_bandwidth_limiter: Arc::new(std::sync::RwLock::new(None)),
            stats_manager,
            network_name,
            background_task: background_task.into(),
        })
    }

    /// 静态后台任务运行方法
    async fn run_background_tasks_static(
        config: std::sync::Weak<RwLock<Option<FlowPolicyConfig>>>,
        traffic_stats: std::sync::Weak<RwLock<TrafficStats>>,
        active_policies: std::sync::Weak<DashMap<FlowPolicyAction, ActivePolicy>>,
        whitelist_networks: std::sync::Weak<RwLock<WhitelistNetworks>>,
        _bandwidth_limit: std::sync::Weak<RwLock<Option<BandwidthLimitConfig>>>,
        stats_manager: std::sync::Weak<StatsManager>,
        network_name: String,
    ) {
        let mut check_interval = interval(Duration::from_secs(10));
        let mut reset_check_interval = interval(Duration::from_secs(3600));

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    let Some(stats_mgr) = stats_manager.upgrade() else { break; };
                    let Some(t_stats) = traffic_stats.upgrade() else { break; };
                    let Some(cfg) = config.upgrade() else { break; };
                    let Some(policies) = active_policies.upgrade() else { break; };
                    let Some(whitelist) = whitelist_networks.upgrade() else { break; };

                    Self::update_traffic_stats_static(&stats_mgr, &t_stats, &network_name).await;
                    Self::check_and_apply_policies_static(&cfg, &t_stats, &policies, &whitelist).await;
                }
                _ = reset_check_interval.tick() => {
                    let Some(cfg) = config.upgrade() else { break; };
                    let Some(t_stats) = traffic_stats.upgrade() else { break; };
                    let Some(policies) = active_policies.upgrade() else { break; };
                    let Some(whitelist) = whitelist_networks.upgrade() else { break; };

                    Self::check_reset_static(&cfg, &t_stats, &policies, &whitelist).await;
                }
            }
        }
    }

    /// 静态方法：更新流量统计
    async fn update_traffic_stats_static(
        stats_manager: &StatsManager,
        traffic_stats: &RwLock<TrafficStats>,
        network_name: &str,
    ) {
        let label_set = LabelSet::new()
            .with_label("network_name", network_name.to_string());

        let tx_bytes = stats_manager
            .get_metric(MetricName::TrafficBytesTx, &label_set)
            .map(|m| m.value)
            .unwrap_or(0);

        let rx_bytes = stats_manager
            .get_metric(MetricName::TrafficBytesRx, &label_set)
            .map(|m| m.value)
            .unwrap_or(0);

        let mut stats = traffic_stats.write().await;
        stats.tx_bytes = tx_bytes;
        stats.rx_bytes = rx_bytes;
        stats.total_bytes = tx_bytes + rx_bytes;
    }

    /// 静态方法：检查并应用策略
    async fn check_and_apply_policies_static(
        config: &RwLock<Option<FlowPolicyConfig>>,
        traffic_stats: &RwLock<TrafficStats>,
        active_policies: &DashMap<FlowPolicyAction, ActivePolicy>,
        whitelist_networks: &RwLock<WhitelistNetworks>,
    ) {
        let cfg = config.read().await;
        let Some(ref policy_config) = *cfg else {
            return;
        };

        // 检查是否启用流量统计
        if !policy_config.enable_traffic_stats {
            return;
        }

        let stats = traffic_stats.read().await;
        let total_gb = stats.total_gb();

        // 清除所有当前激活的策略
        active_policies.clear();

        // 检查每个规则
        for rule in &policy_config.rules {
            if total_gb >= rule.traffic_threshold_gb {
                Self::apply_policy_static(rule.clone(), active_policies, whitelist_networks).await;
            }
        }
    }

    /// 静态方法：应用策略
    async fn apply_policy_static(
        rule: FlowPolicyRule,
        active_policies: &DashMap<FlowPolicyAction, ActivePolicy>,
        whitelist_networks: &RwLock<WhitelistNetworks>,
    ) {
        let action = FlowPolicyAction::try_from(rule.action).unwrap_or(FlowPolicyAction::LimitBandwidth);

        match action {
            FlowPolicyAction::AddNetworkWhitelist => {
                // 添加白名单网络
                let mut whitelist = whitelist_networks.write().await;
                for network in &rule.whitelist_networks {
                    whitelist.networks.insert(network.clone());
                }
                tracing::info!(
                    "Added network whitelist: {:?}",
                    rule.whitelist_networks
                );
            }
            _ => {
                let bandwidth_limiter = if action == FlowPolicyAction::LimitBandwidth {
                    if let Some(bandwidth_mbps) = rule.bandwidth_limit_mbps {
                        let bps = (bandwidth_mbps * 1024.0 * 1024.0 / 8.0) as u64;
                        let capacity = bps * 2;
                        let refill_interval = Duration::from_millis(100);
                        Some(TokenBucket::new(capacity, bps, refill_interval))
                    } else {
                        None
                    }
                } else {
                    None
                };

                let active_policy = ActivePolicy {
                    rule: rule.clone(),
                    bandwidth_limiter,
                };

                active_policies.insert(action, active_policy);
            }
        }

        tracing::info!(
            "Applied flow policy: action={:?}, threshold={}GB",
            action,
            rule.traffic_threshold_gb
        );
    }

    /// 静态方法：检查是否需要重置（支持按天数和按月重置）
    async fn check_reset_static(
        config: &RwLock<Option<FlowPolicyConfig>>,
        traffic_stats: &RwLock<TrafficStats>,
        active_policies: &DashMap<FlowPolicyAction, ActivePolicy>,
        whitelist_networks: &RwLock<WhitelistNetworks>,
    ) {
        let cfg = config.read().await;
        let Some(ref policy_config) = *cfg else {
            return;
        };

        // 检查是否启用流量统计
        if !policy_config.enable_traffic_stats {
            return;
        }

        let reset_by_days = policy_config.reset_by_days;
        let reset_day = policy_config.monthly_reset_day;

        // 如果都不设置，则不自动重置
        if reset_by_days <= 0 && (reset_day < 1 || reset_day > 31) {
            return;
        }

        let stats = traffic_stats.read().await;
        let last_reset = stats.last_reset_time;
        drop(stats);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let days_since_reset = (now - last_reset) / (24 * 3600);

        let should_reset = if reset_by_days > 0 {
            // 按天数重置
            days_since_reset >= reset_by_days as u64
        } else {
            // 按月重置：检查当前日期是否 >= reset_day 且上次重置不在本月
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            // 获取当前日（1-31）通过 Unix timestamp
            let current_day_of_month = {
                // 从 Unix 时间戳计算当前日期
                let secs = now_secs as i64;
                let days = secs / 86400;
                // Zeller-like calculation for day of month
                let mut y = 1970i64;
                let mut remaining_days = days;
                loop {
                    let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
                    if remaining_days < days_in_year {
                        break;
                    }
                    remaining_days -= days_in_year;
                    y += 1;
                }
                let is_leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
                let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                let mut _month = 0u32;
                for md in month_days.iter() {
                    if remaining_days < *md as i64 {
                        break;
                    }
                    remaining_days -= *md as i64;
                    _month += 1;
                }
                (remaining_days + 1) as i32 // day of month (1-based)
            };
            // 如果当前日 >= 重置日 且距上次重置超过25天（避免同月重复重置）
            current_day_of_month >= reset_day && days_since_reset >= 25
        };

        if should_reset {
            let mut stats = traffic_stats.write().await;
            stats.reset();
            drop(stats);

            // 清除激活的策略和白名单
            active_policies.clear();
            whitelist_networks.write().await.clear();

            tracing::info!(
                "Traffic stats reset (type: {}, days since last reset: {})",
                if reset_by_days > 0 { "by_days" } else { "monthly" },
                days_since_reset
            );
        }
    }

    /// 重置流量统计
    pub async fn reset_traffic_stats(&self) {
        let mut stats = self.traffic_stats.write().await;
        stats.reset();

        // 清除激活的策略和白名单
        self.active_policies.clear();
        self.whitelist_networks.write().await.clear();

        tracing::info!("Traffic stats reset (manual)");
    }

    /// 获取流量统计
    pub async fn get_traffic_stats(&self) -> TrafficStats {
        self.traffic_stats.read().await.clone()
    }

    /// 获取流量统计信息（用于RPC响应）
    pub async fn get_traffic_stats_info(&self) -> TrafficStatsInfo {
        let stats = self.traffic_stats.read().await.clone();
        let config = self.config.read().await.clone();
        
        let (reset_day, reset_by_days, is_reset_by_days) = if let Some(ref cfg) = config {
            (cfg.monthly_reset_day, cfg.reset_by_days, cfg.reset_by_days > 0)
        } else {
            (0, 0, false)
        };

        TrafficStatsInfo {
            tx_bytes: stats.tx_bytes,
            rx_bytes: stats.rx_bytes,
            total_bytes: stats.total_bytes,
            total_gb: stats.total_gb(),
            last_reset_time: stats.last_reset_time,
            is_reset_by_days,
            reset_day,
            reset_by_days,
        }
    }

    /// 获取激活的策略状态列表（用于RPC响应）
    pub async fn get_policy_states(&self) -> Vec<PolicyStateInfo> {
        self.active_policies
            .iter()
            .map(|entry| {
                let action = *entry.key();
                let policy = entry.value();
                let current_bandwidth = policy.bandwidth_limiter.as_ref().map(|_tb| {
                    // 估算当前带宽限制（简化实现）
                    0.0 // TODO: 实现真实的带宽计算
                });
                PolicyStateInfo {
                    action: action as i32,
                    rule: Some(policy.rule.clone()),
                    is_active: true,
                    current_bandwidth_limit_mbps: current_bandwidth,
                }
            })
            .collect()
    }

    /// 更新配置
    pub async fn update_config(&self, new_config: Option<FlowPolicyConfig>) {
        let mut config = self.config.write().await;
        *config = new_config.clone();
        drop(config);

        // 立即检查并应用策略
        let whitelist = self.whitelist_networks.clone();
        Self::check_and_apply_policies_static(&self.config, &self.traffic_stats, &self.active_policies, &whitelist).await;
    }

    /// 设置带宽限制配置（直接限速，非策略触发）
    pub async fn set_bandwidth_limit(&self, limit: Option<BandwidthLimitConfig>) {
        let mut bw_limit = self.bandwidth_limit.write().await;
        *bw_limit = limit.clone();
        drop(bw_limit);

        // 根据配置创建或清除直接限速的 TokenBucket
        let limiter = if let Some(ref cfg) = limit {
            // 取两者中较小的非零值作为总限速（更保守）
            let current = cfg.current_network_limit_mbps.unwrap_or(0.0);
            let other = cfg.other_network_limit_mbps.unwrap_or(0.0);
            let limit_mbps = match (current > 0.0, other > 0.0) {
                (true, true) => current.min(other),
                (true, false) => current,
                (false, true) => other,
                (false, false) => 0.0,
            };
            if limit_mbps > 0.0 {
                let bps = (limit_mbps * 1024.0 * 1024.0 / 8.0) as u64; // Mbps -> Bytes/s
                let capacity = bps * 2; // burst容量为2秒
                let refill_interval = Duration::from_millis(100);
                Some(TokenBucket::new(capacity, bps, refill_interval))
            } else {
                None
            }
        } else {
            None
        };

        *self.direct_bandwidth_limiter.write().unwrap() = limiter;
    }

    /// 获取带宽限制配置
    pub async fn get_bandwidth_limit(&self) -> Option<BandwidthLimitConfig> {
        self.bandwidth_limit.read().await.clone()
    }

    /// 检查是否应该限制带宽（优先返回策略限速，否则返回直接限速）
    pub fn should_limit_bandwidth(&self) -> Option<Arc<TokenBucket>> {
        // 优先检查策略触发的限速
        if let Some(policy_limiter) = self.active_policies
            .get(&FlowPolicyAction::LimitBandwidth)
            .and_then(|policy| policy.bandwidth_limiter.clone())
        {
            return Some(policy_limiter);
        }
        // 否则检查直接带宽限制
        self.direct_bandwidth_limiter
            .read()
            .unwrap()
            .clone()
    }

    /// 检查是否应该禁用中转
    pub fn should_disable_relay(&self) -> bool {
        self.active_policies.contains_key(&FlowPolicyAction::DisableRelay)
    }

    /// 检查是否应该禁用公共转发
    pub fn should_disable_public_forward(&self) -> bool {
        self.active_policies.contains_key(&FlowPolicyAction::DisablePublicForward)
    }

    /// 检查公共转发是否被禁用，但网络在白名单中（同步版本，用于热路径）
    /// 返回 true 表示应该禁止转发
    pub fn should_block_public_forward_for_network(&self, network_name: &str) -> bool {
        if !self.should_disable_public_forward() {
            return false;
        }
        // 尝试非阻塞读取白名单
        match self.whitelist_networks.try_read() {
            Ok(whitelist) => {
                // 白名单为空 = 全部禁止；白名单非空 = 只有在白名单中的不禁止
                if whitelist.networks.is_empty() {
                    true // 白名单为空时禁止所有
                } else {
                    !whitelist.networks.contains(network_name) // 不在白名单中则禁止
                }
            }
            Err(_) => true, // 无法获取锁时保守禁止
        }
    }

    /// 检查是否应该禁用网络
    pub fn should_disable_network(&self) -> bool {
        self.active_policies.contains_key(&FlowPolicyAction::DisableNetwork)
    }

    /// 检查网络是否在白名单中
    pub async fn is_network_whitelisted(&self, network_name: &str) -> bool {
        let whitelist = self.whitelist_networks.read().await;
        // 如果白名单为空，表示不启用白名单限制
        whitelist.networks.is_empty() || whitelist.networks.contains(network_name)
    }

    /// 检查网络是否被禁用
    pub async fn is_network_allowed(&self, network_name: &str) -> bool {
        // 如果激活了DisableNetwork策略，检查白名单
        if self.should_disable_network() {
            self.is_network_whitelisted(network_name).await
        } else {
            true
        }
    }

    /// 获取当前激活的策略列表
    pub fn get_active_policies(&self) -> Vec<(FlowPolicyAction, FlowPolicyRule)> {
        self.active_policies
            .iter()
            .map(|entry| (*entry.key(), entry.value().rule.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_traffic_stats() {
        let mut stats = TrafficStats::default();
        assert_eq!(stats.total_bytes, 0);

        stats.add_traffic(1024 * 1024 * 1024, 1024 * 1024 * 1024); // 1GB + 1GB
        assert_eq!(stats.total_gb(), 2.0);

        stats.reset();
        assert_eq!(stats.total_bytes, 0);
    }

    #[tokio::test]
    async fn test_flow_policy_manager_creation() {
        let stats_manager = Arc::new(StatsManager::new());
        let config = Some(FlowPolicyConfig {
            rules: vec![],
            monthly_reset_day: 1,
            reset_by_days: 0,
            enable_traffic_stats: true,
        });

        let manager = FlowPolicyManager::new(
            config,
            stats_manager,
            "test_network".to_string(),
        );

        let stats = manager.get_traffic_stats().await;
        assert_eq!(stats.total_bytes, 0);
    }

    #[tokio::test]
    async fn test_policy_application() {
        let stats_manager = Arc::new(StatsManager::new());
        
        let rule = FlowPolicyRule {
            traffic_threshold_gb: 1.0,
            action: FlowPolicyAction::LimitBandwidth as i32,
            bandwidth_limit_mbps: Some(10.0),
            whitelist_networks: vec![],
        };

        let config = Some(FlowPolicyConfig {
            rules: vec![rule],
            monthly_reset_day: 1,
            reset_by_days: 0,
            enable_traffic_stats: true,
        });

        let manager = FlowPolicyManager::new(
            config,
            stats_manager,
            "test_network".to_string(),
        );

        // 初始状态不应该有激活的策略
        assert!(!manager.should_disable_relay());
        assert!(!manager.should_disable_public_forward());
    }

    #[tokio::test]
    async fn test_whitelist_networks() {
        let whitelist = WhitelistNetworks::new(vec![
            "network1".to_string(),
            "network2".to_string(),
        ]);

        assert!(whitelist.contains("network1"));
        assert!(whitelist.contains("network2"));
        assert!(!whitelist.contains("network3"));

        // 空白名单表示不限制
        let empty_whitelist = WhitelistNetworks::default();
        assert!(empty_whitelist.contains("any_network"));
    }
}
