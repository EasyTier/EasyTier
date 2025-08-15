use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::Context as _;
use tokio::time::{interval, Interval};
use tracing::{error, info};

use crate::{
    db::{entity::shared_nodes, operations::NodeOperations, Db},
    health_checker::HealthChecker,
};

/// HealthChecker的封装器，用于监控数据库中节点的添加和删除
pub struct HealthCheckerManager {
    health_checker: Arc<HealthChecker>,
    db: Db,
    current_nodes: Arc<tokio::sync::RwLock<HashSet<i32>>>,
    monitor_interval: Duration,
}

impl HealthCheckerManager {
    /// 创建新的HealthCheckerManager实例
    pub fn new(health_checker: Arc<HealthChecker>, db: Db) -> Self {
        Self {
            health_checker,
            db,
            current_nodes: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
            monitor_interval: Duration::from_secs(1), // 默认每1秒检查一次
        }
    }

    /// 设置监控间隔
    pub fn with_monitor_interval(mut self, interval: Duration) -> Self {
        self.monitor_interval = interval;
        self
    }

    /// 启动监控任务
    pub async fn start_monitoring(&self) -> anyhow::Result<()> {
        // 启动定期检查任务
        let health_checker = Arc::clone(&self.health_checker);
        let db = self.db.clone();
        let current_nodes = Arc::clone(&self.current_nodes);
        let monitor_interval = self.monitor_interval;

        tokio::spawn(async move {
            let mut ticker = interval(monitor_interval);
            loop {
                if let Err(e) = Self::check_node_changes(&health_checker, &db, &current_nodes).await
                {
                    tracing::error!("Error checking node changes: {}", e);
                }
                ticker.tick().await;
            }
        });

        Ok(())
    }

    /// 检查节点变化并更新监控
    async fn check_node_changes(
        health_checker: &Arc<HealthChecker>,
        db: &Db,
        current_nodes: &Arc<tokio::sync::RwLock<HashSet<i32>>>,
    ) -> anyhow::Result<()> {
        // 获取数据库中当前的所有节点
        let db_nodes = NodeOperations::get_all_nodes(db)
            .await
            .with_context(|| "Failed to get all nodes from database")?;

        let db_node_ids: HashSet<i32> = db_nodes.iter().map(|node| node.id).collect();

        let mut current_nodes_guard = current_nodes.write().await;

        // 检查新增的节点
        for &node_id in &db_node_ids {
            if !current_nodes_guard.contains(&node_id) {
                // 新节点，添加到监控
                if let Err(e) = health_checker.add_node(node_id).await {
                    error!("Failed to add node {} to health checker: {}", node_id, e);
                    continue;
                }
                current_nodes_guard.insert(node_id);
                info!("Added new node {} to health monitoring", node_id);
            } else if let Err(e) = health_checker.try_update_node(node_id).await {
                error!("Failed to add node {} to health checker: {}", node_id, e);
            }
        }

        // 检查删除的节点
        let nodes_to_remove: Vec<i32> = current_nodes_guard
            .iter()
            .filter(|&&node_id| !db_node_ids.contains(&node_id))
            .copied()
            .collect();

        for node_id in nodes_to_remove {
            // 节点已删除，从监控中移除
            if let Err(e) = health_checker.remove_node(node_id).await {
                error!(
                    "Failed to remove node {} from health checker: {}",
                    node_id, e
                );
                continue;
            }
            current_nodes_guard.remove(&node_id);
            info!("Removed node {} from health monitoring", node_id);
        }

        Ok(())
    }

    /// 手动触发节点变化检查
    pub async fn refresh_nodes(&self) -> anyhow::Result<()> {
        Self::check_node_changes(&self.health_checker, &self.db, &self.current_nodes).await
    }

    /// 获取当前监控的节点数量
    pub async fn get_monitored_node_count(&self) -> usize {
        self.current_nodes.read().await.len()
    }

    /// 获取当前监控的节点ID列表
    pub async fn get_monitored_nodes(&self) -> Vec<i32> {
        self.current_nodes.read().await.iter().copied().collect()
    }

    /// 获取节点的内存健康记录
    pub fn get_node_memory_record(
        &self,
        node_id: i32,
    ) -> Option<crate::health_checker::HealthyMemRecord> {
        self.health_checker.get_node_memory_record(node_id)
    }

    /// 获取节点的健康统计信息
    pub fn get_node_health_stats(
        &self,
        node_id: i32,
        hours: u64,
    ) -> Option<crate::db::HealthStats> {
        self.health_checker.get_node_health_stats(node_id, hours)
    }

    /// 获取所有节点的当前健康状态
    pub fn get_all_nodes_health_status(
        &self,
    ) -> Vec<(i32, crate::db::HealthStatus, Option<String>)> {
        self.health_checker.get_all_nodes_health_status()
    }

    pub async fn test_connection(
        &self,
        node_info: &shared_nodes::Model,
        max_time: Duration,
    ) -> anyhow::Result<()> {
        self.health_checker
            .test_connection(node_info, max_time)
            .await
    }
}
