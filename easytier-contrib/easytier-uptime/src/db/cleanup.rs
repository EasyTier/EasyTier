use crate::db::entity::*;
use crate::db::Db;
use sea_orm::*;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// 数据清理策略配置
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// 健康记录保留天数
    pub health_record_retention_days: i64,
    /// 每个节点保留的健康记录最大数量
    pub max_health_records_per_node: u64,
    /// 清理任务运行间隔（秒）
    pub cleanup_interval_seconds: u64,
    /// 是否启用自动清理
    pub auto_cleanup_enabled: bool,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            health_record_retention_days: 30,
            max_health_records_per_node: 70000,
            cleanup_interval_seconds: 1200, // 20分钟
            auto_cleanup_enabled: true,
        }
    }
}

/// 数据清理管理器
pub struct CleanupManager {
    db: Db,
    config: CleanupConfig,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CleanupManager {
    /// 创建新的清理管理器
    pub fn new(db: Db, config: CleanupConfig) -> Self {
        Self {
            db,
            config,
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// 使用默认配置创建清理管理器
    pub fn with_default_config(db: Db) -> Self {
        Self::new(db, CleanupConfig::default())
    }

    /// 启动自动清理任务
    pub async fn start_auto_cleanup(&self) -> anyhow::Result<()> {
        if self.config.auto_cleanup_enabled {
            let running = self.running.clone();
            let db = self.db.clone();
            let config = self.config.clone();

            running.store(true, std::sync::atomic::Ordering::SeqCst);

            tokio::spawn(async move {
                info!("Auto cleanup task started");

                while running.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Err(e) = Self::perform_cleanup(&db, &config).await {
                        error!("Auto cleanup failed: {}", e);
                    }

                    sleep(Duration::from_secs(config.cleanup_interval_seconds)).await;
                }

                info!("Auto cleanup task stopped");
            });
        }

        Ok(())
    }

    /// 停止自动清理任务
    pub fn stop_auto_cleanup(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// 执行一次完整的清理操作
    pub async fn perform_cleanup(db: &Db, config: &CleanupConfig) -> anyhow::Result<CleanupResult> {
        let mut result = CleanupResult::default();

        // 清理旧的健康记录
        let health_cleanup_result =
            Self::cleanup_old_health_records(db, config.health_record_retention_days).await?;
        result.old_health_records_cleaned = health_cleanup_result.records_removed;

        // 清理过量的健康记录
        let excess_cleanup_result =
            Self::cleanup_excess_health_records(db, config.max_health_records_per_node).await?;
        result.excess_health_records_cleaned = excess_cleanup_result.records_removed;

        // 数据库维护
        let maintenance_result = Self::perform_database_maintenance(db).await?;
        result.vacuum_performed = maintenance_result.vacuum_performed;
        result.analyze_performed = maintenance_result.analyze_performed;

        info!("Cleanup completed: {:?}", result);

        Ok(result)
    }

    /// 清理旧的健康记录
    async fn cleanup_old_health_records(
        db: &Db,
        days: i64,
    ) -> anyhow::Result<CleanupHealthRecordsResult> {
        let cutoff = chrono::Local::now().fixed_offset() - chrono::Duration::days(days);

        let result = health_records::Entity::delete_many()
            .filter(health_records::Column::CheckedAt.lt(cutoff))
            .exec(db.orm_db())
            .await?;

        let records_removed = result.rows_affected;

        if records_removed > 0 {
            info!(
                "Cleaned {} old health records (older than {} days)",
                records_removed, days
            );
        }

        Ok(CleanupHealthRecordsResult { records_removed })
    }

    /// 清理过量的健康记录
    async fn cleanup_excess_health_records(
        db: &Db,
        max_records: u64,
    ) -> anyhow::Result<CleanupExcessRecordsResult> {
        // 获取所有节点
        let nodes = shared_nodes::Entity::find().all(db.orm_db()).await?;

        let mut total_removed = 0;

        for node in nodes {
            // 计算需要删除的记录数量
            let total_count = health_records::Entity::find()
                .filter(health_records::Column::NodeId.eq(node.id))
                .count(db.orm_db())
                .await?;

            if total_count > max_records {
                let to_remove = total_count - max_records;

                // 获取需要保留的最小ID
                let keep_id = health_records::Entity::find()
                    .filter(health_records::Column::NodeId.eq(node.id))
                    .order_by_desc(health_records::Column::CheckedAt)
                    .offset(max_records)
                    .limit(1)
                    .into_model::<health_records::Model>()
                    .one(db.orm_db())
                    .await?;

                info!(
                    "Node {}: total count: {}, to remove: {}, last keep record: {:?}",
                    node.id, total_count, to_remove, keep_id
                );

                if let Some(keep_record) = keep_id {
                    // 删除比保留记录更早的记录
                    let result = health_records::Entity::delete_many()
                        .filter(health_records::Column::NodeId.eq(node.id))
                        .filter(health_records::Column::Id.lt(keep_record.id))
                        .exec(db.orm_db())
                        .await?;

                    total_removed += result.rows_affected;
                }
            }
        }

        if total_removed > 0 {
            info!(
                "Cleaned {} excess health records (max {} per node)",
                total_removed, max_records
            );
        }

        Ok(CleanupExcessRecordsResult {
            records_removed: total_removed,
        })
    }

    /// 执行数据库维护操作
    async fn perform_database_maintenance(db: &Db) -> anyhow::Result<DatabaseMaintenanceResult> {
        let mut vacuum_performed = false;
        let mut analyze_performed = false;

        // 执行 ANALYZE
        match db
            .orm_db()
            .execute(Statement::from_string(
                DatabaseBackend::Sqlite,
                "ANALYZE".to_string(),
            ))
            .await
        {
            Ok(_) => {
                analyze_performed = true;
                info!("Database ANALYZE completed");
            }
            Err(e) => {
                warn!("Database ANALYZE failed: {}", e);
            }
        }

        // 执行 VACUUM（仅在需要时）
        if vacuum_performed || analyze_performed {
            match db
                .orm_db()
                .execute(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "VACUUM".to_string(),
                ))
                .await
            {
                Ok(_) => {
                    vacuum_performed = true;
                    info!("Database VACUUM completed");
                }
                Err(e) => {
                    warn!("Database VACUUM failed: {}", e);
                }
            }
        }

        Ok(DatabaseMaintenanceResult {
            vacuum_performed,
            analyze_performed,
        })
    }

    /// 获取数据库统计信息
    pub async fn get_database_stats(db: &Db) -> anyhow::Result<DatabaseStats> {
        let total_nodes = shared_nodes::Entity::find().count(db.orm_db()).await?;

        let total_health_records = health_records::Entity::find().count(db.orm_db()).await?;

        let active_nodes = shared_nodes::Entity::find()
            .filter(shared_nodes::Column::IsActive.eq(true))
            .count(db.orm_db())
            .await?;

        Ok(DatabaseStats {
            total_nodes,
            active_nodes,
            total_health_records,
        })
    }

    /// 获取清理配置
    pub fn get_config(&self) -> &CleanupConfig {
        &self.config
    }

    /// 更新清理配置
    pub fn update_config(&mut self, config: CleanupConfig) {
        self.config = config;
    }
}

/// 清理结果
#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct CleanupResult {
    pub old_health_records_cleaned: u64,
    pub old_instances_cleaned: u64,
    pub excess_health_records_cleaned: u64,
    pub vacuum_performed: bool,
    pub analyze_performed: bool,
}

/// 健康记录清理结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanupHealthRecordsResult {
    pub records_removed: u64,
}

/// 停止实例清理结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanupStoppedInstancesResult {
    pub instances_removed: u64,
}

/// 过量记录清理结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanupExcessRecordsResult {
    pub records_removed: u64,
}

/// 数据库维护结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseMaintenanceResult {
    pub vacuum_performed: bool,
    pub analyze_performed: bool,
}

/// 数据库统计信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseStats {
    pub total_nodes: u64,
    pub active_nodes: u64,
    pub total_health_records: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[tokio::test]
    async fn test_cleanup_manager() {
        let db = Db::memory_db().await;
        let cleanup_manager = CleanupManager::with_default_config(db.clone());

        // 测试获取配置
        let config = cleanup_manager.get_config();
        assert_eq!(config.health_record_retention_days, 30);

        // 测试清理操作
        let result = CleanupManager::perform_cleanup(&db, config).await.unwrap();
        println!("Cleanup result: {:?}", result);

        // 测试获取统计信息
        let stats = CleanupManager::get_database_stats(&db).await.unwrap();
        println!("Database stats: {:?}", stats);
    }

    #[tokio::test]
    async fn test_cleanup_config() {
        let config = CleanupConfig {
            health_record_retention_days: 7,
            max_health_records_per_node: 500,
            cleanup_interval_seconds: 1800,
            auto_cleanup_enabled: false,
        };

        let db = Db::memory_db().await;
        let mut cleanup_manager = CleanupManager::new(db, config.clone());

        assert_eq!(cleanup_manager.get_config().health_record_retention_days, 7);

        // 测试更新配置
        let new_config = CleanupConfig::default();
        cleanup_manager.update_config(new_config);
        assert_eq!(
            cleanup_manager.get_config().health_record_retention_days,
            30
        );
    }
}
