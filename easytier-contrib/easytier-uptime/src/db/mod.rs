pub mod cleanup;
pub mod entity;
pub mod operations;

use std::fmt;

use sea_orm::{
    prelude::*, sea_query::OnConflict, ColumnTrait as _, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter as _, Set, SqlxSqliteConnector, Statement, TransactionTrait as _,
};
use sea_orm_migration::MigratorTrait as _;
use serde::{Deserialize, Serialize};
use sqlx::{migrate::MigrateDatabase as _, Sqlite, SqlitePool};

use crate::migrator;

#[derive(Debug, Clone)]
pub struct Db {
    db_path: String,
    db: SqlitePool,
    orm_db: DatabaseConnection,
}

impl Db {
    pub async fn new<T: ToString>(db_path: T) -> anyhow::Result<Self> {
        let db = Self::prepare_db(db_path.to_string().as_str()).await?;
        let orm_db = SqlxSqliteConnector::from_sqlx_sqlite_pool(db.clone());

        // 运行数据库迁移
        migrator::Migrator::up(&orm_db, None).await?;

        // 优化 SQLite 性能
        Self::optimize_sqlite(&orm_db).await?;

        Ok(Self {
            db_path: db_path.to_string(),
            db,
            orm_db,
        })
    }

    pub async fn memory_db() -> Self {
        Self::new(":memory:").await.unwrap()
    }

    #[tracing::instrument(ret)]
    async fn prepare_db(db_path: &str) -> anyhow::Result<SqlitePool> {
        if !Sqlite::database_exists(db_path).await.unwrap_or(false) {
            tracing::info!("Database not found, creating a new one");
            Sqlite::create_database(db_path).await?;
        }

        let db = sqlx::pool::PoolOptions::new()
            .max_lifetime(None)
            .idle_timeout(None)
            .connect(db_path)
            .await?;

        Ok(db)
    }

    async fn optimize_sqlite(db: &DatabaseConnection) -> Result<(), DbErr> {
        // 优化 SQLite 性能
        let pragmas = vec![
            "PRAGMA journal_mode = WAL",    // 使用 WAL 模式提高并发性能
            "PRAGMA synchronous = NORMAL",  // 平衡性能和数据安全
            "PRAGMA cache_size = 10000",    // 增加缓存大小
            "PRAGMA temp_store = memory",   // 临时存储使用内存
            "PRAGMA mmap_size = 268435456", // 内存映射大小 256MB
            "PRAGMA foreign_keys = ON",     // 启用外键约束
        ];

        for pragma in pragmas {
            db.execute(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                pragma.to_string(),
            ))
            .await?;
        }

        Ok(())
    }

    pub fn inner(&self) -> SqlitePool {
        self.db.clone()
    }

    pub fn orm_db(&self) -> &DatabaseConnection {
        &self.orm_db
    }

    /// 清理旧的健康度记录（删除30天前的记录）
    pub async fn cleanup_old_health_records(&self) -> Result<u64, DbErr> {
        use chrono::Duration;
        use entity::health_records;

        let cutoff_date = chrono::Utc::now().naive_utc() - Duration::days(30);

        let result = health_records::Entity::delete_many()
            .filter(health_records::Column::CheckedAt.lt(cutoff_date))
            .exec(self.orm_db())
            .await?;

        Ok(result.rows_affected)
    }

    /// 获取数据库统计信息
    pub async fn get_database_stats(&self) -> anyhow::Result<DatabaseStats> {
        use entity::{health_records, shared_nodes};

        let node_count = shared_nodes::Entity::find().count(self.orm_db()).await?;

        let health_record_count = health_records::Entity::find().count(self.orm_db()).await?;

        let active_nodes_count = shared_nodes::Entity::find()
            .filter(shared_nodes::Column::IsActive.eq(true))
            .count(self.orm_db())
            .await?;

        Ok(DatabaseStats {
            total_nodes: node_count,
            active_nodes: active_nodes_count,
            total_health_records: health_record_count,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseStats {
    pub total_nodes: u64,
    pub active_nodes: u64,
    pub total_health_records: u64,
}

/// 健康状态枚举
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// 健康状态
    Healthy,
    /// 不健康状态
    Unhealthy,
    /// 超时状态
    Timeout,
    /// 连接错误
    ConnectionError,
    /// 未知错误
    Unknown,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Timeout => write!(f, "timeout"),
            HealthStatus::ConnectionError => write!(f, "connection_error"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<String> for HealthStatus {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "healthy" => HealthStatus::Healthy,
            "unhealthy" => HealthStatus::Unhealthy,
            "timeout" => HealthStatus::Timeout,
            "connection_error" => HealthStatus::ConnectionError,
            _ => HealthStatus::Unknown,
        }
    }
}

impl From<&str> for HealthStatus {
    fn from(s: &str) -> Self {
        HealthStatus::from(s.to_string())
    }
}

/// 健康统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStats {
    /// 总检查次数
    pub total_checks: u64,
    /// 健康检查次数
    pub healthy_count: u64,
    /// 不健康检查次数
    pub unhealthy_count: u64,
    /// 健康百分比
    pub health_percentage: f64,
    /// 平均响应时间（毫秒）
    pub average_response_time: Option<f64>,
    /// 正常运行时间百分比
    pub uptime_percentage: f64,
    /// 最后检查时间
    pub last_check_time: Option<chrono::DateTime<chrono::Utc>>,
    /// 最后健康状态
    pub last_status: Option<HealthStatus>,
}

impl Default for HealthStats {
    fn default() -> Self {
        Self {
            total_checks: 0,
            healthy_count: 0,
            unhealthy_count: 0,
            health_percentage: 0.0,
            average_response_time: None,
            uptime_percentage: 0.0,
            last_check_time: None,
            last_status: None,
        }
    }
}

impl HealthStats {
    /// 从健康记录列表创建统计信息
    pub fn from_records(records: &[self::entity::health_records::Model]) -> Self {
        if records.is_empty() {
            return Self::default();
        }

        let total_checks = records.len() as u64;
        let healthy_count = records.iter().filter(|r| r.is_healthy()).count() as u64;
        let unhealthy_count = total_checks - healthy_count;

        let health_percentage = if total_checks > 0 {
            (healthy_count as f64 / total_checks as f64) * 100.0
        } else {
            0.0
        };

        // 计算平均响应时间（只计算健康状态的记录）
        let healthy_records: Vec<_> = records
            .iter()
            .filter(|r| r.is_healthy() && r.response_time > 0)
            .collect();

        let average_response_time = if !healthy_records.is_empty() {
            let total_time: i32 = healthy_records.iter().map(|r| r.response_time).sum();
            Some(total_time as f64 / healthy_records.len() as f64)
        } else {
            None
        };

        // 正常运行时间百分比（基于健康状态）
        let uptime_percentage = health_percentage;

        // 获取最后的检查信息
        let last_record = records.first(); // records 应该按时间倒序排列
        let last_check_time = last_record.map(|r| r.checked_at.into());
        let last_status = last_record.map(|r| HealthStatus::from(r.status.clone()));

        Self {
            total_checks,
            healthy_count,
            unhealthy_count,
            health_percentage,
            average_response_time,
            uptime_percentage,
            last_check_time,
            last_status,
        }
    }
}

/// Model 的扩展方法
impl entity::health_records::Model {
    /// 检查记录是否为健康状态
    pub fn is_healthy(&self) -> bool {
        let status = HealthStatus::from(self.status.clone());
        matches!(status, HealthStatus::Healthy)
    }

    /// 创建新的活动模型
    pub fn new_active_model(
        node_id: i32,
        status: HealthStatus,
        response_time: Option<i32>,
        error_message: Option<String>,
    ) -> entity::health_records::ActiveModel {
        entity::health_records::ActiveModel {
            node_id: Set(node_id),
            status: Set(status.to_string()),
            response_time: Set(response_time.unwrap_or(0)),
            error_message: Set(error_message.unwrap_or_default()),
            checked_at: Set(chrono::Utc::now().fixed_offset()),
            ..Default::default()
        }
    }

    /// 获取健康状态
    pub fn get_status(&self) -> HealthStatus {
        HealthStatus::from(self.status.clone())
    }
}

/// Model 的扩展方法
impl entity::shared_nodes::Model {
    /// 创建新的活动模型
    #[allow(clippy::too_many_arguments)]
    pub fn new_active_model(
        name: String,
        host: String,
        port: i32,
        protocol: String,
        version: Option<String>,
        description: Option<String>,
        max_connections: i32,
        allow_relay: bool,
        network_name: String,
        network_secret: Option<String>,
    ) -> entity::shared_nodes::ActiveModel {
        let now = chrono::Utc::now().fixed_offset();
        entity::shared_nodes::ActiveModel {
            name: Set(name),
            host: Set(host),
            port: Set(port),
            protocol: Set(protocol),
            version: Set(version.unwrap_or_default()),
            description: Set(description.unwrap_or_default()),
            max_connections: Set(max_connections),
            current_connections: Set(0),
            is_active: Set(true),
            is_approved: Set(false),
            allow_relay: Set(allow_relay),
            network_name: Set(network_name),
            network_secret: Set(network_secret.unwrap_or_default()),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter as _};

    #[tokio::test]
    async fn test_database_creation() {
        let db = Db::memory_db().await;
        let stats = db.get_database_stats().await.unwrap();

        // 初始状态下应该没有记录
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.active_nodes, 0);
        assert_eq!(stats.total_health_records, 0);
    }
}
