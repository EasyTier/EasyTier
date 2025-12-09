use crate::api::CreateNodeRequest;
use crate::db::entity::*;
use crate::db::Db;
use crate::db::HealthStats;
use crate::db::HealthStatus;
use sea_orm::*;
use std::collections::{HashMap, HashSet};

/// 节点管理操作
pub struct NodeOperations;

impl NodeOperations {
    pub fn create_node_model(req: CreateNodeRequest) -> shared_nodes::ActiveModel {
        shared_nodes::ActiveModel {
            id: NotSet,
            name: Set(req.name),
            host: Set(req.host),
            port: Set(req.port),
            protocol: Set(req.protocol),
            version: Set("".to_string()),
            description: Set(req.description.unwrap_or_default()),
            max_connections: Set(req.max_connections),
            current_connections: Set(0),
            is_active: Set(false),
            is_approved: Set(false),
            allow_relay: Set(req.allow_relay),
            network_name: Set(req.network_name),
            network_secret: Set(req.network_secret.unwrap_or_default()),
            qq_number: Set(req.qq_number.unwrap_or_default()),
            wechat: Set(req.wechat.unwrap_or_default()),
            mail: Set(req.mail.unwrap_or_default()),
            created_at: Set(chrono::Utc::now().fixed_offset()),
            updated_at: Set(chrono::Utc::now().fixed_offset()),
        }
    }

    /// 创建新节点
    pub async fn create_node(
        db: &Db,
        req: CreateNodeRequest,
    ) -> Result<shared_nodes::Model, DbErr> {
        let node = Self::create_node_model(req);
        let insert_result = shared_nodes::Entity::insert(node).exec(db.orm_db()).await?;

        shared_nodes::Entity::find_by_id(insert_result.last_insert_id)
            .one(db.orm_db())
            .await?
            .ok_or(DbErr::RecordNotFound(
                "Failed to retrieve created node".to_string(),
            ))
    }

    /// 获取所有节点
    pub async fn get_all_nodes(db: &Db) -> Result<Vec<shared_nodes::Model>, DbErr> {
        shared_nodes::Entity::find()
            .order_by_asc(shared_nodes::Column::Id)
            .all(db.orm_db())
            .await
    }

    /// 根据ID获取节点
    pub async fn get_node_by_id(db: &Db, id: i32) -> Result<Option<shared_nodes::Model>, DbErr> {
        shared_nodes::Entity::find_by_id(id).one(db.orm_db()).await
    }

    /// 更新节点状态
    pub async fn update_node_status(
        db: &Db,
        id: i32,
        is_active: bool,
        current_connections: Option<i32>,
    ) -> Result<shared_nodes::Model, DbErr> {
        let mut node = shared_nodes::Entity::find_by_id(id)
            .one(db.orm_db())
            .await?
            .ok_or(DbErr::RecordNotFound("Node not found".to_string()))?;

        let mut node = node.into_active_model();

        node.is_active = Set(is_active);
        if let Some(connections) = current_connections {
            node.current_connections = Set(connections);
        }
        node.updated_at = Set(chrono::Utc::now().fixed_offset());

        let updated_node = shared_nodes::Entity::update(node).exec(db.orm_db()).await?;

        Ok(updated_node)
    }

    /// 删除节点
    pub async fn delete_node(db: &Db, id: i32) -> Result<u64, DbErr> {
        let result = shared_nodes::Entity::delete_by_id(id)
            .exec(db.orm_db())
            .await?;
        Ok(result.rows_affected)
    }

    /// 获取活跃节点
    pub async fn get_active_nodes(db: &Db) -> Result<Vec<shared_nodes::Model>, DbErr> {
        shared_nodes::Entity::find()
            .filter(shared_nodes::Column::IsActive.eq(true))
            .order_by_asc(shared_nodes::Column::Id)
            .all(db.orm_db())
            .await
    }

    /// 检查节点是否存在（根据host、port、protocol）
    pub async fn node_exists(
        db: &Db,
        host: &str,
        port: i32,
        protocol: &str,
    ) -> Result<bool, DbErr> {
        let count = shared_nodes::Entity::find()
            .filter(shared_nodes::Column::Host.eq(host))
            .filter(shared_nodes::Column::Port.eq(port))
            .filter(shared_nodes::Column::Protocol.eq(protocol))
            .count(db.orm_db())
            .await?;

        Ok(count > 0)
    }

    pub async fn update_node_version(
        db: &Db,
        node_id: i32,
        version: String,
    ) -> Result<shared_nodes::Model, DbErr> {
        let mut node = shared_nodes::Entity::find_by_id(node_id)
            .one(db.orm_db())
            .await?
            .ok_or(DbErr::RecordNotFound("Node not found".to_string()))?;

        let mut node = node.into_active_model();

        node.version = Set(version);
        node.updated_at = Set(chrono::Utc::now().fixed_offset());

        let updated_node = shared_nodes::Entity::update(node).exec(db.orm_db()).await?;

        Ok(updated_node)
    }
}

/// 健康记录操作
pub struct HealthOperations;

impl HealthOperations {
    /// 创建健康记录
    pub async fn create_health_record(
        db: &Db,
        node_id: i32,
        status: HealthStatus,
        response_time: Option<i32>,
        error_message: Option<String>,
    ) -> Result<health_records::Model, DbErr> {
        let record =
            health_records::Model::new_active_model(node_id, status, response_time, error_message);

        let insert_result = health_records::Entity::insert(record)
            .exec(db.orm_db())
            .await?;

        health_records::Entity::find_by_id(insert_result.last_insert_id)
            .one(db.orm_db())
            .await?
            .ok_or(DbErr::RecordNotFound(
                "Failed to retrieve created health record".to_string(),
            ))
    }

    /// 获取节点的健康记录
    pub async fn get_node_health_records(
        db: &Db,
        node_id: i32,
        from_date: Option<chrono::NaiveDateTime>,
        limit: Option<u64>,
    ) -> Result<Vec<health_records::Model>, DbErr> {
        let mut query = health_records::Entity::find()
            .filter(health_records::Column::NodeId.eq(node_id))
            .order_by_desc(health_records::Column::CheckedAt);

        if let Some(from_date) = from_date {
            query = query.filter(health_records::Column::CheckedAt.gte(from_date));
        }

        if let Some(limit) = limit {
            query = query.limit(Some(limit));
        }

        query.all(db.orm_db()).await
    }

    /// 获取节点最近的健康状态
    pub async fn get_latest_health_status(
        db: &Db,
        node_id: i32,
    ) -> Result<Option<health_records::Model>, DbErr> {
        health_records::Entity::find()
            .filter(health_records::Column::NodeId.eq(node_id))
            .order_by_desc(health_records::Column::CheckedAt)
            .one(db.orm_db())
            .await
    }

    /// 获取健康统计信息
    pub async fn get_health_stats(db: &Db, node_id: i32, hours: i64) -> Result<HealthStats, DbErr> {
        let since = chrono::Utc::now().naive_utc() - chrono::Duration::hours(hours);

        let records = health_records::Entity::find()
            .filter(health_records::Column::NodeId.eq(node_id))
            .filter(health_records::Column::CheckedAt.gte(since))
            .order_by_desc(health_records::Column::CheckedAt)
            .all(db.orm_db())
            .await?;

        Ok(HealthStats::from_records(&records))
    }

    /// 清理旧的健康记录
    pub async fn cleanup_old_records(db: &Db, days: i64) -> Result<u64, DbErr> {
        let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::days(days);

        let result = health_records::Entity::delete_many()
            .filter(health_records::Column::CheckedAt.lt(cutoff))
            .exec(db.orm_db())
            .await?;

        Ok(result.rows_affected)
    }
}
impl NodeOperations {
    /// 获取节点的全部标签
    pub async fn get_node_tags(db: &Db, node_id: i32) -> Result<Vec<String>, DbErr> {
        let tags = node_tags::Entity::find()
            .filter(node_tags::Column::NodeId.eq(node_id))
            .all(db.orm_db())
            .await?;
        Ok(tags.into_iter().map(|m| m.tag).collect())
    }

    /// 批量获取节点的标签映射
    pub async fn get_nodes_tags_map(
        db: &Db,
        node_ids: &[i32],
    ) -> Result<HashMap<i32, Vec<String>>, DbErr> {
        if node_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let tags = node_tags::Entity::find()
            .filter(node_tags::Column::NodeId.is_in(node_ids.to_vec()))
            .order_by_asc(node_tags::Column::NodeId)
            .all(db.orm_db())
            .await?;
        let mut map: HashMap<i32, Vec<String>> = HashMap::new();
        for t in tags {
            map.entry(t.node_id).or_default().push(t.tag);
        }
        Ok(map)
    }

    /// 使用标签过滤节点（返回节点ID）
    pub async fn filter_node_ids_by_tag(db: &Db, tag: &str) -> Result<Vec<i32>, DbErr> {
        let tagged = node_tags::Entity::find()
            .filter(node_tags::Column::Tag.eq(tag))
            .all(db.orm_db())
            .await?;
        Ok(tagged.into_iter().map(|m| m.node_id).collect())
    }

    /// 设置节点标签（替换为给定集合）
    pub async fn set_node_tags(db: &Db, node_id: i32, tags: Vec<String>) -> Result<(), DbErr> {
        // 去重与清理空白
        let mut set: HashSet<String> = HashSet::new();
        for tag in tags.into_iter() {
            let trimmed = tag.trim();
            if !trimmed.is_empty() {
                set.insert(trimmed.to_string());
            }
        }

        // 取出当前标签
        let existing = node_tags::Entity::find()
            .filter(node_tags::Column::NodeId.eq(node_id))
            .all(db.orm_db())
            .await?;

        let existing_set: HashSet<String> = existing.iter().map(|m| m.tag.clone()).collect();

        // 需要删除的
        let to_delete: Vec<i32> = existing
            .iter()
            .filter(|m| !set.contains(&m.tag))
            .map(|m| m.id)
            .collect();

        // 需要新增的
        let to_insert: Vec<String> = set
            .into_iter()
            .filter(|t| !existing_set.contains(t))
            .collect();

        // 执行删除
        if !to_delete.is_empty() {
            node_tags::Entity::delete_many()
                .filter(node_tags::Column::Id.is_in(to_delete))
                .exec(db.orm_db())
                .await?;
        }

        // 执行新增
        for t in to_insert {
            let now = chrono::Utc::now().fixed_offset();
            let am = node_tags::ActiveModel {
                id: NotSet,
                node_id: Set(node_id),
                tag: Set(t),
                created_at: Set(now),
            };
            node_tags::Entity::insert(am).exec(db.orm_db()).await?;
        }

        Ok(())
    }

    // 新增：获取所有唯一标签（按字母排序）
    pub async fn get_all_tags(db: &Db) -> Result<Vec<String>, DbErr> {
        let rows = node_tags::Entity::find().all(db.orm_db()).await?;
        let mut set: HashSet<String> = HashSet::new();
        for r in rows {
            set.insert(r.tag);
        }
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        Ok(list)
    }

    // 新增：使用多标签（OR 语义）过滤节点，返回匹配的节点ID
    pub async fn filter_node_ids_by_tags_any(db: &Db, tags: &[String]) -> Result<Vec<i32>, DbErr> {
        if tags.is_empty() {
            return Ok(vec![]);
        }
        let tagged = node_tags::Entity::find()
            .filter(node_tags::Column::Tag.is_in(tags.to_vec()))
            .all(db.orm_db())
            .await?;
        let mut set: HashSet<i32> = HashSet::new();
        for m in tagged {
            set.insert(m.node_id);
        }
        Ok(set.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[tokio::test]
    async fn test_node_operations() {
        let db = Db::memory_db().await;

        let req = CreateNodeRequest {
            name: "Test Node".to_string(),
            host: "test.example.com".to_string(),
            port: 11010,
            protocol: "tcp".to_string(),
            description: Some("Test node".to_string()),
            max_connections: 100,
            allow_relay: false,
            network_name: "test-network".to_string(),
            network_secret: Some("test-secret".to_string()),
            qq_number: Some("123456789".to_string()),
            wechat: Some("test_wechat".to_string()),
            mail: Some("test@example.com".to_string()),
        };

        // 测试创建节点
        let node = NodeOperations::create_node(&db, req).await.unwrap();

        assert_eq!(node.name, "Test Node");
        assert_eq!(node.host, "test.example.com");
        assert_eq!(node.port, 11010);
        assert!(node.is_active);

        // 测试获取节点
        let found_node = NodeOperations::get_node_by_id(&db, node.id).await.unwrap();
        assert!(found_node.is_some());
        assert_eq!(found_node.unwrap().id, node.id);

        // 测试获取所有节点
        let all_nodes = NodeOperations::get_all_nodes(&db).await.unwrap();
        assert_eq!(all_nodes.len(), 1);

        // 测试节点存在性检查
        let exists = NodeOperations::node_exists(&db, "test.example.com", 11010, "tcp")
            .await
            .unwrap();
        assert!(exists);

        let not_exists = NodeOperations::node_exists(&db, "nonexistent.com", 8080, "tcp")
            .await
            .unwrap();
        assert!(!not_exists);
    }

    #[tokio::test]
    async fn test_health_operations() {
        let db = Db::memory_db().await;

        let req = CreateNodeRequest {
            name: "Test Node".to_string(),
            host: "test.example.com".to_string(),
            port: 11010,
            protocol: "tcp".to_string(),
            description: Some("Test node".to_string()),
            max_connections: 100,
            allow_relay: false,
            network_name: "test-network".to_string(),
            network_secret: Some("test-secret".to_string()),
            qq_number: Some("123456789".to_string()),
            wechat: Some("test_wechat".to_string()),
            mail: Some("test@example.com".to_string()),
        };

        // 创建测试节点
        let node = NodeOperations::create_node(&db, req).await.unwrap();
        // 测试创建健康记录
        let record = HealthOperations::create_health_record(
            &db,
            node.id,
            HealthStatus::Healthy,
            Some(100),
            None,
        )
        .await
        .unwrap();

        assert_eq!(record.node_id, node.id);
        assert!(record.is_healthy());
        assert_eq!(record.response_time, 100);

        // 测试获取健康记录
        let records = HealthOperations::get_node_health_records(&db, node.id, None, None)
            .await
            .unwrap();
        assert_eq!(records.len(), 1);

        // 测试获取最新状态
        let latest = HealthOperations::get_latest_health_status(&db, node.id)
            .await
            .unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().id, record.id);

        // 测试健康统计
        let stats = HealthOperations::get_health_stats(&db, node.id, 24)
            .await
            .unwrap();
        assert_eq!(stats.total_checks, 1);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.health_percentage, 100.0);
    }
}
