use std::{
    ops::{DerefMut, Div},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use dashmap::DashMap;
use easytier::{
    common::{
        config::{ConfigLoader, NetworkIdentity, PeerConfig, TomlConfigLoader},
        scoped_task::ScopedTask,
    },
    defer,
    instance_manager::NetworkInstanceManager,
    launcher::ConfigSource,
};
use serde::{Deserialize, Serialize};
use sqlx::any;
use tracing::{debug, error, info, instrument, warn};

use crate::db::{
    entity::shared_nodes,
    operations::{HealthOperations, NodeOperations},
    Db, HealthStatus,
};

pub struct HealthCheckOneNode {
    node_id: String,
}

const HEALTH_CHECK_RING_GRANULARITY_SEC: usize = 60 * 15; // 15分钟
const HEALTH_CHECK_RING_MAX_DURATION_SEC: usize = 60 * 60 * 24; // 最多一天

// const HEALTH_CHECK_RING_GRANULARITY_SEC: usize = 10;
// const HEALTH_CHECK_RING_MAX_DURATION_SEC: usize = 60;

const HEALTH_CHECK_RING_SIZE: usize =
    HEALTH_CHECK_RING_MAX_DURATION_SEC / HEALTH_CHECK_RING_GRANULARITY_SEC;

#[derive(Debug, Default, Clone)]
struct RingItem {
    counter: u64,
    round: u64,
}

impl RingItem {
    fn try_update_round(&mut self, timestamp: u64) {
        let cur_round =
            timestamp.div((HEALTH_CHECK_RING_GRANULARITY_SEC * HEALTH_CHECK_RING_SIZE) as u64);
        if self.round != cur_round {
            self.round = cur_round;
            self.counter = 0;
        }
    }

    fn inc(&mut self, timestamp: u64) {
        self.try_update_round(timestamp);
        self.counter += 1;
    }

    fn get(&mut self, timestamp: u64) -> u64 {
        self.try_update_round(timestamp);
        self.counter
    }
}

#[derive(Debug, Clone)]
pub struct HealthyMemRecord {
    node_id: i32,
    current_health_status: HealthStatus,
    last_error_info: Option<String>,
    last_check_time: chrono::DateTime<chrono::Utc>,
    last_response_time: Option<i32>,

    // the current time is corresponding to the index by modulo with UNIX-timestamp.
    total_check_counter_ring: Vec<RingItem>,
    healthy_counter_ring: Vec<RingItem>,
}

impl HealthyMemRecord {
    pub fn new(node_id: i32) -> Self {
        Self {
            node_id,
            current_health_status: HealthStatus::Unknown,
            last_error_info: None,
            last_check_time: chrono::Utc::now(),
            last_response_time: None,
            total_check_counter_ring: vec![Default::default(); HEALTH_CHECK_RING_SIZE],
            healthy_counter_ring: vec![Default::default(); HEALTH_CHECK_RING_SIZE],
        }
    }

    /// 从数据库记录初始化内存记录
    pub fn from_db_records(
        node_id: i32,
        records: &[crate::db::entity::health_records::Model],
    ) -> Self {
        let mut mem_record = Self::new(node_id);

        if let Some(latest) = records.first() {
            mem_record.current_health_status = latest.get_status();
            mem_record.last_check_time = latest.checked_at.to_utc();
            mem_record.last_response_time = if latest.response_time == 0 {
                None
            } else {
                Some(latest.response_time)
            };
            mem_record.last_error_info = if latest.error_message.is_empty() {
                None
            } else {
                Some(latest.error_message.clone())
            };
        }

        // 填充环形缓冲区
        mem_record.populate_ring_from_records(records);
        mem_record
    }

    /// 从历史记录填充环形缓冲区
    fn populate_ring_from_records(&mut self, records: &[crate::db::entity::health_records::Model]) {
        let now = chrono::Utc::now().timestamp() as usize;

        for record in records {
            let record_time = record.checked_at.to_utc().timestamp() as usize;
            let time_diff = now.saturating_sub(record_time);

            // 只处理在环形缓冲区时间范围内的记录
            if time_diff < HEALTH_CHECK_RING_MAX_DURATION_SEC {
                let ring_index =
                    (record_time / HEALTH_CHECK_RING_GRANULARITY_SEC) % HEALTH_CHECK_RING_SIZE;
                self.total_check_counter_ring[ring_index].inc(record_time as u64);

                if record.get_status() == HealthStatus::Healthy {
                    self.healthy_counter_ring[ring_index].inc(record_time as u64);
                }
            }
        }
    }

    /// 更新健康状态并记录到环形缓冲区
    pub fn update_health_status(
        &mut self,
        status: HealthStatus,
        response_time: Option<i32>,
        error_message: Option<String>,
    ) {
        self.current_health_status = status.clone();
        self.last_check_time = chrono::Utc::now();
        self.last_response_time = response_time;
        self.last_error_info = error_message;

        // 更新环形缓冲区
        let now = chrono::Utc::now().timestamp() as usize;
        let ring_index = (now / HEALTH_CHECK_RING_GRANULARITY_SEC) % HEALTH_CHECK_RING_SIZE;

        self.total_check_counter_ring[ring_index].inc(now as u64);
        self.healthy_counter_ring[ring_index].try_update_round(now as u64);
        if status == HealthStatus::Healthy {
            self.healthy_counter_ring[ring_index].inc(now as u64);
        }
    }

    /// 获取健康统计信息
    pub fn get_health_stats(&self, hours: u64) -> crate::db::HealthStats {
        let now = chrono::Utc::now().timestamp() as usize;

        let mut total_checks = 0;
        let mut healthy_count = 0;

        for ring_index in 0..HEALTH_CHECK_RING_SIZE {
            total_checks += self.total_check_counter_ring[ring_index].counter;
            healthy_count += self.healthy_counter_ring[ring_index].counter;
        }

        let health_percentage = if total_checks > 0 {
            (healthy_count as f64 / total_checks as f64) * 100.0
        } else {
            0.0
        };

        crate::db::HealthStats {
            total_checks,
            healthy_count,
            unhealthy_count: total_checks - healthy_count,
            health_percentage,
            average_response_time: self.last_response_time.map(|rt| rt as f64),
            uptime_percentage: health_percentage,
            last_check_time: Some(self.last_check_time),
            last_status: Some(self.current_health_status.clone()),
        }
    }

    /// 获取当前健康状态
    pub fn get_current_health_status(&self) -> &HealthStatus {
        &self.current_health_status
    }

    /// 获取最后检查时间
    pub fn get_last_check_time(&self) -> chrono::DateTime<chrono::Utc> {
        self.last_check_time
    }

    /// 获取最后响应时间
    pub fn get_last_response_time(&self) -> Option<i32> {
        self.last_response_time
    }

    /// 获取最后错误信息
    pub fn get_last_error_info(&self) -> &Option<String> {
        &self.last_error_info
    }

    pub fn get_counter_ring(&mut self) -> (Vec<u64>, Vec<u64>) {
        let now = self.last_check_time.timestamp() as usize;

        let mut total_ring = vec![0; HEALTH_CHECK_RING_SIZE];
        let mut healthy_ring = vec![0; HEALTH_CHECK_RING_SIZE];

        let mut total_checks = 0;
        let mut healthy_count = 0;

        for i in 0..HEALTH_CHECK_RING_SIZE {
            let ring_time = now - (i * HEALTH_CHECK_RING_GRANULARITY_SEC);
            let ring_index =
                ring_time.div_euclid(HEALTH_CHECK_RING_GRANULARITY_SEC) % HEALTH_CHECK_RING_SIZE;
            total_ring[i] = self.total_check_counter_ring[ring_index].get(ring_time as u64);
            healthy_ring[i] = self.healthy_counter_ring[ring_index].counter;
        }

        (total_ring, healthy_ring)
    }

    pub fn get_ring_granularity(&self) -> u32 {
        HEALTH_CHECK_RING_GRANULARITY_SEC as u32
    }
}

pub struct HealthChecker {
    db: Db,
    instance_mgr: Arc<NetworkInstanceManager>,
    inst_id_map: DashMap<i32, uuid::Uuid>,
    node_tasks: DashMap<i32, ScopedTask<()>>,
    node_records: Arc<DashMap<i32, HealthyMemRecord>>,
    node_cfg: Arc<DashMap<i32, TomlConfigLoader>>,
}

impl HealthChecker {
    pub fn new(db: Db) -> Self {
        let instance_mgr = Arc::new(NetworkInstanceManager::new());
        Self {
            db,
            instance_mgr,
            inst_id_map: DashMap::new(),
            node_tasks: DashMap::new(),
            node_records: Arc::new(DashMap::new()),
            node_cfg: Arc::new(DashMap::new()),
        }
    }

    /// 启动时从数据库加载所有节点的健康记录到内存
    pub async fn load_health_records_from_db(&self) -> anyhow::Result<()> {
        info!("Loading health records from database...");

        // 获取所有活跃节点
        let nodes = NodeOperations::get_all_nodes(&self.db)
            .await
            .with_context(|| "Failed to get all nodes from database")?;

        let from_date = chrono::Utc::now().naive_utc()
            - chrono::Duration::seconds(HEALTH_CHECK_RING_MAX_DURATION_SEC as i64);

        for node in nodes {
            // 获取每个节点最近的健康记录（用于初始化环形缓冲区）
            let records =
                HealthOperations::get_node_health_records(&self.db, node.id, Some(from_date), None)
                    .await
                    .with_context(|| {
                        format!("Failed to get health records for node {}", node.id)
                    })?;

            // 创建内存记录
            let mem_record = HealthyMemRecord::from_db_records(node.id, &records);
            self.node_records.insert(node.id, mem_record);

            debug!(
                "Loaded {} health records for node {} ({})",
                records.len(),
                node.id,
                node.name
            );
        }

        info!(
            "Loaded health records for {} nodes",
            self.node_records.len()
        );
        Ok(())
    }

    /// 获取节点的内存健康记录
    pub fn get_node_memory_record(&self, node_id: i32) -> Option<HealthyMemRecord> {
        self.node_records.get(&node_id).map(|entry| entry.clone())
    }

    /// 获取节点的健康统计信息（从内存）
    pub fn get_node_health_stats(
        &self,
        node_id: i32,
        hours: u64,
    ) -> Option<crate::db::HealthStats> {
        self.node_records
            .get(&node_id)
            .map(|record| record.get_health_stats(hours))
    }

    /// 获取所有节点的当前健康状态（从内存）
    pub fn get_all_nodes_health_status(&self) -> Vec<(i32, HealthStatus, Option<String>)> {
        self.node_records
            .iter()
            .map(|entry| {
                let record = entry.value();
                (
                    record.node_id,
                    record.current_health_status.clone(),
                    record.last_error_info.clone(),
                )
            })
            .collect()
    }

    pub async fn try_update_node(&self, node_id: i32) -> anyhow::Result<()> {
        let old_cfg = self
            .node_cfg
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("old node cfg not found, node_id: {}", node_id))?
            .clone();
        let new_cfg = self.get_node_cfg(node_id, Some(old_cfg.get_id())).await?;

        if new_cfg.dump() != old_cfg.dump() {
            self.remove_node(node_id).await?;
            self.add_node(node_id).await?;
            info!("node {} cfg updated", node_id);
        }

        Ok(())
    }

    async fn get_node_cfg_with_model(
        &self,
        node_info: &shared_nodes::Model,
        inst_id: Option<uuid::Uuid>,
    ) -> anyhow::Result<TomlConfigLoader> {
        let cfg = TomlConfigLoader::default();
        cfg.set_peers(vec![PeerConfig {
            uri: format!(
                "{}://{}:{}",
                node_info.protocol, node_info.host, node_info.port
            )
            .parse()
            .with_context(|| "failed to parse peer uri")?,
        }]);

        let inst_id = inst_id.unwrap_or(uuid::Uuid::new_v4());
        cfg.set_id(inst_id);
        cfg.set_network_identity(NetworkIdentity::new(
            node_info.network_name.clone(),
            node_info.network_secret.clone(),
        ));

        cfg.set_hostname(Some("HealthCheckNode".to_string()));

        let mut flags = cfg.get_flags();
        flags.no_tun = true;
        flags.disable_p2p = true;
        flags.disable_udp_hole_punching = true;
        cfg.set_flags(flags);

        Ok(cfg)
    }

    pub async fn test_connection(
        &self,
        node_info: &shared_nodes::Model,
        max_time: Duration,
    ) -> anyhow::Result<()> {
        let cfg = self.get_node_cfg_with_model(node_info, None).await?;
        defer!({
            let _ = self
                .instance_mgr
                .delete_network_instance(vec![cfg.get_id()]);
        });
        self.instance_mgr
            .run_network_instance(cfg.clone(), ConfigSource::FFI)
            .with_context(|| "failed to run network instance")?;

        let now = Instant::now();
        let mut err = None;
        while now.elapsed() < max_time {
            match Self::test_node_healthy(cfg.get_id(), self.instance_mgr.clone()).await {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "test node healthy failed, node_info: {:?}, err: {}",
                        node_info, e
                    );
                    err = Some(e);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(anyhow::anyhow!("test node healthy failed, err: {:?}", err))
    }

    async fn get_node_cfg(
        &self,
        node_id: i32,
        inst_id: Option<uuid::Uuid>,
    ) -> anyhow::Result<TomlConfigLoader> {
        let node_info = NodeOperations::get_node_by_id(&self.db, node_id)
            .await
            .with_context(|| format!("failed to get node by id: {}", node_id))?
            .ok_or_else(|| anyhow::anyhow!("node not found"))?;
        self.get_node_cfg_with_model(&node_info, inst_id).await
    }

    pub async fn add_node(&self, node_id: i32) -> anyhow::Result<()> {
        let cfg = self.get_node_cfg(node_id, None).await?;
        info!(
            "Add node {} to health checker, cfg: {}",
            node_id,
            cfg.dump()
        );

        self.instance_mgr
            .run_network_instance(cfg.clone(), ConfigSource::Web)
            .with_context(|| "failed to run network instance")?;
        self.inst_id_map.insert(node_id, cfg.get_id());

        // 初始化内存记录（如果不存在）
        if !self.node_records.contains_key(&node_id) {
            // 从数据库加载历史记录
            let from_date = chrono::Utc::now().naive_utc()
                - chrono::Duration::seconds(HEALTH_CHECK_RING_MAX_DURATION_SEC as i64);
            if let Ok(records) =
                HealthOperations::get_node_health_records(&self.db, node_id, Some(from_date), None)
                    .await
            {
                let mem_record = HealthyMemRecord::from_db_records(node_id, &records);
                self.node_records.insert(node_id, mem_record);
                info!(
                    "Initialized memory record for node {} with {} historical records",
                    node_id,
                    records.len()
                );
            } else {
                self.node_records
                    .insert(node_id, HealthyMemRecord::new(node_id));
                info!("Initialized new memory record for node {}", node_id);
            }
        }

        // 启动健康检查任务
        let task = ScopedTask::from(tokio::spawn(Self::node_health_check_task(
            node_id,
            cfg.get_id(),
            Arc::clone(&self.instance_mgr),
            self.db.clone(),
            Arc::clone(&self.node_records),
        )));
        self.node_tasks.insert(node_id, task);
        self.node_cfg.insert(node_id, cfg.clone());

        Ok(())
    }

    pub async fn remove_node(&self, node_id: i32) -> anyhow::Result<()> {
        self.node_tasks.remove(&node_id);
        if let Some(inst_id) = self.inst_id_map.remove(&node_id) {
            let _ = self.instance_mgr.delete_network_instance(vec![inst_id.1]);
        }
        self.node_cfg.remove(&node_id);
        // 保留内存记录，不删除，以便后续查询历史数据
        info!(
            "Removed health check task for node {}, memory record retained",
            node_id
        );
        Ok(())
    }

    #[instrument(err, ret, skip(instance_mgr))]
    async fn test_node_healthy(
        inst_id: uuid::Uuid,
        instance_mgr: Arc<NetworkInstanceManager>,
        // return version, response time on healthy, conn_count
    ) -> anyhow::Result<(String, u64, u32)> {
        let Some(instance) = instance_mgr.get_network_info(&inst_id) else {
            anyhow::bail!("healthy check node is not started");
        };

        let running = instance.running;
        // health check node is not running, update db
        if !running {
            anyhow::bail!("healthy check node is not running");
        }

        if let Some(err) = instance.error_msg {
            anyhow::bail!("healthy check node has error: {}", err);
        }

        let p = instance.peer_route_pairs;
        // dst node is not online
        let Some(dst_node) = p.iter().find(|x| {
            // we disable p2p, so we only check direct connected peer
            x.route.as_ref().is_some_and(|route| {
                !route.feature_flag.unwrap().is_public_server && route.hostname != "HealthCheckNode"
            }) && x.peer.as_ref().is_some_and(|p| !p.conns.is_empty())
        }) else {
            anyhow::bail!("dst node is not online");
        };

        let Some(route_info) = &dst_node.route else {
            anyhow::bail!("dst node route is not found");
        };

        let Some(peer_info) = &dst_node.peer else {
            anyhow::bail!("dst node peer is not found");
        };

        let version = route_info
            .version
            .clone()
            .split("-")
            .next()
            .unwrap_or("")
            .to_string();

        // 计算响应时间（这里可以根据实际需要实现）
        let response_time = peer_info
            .conns
            .iter()
            .filter_map(|x| x.stats)
            .map(|x| x.latency_us)
            .min()
            .unwrap_or(0);

        let peer_id = peer_info.peer_id;

        let conn_count = if let Some(summary) = instance.foreign_network_summary {
            summary
                .info_map
                .get(&peer_id)
                .map(|x| x.network_count)
                .unwrap_or(0)
        } else {
            0
        };

        Ok((version, response_time, conn_count))
    }

    async fn node_health_check_task(
        node_id: i32,
        inst_id: uuid::Uuid,
        instance_mgr: Arc<NetworkInstanceManager>,
        db: Db,
        node_records: Arc<DashMap<i32, HealthyMemRecord>>,
    ) {
        /// 记录健康状态到数据库和内存
        async fn record_health_status(
            db: &Db,
            node_records: &Arc<DashMap<i32, HealthyMemRecord>>,
            node_id: i32,
            status: HealthStatus,
            response_time: Option<i32>,
            error_message: Option<String>,
        ) {
            // 写入数据库
            if let Err(e) = HealthOperations::create_health_record(
                db,
                node_id,
                status.clone(),
                response_time,
                error_message.clone(),
            )
            .await
            {
                error!("Failed to create health record for node {}: {}", node_id, e);
            }

            // 更新内存记录
            if let Some(mut record) = node_records.get_mut(&node_id) {
                record.update_health_status(status, response_time, error_message);
            } else {
                let mut new_record = HealthyMemRecord::new(node_id);
                new_record.update_health_status(status, response_time, error_message);
                node_records.insert(node_id, new_record);
            }
        }
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut counter: u64 = 0;
        loop {
            if counter != 0 {
                tick.tick().await;
            }
            counter += 1;

            match Self::test_node_healthy(inst_id, instance_mgr.clone()).await {
                Ok((version, response_time, conn_count)) => {
                    if let Err(e) = NodeOperations::update_node_status(
                        &db,
                        node_id,
                        true,
                        Some(conn_count as i32),
                    )
                    .await
                    {
                        error!("Failed to update node status for node {}: {}", node_id, e);
                    }

                    record_health_status(
                        &db,
                        &node_records,
                        node_id,
                        HealthStatus::Healthy,
                        Some(response_time as i32),
                        None,
                    )
                    .await;

                    // update node version
                    if let Err(e) = NodeOperations::update_node_version(&db, node_id, version).await
                    {
                        error!("Failed to update node version for node {}: {}", node_id, e);
                    }
                }
                Err(e) => {
                    if let Err(e) =
                        NodeOperations::update_node_status(&db, node_id, false, None).await
                    {
                        error!("Failed to update node status for node {}: {}", node_id, e);
                    }

                    record_health_status(
                        &db,
                        &node_records,
                        node_id,
                        HealthStatus::Unhealthy,
                        None,
                        Some(format!("inst id: {}, err: {}", inst_id, e)),
                    )
                    .await;
                }
            }
        }
    }
}
