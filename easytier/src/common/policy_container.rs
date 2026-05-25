use std::sync::{Arc, RwLock, Weak};

use crate::common::flow_policy_manager::FlowPolicyManager;
use crate::common::report_manager::ReportManager;

/// 策略容器，用于存储流量策略管理器和上报管理器的弱引用
/// 使用 std::sync::RwLock 而非 tokio::RwLock，因为临界区极短（仅读取/写入指针），
/// 且在数据面热路径中被频繁调用，避免 .await 的开销
pub struct PolicyContainer {
    flow_policy_manager: RwLock<Option<Weak<FlowPolicyManager>>>,
    report_manager: RwLock<Option<Weak<ReportManager>>>,
}

impl PolicyContainer {
    pub fn new() -> Self {
        Self {
            flow_policy_manager: RwLock::new(None),
            report_manager: RwLock::new(None),
        }
    }

    pub fn set_flow_policy_manager_sync(&self, manager: Option<Arc<FlowPolicyManager>>) {
        *self.flow_policy_manager.write().unwrap() = manager.map(|m| Arc::downgrade(&m));
    }

    /// 同步获取 FlowPolicyManager（热路径使用，无 .await）
    pub fn get_flow_policy_manager_sync(&self) -> Option<Arc<FlowPolicyManager>> {
        self.flow_policy_manager
            .read()
            .unwrap()
            .as_ref()
            .and_then(|weak| weak.upgrade())
    }

    /// 兼容异步接口（用于 RPC 层等非热路径）
    pub async fn get_flow_policy_manager(&self) -> Option<Arc<FlowPolicyManager>> {
        self.get_flow_policy_manager_sync()
    }

    pub fn set_report_manager_sync(&self, manager: Option<Arc<ReportManager>>) {
        *self.report_manager.write().unwrap() = manager.map(|m| Arc::downgrade(&m));
    }

    pub fn get_report_manager_sync(&self) -> Option<Arc<ReportManager>> {
        self.report_manager
            .read()
            .unwrap()
            .as_ref()
            .and_then(|weak| weak.upgrade())
    }

    pub async fn get_report_manager(&self) -> Option<Arc<ReportManager>> {
        self.get_report_manager_sync()
    }

    // 兼容旧的异步 set 接口
    pub async fn set_flow_policy_manager(&self, manager: Option<Arc<FlowPolicyManager>>) {
        self.set_flow_policy_manager_sync(manager);
    }

    pub async fn set_report_manager(&self, manager: Option<Arc<ReportManager>>) {
        self.set_report_manager_sync(manager);
    }
}

impl Default for PolicyContainer {
    fn default() -> Self {
        Self::new()
    }
}
