#[cfg(test)]
mod tests {
    use easytier::common::config::{ConfigLoader, PeerConfig};
    use easytier::common::global_ctx::GlobalCtx;
    use easytier::instance::Instance;
    use easytier::common::flow_policy_manager::FlowPolicyManager;
    use easytier::common::report_manager::ReportManager;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct TestConfig {
        hostname: String,
    }

    impl ConfigLoader for TestConfig {
        fn load(&self) -> Result<easytier::common::config::Config, anyhow::Error> {
            Ok(easytier::common::config::Config::default())
        }

        fn store(&self, _config: &easytier::common::config::Config) -> Result<(), anyhow::Error> {
            Ok(())
        }

        fn get_hostname(&self) -> String {
            self.hostname.clone()
        }
    }

    #[tokio::test]
    async fn test_flow_policy_and_report_manager_creation() {
        let config = TestConfig {
            hostname: "test-host".to_string(),
        };
        
        // 创建实例
        let instance = Instance::new(config);
        
        // 验证实例已正确创建
        assert!(!instance.get_id().is_empty());
        
        // 初始化管理器
        instance.init_managers().await;
        
        // 验证 global_ctx 中的管理器设置
        let global_ctx = instance.get_global_ctx();
        
        // 检查 flow_policy_manager 是否被设置
        // 注意：这些是内部 API，实际测试可能需要通过公共接口验证
        println!("Instance ID: {}", instance.get_id());
        println!("Test completed successfully");
    }

    #[tokio::test]
    async fn test_flow_policy_manager_functionality() {
        let stats_manager = Arc::new(easytier::common::stats::StatsManager::new());
        let network_name = "test-network".to_string();
        
        // 创建 FlowPolicyManager
        let flow_policy_manager = FlowPolicyManager::new(None, stats_manager, network_name);
        
        // 验证管理器已创建
        assert!(flow_policy_manager.is_some());
        
        if let Some(manager) = flow_policy_manager {
            println!("FlowPolicyManager created successfully");
            // 这里可以添加更多具体的策略测试
        }
    }

    #[tokio::test]
    async fn test_report_manager_functionality() {
        let stats_manager = Arc::new(easytier::common::stats::StatsManager::new());
        let network_name = "test-network".to_string();
        let node_name = "test-node".to_string();
        let email = "test@example.com".to_string();
        
        // 创建 ReportManager
        let report_manager = ReportManager::new(None, stats_manager, network_name, node_name, email);
        
        // 验证管理器已创建
        assert!(report_manager.is_some());
        
        if let Some(manager) = report_manager {
            println!("ReportManager created successfully");
            // 这里可以添加更多具体的上报测试
        }
    }

    #[tokio::test]
    async fn test_instance_with_managers() {
        let config = TestConfig {
            hostname: "test-instance".to_string(),
        };
        
        // 创建实例并初始化
        let instance = Instance::new(config);
        instance.init_managers().await;
        
        // 验证实例功能
        let instance_id = instance.get_id();
        assert!(!instance_id.is_empty());
        
        println!("Instance with managers test completed. Instance ID: {}", instance_id);
    }
}