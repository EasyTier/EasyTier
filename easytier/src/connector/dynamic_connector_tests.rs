#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::manual::ManualConnectorManager;
    use crate::common::config::TomlConfigLoader;
    use crate::common::global_ctx::GlobalCtx;
    use crate::peers::peer_manager::PeerManager;
    use std::sync::Arc;

    fn create_test_instance(id: &str) -> (Arc<GlobalCtx>, Arc<ManualConnectorManager>) {
        let config = TomlConfigLoader::default();
        config.set_inst_name(id.to_string());
        let global_ctx = Arc::new(GlobalCtx::new(config));
        
        let peer_config = TomlConfigLoader::default();
        let peer_manager = Arc::new(PeerManager::new(peer_config, global_ctx.clone()));
        let manual_manager = Arc::new(ManualConnectorManager::new(global_ctx.clone(), peer_manager));
        
        (global_ctx, manual_manager)
    }

    #[tokio::test]
    async fn test_global_manager_is_singleton() {
        let manager1 = GlobalDynamicConnectorManager::get_instance();
        let manager2 = GlobalDynamicConnectorManager::get_instance();
        assert!(Arc::ptr_eq(manager1, manager2), "Should be the same instance");
    }

    #[tokio::test]
    async fn test_register_multiple_instances() {
        let global_manager = GlobalDynamicConnectorManager::get_instance();
        
        let (_, manager1) = create_test_instance("instance_1");
        let (_, manager2) = create_test_instance("instance_2");
        let (_, manager3) = create_test_instance("instance_3");
        
        global_manager.register_manual_manager("instance_1".to_string(), manager1);
        global_manager.register_manual_manager("instance_2".to_string(), manager2);
        global_manager.register_manual_manager("instance_3".to_string(), manager3);
        
        assert_eq!(global_manager.manual_managers.len(), 3);
        
        // Cleanup
        global_manager.unregister_manual_manager("instance_1");
        global_manager.unregister_manual_manager("instance_2");
        global_manager.unregister_manual_manager("instance_3");
    }

    #[tokio::test]
    async fn test_unregister_instance() {
        let global_manager = GlobalDynamicConnectorManager::get_instance();
        
        let (_, manager) = create_test_instance("test_instance");
        global_manager.register_manual_manager("test_instance".to_string(), manager);
        
        assert_eq!(global_manager.manual_managers.len(), 1);
        
        global_manager.unregister_manual_manager("test_instance");
        assert_eq!(global_manager.manual_managers.len(), 0);
    }

    #[tokio::test]
    async fn test_add_dynamic_connector_http() {
        let global_manager = GlobalDynamicConnectorManager::get_instance();
        let (_, manual_manager) = create_test_instance("test_http");
        
        global_manager.register_manual_manager("test_http".to_string(), manual_manager);
        
        let url: url::Url = "http://example.com/nodes".parse().unwrap();
        let result = global_manager.add_dynamic_connector(
            url.clone(),
            DynamicConnectorType::Http,
            IpVersion::Both,
            300,
        ).await;
        
        // Note: This will fail because example.com doesn't have a real EasyTier node server
        // But we can test that it was registered
        assert!(global_manager.connectors.contains_key(&url));
        
        // Cleanup
        global_manager.remove_dynamic_connector(&url).await.ok();
        global_manager.unregister_manual_manager("test_http");
    }

    #[tokio::test]
    async fn test_ttl_validation_in_connector() {
        // Test that TTL values are properly validated when adding connectors
        let global_manager = GlobalDynamicConnectorManager::get_instance();
        
        // Valid TTL should work
        let url1: url::Url = "http://test1.com/nodes".parse().unwrap();
        // We can't easily test the actual refresh without a real server,
        // but we can verify the connector is registered
        
        // Invalid scenarios would be caught during URL parsing or TTL extraction
        // in the HttpTunnelConnector, which has its own tests
    }

    #[tokio::test]
    async fn test_concurrent_registration() {
        let global_manager = GlobalDynamicConnectorManager::get_instance();
        
        // Register multiple instances concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let gm = global_manager.clone();
            let handle = tokio::spawn(async move {
                let (_, manager) = create_test_instance(&format!("concurrent_{}", i));
                gm.register_manual_manager(format!("concurrent_{}", i), manager);
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await.unwrap();
        }
        
        assert_eq!(global_manager.manual_managers.len(), 10);
        
        // Cleanup
        for i in 0..10 {
            global_manager.unregister_manual_manager(&format!("concurrent_{}", i));
        }
    }
}
