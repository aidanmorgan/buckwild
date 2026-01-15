use buckwild_daemon::logging::mod::*;
use tracing::Level;

    #[tokio::test]
    async fn test_logging_manager_creation() {
        let config = LoggingConfig::default();
        let manager = LoggingManager::new(config).unwrap();
        
        let correlation = manager.create_correlation("test_operation");
        assert!(!correlation.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_structured_logging() {
        let config = LoggingConfig::default();
        let manager = LoggingManager::new(config).unwrap();
        
        let correlation = manager.create_correlation("test_operation");
        
        let mut fields = HashMap::new();
        fields.insert("test_field".to_string(), serde_json::json!("test_value"));
        
        manager.log_event(
            Level::INFO,
            "Test message",
            "test_component",
            Some(correlation),
            fields
        );
        
        let stats = manager.get_statistics();
        assert_eq!(stats.active_correlations, 1);
    }

    #[tokio::test]
    async fn test_correlation_cleanup() {
        let mut config = LoggingConfig::default();
        config.correlation_ttl_seconds = 1; // 1 second TTL for testing
        
        let manager = LoggingManager::new(config).unwrap();
        let _correlation = manager.create_correlation("test_operation");
        
        assert_eq!(manager.get_statistics().active_correlations, 1);
        
        // Wait for TTL to expire
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        manager.cleanup_correlations();
        
        assert_eq!(manager.get_statistics().active_correlations, 0);
    }
