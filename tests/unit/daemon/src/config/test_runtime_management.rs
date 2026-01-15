use buckwild_daemon::config::runtime_management::*;
use crate::logging::LoggingConfig;

    #[tokio::test]
    async fn test_runtime_config_manager_creation() {
        let logging_config = LoggingConfig::default();
        let monitoring_config = MonitoringConfig::default();
        let logging_manager = Arc::new(LoggingManager::new(logging_config.clone()).unwrap());

        let manager = RuntimeConfigManager::new(
            logging_config,
            monitoring_config,
            logging_manager,
        );

        assert_eq!(manager.get_config_statistics().total_changes, 0);
    }

    #[tokio::test]
    async fn test_logging_config_update() {
        let logging_config = LoggingConfig::default();
        let monitoring_config = MonitoringConfig::default();
        let logging_manager = Arc::new(LoggingManager::new(logging_config.clone()).unwrap());

        let manager = RuntimeConfigManager::new(
            logging_config,
            monitoring_config,
            logging_manager,
        );

        let mut new_config = LoggingConfig::default();
        new_config.level = "debug".to_string();

        let result = manager.update_logging_config(new_config.clone(), None).await;
        assert!(result.is_ok());

        let updated_config = manager.get_logging_config().await;
        assert_eq!(updated_config.level, "debug");

        let stats = manager.get_config_statistics();
        assert_eq!(stats.total_changes, 1);
        assert_eq!(stats.successful_changes, 1);
    }

    #[tokio::test]
    async fn test_invalid_config_validation() {
        let logging_config = LoggingConfig::default();
        let monitoring_config = MonitoringConfig::default();
        let logging_manager = Arc::new(LoggingManager::new(logging_config.clone()).unwrap());

        let manager = RuntimeConfigManager::new(
            logging_config,
            monitoring_config,
            logging_manager,
        );

        let mut invalid_config = LoggingConfig::default();
        invalid_config.level = "invalid_level".to_string();

        let result = manager.update_logging_config(invalid_config, None).await;
        assert!(result.is_err());

        let stats = manager.get_config_statistics();
        assert_eq!(stats.total_changes, 1);
        assert_eq!(stats.successful_changes, 0);
        assert_eq!(stats.failed_changes, 1);
    }

    #[tokio::test]
    async fn test_custom_config_management() {
        let logging_config = LoggingConfig::default();
        let monitoring_config = MonitoringConfig::default();
        let logging_manager = Arc::new(LoggingManager::new(logging_config.clone()).unwrap());

        let manager = RuntimeConfigManager::new(
            logging_config,
            monitoring_config,
            logging_manager,
        );

        let key = "custom_setting".to_string();
        let value = serde_json::json!({"enabled": true, "timeout": 30});

        let result = manager.update_custom_config(key.clone(), value.clone(), None).await;
        assert!(result.is_ok());

        let retrieved_value = manager.get_custom_config(&key);
        assert_eq!(retrieved_value, Some(value));

        let all_configs = manager.get_all_custom_configs();
        assert_eq!(all_configs.len(), 1);
    }

    #[tokio::test]
    async fn test_config_rollback() {
        let logging_config = LoggingConfig::default();
        let monitoring_config = MonitoringConfig::default();
        let logging_manager = Arc::new(LoggingManager::new(logging_config.clone()).unwrap());

        let manager = RuntimeConfigManager::new(
            logging_config,
            monitoring_config,
            logging_manager,
        );

        // Make initial change
        let mut new_config = LoggingConfig::default();
        new_config.level = "debug".to_string();
        manager.update_logging_config(new_config, None).await.unwrap();

        // Make another change
        let mut newer_config = LoggingConfig::default();
        newer_config.level = "trace".to_string();
        manager.update_logging_config(newer_config, None).await.unwrap();

        // Rollback
        let result = manager.rollback_config("logging", None).await;
        assert!(result.is_ok());

        let current_config = manager.get_logging_config().await;
        assert_eq!(current_config.level, "debug");
    }

    #[tokio::test]
    async fn test_change_history() {
        let logging_config = LoggingConfig::default();
        let monitoring_config = MonitoringConfig::default();
        let logging_manager = Arc::new(LoggingManager::new(logging_config.clone()).unwrap());

        let manager = RuntimeConfigManager::new(
            logging_config,
            monitoring_config,
            logging_manager,
        );

        // Make several changes
        for level in &["debug", "info", "warn"] {
            let mut new_config = LoggingConfig::default();
            new_config.level = level.to_string();
            manager.update_logging_config(new_config, None).await.unwrap();
        }

        let history = manager.get_change_history();
        assert_eq!(history.len(), 3);

        // Test recent changes
        let recent = manager.get_recent_changes(SystemTime::now() - Duration::from_secs(1));
        assert_eq!(recent.len(), 3);
    }
