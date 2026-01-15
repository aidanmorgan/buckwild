use buckwild_daemon::monitoring::mod::*;
use crate::logging::{LoggingConfig, security::SecurityLogger};

    #[tokio::test]
    async fn test_monitoring_manager_creation() {
        let config = MonitoringConfig::default();
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let security_logger = Arc::new(SecurityLogger::new().unwrap());
        let logging_manager = Arc::new(LoggingManager::new(LoggingConfig::default()).unwrap());

        let manager = MonitoringManager::new(
            config,
            performance_logger,
            security_logger,
            logging_manager,
        ).await.unwrap();

        assert!(manager.snmp_agent.is_some());
    }

    #[tokio::test]
    async fn test_monitoring_statistics() {
        let config = MonitoringConfig::default();
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let security_logger = Arc::new(SecurityLogger::new().unwrap());
        let logging_manager = Arc::new(LoggingManager::new(LoggingConfig::default()).unwrap());

        let manager = MonitoringManager::new(
            config,
            performance_logger,
            security_logger,
            logging_manager,
        ).await.unwrap();

        let stats = manager.get_monitoring_statistics().await;
        assert!(stats.snmp_stats.is_some());
        assert_eq!(stats.security_events_count, 0);
    }

    #[tokio::test]
    async fn test_config_update() {
        let config = MonitoringConfig::default();
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let security_logger = Arc::new(SecurityLogger::new().unwrap());
        let logging_manager = Arc::new(LoggingManager::new(LoggingConfig::default()).unwrap());

        let manager = MonitoringManager::new(
            config,
            performance_logger,
            security_logger,
            logging_manager,
        ).await.unwrap();

        let mut new_config = MonitoringConfig::default();
        new_config.snmp_port = 1161;

        manager.update_config(new_config.clone()).await.unwrap();
        let updated_config = manager.get_config().await;
        assert_eq!(updated_config.snmp_port, 1161);
    }

    #[tokio::test]
    async fn test_snmp_requests() {
        let config = MonitoringConfig::default();
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let security_logger = Arc::new(SecurityLogger::new().unwrap());
        let logging_manager = Arc::new(LoggingManager::new(LoggingConfig::default()).unwrap());

        let manager = MonitoringManager::new(
            config,
            performance_logger,
            security_logger,
            logging_manager,
        ).await.unwrap();

        // Wait for SNMP agent initialization
        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = manager.handle_snmp_get(crate::monitoring::snmp::oids::SYSTEM_VERSION).await;
        assert!(result.is_ok());

        let getnext_result = manager.handle_snmp_getnext("1.3.6.1.4.1.99999.1.1.0").await;
        assert!(getnext_result.is_ok());

        let getbulk_result = manager.handle_snmp_getbulk("1.3.6.1.4.1.99999.1.1.0", 5).await;
        assert!(getbulk_result.is_ok());
    }
