use buckwild_daemon::monitoring::snmp::*;
use crate::logging::performance::PerformanceLogger;

    #[tokio::test]
    async fn test_snmp_agent_creation() {
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let agent = SnmpAgent::new(performance_logger).unwrap();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let stats = agent.get_agent_statistics().await;
        assert!(stats.total_oids > 0);
    }

    #[tokio::test]
    async fn test_mib_entry_retrieval() {
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let agent = SnmpAgent::new(performance_logger).unwrap();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let entry = agent.get_mib_entry(oids::SYSTEM_VERSION).await;
        assert!(entry.is_some());
        
        let entry = entry.unwrap();
        assert_eq!(entry.oid, oids::SYSTEM_VERSION);
        assert!(entry.value.as_string().is_some());
    }

    #[tokio::test]
    async fn test_snmp_get_request() {
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let agent = SnmpAgent::new(performance_logger).unwrap();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let result = agent.handle_get_request(oids::SYSTEM_VERSION).await;
        assert!(result.is_ok());
        
        let value = result.unwrap();
        assert!(value.as_string().is_some());
    }

    #[tokio::test]
    async fn test_snmp_getnext_request() {
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let agent = SnmpAgent::new(performance_logger).unwrap();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let result = agent.handle_getnext_request("1.3.6.1.4.1.99999.1.1.0").await;
        assert!(result.is_ok());
        
        let (oid, _value) = result.unwrap();
        assert!(oid.starts_with("1.3.6.1.4.1.99999.1.1."));
    }

    #[tokio::test]
    async fn test_snmp_getbulk_request() {
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let agent = SnmpAgent::new(performance_logger).unwrap();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let result = agent.handle_getbulk_request("1.3.6.1.4.1.99999.1.1.0", 5).await;
        assert!(result.is_ok());
        
        let results = result.unwrap();
        assert!(!results.is_empty());
        assert!(results.len() <= 5);
    }

    #[tokio::test]
    async fn test_mib_value_updates() {
        let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
        let agent = SnmpAgent::new(performance_logger.clone()).unwrap();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Get initial value
        let initial_value = agent.handle_get_request(oids::TOTAL_CONNECTIONS).await.unwrap();
        
        // Simulate performance update
        let mut metrics = std::collections::HashMap::new();
        metrics.insert("total_connections".to_string(), 
            crate::logging::performance::MetricValue::Counter(10));
        
        let perf_metrics = crate::logging::performance::PerformanceMetrics {
            timestamp: chrono::Utc::now(),
            component: "connection".to_string(),
            correlation_id: None,
            metrics,
        };
        
        performance_logger.log_metrics(perf_metrics);
        
        // Wait for update
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Force MIB update
        let mib_clone = Arc::clone(&agent.mib);
        let performance_logger_clone = Arc::clone(&agent.performance_logger);
        SnmpAgent::update_mib_values(&mib_clone, &performance_logger_clone, agent.start_time).await.unwrap();
        
        let updated_value = agent.handle_get_request(oids::TOTAL_CONNECTIONS).await.unwrap();
        
        // Value should have been updated
        assert_ne!(initial_value.as_counter64(), updated_value.as_counter64());
    }
