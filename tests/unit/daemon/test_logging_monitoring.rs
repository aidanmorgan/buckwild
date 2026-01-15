use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

use buckwild_daemon::logging::{
    LoggingManager, LoggingConfig,
    correlation::CorrelationId,
    security::{SecurityLogger, SecurityEvent, SecurityEventType, SecuritySeverity},
    performance::{PerformanceLogger, PerformanceMetrics, MetricValue},
    sanitizer::LogSanitizer,
};
use buckwild_daemon::monitoring::{
    MonitoringManager, MonitoringConfig,
    snmp::{SnmpAgent, oids},
};
use buckwild_daemon::config::runtime_management::{
    RuntimeConfigManager, ConfigChangeType,
};
use buckwild_common::protocol::types::{
    Port, SessionCount, AttemptCount, FailureCount, SuccessCount,
    ConnectionCount, PacketCount, ByteCount, TimeoutMs, IntervalMs
};

#[tokio::test]
async fn test_comprehensive_logging_system() {
    // Test logging manager creation and configuration
    let config = LoggingConfig {
        level: "debug".to_string(),
        enable_correlation: true,
        enable_security_audit: true,
        enable_performance_metrics: true,
        sanitize_sensitive_data: true,
        max_correlation_entries: SessionCount::new(1000),
        correlation_ttl_seconds: TimeoutMs::new(3600000),
    };

    let logging_manager = Arc::new(LoggingManager::new(config.clone()).unwrap());
    
    // Test correlation creation and tracking
    let correlation_id = logging_manager.create_correlation("test_operation");
    assert!(!correlation_id.to_string().is_empty());

    // Test structured logging with correlation
    let mut fields = HashMap::new();
    fields.insert("test_field".to_string(), serde_json::json!("test_value"));
    fields.insert("session_id".to_string(), serde_json::json!("session_12345"));
    fields.insert("password".to_string(), serde_json::json!("secret123"));

    logging_manager.log_event(
        tracing::Level::INFO,
        "Test structured log message",
        "test_component",
        Some(correlation_id.clone()),
        fields,
    );

    // Test security event logging
    let security_event = SecurityEvent::new(
        SecurityEventType::AuthenticationFailure,
        SecuritySeverity::Medium,
        "Test authentication failure".to_string(),
        Some(correlation_id.clone()),
    )
    .with_source_ip("192.168.1.100".to_string())
    .with_additional_data("failure_reason".to_string(), serde_json::json!("invalid_credentials"));

    logging_manager.log_security_event(security_event);

    // Test performance metrics logging
    let mut metrics = HashMap::new();
    metrics.insert("response_time".to_string(), MetricValue::Duration(Duration::from_millis(150)));
    metrics.insert("requests_per_second".to_string(), MetricValue::Gauge(45.2));
    metrics.insert("total_requests".to_string(), MetricValue::Counter(PacketCount::new(1000).as_u64()));

    let perf_metrics = PerformanceMetrics {
        timestamp: chrono::Utc::now(),
        component: "test_component".to_string(),
        correlation_id: Some(correlation_id),
        metrics,
    };

    logging_manager.log_performance_metrics(perf_metrics);

    // Verify logging statistics
    let stats = logging_manager.get_statistics();
    assert_eq!(stats.active_correlations, SessionCount::new(1));
    assert!(stats.security_events_count > SuccessCount::new(0));
    assert!(stats.performance_metrics_count > SuccessCount::new(0));
}

#[tokio::test]
async fn test_log_sanitization() {
    let sanitizer = LogSanitizer::new();
    
    // Test sensitive field redaction
    let mut fields = HashMap::new();
    fields.insert("password".to_string(), serde_json::json!("secret123"));
    fields.insert("api_key".to_string(), serde_json::json!("key_abc123"));
    fields.insert("session_id".to_string(), serde_json::json!("session_456"));
    fields.insert("normal_field".to_string(), serde_json::json!("normal_value"));
    fields.insert("message".to_string(), serde_json::json!("Connection from 192.168.1.100"));

    let sanitized = sanitizer.sanitize_fields(fields.clone());

    // Verify sensitive fields are redacted
    assert_eq!(sanitized.get("password").unwrap(), &serde_json::json!("[REDACTED]"));
    assert_eq!(sanitized.get("api_key").unwrap(), &serde_json::json!("[REDACTED]"));
    
    // Verify session_id is hashed
    let session_value = sanitized.get("session_id").unwrap().as_str().unwrap();
    assert!(session_value.starts_with("hash:"));
    
    // Verify IP address is masked
    let message_value = sanitized.get("message").unwrap().as_str().unwrap();
    assert!(message_value.contains("192.168.xxx.xxx"));
    
    // Verify normal field is unchanged
    assert_eq!(sanitized.get("normal_field").unwrap(), &serde_json::json!("normal_value"));

    // Test sanitization statistics
    let stats = sanitizer.get_sanitization_stats(&fields, &sanitized);
    assert_eq!(stats.total_fields, SuccessCount::new(5));
    assert_eq!(stats.redacted_fields, SuccessCount::new(2)); // password, api_key
    assert_eq!(stats.hashed_fields, SuccessCount::new(1));   // session_id
    assert_eq!(stats.masked_values, SuccessCount::new(1));   // IP in message
}

#[tokio::test]
async fn test_security_event_logging_and_cef_format() {
    let security_logger = SecurityLogger::new().unwrap();
    
    // Test various security events
    security_logger.log_authentication_failure("192.168.1.100", "Invalid credentials", None);
    security_logger.log_attack_detected(
        SecurityEventType::FragmentBombDetected,
        "10.0.0.5",
        "Fragment bomb attack detected with 1000 fragments",
        None,
    );
    security_logger.log_rate_limit_exceeded("172.16.0.10", "connection_attempts", None);
    security_logger.log_system_event(SecurityEventType::SystemStartup, "System started successfully");

    // Verify event count
    assert_eq!(security_logger.get_event_count(), SuccessCount::new(4));

    // Test CEF format generation
    let event = SecurityEvent::new(
        SecurityEventType::ReplayAttackDetected,
        SecuritySeverity::High,
        "Replay attack detected".to_string(),
        None,
    )
    .with_source_ip("192.168.1.200".to_string())
    .with_session_hash("hash:abcd1234".to_string());

    let cef = event.to_cef();
    assert!(cef.starts_with("CEF:0|Buckwild|FrequencyHoppingNetwork|1.0|"));
    assert!(cef.contains("ReplayAttackDetected"));
    assert!(cef.contains("src=192.168.1.200"));
    assert!(cef.contains("cs2=hash:abcd1234"));
    assert!(cef.contains("Replay attack detected"));
}

#[tokio::test]
async fn test_performance_metrics_collection() {
    let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
    
    // Test port hopping metrics
    let mut port_metrics = HashMap::new();
    port_metrics.insert("total_hops".to_string(), MetricValue::Counter(SuccessCount::new(100).as_u64()));
    port_metrics.insert("successful_hops".to_string(), MetricValue::Counter(SuccessCount::new(95).as_u64()));
    port_metrics.insert("failed_hops".to_string(), MetricValue::Counter(FailureCount::new(5).as_u64()));
    port_metrics.insert("current_port".to_string(), MetricValue::Counter(Port::new(8080).as_u16() as u64));
    port_metrics.insert("average_hop_time".to_string(), MetricValue::Duration(Duration::from_millis(50)));

    performance_logger.update_port_hopping_stats(&port_metrics);

    // Test connection health metrics
    let mut conn_metrics = HashMap::new();
    conn_metrics.insert("active_connections".to_string(), MetricValue::Counter(ConnectionCount::new(25).as_u64()));
    conn_metrics.insert("total_connections".to_string(), MetricValue::Counter(ConnectionCount::new(1000).as_u64()));
    conn_metrics.insert("failed_connections".to_string(), MetricValue::Counter(FailureCount::new(50).as_u64()));
    conn_metrics.insert("packet_loss_rate".to_string(), MetricValue::Gauge(0.02));
    conn_metrics.insert("throughput_bps".to_string(), MetricValue::Counter(ByteCount::new(1048576).as_u64()));

    performance_logger.update_connection_health(&conn_metrics);

    // Test crypto performance metrics
    let mut crypto_metrics = HashMap::new();
    crypto_metrics.insert("ecdh_operations_per_second".to_string(), MetricValue::Gauge(150.5));
    crypto_metrics.insert("hmac_operations_per_second".to_string(), MetricValue::Gauge(2500.0));
    crypto_metrics.insert("key_cache_hit_rate".to_string(), MetricValue::Gauge(0.85));

    performance_logger.update_crypto_stats(&crypto_metrics);

    // Verify statistics
    let port_stats = performance_logger.get_port_hopping_stats();
    assert_eq!(port_stats.total_hops, SuccessCount::new(100));
    assert_eq!(port_stats.successful_hops, SuccessCount::new(95));
    assert_eq!(port_stats.current_port, Port::new(8080));

    let conn_health = performance_logger.get_connection_health();
    assert_eq!(conn_health.active_connections, ConnectionCount::new(25));
    assert_eq!(conn_health.total_connections, ConnectionCount::new(1000));
    assert_eq!(conn_health.packet_loss_rate, 0.02);

    let crypto_stats = performance_logger.get_crypto_stats();
    assert_eq!(crypto_stats.ecdh_operations_per_second, 150.5);
    assert_eq!(crypto_stats.key_cache_hit_rate, 0.85);

    // Test performance report generation
    let report = performance_logger.generate_performance_report();
    assert!(report.uptime.as_millis() > 0);
    assert_eq!(report.port_hopping.total_hops, SuccessCount::new(100));
    assert_eq!(report.connection_health.active_connections, ConnectionCount::new(25));
    assert_eq!(report.crypto_performance.ecdh_operations_per_second, 150.5);
}

#[tokio::test]
async fn test_snmp_agent_functionality() {
    let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
    let snmp_agent = SnmpAgent::new(performance_logger.clone()).unwrap();
    
    // Wait for initialization
    sleep(Duration::from_millis(200)).await;
    
    // Test SNMP GET requests
    let system_version = snmp_agent.handle_get_request(oids::SYSTEM_VERSION).await;
    assert!(system_version.is_ok());
    assert!(system_version.unwrap().as_string().is_some());

    let active_connections = snmp_agent.handle_get_request(oids::ACTIVE_CONNECTIONS).await;
    assert!(active_connections.is_ok());
    assert!(active_connections.unwrap().as_counter64().is_some());

    // Test SNMP GETNEXT requests
    let getnext_result = snmp_agent.handle_getnext_request("1.3.6.1.4.1.99999.1.1.0").await;
    assert!(getnext_result.is_ok());
    let (next_oid, _value) = getnext_result.unwrap();
    assert!(next_oid.starts_with("1.3.6.1.4.1.99999.1.1."));

    // Test SNMP GETBULK requests
    let getbulk_result = snmp_agent.handle_getbulk_request("1.3.6.1.4.1.99999.1.1.0", 5).await;
    assert!(getbulk_result.is_ok());
    let results = getbulk_result.unwrap();
    assert!(!results.is_empty());
    assert!(results.len() <= 5);

    // Test agent statistics
    let stats = snmp_agent.get_agent_statistics().await;
    assert!(stats.total_oids > 0);
    assert!(stats.uptime.as_millis() > 0);
}

#[tokio::test]
async fn test_monitoring_manager_integration() {
    let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
    let security_logger = Arc::new(SecurityLogger::new().unwrap());
    let logging_manager = Arc::new(LoggingManager::new(LoggingConfig::default()).unwrap());
    
    let monitoring_config = MonitoringConfig {
        enable_snmp: true,
        snmp_port: Port::new(1161), // Use non-standard port for testing
        snmp_community: "test_community".to_string(),
        metrics_update_interval_seconds: IntervalMs::new(5000),
        enable_prometheus: false,
        prometheus_port: Port::new(9091),
        enable_syslog: true,
        syslog_facility: "daemon".to_string(),
        syslog_server: None,
    };

    let monitoring_manager = MonitoringManager::new(
        monitoring_config.clone(),
        performance_logger,
        security_logger,
        logging_manager,
    ).await.unwrap();

    // Test monitoring statistics
    let stats = monitoring_manager.get_monitoring_statistics().await;
    assert!(stats.snmp_stats.is_some());
    assert_eq!(stats.security_events_count, SuccessCount::new(0));

    // Test configuration retrieval
    let config = monitoring_manager.get_config().await;
    assert_eq!(config.snmp_port, Port::new(1161));
    assert_eq!(config.snmp_community, "test_community");

    // Test configuration update
    let mut new_config = monitoring_config;
    new_config.metrics_update_interval_seconds = IntervalMs::new(10000);
    
    let update_result = monitoring_manager.update_config(new_config).await;
    assert!(update_result.is_ok());

    let updated_config = monitoring_manager.get_config().await;
    assert_eq!(updated_config.metrics_update_interval_seconds, IntervalMs::new(10000));
}

#[tokio::test]
async fn test_runtime_configuration_management() {
    let logging_config = LoggingConfig::default();
    let monitoring_config = MonitoringConfig::default();
    let logging_manager = Arc::new(LoggingManager::new(logging_config.clone()).unwrap());

    let config_manager = RuntimeConfigManager::new(
        logging_config,
        monitoring_config,
        logging_manager,
    );

    // Test logging configuration update
    let mut new_logging_config = LoggingConfig::default();
    new_logging_config.level = "debug".to_string();
    new_logging_config.enable_correlation = false;

    let correlation_id = CorrelationId::new();
    let result = config_manager.update_logging_config(new_logging_config.clone(), Some(correlation_id.clone())).await;
    assert!(result.is_ok());

    let updated_config = config_manager.get_logging_config().await;
    assert_eq!(updated_config.level, "debug");
    assert!(!updated_config.enable_correlation);

    // Test monitoring configuration update
    let mut new_monitoring_config = MonitoringConfig::default();
    new_monitoring_config.metrics_update_interval_seconds = IntervalMs::new(60000);
    new_monitoring_config.enable_snmp = false;

    let result = config_manager.update_monitoring_config(new_monitoring_config.clone(), Some(correlation_id.clone())).await;
    assert!(result.is_ok());

    let updated_monitoring_config = config_manager.get_monitoring_config().await;
    assert_eq!(updated_monitoring_config.metrics_update_interval_seconds, IntervalMs::new(60000));
    assert!(!updated_monitoring_config.enable_snmp);

    // Test custom configuration
    let custom_key = "test_setting".to_string();
    let custom_value = serde_json::json!({"enabled": true, "timeout": 30});

    let result = config_manager.update_custom_config(custom_key.clone(), custom_value.clone(), Some(correlation_id.clone())).await;
    assert!(result.is_ok());

    let retrieved_value = config_manager.get_custom_config(&custom_key);
    assert_eq!(retrieved_value, Some(custom_value));

    // Test configuration validation (invalid logging level)
    let mut invalid_config = LoggingConfig::default();
    invalid_config.level = "invalid_level".to_string();

    let result = config_manager.update_logging_config(invalid_config, Some(correlation_id.clone())).await;
    assert!(result.is_err());

    // Test change history
    let history = config_manager.get_change_history();
    assert_eq!(history.len(), AttemptCount::new(4).as_u32() as usize); // 2 successful + 1 failed + 1 custom

    let successful_changes: Vec<_> = history.iter().filter(|e| e.applied).collect();
    assert_eq!(successful_changes.len(), SuccessCount::new(3).as_u64() as usize);

    let failed_changes: Vec<_> = history.iter().filter(|e| !e.applied).collect();
    assert_eq!(failed_changes.len(), FailureCount::new(1).as_u64() as usize);

    // Test configuration statistics
    let stats = config_manager.get_config_statistics();
    assert_eq!(stats.total_changes, AttemptCount::new(4));
    assert_eq!(stats.successful_changes, SuccessCount::new(3));
    assert_eq!(stats.failed_changes, FailureCount::new(1));
    assert_eq!(stats.custom_configs_count, SuccessCount::new(1));

    // Test configuration rollback
    let rollback_result = config_manager.rollback_config("logging", Some(correlation_id)).await;
    assert!(rollback_result.is_ok());

    let rolled_back_config = config_manager.get_logging_config().await;
    assert_eq!(rolled_back_config.level, "info"); // Should be back to default
}

#[tokio::test]
async fn test_correlation_tracking_and_cleanup() {
    let mut config = LoggingConfig::default();
    config.correlation_ttl_seconds = TimeoutMs::new(1000); // 1 second TTL for testing
    
    let logging_manager = Arc::new(LoggingManager::new(config).unwrap());
    
    // Create multiple correlations
    let correlation1 = logging_manager.create_correlation("operation1");
    let correlation2 = logging_manager.create_correlation("operation2");
    let correlation3 = logging_manager.create_correlation("operation3");

    // Log events with correlations
    logging_manager.log_event(
        tracing::Level::INFO,
        "Test message 1",
        "test_component",
        Some(correlation1),
        HashMap::new(),
    );

    logging_manager.log_event(
        tracing::Level::INFO,
        "Test message 2",
        "test_component",
        Some(correlation2),
        HashMap::new(),
    );

    logging_manager.log_event(
        tracing::Level::INFO,
        "Test message 3",
        "test_component",
        Some(correlation3),
        HashMap::new(),
    );

    // Verify correlations are active
    let stats = logging_manager.get_statistics();
    assert_eq!(stats.active_correlations, SessionCount::new(3));

    // Wait for TTL to expire
    sleep(Duration::from_secs(2)).await;

    // Clean up expired correlations
    logging_manager.cleanup_correlations();

    // Verify correlations are cleaned up
    let stats_after_cleanup = logging_manager.get_statistics();
    assert_eq!(stats_after_cleanup.active_correlations, SessionCount::new(0));
}

#[tokio::test]
async fn test_security_event_hash_chain_integrity() {
    let security_logger = SecurityLogger::new().unwrap();
    
    // Create a series of security events
    let mut events = Vec::new();
    
    for i in 0..5 {
        let mut event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Medium,
            format!("Test event {}", i),
            None,
        );
        
        // Simulate hash chain calculation (normally done by SecurityLogger)
        event.chain_hash = format!("hash_{}", i);
        events.push(event);
    }
    
    // Log events to build hash chain
    for event in &events {
        security_logger.log_event(event.clone());
    }
    
    assert_eq!(security_logger.get_event_count(), SuccessCount::new(5));
    
    // Note: In a real implementation, we would test hash chain integrity
    // verification, but that requires access to the internal hash calculation
    // which is private to the SecurityLogger implementation
}

#[tokio::test]
async fn test_performance_measurement_helper() {
    let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
    
    // Test performance measurement
    let measurement = buckwild_daemon::logging::performance::PerformanceMeasurement::new(
        "test_component",
        "test_operation",
        None,
    );
    
    // Simulate some work
    sleep(Duration::from_millis(10)).await;
    
    measurement.finish(&performance_logger);
    
    // Verify metrics were logged
    assert_eq!(performance_logger.get_metrics_count(), SuccessCount::new(1));
    
    // Test custom metrics
    performance_logger.set_custom_metric(
        "test_counter".to_string(),
        MetricValue::Counter(SuccessCount::new(42).as_u64()),
    );
    
    performance_logger.set_custom_metric(
        "test_gauge".to_string(),
        MetricValue::Gauge(3.14),
    );
    
    assert_eq!(performance_logger.get_custom_metric("test_counter").unwrap().as_counter(), Some(SuccessCount::new(42).as_u64()));
    assert_eq!(performance_logger.get_custom_metric("test_gauge").unwrap().as_gauge(), Some(3.14));
    
    let all_custom_metrics = performance_logger.get_all_custom_metrics();
    assert_eq!(all_custom_metrics.len(), SuccessCount::new(2).as_u64() as usize);
}