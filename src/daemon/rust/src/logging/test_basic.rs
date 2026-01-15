use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::{LoggingManager, LoggingConfig};
use super::correlation::CorrelationId;
use super::security::{SecurityLogger, SecurityEvent, SecurityEventType, SecuritySeverity};
use super::performance::{PerformanceLogger, PerformanceMetrics, MetricValue};
use super::sanitizer::LogSanitizer;

#[tokio::test]
async fn test_basic_logging_functionality() {
    // Test logging manager creation
    let config = LoggingConfig::default();
    let logging_manager = Arc::new(LoggingManager::new(config).unwrap());
    
    // Test correlation creation
    let correlation_id = logging_manager.create_correlation("test_operation");
    assert!(!correlation_id.to_string().is_empty());

    // Test structured logging
    let mut fields = HashMap::new();
    fields.insert("test_field".to_string(), serde_json::json!("test_value"));
    
    logging_manager.log_event(
        tracing::Level::INFO,
        "Test message",
        "test_component",
        Some(correlation_id),
        fields,
    );

    let stats = logging_manager.get_statistics();
    assert_eq!(stats.active_correlations, 1);
}

#[tokio::test]
async fn test_security_logging() {
    let security_logger = SecurityLogger::new().unwrap();
    
    security_logger.log_authentication_failure("192.168.1.100", "Invalid credentials", None);
    
    assert_eq!(security_logger.get_event_count(), 1);
}

#[tokio::test]
async fn test_performance_logging() {
    let performance_logger = Arc::new(PerformanceLogger::new().unwrap());
    
    let mut metrics = HashMap::new();
    metrics.insert("test_counter".to_string(), MetricValue::Counter(42));
    
    let perf_metrics = PerformanceMetrics {
        timestamp: chrono::Utc::now(),
        component: "test_component".to_string(),
        correlation_id: None,
        metrics,
    };
    
    performance_logger.log_metrics(perf_metrics);
    assert_eq!(performance_logger.get_metrics_count(), 1);
}

#[tokio::test]
async fn test_log_sanitization() {
    let sanitizer = LogSanitizer::new();
    
    let mut fields = HashMap::new();
    fields.insert("password".to_string(), serde_json::json!("secret123"));
    fields.insert("normal_field".to_string(), serde_json::json!("normal_value"));
    
    let sanitized = sanitizer.sanitize_fields(fields);
    
    assert_eq!(sanitized.get("password").unwrap(), &serde_json::json!("[REDACTED]"));
    assert_eq!(sanitized.get("normal_field").unwrap(), &serde_json::json!("normal_value"));
}

#[test]
fn test_correlation_id_creation() {
    let id1 = CorrelationId::new();
    let id2 = CorrelationId::new();
    
    assert_ne!(id1, id2);
    assert!(!id1.to_string().is_empty());
}

#[test]
fn test_security_event_cef_format() {
    let event = SecurityEvent::new(
        SecurityEventType::AuthenticationFailure,
        SecuritySeverity::Medium,
        "Test authentication failure".to_string(),
        None,
    );
    
    let cef = event.to_cef();
    assert!(cef.starts_with("CEF:0|Buckwild|FrequencyHoppingNetwork|1.0|"));
    assert!(cef.contains("AuthenticationFailure"));
    assert!(cef.contains("Test authentication failure"));
}