use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::Tracer;

pub mod correlation;
pub mod performance;
pub mod sanitizer;
pub mod security;

use correlation::CorrelationId;
use sanitizer::LogSanitizer;

/// Errors that can occur during logging manager operations
#[derive(Error, Debug)]
pub enum LoggingError {
    #[error("Failed to set global tracing subscriber")]
    TracingInit,
    #[error("Failed to initialize OpenTelemetry: {0}")]
    OpenTelemetryInit(String),
}

/// Structured log event with correlation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub correlation_id: Option<CorrelationId>,
    pub component: String,
    pub session_id: Option<String>, // Sanitized session ID (hash only)
    pub fields: HashMap<String, serde_json::Value>,
}

/// Security-focused logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub enable_correlation: bool,
    pub enable_security_audit: bool,
    pub enable_performance_metrics: bool,
    pub sanitize_sensitive_data: bool,
    pub max_correlation_entries: usize,
    pub correlation_ttl_seconds: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            enable_correlation: true,
            enable_security_audit: true,
            enable_performance_metrics: true,
            sanitize_sensitive_data: true,
            max_correlation_entries: 10000,
            correlation_ttl_seconds: 3600, // 1 hour
        }
    }
}

/// Centralized logging manager with security features
pub struct LoggingManager {
    config: Arc<RwLock<LoggingConfig>>,
    correlation_tracker: Arc<DashMap<CorrelationId, correlation::CorrelationContext>>,
    sanitizer: LogSanitizer,
    security_logger: security::SecurityLogger,
    performance_logger: performance::PerformanceLogger,
}

/// Set up OpenTelemetry tracer with OTLP exporter
fn setup_opentelemetry() -> Result<Tracer, LoggingError> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").map_err(|_| {
        LoggingError::OpenTelemetryInit("OTEL_EXPORTER_OTLP_ENDPOINT not set".to_string())
    })?;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::config().with_resource(
            opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
                "service.name",
                "buckwild-daemon",
            )]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| LoggingError::OpenTelemetryInit(e.to_string()))?;

    Ok(tracer)
}

impl LoggingManager {
    pub fn new(config: LoggingConfig) -> Result<Self, LoggingError> {
        // Initialize tracing subscriber with security-focused configuration
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

        // Check if OpenTelemetry is configured
        let otel_configured = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok();

        if otel_configured {
            // Set up OpenTelemetry with JSON formatting
            let tracer = setup_opentelemetry()?;
            let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

            tracing_subscriber::registry()
                .with(filter)
                .with(telemetry_layer)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_current_span(true)
                        .with_span_list(true),
                )
                .try_init()
                .map_err(|_| LoggingError::TracingInit)?;
        } else {
            // Fallback to JSON-only logging without OpenTelemetry
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true),
                )
                .try_init()
                .map_err(|_| LoggingError::TracingInit)?;
        }

        let correlation_tracker = Arc::new(DashMap::new());
        let sanitizer = LogSanitizer::new();
        let security_logger = security::SecurityLogger::new();
        let performance_logger = performance::PerformanceLogger::new();

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            correlation_tracker,
            sanitizer,
            security_logger,
            performance_logger,
        })
    }

    /// Create a new correlation context for request tracking
    pub fn create_correlation(&self, operation: &str) -> CorrelationId {
        let correlation_id = CorrelationId::new();

        if self.config.read().enable_correlation {
            let context = correlation::CorrelationContext::new(operation.to_string());
            self.correlation_tracker
                .insert(correlation_id.clone(), context);
        }

        correlation_id
    }

    /// Log structured event with correlation and sanitization
    pub fn log_event(
        &self,
        level: Level,
        message: &str,
        component: &str,
        correlation_id: Option<CorrelationId>,
        fields: HashMap<String, serde_json::Value>,
    ) {
        let config = self.config.read();

        // Sanitize sensitive data from fields
        let sanitized_fields = if config.sanitize_sensitive_data {
            self.sanitizer.sanitize_fields(fields)
        } else {
            fields
        };

        let event = LogEvent {
            timestamp: Utc::now(),
            level: level.to_string(),
            message: message.to_string(),
            correlation_id: correlation_id.clone(),
            component: component.to_string(),
            session_id: None, // Will be set by sanitizer if needed
            fields: sanitized_fields,
        };

        // Update correlation context if present
        if let Some(ref corr_id) = correlation_id {
            if let Some(mut context) = self.correlation_tracker.get_mut(corr_id) {
                context.add_event(event.clone());
            }
        }

        // Emit structured log
        match level {
            Level::ERROR => error!(
                correlation_id = ?correlation_id,
                component = component,
                fields = ?event.fields,
                "{}", message
            ),
            Level::WARN => warn!(
                correlation_id = ?correlation_id,
                component = component,
                fields = ?event.fields,
                "{}", message
            ),
            Level::INFO => info!(
                correlation_id = ?correlation_id,
                component = component,
                fields = ?event.fields,
                "{}", message
            ),
            Level::DEBUG => debug!(
                correlation_id = ?correlation_id,
                component = component,
                fields = ?event.fields,
                "{}", message
            ),
            _ => debug!(
                correlation_id = ?correlation_id,
                component = component,
                fields = ?event.fields,
                "{}", message
            ),
        }
    }

    /// Log security event with audit trail
    pub fn log_security_event(&self, event: security::SecurityEvent) {
        self.security_logger.log_event(event);
    }

    /// Log performance metrics
    pub fn log_performance_metrics(&self, metrics: performance::PerformanceMetrics) {
        self.performance_logger.log_metrics(metrics);
    }

    /// Clean up expired correlation contexts
    pub fn cleanup_correlations(&self) {
        let config = self.config.read();
        let ttl = std::time::Duration::from_secs(config.correlation_ttl_seconds);

        self.correlation_tracker
            .retain(|_, context| context.created_at.elapsed() < ttl);
    }

    /// Update logging configuration atomically
    pub fn update_config(&self, new_config: LoggingConfig) {
        *self.config.write() = new_config;
        info!("Logging configuration updated");
    }

    /// Get current logging statistics
    pub fn get_statistics(&self) -> LoggingStatistics {
        LoggingStatistics {
            active_correlations: self.correlation_tracker.len(),
            security_events_count: self.security_logger.get_event_count(),
            performance_metrics_count: self.performance_logger.get_metrics_count(),
        }
    }

    /// Sanitize an error message to remove sensitive information
    pub fn sanitize_error_message(&self, error: &str) -> String {
        self.sanitizer.sanitize_error_message(error)
    }

    /// Sanitize a string to remove sensitive information
    pub fn sanitize_string(&self, input: String) -> String {
        self.sanitizer.sanitize_string(input)
    }
}

#[derive(Debug, Serialize)]
pub struct LoggingStatistics {
    pub active_correlations: usize,
    pub security_events_count: u64,
    pub performance_metrics_count: u64,
}

/// Convenience macros for structured logging with correlation
#[macro_export]
macro_rules! log_with_correlation {
    ($manager:expr, $level:expr, $correlation:expr, $component:expr, $message:expr) => {
        $manager.log_event($level, $message, $component, Some($correlation), std::collections::HashMap::new())
    };
    ($manager:expr, $level:expr, $correlation:expr, $component:expr, $message:expr, $($key:expr => $value:expr),*) => {
        {
            let mut fields = std::collections::HashMap::new();
            $(
                fields.insert($key.to_string(), serde_json::json!($value));
            )*
            $manager.log_event($level, $message, $component, Some($correlation), fields)
        }
    };
}

#[macro_export]
macro_rules! log_security {
    ($manager:expr, $event_type:expr, $severity:expr, $message:expr) => {
        $manager.log_security_event($crate::logging::security::SecurityEvent::new(
            $event_type,
            $severity,
            $message.to_string(),
            None,
        ))
    };
    ($manager:expr, $event_type:expr, $severity:expr, $message:expr, $correlation:expr) => {
        $manager.log_security_event($crate::logging::security::SecurityEvent::new(
            $event_type,
            $severity,
            $message.to_string(),
            Some($correlation),
        ))
    };
}
