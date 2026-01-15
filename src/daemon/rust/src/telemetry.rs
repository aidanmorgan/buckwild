//! OpenTelemetry telemetry initialization for the daemon.
//!
//! This module provides OTLP export for traces, logs, and metrics using the
//! OpenTelemetry SDK with tokio runtime integration.

use opentelemetry_otlp::WithExportConfig;
use thiserror::Error;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Errors that can occur during telemetry initialization
#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("Failed to initialize OpenTelemetry tracer: {0}")]
    TracerInit(String),
    #[error("Failed to set global tracing subscriber: {0}")]
    SubscriberInit(String),
    #[error("OTLP endpoint not configured")]
    EndpointNotConfigured,
}

/// Initialize OpenTelemetry telemetry with OTLP export.
///
/// This function sets up a tracing subscriber that exports traces to an OTLP endpoint.
/// The endpoint is configured via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable.
///
/// # Environment Variables
///
/// - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint URL (required)
/// - `RUST_LOG`: Log level filter (optional, defaults to "info")
///
/// # Errors
///
/// Returns an error if:
/// - The OTLP endpoint is not configured
/// - The OpenTelemetry tracer cannot be initialized
/// - The tracing subscriber cannot be set as the global default
pub fn init_telemetry() -> Result<(), TelemetryError> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .map_err(|_| TelemetryError::EndpointNotConfigured)?;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::config().with_resource(
            opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", "buckwild-daemon"),
                opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            ]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| TelemetryError::TracerInit(e.to_string()))?;

    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

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
        .map_err(|e| TelemetryError::SubscriberInit(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_error_display() {
        let tracer_err = TelemetryError::TracerInit("test error".to_string());
        assert!(tracer_err.to_string().contains("test error"));

        let subscriber_err = TelemetryError::SubscriberInit("init failed".to_string());
        assert!(subscriber_err.to_string().contains("init failed"));

        let endpoint_err = TelemetryError::EndpointNotConfigured;
        assert!(endpoint_err.to_string().contains("not configured"));
    }

    #[test]
    fn test_init_telemetry_without_endpoint() {
        // Ensure env var is not set for this test
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");

        let result = init_telemetry();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TelemetryError::EndpointNotConfigured));
    }
}
