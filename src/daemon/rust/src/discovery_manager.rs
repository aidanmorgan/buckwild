//! Discovery Session Management with integrated logging and monitoring
//!
//! This module manages PSK discovery sessions with timeouts and retry logic,
//! including comprehensive logging, monitoring, and security event tracking.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use thiserror::Error;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

// Import consolidated types from common crate
use buckwild_common::protocol::types::*;

use crate::crypto::SecureBytes;
use crate::logging::{
    LoggingManager,
    performance::{MetricValue, PerformanceMetrics},
    security::{SecurityEvent, SecurityEventType, SecuritySeverity},
};
use crate::psk_discovery::{
    DISCOVERY_RETRY_COUNT, DISCOVERY_TIMEOUT, DiscoveryPacket, DiscoveryResult, PskDiscoveryEngine,
};
use crate::types::PskFingerprint;

/// Errors that can occur during discovery operations
#[derive(Error, Debug)]

pub enum DiscoveryError {
    #[error("Discovery packet send failed: {0}")]
    SendError(String),

    #[error("Discovery timeout after {attempts} attempts")]
    Timeout { attempts: u32 },

    #[error("Discovery session not found")]
    SessionNotFound,

    #[error("Channel error: {0}")]
    ChannelError(String),

    #[error("Discovery manager already started")]
    AlreadyStarted,
}

/// Discovery session with retry logic
#[derive(Debug)]

struct DiscoverySessionWithRetry {
    engine: Arc<PskDiscoveryEngine>,
    remote_endpoint: NetworkEndpoint,
    attempts: AttemptCount,
    last_attempt: Timestamp,
    result_sender: Option<tokio::sync::oneshot::Sender<DiscoveryResult>>,
}

/// Discovery Manager handles PSK discovery sessions with integrated logging and monitoring
pub struct DiscoveryManager {
    /// PSK discovery engine
    discovery_engine: Arc<PskDiscoveryEngine>,

    /// Active discovery sessions with retry logic
    active_sessions: DashMap<String, DiscoverySessionWithRetry>,

    /// Packet sender for outgoing discovery packets
    packet_sender: mpsc::UnboundedSender<DiscoveryPacket>,

    /// Packet receiver for incoming discovery packets
    packet_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<DiscoveryPacket>>>>,

    /// Cleanup interval
    cleanup_interval: std::time::Duration,

    /// Integrated logging manager
    logging_manager: Option<Arc<LoggingManager>>,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    pub fn new() -> Self {
        let discovery_engine = Arc::new(PskDiscoveryEngine::new());
        let (packet_sender, packet_receiver) = mpsc::unbounded_channel();

        Self {
            discovery_engine,
            active_sessions: DashMap::new(),
            packet_sender,
            packet_receiver: Arc::new(RwLock::new(Some(packet_receiver))),
            cleanup_interval: std::time::Duration::from_secs(30),
            logging_manager: None,
        }
    }

    /// Set the logging manager for integrated logging
    pub fn set_logging_manager(&mut self, logging_manager: Arc<LoggingManager>) {
        self.logging_manager = Some(logging_manager);

        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("discovery_manager_logging_init");

            logger.log_event(
                tracing::Level::INFO,
                "Discovery manager logging integration enabled",
                "discovery_manager",
                Some(correlation_id.clone()),
                HashMap::new(),
            );

            // Log security event for logging integration
            logger.log_security_event(SecurityEvent::new(
                SecurityEventType::SystemStartup,
                SecuritySeverity::Medium,
                "Discovery manager logging integration enabled".to_string(),
                Some(correlation_id),
            ));
        }
    }

    /// Start the discovery manager with integrated logging
    pub async fn start(&self) -> Result<(), DiscoveryError> {
        let start_time = Timestamp::now();
        let correlation_id = if let Some(ref logger) = self.logging_manager {
            let corr_id = logger.create_correlation("discovery_manager_start");

            logger.log_event(
                tracing::Level::INFO,
                "Starting PSK discovery manager",
                "discovery_manager",
                Some(corr_id.clone()),
                HashMap::new(),
            );

            Some(corr_id)
        } else {
            info!("Starting PSK discovery manager");
            None
        };

        // Start packet processing task
        let engine = self.discovery_engine.clone();
        let logging_manager = self.logging_manager.clone();
        let mut packet_receiver = self
            .packet_receiver
            .write()
            .await
            .take()
            .ok_or(DiscoveryError::AlreadyStarted)?;

        tokio::spawn(async move {
            while let Some(packet) = packet_receiver.recv().await {
                let packet_correlation = if let Some(ref logger) = logging_manager {
                    let corr_id = logger.create_correlation("discovery_packet_handle");

                    // Log packet handling (no sensitive data)
                    let mut fields = HashMap::new();
                    fields.insert(
                        "packet_type".to_string(),
                        serde_json::json!(format!("{:?}", packet.sub_type)),
                    );
                    fields.insert(
                        "discovery_id".to_string(),
                        serde_json::json!(packet.discovery_id.as_u64()),
                    );

                    logger.log_event(
                        tracing::Level::DEBUG,
                        "Handling discovery packet",
                        "discovery_manager",
                        Some(corr_id.clone()),
                        fields,
                    );

                    Some(corr_id)
                } else {
                    None
                };

                match engine.handle_discovery_packet(packet).await {
                    Ok(()) => {
                        if let (Some(logger), Some(corr_id)) =
                            (&logging_manager, packet_correlation)
                        {
                            logger.log_event(
                                tracing::Level::DEBUG,
                                "Discovery packet handled successfully",
                                "discovery_manager",
                                Some(corr_id),
                                HashMap::new(),
                            );
                        }
                    }
                    Err(e) => {
                        if let (Some(logger), Some(corr_id)) =
                            (&logging_manager, packet_correlation)
                        {
                            let sanitized_error = logger.sanitize_error_message(&e.to_string());

                            logger.log_event(
                                tracing::Level::ERROR,
                                &format!("Error handling discovery packet: {}", sanitized_error),
                                "discovery_manager",
                                Some(corr_id.clone()),
                                HashMap::new(),
                            );

                            // Log security event for packet handling failure
                            logger.log_security_event(SecurityEvent::new(
                                SecurityEventType::InvalidPacketReceived,
                                SecuritySeverity::Medium,
                                format!("Discovery packet handling failed: {}", sanitized_error),
                                Some(corr_id),
                            ));
                        } else {
                            error!("Error handling discovery packet: {}", e);
                        }
                    }
                }
            }
        });

        // Start cleanup task
        let engine_cleanup = self.discovery_engine.clone();
        let cleanup_interval = self.cleanup_interval;
        let logging_manager_cleanup = self.logging_manager.clone();

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                if let Some(ref logger) = logging_manager_cleanup {
                    let cleanup_correlation = logger.create_correlation("discovery_cleanup");

                    logger.log_event(
                        tracing::Level::DEBUG,
                        "Running discovery session cleanup",
                        "discovery_manager",
                        Some(cleanup_correlation),
                        HashMap::new(),
                    );
                }

                // Clean up expired discovery engine sessions
                engine_cleanup.cleanup_expired_sessions().await;
            }
        });

        let duration = start_time.elapsed();

        if let Some(ref logger) = self.logging_manager {
            if let Some(corr_id) = correlation_id {
                logger.log_event(
                    tracing::Level::INFO,
                    "PSK discovery manager started successfully",
                    "discovery_manager",
                    Some(corr_id.clone()),
                    HashMap::new(),
                );

                // Log security event for successful startup
                logger.log_security_event(SecurityEvent::new(
                    SecurityEventType::SystemStartup,
                    SecuritySeverity::Medium,
                    "PSK discovery manager started successfully".to_string(),
                    Some(corr_id.clone()),
                ));

                // Log performance metrics
                let mut metrics = HashMap::new();
                metrics.insert(
                    "startup_duration_ms".to_string(),
                    MetricValue::Duration(Timeout::from_millis(duration.as_millis() as u64)),
                );

                let perf_metrics = PerformanceMetrics {
                    timestamp: Timestamp::now(),
                    component: "discovery_manager".to_string(),
                    correlation_id: Some(corr_id),
                    metrics,
                };

                logger.log_performance_metrics(perf_metrics);
            }
        } else {
            info!("PSK discovery manager started successfully");
        }

        Ok(())
    }

    /// Add a PSK to the discovery engine with logging
    pub async fn add_psk(&self, fingerprint: PskFingerprint, psk: Arc<SecureBytes>) {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("psk_add");

            // Create sanitized fingerprint for logging (first 8 chars only)
            let sanitized_fingerprint = format!("{}...", hex::encode(&fingerprint[..4]));

            // Log PSK addition attempt (no sensitive data)
            let mut fields = HashMap::new();
            fields.insert(
                "fingerprint_prefix".to_string(),
                serde_json::json!(sanitized_fingerprint),
            );
            fields.insert("psk_length".to_string(), serde_json::json!(psk.len()));

            logger.log_event(
                tracing::Level::DEBUG,
                "Adding PSK to discovery manager",
                "discovery_manager",
                Some(correlation_id.clone()),
                fields,
            );

            // Add PSK to engine
            self.discovery_engine.add_psk(fingerprint, psk).await;

            // Log successful addition
            logger.log_event(
                tracing::Level::INFO,
                "PSK added successfully",
                "discovery_manager",
                Some(correlation_id.clone()),
                HashMap::new(),
            );

            // Log security event for PSK management
            logger.log_security_event(SecurityEvent::new(
                SecurityEventType::ConfigurationChanged,
                SecuritySeverity::Medium,
                "PSK added to discovery manager".to_string(),
                Some(correlation_id),
            ));
        } else {
            self.discovery_engine.add_psk(fingerprint, psk).await;
        }
    }

    /// Remove a PSK from the discovery engine with logging
    pub async fn remove_psk(&self, fingerprint: &PskFingerprint) {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("psk_remove");

            // Create sanitized fingerprint for logging
            let sanitized_fingerprint = format!("{}...", hex::encode(&fingerprint[..4]));

            // Log PSK removal attempt
            let mut fields = HashMap::new();
            fields.insert(
                "fingerprint_prefix".to_string(),
                serde_json::json!(sanitized_fingerprint),
            );

            logger.log_event(
                tracing::Level::DEBUG,
                "Removing PSK from discovery manager",
                "discovery_manager",
                Some(correlation_id.clone()),
                fields,
            );

            // Remove PSK from engine
            self.discovery_engine.remove_psk(fingerprint).await;

            // Log successful removal
            logger.log_event(
                tracing::Level::INFO,
                "PSK removed successfully",
                "discovery_manager",
                Some(correlation_id.clone()),
                HashMap::new(),
            );

            // Log security event for PSK management
            logger.log_security_event(SecurityEvent::new(
                SecurityEventType::ConfigurationChanged,
                SecuritySeverity::Medium,
                "PSK removed from discovery manager".to_string(),
                Some(correlation_id),
            ));
        } else {
            self.discovery_engine.remove_psk(fingerprint).await;
        }
    }

    /// Discover shared PSK with a remote endpoint with logging
    pub async fn discover_psk(
        &self,
        remote_endpoint: NetworkEndpoint,
    ) -> Result<DiscoveryResult, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Timestamp::now();
        let correlation_id = if let Some(ref logger) = self.logging_manager {
            let corr_id = logger.create_correlation("psk_discovery");

            // Sanitize endpoint for logging (mask IP if present)
            let sanitized_endpoint = logger.sanitize_string(remote_endpoint.to_string());

            // Log discovery attempt
            let mut fields = HashMap::new();
            fields.insert(
                "remote_endpoint".to_string(),
                serde_json::json!(sanitized_endpoint),
            );

            logger.log_event(
                tracing::Level::INFO,
                "Starting PSK discovery",
                "discovery_manager",
                Some(corr_id.clone()),
                fields,
            );

            Some(corr_id)
        } else {
            info!("Starting PSK discovery with endpoint: {}", remote_endpoint);
            None
        };

        // Check if there's already an active session for this endpoint
        if self
            .active_sessions
            .contains_key(&remote_endpoint.to_string())
        {
            if let Some(ref logger) = self.logging_manager {
                if let Some(corr_id) = correlation_id {
                    logger.log_event(
                        tracing::Level::WARN,
                        "Discovery already in progress for endpoint",
                        "discovery_manager",
                        Some(corr_id),
                        HashMap::new(),
                    );
                }
            }
            return Err("Discovery already in progress for this endpoint".into());
        }

        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();

        // Create retry session
        let retry_session = DiscoverySessionWithRetry {
            engine: self.discovery_engine.clone(),
            remote_endpoint,
            attempts: AttemptCount::from_raw(0),
            last_attempt: Timestamp::now(),
            result_sender: Some(result_sender),
        };

        self.active_sessions
            .insert(remote_endpoint.to_string(), retry_session);

        // Start discovery attempt
        self.attempt_discovery(&remote_endpoint.to_string()).await?;

        // Wait for result
        let result: Result<DiscoveryResult, Box<dyn std::error::Error + Send + Sync>> =
            match timeout(
                DISCOVERY_TIMEOUT * (DISCOVERY_RETRY_COUNT as u32 + 1),
                result_receiver,
            )
            .await
            {
                Ok(Ok(result)) => {
                    self.active_sessions.remove(&remote_endpoint.to_string());
                    Ok(result)
                }
                Ok(Err(_)) => {
                    self.active_sessions.remove(&remote_endpoint.to_string());
                    Ok(DiscoveryResult::Error("Result channel closed".to_string()))
                }
                Err(_) => {
                    self.active_sessions.remove(&remote_endpoint.to_string());
                    Ok(DiscoveryResult::Timeout)
                }
            };

        let duration = start_time.elapsed();

        // Log result with performance metrics
        if let Some(ref logger) = self.logging_manager {
            if let Some(corr_id) = correlation_id {
                match &result {
                    Ok(DiscoveryResult::Success { .. }) => {
                        logger.log_event(
                            tracing::Level::INFO,
                            "PSK discovery completed successfully",
                            "discovery_manager",
                            Some(corr_id.clone()),
                            HashMap::new(),
                        );

                        // Log security event for successful authentication
                        logger.log_security_event(SecurityEvent::new(
                            SecurityEventType::AuthenticationSuccess,
                            SecuritySeverity::Low,
                            "PSK discovery successful".to_string(),
                            Some(corr_id.clone()),
                        ));
                    }
                    Ok(DiscoveryResult::Timeout) => {
                        logger.log_event(
                            tracing::Level::WARN,
                            "PSK discovery timed out",
                            "discovery_manager",
                            Some(corr_id.clone()),
                            HashMap::new(),
                        );

                        // Log security event for timeout (potential attack)
                        logger.log_security_event(SecurityEvent::new(
                            SecurityEventType::TimingAttackDetected,
                            SecuritySeverity::Medium,
                            "PSK discovery timeout - potential timing attack".to_string(),
                            Some(corr_id.clone()),
                        ));
                    }
                    Ok(DiscoveryResult::NoSharedPsk) => {
                        logger.log_event(
                            tracing::Level::WARN,
                            "No shared PSK found during discovery",
                            "discovery_manager",
                            Some(corr_id.clone()),
                            HashMap::new(),
                        );

                        // Log security event for no shared PSK
                        logger.log_security_event(SecurityEvent::new(
                            SecurityEventType::AuthenticationFailure,
                            SecuritySeverity::Low,
                            "No shared PSK found during discovery".to_string(),
                            Some(corr_id.clone()),
                        ));
                    }
                    Ok(DiscoveryResult::Error(error)) => {
                        let sanitized_error = logger.sanitize_error_message(error);

                        logger.log_event(
                            tracing::Level::ERROR,
                            &format!("PSK discovery failed: {}", sanitized_error),
                            "discovery_manager",
                            Some(corr_id.clone()),
                            HashMap::new(),
                        );

                        // Log security event for authentication failure
                        logger.log_security_event(SecurityEvent::new(
                            SecurityEventType::AuthenticationFailure,
                            SecuritySeverity::Medium,
                            format!("PSK discovery failed: {}", sanitized_error),
                            Some(corr_id.clone()),
                        ));
                    }
                    Err(e) => {
                        let sanitized_error = logger.sanitize_error_message(&e.to_string());

                        logger.log_event(
                            tracing::Level::ERROR,
                            &format!("PSK discovery system error: {}", sanitized_error),
                            "discovery_manager",
                            Some(corr_id.clone()),
                            HashMap::new(),
                        );

                        // Log security event for system error
                        logger.log_security_event(SecurityEvent::new(
                            SecurityEventType::CryptographicFailure,
                            SecuritySeverity::High,
                            format!("PSK discovery system error: {}", sanitized_error),
                            Some(corr_id.clone()),
                        ));
                    }
                }

                // Log performance metrics
                let mut metrics = HashMap::new();
                metrics.insert(
                    "discovery_duration_ms".to_string(),
                    MetricValue::Duration(Timeout::from_millis(duration.as_millis() as u64)),
                );
                metrics.insert(
                    "discovery_success".to_string(),
                    MetricValue::Counter(if result.is_ok() { 1 } else { 0 }),
                );

                let perf_metrics = PerformanceMetrics {
                    timestamp: Timestamp::now(),
                    component: "discovery_manager".to_string(),
                    correlation_id: Some(corr_id),
                    metrics,
                };

                logger.log_performance_metrics(perf_metrics);
            }
        }

        result
    }

    /// Attempt discovery for an endpoint
    async fn attempt_discovery(
        &self,
        remote_endpoint: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(mut session_entry) = self.active_sessions.get_mut(remote_endpoint) {
            let session = session_entry.value_mut();

            if session.attempts.as_raw() >= DISCOVERY_RETRY_COUNT as u32 {
                // Max retries exceeded
                if let Some(sender) = session.result_sender.take() {
                    let _ = sender.send(DiscoveryResult::Error("Max retries exceeded".to_string()));
                }
                return Ok(());
            }

            session.attempts = AttemptCount::from_raw(session.attempts.as_raw() + 1);
            session.last_attempt = Timestamp::now();

            if let Some(ref logger) = self.logging_manager {
                let correlation_id = logger.create_correlation("discovery_attempt");

                let mut fields = HashMap::new();
                fields.insert(
                    "attempt".to_string(),
                    serde_json::json!(session.attempts.as_raw()),
                );
                fields.insert(
                    "max_attempts".to_string(),
                    serde_json::json!(DISCOVERY_RETRY_COUNT),
                );

                logger.log_event(
                    tracing::Level::DEBUG,
                    "Attempting PSK discovery",
                    "discovery_manager",
                    Some(correlation_id),
                    fields,
                );
            } else {
                debug!(
                    "Attempting PSK discovery with {} (attempt {}/{})",
                    remote_endpoint,
                    session.attempts.as_raw(),
                    DISCOVERY_RETRY_COUNT
                );
            }

            // Clone the engine for the async task
            let engine = session.engine.clone();
            let endpoint = remote_endpoint.to_string();
            let attempt_num = session.attempts.as_raw();
            let logging_manager = self.logging_manager.clone();

            // Spawn discovery task
            tokio::spawn(async move {
                match engine.initiate_discovery(endpoint.clone()).await {
                    Ok(result) => {
                        if let Some(ref logger) = logging_manager {
                            let correlation_id =
                                logger.create_correlation("discovery_attempt_result");

                            logger.log_event(
                                tracing::Level::DEBUG,
                                "Discovery attempt completed",
                                "discovery_manager",
                                Some(correlation_id),
                                HashMap::new(),
                            );
                        } else {
                            debug!(
                                "Discovery attempt {} completed for {}: {:?}",
                                attempt_num, endpoint, result
                            );
                        }
                    }
                    Err(e) => {
                        if let Some(ref logger) = logging_manager {
                            let correlation_id =
                                logger.create_correlation("discovery_attempt_error");
                            let sanitized_error = logger.sanitize_error_message(&e.to_string());

                            logger.log_event(
                                tracing::Level::ERROR,
                                &format!("Discovery attempt failed: {}", sanitized_error),
                                "discovery_manager",
                                Some(correlation_id),
                                HashMap::new(),
                            );
                        } else {
                            error!(
                                "Discovery attempt {} failed for {}: {}",
                                attempt_num, endpoint, e
                            );
                        }
                    }
                }
            });
        }

        Ok(())
    }

    /// Handle discovery timeout and retry with logging
    pub async fn handle_discovery_timeout(&self, remote_endpoint: &str) {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("discovery_timeout");
            let sanitized_endpoint = logger.sanitize_string(remote_endpoint.to_string());

            let mut fields = HashMap::new();
            fields.insert(
                "remote_endpoint".to_string(),
                serde_json::json!(sanitized_endpoint),
            );

            logger.log_event(
                tracing::Level::WARN,
                "Handling discovery timeout",
                "discovery_manager",
                Some(correlation_id.clone()),
                fields,
            );

            // Log security event for potential attack
            logger.log_security_event(SecurityEvent::new(
                SecurityEventType::TimingAttackDetected,
                SecuritySeverity::Medium,
                "Discovery timeout handled - potential timing attack".to_string(),
                Some(correlation_id),
            ));
        }

        if let Some(session_entry) = self.active_sessions.get(remote_endpoint) {
            let session = session_entry.value();

            if session.attempts.as_raw() < DISCOVERY_RETRY_COUNT as u32 {
                if let Some(ref logger) = self.logging_manager {
                    let mut fields = HashMap::new();
                    fields.insert(
                        "attempt".to_string(),
                        serde_json::json!(session.attempts.as_raw() + 1),
                    );
                    fields.insert(
                        "max_attempts".to_string(),
                        serde_json::json!(DISCOVERY_RETRY_COUNT),
                    );

                    logger.log_event(
                        tracing::Level::WARN,
                        "Discovery timeout, retrying",
                        "discovery_manager",
                        None,
                        fields,
                    );
                } else {
                    warn!(
                        "Discovery timeout for {}, retrying (attempt {}/{})",
                        remote_endpoint,
                        session.attempts.as_raw() + 1,
                        DISCOVERY_RETRY_COUNT
                    );
                }

                drop(session_entry);

                // Note: Retry logic would need to be implemented differently
                // due to lifetime constraints with the current design
                warn!(
                    "Discovery timeout for {}, retry not implemented yet",
                    remote_endpoint
                );
            } else {
                // Max retries exceeded
                if let Some(ref logger) = self.logging_manager {
                    logger.log_event(
                        tracing::Level::WARN,
                        "Max discovery retries exceeded",
                        "discovery_manager",
                        None,
                        HashMap::new(),
                    );
                } else {
                    warn!("Max discovery retries exceeded for {}", remote_endpoint);
                }

                if let Some((_, mut session)) = self.active_sessions.remove(remote_endpoint) {
                    if let Some(sender) = session.result_sender.take() {
                        let _ = sender.send(DiscoveryResult::Timeout);
                    }
                }
            }
        }
    }

    /// Handle successful discovery with logging
    pub async fn handle_discovery_success(&self, remote_endpoint: &str, result: DiscoveryResult) {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("discovery_success");
            let sanitized_endpoint = logger.sanitize_string(remote_endpoint.to_string());

            let mut fields = HashMap::new();
            fields.insert(
                "remote_endpoint".to_string(),
                serde_json::json!(sanitized_endpoint),
            );

            logger.log_event(
                tracing::Level::INFO,
                "PSK discovery successful",
                "discovery_manager",
                Some(correlation_id.clone()),
                fields,
            );

            // Log security event for successful authentication
            logger.log_security_event(SecurityEvent::new(
                SecurityEventType::AuthenticationSuccess,
                SecuritySeverity::Low,
                "Discovery success handled".to_string(),
                Some(correlation_id),
            ));
        } else {
            info!("PSK discovery successful for {}", remote_endpoint);
        }

        if let Some((_, mut session)) = self.active_sessions.remove(remote_endpoint) {
            if let Some(sender) = session.result_sender.take() {
                let _ = sender.send(result);
            }
        }
    }

    /// Handle discovery failure with logging
    pub async fn handle_discovery_failure(&self, remote_endpoint: &str, error: String) {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("discovery_failure");
            let sanitized_endpoint = logger.sanitize_string(remote_endpoint.to_string());
            let sanitized_error = logger.sanitize_error_message(&error);

            let mut fields = HashMap::new();
            fields.insert(
                "remote_endpoint".to_string(),
                serde_json::json!(sanitized_endpoint),
            );
            fields.insert("error".to_string(), serde_json::json!(sanitized_error));

            logger.log_event(
                tracing::Level::WARN,
                "PSK discovery failed",
                "discovery_manager",
                Some(correlation_id.clone()),
                fields,
            );

            // Log security event for authentication failure
            logger.log_security_event(SecurityEvent::new(
                SecurityEventType::AuthenticationFailure,
                SecuritySeverity::Medium,
                format!("Discovery failure handled: {}", sanitized_error),
                Some(correlation_id),
            ));
        } else {
            warn!("PSK discovery failed for {}: {}", remote_endpoint, error);
        }

        if let Some(session_entry) = self.active_sessions.get(remote_endpoint) {
            let session = session_entry.value();

            if session.attempts.as_raw() < DISCOVERY_RETRY_COUNT as u32 {
                // Retry
                drop(session_entry);
                self.handle_discovery_timeout(remote_endpoint).await;
            } else {
                // Max retries exceeded
                drop(session_entry);

                if let Some((_, mut session)) = self.active_sessions.remove(remote_endpoint) {
                    if let Some(sender) = session.result_sender.take() {
                        let _ = sender.send(DiscoveryResult::Error(error));
                    }
                }
            }
        }
    }

    /// Clean up expired retry sessions
    async fn cleanup_expired_retry_sessions(
        active_sessions: &DashMap<String, DiscoverySessionWithRetry>,
    ) {
        let _now = Instant::now();
        let mut expired_endpoints = Vec::new();

        for entry in active_sessions.iter() {
            let session = entry.value();
            let total_timeout = DISCOVERY_TIMEOUT * (DISCOVERY_RETRY_COUNT as u32 + 1);

            if session.last_attempt.elapsed() > total_timeout {
                expired_endpoints.push(entry.key().clone());
            }
        }

        for endpoint in expired_endpoints {
            if let Some((_, mut session)) = active_sessions.remove(&endpoint) {
                if let Some(sender) = session.result_sender.take() {
                    let _ = sender.send(DiscoveryResult::Timeout);
                }
            }

            debug!("Cleaned up expired discovery session for: {}", endpoint);
        }
    }

    /// Get discovery statistics with performance logging
    pub async fn get_statistics(&self) -> DiscoveryManagerStatistics {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("get_statistics");

            logger.log_event(
                tracing::Level::DEBUG,
                "Discovery manager statistics requested",
                "discovery_manager",
                Some(correlation_id),
                HashMap::new(),
            );
        }

        let engine_stats = self.discovery_engine.get_statistics().await;
        let active_retry_sessions = self.active_sessions.len();

        let stats = DiscoveryManagerStatistics {
            active_sessions: engine_stats.active_sessions,
            active_retry_sessions,
            cached_psks: engine_stats.cached_psks,
            local_psks: engine_stats.local_psks,
        };

        // Log performance metrics
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("statistics_metrics");

            let mut metrics = HashMap::new();
            metrics.insert(
                "active_sessions".to_string(),
                MetricValue::Gauge(stats.active_sessions as f64),
            );
            metrics.insert(
                "active_retry_sessions".to_string(),
                MetricValue::Gauge(stats.active_retry_sessions as f64),
            );
            metrics.insert(
                "cached_psks".to_string(),
                MetricValue::Gauge(stats.cached_psks as f64),
            );
            metrics.insert(
                "local_psks".to_string(),
                MetricValue::Gauge(stats.local_psks as f64),
            );

            let perf_metrics = PerformanceMetrics {
                timestamp: Timestamp::now(),
                component: "discovery_manager".to_string(),
                correlation_id: Some(correlation_id),
                metrics,
            };

            logger.log_performance_metrics(perf_metrics);
        }

        stats
    }

    /// Send a discovery packet with logging
    pub async fn send_discovery_packet(
        &self,
        packet: DiscoveryPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("send_packet");

            // Log packet send attempt (no sensitive data)
            let mut fields = HashMap::new();
            fields.insert(
                "packet_type".to_string(),
                serde_json::json!(format!("{:?}", packet.sub_type)),
            );
            fields.insert(
                "discovery_id".to_string(),
                serde_json::json!(packet.discovery_id.as_u64()),
            );

            logger.log_event(
                tracing::Level::DEBUG,
                "Sending discovery packet",
                "discovery_manager",
                Some(correlation_id.clone()),
                fields,
            );

            match self.packet_sender.send(packet) {
                Ok(()) => {
                    logger.log_event(
                        tracing::Level::DEBUG,
                        "Discovery packet sent successfully",
                        "discovery_manager",
                        Some(correlation_id),
                        HashMap::new(),
                    );
                    Ok(())
                }
                Err(e) => {
                    let sanitized_error = logger.sanitize_error_message(&e.to_string());

                    logger.log_event(
                        tracing::Level::ERROR,
                        &format!("Failed to send discovery packet: {}", sanitized_error),
                        "discovery_manager",
                        Some(correlation_id),
                        HashMap::new(),
                    );

                    Err(e.into())
                }
            }
        } else {
            self.packet_sender.send(packet)?;
            Ok(())
        }
    }

    /// Handle incoming discovery packet with logging
    pub async fn handle_incoming_packet(
        &self,
        packet: DiscoveryPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref logger) = self.logging_manager {
            let correlation_id = logger.create_correlation("handle_packet");

            // Log packet handling (no sensitive data)
            let mut fields = HashMap::new();
            fields.insert(
                "packet_type".to_string(),
                serde_json::json!(format!("{:?}", packet.sub_type)),
            );
            fields.insert(
                "discovery_id".to_string(),
                serde_json::json!(packet.discovery_id.as_u64()),
            );

            logger.log_event(
                tracing::Level::DEBUG,
                "Handling incoming discovery packet",
                "discovery_manager",
                Some(correlation_id.clone()),
                fields,
            );

            match self.discovery_engine.handle_discovery_packet(packet).await {
                Ok(()) => {
                    logger.log_event(
                        tracing::Level::DEBUG,
                        "Discovery packet handled successfully",
                        "discovery_manager",
                        Some(correlation_id),
                        HashMap::new(),
                    );
                    Ok(())
                }
                Err(e) => {
                    let sanitized_error = logger.sanitize_error_message(&e.to_string());

                    logger.log_event(
                        tracing::Level::ERROR,
                        &format!("Failed to handle discovery packet: {}", sanitized_error),
                        "discovery_manager",
                        Some(correlation_id.clone()),
                        HashMap::new(),
                    );

                    // Log security event for packet handling failure
                    logger.log_security_event(SecurityEvent::new(
                        SecurityEventType::InvalidPacketReceived,
                        SecuritySeverity::Medium,
                        format!("Failed to handle discovery packet: {}", sanitized_error),
                        Some(correlation_id),
                    ));

                    Err(e)
                }
            }
        } else {
            self.discovery_engine.handle_discovery_packet(packet).await
        }
    }
}

/// Discovery manager statistics
#[derive(Debug, Clone)]

pub struct DiscoveryManagerStatistics {
    pub active_sessions: usize,
    pub active_retry_sessions: usize,
    pub cached_psks: usize,
    pub local_psks: usize,
}

impl Default for DiscoveryManager {
    fn default() -> Self {
        Self::new()
    }
}
