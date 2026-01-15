use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{error, info, warn};

use super::correlation::CorrelationId;
use super::sanitizer::LogSanitizer;

/// Security event types for audit logging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityEventType {
    AuthenticationFailure,
    AuthenticationSuccess,
    ConnectionEstablished,
    ConnectionTerminated,
    PacketDropped,
    RateLimitExceeded,
    FragmentBombDetected,
    ReplayAttackDetected,
    EnumerationAttackDetected,
    TimingAttackDetected,
    InvalidPacketReceived,
    SessionHijackAttempt,
    CryptographicFailure,
    ConfigurationChanged,
    SystemStartup,
    SystemShutdown,
    EmergencyShutdown,
    SuspiciousActivity,
}

/// Security event severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum SecuritySeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Security event with audit trail information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub message: String,
    pub correlation_id: Option<CorrelationId>,
    pub source_ip: Option<String>,
    pub session_id_hash: Option<String>, // Sanitized session ID
    pub additional_data: HashMap<String, serde_json::Value>,
    pub chain_hash: String, // Hash chain for tamper detection
}

impl SecurityEvent {
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        message: String,
        correlation_id: Option<CorrelationId>,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        Self {
            id,
            timestamp,
            event_type,
            severity,
            message,
            correlation_id,
            source_ip: None,
            session_id_hash: None,
            additional_data: HashMap::new(),
            chain_hash: String::new(), // Will be set by SecurityLogger
        }
    }

    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_session_hash(mut self, session_hash: String) -> Self {
        self.session_id_hash = Some(session_hash);
        self
    }

    pub fn with_additional_data(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional_data.insert(key, value);
        self
    }

    /// Convert to Common Event Format (CEF) for SIEM compatibility
    pub fn to_cef(&self) -> String {
        let device_vendor = "Buckwild";
        let device_product = "FrequencyHoppingNetwork";
        let device_version = "1.0";
        let signature_id = format!("{:?}", self.event_type);
        let name = &self.message;
        let severity = self.severity as u8;

        let mut extensions = Vec::new();

        if let Some(ref source_ip) = self.source_ip {
            extensions.push(format!("src={}", source_ip));
        }

        if let Some(ref correlation_id) = self.correlation_id {
            extensions.push(format!("cs1={}", correlation_id));
            extensions.push("cs1Label=CorrelationID".to_string());
        }

        if let Some(ref session_hash) = self.session_id_hash {
            extensions.push(format!("cs2={}", session_hash));
            extensions.push("cs2Label=SessionHash".to_string());
        }

        extensions.push(format!("cs3={}", self.chain_hash));
        extensions.push("cs3Label=ChainHash".to_string());

        extensions.push(format!("rt={}", self.timestamp.timestamp_millis()));

        // Add additional data as custom fields
        for (key, value) in &self.additional_data {
            extensions.push(format!("cs4={}={}", key, value));
        }
        extensions.push("cs4Label=AdditionalData".to_string());

        let extension_string = extensions.join(" ");

        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            device_vendor,
            device_product,
            device_version,
            signature_id,
            name,
            severity,
            extension_string
        )
    }
}

/// Security logger with hash chaining for tamper detection
pub struct SecurityLogger {
    event_counter: AtomicU64,
    last_chain_hash: Arc<RwLock<String>>,
    sanitizer: LogSanitizer,
}

impl Default for SecurityLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityLogger {
    pub fn new() -> Self {
        let initial_hash = Self::calculate_initial_hash();

        Self {
            event_counter: AtomicU64::new(0),
            last_chain_hash: Arc::new(RwLock::new(initial_hash)),
            sanitizer: LogSanitizer::new(),
        }
    }

    /// Log security event with hash chaining
    pub fn log_event(&self, mut event: SecurityEvent) {
        // Sanitize sensitive data
        event.additional_data = self.sanitizer.sanitize_fields(event.additional_data);

        // Calculate chain hash for tamper detection
        let previous_hash = self.last_chain_hash.read().clone();
        let chain_hash = self.calculate_chain_hash(&event, &previous_hash);
        event.chain_hash = chain_hash.clone();

        // Update chain hash
        *self.last_chain_hash.write() = chain_hash;

        // Increment event counter
        self.event_counter.fetch_add(1, Ordering::Relaxed);

        // Log based on severity
        match event.severity {
            SecuritySeverity::Critical => {
                error!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    correlation_id = ?event.correlation_id,
                    source_ip = ?event.source_ip,
                    chain_hash = %event.chain_hash,
                    cef = %event.to_cef(),
                    "CRITICAL SECURITY EVENT: {}", event.message
                );
            }
            SecuritySeverity::High => {
                error!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    correlation_id = ?event.correlation_id,
                    source_ip = ?event.source_ip,
                    chain_hash = %event.chain_hash,
                    cef = %event.to_cef(),
                    "HIGH SECURITY EVENT: {}", event.message
                );
            }
            SecuritySeverity::Medium => {
                warn!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    correlation_id = ?event.correlation_id,
                    source_ip = ?event.source_ip,
                    chain_hash = %event.chain_hash,
                    cef = %event.to_cef(),
                    "MEDIUM SECURITY EVENT: {}", event.message
                );
            }
            SecuritySeverity::Low => {
                info!(
                    event_id = %event.id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    correlation_id = ?event.correlation_id,
                    source_ip = ?event.source_ip,
                    chain_hash = %event.chain_hash,
                    cef = %event.to_cef(),
                    "LOW SECURITY EVENT: {}", event.message
                );
            }
        }
    }

    /// Get total number of security events logged
    pub fn get_event_count(&self) -> u64 {
        self.event_counter.load(Ordering::Relaxed)
    }

    /// Calculate initial hash for chain
    fn calculate_initial_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"BUCKWILD_SECURITY_LOG_CHAIN_INIT");
        hasher.update(Utc::now().to_rfc3339().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Calculate hash chain for tamper detection
    fn calculate_chain_hash(&self, event: &SecurityEvent, previous_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(previous_hash.as_bytes());
        hasher.update(event.id.as_bytes());
        hasher.update(event.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", event.event_type).as_bytes());
        hasher.update(format!("{:?}", event.severity).as_bytes());
        hasher.update(event.message.as_bytes());

        if let Some(ref correlation_id) = event.correlation_id {
            hasher.update(correlation_id.to_string().as_bytes());
        }

        if let Some(ref source_ip) = event.source_ip {
            hasher.update(source_ip.as_bytes());
        }

        // Include sanitized additional data in hash
        let mut sorted_keys: Vec<_> = event.additional_data.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            hasher.update(key.as_bytes());
            hasher.update(event.additional_data[key].to_string().as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    /// Verify hash chain integrity (for audit purposes)
    pub fn verify_chain_integrity(&self, events: &[SecurityEvent]) -> bool {
        if events.is_empty() {
            return true;
        }

        let mut expected_hash = Self::calculate_initial_hash();

        for event in events {
            let calculated_hash = self.calculate_chain_hash(event, &expected_hash);
            if calculated_hash != event.chain_hash {
                error!(
                    event_id = %event.id,
                    expected_hash = %calculated_hash,
                    actual_hash = %event.chain_hash,
                    "Hash chain integrity violation detected"
                );
                return false;
            }
            expected_hash = event.chain_hash.clone();
        }

        true
    }
}

/// Convenience functions for common security events
impl SecurityLogger {
    pub fn log_authentication_failure(
        &self,
        source_ip: &str,
        reason: &str,
        correlation_id: Option<CorrelationId>,
    ) {
        let event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Medium,
            format!("Authentication failed: {}", reason),
            correlation_id,
        )
        .with_source_ip(source_ip.to_string())
        .with_additional_data("failure_reason".to_string(), serde_json::json!(reason));

        self.log_event(event);
    }

    pub fn log_attack_detected(
        &self,
        attack_type: SecurityEventType,
        source_ip: &str,
        details: &str,
        correlation_id: Option<CorrelationId>,
    ) {
        let severity = match attack_type {
            SecurityEventType::FragmentBombDetected | SecurityEventType::SessionHijackAttempt => {
                SecuritySeverity::Critical
            }
            SecurityEventType::ReplayAttackDetected
            | SecurityEventType::EnumerationAttackDetected => SecuritySeverity::High,
            _ => SecuritySeverity::Medium,
        };

        let event = SecurityEvent::new(
            attack_type,
            severity,
            format!("Attack detected: {}", details),
            correlation_id,
        )
        .with_source_ip(source_ip.to_string())
        .with_additional_data("attack_details".to_string(), serde_json::json!(details));

        self.log_event(event);
    }

    pub fn log_rate_limit_exceeded(
        &self,
        source_ip: &str,
        limit_type: &str,
        correlation_id: Option<CorrelationId>,
    ) {
        let event = SecurityEvent::new(
            SecurityEventType::RateLimitExceeded,
            SecuritySeverity::Medium,
            format!("Rate limit exceeded for {}", limit_type),
            correlation_id,
        )
        .with_source_ip(source_ip.to_string())
        .with_additional_data("limit_type".to_string(), serde_json::json!(limit_type));

        self.log_event(event);
    }

    pub fn log_system_event(&self, event_type: SecurityEventType, message: &str) {
        let severity = match event_type {
            SecurityEventType::EmergencyShutdown => SecuritySeverity::Critical,
            SecurityEventType::SystemShutdown => SecuritySeverity::High,
            SecurityEventType::SystemStartup => SecuritySeverity::Medium,
            _ => SecuritySeverity::Low,
        };

        let event = SecurityEvent::new(event_type, severity, message.to_string(), None);

        self.log_event(event);
    }
}
