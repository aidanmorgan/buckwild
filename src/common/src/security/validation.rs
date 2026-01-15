// Security validation module
//
// This module provides comprehensive security validation for the Buckwild protocol,
// including input validation, cryptographic verification, and security policy enforcement.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::SecurityError;
use crate::protocol::types::{
    Port, SecurityFlag, SequenceNumber, SessionId, Timestamp, WindowSizeValue,
};
use std::time::Duration;

/// Security validation engine for comprehensive security checks
pub struct SecurityValidator {
    /// Maximum allowed timestamp drift
    max_timestamp_drift: Duration,
    /// Minimum packet size to prevent amplification attacks
    min_packet_size: usize,
    /// Maximum packet size to prevent buffer overflow attacks
    max_packet_size: usize,
    /// Maximum session lifetime
    max_session_lifetime: Duration,
}

impl SecurityValidator {
    /// Create a new security validator with default settings
    pub fn new() -> Self {
        Self {
            max_timestamp_drift: Duration::new(30, 0), // 30 seconds in nanoseconds
            min_packet_size: 32,
            max_packet_size: 65536,
            max_session_lifetime: Duration::new(3600, 0), // 1 hour in nanoseconds
        }
    }

    /// Create a new security validator with custom settings
    pub fn with_config(
        max_timestamp_drift: Duration,
        min_packet_size: usize,
        max_packet_size: usize,
        max_session_lifetime: Duration,
    ) -> Self {
        Self {
            max_timestamp_drift,
            min_packet_size,
            max_packet_size,
            max_session_lifetime,
        }
    }

    /// Validate packet size constraints
    pub fn validate_packet_size(&self, size: usize) -> Result<(), SecurityError> {
        if size < self.min_packet_size {
            return Err(SecurityError::internal_error(format!(
                "Packet size {} below minimum {}",
                size, self.min_packet_size
            )));
        }

        if size > self.max_packet_size {
            return Err(SecurityError::internal_error(format!(
                "Packet size {} exceeds maximum {}",
                size, self.max_packet_size
            )));
        }

        Ok(())
    }

    /// Validate timestamp to prevent replay attacks and clock skew issues
    pub fn validate_timestamp(&self, timestamp: Timestamp) -> Result<(), SecurityError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SecurityError::internal_error(format!("System time error: {}", e)))?;

        let packet_time = std::time::Duration::from_nanos(timestamp.as_nanos());
        let max_drift = std::time::Duration::from_nanos(self.max_timestamp_drift.as_nanos() as u64);

        // Check if timestamp is too far in the future
        if packet_time > now + max_drift {
            return Err(SecurityError::internal_error(
                "Timestamp too far in the future",
            ));
        }

        // Check if timestamp is too far in the past
        if packet_time + max_drift < now {
            return Err(SecurityError::internal_error(
                "Timestamp too far in the past",
            ));
        }

        Ok(())
    }

    /// Validate session ID format and constraints
    pub fn validate_session_id(&self, session_id: SessionId) -> Result<(), SecurityError> {
        if session_id.as_u64() == 0 {
            return Err(SecurityError::internal_error("Invalid session ID (zero)"));
        }

        Ok(())
    }

    /// Validate sequence number for proper ordering
    pub fn validate_sequence_number(
        &self,
        session_id: SessionId,
        seq_num: SequenceNumber,
        last_seq: Option<SequenceNumber>,
    ) -> Result<(), SecurityError> {
        if let Some(last) = last_seq {
            // Check for sequence number reuse (potential replay attack)
            if seq_num == last {
                return Err(SecurityError::replay_attack(session_id, seq_num));
            }

            // Check for reasonable sequence number progression
            let distance = seq_num.diff(&last);
            if distance > 1000000 {
                return Err(SecurityError::internal_error(
                    "Sequence number jump too large",
                ));
            }
        }

        Ok(())
    }

    /// Validate port number for security constraints
    pub fn validate_port(&self, port: Port) -> Result<(), SecurityError> {
        let port_num = port.as_u16();

        // Prevent use of well-known system ports
        if port_num < 1024 {
            return Err(SecurityError::internal_error(
                "Cannot use well-known system ports",
            ));
        }

        // Prevent use of common service ports that might cause conflicts
        const FORBIDDEN_PORTS: &[u16] = &[
            22,   // SSH
            53,   // DNS
            80,   // HTTP
            443,  // HTTPS
            993,  // IMAPS
            995,  // POP3S
            3389, // RDP
            5432, // PostgreSQL
            3306, // MySQL
        ];

        if FORBIDDEN_PORTS.contains(&port_num) {
            return Err(SecurityError::internal_error(format!(
                "Port {} is forbidden for security reasons",
                port_num
            )));
        }

        Ok(())
    }

    /// Validate cryptographic key material
    pub fn validate_key_material(&self, key: &[u8]) -> Result<(), SecurityError> {
        // Check minimum key length
        if key.len() < 32 {
            return Err(SecurityError::internal_error(
                "Key material too short (minimum 32 bytes)",
            ));
        }

        // Check for all-zero key (weak key)
        if key.iter().all(|&b| b == 0) {
            return Err(SecurityError::internal_error("All-zero key is not allowed"));
        }

        // Check for all-same-byte key (weak key)
        if key.iter().all(|&b| b == key[0]) {
            return Err(SecurityError::internal_error(
                "Uniform key material is not allowed",
            ));
        }

        Ok(())
    }

    /// Validate session lifetime to prevent indefinite sessions
    pub fn validate_session_lifetime(&self, created_at: Timestamp) -> Result<(), SecurityError> {
        let now = Timestamp::now();
        let session_age_nanos = now.saturating_sub(&created_at);
        let session_age = Duration::new(
            session_age_nanos / 1_000_000_000,
            (session_age_nanos % 1_000_000_000) as u32,
        );

        if session_age.as_nanos() > self.max_session_lifetime.as_nanos() {
            return Err(SecurityError::internal_error("Session lifetime exceeded"));
        }

        Ok(())
    }

    /// Comprehensive packet validation
    pub fn validate_packet(
        &self,
        data: &[u8],
        session_id: SessionId,
        timestamp: Timestamp,
        seq_num: SequenceNumber,
        last_seq: Option<SequenceNumber>,
    ) -> Result<(), SecurityError> {
        // Validate packet size
        self.validate_packet_size(data.len())?;

        // Validate session ID
        self.validate_session_id(session_id)?;

        // Validate timestamp
        self.validate_timestamp(timestamp)?;

        // Validate sequence number
        self.validate_sequence_number(SessionId::from_raw(0), seq_num, last_seq)?;

        Ok(())
    }

    /// Validate input data for potential injection attacks
    pub fn validate_input_data(&self, data: &[u8]) -> Result<(), SecurityError> {
        // Check for null bytes that might indicate injection attempts
        if data.contains(&0) {
            return Err(SecurityError::internal_error(
                "Null bytes not allowed in input data",
            ));
        }

        // Check for excessively long strings that might cause buffer overflows
        if data.len() > 1048576 {
            // 1MB limit
            return Err(SecurityError::internal_error("Input data too large"));
        }

        Ok(())
    }

    /// Rate limiting validation to prevent DoS attacks
    pub fn validate_rate_limit(
        &self,
        requests_per_second: f64,
        max_rate: f64,
    ) -> Result<(), SecurityError> {
        if requests_per_second > max_rate {
            return Err(SecurityError::internal_error(format!(
                "Rate limit exceeded: {:.2} > {:.2} requests/second",
                requests_per_second, max_rate
            )));
        }

        Ok(())
    }

    /// Cleanup expired entries (no-op for stateless validator)
    ///
    /// This method exists for API compatibility with boundary condition management.
    /// The SecurityValidator is stateless, so there are no entries to clean up.
    pub fn cleanup_expired_entries(&self) {
        // No-op: SecurityValidator is stateless and doesn't maintain any caches
        // or session state that needs cleanup
    }
}

impl Default for SecurityValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Security policy enforcement
pub struct SecurityPolicy {
    /// Require HMAC authentication
    pub require_hmac: SecurityFlag,
    /// Require timestamp validation
    pub require_timestamp_validation: SecurityFlag,
    /// Require sequence number validation
    pub require_sequence_validation: SecurityFlag,
    /// Maximum allowed clock skew
    pub max_clock_skew: Duration,
    /// Minimum key rotation interval
    pub min_key_rotation_interval: Duration,
}

impl SecurityPolicy {
    /// Create a strict security policy
    pub fn strict() -> Self {
        Self {
            require_hmac: SecurityFlag::enabled(),
            require_timestamp_validation: SecurityFlag::enabled(),
            require_sequence_validation: SecurityFlag::enabled(),
            max_clock_skew: Duration::from_nanos(5_000_000_000), // 5 seconds
            min_key_rotation_interval: Duration::from_nanos(300_000_000_000), // 5 minutes
        }
    }

    /// Create a relaxed security policy for testing
    pub fn relaxed() -> Self {
        Self {
            require_hmac: SecurityFlag::enabled(),
            require_timestamp_validation: SecurityFlag::disabled(),
            require_sequence_validation: SecurityFlag::disabled(),
            max_clock_skew: Duration::from_nanos(60_000_000_000), // 60 seconds
            min_key_rotation_interval: Duration::from_nanos(3_600_000_000_000), // 1 hour
        }
    }

    /// Validate a configuration against this policy
    pub fn validate_config(&self, config: &SecurityConfig) -> Result<(), SecurityError> {
        if self.require_hmac.is_enabled() && !config.hmac_enabled.is_enabled() {
            return Err(SecurityError::internal_error(
                "HMAC authentication is required by policy",
            ));
        }

        if config.key_rotation_interval.as_nanos() < self.min_key_rotation_interval.as_nanos() {
            return Err(SecurityError::internal_error(format!(
                "Key rotation interval {:?} is below minimum {:?}",
                config.key_rotation_interval.as_nanos(),
                self.min_key_rotation_interval.as_nanos()
            )));
        }

        Ok(())
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

/// Security configuration structure
pub struct SecurityConfig {
    /// Whether HMAC authentication is enabled
    pub hmac_enabled: SecurityFlag,
    /// Key rotation interval
    pub key_rotation_interval: Duration,
    /// Anti-replay window size
    pub anti_replay_window: WindowSizeValue,
    /// Maximum timestamp drift
    pub max_timestamp_drift: Duration,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            hmac_enabled: SecurityFlag::enabled(),
            key_rotation_interval: Duration::from_nanos(3_600_000_000_000), // 1 hour
            anti_replay_window: WindowSizeValue::new(64),
            max_timestamp_drift: Duration::from_nanos(30_000_000_000), // 30 seconds
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_packet_size_validation() {
        let validator = SecurityValidator::new();

        // Valid size
        assert!(validator.validate_packet_size(1000).is_ok());

        // Too small
        assert!(validator.validate_packet_size(10).is_err());

        // Too large
        assert!(validator.validate_packet_size(100000).is_err());
    }

    #[tokio::test]
    async fn test_timestamp_validation() {
        let validator = SecurityValidator::new();
        let now = Timestamp::now();

        // Valid timestamp (current time)
        assert!(validator.validate_timestamp(now).is_ok());

        // Timestamp too far in the past
        let old_timestamp = Timestamp::from_raw(now.as_nanos() - (60 * 1_000_000_000));
        assert!(validator.validate_timestamp(old_timestamp).is_err());
    }

    #[tokio::test]
    async fn test_session_id_validation() {
        let validator = SecurityValidator::new();

        // Valid session ID
        let valid_id = SessionId::from_raw(12345);
        assert!(validator.validate_session_id(valid_id).is_ok());

        // Invalid session ID (zero)
        let invalid_id = SessionId::from_raw(0);
        assert!(validator.validate_session_id(invalid_id).is_err());
    }

    #[tokio::test]
    async fn test_key_material_validation() {
        let validator = SecurityValidator::new();

        // Valid key (must have varying bytes)
        let valid_key: Vec<u8> = (0..32).map(|i| i as u8).collect();
        assert!(validator.validate_key_material(&valid_key).is_ok());

        // Too short
        let short_key = vec![0x42; 16];
        assert!(validator.validate_key_material(&short_key).is_err());

        // All zeros
        let zero_key = vec![0x00; 32];
        assert!(validator.validate_key_material(&zero_key).is_err());

        // All same byte
        let uniform_key = vec![0xFF; 32];
        assert!(validator.validate_key_material(&uniform_key).is_err());
    }

    #[tokio::test]
    async fn test_security_policy() {
        let policy = SecurityPolicy::strict();
        let mut config = SecurityConfig::default();

        // Valid config
        assert!(policy.validate_config(&config).is_ok());

        // Invalid config (key rotation too frequent)
        config.key_rotation_interval = Duration::new(60, 0); // 60 seconds in nanoseconds
        assert!(policy.validate_config(&config).is_err());
    }
}
