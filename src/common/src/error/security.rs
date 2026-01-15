#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Security layer errors
//!
//! This module defines errors for cryptographic operations, key derivation,
//! HMAC verification, and anti-replay protection. All errors include context
//! such as SessionId and SequenceNumber where applicable.

use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Security layer error types
#[derive(Error, Debug, Clone)]
pub enum SecurityError {
    #[error("Cryptographic error: {reason}")]
    CryptographicError { reason: String },

    #[error("ECDH key exchange failed: {reason}")]
    EcdhKeyExchangeFailed { reason: String },

    #[error("Invalid public key: {reason}")]
    InvalidPublicKey { reason: String },

    #[error("Invalid private key: {reason}")]
    InvalidPrivateKey { reason: String },

    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed { reason: String },

    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    #[error("HMAC generation failed: {reason}")]
    HmacGenerationFailed { reason: String },

    #[error("Invalid HMAC tag")]
    InvalidHmacTag,

    #[error("Anti-replay check failed: {reason}")]
    AntiReplayFailed { reason: String },

    #[error("Duplicate packet detected: session {session_id}, sequence {sequence}")]
    DuplicatePacket {
        session_id: SessionId,
        sequence: SequenceNumber,
    },

    #[error("Replay attack detected: session {session_id}, sequence {sequence}")]
    ReplayAttack {
        session_id: SessionId,
        sequence: SequenceNumber,
    },

    #[error("Timestamp validation failed: {timestamp:?} (tolerance: {tolerance_ns}ns)")]
    TimestampValidationFailed {
        timestamp: Timestamp,
        tolerance_ns: ProtocolDuration,
    },

    #[error("Sequence validation failed: {sequence} (expected: {expected})")]
    SequenceValidationFailed {
        sequence: SequenceNumber,
        expected: SequenceNumber,
    },

    #[error("Security context not found: {session_id}")]
    SecurityContextNotFound { session_id: SessionId },

    #[error("Security context expired: {session_id}")]
    SecurityContextExpired { session_id: SessionId },

    #[error("Key rotation failed: {reason}")]
    KeyRotationFailed { reason: String },

    #[error("Secure memory allocation failed")]
    SecureMemoryAllocationFailed,

    #[error("Secure memory operation failed: {operation}")]
    SecureMemoryOperationFailed { operation: String },

    #[error("Random number generation failed")]
    RandomGenerationFailed,

    #[error("Nonce validation failed: duplicate or invalid nonce")]
    NonceValidationFailed,

    #[error("Security policy violation: {policy}")]
    SecurityPolicyViolation { policy: String },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Authorization failed: {reason}")]
    AuthorizationFailed { reason: String },

    #[error("Security validation failed: {check}")]
    SecurityValidationFailed { check: String },

    #[error("HMAC policy mismatch: {reason}")]
    PolicyMismatch { reason: String },
}

impl SecurityError {
    /// Create a cryptographic error
    pub fn cryptographic_error(reason: impl Into<String>) -> Self {
        Self::CryptographicError {
            reason: reason.into(),
        }
    }

    /// Create an ECDH key exchange error
    pub fn ecdh_key_exchange_failed(reason: impl Into<String>) -> Self {
        Self::EcdhKeyExchangeFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid public key error
    pub fn invalid_public_key(reason: impl Into<String>) -> Self {
        Self::InvalidPublicKey {
            reason: reason.into(),
        }
    }

    /// Create a key derivation error
    pub fn key_derivation_failed(reason: impl Into<String>) -> Self {
        Self::KeyDerivationFailed {
            reason: reason.into(),
        }
    }

    /// Create an HMAC generation error
    pub fn hmac_generation_failed(reason: impl Into<String>) -> Self {
        Self::HmacGenerationFailed {
            reason: reason.into(),
        }
    }

    /// Create an anti-replay error
    pub fn anti_replay_failed(reason: impl Into<String>) -> Self {
        Self::AntiReplayFailed {
            reason: reason.into(),
        }
    }

    /// Create a key rotation error
    pub fn key_rotation_failed(reason: impl Into<String>) -> Self {
        Self::KeyRotationFailed {
            reason: reason.into(),
        }
    }

    /// Create a secure memory operation error
    pub fn secure_memory_operation_failed(operation: impl Into<String>) -> Self {
        Self::SecureMemoryOperationFailed {
            operation: operation.into(),
        }
    }

    /// Create a security policy violation error
    pub fn security_policy_violation(policy: impl Into<String>) -> Self {
        Self::SecurityPolicyViolation {
            policy: policy.into(),
        }
    }

    /// Create an authentication error
    pub fn authentication_failed(reason: impl Into<String>) -> Self {
        Self::AuthenticationFailed {
            reason: reason.into(),
        }
    }

    /// Create an authorization error
    pub fn authorization_failed(reason: impl Into<String>) -> Self {
        Self::AuthorizationFailed {
            reason: reason.into(),
        }
    }

    /// Create a security validation error
    pub fn security_validation_failed(check: impl Into<String>) -> Self {
        Self::SecurityValidationFailed {
            check: check.into(),
        }
    }

    /// Create a policy mismatch error
    pub fn policy_mismatch(reason: impl Into<String>) -> Self {
        Self::PolicyMismatch {
            reason: reason.into(),
        }
    }

    /// Create a timestamp validation error
    pub fn timestamp_validation_failed(timestamp: Timestamp, tolerance_ns: u64) -> Self {
        Self::TimestampValidationFailed {
            timestamp,
            tolerance_ns: ProtocolDuration(tolerance_ns),
        }
    }

    /// Create a sequence validation error
    pub fn sequence_validation_failed(sequence: SequenceNumber, expected: SequenceNumber) -> Self {
        Self::SequenceValidationFailed { sequence, expected }
    }

    /// Create an invalid parameter error
    pub fn invalid_parameter(reason: impl Into<String>) -> Self {
        Self::CryptographicError {
            reason: format!("Invalid parameter: {}", reason.into()),
        }
    }

    /// Create an invalid key error
    pub fn invalid_key(reason: impl Into<String>) -> Self {
        Self::InvalidPublicKey {
            reason: format!("Invalid key: {}", reason.into()),
        }
    }

    /// Create an internal error
    pub fn internal_error(reason: impl Into<String>) -> Self {
        Self::CryptographicError {
            reason: format!("Internal error: {}", reason.into()),
        }
    }

    /// Create an HMAC verification failed error
    pub fn hmac_verification_failed() -> Self {
        Self::HmacVerificationFailed
    }

    /// Create an invalid HMAC tag error
    pub fn invalid_hmac_tag() -> Self {
        Self::InvalidHmacTag
    }

    /// Create a key generation failed error
    pub fn key_generation_failed(reason: impl Into<String>) -> Self {
        Self::CryptographicError {
            reason: format!("Key generation failed: {}", reason.into()),
        }
    }

    /// Create a duplicate packet error
    pub fn duplicate_packet(session_id: SessionId, sequence: SequenceNumber) -> Self {
        Self::DuplicatePacket {
            session_id,
            sequence,
        }
    }

    /// Create a simple duplicate packet error (test compatibility)
    pub fn simple_duplicate_packet() -> Self {
        Self::AntiReplayFailed {
            reason: "Duplicate packet detected".to_string(),
        }
    }

    /// Create a replay attack error
    pub fn replay_attack(session_id: SessionId, sequence: SequenceNumber) -> Self {
        Self::ReplayAttack {
            session_id,
            sequence,
        }
    }

    /// Create a timestamp too old error (for anti-replay)
    pub fn timestamp_too_old() -> Self {
        Self::AntiReplayFailed {
            reason: "Timestamp too old".to_string(),
        }
    }

    /// Create a timestamp invalid error (for anti-replay)
    pub fn timestamp_invalid() -> Self {
        Self::AntiReplayFailed {
            reason: "Timestamp invalid".to_string(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::CryptographicError { .. } => false,
            Self::EcdhKeyExchangeFailed { .. } => true,
            Self::InvalidPublicKey { .. } => false,
            Self::InvalidPrivateKey { .. } => false,
            Self::KeyDerivationFailed { .. } => true,
            Self::HmacVerificationFailed => false,
            Self::HmacGenerationFailed { .. } => true,
            Self::InvalidHmacTag => false,
            Self::AntiReplayFailed { .. } => false,
            Self::DuplicatePacket { .. } => false,
            Self::ReplayAttack { .. } => false,
            Self::TimestampValidationFailed { .. } => true,
            Self::SequenceValidationFailed { .. } => true,
            Self::SecurityContextNotFound { .. } => true,
            Self::SecurityContextExpired { .. } => true,
            Self::KeyRotationFailed { .. } => true,
            Self::SecureMemoryAllocationFailed => true,
            Self::SecureMemoryOperationFailed { .. } => true,
            Self::RandomGenerationFailed => true,
            Self::NonceValidationFailed => false,
            Self::SecurityPolicyViolation { .. } => false,
            Self::AuthenticationFailed { .. } => true,
            Self::AuthorizationFailed { .. } => false,
            Self::SecurityValidationFailed { .. } => true,
            Self::PolicyMismatch { .. } => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::EcdhKeyExchangeFailed { .. } => Some("Retry key exchange with new keys"),
            Self::KeyDerivationFailed { .. } => Some("Use alternative key derivation method"),
            Self::HmacGenerationFailed { .. } => Some("Regenerate HMAC with fresh key"),
            Self::TimestampValidationFailed { .. } => Some("Synchronize clocks"),
            Self::SequenceValidationFailed { .. } => Some("Resynchronize sequence numbers"),
            Self::SecurityContextNotFound { .. } => Some("Reinitialize security context"),
            Self::SecurityContextExpired { .. } => Some("Renew security context"),
            Self::KeyRotationFailed { .. } => Some("Retry key rotation"),
            Self::SecureMemoryAllocationFailed => Some("Free memory and retry"),
            Self::SecureMemoryOperationFailed { .. } => Some("Retry memory operation"),
            Self::RandomGenerationFailed => Some("Use alternative entropy source"),
            Self::AuthenticationFailed { .. } => Some("Retry authentication"),
            Self::SecurityValidationFailed { .. } => Some("Retry validation"),
            _ => None,
        }
    }

    /// Check if this error indicates a potential security attack
    pub fn is_potential_attack(&self) -> bool {
        matches!(
            self,
            Self::DuplicatePacket { .. }
                | Self::ReplayAttack { .. }
                | Self::NonceValidationFailed
                | Self::HmacVerificationFailed
                | Self::InvalidHmacTag
                | Self::SecurityPolicyViolation { .. }
                | Self::PolicyMismatch { .. }
        )
    }

    /// Get the security severity level
    pub fn severity_level(&self) -> SecuritySeverity {
        match self {
            Self::ReplayAttack { .. } => SecuritySeverity::Critical,
            Self::DuplicatePacket { .. } => SecuritySeverity::High,
            Self::NonceValidationFailed => SecuritySeverity::High,
            Self::HmacVerificationFailed => SecuritySeverity::High,
            Self::InvalidHmacTag => SecuritySeverity::High,
            Self::SecurityPolicyViolation { .. } => SecuritySeverity::High,
            Self::PolicyMismatch { .. } => SecuritySeverity::High,
            Self::AuthorizationFailed { .. } => SecuritySeverity::Medium,
            Self::AuthenticationFailed { .. } => SecuritySeverity::Medium,
            Self::SecurityContextExpired { .. } => SecuritySeverity::Medium,
            _ => SecuritySeverity::Low,
        }
    }
}

/// Security severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Security layer result type
pub type SecurityResult<T> = Result<T, SecurityError>;

impl From<crate::protocol::types::ValidationError> for SecurityError {
    fn from(err: crate::protocol::types::ValidationError) -> Self {
        SecurityError::CryptographicError {
            reason: format!("Validation error: {:?}", err),
        }
    }
}
