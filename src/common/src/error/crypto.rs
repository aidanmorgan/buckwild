#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Cryptographic layer errors
//!
//! This module defines errors for all cryptographic operations in the Buckwild protocol,
//! including ECDH key exchange, HMAC operations, key derivation, and key management.

use thiserror::Error;

/// Cryptographic error types
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    // Key Management Errors
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("Key expired: {key_id}")]
    KeyExpired { key_id: String },

    #[error("Key revoked: {key_id}")]
    KeyRevoked { key_id: String },

    #[error("Key not usable: {reason}")]
    KeyNotUsable { reason: String },

    #[error("Key usage limit exceeded: {key_id}")]
    KeyUsageLimitExceeded { key_id: String },

    #[error("Key rotation failed: {reason}")]
    KeyRotationFailed { reason: String },

    #[error("Invalid key: {reason}")]
    InvalidKey { reason: String },

    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    // ECDH Errors
    #[error("ECDH key exchange failed: {reason}")]
    EcdhKeyExchangeFailed { reason: String },

    #[error("Invalid ECDH public key: {reason}")]
    InvalidEcdhPublicKey { reason: String },

    #[error("Invalid ECDH private key: {reason}")]
    InvalidEcdhPrivateKey { reason: String },

    #[error("ECDH shared secret computation failed: {reason}")]
    SharedSecretComputationFailed { reason: String },

    #[error("Invalid ECDH key encoding: {reason}")]
    InvalidEcdhKeyEncoding { reason: String },

    // HMAC Errors
    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    #[error("HMAC generation failed: {reason}")]
    HmacGenerationFailed { reason: String },

    #[error("Invalid HMAC tag: {reason}")]
    InvalidHmacTag { reason: String },

    #[error("Invalid HMAC tag length: expected {expected}, got {actual}")]
    InvalidHmacTagLength { expected: usize, actual: usize },

    #[error("HMAC policy mismatch: {reason}")]
    HmacPolicyMismatch { reason: String },

    #[error("HMAC policy negotiation failed: {reason}")]
    HmacPolicyNegotiationFailed { reason: String },

    // KDF Errors
    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed { reason: String },

    #[error("Invalid KDF parameters: {reason}")]
    InvalidKdfParameters { reason: String },

    #[error("Invalid iteration count: {count}")]
    InvalidIterationCount { count: u32 },

    #[error("Invalid salt: {reason}")]
    InvalidSalt { reason: String },

    #[error("KDF chunk index out of bounds: chunk {chunk}, max {max}")]
    KdfChunkOutOfBounds { chunk: usize, max: usize },

    #[error("Invalid parameter buffer size: needed {needed}, got {actual}")]
    InvalidParameterBufferSize { needed: usize, actual: usize },

    // Session Derivation Errors
    #[error("Session derivation failed: {reason}")]
    SessionDerivationFailed { reason: String },

    #[error("Invalid session parameters: {reason}")]
    InvalidSessionParameters { reason: String },

    // Random Number Generation Errors
    #[error("Random number generation failed: {reason}")]
    RandomGenerationFailed { reason: String },

    #[error("RNG not available: {reason}")]
    RngNotAvailable { reason: String },

    // Lock and Concurrency Errors
    #[error("Failed to acquire lock: {lock_type}")]
    LockAcquisitionFailed { lock_type: String },

    #[error("Lock poisoned: {lock_type}")]
    LockPoisoned { lock_type: String },

    // Cache Errors
    #[error("Key cache error: {reason}")]
    KeyCacheError { reason: String },

    #[error("Cache cleanup failed: {reason}")]
    CacheCleanupFailed { reason: String },

    // Secure Memory Errors
    #[error("Secure memory allocation failed")]
    SecureMemoryAllocationFailed,

    #[error("Secure memory operation failed: {operation}")]
    SecureMemoryOperationFailed { operation: String },

    // Internal Errors
    #[error("Internal cryptographic error: {reason}")]
    InternalError { reason: String },

    #[error("Invalid parameter: {reason}")]
    InvalidParameter { reason: String },

    #[error("Operation not supported: {operation}")]
    OperationNotSupported { operation: String },
}

impl CryptoError {
    /// Create a key generation failed error
    pub fn key_generation_failed(reason: impl Into<String>) -> Self {
        Self::KeyGenerationFailed {
            reason: reason.into(),
        }
    }

    /// Create a key not found error
    pub fn key_not_found(key_id: impl Into<String>) -> Self {
        Self::KeyNotFound {
            key_id: key_id.into(),
        }
    }

    /// Create a key expired error
    pub fn key_expired(key_id: impl Into<String>) -> Self {
        Self::KeyExpired {
            key_id: key_id.into(),
        }
    }

    /// Create a key revoked error
    pub fn key_revoked(key_id: impl Into<String>) -> Self {
        Self::KeyRevoked {
            key_id: key_id.into(),
        }
    }

    /// Create a key not usable error
    pub fn key_not_usable(reason: impl Into<String>) -> Self {
        Self::KeyNotUsable {
            reason: reason.into(),
        }
    }

    /// Create a key usage limit exceeded error
    pub fn key_usage_limit_exceeded(key_id: impl Into<String>) -> Self {
        Self::KeyUsageLimitExceeded {
            key_id: key_id.into(),
        }
    }

    /// Create a key rotation failed error
    pub fn key_rotation_failed(reason: impl Into<String>) -> Self {
        Self::KeyRotationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid key error
    pub fn invalid_key(reason: impl Into<String>) -> Self {
        Self::InvalidKey {
            reason: reason.into(),
        }
    }

    /// Create an invalid key size error
    pub fn invalid_key_size(expected: usize, actual: usize) -> Self {
        Self::InvalidKeySize { expected, actual }
    }

    /// Create an ECDH key exchange failed error
    pub fn ecdh_key_exchange_failed(reason: impl Into<String>) -> Self {
        Self::EcdhKeyExchangeFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid ECDH public key error
    pub fn invalid_ecdh_public_key(reason: impl Into<String>) -> Self {
        Self::InvalidEcdhPublicKey {
            reason: reason.into(),
        }
    }

    /// Create an invalid ECDH private key error
    pub fn invalid_ecdh_private_key(reason: impl Into<String>) -> Self {
        Self::InvalidEcdhPrivateKey {
            reason: reason.into(),
        }
    }

    /// Create a shared secret computation failed error
    pub fn shared_secret_computation_failed(reason: impl Into<String>) -> Self {
        Self::SharedSecretComputationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid ECDH key encoding error
    pub fn invalid_ecdh_key_encoding(reason: impl Into<String>) -> Self {
        Self::InvalidEcdhKeyEncoding {
            reason: reason.into(),
        }
    }

    /// Create an HMAC verification failed error
    pub fn hmac_verification_failed() -> Self {
        Self::HmacVerificationFailed
    }

    /// Create an HMAC generation failed error
    pub fn hmac_generation_failed(reason: impl Into<String>) -> Self {
        Self::HmacGenerationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid HMAC tag error
    pub fn invalid_hmac_tag(reason: impl Into<String>) -> Self {
        Self::InvalidHmacTag {
            reason: reason.into(),
        }
    }

    /// Create an invalid HMAC tag length error
    pub fn invalid_hmac_tag_length(expected: usize, actual: usize) -> Self {
        Self::InvalidHmacTagLength { expected, actual }
    }

    /// Create an HMAC policy mismatch error
    pub fn hmac_policy_mismatch(reason: impl Into<String>) -> Self {
        Self::HmacPolicyMismatch {
            reason: reason.into(),
        }
    }

    /// Create an HMAC policy negotiation failed error
    pub fn hmac_policy_negotiation_failed(reason: impl Into<String>) -> Self {
        Self::HmacPolicyNegotiationFailed {
            reason: reason.into(),
        }
    }

    /// Create a key derivation failed error
    pub fn key_derivation_failed(reason: impl Into<String>) -> Self {
        Self::KeyDerivationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid KDF parameters error
    pub fn invalid_kdf_parameters(reason: impl Into<String>) -> Self {
        Self::InvalidKdfParameters {
            reason: reason.into(),
        }
    }

    /// Create an invalid iteration count error
    pub fn invalid_iteration_count(count: u32) -> Self {
        Self::InvalidIterationCount { count }
    }

    /// Create an invalid salt error
    pub fn invalid_salt(reason: impl Into<String>) -> Self {
        Self::InvalidSalt {
            reason: reason.into(),
        }
    }

    /// Create a KDF chunk out of bounds error
    pub fn kdf_chunk_out_of_bounds(chunk: usize, max: usize) -> Self {
        Self::KdfChunkOutOfBounds { chunk, max }
    }

    /// Create an invalid parameter buffer size error
    pub fn invalid_parameter_buffer_size(needed: usize, actual: usize) -> Self {
        Self::InvalidParameterBufferSize { needed, actual }
    }

    /// Create a session derivation failed error
    pub fn session_derivation_failed(reason: impl Into<String>) -> Self {
        Self::SessionDerivationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid session parameters error
    pub fn invalid_session_parameters(reason: impl Into<String>) -> Self {
        Self::InvalidSessionParameters {
            reason: reason.into(),
        }
    }

    /// Create a random generation failed error
    pub fn random_generation_failed(reason: impl Into<String>) -> Self {
        Self::RandomGenerationFailed {
            reason: reason.into(),
        }
    }

    /// Create an RNG not available error
    pub fn rng_not_available(reason: impl Into<String>) -> Self {
        Self::RngNotAvailable {
            reason: reason.into(),
        }
    }

    /// Create a lock acquisition failed error
    pub fn lock_acquisition_failed(lock_type: impl Into<String>) -> Self {
        Self::LockAcquisitionFailed {
            lock_type: lock_type.into(),
        }
    }

    /// Create a lock poisoned error
    pub fn lock_poisoned(lock_type: impl Into<String>) -> Self {
        Self::LockPoisoned {
            lock_type: lock_type.into(),
        }
    }

    /// Create a key cache error
    pub fn key_cache_error(reason: impl Into<String>) -> Self {
        Self::KeyCacheError {
            reason: reason.into(),
        }
    }

    /// Create a cache cleanup failed error
    pub fn cache_cleanup_failed(reason: impl Into<String>) -> Self {
        Self::CacheCleanupFailed {
            reason: reason.into(),
        }
    }

    /// Create a secure memory allocation failed error
    pub fn secure_memory_allocation_failed() -> Self {
        Self::SecureMemoryAllocationFailed
    }

    /// Create a secure memory operation failed error
    pub fn secure_memory_operation_failed(operation: impl Into<String>) -> Self {
        Self::SecureMemoryOperationFailed {
            operation: operation.into(),
        }
    }

    /// Create an internal error
    pub fn internal_error(reason: impl Into<String>) -> Self {
        Self::InternalError {
            reason: reason.into(),
        }
    }

    /// Create an invalid parameter error
    pub fn invalid_parameter(reason: impl Into<String>) -> Self {
        Self::InvalidParameter {
            reason: reason.into(),
        }
    }

    /// Create an operation not supported error
    pub fn operation_not_supported(operation: impl Into<String>) -> Self {
        Self::OperationNotSupported {
            operation: operation.into(),
        }
    }
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;
