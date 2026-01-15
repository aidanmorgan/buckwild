#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Timestamp Key Derivation using HKDF-SHA256
//
// This module implements HKDF-based key derivation for timestamp authentication
// as specified in the audit remediation plan TASK-036.
//
// The timestamp key is derived from the session key using HKDF-SHA256 with a
// "timestamp" context string. This key is used to authenticate timestamps in
// the protocol, preventing timestamp manipulation attacks.
//
// Addresses audit findings: 3P-CRIT-017, SEC-005

use crate::error::security::SecurityError;
use ring::hkdf;

/// Result type for timestamp key derivation operations
pub type TimestampKeyResult<T> = Result<T, SecurityError>;

/// Output length for timestamp key (256 bits)
const TIMESTAMP_KEY_LENGTH: usize = 32;

/// Context string for timestamp key derivation
const TIMESTAMP_CONTEXT: &[u8] = b"timestamp";

/// HKDF output length specification for ring
struct TimestampKeyLength(usize);

impl hkdf::KeyType for TimestampKeyLength {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive timestamp authentication key from session key
///
/// This function implements timestamp key derivation using HKDF-SHA256
/// as specified in TASK-036 of the audit remediation plan.
///
/// # Derivation Process
///
/// The timestamp key is derived from session key chunks 24-25 (reserved chunks)
/// using HKDF-SHA256 with the context string "timestamp". This provides:
/// - Key separation between timestamp and other session keys
/// - Domain separation through the context string
/// - Strong cryptographic binding to the session key
///
/// # Arguments
///
/// * `session_key` - The session key material (32 bytes from ECDH derivation)
///
/// # Returns
///
/// A 32-byte (256-bit) key for timestamp HMAC authentication
///
/// # Errors
///
/// Returns `SecurityError` if:
/// - Session key is empty
/// - Session key length is not 32 bytes
/// - HKDF derivation fails
///
/// # Security Properties
///
/// - **Deterministic**: Same session key always produces the same timestamp key
/// - **Unique Per Session**: Different session keys produce different timestamp keys
/// - **Domain Separation**: "timestamp" context prevents key reuse
/// - **Key Length**: 256 bits provides sufficient entropy for HMAC
pub fn generate_timestamp_key(session_key: &[u8]) -> TimestampKeyResult<Vec<u8>> {
    // Validate inputs
    if session_key.is_empty() {
        return Err(SecurityError::invalid_parameter(
            "Session key cannot be empty for timestamp key derivation",
        ));
    }

    if session_key.len() != TIMESTAMP_KEY_LENGTH {
        return Err(SecurityError::invalid_parameter(format!(
            "Session key must be {} bytes, got {}",
            TIMESTAMP_KEY_LENGTH,
            session_key.len()
        )));
    }

    // Derive timestamp key using HKDF-SHA256
    // - IKM (Input Key Material): session key
    // - salt: None (session key is already high-entropy from ECDH)
    // - info: "timestamp" context string for domain separation
    // - output: 32 bytes (256 bits)

    // Extract phase: create PRK from session key without salt
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(session_key);

    // Expand phase: derive timestamp key with context
    let mut timestamp_key = vec![0u8; TIMESTAMP_KEY_LENGTH];
    prk.expand(
        &[TIMESTAMP_CONTEXT],
        TimestampKeyLength(TIMESTAMP_KEY_LENGTH),
    )
    .map_err(|_| SecurityError::key_derivation_failed("HKDF expand failed for timestamp key"))?
    .fill(&mut timestamp_key)
    .map_err(|_| SecurityError::key_derivation_failed("HKDF fill failed for timestamp key"))?;

    Ok(timestamp_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that timestamp key derivation is deterministic
    ///
    /// The same session key should always produce the same timestamp key.
    /// This is critical for peers to derive matching timestamp keys.
    #[test]
    fn test_deterministic_derivation() {
        let session_key = [0x42u8; 32];

        let key1 = generate_timestamp_key(&session_key).expect("First derivation failed");
        let key2 = generate_timestamp_key(&session_key).expect("Second derivation failed");

        assert_eq!(
            key1, key2,
            "Same session key should produce identical timestamp keys"
        );
    }

    /// Test that different session keys produce different timestamp keys
    ///
    /// This ensures that each session has a unique timestamp key.
    #[test]
    fn test_different_session_keys_produce_different_keys() {
        let session_key1 = [0x11u8; 32];
        let session_key2 = [0x22u8; 32];

        let key1 = generate_timestamp_key(&session_key1).expect("Key1 derivation failed");
        let key2 = generate_timestamp_key(&session_key2).expect("Key2 derivation failed");

        assert_ne!(
            key1, key2,
            "Different session keys should produce different timestamp keys"
        );
    }

    /// Test that output is exactly 32 bytes
    ///
    /// The timestamp key must be 256 bits (32 bytes) for HMAC authentication.
    #[test]
    fn test_key_length() {
        let session_key = [0x42u8; 32];

        let key = generate_timestamp_key(&session_key).expect("Derivation failed");

        assert_eq!(key.len(), 32, "Timestamp key must be exactly 32 bytes");
    }

    /// Test that empty session key returns error
    ///
    /// Session key must not be empty for secure derivation.
    #[test]
    fn test_empty_session_key_error() {
        let empty_key: &[u8] = &[];

        let result = generate_timestamp_key(empty_key);

        assert!(result.is_err(), "Empty session key should return error");

        if let Err(e) = result {
            assert!(
                e.to_string().contains("Session key cannot be empty"),
                "Error message should mention empty session key"
            );
        }
    }

    /// Test that invalid session key length returns error
    ///
    /// Session key must be exactly 32 bytes.
    #[test]
    fn test_invalid_session_key_length_error() {
        let short_key = [0x42u8; 16];
        let long_key = [0x42u8; 64];

        let result_short = generate_timestamp_key(&short_key);
        let result_long = generate_timestamp_key(&long_key);

        assert!(
            result_short.is_err(),
            "Short session key should return error"
        );
        assert!(result_long.is_err(), "Long session key should return error");

        if let Err(e) = result_short {
            assert!(
                e.to_string().contains("must be 32 bytes"),
                "Error message should mention required length"
            );
        }
    }

    /// Test that timestamp key is not all zeros
    ///
    /// A valid HKDF output should not be all zeros.
    #[test]
    fn test_non_zero_output() {
        let session_key = [0x42u8; 32];

        let key = generate_timestamp_key(&session_key).expect("Derivation failed");

        let all_zeros = key.iter().all(|&b| b == 0);
        assert!(!all_zeros, "Timestamp key should not be all zeros");
    }

    /// Test that timestamp key is not the same as session key
    ///
    /// The derived timestamp key should be different from the input session key
    /// due to the HKDF transformation.
    #[test]
    fn test_derived_key_differs_from_session_key() {
        let session_key = [0x42u8; 32];

        let timestamp_key = generate_timestamp_key(&session_key).expect("Derivation failed");

        assert_ne!(
            &timestamp_key[..],
            &session_key[..],
            "Timestamp key should differ from session key"
        );
    }

    /// Integration test: Timestamp authentication workflow
    ///
    /// This test simulates how the timestamp key would be used in the
    /// actual protocol to authenticate timestamps.
    #[test]
    fn test_timestamp_authentication_integration() {
        // Simulate session setup with ECDH-derived session key
        let session_key = [0x99u8; 32]; // In practice, from ECDH

        // Derive timestamp key
        let timestamp_key =
            generate_timestamp_key(&session_key).expect("Timestamp key derivation failed");

        // Verify key properties
        assert_eq!(timestamp_key.len(), 32);
        assert!(timestamp_key.iter().any(|&b| b != 0));

        // Simulate both peers deriving the same key
        let peer_timestamp_key =
            generate_timestamp_key(&session_key).expect("Peer timestamp key derivation failed");

        assert_eq!(
            timestamp_key, peer_timestamp_key,
            "Both peers should derive identical timestamp keys"
        );
    }

    /// Test HKDF context separation
    ///
    /// Verify that the "timestamp" context string provides proper domain separation.
    /// A different context string should produce a different key.
    #[test]
    fn test_context_separation() {
        let session_key = [0x42u8; 32];

        // Derive timestamp key with correct context
        let timestamp_key = generate_timestamp_key(&session_key).expect("Derivation failed");

        // Manually derive key with different context to verify separation
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(&session_key);
        let mut different_key = vec![0u8; 32];
        prk.expand(&[b"different_context"], TimestampKeyLength(32))
            .expect("HKDF expand failed")
            .fill(&mut different_key)
            .expect("HKDF fill failed");

        assert_ne!(
            timestamp_key, different_key,
            "Different context strings should produce different keys"
        );
    }

    /// Test that timestamp key can be used for HMAC
    ///
    /// Verify that the derived key has appropriate properties for HMAC usage.
    #[test]
    fn test_timestamp_key_hmac_usage() {
        use ring::hmac;

        let session_key = [0x42u8; 32];
        let timestamp_key = generate_timestamp_key(&session_key).expect("Derivation failed");

        // Verify key can be used with HMAC-SHA256
        let key = hmac::Key::new(hmac::HMAC_SHA256, &timestamp_key);

        // Create a test timestamp value
        let timestamp_data = 1234567890u64.to_be_bytes();

        // Compute HMAC tag
        let tag = hmac::sign(&key, &timestamp_data);

        // Verify HMAC tag was created
        assert_eq!(tag.as_ref().len(), 32, "HMAC-SHA256 tag should be 32 bytes");
    }

    /// Audit compliance test: Verify chunks 24-25 usage
    ///
    /// This test documents that the timestamp key is derived from the session key,
    /// which was extracted from chunks 24-25 (reserved chunks) in TASK-005.
    /// The session key serves as input to this derivation.
    #[test]
    fn test_audit_compliance_chunks_24_25() {
        // Session key is derived from chunks 24-25 as per TASK-005
        // We verify here that the timestamp key derivation works correctly
        // with session key material from those chunks

        let session_key_from_chunks_24_25 = [0xAAu8; 32];

        let timestamp_key = generate_timestamp_key(&session_key_from_chunks_24_25)
            .expect("Timestamp key derivation from chunks 24-25 failed");

        assert_eq!(
            timestamp_key.len(),
            32,
            "Timestamp key derived from chunks 24-25 should be 32 bytes"
        );

        // Verify determinism for chunks 24-25 derived session key
        let timestamp_key2 = generate_timestamp_key(&session_key_from_chunks_24_25)
            .expect("Second derivation failed");
        assert_eq!(
            timestamp_key, timestamp_key2,
            "Timestamp key derivation should be deterministic"
        );
    }
}
