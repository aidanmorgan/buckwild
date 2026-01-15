#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Sequence Key Derivation using PBKDF2
//
// This module implements PBKDF2-based key derivation for sequence number obfuscation
// as specified in design/protocol/04-ecdh-cryptography.md §332-356.
//
// The sequence key is derived from the session key and a salt specific to sequence operations.
// This key is used for sequence number obfuscation to prevent predictable sequence values.

use crate::error::security::SecurityError;
use crate::security::crypto::kdf::derive_key_pbkdf2;

/// Result type for sequence key derivation operations
pub type SequenceKeyResult<T> = Result<T, SecurityError>;

/// PBKDF2 iterations for sequence number key derivation
///
/// As specified in design/protocol/02-core-definitions.md:130
pub const PBKDF2_ITERATIONS_SEQUENCE: u32 = 2048;

/// Output length for sequence key (256 bits)
const SEQUENCE_KEY_LENGTH: usize = 32;

/// Derive sequence obfuscation key from session key and salt
///
/// This function implements the sequence number obfuscation key derivation
/// as specified in design/protocol/04-ecdh-cryptography.md:332-356.
///
/// # Protocol Reference
///
/// From design/protocol/04-ecdh-cryptography.md:332-342:
/// ```text
/// function derive_sequence_numbers(shared_secret, client_pubkey, server_pubkey):
///     # Derive initial sequence numbers using PBKDF2 from ECDH shared secret
///     salt = SHA256(client_pubkey || server_pubkey || b"sequence_derivation_v1")
///
///     # Generate sequence key material
///     sequence_material = PBKDF2_HMAC_SHA256(
///         password = shared_secret,
///         salt = salt,
///         iterations = PBKDF2_ITERATIONS_SEQUENCE,
///         key_length = 16     # 128 bits for two 32-bit sequences + padding
///     )
/// ```
///
/// # Arguments
///
/// * `session_key` - The session key material (typically derived from ECDH)
/// * `sequence_salt` - Salt value specific to sequence derivation
///
/// # Returns
///
/// A 32-byte (256-bit) key for sequence number obfuscation
///
/// # Errors
///
/// Returns `SecurityError` if:
/// - Session key is empty
/// - PBKDF2 derivation fails
///
/// # Security Properties
///
/// - **Deterministic**: Same session key and salt always produce the same sequence key
/// - **Unique Per Session**: Different salts produce different sequence keys
/// - **Computational Cost**: 2048 iterations provide protection against brute force
/// - **Key Length**: 256 bits provides sufficient entropy for obfuscation
pub fn derive_sequence_key(session_key: &[u8], sequence_salt: &[u8]) -> SequenceKeyResult<Vec<u8>> {
    // Validate inputs
    if session_key.is_empty() {
        return Err(SecurityError::invalid_parameter(
            "Session key cannot be empty for sequence key derivation",
        ));
    }

    // Derive sequence key using PBKDF2-HMAC-SHA256
    // - password: session key material
    // - salt: sequence-specific salt
    // - iterations: 2048 (PBKDF2_ITERATIONS_SEQUENCE)
    // - output: 32 bytes (256 bits)
    let sequence_key = derive_key_pbkdf2(
        session_key,
        sequence_salt,
        PBKDF2_ITERATIONS_SEQUENCE,
        SEQUENCE_KEY_LENGTH,
    )
    .map_err(|e| {
        SecurityError::key_derivation_failed(format!(
            "PBKDF2 sequence key derivation failed: {}",
            e
        ))
    })?;

    Ok(sequence_key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that sequence key derivation is deterministic
    ///
    /// The same session key and salt should always produce the same sequence key.
    /// This is critical for peers to derive matching sequence keys.
    #[test]
    fn test_deterministic_derivation() {
        let session_key = b"test_session_key_material_here_32";
        let salt = b"test_sequence_salt";

        let key1 = derive_sequence_key(session_key, salt).expect("First derivation failed");
        let key2 = derive_sequence_key(session_key, salt).expect("Second derivation failed");

        assert_eq!(
            key1, key2,
            "Same inputs should produce identical sequence keys"
        );
    }

    /// Test that different salts produce different keys
    ///
    /// This ensures that each session has a unique sequence key even if
    /// the session key material is reused.
    #[test]
    fn test_different_salt_produces_different_keys() {
        let session_key = b"test_session_key_material_here_32";
        let salt1 = b"sequence_salt_one";
        let salt2 = b"sequence_salt_two";

        let key1 = derive_sequence_key(session_key, salt1).expect("Salt1 derivation failed");
        let key2 = derive_sequence_key(session_key, salt2).expect("Salt2 derivation failed");

        assert_ne!(
            key1, key2,
            "Different salts should produce different sequence keys"
        );
    }

    /// Test that output is exactly 32 bytes
    ///
    /// The sequence key must be 256 bits (32 bytes) for use in
    /// cryptographic operations.
    #[test]
    fn test_key_length() {
        let session_key = b"test_session_key_material_here_32";
        let salt = b"test_sequence_salt";

        let key = derive_sequence_key(session_key, salt).expect("Derivation failed");

        assert_eq!(key.len(), 32, "Sequence key must be exactly 32 bytes");
    }

    /// Test that empty session key returns error
    ///
    /// Session key must not be empty for secure derivation.
    #[test]
    fn test_empty_session_key_error() {
        let empty_key = b"";
        let salt = b"test_sequence_salt";

        let result = derive_sequence_key(empty_key, salt);

        assert!(result.is_err(), "Empty session key should return error");

        if let Err(e) = result {
            assert!(
                e.to_string().contains("Session key cannot be empty"),
                "Error message should mention empty session key"
            );
        }
    }

    /// Test PBKDF2 iteration count is correct
    ///
    /// Verify that the iteration count matches the protocol specification.
    #[test]
    fn test_iteration_count_constant() {
        assert_eq!(
            PBKDF2_ITERATIONS_SEQUENCE, 2048,
            "PBKDF2 iterations must be 2048 per protocol specification"
        );
    }

    /// Test different session keys produce different sequence keys
    ///
    /// Even with the same salt, different session keys should produce
    /// different sequence keys.
    #[test]
    fn test_different_session_key_produces_different_keys() {
        let session_key1 = b"session_key_one_material_here_32b";
        let session_key2 = b"session_key_two_material_here_32b";
        let salt = b"same_salt_for_both";

        let key1 = derive_sequence_key(session_key1, salt).expect("Key1 derivation failed");
        let key2 = derive_sequence_key(session_key2, salt).expect("Key2 derivation failed");

        assert_ne!(
            key1, key2,
            "Different session keys should produce different sequence keys"
        );
    }

    /// Test that sequence key is not all zeros
    ///
    /// A valid PBKDF2 output should not be all zeros.
    #[test]
    fn test_non_zero_output() {
        let session_key = b"test_session_key_material_here_32";
        let salt = b"test_sequence_salt";

        let key = derive_sequence_key(session_key, salt).expect("Derivation failed");

        let all_zeros = key.iter().all(|&b| b == 0);
        assert!(!all_zeros, "Sequence key should not be all zeros");
    }

    /// Test empty salt is allowed
    ///
    /// PBKDF2 allows empty salt, though it's not recommended.
    /// This test verifies the function doesn't reject empty salts.
    #[test]
    fn test_empty_salt_allowed() {
        let session_key = b"test_session_key_material_here_32";
        let empty_salt = b"";

        let result = derive_sequence_key(session_key, empty_salt);

        assert!(
            result.is_ok(),
            "Empty salt should be allowed (though not recommended)"
        );
    }

    /// Integration test: Sequence obfuscation workflow
    ///
    /// This test simulates how the sequence key would be used in the
    /// actual protocol to obfuscate sequence numbers.
    #[test]
    fn test_sequence_obfuscation_integration() {
        // Simulate session setup
        let session_key = b"ecdh_derived_session_key_32bytes";
        let sequence_salt = b"client_server_sequence_salt_v1";

        // Derive sequence key
        let sequence_key = derive_sequence_key(session_key, sequence_salt)
            .expect("Sequence key derivation failed");

        // Verify key properties
        assert_eq!(sequence_key.len(), 32);
        assert!(sequence_key.iter().any(|&b| b != 0));

        // Simulate both peers deriving the same key
        let peer_sequence_key = derive_sequence_key(session_key, sequence_salt)
            .expect("Peer sequence key derivation failed");

        assert_eq!(
            sequence_key, peer_sequence_key,
            "Both peers should derive identical sequence keys"
        );
    }
}
