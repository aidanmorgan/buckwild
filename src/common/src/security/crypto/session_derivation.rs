#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Session Parameter Derivation from ECDH Shared Secret
//
// This module implements the PBKDF2-SHA256-based parameter derivation from ECDH shared secrets
// as specified in design/protocol/04-ecdh-cryptography.md §265-301

use crate::error::security::SecurityError;
use crate::protocol::types::*;
use crate::security::crypto::kdf::{ChunkRange, Kdf, derive_key_pbkdf2};
use ring::digest;

/// PBKDF2 iterations for session key derivation (from 02-core-definitions.md)
const PBKDF2_ITERATIONS_SESSION: u32 = 4096;

/// Session key material output length (128 bytes = 1024 bits)
const SESSION_KEY_MATERIAL_SIZE: usize = 128;

/// Result type for session derivation operations
pub type SessionDerivationResult<T> = Result<T, SecurityError>;

/// Complete session parameters derived from ECDH shared secret
#[derive(Debug, Clone)]
pub struct DerivedSessionParams {
    /// Client initial sequence number
    pub client_initial_sequence: SequenceNumber,

    /// Server initial sequence number
    pub server_initial_sequence: SequenceNumber,

    /// Client port offset
    pub client_port_offset: u16,

    /// Server port offset
    pub server_port_offset: u16,

    /// Session authentication key (256-bit for HMAC)
    pub session_key: SessionKey,

    /// Port hopping seed (32-bit)
    pub port_hop_seed: u32,

    /// Time synchronization offset (16-bit)
    pub time_offset: u16,

    /// Congestion control seed (16-bit)
    pub congestion_seed: u16,
}

/// Session parameter derivation engine
pub struct SessionDerivation;

impl SessionDerivation {
    /// Derive complete session parameters from ECDH shared secret
    ///
    /// Implements the algorithm from design/protocol/04-ecdh-cryptography.md §265-301:
    /// 1. Create salt from public keys and session context: SHA256(client_pubkey || server_pubkey || session_context || "ecdh_salt_v1")
    /// 2. Use PBKDF2-HMAC-SHA256 to derive 128 bytes from ECDH shared secret with 4096 iterations
    /// 3. Extract 16-bit chunks and assign to session parameters
    pub fn derive_session_keys_from_dh(
        shared_secret: &SharedSecret,
        client_public_key: &EcdhPublicKey,
        server_public_key: &EcdhPublicKey,
        session_context: &[u8],
    ) -> SessionDerivationResult<DerivedSessionParams> {
        // Step 1: Create salt from public keys and session context
        // Salt = SHA256(client_pubkey || server_pubkey || session_context || "ecdh_salt_v1")
        let salt = Self::create_salt(client_public_key, server_public_key, session_context)?;

        // Step 2: Derive 128 bytes (1024 bits) of master key material using PBKDF2-HMAC-SHA256
        // with 4096 iterations as specified in design/protocol/02-core-definitions.md
        let master_key_material = derive_key_pbkdf2(
            shared_secret.as_bytes(),
            salt.as_slice(),
            PBKDF2_ITERATIONS_SESSION,
            SESSION_KEY_MATERIAL_SIZE,
        )?;

        // Step 3: Validate parameters
        if master_key_material.len() != SESSION_KEY_MATERIAL_SIZE {
            return Err(SecurityError::key_derivation_failed(format!(
                "Invalid master key material length: expected {}, got {}",
                SESSION_KEY_MATERIAL_SIZE,
                master_key_material.len()
            )));
        }

        // Step 4: Extract session parameters from 16-bit chunks
        Self::extract_session_params(&master_key_material)
    }

    /// Create salt from public keys and session context
    ///
    /// Salt = SHA256(client_pubkey || server_pubkey || session_context || "ecdh_salt_v1")
    fn create_salt(
        client_public_key: &EcdhPublicKey,
        server_public_key: &EcdhPublicKey,
        session_context: &[u8],
    ) -> SessionDerivationResult<SaltBytes> {
        let mut salt_input = Vec::with_capacity(
            client_public_key.as_bytes().len()
                + server_public_key.as_bytes().len()
                + session_context.len()
                + 14, // "ecdh_salt_v1" length
        );

        salt_input.extend_from_slice(client_public_key.as_bytes());
        salt_input.extend_from_slice(server_public_key.as_bytes());
        salt_input.extend_from_slice(session_context);
        salt_input.extend_from_slice(b"ecdh_salt_v1");

        // Hash the salt input
        let hash = digest::digest(&digest::SHA256, &salt_input);

        // Create SaltBytes from hash
        Ok(SaltBytes::new(hash.as_ref().to_vec()))
    }

    /// Extract session parameters from master key material using 16-bit chunks
    fn extract_session_params(params: &[u8]) -> SessionDerivationResult<DerivedSessionParams> {
        // Extract sequence numbers (chunks 0-3)
        let (client_seq_raw, server_seq_raw) = Kdf::extract_sequence_numbers(params)?;

        // Extract port offsets (chunks 4-5)
        let (client_port_offset, server_port_offset) = Kdf::extract_port_offsets(params)?;

        // Extract HMAC key (chunks 6-21, 32 bytes)
        let session_key_bytes = Kdf::extract_hmac_key(params)?;

        // Extract port hopping seed (chunks 22-23)
        let port_hop_seed = Kdf::extract_port_hopping_seed(params)?;

        // Extract time offset (chunk 24)
        let time_offset = Kdf::get_chunk(params, ChunkRange::Reserved, 0)?;

        // Extract congestion seed (chunk 25)
        let congestion_seed = Kdf::get_chunk(params, ChunkRange::Reserved, 1)?;

        Ok(DerivedSessionParams {
            client_initial_sequence: SequenceNumber::new(client_seq_raw),
            server_initial_sequence: SequenceNumber::new(server_seq_raw),
            client_port_offset,
            server_port_offset,
            session_key: SessionKey::new(session_key_bytes),
            port_hop_seed,
            time_offset,
            congestion_seed,
        })
    }

    /// Create ECDH verification hash for mutual authentication
    ///
    /// Hash = SHA256(shared_secret || client_nonce || server_nonce || server_challenge ||
    ///               key_exchange_id || "ecdh_verification_v1")
    pub fn create_ecdh_verification_hash(
        shared_secret: &SharedSecret,
        client_nonce: &[u8],
        server_nonce: &[u8],
        server_challenge: &[u8],
        key_exchange_id: u16,
    ) -> SessionDerivationResult<[u8; 32]> {
        let mut hash_input = Vec::with_capacity(
            shared_secret.as_bytes().len() +
            client_nonce.len() +
            server_nonce.len() +
            server_challenge.len() +
            2 + // key_exchange_id
            22, // "ecdh_verification_v1"
        );

        hash_input.extend_from_slice(shared_secret.as_bytes());
        hash_input.extend_from_slice(client_nonce);
        hash_input.extend_from_slice(server_nonce);
        hash_input.extend_from_slice(server_challenge);
        hash_input.extend_from_slice(&key_exchange_id.to_be_bytes());
        hash_input.extend_from_slice(b"ecdh_verification_v1");

        let hash = digest::digest(&digest::SHA256, &hash_input);

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(hash.as_ref());

        Ok(hash_array)
    }

    /// Verify ECDH shared secret hash for mutual authentication
    pub fn verify_ecdh_shared_secret_hash(
        computed_shared_secret: &SharedSecret,
        client_nonce: &[u8],
        server_nonce: &[u8],
        server_challenge: &[u8],
        key_exchange_id: u16,
        received_hash: &[u8; 32],
    ) -> SessionDerivationResult<bool> {
        let computed_hash = Self::create_ecdh_verification_hash(
            computed_shared_secret,
            client_nonce,
            server_nonce,
            server_challenge,
            key_exchange_id,
        )?;

        // Constant-time comparison to prevent timing attacks
        #[allow(deprecated)]
        Ok(ring::constant_time::verify_slices_are_equal(&computed_hash, received_hash).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_shared_secret() -> SharedSecret {
        SharedSecret::new([0x42u8; 32])
    }

    fn create_test_public_keys() -> (EcdhPublicKey, EcdhPublicKey) {
        let client_key = EcdhPublicKey::new([0x11u8; 64]);
        let server_key = EcdhPublicKey::new([0x22u8; 64]);
        (client_key, server_key)
    }

    #[test]
    fn test_derive_session_keys_from_dh() {
        let shared_secret = create_test_shared_secret();
        let (client_pub, server_pub) = create_test_public_keys();
        let session_context = b"test_session_001";

        let result = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub,
            &server_pub,
            session_context,
        );

        assert!(result.is_ok(), "Session key derivation should succeed");

        let params = result.unwrap();

        // Verify all parameters are derived
        assert!(
            params.client_initial_sequence > SequenceNumber::new(0)
                || params.server_initial_sequence > SequenceNumber::new(0)
        );
        assert_eq!(params.session_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_derivation_is_deterministic() {
        let shared_secret = create_test_shared_secret();
        let (client_pub, server_pub) = create_test_public_keys();
        let session_context = b"test_session_002";

        let params1 = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub,
            &server_pub,
            session_context,
        )
        .unwrap();

        let params2 = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub,
            &server_pub,
            session_context,
        )
        .unwrap();

        // All derived parameters should be identical
        assert_eq!(
            params1.client_initial_sequence,
            params2.client_initial_sequence
        );
        assert_eq!(
            params1.server_initial_sequence,
            params2.server_initial_sequence
        );
        assert_eq!(params1.client_port_offset, params2.client_port_offset);
        assert_eq!(params1.server_port_offset, params2.server_port_offset);
        assert_eq!(
            params1.session_key.as_bytes(),
            params2.session_key.as_bytes()
        );
        assert_eq!(params1.port_hop_seed, params2.port_hop_seed);
        assert_eq!(params1.time_offset, params2.time_offset);
        assert_eq!(params1.congestion_seed, params2.congestion_seed);
    }

    #[test]
    fn test_different_contexts_produce_different_keys() {
        let shared_secret = create_test_shared_secret();
        let (client_pub, server_pub) = create_test_public_keys();

        let params1 = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub,
            &server_pub,
            b"context_1",
        )
        .unwrap();

        let params2 = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub,
            &server_pub,
            b"context_2",
        )
        .unwrap();

        // Different contexts should produce different session keys
        assert_ne!(
            params1.session_key.as_bytes(),
            params2.session_key.as_bytes()
        );
    }

    #[test]
    fn test_different_public_keys_produce_different_keys() {
        let shared_secret = create_test_shared_secret();
        let (client_pub1, server_pub1) = create_test_public_keys();
        let client_pub2 = EcdhPublicKey::new([0x33u8; 64]);

        let params1 = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub1,
            &server_pub1,
            b"session",
        )
        .unwrap();

        let params2 = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub2,
            &server_pub1,
            b"session",
        )
        .unwrap();

        // Different public keys should produce different session keys
        assert_ne!(
            params1.session_key.as_bytes(),
            params2.session_key.as_bytes()
        );
    }

    #[test]
    fn test_create_ecdh_verification_hash() {
        let shared_secret = create_test_shared_secret();
        let client_nonce = b"client_nonce_12345678";
        let server_nonce = b"server_nonce_87654321";
        let server_challenge = b"server_challenge_data";
        let key_exchange_id = 42u16;

        let result = SessionDerivation::create_ecdh_verification_hash(
            &shared_secret,
            client_nonce,
            server_nonce,
            server_challenge,
            key_exchange_id,
        );

        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_verify_ecdh_shared_secret_hash() {
        let shared_secret = create_test_shared_secret();
        let client_nonce = b"client_nonce_12345678";
        let server_nonce = b"server_nonce_87654321";
        let server_challenge = b"server_challenge_data";
        let key_exchange_id = 42u16;

        // Create hash
        let hash = SessionDerivation::create_ecdh_verification_hash(
            &shared_secret,
            client_nonce,
            server_nonce,
            server_challenge,
            key_exchange_id,
        )
        .unwrap();

        // Verify it matches
        let result = SessionDerivation::verify_ecdh_shared_secret_hash(
            &shared_secret,
            client_nonce,
            server_nonce,
            server_challenge,
            key_exchange_id,
            &hash,
        );

        assert!(result.is_ok());
        assert!(result.unwrap(), "Hash verification should succeed");
    }

    #[test]
    fn test_verification_hash_is_deterministic() {
        let shared_secret = create_test_shared_secret();
        let client_nonce = b"client_nonce";
        let server_nonce = b"server_nonce";
        let server_challenge = b"challenge";
        let key_exchange_id = 100u16;

        let hash1 = SessionDerivation::create_ecdh_verification_hash(
            &shared_secret,
            client_nonce,
            server_nonce,
            server_challenge,
            key_exchange_id,
        )
        .unwrap();

        let hash2 = SessionDerivation::create_ecdh_verification_hash(
            &shared_secret,
            client_nonce,
            server_nonce,
            server_challenge,
            key_exchange_id,
        )
        .unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verification_fails_with_wrong_hash() {
        let shared_secret = create_test_shared_secret();
        let client_nonce = b"client_nonce";
        let server_nonce = b"server_nonce";
        let server_challenge = b"challenge";
        let key_exchange_id = 100u16;

        let wrong_hash = [0x99u8; 32];

        let result = SessionDerivation::verify_ecdh_shared_secret_hash(
            &shared_secret,
            client_nonce,
            server_nonce,
            server_challenge,
            key_exchange_id,
            &wrong_hash,
        );

        assert!(result.is_ok());
        assert!(!result.unwrap(), "Verification should fail with wrong hash");
    }

    #[test]
    fn test_different_nonces_produce_different_hashes() {
        let shared_secret = create_test_shared_secret();
        let server_challenge = b"challenge";
        let key_exchange_id = 100u16;

        let hash1 = SessionDerivation::create_ecdh_verification_hash(
            &shared_secret,
            b"nonce_1",
            b"nonce_2",
            server_challenge,
            key_exchange_id,
        )
        .unwrap();

        let hash2 = SessionDerivation::create_ecdh_verification_hash(
            &shared_secret,
            b"nonce_3",
            b"nonce_4",
            server_challenge,
            key_exchange_id,
        )
        .unwrap();

        assert_ne!(hash1, hash2);
    }
}
