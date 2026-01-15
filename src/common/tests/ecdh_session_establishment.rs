//! ECDH Session Establishment Integration Tests
//!
//! Tests the complete ECDH-based session key establishment flow:
//! 1. Ephemeral keypair generation
//! 2. Public key exchange in handshake packets
//! 3. Shared secret derivation via ECDH
//! 4. Session key extraction via HKDF
//!
//! Validates against design/protocol/04-ecdh-cryptography.md

#![cfg(test)]

use buckwild_common::security::crypto::ecdh::{EcdhManager, ThreadSafeEcdhManager};
use buckwild_common::security::crypto::session_derivation::SessionDerivation;

/// Test that ECDH keypair generation produces valid keys
#[test]
fn test_ecdh_keypair_generation() {
    let manager = EcdhManager::new(10);

    // Generate keypair for a session
    let result = manager.get_key_pair("session_001");

    assert!(result.is_ok(), "Keypair generation should succeed");

    let public_key = result.unwrap();

    // P-256 public key should be 64 bytes (x || y coordinates)
    assert_eq!(
        public_key.as_bytes().len(),
        64,
        "P-256 public key must be 64 bytes"
    );
}

/// Test that both parties derive the same shared secret
#[test]
fn test_ecdh_shared_secret_agreement() {
    let alice_manager = EcdhManager::new(10);
    let bob_manager = EcdhManager::new(10);

    // Alice generates her keypair
    let alice_public = alice_manager.get_key_pair("alice").unwrap();

    // Bob generates his keypair
    let bob_public = bob_manager.get_key_pair("bob").unwrap();

    // Alice computes shared secret using Bob's public key
    let alice_shared_secret = alice_manager
        .compute_shared_secret("alice", &bob_public)
        .unwrap();

    // Bob computes shared secret using Alice's public key
    let bob_shared_secret = bob_manager
        .compute_shared_secret("bob", &alice_public)
        .unwrap();

    // Both should derive the same shared secret
    assert_eq!(
        alice_shared_secret.as_bytes(),
        bob_shared_secret.as_bytes(),
        "Both parties must derive identical shared secret"
    );

    // Shared secret should be 32 bytes for P-256
    assert_eq!(
        alice_shared_secret.as_bytes().len(),
        32,
        "P-256 shared secret must be 32 bytes"
    );
}

/// Test session key derivation from ECDH shared secret
#[test]
fn test_session_key_derivation_from_ecdh() {
    let alice_manager = EcdhManager::new(10);
    let bob_manager = EcdhManager::new(10);

    // Generate keypairs
    let alice_public = alice_manager.get_key_pair("alice").unwrap();
    let bob_public = bob_manager.get_key_pair("bob").unwrap();

    // Compute shared secret
    let shared_secret = alice_manager
        .compute_shared_secret("alice", &bob_public)
        .unwrap();

    // Session context (e.g., key_exchange_id)
    let session_context = b"session_12345";

    // Derive session parameters from shared secret
    let result = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &alice_public,
        &bob_public,
        session_context,
    );

    assert!(
        result.is_ok(),
        "Session key derivation should succeed: {:?}",
        result.err()
    );

    let params = result.unwrap();

    // Verify all session parameters are derived
    assert_eq!(
        params.session_key.as_bytes().len(),
        32,
        "Session key must be 32 bytes for HMAC-SHA256"
    );

    // Sequence numbers should be non-zero (statistically)
    assert!(
        params.client_initial_sequence.get() > 0 || params.server_initial_sequence.get() > 0,
        "At least one sequence number should be non-zero"
    );

    // Port hop seed should exist
    assert!(params.port_hop_seed > 0, "Port hop seed should be non-zero");
}

/// Test that session derivation is deterministic
#[test]
fn test_session_derivation_is_deterministic() {
    let manager = EcdhManager::new(10);

    let alice_public = manager.get_key_pair("alice").unwrap();
    let bob_public = manager.get_key_pair("bob").unwrap();

    let shared_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();

    let session_context = b"determinism_test";

    // Derive session parameters twice
    let params1 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &alice_public,
        &bob_public,
        session_context,
    )
    .unwrap();

    let params2 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &alice_public,
        &bob_public,
        session_context,
    )
    .unwrap();

    // All parameters should match exactly
    assert_eq!(
        params1.client_initial_sequence, params2.client_initial_sequence,
        "Client sequence must be deterministic"
    );
    assert_eq!(
        params1.server_initial_sequence, params2.server_initial_sequence,
        "Server sequence must be deterministic"
    );
    assert_eq!(
        params1.session_key.as_bytes(),
        params2.session_key.as_bytes(),
        "Session key must be deterministic"
    );
    assert_eq!(
        params1.port_hop_seed, params2.port_hop_seed,
        "Port hop seed must be deterministic"
    );
}

/// Test that different session contexts produce different keys
#[test]
fn test_different_contexts_produce_different_keys() {
    let manager = EcdhManager::new(10);

    let alice_public = manager.get_key_pair("alice").unwrap();
    let bob_public = manager.get_key_pair("bob").unwrap();

    let shared_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();

    // Derive with different contexts
    let params1 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &alice_public,
        &bob_public,
        b"context_1",
    )
    .unwrap();

    let params2 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &alice_public,
        &bob_public,
        b"context_2",
    )
    .unwrap();

    // Keys should be different
    assert_ne!(
        params1.session_key.as_bytes(),
        params2.session_key.as_bytes(),
        "Different contexts must produce different session keys"
    );
}

/// Test complete client-server ECDH session establishment flow
#[test]
fn test_complete_ecdh_session_establishment() {
    // Client and server ECDH managers
    let client_manager = EcdhManager::new(10);
    let server_manager = EcdhManager::new(10);

    // === STEP 1: Client generates ephemeral keypair ===
    let client_public = client_manager.get_key_pair("client_session").unwrap();

    // Client would send client_public in SYN packet here
    // ...

    // === STEP 2: Server generates ephemeral keypair ===
    let server_public = server_manager.get_key_pair("server_session").unwrap();

    // Server would send server_public in SYN-ACK packet here
    // ...

    // === STEP 3: Both parties compute shared secret ===

    // Client computes shared secret from server's public key
    let client_shared_secret = client_manager
        .compute_shared_secret("client_session", &server_public)
        .unwrap();

    // Server computes shared secret from client's public key
    let server_shared_secret = server_manager
        .compute_shared_secret("server_session", &client_public)
        .unwrap();

    // Verify both parties derived the same shared secret
    assert_eq!(
        client_shared_secret.as_bytes(),
        server_shared_secret.as_bytes(),
        "Client and server must derive identical shared secret"
    );

    // === STEP 4: Derive session keys from shared secret ===

    let key_exchange_id = 42u16;
    let session_context = key_exchange_id.to_be_bytes();

    // Client derives session keys
    let client_params = SessionDerivation::derive_session_keys_from_dh(
        &client_shared_secret,
        &client_public,
        &server_public,
        &session_context,
    )
    .unwrap();

    // Server derives session keys
    let server_params = SessionDerivation::derive_session_keys_from_dh(
        &server_shared_secret,
        &client_public,
        &server_public,
        &session_context,
    )
    .unwrap();

    // === STEP 5: Verify both parties derived identical session parameters ===

    assert_eq!(
        client_params.client_initial_sequence, server_params.client_initial_sequence,
        "Client initial sequence must match"
    );

    assert_eq!(
        client_params.server_initial_sequence, server_params.server_initial_sequence,
        "Server initial sequence must match"
    );

    assert_eq!(
        client_params.session_key.as_bytes(),
        server_params.session_key.as_bytes(),
        "Session keys must match"
    );

    assert_eq!(
        client_params.port_hop_seed, server_params.port_hop_seed,
        "Port hop seeds must match"
    );

    assert_eq!(
        client_params.client_port_offset, server_params.client_port_offset,
        "Client port offset must match"
    );

    assert_eq!(
        client_params.server_port_offset, server_params.server_port_offset,
        "Server port offset must match"
    );

    // === Connection successfully established with matching session keys ===
}

/// Test ECDH verification hash for mutual authentication
#[test]
fn test_ecdh_verification_hash() {
    let manager = EcdhManager::new(10);

    let _alice_public = manager.get_key_pair("alice").unwrap();
    let bob_public = manager.get_key_pair("bob").unwrap();

    let shared_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();

    let client_nonce = b"client_nonce_random_data";
    let server_nonce = b"server_nonce_random_data";
    let server_challenge = b"server_challenge_123456";
    let key_exchange_id = 100u16;

    // Create verification hash
    let hash = SessionDerivation::create_ecdh_verification_hash(
        &shared_secret,
        client_nonce,
        server_nonce,
        server_challenge,
        key_exchange_id,
    )
    .unwrap();

    assert_eq!(hash.len(), 32, "Verification hash must be 32 bytes");

    // Verify the hash
    let verification_result = SessionDerivation::verify_ecdh_shared_secret_hash(
        &shared_secret,
        client_nonce,
        server_nonce,
        server_challenge,
        key_exchange_id,
        &hash,
    )
    .unwrap();

    assert!(
        verification_result,
        "Verification should succeed with correct hash"
    );

    // Test that wrong hash fails verification
    let wrong_hash = [0xFFu8; 32];
    let wrong_verification = SessionDerivation::verify_ecdh_shared_secret_hash(
        &shared_secret,
        client_nonce,
        server_nonce,
        server_challenge,
        key_exchange_id,
        &wrong_hash,
    )
    .unwrap();

    assert!(
        !wrong_verification,
        "Verification should fail with wrong hash"
    );
}

/// Test that keys are never reused across sessions (ephemeral property)
#[test]
fn test_ephemeral_keys_not_reused() {
    let manager = EcdhManager::new(10);

    // Generate keys for two different sessions
    let session1_public = manager.get_key_pair("session_001").unwrap();
    let session2_public = manager.get_key_pair("session_002").unwrap();

    // Keys should be different for different sessions
    assert_ne!(
        session1_public.as_bytes(),
        session2_public.as_bytes(),
        "Different sessions must have different ephemeral keys"
    );
}

/// Test thread-safe ECDH manager
#[test]
fn test_thread_safe_ecdh_manager() {
    let manager = ThreadSafeEcdhManager::new(10);

    let _alice_public = manager.get_key_pair("alice").unwrap();
    let bob_public = manager.get_key_pair("bob").unwrap();

    let shared_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();

    assert_eq!(
        shared_secret.as_bytes().len(),
        32,
        "Shared secret must be 32 bytes"
    );
}

/// Test public key serialization/deserialization for network transmission
#[test]
fn test_public_key_serialization() {
    let manager = EcdhManager::new(10);

    let original_key = manager.get_key_pair("serialize_test").unwrap();

    // Serialize to bytes
    let serialized = EcdhManager::serialize_public_key(&original_key);

    assert_eq!(
        serialized.len(),
        64,
        "Serialized public key must be 64 bytes"
    );

    // Deserialize back
    let deserialized = EcdhManager::deserialize_public_key(&serialized).unwrap();

    assert_eq!(
        original_key.as_bytes(),
        deserialized.as_bytes(),
        "Deserialized key must match original"
    );
}

/// Test that invalid public keys are rejected
#[test]
fn test_invalid_public_key_rejection() {
    // Try to deserialize invalid key (wrong length)
    let invalid_short = vec![0u8; 32]; // Too short
    let result = EcdhManager::deserialize_public_key(&invalid_short);

    assert!(
        result.is_err(),
        "Should reject public key with wrong length"
    );

    // Try to deserialize invalid key (not on curve)
    let invalid_data = vec![0xFFu8; 64]; // Invalid point
    let result = EcdhManager::deserialize_public_key(&invalid_data);

    assert!(result.is_err(), "Should reject invalid curve point");
}

/// Test key rotation clears cached keys
#[test]
fn test_key_rotation() {
    let manager = EcdhManager::new(10);

    let key1 = manager.get_key_pair("rotation_test").unwrap();

    // Rotate keys
    manager.rotate_keys().unwrap();

    // Generate new key after rotation
    let key2 = manager.get_key_pair("rotation_test").unwrap();

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Key after rotation must be different"
    );
}

/// Test session derivation with all parameter types
#[test]
fn test_complete_session_parameter_extraction() {
    let manager = EcdhManager::new(10);

    let alice_public = manager.get_key_pair("alice").unwrap();
    let bob_public = manager.get_key_pair("bob").unwrap();
    let shared_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();

    let params = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &alice_public,
        &bob_public,
        b"test_session",
    )
    .unwrap();

    // Verify all fields are present and valid
    // (client_initial_sequence and server_initial_sequence are u32 so always valid)
    // client_port_offset and server_port_offset are u16, so always valid
    assert_eq!(
        params.session_key.as_bytes().len(),
        32,
        "Session key must be 32 bytes"
    );
    assert!(params.port_hop_seed > 0, "Port hop seed should be non-zero");
    // time_offset and congestion_seed are u16, so always valid
}
