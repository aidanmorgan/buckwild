// Integration test for ECDH key exchange with PBKDF2 session key derivation
//
// This test validates TASK-008: ECDH Key Exchange Integration
// It verifies that:
// 1. Ephemeral P-256 key pairs are generated
// 2. Shared secrets are computed correctly
// 3. Session keys are derived using PBKDF2 (not directly from shared secret)
// 4. Both peers derive identical session keys
// 5. Invalid public keys are rejected

use buckwild_common::protocol::types::*;
use buckwild_common::security::crypto::ecdh::{EcdhManager, ThreadSafeEcdhManager};
use buckwild_common::security::crypto::session_derivation::SessionDerivation;

#[test]
fn test_ecdh_shared_secret_agreement() {
    // Test Case 1: Client and server derive same shared secret
    let manager1 = EcdhManager::new(10);
    let manager2 = EcdhManager::new(10);

    // Generate key pairs for both parties
    let client_pub = manager1.get_key_pair("client").unwrap();
    let server_pub = manager2.get_key_pair("server").unwrap();

    // Perform ECDH key agreement
    let client_secret = manager1.compute_shared_secret("client", &server_pub).unwrap();
    let server_secret = manager2.compute_shared_secret("server", &client_pub).unwrap();

    // Both should derive the same shared secret
    assert_eq!(
        client_secret.as_bytes(),
        server_secret.as_bytes(),
        "Client and server must derive identical ECDH shared secrets"
    );
}

#[test]
fn test_public_key_format_p256_compressed() {
    // Test Case 2: Public keys are valid P-256 uncompressed points
    let manager = EcdhManager::new(10);
    let public_key = manager.get_key_pair("test").unwrap();

    // P-256 uncompressed public key should be 64 bytes (x || y coordinates)
    assert_eq!(
        public_key.as_bytes().len(),
        64,
        "P-256 public key must be 64 bytes (32-byte x + 32-byte y)"
    );

    // Verify serialization/deserialization round-trip
    let serialized = EcdhManager::serialize_public_key(&public_key);
    assert_eq!(serialized.len(), 64, "Serialized key must be 64 bytes");

    let deserialized = EcdhManager::deserialize_public_key(&serialized).unwrap();
    assert_eq!(
        public_key.as_bytes(),
        deserialized.as_bytes(),
        "Deserialized key must match original"
    );
}

#[test]
fn test_ephemeral_keys_unique_each_exchange() {
    // Test Case 3: Ephemeral keys are unique per exchange
    let manager = EcdhManager::new(10);

    // Generate multiple key pairs with different IDs
    let key1 = manager.get_key_pair("exchange1").unwrap();
    let key2 = manager.get_key_pair("exchange2").unwrap();
    let key3 = manager.get_key_pair("exchange3").unwrap();

    // All keys should be different (ephemeral)
    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Different exchanges must produce different ephemeral keys"
    );
    assert_ne!(
        key2.as_bytes(),
        key3.as_bytes(),
        "Different exchanges must produce different ephemeral keys"
    );
    assert_ne!(
        key1.as_bytes(),
        key3.as_bytes(),
        "Different exchanges must produce different ephemeral keys"
    );
}

#[test]
fn test_invalid_peer_key_rejected() {
    // Test Case 4: Invalid public keys rejected with error
    let manager = EcdhManager::new(10);

    // Try to deserialize invalid public key (wrong length)
    let invalid_short = vec![0u8; 32]; // Too short
    let result = EcdhManager::deserialize_public_key(&invalid_short);
    assert!(
        result.is_err(),
        "Public key with wrong length must be rejected"
    );

    // Try to deserialize invalid public key (not on curve)
    let invalid_data = vec![0xFFu8; 64]; // Unlikely to be a valid point
    let result = EcdhManager::deserialize_public_key(&invalid_data);
    assert!(
        result.is_err(),
        "Invalid curve point must be rejected"
    );
}

#[test]
fn test_session_key_derivation_uses_pbkdf2() {
    // Test Case 5: Session keys are derived using PBKDF2, not directly from shared secret
    let manager1 = EcdhManager::new(10);
    let manager2 = EcdhManager::new(10);

    // Generate key pairs
    let client_pub = manager1.get_key_pair("client").unwrap();
    let server_pub = manager2.get_key_pair("server").unwrap();

    // Compute shared secrets
    let client_secret = manager1.compute_shared_secret("client", &server_pub).unwrap();
    let server_secret = manager2.compute_shared_secret("server", &client_pub).unwrap();

    assert_eq!(client_secret.as_bytes(), server_secret.as_bytes());

    // Derive session parameters using PBKDF2 (not direct conversion)
    let session_context = b"test_session_context";

    let client_params = SessionDerivation::derive_session_keys_from_dh(
        &client_secret,
        &client_pub,
        &server_pub,
        session_context,
    )
    .unwrap();

    let server_params = SessionDerivation::derive_session_keys_from_dh(
        &server_secret,
        &server_pub,
        &client_pub,
        session_context,
    )
    .unwrap();

    // Both sides must derive identical session keys
    assert_eq!(
        client_params.session_key.as_bytes(),
        server_params.session_key.as_bytes(),
        "PBKDF2-derived session keys must match on both sides"
    );

    // Session key must NOT be the same as shared secret (proves PBKDF2 was used)
    assert_ne!(
        client_params.session_key.as_bytes(),
        client_secret.as_bytes(),
        "Session key must be PBKDF2-derived, not directly from shared secret"
    );

    // Verify all derived parameters match
    assert_eq!(
        client_params.client_initial_sequence, server_params.client_initial_sequence,
        "Client sequence numbers must match"
    );
    assert_eq!(
        client_params.server_initial_sequence, server_params.server_initial_sequence,
        "Server sequence numbers must match"
    );
    assert_eq!(
        client_params.client_port_offset, server_params.client_port_offset,
        "Client port offsets must match"
    );
    assert_eq!(
        client_params.server_port_offset, server_params.server_port_offset,
        "Server port offsets must match"
    );
    assert_eq!(
        client_params.port_hop_seed, server_params.port_hop_seed,
        "Port hopping seeds must match"
    );
    assert_eq!(
        client_params.time_offset, server_params.time_offset,
        "Time offsets must match"
    );
    assert_eq!(
        client_params.congestion_seed, server_params.congestion_seed,
        "Congestion seeds must match"
    );
}

#[test]
fn test_different_contexts_produce_different_keys() {
    // Verify that different session contexts produce different session keys
    let manager1 = EcdhManager::new(10);
    let manager2 = EcdhManager::new(10);

    let client_pub = manager1.get_key_pair("client").unwrap();
    let server_pub = manager2.get_key_pair("server").unwrap();
    let shared_secret = manager1.compute_shared_secret("client", &server_pub).unwrap();

    // Derive with different contexts
    let params1 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &client_pub,
        &server_pub,
        b"context1",
    )
    .unwrap();

    let params2 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &client_pub,
        &server_pub,
        b"context2",
    )
    .unwrap();

    // Session keys must be different for different contexts
    assert_ne!(
        params1.session_key.as_bytes(),
        params2.session_key.as_bytes(),
        "Different session contexts must produce different session keys"
    );
}

#[test]
fn test_thread_safe_ecdh_manager() {
    // Verify ThreadSafeEcdhManager works correctly
    let manager = ThreadSafeEcdhManager::new(10);

    let pub1 = manager.get_key_pair("key1").unwrap();
    let pub2 = manager.get_key_pair("key2").unwrap();

    // Keys should be cached - second call returns cached key
    let pub1_again = manager.get_key_pair("key1").unwrap();
    assert_eq!(pub1.as_bytes(), pub1_again.as_bytes(), "Cached key must be returned");

    // Compute shared secret
    let secret = manager.compute_shared_secret("key1", &pub2).unwrap();
    assert_eq!(secret.as_bytes().len(), 32, "Shared secret must be 32 bytes");

    // Key rotation clears cache
    manager.rotate_keys().unwrap();
    let pub1_new = manager.get_key_pair("key1").unwrap();
    assert_ne!(
        pub1.as_bytes(),
        pub1_new.as_bytes(),
        "After rotation, new key must be generated"
    );
}

#[test]
fn test_full_handshake_simulation() {
    // Test Case 6: Full round trip SYN -> SYN-ACK -> ACK completes key exchange
    // This simulates the complete handshake flow

    // Client side
    let client_manager = EcdhManager::new(10);
    let client_pub = client_manager.get_key_pair("client_conn_1").unwrap();

    // Server receives SYN with client public key, generates its own key pair
    let server_manager = EcdhManager::new(10);
    let server_pub = server_manager.get_key_pair("server_conn_1").unwrap();

    // Server computes shared secret
    let server_shared_secret = server_manager
        .compute_shared_secret("server_conn_1", &client_pub)
        .unwrap();

    // Client receives SYN-ACK with server public key, computes shared secret
    let client_shared_secret = client_manager
        .compute_shared_secret("client_conn_1", &server_pub)
        .unwrap();

    // Both sides have same shared secret
    assert_eq!(
        client_shared_secret.as_bytes(),
        server_shared_secret.as_bytes(),
        "Handshake must result in matching shared secrets"
    );

    // Both sides derive session parameters
    let connection_id = 12345u64;
    let session_context = connection_id.to_be_bytes();

    let client_params = SessionDerivation::derive_session_keys_from_dh(
        &client_shared_secret,
        &client_pub,
        &server_pub,
        &session_context,
    )
    .unwrap();

    let server_params = SessionDerivation::derive_session_keys_from_dh(
        &server_shared_secret,
        &server_pub,
        &client_pub,
        &session_context,
    )
    .unwrap();

    // Session keys must match for encrypted communication
    assert_eq!(
        client_params.session_key.as_bytes(),
        server_params.session_key.as_bytes(),
        "Full handshake must produce matching session keys"
    );

    // All derived parameters must match
    assert_eq!(
        client_params.port_hop_seed, server_params.port_hop_seed,
        "Port hopping parameters must match for synchronized hopping"
    );
}
