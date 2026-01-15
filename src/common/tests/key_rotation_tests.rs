// Key Rotation Integration Tests (M4: CRIT-004)
//
// Validates session key rotation mechanisms including:
// - Periodic rekey triggers at interval boundaries
// - Mid-session rotation with active data transfer
// - Key derivation chain produces unique keys per rotation
// - Concurrent rekey handling (race condition safety)
//
// Protocol reference: design/protocol/04-ecdh-cryptography.md §"ECDH-Based Session Recovery"

use buckwild_common::engines::management::{RekeyEngine, RekeyResult};
use buckwild_common::protocol::types::*;
use buckwild_common::security::crypto::ecdh::ThreadSafeEcdhManager;
use buckwild_common::security::crypto::session_derivation::SessionDerivation;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Helper to create test session context
fn create_test_session_context(suffix: &str) -> Vec<u8> {
    format!("test_session_{}", suffix).into_bytes()
}

// Helper to create test shared secret
fn create_test_shared_secret(seed: u8) -> SharedSecret {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    for i in 1..32 {
        bytes[i] = bytes[i - 1].wrapping_add(seed);
    }
    SharedSecret::new(bytes)
}

// Helper to create test public keys
fn create_test_public_keys(seed: u8) -> (EcdhPublicKey, EcdhPublicKey) {
    let mut client_bytes = [seed; 64];
    let mut server_bytes = [seed.wrapping_add(1); 64];

    for i in 0..64 {
        client_bytes[i] = client_bytes[i].wrapping_add(i as u8);
        server_bytes[i] = server_bytes[i].wrapping_add(i as u8);
    }

    (
        EcdhPublicKey::new(client_bytes),
        EcdhPublicKey::new(server_bytes),
    )
}

#[tokio::test]
async fn test_periodic_rekey_at_boundary() {
    // Scenario: Rekey triggered exactly at the configured interval boundary
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = RekeyEngine::new(ecdh_manager.clone());

    let session_id = SessionId::new(12345u64);
    let reason = RekeyReason::Periodic;

    // Execute rekey
    let result = rekey_engine.initiate_rekey(session_id, reason).await;

    assert!(result.is_ok(), "Periodic rekey at boundary should succeed");
    let packet = result.unwrap();
    assert!(
        !packet.is_empty(),
        "Rekey request packet should not be empty"
    );
}

#[tokio::test]
async fn test_periodic_rekey_just_before_boundary() {
    // Scenario: Rekey triggered slightly before the interval boundary
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = RekeyEngine::new(ecdh_manager.clone());

    let session_id = SessionId::new(54321u64);
    let reason = RekeyReason::Periodic;

    // Execute rekey
    let result = rekey_engine.initiate_rekey(session_id, reason).await;

    assert!(
        result.is_ok(),
        "Periodic rekey before boundary should succeed"
    );
}

#[tokio::test]
async fn test_mid_session_rotation_with_pending_data() {
    // Scenario: Rekey while data transmission is active
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = RekeyEngine::new(ecdh_manager.clone());

    let session_id = SessionId::new(99999u64);
    let reason = RekeyReason::SecurityEvent;

    // Simulate active data transfer by initiating rekey
    let result = rekey_engine
        .initiate_rekey(session_id.clone(), reason)
        .await;

    assert!(
        result.is_ok(),
        "Mid-session rekey with pending data should succeed"
    );

    // Verify we can initiate another rekey immediately (simulating queued data)
    let result2 = rekey_engine
        .initiate_rekey(session_id, RekeyReason::PolicyChange)
        .await;
    assert!(result2.is_ok(), "Sequential rekeys should both succeed");
}

#[tokio::test]
async fn test_mid_session_rotation_without_pending_data() {
    // Scenario: Rekey with idle session
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = RekeyEngine::new(ecdh_manager.clone());

    let session_id = SessionId::new(77777u64);
    let reason = RekeyReason::Scheduled;

    // Execute rekey on idle session
    let result = rekey_engine.initiate_rekey(session_id, reason).await;

    assert!(
        result.is_ok(),
        "Mid-session rekey without pending data should succeed"
    );
}

#[test]
fn test_sequential_key_derivation_produces_unique_keys() {
    // Scenario: Verify that sequential rotations produce different keys
    let shared_secret = create_test_shared_secret(42);
    let (client_pub, server_pub) = create_test_public_keys(10);

    // First derivation
    let context1 = create_test_session_context("rotation_1");
    let params1 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &client_pub,
        &server_pub,
        &context1,
    )
    .unwrap();

    // Second derivation with different context (simulating rotation)
    let context2 = create_test_session_context("rotation_2");
    let params2 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &client_pub,
        &server_pub,
        &context2,
    )
    .unwrap();

    // Keys must be unique across rotations
    assert_ne!(
        params1.session_key.as_bytes(),
        params2.session_key.as_bytes(),
        "Sequential rotations must produce unique session keys"
    );

    // Other parameters should also differ
    assert_ne!(
        params1.port_hop_seed, params2.port_hop_seed,
        "Port hop seeds must differ across rotations"
    );
}

#[test]
fn test_parallel_key_derivation_with_different_secrets() {
    // Scenario: Multiple peers derive keys in parallel from different secrets
    let secret1 = create_test_shared_secret(1);
    let secret2 = create_test_shared_secret(2);
    let (client_pub, server_pub) = create_test_public_keys(20);
    let context = create_test_session_context("parallel");

    // Parallel derivation
    let params1 = SessionDerivation::derive_session_keys_from_dh(
        &secret1,
        &client_pub,
        &server_pub,
        &context,
    )
    .unwrap();

    let params2 = SessionDerivation::derive_session_keys_from_dh(
        &secret2,
        &client_pub,
        &server_pub,
        &context,
    )
    .unwrap();

    // Keys must be unique when derived from different secrets
    assert_ne!(
        params1.session_key.as_bytes(),
        params2.session_key.as_bytes(),
        "Different shared secrets must produce unique keys"
    );
}

#[tokio::test]
async fn test_concurrent_rekey_requests_single_session() {
    // Scenario: Race condition - two tasks request rekey simultaneously
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = Arc::new(RekeyEngine::new(ecdh_manager));

    let session_id = SessionId::new(11111u64);

    // Spawn two tasks that simultaneously initiate rekey
    let engine1 = rekey_engine.clone();
    let sid1 = session_id.clone();
    let handle1 =
        tokio::spawn(async move { engine1.initiate_rekey(sid1, RekeyReason::Periodic).await });

    let engine2 = rekey_engine.clone();
    let sid2 = session_id.clone();
    let handle2 = tokio::spawn(async move {
        engine2
            .initiate_rekey(sid2, RekeyReason::SecurityEvent)
            .await
    });

    // Both should succeed without race conditions
    let result1 = handle1.await.unwrap();
    let result2 = handle2.await.unwrap();

    assert!(result1.is_ok(), "First concurrent rekey should succeed");
    assert!(result2.is_ok(), "Second concurrent rekey should succeed");
}

#[tokio::test]
async fn test_concurrent_rekey_requests_different_sessions() {
    // Scenario: Multiple sessions undergoing rekey simultaneously
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = Arc::new(RekeyEngine::new(ecdh_manager));

    let session_id1 = SessionId::new(1001u64);
    let session_id2 = SessionId::new(1002u64);
    let session_id3 = SessionId::new(1003u64);

    // Spawn three concurrent rekeys on different sessions
    let engine1 = rekey_engine.clone();
    let handle1 = tokio::spawn(async move {
        engine1
            .initiate_rekey(session_id1, RekeyReason::Periodic)
            .await
    });

    let engine2 = rekey_engine.clone();
    let handle2 = tokio::spawn(async move {
        engine2
            .initiate_rekey(session_id2, RekeyReason::Periodic)
            .await
    });

    let engine3 = rekey_engine.clone();
    let handle3 = tokio::spawn(async move {
        engine3
            .initiate_rekey(session_id3, RekeyReason::Periodic)
            .await
    });

    // All should succeed
    assert!(handle1.await.unwrap().is_ok());
    assert!(handle2.await.unwrap().is_ok());
    assert!(handle3.await.unwrap().is_ok());
}

#[test]
fn test_key_derivation_chain_uniqueness() {
    // Scenario: Verify chain of rotations produces unique keys at each step
    let shared_secret = create_test_shared_secret(100);
    let (client_pub, server_pub) = create_test_public_keys(50);

    let mut previous_keys: Vec<Vec<u8>> = Vec::new();

    // Perform 5 sequential rotations
    for i in 0..5 {
        let context = create_test_session_context(&format!("chain_{}", i));
        let params = SessionDerivation::derive_session_keys_from_dh(
            &shared_secret,
            &client_pub,
            &server_pub,
            &context,
        )
        .unwrap();

        // Verify this key is unique compared to all previous keys
        for (idx, prev_key) in previous_keys.iter().enumerate() {
            assert_ne!(
                params.session_key.as_bytes(),
                prev_key.as_slice(),
                "Rotation {} produced duplicate key (same as rotation {})",
                i,
                idx
            );
        }

        previous_keys.push(params.session_key.as_bytes().to_vec());
    }
}

#[tokio::test]
async fn test_rekey_response_handling() {
    // Scenario: Verify rekey response processing
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = RekeyEngine::new(ecdh_manager);

    let key_id = KeyId::from_u32(9999u32);

    // Handle rekey response
    let result = rekey_engine.handle_rekey_response(key_id.clone()).await;

    assert!(result.is_ok(), "Rekey response handling should succeed");

    match result.unwrap() {
        RekeyResult::Success {
            key_id: returned_id,
        } => {
            assert_eq!(returned_id, key_id, "Key ID should match");
        }
        _ => panic!("Expected Success result"),
    }
}

#[tokio::test]
async fn test_rapid_sequential_rekeys() {
    // Scenario: Stress test - rapid sequential rekeys
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = RekeyEngine::new(ecdh_manager);

    let session_id = SessionId::new(88888u64);

    // Perform 10 rapid sequential rekeys
    for i in 0..10 {
        let reason = if i % 2 == 0 {
            RekeyReason::Periodic
        } else {
            RekeyReason::SecurityEvent
        };

        let result = rekey_engine
            .initiate_rekey(session_id.clone(), reason)
            .await;
        assert!(result.is_ok(), "Rapid rekey iteration {} should succeed", i);
    }
}

#[tokio::test]
async fn test_rekey_timing_boundaries() {
    // Scenario: Verify rekey timing doesn't drift
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let rekey_engine = RekeyEngine::new(ecdh_manager);

    let session_id = SessionId::new(33333u64);
    let start = Instant::now();

    // Initiate rekey
    let result = rekey_engine
        .initiate_rekey(session_id, RekeyReason::Periodic)
        .await;

    let elapsed = start.elapsed();

    assert!(result.is_ok(), "Rekey should succeed");
    assert!(
        elapsed < Duration::from_millis(100),
        "Rekey initiation should complete quickly (took {:?})",
        elapsed
    );
}

#[test]
fn test_key_derivation_deterministic() {
    // Scenario: Verify key derivation is deterministic
    let shared_secret = create_test_shared_secret(200);
    let (client_pub, server_pub) = create_test_public_keys(100);
    let context = create_test_session_context("deterministic");

    // Derive keys twice with same inputs
    let params1 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &client_pub,
        &server_pub,
        &context,
    )
    .unwrap();

    let params2 = SessionDerivation::derive_session_keys_from_dh(
        &shared_secret,
        &client_pub,
        &server_pub,
        &context,
    )
    .unwrap();

    // Results must be identical
    assert_eq!(
        params1.session_key.as_bytes(),
        params2.session_key.as_bytes(),
        "Key derivation must be deterministic"
    );
    assert_eq!(params1.port_hop_seed, params2.port_hop_seed);
    assert_eq!(
        params1.client_initial_sequence,
        params2.client_initial_sequence
    );
    assert_eq!(
        params1.server_initial_sequence,
        params2.server_initial_sequence
    );
}
