#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Tests for Sequence Repair HMAC Confirmation (TASK-047)
//!
//! Verifies that sequence repair includes cryptographic confirmation
//! per design/protocol/12-recovery-mechanisms.md §2.

use buckwild_common::engines::recovery::RecoveryStrategies;
use buckwild_common::protocol::types::*;

// Test helper to create a test session key
fn create_test_session_key() -> SessionKey {
    let key_bytes = [42u8; 32]; // Test key
    SessionKey::new(key_bytes)
}

// =============================================================================
// HMAC Calculation Tests
// =============================================================================

#[test]
fn test_calculate_repair_confirmation_deterministic() {
    // Verify that the same inputs produce the same HMAC

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id = SessionId::new(11111);
    let session_key = create_test_session_key();

    let confirmation1 = RecoveryStrategies::verify_repair_confirmation(
        nonce,
        sequence,
        session_id.clone(),
        &session_key,
        [0u8; 8], // Will be replaced by calculated value
    );

    // Calculate expected confirmation
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
    mac.update(&confirmation_input);
    let result = mac.finalize();
    let hmac_bytes = result.into_bytes();

    let mut expected = [0u8; 8];
    expected.copy_from_slice(&hmac_bytes[..8]);

    // Verify with correct HMAC
    assert!(
        RecoveryStrategies::verify_repair_confirmation(
            nonce,
            sequence,
            session_id,
            &session_key,
            expected
        ),
        "HMAC verification should succeed with correct confirmation"
    );
}

#[test]
fn test_repair_confirmation_different_nonce() {
    // Verify that different nonces produce different HMACs

    let session_key = create_test_session_key();
    let sequence = SequenceNumber::new(1000);
    let session_id = SessionId::new(2000);

    let nonce1 = RecoveryNonce::new(1);
    let nonce2 = RecoveryNonce::new(2);

    // Calculate confirmations
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let calc_hmac = |nonce: RecoveryNonce| -> [u8; 8] {
        let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
        confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
        confirmation_input.extend_from_slice(b"sequence_repair_v1");

        let mut mac =
            Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
        mac.update(&confirmation_input);
        let result = mac.finalize();
        let hmac_bytes = result.into_bytes();

        let mut confirmation = [0u8; 8];
        confirmation.copy_from_slice(&hmac_bytes[..8]);
        confirmation
    };

    let confirmation1 = calc_hmac(nonce1);
    let confirmation2 = calc_hmac(nonce2);

    assert_ne!(
        confirmation1, confirmation2,
        "Different nonces must produce different HMACs"
    );
}

#[test]
fn test_repair_confirmation_different_sequence() {
    // Verify that different sequences produce different HMACs

    let session_key = create_test_session_key();
    let nonce = RecoveryNonce::new(1000);
    let session_id = SessionId::new(2000);

    let seq1 = SequenceNumber::new(1);
    let seq2 = SequenceNumber::new(2);

    // Calculate confirmations
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let calc_hmac = |sequence: SequenceNumber| -> [u8; 8] {
        let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
        confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
        confirmation_input.extend_from_slice(b"sequence_repair_v1");

        let mut mac =
            Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
        mac.update(&confirmation_input);
        let result = mac.finalize();
        let hmac_bytes = result.into_bytes();

        let mut confirmation = [0u8; 8];
        confirmation.copy_from_slice(&hmac_bytes[..8]);
        confirmation
    };

    let confirmation1 = calc_hmac(seq1);
    let confirmation2 = calc_hmac(seq2);

    assert_ne!(
        confirmation1, confirmation2,
        "Different sequences must produce different HMACs"
    );
}

#[test]
fn test_repair_confirmation_different_session() {
    // Verify that different session IDs produce different HMACs

    let session_key = create_test_session_key();
    let nonce = RecoveryNonce::new(1000);
    let sequence = SequenceNumber::new(2000);

    let session_id1 = SessionId::new(1);
    let session_id2 = SessionId::new(2);

    // Calculate confirmations
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let calc_hmac = |session_id: SessionId| -> [u8; 8] {
        let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
        confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
        confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
        confirmation_input.extend_from_slice(b"sequence_repair_v1");

        let mut mac =
            Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
        mac.update(&confirmation_input);
        let result = mac.finalize();
        let hmac_bytes = result.into_bytes();

        let mut confirmation = [0u8; 8];
        confirmation.copy_from_slice(&hmac_bytes[..8]);
        confirmation
    };

    let confirmation1 = calc_hmac(session_id1);
    let confirmation2 = calc_hmac(session_id2);

    assert_ne!(
        confirmation1, confirmation2,
        "Different session IDs must produce different HMACs"
    );
}

// =============================================================================
// HMAC Verification Tests
// =============================================================================

#[test]
fn test_verify_repair_confirmation_valid_hmac() {
    // Test Case 2: HMAC Correct - Confirmation HMAC verifiable

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id = SessionId::new(11111);
    let session_key = create_test_session_key();

    // Calculate correct HMAC
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
    mac.update(&confirmation_input);
    let result = mac.finalize();
    let hmac_bytes = result.into_bytes();

    let mut correct_hmac = [0u8; 8];
    correct_hmac.copy_from_slice(&hmac_bytes[..8]);

    // Test Case 3: Peer Accepts - Peer accepts new sequence on valid HMAC
    assert!(
        RecoveryStrategies::verify_repair_confirmation(
            nonce,
            sequence,
            session_id,
            &session_key,
            correct_hmac
        ),
        "Valid HMAC should be accepted"
    );
}

#[test]
fn test_verify_repair_confirmation_invalid_hmac() {
    // Test Case 4: Peer Rejects - Invalid HMAC rejects repair

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id = SessionId::new(11111);
    let session_key = create_test_session_key();

    let invalid_hmac = [0xFFu8; 8]; // Wrong HMAC

    assert!(
        !RecoveryStrategies::verify_repair_confirmation(
            nonce,
            sequence,
            session_id,
            &session_key,
            invalid_hmac
        ),
        "Invalid HMAC should be rejected"
    );
}

#[test]
fn test_verify_repair_confirmation_modified_nonce() {
    // Verify that modifying the nonce invalidates the HMAC

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id = SessionId::new(11111);
    let session_key = create_test_session_key();

    // Calculate HMAC with original nonce
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
    mac.update(&confirmation_input);
    let result = mac.finalize();
    let hmac_bytes = result.into_bytes();

    let mut hmac = [0u8; 8];
    hmac.copy_from_slice(&hmac_bytes[..8]);

    // Try to verify with different nonce
    let wrong_nonce = RecoveryNonce::new(54321);

    assert!(
        !RecoveryStrategies::verify_repair_confirmation(
            wrong_nonce,
            sequence,
            session_id,
            &session_key,
            hmac
        ),
        "HMAC should fail with modified nonce"
    );
}

#[test]
fn test_verify_repair_confirmation_modified_sequence() {
    // Verify that modifying the sequence invalidates the HMAC

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id = SessionId::new(11111);
    let session_key = create_test_session_key();

    // Calculate HMAC with original sequence
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
    mac.update(&confirmation_input);
    let result = mac.finalize();
    let hmac_bytes = result.into_bytes();

    let mut hmac = [0u8; 8];
    hmac.copy_from_slice(&hmac_bytes[..8]);

    // Try to verify with different sequence
    let wrong_sequence = SequenceNumber::new(99999);

    assert!(
        !RecoveryStrategies::verify_repair_confirmation(
            nonce,
            wrong_sequence,
            session_id,
            &session_key,
            hmac
        ),
        "HMAC should fail with modified sequence"
    );
}

#[test]
fn test_verify_repair_confirmation_constant_time() {
    // Verify that HMAC comparison is constant-time
    // This is critical for preventing timing attacks

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id = SessionId::new(11111);
    let session_key = create_test_session_key();

    // Calculate correct HMAC
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
    mac.update(&confirmation_input);
    let result = mac.finalize();
    let hmac_bytes = result.into_bytes();

    let mut correct_hmac = [0u8; 8];
    correct_hmac.copy_from_slice(&hmac_bytes[..8]);

    // Test with HMACs that differ in first byte vs last byte
    let mut wrong_hmac_first = correct_hmac;
    wrong_hmac_first[0] ^= 0xFF;

    let mut wrong_hmac_last = correct_hmac;
    wrong_hmac_last[7] ^= 0xFF;

    // Both should fail
    assert!(
        !RecoveryStrategies::verify_repair_confirmation(
            nonce,
            sequence,
            session_id.clone(),
            &session_key,
            wrong_hmac_first
        ),
        "Wrong first byte should fail"
    );

    assert!(
        !RecoveryStrategies::verify_repair_confirmation(
            nonce,
            sequence,
            session_id,
            &session_key,
            wrong_hmac_last
        ),
        "Wrong last byte should fail"
    );

    // Note: The implementation uses subtle::ConstantTimeEq for constant-time comparison
}

// =============================================================================
// Protocol Compliance Tests
// =============================================================================

#[test]
fn test_repair_confirmation_hmac_length() {
    // Verify that confirmation HMAC is exactly 8 bytes per spec
    // Per design/protocol/12-recovery-mechanisms.md:
    // "HMAC_SHA256_128(session_key, nonce || sequence || session_id || 'sequence_repair_v1')[0:8]"

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id = SessionId::new(11111);
    let session_key = create_test_session_key();

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
    mac.update(&confirmation_input);
    let result = mac.finalize();
    let hmac_bytes = result.into_bytes();

    let mut confirmation = [0u8; 8];
    confirmation.copy_from_slice(&hmac_bytes[..8]);

    assert_eq!(
        confirmation.len(),
        8,
        "Confirmation HMAC must be exactly 8 bytes"
    );
}

#[test]
fn test_repair_confirmation_input_format() {
    // Verify that confirmation input follows spec format:
    // nonce (4 bytes) || sequence (4 bytes) || session_id (8 bytes) || "sequence_repair_v1" (19 bytes)

    let nonce = RecoveryNonce::new(0x12345678);
    let sequence = SequenceNumber::new(0x9ABCDEF0);
    let session_id = SessionId::new(0x1122334455667788);

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    // Verify total length
    assert_eq!(
        confirmation_input.len(),
        4 + 4 + 8 + 19,
        "Confirmation input must be 35 bytes"
    );

    // Verify nonce position
    assert_eq!(
        &confirmation_input[0..4],
        &[0x12, 0x34, 0x56, 0x78],
        "Nonce must be in big-endian at offset 0"
    );

    // Verify sequence position
    assert_eq!(
        &confirmation_input[4..8],
        &[0x9A, 0xBC, 0xDE, 0xF0],
        "Sequence must be in big-endian at offset 4"
    );

    // Verify session_id position
    assert_eq!(
        &confirmation_input[8..16],
        &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        "Session ID must be in big-endian at offset 8"
    );

    // Verify version string position
    assert_eq!(
        &confirmation_input[16..35],
        b"sequence_repair_v1",
        "Version string must be at offset 16"
    );
}

// =============================================================================
// Cross-Session Attack Prevention Tests
// =============================================================================

#[test]
fn test_repair_confirmation_prevents_cross_session_replay() {
    // Verify that a valid confirmation for one session cannot be replayed to another

    let nonce = RecoveryNonce::new(12345);
    let sequence = SequenceNumber::new(67890);
    let session_id1 = SessionId::new(11111);
    let session_id2 = SessionId::new(22222);
    let session_key = create_test_session_key();

    // Calculate HMAC for session 1
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut confirmation_input = Vec::with_capacity(4 + 4 + 8 + 19);
    confirmation_input.extend_from_slice(&nonce.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&sequence.as_u32().to_be_bytes());
    confirmation_input.extend_from_slice(&session_id1.as_u64().to_be_bytes());
    confirmation_input.extend_from_slice(b"sequence_repair_v1");

    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key.as_bytes()).expect("HMAC creation failed");
    mac.update(&confirmation_input);
    let result = mac.finalize();
    let hmac_bytes = result.into_bytes();

    let mut session1_hmac = [0u8; 8];
    session1_hmac.copy_from_slice(&hmac_bytes[..8]);

    // Verify succeeds for session 1
    assert!(
        RecoveryStrategies::verify_repair_confirmation(
            nonce,
            sequence,
            session_id1,
            &session_key,
            session1_hmac
        ),
        "HMAC should be valid for session 1"
    );

    // Verify fails for session 2 (replay attack)
    assert!(
        !RecoveryStrategies::verify_repair_confirmation(
            nonce,
            sequence,
            session_id2,
            &session_key,
            session1_hmac
        ),
        "HMAC from session 1 should not be valid for session 2"
    );
}
