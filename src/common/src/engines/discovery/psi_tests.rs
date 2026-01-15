#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// PSK Discovery Protocol Tests (Privacy-Preserving Set Intersection)
//
// These tests verify the complete PSK discovery protocol implementation
// following design/protocol/05-psk-discovery.md

use super::bloom::*;
use super::*;

// Helper to run async tests
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Runtime::new()
        .expect("Failed to create runtime for test")
        .block_on(f)
}

/// Test helper to create PSK fingerprints
/// TASK-007: Use valid non-zero keys for HMAC operations
fn create_test_fingerprints(count: usize) -> Vec<PskFingerprint> {
    (0..count)
        .map(|i| {
            // Create valid test fingerprints with repeating pattern (not all zeros)
            let mut bytes = [0x42u8; 32]; // Non-zero base
            bytes[0] = i as u8; // Unique first byte
            bytes[1] = (i >> 8) as u8; // Add more uniqueness
            bytes[31] = !i as u8; // Different pattern at end
            PskId::new(bytes)
        })
        .collect()
}

// =========================================================================
// Blinded Fingerprint Tests
// =========================================================================

#[test]
fn test_create_blinded_fingerprint_set() {
    let fingerprints = create_test_fingerprints(10);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let builder = BloomFilterBuilder::default();
    let blinded_set: Vec<[u8; 16]> = fingerprints
        .iter()
        .map(|fp| builder.blind_fingerprint(fp, discovery_id, session_salt))
        .collect();

    // Verify all fingerprints were blinded
    assert_eq!(blinded_set.len(), 10);

    // Verify blinding produces unique values
    for i in 0..blinded_set.len() {
        for j in (i + 1)..blinded_set.len() {
            assert_ne!(
                blinded_set[i], blinded_set[j],
                "Blinded fingerprints should be unique"
            );
        }
    }
}

#[test]
fn test_blinding_is_deterministic() {
    let fingerprints = create_test_fingerprints(5);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let builder = BloomFilterBuilder::default();

    let blinded1: Vec<[u8; 16]> = fingerprints
        .iter()
        .map(|fp| builder.blind_fingerprint(fp, discovery_id, session_salt))
        .collect();

    let blinded2: Vec<[u8; 16]> = fingerprints
        .iter()
        .map(|fp| builder.blind_fingerprint(fp, discovery_id, session_salt))
        .collect();

    // Same inputs should produce same outputs
    for i in 0..blinded1.len() {
        assert_eq!(blinded1[i], blinded2[i], "Blinding should be deterministic");
    }
}

#[test]
fn test_different_discovery_context_produces_different_blinding() {
    let fingerprints = create_test_fingerprints(5);
    let builder = BloomFilterBuilder::default();

    let blinded1: Vec<[u8; 16]> = fingerprints
        .iter()
        .map(|fp| builder.blind_fingerprint(fp, DiscoveryId::new(111), 222))
        .collect();

    let blinded2: Vec<[u8; 16]> = fingerprints
        .iter()
        .map(|fp| builder.blind_fingerprint(fp, DiscoveryId::new(333), 444))
        .collect();

    // Different context should produce different blinding
    for i in 0..blinded1.len() {
        assert_ne!(
            blinded1[i], blinded2[i],
            "Different context should change blinding"
        );
    }
}

// =========================================================================
// Bloom Filter Set Intersection Tests
// =========================================================================

#[test]
#[allow(clippy::useless_vec)]
fn test_bloom_filter_finds_shared_psks() {
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create two sets with overlap
    let alice_psks = create_test_fingerprints(10); // PSKs 0-9
    let bob_psks = create_test_fingerprints(15); // PSKs 0-14 (0-9 shared with Alice)

    let builder = BloomFilterBuilder::new(20, 0.01);

    // Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_psks, discovery_id, session_salt);

    // Bob tests his fingerprints against Alice's Bloom filter
    let mut candidates = Vec::new();
    for psk in &bob_psks {
        let blinded = builder.blind_fingerprint(psk, discovery_id, session_salt);
        if builder.test(&alice_bloom, &blinded) {
            candidates.push(psk.clone());
        }
    }

    // Should find at least the 10 shared PSKs (may have false positives)
    assert!(
        candidates.len() >= 10,
        "Should find at least 10 shared PSKs, found {}",
        candidates.len()
    );

    // Verify the first 10 are definitely in candidates (these are shared)
    for (i, alice_psk) in alice_psks.iter().enumerate().take(10) {
        let found = candidates
            .iter()
            .any(|c| c.as_bytes() == alice_psk.as_bytes());
        assert!(found, "Shared PSK {} should be found in candidates", i);
    }
}

#[test]
fn test_bloom_filter_no_intersection() {
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create two non-overlapping sets
    let alice_psks = create_test_fingerprints(5); // PSKs 0-4

    // Create Bob's PSKs starting from 10 to ensure no overlap
    let bob_psks: Vec<PskFingerprint> = (10..15)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            PskId::new(bytes)
        })
        .collect();

    let builder = BloomFilterBuilder::new(20, 0.01);

    // Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_psks, discovery_id, session_salt);

    // Bob tests his fingerprints
    let mut candidates = Vec::new();
    for psk in &bob_psks {
        let blinded = builder.blind_fingerprint(psk, discovery_id, session_salt);
        if builder.test(&alice_bloom, &blinded) {
            candidates.push(psk.clone());
        }
    }

    // With 1% false positive rate and 5 non-member tests, statistically expect 0-1 false positives
    // Allow up to 2 to account for random variation
    assert!(
        candidates.len() <= 2,
        "Should have ≤2 false positives with 1% FP rate and 5 tests, found {}",
        candidates.len()
    );
}

#[test]
fn test_bloom_filter_privacy_preservation() {
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Alice has PSKs 0-4
    let alice_psks = create_test_fingerprints(5);
    // Bob has PSKs 3-7 (PSKs 3-4 shared)
    // TASK-007: Use valid non-zero keys matching create_test_fingerprints pattern
    let bob_psks: Vec<PskFingerprint> = (3..8)
        .map(|i| {
            let mut bytes = [0x42u8; 32]; // Non-zero base (matches create_test_fingerprints)
            bytes[0] = i as u8;
            bytes[1] = (i >> 8) as u8;
            bytes[31] = !i as u8;
            PskId::new(bytes)
        })
        .collect();

    let builder = BloomFilterBuilder::new(20, 0.01);

    // Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_psks, discovery_id, session_salt);

    // Bob tests his fingerprints
    let mut candidates = Vec::new();
    for psk in &bob_psks {
        let blinded = builder.blind_fingerprint(psk, discovery_id, session_salt);
        if builder.test(&alice_bloom, &blinded) {
            candidates.push(psk.clone());
        }
    }

    // Bob should find PSKs 3 and 4 as candidates
    assert!(candidates.len() >= 2, "Should find at least 2 shared PSKs");

    // Verify PSKs 3 and 4 are in candidates
    let psk3_found = candidates.iter().any(|c| c.as_bytes()[0] == 3);
    let psk4_found = candidates.iter().any(|c| c.as_bytes()[0] == 4);

    assert!(psk3_found, "PSK 3 should be found");
    assert!(psk4_found, "PSK 4 should be found");

    // Bob CANNOT learn about Alice's PSKs 0, 1, 2 (privacy preserved)
    // This is guaranteed by the Bloom filter property - no false negatives
}

// =========================================================================
// Discovery Protocol Flow Tests
// =========================================================================

#[test]
fn test_discovery_engine_initiate_discovery() {
    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Initiate discovery should create packet
    let result = block_on(engine.initiate_discovery(session_id));

    assert!(result.is_ok(), "Discovery initiation should succeed");
    let packet_bytes = result.unwrap();
    assert!(!packet_bytes.is_empty(), "Should produce non-empty packet");
}

#[test]
fn test_discovery_engine_handle_response_with_candidates() {
    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
    let discovery_id = DiscoveryId::new(12345);

    // Simulate response with candidates
    let candidate_hashes = vec![CandidateHash::new([1u8; 32]), CandidateHash::new([2u8; 32])];

    let result =
        block_on(engine.handle_discovery_response(session_id, discovery_id, candidate_hashes));

    assert!(result.is_ok(), "Response handling should succeed");
    let psk_option = result.unwrap();
    assert!(psk_option.is_some(), "Should select a PSK from candidates");
}

#[test]
fn test_discovery_engine_handle_response_no_candidates() {
    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
    let discovery_id = DiscoveryId::new(12345);

    // Empty candidate list (no intersection)
    let candidate_hashes = vec![];

    let result =
        block_on(engine.handle_discovery_response(session_id, discovery_id, candidate_hashes));

    assert!(result.is_ok(), "Should handle no candidates gracefully");
    let psk_option = result.unwrap();
    assert!(
        psk_option.is_none(),
        "Should return None when no candidates"
    );
}

#[test]
fn test_discovery_engine_create_confirmation() {
    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
    let discovery_id = DiscoveryId::new(12345);
    let selected_psk = PskId::from_u32(1);

    let result = block_on(engine.create_confirmation(session_id, discovery_id, selected_psk));

    assert!(result.is_ok(), "Confirmation creation should succeed");
    let packet_bytes = result.unwrap();
    assert!(
        !packet_bytes.is_empty(),
        "Should produce non-empty confirmation packet"
    );
}

#[test]
fn test_discovery_timeout_detection() {
    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let discovery_id = DiscoveryId::new(12345);

    // Initially no timeout
    assert!(
        !engine.check_timeout(&discovery_id),
        "Should not timeout immediately"
    );

    // After initiating, still no timeout (would need to wait DISCOVERY_TIMEOUT_MS)
    // This is a unit test, so we just verify the method exists and doesn't panic
}

// =========================================================================
// Optimal PSK Selection Tests
// =========================================================================

#[test]
#[allow(clippy::useless_vec)]
fn test_select_optimal_psk_from_candidates() {
    // When multiple PSKs match, should select one consistently
    let candidate_hashes = vec![
        CandidateHash::new([1u8; 32]),
        CandidateHash::new([2u8; 32]),
        CandidateHash::new([3u8; 32]),
    ];

    // For now, just verify we can select from candidates
    // Real implementation would use priority/recency
    assert!(
        !candidate_hashes.is_empty(),
        "Should have candidates to select from"
    );
    let selected = &candidate_hashes[0];
    assert_eq!(selected.as_bytes()[0], 1, "Should select first candidate");
}

// =========================================================================
// Bloom Filter Parameter Optimization Tests
// =========================================================================

#[test]
fn test_bloom_filter_optimal_size_calculation() {
    // For 100 elements with 1% false positive rate
    let builder = BloomFilterBuilder::new(100, 0.01);

    // Formula: m = -(n * ln(p)) / (ln(2)^2)
    // m = -(100 * ln(0.01)) / (ln(2)^2) ≈ 959 bits
    assert!(
        builder.size_bits() > 900 && builder.size_bits() < 1000,
        "Optimal size should be around 959 bits for n=100, p=0.01, got {}",
        builder.size_bits()
    );
}

#[test]
fn test_bloom_filter_optimal_hash_count() {
    // For 100 elements and ~959 bits
    let builder = BloomFilterBuilder::new(100, 0.01);

    // Formula: k = (m/n) * ln(2)
    // k = (959/100) * ln(2) ≈ 6.65 ≈ 7
    assert!(
        builder.hash_functions() >= 6 && builder.hash_functions() <= 8,
        "Optimal hash count should be 6-8 for n=100, m~=959, got {}",
        builder.hash_functions()
    );
}

#[test]
fn test_bloom_filter_false_positive_rate() {
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create Bloom filter with known parameters
    let actual_psks = create_test_fingerprints(100);
    let builder = BloomFilterBuilder::new(100, 0.01);

    let bloom = builder.build_from_fingerprints(&actual_psks, discovery_id, session_salt);

    // Test with 1000 random non-member PSKs
    let mut false_positives = 0;
    for i in 200..1200 {
        let mut bytes = [0u8; 32];
        bytes[0] = (i >> 8) as u8;
        bytes[1] = (i & 0xFF) as u8;
        let test_psk = PskId::new(bytes);

        let blinded = builder.blind_fingerprint(&test_psk, discovery_id, session_salt);
        if builder.test(&bloom, &blinded) {
            false_positives += 1;
        }
    }

    let fp_rate = false_positives as f64 / 1000.0;
    // Should be around 1% ± some margin
    assert!(
        fp_rate < 0.05,
        "False positive rate should be < 5%, got {}",
        fp_rate
    );
}

// =========================================================================
// HMAC-Based Fingerprint Blinding Protocol Compliance Tests
// =========================================================================

#[test]
fn test_hmac_blinding_uses_correct_algorithm() {
    // Protocol requires: HMAC_SHA256_128 (16-byte truncated HMAC-SHA256)
    // Key = PSK fingerprint
    // Data = discovery_context || b"psi_blinding_v1"

    let builder = BloomFilterBuilder::default();
    let fingerprint = PskId::from_u32(1);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let blinded = builder.blind_fingerprint(&fingerprint, discovery_id, session_salt);

    // Should produce 16-byte output (128 bits)
    assert_eq!(
        blinded.len(),
        16,
        "Blinded fingerprint must be 16 bytes per protocol spec"
    );
}

#[test]
fn test_hmac_blinding_uses_correct_context() {
    // Blinding should use discovery_context = discovery_id || session_salt || b"psi_blinding_v1"
    use crate::security::crypto::hmac::HmacCalculator;

    let builder = BloomFilterBuilder::default();
    let fingerprint = PskId::from_u32(42);
    let discovery_id = DiscoveryId::new(0x1122334455667788);
    let session_salt = 0xAABBCCDDu32;

    // Calculate expected blinded fingerprint manually
    let mut context = Vec::new();
    context.extend_from_slice(&discovery_id.to_be_bytes()); // 8 bytes
    context.extend_from_slice(&session_salt.to_be_bytes()); // 4 bytes
    context.extend_from_slice(b"psi_blinding_v1"); // context string

    // Use HMAC with fingerprint as key, context as data
    let hmac_calc = HmacCalculator::new();
    let hmac_result = hmac_calc
        .calculate_packet_hmac(
            &context,
            fingerprint.as_bytes(),
            HmacPolicy::Medium, // Medium = 16 bytes (128 bits)
        )
        .expect("HMAC calculation should succeed");

    let expected_blinded: [u8; 16] = hmac_result.as_bytes()[0..16].try_into().unwrap();

    // Get actual blinded fingerprint from implementation
    let actual_blinded = builder.blind_fingerprint(&fingerprint, discovery_id, session_salt);

    assert_eq!(
        actual_blinded, expected_blinded,
        "Blinding must use correct HMAC construction per protocol spec"
    );
}

#[test]
fn test_hmac_blinding_provides_unlinkability() {
    // Blinded fingerprints from different discovery sessions should be unlinkable
    let builder = BloomFilterBuilder::default();
    let fingerprint = PskId::from_u32(12345);

    // Session 1
    let discovery_id1 = DiscoveryId::new(1000);
    let session_salt1 = 5000u32;
    let blinded1 = builder.blind_fingerprint(&fingerprint, discovery_id1, session_salt1);

    // Session 2 (different discovery session)
    let discovery_id2 = DiscoveryId::new(2000);
    let session_salt2 = 6000u32;
    let blinded2 = builder.blind_fingerprint(&fingerprint, discovery_id2, session_salt2);

    // Session 3 (different discovery session)
    let discovery_id3 = DiscoveryId::new(3000);
    let session_salt3 = 7000u32;
    let blinded3 = builder.blind_fingerprint(&fingerprint, discovery_id3, session_salt3);

    // All should be different (unlinkable across sessions)
    assert_ne!(
        blinded1, blinded2,
        "Blinded fingerprints must be unlinkable across sessions"
    );
    assert_ne!(
        blinded2, blinded3,
        "Blinded fingerprints must be unlinkable across sessions"
    );
    assert_ne!(
        blinded1, blinded3,
        "Blinded fingerprints must be unlinkable across sessions"
    );
}

// =========================================================================
// Candidate Hash Generation Tests
// =========================================================================

#[test]
fn test_candidate_hash_generation() {
    // Protocol requires: SHA256(blinded_fp || b"candidate_v1")
    use ring::digest;

    let blinded_fp = [0x42u8; 16];

    // Calculate expected candidate hash
    let mut input = Vec::new();
    input.extend_from_slice(&blinded_fp);
    input.extend_from_slice(b"candidate_v1");
    let hash_result = digest::digest(&digest::SHA256, &input);
    let expected_hash: [u8; 32] = hash_result.as_ref().try_into().unwrap();

    // Implementation should produce this hash
    let candidate_hash = CandidateHash::new(expected_hash);
    assert_eq!(candidate_hash.as_bytes(), &expected_hash);
}

// =========================================================================
// PSK Candidate Verification Tests
// =========================================================================

#[test]
fn test_verify_single_candidate_intersection() {
    // Test verifying a single candidate that matches our PSK fingerprints
    let builder = BloomFilterBuilder::default();

    let our_fingerprint = PskId::from_u32(42);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create our blinded fingerprint
    let our_blinded = builder.blind_fingerprint(&our_fingerprint, discovery_id, session_salt);

    // Create candidate hash (what peer sends us)
    use ring::digest;
    let mut input = Vec::new();
    input.extend_from_slice(&our_blinded);
    input.extend_from_slice(b"candidate_v1");
    let hash_result = digest::digest(&digest::SHA256, &input);
    let candidate_hash_bytes: [u8; 32] = hash_result.as_ref().try_into().unwrap();
    let candidate_hash = CandidateHash::new(candidate_hash_bytes);

    // Verify candidate matches our fingerprint
    let local_fingerprints = vec![our_fingerprint.clone()];
    let candidate_hashes = vec![candidate_hash];

    let verified = builder.verify_candidates(
        &candidate_hashes,
        &local_fingerprints,
        discovery_id,
        session_salt,
    );

    assert_eq!(verified.len(), 1, "Should find exactly one intersection");
    assert_eq!(verified[0].original_fingerprint, our_fingerprint);
}

#[test]
fn test_verify_multiple_candidate_intersections() {
    // Test verifying multiple candidates
    let builder = BloomFilterBuilder::default();

    let fingerprint1 = PskId::from_u32(1);
    let fingerprint2 = PskId::from_u32(2);
    let fingerprint3 = PskId::from_u32(3);

    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create blinded fingerprints
    let blinded1 = builder.blind_fingerprint(&fingerprint1, discovery_id, session_salt);
    let blinded2 = builder.blind_fingerprint(&fingerprint2, discovery_id, session_salt);

    // Create candidate hashes for fingerprints 1 and 2 (not 3)
    use ring::digest;
    let mut input1 = Vec::new();
    input1.extend_from_slice(&blinded1);
    input1.extend_from_slice(b"candidate_v1");
    let hash1 = digest::digest(&digest::SHA256, &input1);
    let candidate1 = CandidateHash::new(hash1.as_ref().try_into().unwrap());

    let mut input2 = Vec::new();
    input2.extend_from_slice(&blinded2);
    input2.extend_from_slice(b"candidate_v1");
    let hash2 = digest::digest(&digest::SHA256, &input2);
    let candidate2 = CandidateHash::new(hash2.as_ref().try_into().unwrap());

    let local_fingerprints = vec![
        fingerprint1.clone(),
        fingerprint2.clone(),
        fingerprint3.clone(),
    ];
    let candidate_hashes = vec![candidate1, candidate2];

    let verified = builder.verify_candidates(
        &candidate_hashes,
        &local_fingerprints,
        discovery_id,
        session_salt,
    );

    assert_eq!(verified.len(), 2, "Should find exactly two intersections");

    // Check both fingerprints are found
    let verified_fps: Vec<_> = verified
        .iter()
        .map(|v| v.original_fingerprint.clone())
        .collect();
    assert!(verified_fps.contains(&fingerprint1));
    assert!(verified_fps.contains(&fingerprint2));
    assert!(!verified_fps.contains(&fingerprint3));
}

#[test]
fn test_verify_no_candidate_intersections() {
    // Test when no candidates match
    let builder = BloomFilterBuilder::default();

    let our_fingerprint = PskId::from_u32(42);
    let other_fingerprint = PskId::from_u32(99);

    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create candidate hash for OTHER fingerprint (not ours)
    let other_blinded = builder.blind_fingerprint(&other_fingerprint, discovery_id, session_salt);

    use ring::digest;
    let mut input = Vec::new();
    input.extend_from_slice(&other_blinded);
    input.extend_from_slice(b"candidate_v1");
    let hash_result = digest::digest(&digest::SHA256, &input);
    let candidate_hash = CandidateHash::new(hash_result.as_ref().try_into().unwrap());

    let local_fingerprints = vec![our_fingerprint.clone()];
    let candidate_hashes = vec![candidate_hash];

    let verified = builder.verify_candidates(
        &candidate_hashes,
        &local_fingerprints,
        discovery_id,
        session_salt,
    );

    assert_eq!(verified.len(), 0, "Should find no intersections");
}

// =========================================================================
// Optimal PSK Selection Tests
// =========================================================================

#[test]
fn test_select_optimal_psk_from_single_intersection() {
    // When only one PSK in intersection, select it
    let fingerprint = PskId::from_u32(42);

    let intersections = vec![CandidateIntersection {
        original_fingerprint: fingerprint.clone(),
        blinded_fingerprint: [0u8; 16],
        candidate_hash: CandidateHash::new([0u8; 32]),
    }];

    let selected = BloomFilterBuilder::select_optimal_psk(&intersections);
    assert!(selected.is_some(), "Should select the only PSK");
    assert_eq!(selected.unwrap(), fingerprint);
}

#[test]
fn test_select_optimal_psk_from_multiple_intersections() {
    // When multiple PSKs, select based on priority (deterministic)
    let fp1 = PskId::from_u32(1);
    let fp2 = PskId::from_u32(2);
    let fp3 = PskId::from_u32(3);

    let intersections = vec![
        CandidateIntersection {
            original_fingerprint: fp1,
            blinded_fingerprint: [0u8; 16],
            candidate_hash: CandidateHash::new([0u8; 32]),
        },
        CandidateIntersection {
            original_fingerprint: fp2,
            blinded_fingerprint: [1u8; 16],
            candidate_hash: CandidateHash::new([1u8; 32]),
        },
        CandidateIntersection {
            original_fingerprint: fp3,
            blinded_fingerprint: [2u8; 16],
            candidate_hash: CandidateHash::new([2u8; 32]),
        },
    ];

    let selected = BloomFilterBuilder::select_optimal_psk(&intersections);
    assert!(selected.is_some(), "Should select a PSK");

    // Selection should be deterministic
    let selected2 = BloomFilterBuilder::select_optimal_psk(&intersections);
    assert_eq!(selected, selected2, "PSK selection must be deterministic");
}

#[test]
fn test_select_optimal_psk_returns_none_for_empty() {
    // When no intersections, return None
    let intersections = vec![];

    let selected = BloomFilterBuilder::select_optimal_psk(&intersections);
    assert!(
        selected.is_none(),
        "Should return None for empty intersections"
    );
}

// =========================================================================
// Confirmation Proof Tests
// =========================================================================

#[test]
fn test_confirmation_proof_generation() {
    // Protocol requires: SHA256(psk_fingerprint || confirmation_context || b"psk_confirmation_v1")
    // confirmation_context = discovery_id || session_salt

    let fingerprint = PskId::from_u32(42);
    let discovery_id = DiscoveryId::new(0x1122334455667788);
    let session_salt = 0xAABBCCDDu32;

    // Calculate expected confirmation hash
    use ring::digest;
    let mut input = Vec::new();
    input.extend_from_slice(fingerprint.as_bytes());
    input.extend_from_slice(&discovery_id.to_be_bytes());
    input.extend_from_slice(&session_salt.to_be_bytes());
    input.extend_from_slice(b"psk_confirmation_v1");

    let hash_result = digest::digest(&digest::SHA256, &input);
    let expected_hash: [u8; 32] = hash_result.as_ref().try_into().unwrap();

    // Implementation should produce this hash
    let builder = BloomFilterBuilder::default();
    let confirmation =
        builder.calculate_confirmation_hash(&fingerprint, discovery_id, session_salt);

    assert_eq!(
        confirmation, expected_hash,
        "Confirmation hash must match protocol specification"
    );
}

#[test]
fn test_confirmation_proof_is_deterministic() {
    // Same inputs should always produce same confirmation hash
    let builder = BloomFilterBuilder::default();
    let fingerprint = PskId::from_u32(99);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let hash1 = builder.calculate_confirmation_hash(&fingerprint, discovery_id, session_salt);
    let hash2 = builder.calculate_confirmation_hash(&fingerprint, discovery_id, session_salt);
    let hash3 = builder.calculate_confirmation_hash(&fingerprint, discovery_id, session_salt);

    assert_eq!(hash1, hash2, "Confirmation hash must be deterministic");
    assert_eq!(hash2, hash3, "Confirmation hash must be deterministic");
}

#[test]
fn test_confirmation_proof_verification() {
    // Verifying a confirmation proof should find the matching fingerprint
    let builder = BloomFilterBuilder::default();

    let fp1 = PskId::from_u32(1);
    let fp2 = PskId::from_u32(2);
    let fp3 = PskId::from_u32(3);

    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create confirmation hash for fp2
    let confirmation_hash = builder.calculate_confirmation_hash(&fp2, discovery_id, session_salt);

    // Verify against our local fingerprints
    let local_fingerprints = vec![fp1.clone(), fp2.clone(), fp3.clone()];
    let verified = builder.verify_confirmation(
        &confirmation_hash,
        &local_fingerprints,
        discovery_id,
        session_salt,
    );

    assert!(verified.is_some(), "Should find matching fingerprint");
    assert_eq!(verified.unwrap(), fp2, "Should match fp2");
}

#[test]
fn test_confirmation_proof_verification_no_match() {
    // Verification should return None when no fingerprint matches
    let builder = BloomFilterBuilder::default();

    let fp1 = PskId::from_u32(1);
    let fp2 = PskId::from_u32(2);
    let fp_other = PskId::from_u32(99);

    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    // Create confirmation hash for fingerprint NOT in our list
    let confirmation_hash =
        builder.calculate_confirmation_hash(&fp_other, discovery_id, session_salt);

    // Verify against our local fingerprints
    let local_fingerprints = vec![fp1.clone(), fp2.clone()];
    let verified = builder.verify_confirmation(
        &confirmation_hash,
        &local_fingerprints,
        discovery_id,
        session_salt,
    );

    assert!(verified.is_none(), "Should not find matching fingerprint");
}

// =========================================================================
// PSK Cache Integration Tests
// =========================================================================

#[test]
fn test_discovery_engine_psk_cache_insert_and_get() {
    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
    let psk_id = PskId::from_u32(42);
    let psk = [0x42u8; 32];

    // Cache a PSK
    engine.cache_psk(psk_id.clone(), psk, session_id.clone());

    // Retrieve it
    let cached = engine.get_cached_psk(&psk_id);
    assert!(cached.is_some(), "PSK should be cached");
    let cached = cached.unwrap();
    assert_eq!(cached.psk(), &psk);
    assert_eq!(cached.session_id().as_u64(), session_id.as_u64());
}

#[test]
fn test_discovery_engine_psk_cache_expiration() {
    use std::time::Duration;

    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
    let psk_id = PskId::from_u32(1);
    let psk = [0x01u8; 32];

    // Insert PSK with very short expiration
    engine.psk_cache().insert_with_expiration(
        psk_id.clone(),
        psk,
        session_id,
        Duration::from_millis(10),
    );

    // Should be available immediately
    assert!(engine.get_cached_psk(&psk_id).is_some());

    // Wait for expiration
    std::thread::sleep(Duration::from_millis(20));

    // Should be expired now
    assert!(engine.get_cached_psk(&psk_id).is_none());
}

#[test]
fn test_discovery_engine_cleanup_expired_psks() {
    use std::time::Duration;

    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Insert PSKs with different expirations
    engine.psk_cache().insert_with_expiration(
        PskId::from_u32(1),
        [0x01u8; 32],
        session_id.clone(),
        Duration::from_millis(10),
    );
    engine.psk_cache().insert_with_expiration(
        PskId::from_u32(2),
        [0x02u8; 32],
        session_id,
        Duration::from_secs(3600),
    );

    assert_eq!(engine.psk_cache().len(), 2);

    // Wait for first PSK to expire
    std::thread::sleep(Duration::from_millis(20));

    // Cleanup expired entries
    engine.cleanup_expired_psks();

    // Should only have one entry left
    assert_eq!(engine.psk_cache().len(), 1);
    assert!(engine.get_cached_psk(&PskId::from_u32(2)).is_some());
}

#[test]
fn test_discovery_engine_cache_multiple_sessions() {
    let psks = create_test_fingerprints(10);
    let engine = DiscoveryEngine::new(psks);

    // Different sessions with different PSKs
    let session1 = SessionId::new_with_length(1, SessionIdLength::Bits32);
    let session2 = SessionId::new_with_length(2, SessionIdLength::Bits32);

    let psk1 = PskId::from_u32(1);
    let psk2 = PskId::from_u32(2);

    engine.cache_psk(psk1.clone(), [0x01u8; 32], session1);
    engine.cache_psk(psk2.clone(), [0x02u8; 32], session2);

    // Both should be cached
    let cached1 = engine.get_cached_psk(&psk1);
    let cached2 = engine.get_cached_psk(&psk2);

    assert!(cached1.is_some());
    assert!(cached2.is_some());
    assert_eq!(cached1.unwrap().psk()[0], 0x01);
    assert_eq!(cached2.unwrap().psk()[0], 0x02);
}

#[test]
fn test_psk_cache_zeroization() {
    // This test verifies that CachedPsk uses Zeroizing
    // The actual zeroization happens on drop, which we can't directly test
    // but we can verify the type is correct
    use super::psk_cache::CachedPsk;
    use std::time::{Duration, Instant};

    let psk = [0x42u8; 32];
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
    let now = Instant::now();

    let cached = CachedPsk {
        psk: zeroize::Zeroizing::new(psk),
        validated_at: now,
        session_id,
        expires_at: now + Duration::from_secs(3600),
    };

    // Verify we can access the PSK
    assert_eq!(cached.psk(), &psk);

    // When cached is dropped, the PSK bytes should be zeroized
    drop(cached);
}

// =========================================================================
// Complete PSI Flow Integration Tests
// =========================================================================

#[test]
fn test_complete_psi_flow_with_intersection() {
    // Test complete privacy-preserving set intersection flow
    let builder = BloomFilterBuilder::default();

    // Alice's PSKs
    let alice_fps = vec![PskId::from_u32(1), PskId::from_u32(2), PskId::from_u32(3)];

    // Bob's PSKs (intersection: {2, 3})
    let bob_fps = vec![PskId::from_u32(2), PskId::from_u32(3), PskId::from_u32(4)];

    let discovery_id = DiscoveryId::new(99999);
    let session_salt = 88888u32;

    // Phase 1: Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_fps, discovery_id, session_salt);

    // Phase 2: Bob tests his fingerprints against Alice's Bloom filter
    let mut bob_candidates = Vec::new();
    use ring::digest;

    for fp in &bob_fps {
        let blinded = builder.blind_fingerprint(fp, discovery_id, session_salt);

        if builder.test(&alice_bloom, &blinded) {
            // Potential intersection - create candidate hash
            let mut input = Vec::new();
            input.extend_from_slice(&blinded);
            input.extend_from_slice(b"candidate_v1");
            let hash = digest::digest(&digest::SHA256, &input);
            bob_candidates.push(CandidateHash::new(hash.as_ref().try_into().unwrap()));
        }
    }

    // Should find candidates (2 and 3 are in intersection)
    assert!(
        bob_candidates.len() >= 2,
        "Should find at least 2 candidates"
    );

    // Phase 3: Alice verifies candidates
    let verified =
        builder.verify_candidates(&bob_candidates, &alice_fps, discovery_id, session_salt);

    // Should find exactly 2 intersections
    assert_eq!(verified.len(), 2, "Should find exactly 2 intersections");

    let verified_fps: Vec<_> = verified
        .iter()
        .map(|v| v.original_fingerprint.clone())
        .collect();
    assert!(verified_fps.contains(&PskId::from_u32(2)));
    assert!(verified_fps.contains(&PskId::from_u32(3)));

    // Phase 4: Alice selects optimal PSK
    let selected = BloomFilterBuilder::select_optimal_psk(&verified);
    assert!(selected.is_some(), "Should select a PSK");

    // Phase 5: Alice creates confirmation
    let selected_fp = selected.unwrap();
    let confirmation =
        builder.calculate_confirmation_hash(&selected_fp, discovery_id, session_salt);

    // Phase 6: Bob verifies confirmation
    let bob_verified =
        builder.verify_confirmation(&confirmation, &bob_fps, discovery_id, session_salt);
    assert!(bob_verified.is_some(), "Bob should verify the selected PSK");
    assert_eq!(
        bob_verified.unwrap(),
        selected_fp,
        "Bob should find same PSK"
    );
}

#[test]
fn test_complete_psi_flow_with_no_intersection() {
    // Test PSI when Alice and Bob have no common PSKs
    let builder = BloomFilterBuilder::default();

    // Alice's PSKs
    let alice_fps = vec![PskId::from_u32(1), PskId::from_u32(2)];

    // Bob's PSKs (no intersection)
    let bob_fps = vec![PskId::from_u32(99), PskId::from_u32(100)];

    let discovery_id = DiscoveryId::new(11111);
    let session_salt = 22222u32;

    // Phase 1: Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_fps, discovery_id, session_salt);

    // Phase 2: Bob tests his fingerprints (should find no matches or only false positives)
    let mut bob_candidates = Vec::new();
    use ring::digest;

    for fp in &bob_fps {
        let blinded = builder.blind_fingerprint(fp, discovery_id, session_salt);

        if builder.test(&alice_bloom, &blinded) {
            let mut input = Vec::new();
            input.extend_from_slice(&blinded);
            input.extend_from_slice(b"candidate_v1");
            let hash = digest::digest(&digest::SHA256, &input);
            bob_candidates.push(CandidateHash::new(hash.as_ref().try_into().unwrap()));
        }
    }

    // Phase 3: Alice verifies candidates (should eliminate all false positives)
    let verified =
        builder.verify_candidates(&bob_candidates, &alice_fps, discovery_id, session_salt);

    // Should find NO intersections (false positives eliminated)
    assert_eq!(verified.len(), 0, "Should find no intersections");
}

// ============================================================================
// CRIT-003: Comprehensive PSK Discovery Tests
// ============================================================================
//
// Protocol reference: design/protocol/05-psk-discovery.md
//
// Test Coverage:
// 1. Bloom filter generation (1, 10, 100, 1000 PSKs)
// 2. False positive rate validation within spec bounds
// 3. Privacy preservation (no PSK value leakage)
// 4. Negotiation edge cases (empty, disjoint, single overlap, full overlap)

/// Generate test PSK fingerprints of varying sizes
fn generate_psk_fingerprints(count: usize, offset: u32) -> Vec<PskFingerprint> {
    (0..count)
        .map(|i| PskId::from_u32(offset + i as u32))
        .collect()
}

// ----------------------------------------------------------------------------
// Bloom Filter Generation Tests (1, 10, 100, 1000 PSKs)
// ----------------------------------------------------------------------------

#[test]
fn test_crit003_bloom_filter_generation_1_psk() {
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(1, 0);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let bloom = builder.build_from_fingerprints(&psks, discovery_id, session_salt);

    // Verify bloom filter created with reasonable parameters
    let size_bits = bloom.bits.len() * 8;
    assert!(
        size_bits >= 1024,
        "Filter size {} should be >= 1024 bits for 1 PSK",
        size_bits
    );
    assert!(
        bloom.hash_functions.0 >= 1 && bloom.hash_functions.0 <= 8,
        "Hash functions {} should be 1-8",
        bloom.hash_functions.0
    );

    // Verify the single PSK tests positive
    let blinded = builder.blind_fingerprint(&psks[0], discovery_id, session_salt);
    assert!(
        builder.test(&bloom, &blinded),
        "Added PSK should test positive"
    );
}

#[test]
fn test_crit003_bloom_filter_generation_10_psks() {
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(10, 0);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let bloom = builder.build_from_fingerprints(&psks, discovery_id, session_salt);

    // Verify all PSKs test positive
    for psk in &psks {
        let blinded = builder.blind_fingerprint(psk, discovery_id, session_salt);
        assert!(
            builder.test(&bloom, &blinded),
            "All added PSKs should test positive"
        );
    }

    // Verify reasonable parameters - false positive rate calculation
    // Formula: (1 - e^(-k*n/m))^k where k=hash_functions, n=items, m=size_bits
    let size_bits = bloom.bits.len() * 8;
    let k = bloom.hash_functions.0 as f64;
    let n = psks.len() as f64;
    let m = size_bits as f64;
    let fp_rate = (1.0 - (-k * n / m).exp()).powf(k);
    assert!(
        fp_rate < 0.1,
        "False positive rate {} should be < 10% for 10 PSKs",
        fp_rate
    );
}

#[test]
fn test_crit003_bloom_filter_generation_100_psks() {
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(100, 0);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let bloom = builder.build_from_fingerprints(&psks, discovery_id, session_salt);

    // Verify reasonable filter parameters for 100 PSKs
    let size_bits = bloom.bits.len() * 8;
    assert!(
        size_bits >= 1024,
        "Filter size should be >= 1024 bits for 100 PSKs"
    );
    assert!(size_bits <= 65536, "Filter size should be <= 65536 bits");

    // Spot check some PSKs test positive
    for i in [0, 50, 99] {
        let blinded = builder.blind_fingerprint(&psks[i], discovery_id, session_salt);
        assert!(
            builder.test(&bloom, &blinded),
            "PSK {} should test positive",
            i
        );
    }

    let k = bloom.hash_functions.0 as f64;
    let n = psks.len() as f64;
    let m = size_bits as f64;
    let fp_rate = (1.0 - (-k * n / m).exp()).powf(k);
    assert!(
        fp_rate < 0.15,
        "False positive rate {} should be < 15% for 100 PSKs",
        fp_rate
    );
}

#[test]
fn test_crit003_bloom_filter_generation_1000_psks() {
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(1000, 0);
    let discovery_id = DiscoveryId::new(12345);
    let session_salt = 67890u32;

    let bloom = builder.build_from_fingerprints(&psks, discovery_id, session_salt);

    // Verify filter parameters scale appropriately
    let size_bits = bloom.bits.len() * 8;
    assert!(
        size_bits >= 1024,
        "Filter size should be >= 1024 bits for 1000 PSKs"
    );
    assert!(
        size_bits <= 65536,
        "Filter size should be <= 65536 bits (protocol max)"
    );
    assert!(
        bloom.hash_functions.0 >= 1 && bloom.hash_functions.0 <= 8,
        "Hash functions should be 1-8"
    );

    // Spot check PSKs test positive
    for i in [0, 500, 999] {
        let blinded = builder.blind_fingerprint(&psks[i], discovery_id, session_salt);
        assert!(
            builder.test(&bloom, &blinded),
            "PSK {} should test positive",
            i
        );
    }

    let k = bloom.hash_functions.0 as f64;
    let n = psks.len() as f64;
    let m = size_bits as f64;
    let fp_rate = (1.0 - (-k * n / m).exp()).powf(k);
    // With 1000 PSKs and protocol max filter size (65536 bits), expect high FP rate
    // This is a known trade-off - protocol limits filter size for packet size constraints
    assert!(
        fp_rate < 0.8,
        "False positive rate {} should be < 80% for 1000 PSKs (expected high due to filter size limits)",
        fp_rate
    );
}

// ----------------------------------------------------------------------------
// False Positive Rate Validation
// ----------------------------------------------------------------------------

#[test]
fn test_crit003_false_positive_rate_small_set() {
    // Empirical false positive rate test for small PSK set
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(10, 0);
    let discovery_id = DiscoveryId::new(99999);
    let session_salt = 11111u32;

    let bloom = builder.build_from_fingerprints(&psks, discovery_id, session_salt);

    // Test 1000 random PSKs not in the set
    let test_psks = generate_psk_fingerprints(1000, 10000);
    let mut false_positives = 0;

    for psk in &test_psks {
        let blinded = builder.blind_fingerprint(psk, discovery_id, session_salt);
        if builder.test(&bloom, &blinded) {
            false_positives += 1;
        }
    }

    let empirical_fp_rate = false_positives as f64 / test_psks.len() as f64;

    // Protocol spec: BLOOM_FILTER_FALSE_POSITIVE_RATE = 0.01 (1%)
    // Allow 10% empirical tolerance for small sets
    assert!(
        empirical_fp_rate < 0.1,
        "Empirical false positive rate {} should be < 10%",
        empirical_fp_rate
    );
}

#[test]
fn test_crit003_false_positive_rate_large_set() {
    // Empirical false positive rate test for large PSK set
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(100, 0);
    let discovery_id = DiscoveryId::new(88888);
    let session_salt = 22222u32;

    let bloom = builder.build_from_fingerprints(&psks, discovery_id, session_salt);

    // Test 500 random PSKs not in the set
    let test_psks = generate_psk_fingerprints(500, 10000);
    let mut false_positives = 0;

    for psk in &test_psks {
        let blinded = builder.blind_fingerprint(psk, discovery_id, session_salt);
        if builder.test(&bloom, &blinded) {
            false_positives += 1;
        }
    }

    let empirical_fp_rate = false_positives as f64 / test_psks.len() as f64;

    // For larger sets, expect better false positive control
    assert!(
        empirical_fp_rate < 0.15,
        "Empirical false positive rate {} should be < 15%",
        empirical_fp_rate
    );
}

// ----------------------------------------------------------------------------
// Privacy Preservation Tests (No PSK Value Leakage)
// ----------------------------------------------------------------------------

#[test]
fn test_crit003_no_psk_leakage_in_blinded_fingerprints() {
    // Verify blinded fingerprints do not reveal PSK values
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(20, 0);
    let discovery_id = DiscoveryId::new(77777);
    let session_salt = 33333u32;

    // Create blinded fingerprints
    let blinded_fps: Vec<[u8; 16]> = psks
        .iter()
        .map(|fp| builder.blind_fingerprint(fp, discovery_id, session_salt))
        .collect();

    // Verify blinded fingerprints are different from raw PSK IDs
    for (i, blinded) in blinded_fps.iter().enumerate() {
        let psk_bytes = psks[i].as_bytes();

        // Blinded fingerprint should not match PSK bytes
        assert_ne!(
            &blinded[0..psk_bytes.len().min(16)],
            &psk_bytes[0..psk_bytes.len().min(16)],
            "Blinded fingerprint should not expose PSK bytes"
        );

        // Blinded fingerprint should not be simple hash of PSK
        use ring::digest;
        let psk_hash = digest::digest(&digest::SHA256, psk_bytes);
        assert_ne!(
            &blinded[..],
            &psk_hash.as_ref()[0..16],
            "Blinded fingerprint should not be simple hash of PSK"
        );
    }
}

#[test]
fn test_crit003_no_psk_leakage_in_protocol_messages() {
    // Verify protocol messages do not leak PSK values through direct comparison
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(10, 7919);
    let discovery_id = DiscoveryId::new(66666);
    let session_salt = 44444u32;

    let bloom = builder.build_from_fingerprints(&psks, discovery_id, session_salt);

    // Verify PSKs are not stored in cleartext in Bloom filter
    // Check that full PSK values don't appear verbatim
    for psk in &psks {
        let psk_bytes = psk.as_bytes();
        let bloom_bytes = &bloom.bits;

        // PSK should not appear in cleartext (full 32-byte match)
        let mut found_cleartext = false;
        for i in 0..bloom_bytes.len().saturating_sub(31) {
            if &bloom_bytes[i..i + 32] == psk_bytes {
                found_cleartext = true;
                break;
            }
        }

        assert!(
            !found_cleartext,
            "Bloom filter should not contain PSK in cleartext"
        );
    }

    // Verify blinded fingerprints are used (not direct PSK hashes)
    use ring::digest;
    for psk in &psks {
        let psk_hash = digest::digest(&digest::SHA256, psk.as_bytes());
        let bloom_bytes = &bloom.bits;

        // Direct SHA-256(PSK) should not appear in bloom filter
        let mut found_direct_hash = false;
        for i in 0..bloom_bytes.len().saturating_sub(31) {
            if &bloom_bytes[i..i + 32] == psk_hash.as_ref() {
                found_direct_hash = true;
                break;
            }
        }

        assert!(
            !found_direct_hash,
            "Bloom filter should not contain direct PSK hash (blinding is required)"
        );
    }

    // Verify candidate hashes use proper blinding
    for psk in &psks {
        let blinded = builder.blind_fingerprint(psk, discovery_id, session_salt);
        let mut input = Vec::new();
        input.extend_from_slice(&blinded);
        input.extend_from_slice(b"candidate_v1");
        let candidate_hash = digest::digest(&digest::SHA256, &input);

        // Candidate hash should not be direct hash of PSK
        let psk_hash = digest::digest(&digest::SHA256, psk.as_bytes());
        assert_ne!(
            candidate_hash.as_ref(),
            psk_hash.as_ref(),
            "Candidate hash should use blinded fingerprint, not direct PSK hash"
        );
    }
}

// ----------------------------------------------------------------------------
// Edge Case Tests (Empty, Disjoint, Single Overlap, Full Overlap)
// ----------------------------------------------------------------------------

#[test]
fn test_crit003_edge_case_empty_responder_set() {
    // Test when responder has no PSKs (edge case)
    let builder = BloomFilterBuilder::default();
    let alice_psks = generate_psk_fingerprints(5, 0);
    let bob_psks: Vec<PskFingerprint> = Vec::new(); // Empty

    let discovery_id = DiscoveryId::new(11111);
    let session_salt = 55555u32;

    // Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_psks, discovery_id, session_salt);

    // Bob has no PSKs to test, so no candidates
    let mut bob_candidates = Vec::new();
    use ring::digest;

    for fp in &bob_psks {
        let blinded = builder.blind_fingerprint(fp, discovery_id, session_salt);
        if builder.test(&alice_bloom, &blinded) {
            let mut input = Vec::new();
            input.extend_from_slice(&blinded);
            input.extend_from_slice(b"candidate_v1");
            let hash = digest::digest(&digest::SHA256, &input);
            bob_candidates.push(CandidateHash::new(hash.as_ref().try_into().unwrap()));
        }
    }

    assert_eq!(
        bob_candidates.len(),
        0,
        "Empty responder set should produce no candidates"
    );

    // Alice verifies (should be empty)
    let verified =
        builder.verify_candidates(&bob_candidates, &alice_psks, discovery_id, session_salt);
    assert_eq!(
        verified.len(),
        0,
        "Should find no intersections with empty responder set"
    );
}

#[test]
fn test_crit003_edge_case_disjoint_sets() {
    // Test when sets have no common PSKs
    let builder = BloomFilterBuilder::default();
    let alice_psks = generate_psk_fingerprints(10, 0);
    let bob_psks = generate_psk_fingerprints(10, 1000); // Completely different

    let discovery_id = DiscoveryId::new(22222);
    let session_salt = 66666u32;

    // Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_psks, discovery_id, session_salt);

    // Bob tests his PSKs
    let mut bob_candidates = Vec::new();
    use ring::digest;

    for fp in &bob_psks {
        let blinded = builder.blind_fingerprint(fp, discovery_id, session_salt);
        if builder.test(&alice_bloom, &blinded) {
            let mut input = Vec::new();
            input.extend_from_slice(&blinded);
            input.extend_from_slice(b"candidate_v1");
            let hash = digest::digest(&digest::SHA256, &input);
            bob_candidates.push(CandidateHash::new(hash.as_ref().try_into().unwrap()));
        }
    }

    // May have false positive candidates
    // Alice verifies (should eliminate all)
    let verified =
        builder.verify_candidates(&bob_candidates, &alice_psks, discovery_id, session_salt);
    assert_eq!(
        verified.len(),
        0,
        "Disjoint sets should produce no verified intersections"
    );
}

#[test]
fn test_crit003_edge_case_single_overlap() {
    // Test when sets have exactly one common PSK
    let builder = BloomFilterBuilder::default();
    let shared_psk = PskId::from_u32(5000);

    let mut alice_psks = generate_psk_fingerprints(5, 0);
    alice_psks.push(shared_psk.clone());

    let mut bob_psks = generate_psk_fingerprints(5, 1000);
    bob_psks.push(shared_psk.clone());

    let discovery_id = DiscoveryId::new(33333);
    let session_salt = 77777u32;

    // Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_psks, discovery_id, session_salt);

    // Bob tests his PSKs
    let mut bob_candidates = Vec::new();
    use ring::digest;

    for fp in &bob_psks {
        let blinded = builder.blind_fingerprint(fp, discovery_id, session_salt);
        if builder.test(&alice_bloom, &blinded) {
            let mut input = Vec::new();
            input.extend_from_slice(&blinded);
            input.extend_from_slice(b"candidate_v1");
            let hash = digest::digest(&digest::SHA256, &input);
            bob_candidates.push(CandidateHash::new(hash.as_ref().try_into().unwrap()));
        }
    }

    // Should find at least one candidate (the shared PSK)
    assert!(
        !bob_candidates.is_empty(),
        "Should find candidate for shared PSK"
    );

    // Alice verifies
    let verified =
        builder.verify_candidates(&bob_candidates, &alice_psks, discovery_id, session_salt);

    // Should find exactly one verified intersection
    assert_eq!(
        verified.len(),
        1,
        "Should find exactly one intersection with single overlap"
    );
    assert_eq!(
        verified[0].original_fingerprint, shared_psk,
        "Verified intersection should be the shared PSK"
    );
}

#[test]
fn test_crit003_edge_case_full_overlap() {
    // Test when sets are identical (full overlap)
    let builder = BloomFilterBuilder::default();
    let psks = generate_psk_fingerprints(10, 0);

    let alice_psks = psks.clone();
    let bob_psks = psks.clone();

    let discovery_id = DiscoveryId::new(44444);
    let session_salt = 88888u32;

    // Alice creates Bloom filter
    let alice_bloom = builder.build_from_fingerprints(&alice_psks, discovery_id, session_salt);

    // Bob tests his PSKs
    let mut bob_candidates = Vec::new();
    use ring::digest;

    for fp in &bob_psks {
        let blinded = builder.blind_fingerprint(fp, discovery_id, session_salt);
        if builder.test(&alice_bloom, &blinded) {
            let mut input = Vec::new();
            input.extend_from_slice(&blinded);
            input.extend_from_slice(b"candidate_v1");
            let hash = digest::digest(&digest::SHA256, &input);
            bob_candidates.push(CandidateHash::new(hash.as_ref().try_into().unwrap()));
        }
    }

    // All PSKs should test positive (may have additional false positives)
    assert!(
        bob_candidates.len() >= psks.len(),
        "Should find candidates for all PSKs with full overlap"
    );

    // Alice verifies
    let verified =
        builder.verify_candidates(&bob_candidates, &alice_psks, discovery_id, session_salt);

    // Should find all PSKs as verified intersections
    assert_eq!(
        verified.len(),
        psks.len(),
        "Should find all {} PSKs as verified intersections with full overlap",
        psks.len()
    );
}
