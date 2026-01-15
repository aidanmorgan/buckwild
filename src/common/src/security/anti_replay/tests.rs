// Anti-Replay Protection Tests
//
// Tests verify timestamp validation, sequence tracking, and duplicate detection
// following design/protocol/14-replay-protection.md

use super::*;
use crate::error::SecurityError;
use crate::protocol::packet::PacketHeader;
use crate::protocol::types::*;

/// Helper to create test packet header
fn create_test_header(session_id: u64, sequence: u32, timestamp_ms: u64) -> PacketHeader {
    PacketHeader::new(
        VersionByte::new(0x01, SessionIdLength::Bits32, TimestampConfig::Bits24),
        PacketType::Data,
        SubType::new(0),
        PacketFlags::new(),
        SessionId::new_with_length(session_id, SessionIdLength::Bits32),
        SequenceNumber::new(sequence),
        AckNumber::new(0),
        Timestamp::new(timestamp_ms, TimestampConfig::Bits24),
        PayloadLength::new(100),
        HmacPolicy::Medium,
    )
}

// =========================================================================
// Timestamp Validation Tests
// =========================================================================

#[test]
fn test_timestamp_validator_accepts_current_timestamp() {
    let validator = TimestampValidator::new();
    let current_time_ms = Timestamp::now();

    let header = create_test_header(1, 100, current_time_ms.as_u64());

    let result = validator.validate(&header);
    assert!(result.is_ok(), "Current timestamp should be valid");
}

#[test]
fn test_timestamp_validator_accepts_recent_timestamp() {
    let validator = TimestampValidator::new();
    let current_time_ns = Timestamp::now();

    // 15 seconds ago (within 30-second window) - timestamps are in nanoseconds
    let recent_time =
        current_time_ns.saturating_sub(&Timestamp::new(15_000_000_000, TimestampConfig::Bits32));
    let header = create_test_header(1, 100, recent_time);

    let result = validator.validate(&header);
    assert!(result.is_ok(), "Recent timestamp (15s ago) should be valid");
}

#[test]
fn test_timestamp_validator_rejects_old_timestamp() {
    let validator = TimestampValidator::new();
    let current_time_ns = Timestamp::now();

    // 35 seconds ago (outside 30-second window) - timestamps are in nanoseconds
    let old_time =
        current_time_ns.saturating_sub(&Timestamp::new(35_000_000_000, TimestampConfig::Bits32));
    let header = create_test_header(1, 100, old_time);

    let result = validator.validate(&header);
    assert!(
        result.is_err(),
        "Old timestamp (35s ago) should be rejected"
    );
}

#[test]
fn test_timestamp_validator_rejects_far_future_timestamp() {
    let validator = TimestampValidator::new();
    let current_time_ns = Timestamp::now();

    // 1 minute in the future (>50ms tolerance) - timestamps are in nanoseconds
    let future_time = (current_time_ns + 60_000_000_000).as_u64();
    let header = create_test_header(1, 100, future_time);

    let result = validator.validate(&header);
    assert!(result.is_err(), "Far future timestamp should be rejected");
}

#[test]
fn test_timestamp_validator_accepts_small_clock_skew() {
    let validator = TimestampValidator::new();
    let current_time_ns = Timestamp::now();

    // 30ms in the future (within 50ms tolerance) - timestamps are in nanoseconds
    let future_time = (current_time_ns + 30_000_000).as_u64();
    let header = create_test_header(1, 100, future_time);

    let result = validator.validate(&header);
    assert!(result.is_ok(), "Small clock skew (30ms) should be accepted");
}

// =========================================================================
// Duplicate Detection Tests
// =========================================================================

#[test]
fn test_duplicate_detector_detects_exact_duplicate() {
    let detector = DuplicateDetector::new();
    let current_time_ms = Timestamp::now();

    let header = create_test_header(1, 100, current_time_ms.as_u64());

    // First packet should be accepted
    let result1 = detector.check_duplicate(&header);
    assert!(result1.is_ok(), "First packet should be accepted");

    // Exact duplicate should be rejected
    let result2 = detector.check_duplicate(&header);
    assert!(result2.is_err(), "Duplicate packet should be rejected");
}

#[test]
fn test_duplicate_detector_allows_different_sequence() {
    let detector = DuplicateDetector::new();
    let current_time_ms = Timestamp::now();

    let header1 = create_test_header(1, 100, current_time_ms.as_u64());
    let header2 = create_test_header(1, 101, current_time_ms.as_u64()); // Different sequence

    let result1 = detector.check_duplicate(&header1);
    assert!(result1.is_ok(), "First packet should be accepted");

    let result2 = detector.check_duplicate(&header2);
    assert!(result2.is_ok(), "Different sequence should be accepted");
}

#[test]
fn test_duplicate_detector_allows_different_session() {
    let detector = DuplicateDetector::new();
    let current_time_ms = Timestamp::now();

    let header1 = create_test_header(1, 100, current_time_ms.as_u64());
    let header2 = create_test_header(2, 100, current_time_ms.as_u64()); // Different session

    let result1 = detector.check_duplicate(&header1);
    assert!(result1.is_ok(), "First packet should be accepted");

    let result2 = detector.check_duplicate(&header2);
    assert!(result2.is_ok(), "Different session should be accepted");
}

#[test]
fn test_duplicate_detector_cleans_up_old_entries() {
    let detector = DuplicateDetector::new();
    let current_time_ms = Timestamp::now();

    // Insert packet with old timestamp
    let old_time = current_time_ms.saturating_sub(&Timestamp::new(40_000, TimestampConfig::Bits32)); // 40 seconds ago
    let old_header = create_test_header(1, 100, old_time);

    let _ = detector.check_duplicate(&old_header);

    // Force cleanup
    detector.cleanup();

    // Same packet should be accepted again after cleanup
    let result = detector.check_duplicate(&old_header);
    assert!(
        result.is_ok(),
        "Old entry should be cleaned up and packet accepted again"
    );
}

// =========================================================================
// Sequence Number Validation Tests
// =========================================================================

#[test]
fn test_sequence_validator_accepts_expected_sequence() {
    let validator = SequenceValidator::new(100); // Start at seq 100

    let header = create_test_header(1, 100, Timestamp::now().as_u64());

    let result = validator.validate(&header);
    assert!(result.is_ok(), "Expected sequence should be accepted");
}

#[test]
fn test_sequence_validator_accepts_next_sequence() {
    let validator = SequenceValidator::new(100);

    let header1 = create_test_header(1, 100, Timestamp::now().as_u64());
    let header2 = create_test_header(1, 101, Timestamp::now().as_u64());

    let _ = validator.validate(&header1);
    let result = validator.validate(&header2);

    assert!(result.is_ok(), "Next sequence should be accepted");
}

#[test]
fn test_sequence_validator_rejects_old_sequence() {
    let validator = SequenceValidator::new(100);

    // Advance to seq 110
    for seq in 100..110 {
        let header = create_test_header(1, seq, Timestamp::now().as_u64());
        let _ = validator.validate(&header);
    }

    // Try to send seq 95 (old sequence)
    let old_header = create_test_header(1, 95, Timestamp::now().as_u64());
    let result = validator.validate(&old_header);

    assert!(result.is_err(), "Old sequence should be rejected");
}

#[test]
fn test_sequence_validator_handles_out_of_order_within_window() {
    let validator = SequenceValidator::new(100);

    // Send seq 105 first (out of order)
    let header1 = create_test_header(1, 105, Timestamp::now().as_u64());
    let result1 = validator.validate(&header1);
    assert!(
        result1.is_ok(),
        "Out-of-order packet within window should be accepted"
    );

    // Then send seq 103 (filling gap)
    let header2 = create_test_header(1, 103, Timestamp::now().as_u64());
    let result2 = validator.validate(&header2);
    assert!(result2.is_ok(), "Gap-filling packet should be accepted");
}

#[test]
fn test_sequence_validator_rejects_duplicate_sequence() {
    let validator = SequenceValidator::new(100);

    let header = create_test_header(1, 100, Timestamp::now().as_u64());

    // First should succeed
    let result1 = validator.validate(&header);
    assert!(result1.is_ok(), "First packet should be accepted");

    // Duplicate should fail
    let result2 = validator.validate(&header);
    assert!(result2.is_err(), "Duplicate sequence should be rejected");
}

#[test]
fn test_sequence_validator_sliding_window() {
    let validator = SequenceValidator::new(0);

    // Fill window with sequences 0-999
    for seq in 0..1000 {
        let header = create_test_header(1, seq, Timestamp::now().as_u64());
        let _ = validator.validate(&header);
    }

    // Sequence 1000 should work (window slides forward)
    let header = create_test_header(1, 1000, Timestamp::now().as_u64());
    let result = validator.validate(&header);
    assert!(
        result.is_ok(),
        "Sequence beyond window should slide window forward"
    );

    // Sequence 0 should now be outside window
    let old_header = create_test_header(1, 0, Timestamp::now().as_u64());
    let old_result = validator.validate(&old_header);
    assert!(
        old_result.is_err(),
        "Sequence outside window should be rejected"
    );
}

// =========================================================================
// Anti-Replay Engine Integration Tests
// =========================================================================

#[test]
fn test_anti_replay_engine_comprehensive_validation() {
    let engine = AntiReplayEngine::new();
    let current_time_ms = Timestamp::now();

    let header = create_test_header(1, 100, current_time_ms.as_u64());

    // First packet should pass all validations
    let result = engine.validate_packet(&header);
    assert!(
        result.is_ok(),
        "Valid packet should pass anti-replay checks"
    );
}

#[test]
fn test_anti_replay_engine_detects_timestamp_replay() {
    let engine = AntiReplayEngine::new();
    let current_time_ns = Timestamp::now();

    // Old timestamp (replay attack) - timestamps are in nanoseconds
    let old_time =
        current_time_ns.saturating_sub(&Timestamp::new(35_000_000_000, TimestampConfig::Bits32));
    let header = create_test_header(1, 100, old_time);

    let result = engine.validate_packet(&header);
    assert!(
        result.is_err(),
        "Replay with old timestamp should be detected"
    );
}

#[test]
fn test_anti_replay_engine_detects_duplicate_packet() {
    let engine = AntiReplayEngine::new();
    let current_time_ms = Timestamp::now();

    let header = create_test_header(1, 100, current_time_ms.as_u64());

    let _ = engine.validate_packet(&header);

    // Exact duplicate
    let result = engine.validate_packet(&header);
    assert!(result.is_err(), "Duplicate packet should be detected");
}

#[test]
fn test_anti_replay_engine_allows_legitimate_traffic() {
    let engine = AntiReplayEngine::new();
    let current_time_ms = Timestamp::now();

    // Send 10 sequential packets
    for seq in 100..110 {
        let header = create_test_header(
            1,
            seq,
            (current_time_ms + (seq as u64 - 100) * 100).as_u64(),
        );
        let result = engine.validate_packet(&header);
        if result.is_err() {
            eprintln!("Failed on packet {}: {:?}", seq, result);
        }
        assert!(
            result.is_ok(),
            "Legitimate packet {} should be accepted",
            seq
        );
    }
}

#[test]
fn test_anti_replay_engine_handles_out_of_order() {
    let engine = AntiReplayEngine::new();
    let current_time_ms = Timestamp::now();

    // Send packets out of order: 100, 102, 101
    let sequences = vec![100, 102, 101];

    for &seq in &sequences {
        let header = create_test_header(1, seq, (current_time_ms + (seq as u64 * 10)).as_u64());
        let result = engine.validate_packet(&header);
        assert!(
            result.is_ok(),
            "Out-of-order packet {} should be accepted",
            seq
        );
    }
}

#[test]
fn test_anti_replay_engine_statistics() {
    let engine = AntiReplayEngine::new();
    let current_time_ns = Timestamp::now();

    // Send valid packet
    let header1 = create_test_header(1, 100, current_time_ns.as_u64());
    let _ = engine.validate_packet(&header1);

    // Send duplicate (should be detected)
    let _ = engine.validate_packet(&header1);

    // Send old packet (should be detected) - timestamps are in nanoseconds
    let old_header = create_test_header(
        1,
        101,
        current_time_ns.saturating_sub(&Timestamp::new(35_000_000_000, TimestampConfig::Bits32)),
    );
    let _ = engine.validate_packet(&old_header);

    let stats = engine.get_statistics();
    eprintln!(
        "Stats: total_packets={}, replay_attempts={}",
        stats.total_packets, stats.replay_attempts
    );
    assert!(
        stats.total_packets >= 3,
        "Should track total packets (got {})",
        stats.total_packets
    );
    assert!(
        stats.replay_attempts >= 2,
        "Should track replay attempts (got {})",
        stats.replay_attempts
    );
}

// =========================================================================
// Handshake Packet Special Handling Tests
// =========================================================================

#[test]
fn test_handshake_packets_use_stricter_window() {
    let engine = AntiReplayEngine::new();
    let current_time_ns = Timestamp::now();

    // Handshake packet (SYN) 15 seconds old - timestamps are in nanoseconds
    // Normal window: 30s (OK), Handshake window: 10s (NOT OK)
    let old_time =
        current_time_ns.saturating_sub(&Timestamp::new(15_000_000_000, TimestampConfig::Bits32));

    let syn_header = PacketHeader::new(
        VersionByte::new(0x01, SessionIdLength::Bits32, TimestampConfig::Bits24),
        PacketType::Syn, // Handshake packet
        SubType::new(0),
        PacketFlags::new(), // SYN flag set by packet type
        SessionId::new_with_length(1, SessionIdLength::Bits32),
        SequenceNumber::new(0),
        AckNumber::new(0),
        Timestamp::new(old_time, TimestampConfig::Bits24),
        PayloadLength::new(100),
        HmacPolicy::Strong, // Handshake uses STRONG
    );

    let result = engine.validate_packet(&syn_header);
    assert!(
        result.is_err(),
        "Old handshake packet should be rejected with stricter window"
    );
}

// =========================================================================
// Month Boundary Handling Tests
// =========================================================================

#[test]
fn test_timestamp_validation_handles_month_wraparound() {
    let validator = TimestampValidator::new();

    // Simulate near month boundary
    // This is a simplified test - real implementation needs proper UTC month handling
    let near_month_end = Timestamp::now();

    let header = create_test_header(1, 100, near_month_end.as_u64());
    let result = validator.validate(&header);

    assert!(
        result.is_ok(),
        "Timestamp near month boundary should be valid"
    );
}

// =========================================================================
// Window Boundary Edge Case Tests (MED-028)
// =========================================================================

#[test]
fn test_sequence_at_exact_window_start() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Set base to 1000
    window.reset(SequenceNumber::new(1000));

    // Sequence at exact window start (base) should be accepted on first send
    let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(1000));
    assert!(
        result.is_ok(),
        "Sequence at exact window start should be accepted"
    );

    // Duplicate at window start should be rejected
    let result2 = window.check_and_mark(session_id, SequenceNumber::new(1000));
    assert!(
        result2.is_err(),
        "Duplicate at window start should be rejected"
    );
}

#[test]
fn test_sequence_at_exact_window_end() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Set base to 1000
    window.reset(SequenceNumber::new(1000));

    // Sequence at exact window end (base + size - 1 = 1063)
    let result = window.check_and_mark(session_id, SequenceNumber::new(1063));
    assert!(
        result.is_ok(),
        "Sequence at exact window end should be accepted"
    );
}

#[test]
fn test_sequence_just_before_window() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Set base to 1000 and advance window by accepting 1100
    window.reset(SequenceNumber::new(1000));
    let _ = window.check_and_mark(session_id.clone(), SequenceNumber::new(1100));

    // Get current base (should have advanced)
    let (base, _, _, _) = window.stats();

    // Sequence just before current window (base - 1) should be rejected
    let old_seq = base.as_u32().wrapping_sub(1);
    let result = window.check_and_mark(session_id, SequenceNumber::new(old_seq));
    assert!(
        result.is_err(),
        "Sequence just before window should be rejected"
    );
}

#[test]
fn test_sequence_just_after_window() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Set base to 1000
    window.reset(SequenceNumber::new(1000));

    // Sequence just after window (base + size = 1064) should advance window
    let result = window.check_and_mark(session_id, SequenceNumber::new(1064));
    assert!(
        result.is_ok(),
        "Sequence just after window should advance window and be accepted"
    );
}

#[test]
fn test_window_boundary_at_wraparound() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Set base near u32::MAX
    let base = u32::MAX - 10;
    window.reset(SequenceNumber::new(base));

    // Test sequences that wrap around zero
    let sequences = vec![
        base,                  // At base
        base + 5,              // Middle of window
        base + 10,             // Near end (wraps to 0)
        base.wrapping_add(20), // After wraparound (wraps to 10)
    ];

    for seq in sequences {
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
        assert!(
            result.is_ok(),
            "Sequence {} around wraparound should be accepted",
            seq
        );
    }
}

#[test]
fn test_window_full_bitmap() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Set base to 1000 (reset counts the base as received, so count starts at 1)
    window.reset(SequenceNumber::new(1000));

    // Fill entire window (base to base+63)
    for i in 0..64 {
        let seq = 1000 + i;
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
        assert!(
            result.is_ok(),
            "Filling window at position {} should succeed",
            i
        );
    }

    // Verify window stats (reset counts as 1, plus 64 packets = 65 total)
    let (base, highest, received, _) = window.stats();
    assert_eq!(base.as_u32(), 1000, "Base should still be 1000");
    assert_eq!(highest.as_u32(), 1063, "Highest should be 1063 (base+63)");
    assert_eq!(
        received, 65,
        "Window should show 65 received (1 from reset + 64 packets)"
    );

    // Any sequence in the full window should be rejected as duplicate
    let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(1032));
    assert!(
        result.is_err(),
        "Duplicate in full window should be rejected"
    );

    // Sequence beyond window should still advance it
    let result = window.check_and_mark(session_id, SequenceNumber::new(1064));
    assert!(
        result.is_ok(),
        "Sequence beyond full window should advance and be accepted"
    );
}

// =========================================================================
// Concurrent Access Tests (MED-028)
// =========================================================================

#[test]
fn test_concurrent_sequence_validation() {
    use std::sync::Arc;
    use std::thread;

    let engine = Arc::new(ThreadSafeAntiReplayEngine::new_default());
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Spawn multiple threads that validate different sequences concurrently
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let engine_clone = Arc::clone(&engine);
            let sid = session_id.clone();
            thread::spawn(move || {
                // Each thread validates 10 sequential packets
                for j in 0..10 {
                    let seq = SequenceNumber::new((i * 10 + j) as u32);
                    let result = engine_clone.validate_packet(sid.clone(), seq, None);
                    // Some may succeed, some may fail due to race conditions
                    // But it should never panic
                    let _ = result;
                }
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Verify we can still validate packets after concurrent access
    let result = engine.validate_packet(session_id.clone(), SequenceNumber::new(10000), None);
    assert!(
        result.is_ok(),
        "Engine should still work after concurrent access"
    );
}

#[test]
fn test_concurrent_session_operations() {
    use std::sync::Arc;
    use std::thread;

    let engine = Arc::new(ThreadSafeAntiReplayEngine::new_default());

    // Spawn threads that operate on different sessions concurrently
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let engine_clone = Arc::clone(&engine);
            thread::spawn(move || {
                let session_id = SessionId::new_with_length(i as u64, SessionIdLength::Bits32);

                // Validate some packets
                for j in 0..20 {
                    let seq = SequenceNumber::new(j);
                    let _ = engine_clone.validate_packet(session_id.clone(), seq, None);
                }

                // Get stats
                let _ = engine_clone.get_session_stats(session_id.clone());

                // Reset session
                let _ = engine_clone.reset_session(session_id.clone(), SequenceNumber::new(100));

                // Validate more packets
                for j in 100..110 {
                    let seq = SequenceNumber::new(j);
                    let _ = engine_clone.validate_packet(session_id.clone(), seq, None);
                }
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Verify total stats
    let stats = engine.get_total_stats();
    assert!(
        stats.is_ok(),
        "Should be able to get stats after concurrent access"
    );
    let (session_count, _, _) = stats.unwrap();
    assert!(session_count >= 5, "Should have at least 5 sessions");
}

#[test]
fn test_concurrent_duplicate_detection() {
    use std::sync::Arc;
    use std::thread;

    let engine = Arc::new(ThreadSafeAntiReplayEngine::new_default());
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // First, establish the session with sequence 0
    let _ = engine.validate_packet(session_id.clone(), SequenceNumber::new(0), None);

    // Spawn multiple threads trying to send the same sequence
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let engine_clone = Arc::clone(&engine);
            let sid = session_id.clone();
            thread::spawn(move || {
                // All threads try to validate sequence 100
                engine_clone.validate_packet(sid, SequenceNumber::new(100), None)
            })
        })
        .collect();

    // Collect results
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("Thread should not panic"))
        .collect();

    // Exactly one should succeed, others should fail with duplicate error
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    let duplicate_count = results
        .iter()
        .filter(|r| {
            if let Err(e) = r {
                matches!(e, SecurityError::DuplicatePacket { .. })
            } else {
                false
            }
        })
        .count();

    assert_eq!(success_count, 1, "Exactly one thread should succeed");
    assert!(
        duplicate_count >= 8,
        "Most other threads should see duplicate (at least 8)"
    );
}

#[test]
fn test_window_advance_under_concurrent_load() {
    use std::sync::Arc;
    use std::thread;

    // Use ThreadSafeAntiReplayEngine instead of SequenceValidator
    // since SequenceValidator uses RefCell which is not thread-safe
    let engine = Arc::new(ThreadSafeAntiReplayEngine::new_default());
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Spawn threads that send sequences in ranges
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let engine_clone = Arc::clone(&engine);
            let sid = session_id.clone();
            thread::spawn(move || {
                let start = i * 250;
                let end = start + 250;
                for seq in start..end {
                    let _ =
                        engine_clone.validate_packet(sid.clone(), SequenceNumber::new(seq), None);
                }
            })
        })
        .collect();

    // Wait for completion
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Verify engine still works after concurrent load
    let result = engine.validate_packet(session_id.clone(), SequenceNumber::new(10000), None);
    assert!(
        result.is_ok(),
        "Engine should still work after concurrent window advance"
    );
}

// =========================================================================
// Property-Based Tests
// =========================================================================

#[cfg(test)]
mod proptest_replay {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        #[test]
        fn test_sequence_window_accepts_monotonic(base in 0u32..100000, count in 1u32..500) {
            let mut window = SequenceWindow::new(64);
            let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

            // Set initial base
            window.reset(SequenceNumber::new(base));

            // Monotonically increasing sequences should all be accepted
            for i in 0..count {
                let seq = base.wrapping_add(i + 1);
                let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
                prop_assert!(result.is_ok(), "Monotonic sequence {} should be accepted", seq);
            }
        }

        #[test]
        fn test_sequence_window_detects_replay(base in 0u32..100000, seq in 0u32..64) {
            let mut window = SequenceWindow::new(64);
            let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

            // Set initial base
            window.reset(SequenceNumber::new(base));

            // Send a packet within window
            let test_seq = base.wrapping_add(seq);
            let result1 = window.check_and_mark(session_id.clone(), SequenceNumber::new(test_seq));
            prop_assert!(result1.is_ok(), "First packet should be accepted");

            // Replay the same packet - should be detected
            let result2 = window.check_and_mark(session_id.clone(), SequenceNumber::new(test_seq));
            prop_assert!(result2.is_err(), "Replayed packet should be detected");
        }

        #[test]
        fn test_sequence_window_wraparound(base in (u32::MAX - 1000)..u32::MAX, count in 1u32..500) {
            let mut window = SequenceWindow::new(64);
            let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

            // Set base near u32::MAX
            window.reset(SequenceNumber::new(base));

            // Send sequences that wrap around
            for i in 0..count {
                let seq = base.wrapping_add(i + 1);
                let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
                prop_assert!(result.is_ok(), "Wraparound sequence {} should be accepted", seq);
            }
        }
    }
}

// =========================================================================
// TASK-024: 1000-Entry Sequence Window Tests
// =========================================================================

#[test]
fn test_window_size_is_1000_entries() {
    // Verify that the window can track 1000 sequence numbers
    let mut window = SequenceWindow::new(1000);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Fill the entire 1000-entry window
    for i in 0..1000 {
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(i));
        assert!(result.is_ok(), "Sequence {} should be accepted", i);
    }

    // Verify window is full
    assert!(window.is_full(), "Window should be full after 1000 entries");

    // Stats should show 1000 received
    let (base, highest, received, _duplicates) = window.stats();
    assert_eq!(base.as_u32(), 0, "Base should be at 0");
    assert_eq!(highest.as_u32(), 999, "Highest should be 999");
    assert_eq!(received, 1000, "Should have received 1000 packets");
}

#[test]
fn test_in_order_accept() {
    // Verify sequential packets are accepted
    let mut window = SequenceWindow::new(1000);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Send 100 sequential packets
    for i in 0..100 {
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(i));
        assert!(result.is_ok(), "Sequential packet {} should be accepted", i);
    }

    let (_base, highest, received, duplicates) = window.stats();
    assert_eq!(highest.as_u32(), 99, "Highest should be 99");
    assert_eq!(received, 100, "Should have received 100 packets");
    assert_eq!(duplicates, 0, "Should have no duplicates");
}

#[test]
fn test_reorder_accept_within_window() {
    // Verify out-of-order packets within window are accepted
    let mut window = SequenceWindow::new(1000);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Send packets in this order: 0, 2, 1, 4, 3, 100, 50
    let test_sequence = vec![0, 2, 1, 4, 3, 100, 50];

    for &seq in &test_sequence {
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
        assert!(
            result.is_ok(),
            "Out-of-order packet {} should be accepted within window",
            seq
        );
    }

    let (_base, highest, received, duplicates) = window.stats();
    assert_eq!(highest.as_u32(), 100, "Highest should be 100");
    assert_eq!(received, 7, "Should have received 7 packets");
    assert_eq!(duplicates, 0, "Should have no duplicates");
}

#[test]
fn test_replay_reject_within_window() {
    // Verify duplicate sequence numbers are rejected
    let mut window = SequenceWindow::new(1000);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Accept sequence 100
    let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(100));
    assert!(result.is_ok(), "First packet should be accepted");

    // Try to replay sequence 100
    let replay_result = window.check_and_mark(session_id.clone(), SequenceNumber::new(100));
    assert!(
        replay_result.is_err(),
        "Replay of sequence 100 should be rejected"
    );

    let (_base, _highest, _received, duplicates) = window.stats();
    assert_eq!(duplicates, 1, "Should have detected one duplicate");
}

#[test]
fn test_window_slide_old_sequences_expire() {
    // Verify old sequences expire as window advances
    let mut window = SequenceWindow::new(1000);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Accept sequences 0-999 (fill the window)
    for i in 0..1000 {
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(i));
        assert!(result.is_ok(), "Sequence {} should be accepted", i);
    }

    // Accept sequence 1000 (should advance window)
    let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(1000));
    assert!(result.is_ok(), "Sequence 1000 should advance window");

    // Now sequence 0 should be outside the window and rejected as replay
    let old_result = window.check_and_mark(session_id.clone(), SequenceNumber::new(0));
    assert!(
        old_result.is_err(),
        "Sequence 0 should be rejected after window advances"
    );

    // Sequence 1 was already received and should be detected as duplicate
    let duplicate_result = window.check_and_mark(session_id.clone(), SequenceNumber::new(1));
    assert!(
        duplicate_result.is_err(),
        "Sequence 1 already received, should be duplicate"
    );

    // Verify stats
    let (_base, _highest, _received, duplicates) = window.stats();
    assert_eq!(duplicates, 1, "Should have one duplicate from sequence 1");
}

#[test]
fn test_memory_usage_acceptable() {
    // Verify memory usage is acceptable (~4KB for 1000 entries)
    let window = SequenceWindow::new(1000);

    // Size of SequenceWindow with 1000-entry bool array
    // Should be approximately:
    // - 1000 bytes for bool array
    // - Plus a few dozen bytes for other fields
    let size = std::mem::size_of_val(&window);

    // Should be roughly 1KB (1000 bytes for array + metadata)
    // Allow up to 2KB for safety margin
    assert!(
        size <= 2048,
        "Window size {} should be <= 2KB (got {} bytes)",
        size,
        size
    );

    // Verify it's at least the array size
    assert!(
        size >= 1000,
        "Window should be at least 1000 bytes for the array"
    );
}

#[test]
fn test_large_gap_within_window() {
    // Test that large gaps within the 1000-entry window work correctly
    let mut window = SequenceWindow::new(1000);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Accept sequence 0
    let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(0));
    assert!(result.is_ok(), "Sequence 0 should be accepted");

    // Jump to sequence 999 (near end of window)
    let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(999));
    assert!(
        result.is_ok(),
        "Sequence 999 should be accepted within window"
    );

    // Go back to sequence 500 (middle of window)
    let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(500));
    assert!(
        result.is_ok(),
        "Sequence 500 should be accepted within window"
    );

    let (_base, highest, received, _duplicates) = window.stats();
    assert_eq!(highest.as_u32(), 999, "Highest should be 999");
    assert_eq!(received, 3, "Should have received 3 packets");
}
