// Sequence Number Wrap-Around Tests (MED-027)
//
// Tests verify sequence number behavior at u32 boundaries, wraparound handling,
// and anti-replay protection across the u32::MAX boundary.
//
// Protocol reference: design/protocol/14-replay-protection.md

use buckwild_common::protocol::types::{SequenceNumber, SessionId, SessionIdLength};
use buckwild_common::security::anti_replay::sequence::{SequenceValidator, SequenceWindow};

// =========================================================================
// Sequence Number Boundary Tests
// =========================================================================

#[test]
fn test_sequence_near_u32_max_minus_1() {
    let seq = SequenceNumber::new(u32::MAX - 1);
    assert_eq!(seq.as_u32(), u32::MAX - 1);
    assert!(seq.is_valid());
}

#[test]
fn test_sequence_at_u32_max() {
    let seq = SequenceNumber::new(u32::MAX);
    assert_eq!(seq.as_u32(), u32::MAX);
    assert!(seq.is_valid());
}

#[test]
fn test_sequence_wraps_to_zero() {
    let seq = SequenceNumber::new(u32::MAX);
    let next = seq + 1;
    assert_eq!(next.as_u32(), 0, "u32::MAX + 1 should wrap to 0");
}

#[test]
fn test_sequence_difference_across_wrap() {
    let seq1 = SequenceNumber::new(u32::MAX - 10);
    let seq2 = SequenceNumber::new(5); // Wrapped around

    // Difference should be 16 (MAX-10 -> MAX-9 -> ... -> MAX -> 0 -> 1 -> ... -> 5)
    let diff = seq2.diff(&seq1);
    assert_eq!(
        diff, 16,
        "Difference across wrap should be calculated correctly"
    );
}

#[test]
fn test_sequence_wrapping_sub() {
    let seq1 = SequenceNumber::new(5);
    let seq2 = SequenceNumber::new(10);

    // 5 - 10 should wrap to u32::MAX - 4
    let result = seq1.wrapping_sub(&seq2);
    assert_eq!(result.as_u32(), 5u32.wrapping_sub(10));
}

// =========================================================================
// Anti-Replay Window Tests at Boundaries
// =========================================================================

#[test]
fn test_window_accepts_sequence_at_u32_max_minus_1() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX - 2));

    let result = window.check_and_mark(session_id, SequenceNumber::new(u32::MAX - 1));
    assert!(
        result.is_ok(),
        "Window should accept sequence at u32::MAX - 1"
    );
}

#[test]
fn test_window_accepts_sequence_at_u32_max() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX - 1));

    let result = window.check_and_mark(session_id, SequenceNumber::new(u32::MAX));
    assert!(result.is_ok(), "Window should accept sequence at u32::MAX");
}

#[test]
fn test_window_accepts_wrap_to_zero() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX));

    let result = window.check_and_mark(session_id, SequenceNumber::new(0));
    assert!(
        result.is_ok(),
        "Window should accept wrap from u32::MAX to 0"
    );
}

#[test]
fn test_window_accepts_sequence_after_wrap() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Start at u32::MAX - 5, send packets through wrap
    window.reset(SequenceNumber::new(u32::MAX - 5));

    // Send sequences: MAX-4, MAX-3, MAX-2, MAX-1, MAX, 0, 1, 2, 3, 4, 5
    for i in 0..11u32 {
        let seq = (u32::MAX - 4).wrapping_add(i);
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
        assert!(
            result.is_ok(),
            "Sequence {} should be accepted (iteration {})",
            seq,
            i
        );
    }

    // Verify highest is now 5
    let (_, highest, _, _) = window.stats();
    assert_eq!(highest.as_u32(), 5, "Highest should be 5 after wrap");
}

// =========================================================================
// Anti-Replay Duplicate Detection Across Wrap
// =========================================================================

#[test]
fn test_window_detects_duplicate_at_u32_max() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX - 1));

    // Send u32::MAX
    let result1 = window.check_and_mark(session_id.clone(), SequenceNumber::new(u32::MAX));
    assert!(
        result1.is_ok(),
        "First packet at u32::MAX should be accepted"
    );

    // Try to send u32::MAX again (duplicate)
    let result2 = window.check_and_mark(session_id, SequenceNumber::new(u32::MAX));
    assert!(
        result2.is_err(),
        "Duplicate packet at u32::MAX should be rejected"
    );
}

#[test]
fn test_window_detects_duplicate_after_wrap() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX - 5));

    // Send packets through wrap
    for i in 0..10u32 {
        let seq = (u32::MAX - 4).wrapping_add(i);
        let _ = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
    }

    // Try to replay sequence 2 (already sent)
    let result = window.check_and_mark(session_id, SequenceNumber::new(2));
    assert!(
        result.is_err(),
        "Duplicate packet after wrap should be rejected"
    );
}

#[test]
fn test_window_rejects_old_sequence_before_wrap() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Start near wrap point
    window.reset(SequenceNumber::new(u32::MAX - 10));

    // Advance past wrap - send enough to move window past the old base
    // Need to advance window by more than 64 to push old base out
    for i in 0..80u32 {
        let seq = (u32::MAX - 9).wrapping_add(i);
        let _ = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
    }

    // Now highest is at ~70, window is [~7..~70], try to send u32::MAX - 10 (way behind)
    let result = window.check_and_mark(session_id, SequenceNumber::new(u32::MAX - 10));
    assert!(
        result.is_err(),
        "Old sequence before wrap should be rejected (more than window size behind)"
    );
}

// =========================================================================
// SequenceValidator Tests Across Wrap
// =========================================================================

#[test]
fn test_validator_accepts_monotonic_through_wrap() {
    let validator = SequenceValidator::new(u32::MAX - 5);

    // Send sequences through wrap: MAX-5, MAX-4, ..., MAX, 0, 1, 2, 3
    for i in 0..10u32 {
        let seq_value = (u32::MAX - 5).wrapping_add(i);
        let (base, _, _, _) = validator.stats();
        let next_expected = validator.expected_next();

        let result = validator.would_accept(SequenceNumber::new(seq_value));
        assert!(
            result,
            "Sequence {} should be accepted (base={}, expected_next={})",
            seq_value,
            base,
            next_expected.as_u32()
        );
    }
}

#[test]
fn test_validator_tracks_highest_across_wrap() {
    let mut validator = SequenceValidator::new(u32::MAX - 3);

    // Send sequences
    let sequences = vec![u32::MAX - 3, u32::MAX - 2, u32::MAX - 1, u32::MAX, 0, 1, 2];

    for &seq_value in &sequences {
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
        let result = validator.validate_sequence(session_id, SequenceNumber::new(seq_value));
        assert!(result.is_ok(), "Sequence {} should be accepted", seq_value);
    }

    let (_, highest, _, _) = validator.stats();
    assert_eq!(
        highest, 2,
        "Highest sequence should be 2 after wrap sequence"
    );
}

#[test]
fn test_validator_detects_replay_across_wrap() {
    let mut validator = SequenceValidator::new(u32::MAX - 5);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Send sequences through wrap
    for i in 0..10u32 {
        let seq_value = (u32::MAX - 5).wrapping_add(i);
        let _ = validator.validate_sequence(session_id.clone(), SequenceNumber::new(seq_value));
    }

    // Try to replay u32::MAX (already sent)
    let result = validator.validate_sequence(session_id, SequenceNumber::new(u32::MAX));
    assert!(
        result.is_err(),
        "Replay of sequence u32::MAX should be detected"
    );
}

// =========================================================================
// Large Sequence Jump Tests
// =========================================================================

#[test]
fn test_window_handles_large_jump_before_wrap() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX - 1000));

    // Jump directly to u32::MAX - 10
    let result = window.check_and_mark(session_id, SequenceNumber::new(u32::MAX - 10));
    assert!(
        result.is_ok(),
        "Large forward jump before wrap should be accepted"
    );
}

#[test]
fn test_window_handles_jump_across_wrap() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX - 5));

    // Jump directly to sequence 100 (past wrap)
    let result = window.check_and_mark(session_id, SequenceNumber::new(100));
    assert!(
        result.is_ok(),
        "Large forward jump across wrap should be accepted"
    );
}

// =========================================================================
// Window Sliding Tests at Boundaries
// =========================================================================

#[test]
fn test_window_slides_correctly_at_wrap_boundary() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Start at u32::MAX - 70
    window.reset(SequenceNumber::new(u32::MAX - 70));

    // Send enough packets to slide window past u32::MAX
    for i in 0..100u32 {
        let seq = (u32::MAX - 69).wrapping_add(i);
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
        assert!(result.is_ok(), "Packet {} should be accepted", seq);
    }

    // Window base should now be past 0
    let (base, highest, _, _) = window.stats();
    // Started at MAX-70, sent 100 packets: MAX-69, MAX-68, ..., MAX, 0, 1, ..., 29
    // Highest should be 29 (100 packets from MAX-69 = 29)
    assert!(
        highest.as_u32() == 29,
        "After sliding through wrap, highest should be 29 (got base={}, highest={})",
        base.as_u32(),
        highest.as_u32()
    );
}

// =========================================================================
// Out-of-Order Delivery Tests at Wrap
// =========================================================================

#[test]
fn test_window_handles_out_of_order_near_wrap() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    window.reset(SequenceNumber::new(u32::MAX - 5));

    // Send in order: MAX-4, 0, MAX-3, 1, MAX-2, 2 (interleaved)
    let sequences = vec![u32::MAX - 4, 0, u32::MAX - 3, 1, u32::MAX - 2, 2];

    for &seq in &sequences {
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
        assert!(
            result.is_ok(),
            "Out-of-order sequence {} should be accepted",
            seq
        );
    }
}

// =========================================================================
// Stress Tests
// =========================================================================

#[test]
fn test_multiple_wraps() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Start very close to wrap
    window.reset(SequenceNumber::new(u32::MAX - 2));

    // Send 200 packets, causing multiple conceptual wraps
    for i in 0..200u32 {
        let seq = (u32::MAX - 1).wrapping_add(i);
        let result = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
        assert!(
            result.is_ok(),
            "Sequence {} (iteration {}) should be accepted",
            seq,
            i
        );
    }

    // Reset sets received_count to 1, then we add 200 more = 201 total
    // Started at MAX-2 (reset), sent from MAX-1: MAX-1, MAX, 0, 1, ..., 197
    let (_, highest, received, _) = window.stats();
    assert_eq!(
        received, 201,
        "Should have received 201 packets (1 from reset + 200 sent)"
    );
    assert_eq!(
        highest.as_u32(),
        197,
        "Highest should be 197 after wrapping (MAX-1 + 199 wrapping)"
    );
}

#[test]
fn test_window_full_at_wrap_boundary() {
    let mut window = SequenceWindow::new(64);
    let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

    // Position window so it spans the wrap boundary
    // Base at u32::MAX - 32, top at u32::MAX + 31 = 30
    window.reset(SequenceNumber::new(u32::MAX - 32));

    // Fill entire 64-entry window (63 packets after reset which counts as 1)
    for i in 0..63u32 {
        let seq = (u32::MAX - 31).wrapping_add(i);
        let _ = window.check_and_mark(session_id.clone(), SequenceNumber::new(seq));
    }

    // Window should be full now
    let (_, _, received, _) = window.stats();
    assert_eq!(received, 64, "Window should have 64 packets");

    // Try to send duplicate in middle of window (should fail)
    let mid_seq = (u32::MAX - 31).wrapping_add(32); // Middle of window
    let result = window.check_and_mark(session_id, SequenceNumber::new(mid_seq));
    assert!(
        result.is_err(),
        "Duplicate in full window should be rejected"
    );
}
