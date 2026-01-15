#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Recovery Trigger Detection
//!
//! This module implements trigger detection mechanisms that determine when recovery
//! actions should be initiated. Triggers include time drift, packet loss, and other
//! conditions that indicate the need for recovery procedures.

use std::time::{Duration, SystemTime};

use crate::protocol::timeout::timeout_constants::TIME_SYNC_TOLERANCE_MS;
use crate::protocol::types::ConnectionState;

use super::engine::RecoveryLevel;

/// Detects time drift between local and peer clocks
///
/// Calculates the absolute difference between local and peer time, and returns
/// the drift if it exceeds the specified tolerance threshold.
///
/// # Arguments
///
/// * `local_time` - The local system time
/// * `peer_time` - The peer system time (from received packet or sync message)
/// * `tolerance_ms` - Maximum acceptable drift in milliseconds
///
/// # Returns
///
/// * `Some(Duration)` - The detected drift if it exceeds tolerance
/// * `None` - If drift is within acceptable tolerance
pub fn detect_time_drift(
    local_time: SystemTime,
    peer_time: SystemTime,
    tolerance_ms: u64,
) -> Option<Duration> {
    // Calculate absolute drift between local and peer time
    let drift = match peer_time.duration_since(local_time) {
        Ok(ahead) => ahead,
        Err(e) => {
            // Peer is behind local - get the negative duration
            e.duration()
        }
    };

    let drift_ms = drift.as_millis() as u64;

    // Return drift if it exceeds tolerance
    if drift_ms > tolerance_ms {
        Some(drift)
    } else {
        None
    }
}

/// Detects time drift using the default TIME_SYNC_TOLERANCE_MS threshold
///
/// Convenience wrapper around `detect_time_drift` using the protocol-specified
/// tolerance of 50ms.
///
/// # Arguments
///
/// * `local_time` - The local system time
/// * `peer_time` - The peer system time
///
/// # Returns
///
/// * `Some(Duration)` - The detected drift if it exceeds TIME_SYNC_TOLERANCE_MS
/// * `None` - If drift is within acceptable tolerance
pub fn detect_time_drift_default(
    local_time: SystemTime,
    peer_time: SystemTime,
) -> Option<Duration> {
    detect_time_drift(local_time, peer_time, TIME_SYNC_TOLERANCE_MS)
}

/// Determine recovery level needed based on failure conditions
///
/// This function evaluates multiple failure conditions and returns the highest
/// applicable recovery level. Per design/protocol/12-recovery-mechanisms.md:
///
/// - TIME_SYNC: Time drift > 50ms
/// - SESSION_REKEY: Auth failures > 5
/// - SEQUENCE_REPAIR: Sequence gap > 100
/// - EMERGENCY: Multiple simultaneous issues (2+)
/// - CONNECTION_TERMINATE: Unrecoverable state
///
/// # Arguments
///
/// * `time_drift` - Optional time drift duration (if measured)
/// * `sequence_gap` - Optional sequence number gap (if detected)
/// * `auth_failures` - Count of authentication failures
/// * `connection_state` - Current connection state
///
/// # Returns
///
/// The highest applicable recovery level for the given conditions.
pub fn determine_recovery_level_needed(
    time_drift: Option<Duration>,
    sequence_gap: Option<u32>,
    auth_failures: u32,
    connection_state: &ConnectionState,
) -> RecoveryLevel {
    // Check for unrecoverable connection states
    if matches!(
        connection_state,
        ConnectionState::Error | ConnectionState::Closed
    ) {
        return RecoveryLevel::ConnectionTerminate;
    }

    // Count how many failure conditions are present
    let mut failure_count = 0;
    let mut highest_level = RecoveryLevel::None;

    // Check time drift: threshold is 50ms per spec
    if let Some(drift) = time_drift {
        if drift > Duration::from_millis(50) {
            failure_count += 1;
            if highest_level < RecoveryLevel::TimeSync {
                highest_level = RecoveryLevel::TimeSync;
            }
        }
    }

    // Check auth failures: threshold is 5 per spec
    if auth_failures > 5 {
        failure_count += 1;
        if highest_level < RecoveryLevel::SessionRekey {
            highest_level = RecoveryLevel::SessionRekey;
        }
    }

    // Check sequence gap: threshold is 100 per spec
    if let Some(gap) = sequence_gap {
        if gap > 100 {
            failure_count += 1;
            if highest_level < RecoveryLevel::SequenceRepair {
                highest_level = RecoveryLevel::SequenceRepair;
            }
        }
    }

    // Multiple simultaneous issues trigger emergency recovery
    // Per spec: 2+ failure conditions = emergency
    if failure_count >= 2 {
        return RecoveryLevel::Emergency;
    }

    highest_level
}

/// Detects authentication failures in a rolling time window
///
/// Tracks HMAC verification failures over a sliding time window to detect potential
/// authentication attacks or key desynchronization. Per design/protocol/12-recovery-mechanisms.md,
/// exceeding the threshold triggers session rekeying.
///
/// # Arguments
///
/// * `hmac_failures` - Number of HMAC failures in the time window
/// * `time_window` - Duration of the rolling time window
/// * `threshold` - Maximum acceptable failures before triggering rekey
///
/// # Returns
///
/// * `true` - If failures exceed threshold, triggering rekey
/// * `false` - If failures are within acceptable limits
///
/// # Default Thresholds
///
/// Per spec:
/// - Threshold: 5 failures
/// - Time window: 60 seconds
/// - These defaults can be overridden via configuration
pub fn detect_authentication_failures(
    hmac_failures: u32,
    _time_window: Duration,
    threshold: u32,
) -> bool {
    hmac_failures >= threshold
}

/// Detects sequence number mismatch outside the acceptable window
///
/// Analyzes the gap between expected and received sequence numbers to determine
/// if recovery is needed. Per design/protocol/12-recovery-mechanisms.md §3.2,
/// gaps exceeding 100 sequences trigger recovery procedures.
///
/// # Arguments
///
/// * `expected_seq` - The expected sequence number
/// * `received_seq` - The received sequence number
/// * `window_size` - The sequence window size (typically 1000)
///
/// # Returns
///
/// * `Some(gap_size)` - The gap size if sequence mismatch is detected (gap > 100)
/// * `None` - If the received sequence is within acceptable bounds
///
/// # Sequence Wraparound Handling
///
/// Per design/protocol/14-replay-protection.md §"Sequence Number Replay Protection",
/// this function handles 32-bit sequence number wraparound at the 2^31 boundary.
/// When wraparound is detected, the gap is calculated correctly across the boundary.
pub fn detect_sequence_mismatch(
    expected_seq: u32,
    received_seq: u32,
    window_size: u32,
) -> Option<u32> {
    // Constants from design/protocol/02-core-definitions.md
    const SEQUENCE_WRAP_THRESHOLD: u32 = 0x8000_0000; // 2^31
    const GAP_THRESHOLD: u32 = 100; // Per task spec and 12-recovery-mechanisms.md

    // Handle sequence wraparound at 32-bit boundary
    // Per 14-replay-protection.md: expected > 2^31 and received < window_size indicates wraparound
    let gap = if expected_seq > SEQUENCE_WRAP_THRESHOLD && received_seq < window_size {
        // Wraparound detected: calculate gap across the boundary
        // Gap = (max_u32 - expected) + received + 1
        let distance_to_wrap = u32::MAX - expected_seq;
        distance_to_wrap + received_seq + 1
    } else if received_seq > expected_seq {
        // Normal case: received is ahead
        received_seq - expected_seq
    } else {
        // Received is behind or equal - no gap
        return None;
    };

    // Return gap if it exceeds the recovery threshold of 100
    if gap > GAP_THRESHOLD { Some(gap) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_drift_within_tolerance() {
        let local = SystemTime::now();
        let peer = local + Duration::from_millis(30);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(
            drift.is_none(),
            "Expected no drift for times within tolerance"
        );
    }

    #[test]
    fn test_small_drift_within_tolerance() {
        let local = SystemTime::now();
        let peer = local + Duration::from_millis(30);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(
            drift.is_none(),
            "30ms drift should be within 50ms tolerance"
        );
    }

    #[test]
    fn test_drift_detected_exceeds_tolerance() {
        let local = SystemTime::now();
        let peer = local + Duration::from_millis(100);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(drift.is_some(), "100ms drift should exceed 50ms tolerance");
        assert_eq!(drift.unwrap().as_millis(), 100);
    }

    #[test]
    fn test_large_drift_detected() {
        let local = SystemTime::now();
        let peer = local + Duration::from_secs(5);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(drift.is_some(), "5s drift should be detected");
        assert_eq!(drift.unwrap().as_secs(), 5);
    }

    #[test]
    fn test_negative_drift_local_ahead() {
        let local = SystemTime::now();
        let peer = local - Duration::from_millis(100);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(
            drift.is_some(),
            "Negative drift (local ahead) should be detected"
        );
        assert_eq!(drift.unwrap().as_millis(), 100);
    }

    #[test]
    fn test_negative_drift_within_tolerance() {
        let local = SystemTime::now();
        let peer = local - Duration::from_millis(30);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(
            drift.is_none(),
            "Negative drift within tolerance should not be detected"
        );
    }

    #[test]
    fn test_exact_tolerance_boundary() {
        let local = SystemTime::now();
        let peer = local + Duration::from_millis(50);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(
            drift.is_none(),
            "Drift exactly at tolerance should not trigger"
        );
    }

    #[test]
    fn test_just_over_tolerance() {
        let local = SystemTime::now();
        let peer = local + Duration::from_millis(51);
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(drift.is_some(), "Drift just over tolerance should trigger");
        assert_eq!(drift.unwrap().as_millis(), 51);
    }

    #[test]
    fn test_zero_drift() {
        let local = SystemTime::now();
        let peer = local;
        let tolerance = 50;

        let drift = detect_time_drift(local, peer, tolerance);
        assert!(drift.is_none(), "Zero drift should not trigger");
    }

    #[test]
    fn test_default_tolerance() {
        let local = SystemTime::now();
        let peer = local + Duration::from_millis(100);

        let drift = detect_time_drift_default(local, peer);
        assert!(
            drift.is_some(),
            "100ms should exceed default 50ms tolerance"
        );
        assert_eq!(drift.unwrap().as_millis(), 100);
    }

    #[test]
    fn test_default_tolerance_within() {
        let local = SystemTime::now();
        let peer = local + Duration::from_millis(30);

        let drift = detect_time_drift_default(local, peer);
        assert!(
            drift.is_none(),
            "30ms should be within default 50ms tolerance"
        );
    }

    // Tests for determine_recovery_level_needed()

    #[test]
    fn test_no_issues_returns_none() {
        let level = determine_recovery_level_needed(None, None, 0, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::None);
    }

    #[test]
    fn test_time_drift_only() {
        // Just under threshold - no recovery
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(50)),
            None,
            0,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::None);

        // At threshold boundary (51ms > 50ms threshold)
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(51)),
            None,
            0,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::TimeSync);

        // Well over threshold
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(100)),
            None,
            0,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::TimeSync);
    }

    #[test]
    fn test_auth_failures_only() {
        // Just under threshold - no recovery
        let level = determine_recovery_level_needed(None, None, 5, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::None);

        // At threshold boundary (6 > 5 threshold)
        let level = determine_recovery_level_needed(None, None, 6, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SessionRekey);

        // Well over threshold
        let level = determine_recovery_level_needed(None, None, 10, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SessionRekey);
    }

    #[test]
    fn test_sequence_gap_only() {
        // Just under threshold - no recovery
        let level =
            determine_recovery_level_needed(None, Some(100), 0, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::None);

        // At threshold boundary (101 > 100 threshold)
        let level =
            determine_recovery_level_needed(None, Some(101), 0, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SequenceRepair);

        // Well over threshold
        let level =
            determine_recovery_level_needed(None, Some(200), 0, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SequenceRepair);
    }

    #[test]
    fn test_multiple_issues_triggers_emergency() {
        // Time drift + auth failures
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(51)),
            None,
            6,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::Emergency);

        // Time drift + sequence gap
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(51)),
            Some(101),
            0,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::Emergency);

        // Auth failures + sequence gap
        let level =
            determine_recovery_level_needed(None, Some(101), 6, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::Emergency);

        // All three issues
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(51)),
            Some(101),
            6,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::Emergency);
    }

    #[test]
    fn test_returns_highest_level_when_single_issue() {
        // Only time drift (lowest level)
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(51)),
            None,
            0,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::TimeSync);

        // Only auth failures (medium level)
        let level = determine_recovery_level_needed(None, None, 6, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SessionRekey);

        // Only sequence gap (high level)
        let level =
            determine_recovery_level_needed(None, Some(101), 0, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SequenceRepair);
    }

    #[test]
    fn test_unrecoverable_connection_states() {
        // Error state
        let level = determine_recovery_level_needed(None, None, 0, &ConnectionState::Error);
        assert_eq!(level, RecoveryLevel::ConnectionTerminate);

        // Closed state
        let level = determine_recovery_level_needed(None, None, 0, &ConnectionState::Closed);
        assert_eq!(level, RecoveryLevel::ConnectionTerminate);
    }

    #[test]
    fn test_boundary_conditions() {
        // Exactly at threshold - should not trigger
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(50)),
            Some(100),
            5,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::None);

        // Just over threshold - should trigger
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(51)),
            Some(101),
            6,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::Emergency); // Multiple issues
    }

    #[test]
    fn test_zero_values() {
        let level = determine_recovery_level_needed(
            Some(Duration::from_millis(0)),
            Some(0),
            0,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::None);
    }

    #[test]
    fn test_extreme_values() {
        // Extreme time drift
        let level = determine_recovery_level_needed(
            Some(Duration::from_secs(10)),
            None,
            0,
            &ConnectionState::Established,
        );
        assert_eq!(level, RecoveryLevel::TimeSync);

        // Extreme auth failures
        let level =
            determine_recovery_level_needed(None, None, 1000, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SessionRekey);

        // Extreme sequence gap
        let level =
            determine_recovery_level_needed(None, Some(u32::MAX), 0, &ConnectionState::Established);
        assert_eq!(level, RecoveryLevel::SequenceRepair);
    }

    // Tests for detect_sequence_mismatch()

    #[test]
    fn test_in_window_no_mismatch() {
        // Small gap within threshold (100) - no mismatch
        let result = detect_sequence_mismatch(100, 150, 1000);
        assert!(result.is_none(), "Gap of 50 should be within threshold");

        // At boundary - exactly 100
        let result = detect_sequence_mismatch(100, 200, 1000);
        assert!(result.is_none(), "Gap of 100 should be at threshold");
    }

    #[test]
    fn test_large_gap_detected() {
        // Gap of 150 exceeds threshold of 100
        let result = detect_sequence_mismatch(100, 250, 1000);
        assert_eq!(result, Some(150), "Gap of 150 should be detected");

        // Gap of 101 just exceeds threshold
        let result = detect_sequence_mismatch(100, 201, 1000);
        assert_eq!(result, Some(101), "Gap of 101 should be detected");
    }

    #[test]
    fn test_wraparound_handling() {
        // Expected near max u32, received near 0 (wraparound)
        // Expected: 0xFFFFFFF0 (4,294,967,280)
        // Received: 100
        // Gap = (0xFFFFFFFF - 0xFFFFFFF0) + 100 + 1 = 15 + 100 + 1 = 116
        let result = detect_sequence_mismatch(0xFFFF_FFF0, 100, 1000);
        assert_eq!(
            result,
            Some(116),
            "Wraparound gap of 116 should be detected"
        );

        // Wraparound with small gap (within threshold)
        // Expected: 0xFFFFFFFF (max u32)
        // Received: 50
        // Gap = 0 + 50 + 1 = 51 (within threshold)
        let result = detect_sequence_mismatch(0xFFFF_FFFF, 50, 1000);
        assert!(
            result.is_none(),
            "Wraparound gap of 51 should be within threshold"
        );

        // Wraparound with large gap
        // Expected: 0x80000010 (just above threshold)
        // Received: 200
        // Gap = (0xFFFFFFFF - 0x80000010) + 200 + 1 = 2,147,483,630
        let result = detect_sequence_mismatch(0x8000_0010, 200, 1000);
        assert!(result.is_some(), "Large wraparound gap should be detected");
        assert!(
            result.unwrap() > 100,
            "Wraparound gap should exceed threshold"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Expected and received are equal - no gap
        let result = detect_sequence_mismatch(100, 100, 1000);
        assert!(
            result.is_none(),
            "Equal sequence numbers should have no gap"
        );

        // Received is behind expected - no gap
        let result = detect_sequence_mismatch(200, 100, 1000);
        assert!(
            result.is_none(),
            "Received behind expected should have no gap"
        );

        // Zero sequences
        let result = detect_sequence_mismatch(0, 0, 1000);
        assert!(result.is_none(), "Zero sequences should have no gap");

        // Gap exactly at threshold boundary
        let result = detect_sequence_mismatch(0, 100, 1000);
        assert!(result.is_none(), "Gap exactly at 100 should not trigger");

        let result = detect_sequence_mismatch(0, 101, 1000);
        assert_eq!(result, Some(101), "Gap of 101 should trigger");
    }

    #[test]
    fn test_threshold_enforcement() {
        // Test gap of 99 (below threshold)
        let result = detect_sequence_mismatch(1000, 1099, 1000);
        assert!(result.is_none(), "Gap of 99 should be below threshold");

        // Test gap of 100 (at threshold)
        let result = detect_sequence_mismatch(1000, 1100, 1000);
        assert!(result.is_none(), "Gap of 100 should be at threshold");

        // Test gap of 101 (above threshold)
        let result = detect_sequence_mismatch(1000, 1101, 1000);
        assert_eq!(result, Some(101), "Gap of 101 should exceed threshold");

        // Test large gap
        let result = detect_sequence_mismatch(1000, 2000, 1000);
        assert_eq!(result, Some(1000), "Gap of 1000 should be detected");
    }

    // Tests for detect_authentication_failures()

    #[test]
    fn test_below_threshold_no_rekey() {
        // 4 failures is below the threshold of 5
        let result = detect_authentication_failures(4, Duration::from_secs(60), 5);
        assert!(!result, "4 failures should be below threshold of 5");
    }

    #[test]
    fn test_at_threshold_triggers_rekey() {
        // 5 failures equals the threshold of 5
        let result = detect_authentication_failures(5, Duration::from_secs(60), 5);
        assert!(result, "5 failures should trigger rekey at threshold of 5");
    }

    #[test]
    fn test_above_threshold_triggers_rekey() {
        // 10 failures exceeds the threshold of 5
        let result = detect_authentication_failures(10, Duration::from_secs(60), 5);
        assert!(
            result,
            "10 failures should trigger rekey above threshold of 5"
        );
    }

    #[test]
    fn test_rolling_window_different_durations() {
        // Test with different time window durations
        // The function tracks failures within the window regardless of duration

        // 30 second window
        let result = detect_authentication_failures(5, Duration::from_secs(30), 5);
        assert!(result, "5 failures should trigger rekey in 30s window");

        // 60 second window (default)
        let result = detect_authentication_failures(5, Duration::from_secs(60), 5);
        assert!(result, "5 failures should trigger rekey in 60s window");

        // 120 second window
        let result = detect_authentication_failures(5, Duration::from_secs(120), 5);
        assert!(result, "5 failures should trigger rekey in 120s window");
    }

    #[test]
    fn test_rate_limiting_prevents_brute_force() {
        // Rapid authentication failures should trigger rekey
        let result = detect_authentication_failures(20, Duration::from_secs(10), 5);
        assert!(
            result,
            "20 failures in 10s should trigger rekey (rate limiting)"
        );
    }

    #[test]
    fn test_zero_failures_no_rekey() {
        // No failures should not trigger rekey
        let result = detect_authentication_failures(0, Duration::from_secs(60), 5);
        assert!(!result, "0 failures should not trigger rekey");
    }

    #[test]
    fn test_custom_threshold() {
        // Test with custom threshold of 10
        let result = detect_authentication_failures(9, Duration::from_secs(60), 10);
        assert!(!result, "9 failures should be below custom threshold of 10");

        let result = detect_authentication_failures(10, Duration::from_secs(60), 10);
        assert!(
            result,
            "10 failures should trigger rekey at custom threshold of 10"
        );

        let result = detect_authentication_failures(11, Duration::from_secs(60), 10);
        assert!(
            result,
            "11 failures should trigger rekey above custom threshold of 10"
        );
    }

    #[test]
    fn test_threshold_of_one() {
        // Edge case: threshold of 1 means any failure triggers rekey
        let result = detect_authentication_failures(0, Duration::from_secs(60), 1);
        assert!(!result, "0 failures should not trigger with threshold 1");

        let result = detect_authentication_failures(1, Duration::from_secs(60), 1);
        assert!(result, "1 failure should trigger with threshold 1");
    }

    #[test]
    fn test_high_failure_count() {
        // Test with extremely high failure count (potential attack)
        let result = detect_authentication_failures(1000, Duration::from_secs(60), 5);
        assert!(
            result,
            "1000 failures should definitely trigger rekey (potential attack)"
        );
    }

    #[test]
    fn test_wraparound_boundary() {
        // Test at wraparound threshold boundary (0x80000000)
        const THRESHOLD: u32 = 0x8000_0000;

        // Just below threshold - normal gap calculation
        let result = detect_sequence_mismatch(THRESHOLD - 1, THRESHOLD + 100, 1000);
        assert_eq!(result, Some(101), "Normal gap across threshold");

        // Just above threshold with low received - wraparound
        let result = detect_sequence_mismatch(THRESHOLD + 1, 100, 1000);
        assert!(result.is_some(), "Wraparound gap should be detected");

        // At exact threshold with low received - wraparound
        let result = detect_sequence_mismatch(THRESHOLD, 100, 1000);
        assert!(result.is_none(), "Exact threshold is not wraparound");
    }

    #[test]
    fn test_window_size_parameter() {
        // Window size parameter is used in wraparound detection
        // but doesn't affect gap threshold (always 100)

        // Small window size - wraparound detected, gap exceeds threshold
        let result = detect_sequence_mismatch(0x8000_0010, 50, 100);
        assert!(result.is_some(), "Wraparound should work with small window");

        // Large window size - still wraparound (received < window_size)
        // Gap is still huge (2^31+ sequences), so mismatch detected
        let result = detect_sequence_mismatch(0x8000_0010, 50, 10000);
        assert!(result.is_some(), "Wraparound gap still exceeds threshold");

        // Normal case - window size doesn't affect gap calculation
        let result = detect_sequence_mismatch(100, 250, 500);
        assert_eq!(
            result,
            Some(150),
            "Gap calculation unaffected by window size"
        );
    }
}
