//! M17 - HIGH-013: Heartbeat Edge Case Tests
//!
//! Comprehensive edge case testing for heartbeat mechanism:
//! - Timeout boundary conditions
//! - Rapid reconnection scenarios
//! - Missed heartbeat handling

use buckwild_common::engines::adaptive::heartbeat::{
    HeartbeatConfig, HeartbeatEngine, HeartbeatError, HeartbeatState,
};
use buckwild_common::protocol::types::{HeartbeatInterval, SessionId};
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Timeout Boundary Tests
// ============================================================================

#[test]
fn test_timeout_exactly_at_boundary() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 100,
        max_consecutive_failures: 3,
        jitter_ms: 0, // No jitter for deterministic boundary test
        enable_suppression: false,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait exactly timeout_ms
    thread::sleep(Duration::from_millis(100));

    // Should timeout at exactly the boundary (100ms elapsed, timeout is 100ms)
    // Note: Due to timing precision, we accept timeout at exactly the boundary
    let result = state.check_timeout();
    assert!(
        result.is_err(),
        "Should timeout at exactly timeout_ms boundary"
    );

    match result {
        Err(HeartbeatError::Timeout {
            elapsed_ms,
            timeout_ms,
        }) => {
            assert!(
                elapsed_ms >= timeout_ms,
                "Elapsed {} should be >= timeout {}",
                elapsed_ms,
                timeout_ms
            );
        }
        _ => panic!("Expected Timeout error"),
    }
}

#[test]
fn test_timeout_just_over_boundary() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 100,
        max_consecutive_failures: 3,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait just over timeout_ms (110ms > 100ms)
    thread::sleep(Duration::from_millis(110));

    let result = state.check_timeout();
    assert!(result.is_err(), "Should timeout when elapsed > timeout_ms");

    match result {
        Err(HeartbeatError::Timeout {
            elapsed_ms,
            timeout_ms,
        }) => {
            assert!(
                elapsed_ms > timeout_ms,
                "Elapsed {} should be > timeout {}",
                elapsed_ms,
                timeout_ms
            );
            assert_eq!(state.consecutive_failures(), 1);
        }
        _ => panic!("Expected Timeout error"),
    }
}

#[test]
fn test_timeout_just_under_boundary() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 150,
        max_consecutive_failures: 3,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait just under timeout_ms (100ms < 150ms)
    thread::sleep(Duration::from_millis(100));

    let result = state.check_timeout();
    assert!(
        result.is_ok(),
        "Should NOT timeout when elapsed < timeout_ms"
    );
    assert_eq!(state.consecutive_failures(), 0);
}

#[test]
fn test_timeout_boundary_with_data_packet_suppression() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 100,
        max_consecutive_failures: 3,
        jitter_ms: 0,
        enable_suppression: true,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait to boundary
    thread::sleep(Duration::from_millis(80));

    // Data packet resets timeout window
    state.record_data_packet();

    // Wait to what would have been timeout (80 + 30 = 110ms from original send)
    thread::sleep(Duration::from_millis(30));

    // Should NOT timeout because data packet reset the window
    let result = state.check_timeout();
    assert!(
        result.is_ok(),
        "Data packet should reset timeout window at boundary"
    );
}

// ============================================================================
// Rapid Reconnect Tests
// ============================================================================

#[test]
fn test_immediate_reconnect_after_disconnect() {
    let session_id = SessionId::new(100);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 2,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    // Generate heartbeat and let it timeout (disconnect)
    engine.generate_heartbeat().unwrap();
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();

    assert!(!engine.is_alive(), "Connection should be dead");
    assert_eq!(engine.consecutive_failures(), 2);

    // Immediate reconnect (reset)
    engine.reset();

    // Should immediately be able to generate heartbeats
    assert!(engine.is_alive(), "Should be alive after immediate reset");
    assert_eq!(engine.consecutive_failures(), 0);

    let result = engine.generate_heartbeat();
    assert!(
        result.is_ok(),
        "Should generate heartbeat immediately after reconnect"
    );
}

#[test]
fn test_delayed_reconnect_after_disconnect() {
    let session_id = SessionId::new(101);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 2,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    // Generate heartbeat and let it timeout
    engine.generate_heartbeat().unwrap();
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();

    assert!(!engine.is_alive(), "Connection should be dead");

    // Delay before reconnect
    thread::sleep(Duration::from_millis(200));

    // Reset after delay
    engine.reset();

    // Should still work after delayed reconnect
    assert!(engine.is_alive(), "Should be alive after delayed reconnect");
    assert_eq!(engine.consecutive_failures(), 0);

    let (sequence, _) = engine.generate_heartbeat().unwrap();
    assert!(sequence.0 > 0, "Sequence should continue incrementing");
}

#[test]
fn test_multiple_rapid_reconnects() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 1,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };

    for iteration in 0..5 {
        let session_id = SessionId::new(102 + iteration);
        let engine = HeartbeatEngine::new(session_id, config.clone()).unwrap();

        // Generate and timeout
        engine.generate_heartbeat().unwrap();
        thread::sleep(Duration::from_millis(130));
        let _ = engine.check_keepalive();

        assert!(
            !engine.is_alive(),
            "Connection should die on iteration {}",
            iteration
        );

        // Immediate reset and reconnect
        engine.reset();

        assert!(
            engine.is_alive(),
            "Should recover on iteration {}",
            iteration
        );
        assert_eq!(
            engine.consecutive_failures(),
            0,
            "Failures should be reset on iteration {}",
            iteration
        );
    }
}

#[test]
fn test_reconnect_preserves_sequence_continuity() {
    let session_id = SessionId::new(103);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 1,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    // Generate several heartbeats
    let (seq1, _) = engine.generate_heartbeat().unwrap();
    let (seq2, _) = engine.generate_heartbeat().unwrap();

    assert_eq!(seq1.0, 0);
    assert_eq!(seq2.0, 1);

    // Timeout and reconnect
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    engine.reset();

    // Sequence should continue (not reset)
    let (seq3, _) = engine.generate_heartbeat().unwrap();
    assert_eq!(
        seq3.0, 2,
        "Sequence should continue after reconnect, not reset"
    );
}

// ============================================================================
// Missed Heartbeat Tests
// ============================================================================

#[test]
fn test_single_missed_heartbeat_recovery() {
    let session_id = SessionId::new(200);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 150,
        max_consecutive_failures: 3,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    // Send heartbeat
    let (seq1, _) = engine.generate_heartbeat().unwrap();
    let send_time = Instant::now();

    // Miss first response (timeout)
    thread::sleep(Duration::from_millis(160));
    let result = engine.check_keepalive();
    assert!(result.is_err(), "Should detect missed heartbeat");
    assert_eq!(engine.consecutive_failures(), 1);
    assert!(engine.is_alive(), "Connection should still be alive");

    // Recover with response
    engine.process_response(seq1, send_time).unwrap();

    // Failures should be reset
    assert_eq!(
        engine.consecutive_failures(),
        0,
        "Response should reset failures"
    );
    assert!(engine.is_alive(), "Connection should remain alive");
}

#[test]
fn test_multiple_missed_heartbeats_before_max() {
    let session_id = SessionId::new(201);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 5,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    engine.generate_heartbeat().unwrap();

    // Miss 4 heartbeats (just under max of 5)
    for expected_failures in 1..=4 {
        thread::sleep(Duration::from_millis(130));
        let result = engine.check_keepalive();

        assert!(
            result.is_err(),
            "Should timeout on failure {}",
            expected_failures
        );
        assert_eq!(
            engine.consecutive_failures(),
            expected_failures,
            "Should have {} failures",
            expected_failures
        );
        assert!(
            engine.is_alive(),
            "Connection should still be alive with {} failures",
            expected_failures
        );
    }

    // Still alive before reaching max
    assert!(
        engine.is_alive(),
        "Connection should be alive with 4/5 failures"
    );
}

#[test]
fn test_missed_heartbeat_exactly_at_max() {
    let session_id = SessionId::new(202);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 3,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    engine.generate_heartbeat().unwrap();

    // Miss exactly max_consecutive_failures heartbeats
    for i in 1..=3 {
        thread::sleep(Duration::from_millis(160));
        let result = engine.check_keepalive();

        assert!(result.is_err(), "Should timeout on failure {}", i);
        assert_eq!(engine.consecutive_failures(), i);

        if i < 3 {
            assert!(engine.is_alive(), "Should be alive with {} failures", i);
        } else {
            assert!(!engine.is_alive(), "Should be dead at exactly max failures");
        }
    }

    // Calling check_keepalive when already dead returns ConnectionDead error
    // The failure count is already at max (3)
    let result = engine.check_keepalive();
    assert!(
        matches!(result, Err(HeartbeatError::ConnectionDead { .. })),
        "Expected ConnectionDead error, got {:?}",
        result
    );
}

#[test]
fn test_missed_heartbeat_with_intermittent_responses() {
    let session_id = SessionId::new(203);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 3,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    // Pattern: miss, miss, respond, miss, miss, respond
    // Never reach max consecutive failures

    // Miss 1
    let (seq1, _) = engine.generate_heartbeat().unwrap();
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    assert_eq!(engine.consecutive_failures(), 1);

    // Miss 2
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    assert_eq!(engine.consecutive_failures(), 2);

    // Respond (reset)
    engine.process_response(seq1, Instant::now()).unwrap();
    assert_eq!(engine.consecutive_failures(), 0);
    assert!(engine.is_alive());

    // Miss 1 again
    let (seq2, _) = engine.generate_heartbeat().unwrap();
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    assert_eq!(engine.consecutive_failures(), 1);

    // Miss 2 again
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    assert_eq!(engine.consecutive_failures(), 2);

    // Respond again (reset)
    engine.process_response(seq2, Instant::now()).unwrap();
    assert_eq!(engine.consecutive_failures(), 0);
    assert!(
        engine.is_alive(),
        "Should remain alive with intermittent responses"
    );
}

#[test]
fn test_missed_heartbeat_recovery_resets_failure_count() {
    let session_id = SessionId::new(204);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 4,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    let (seq, _) = engine.generate_heartbeat().unwrap();

    // Build up failures
    for expected in 1..=3 {
        thread::sleep(Duration::from_millis(130));
        let _ = engine.check_keepalive();
        assert_eq!(engine.consecutive_failures(), expected);
    }

    assert_eq!(
        engine.consecutive_failures(),
        3,
        "Should have 3 failures before recovery"
    );

    // Recovery with response
    let send_time = Instant::now();
    engine.process_response(seq, send_time).unwrap();

    // Count should reset to 0
    assert_eq!(
        engine.consecutive_failures(),
        0,
        "Failures should reset to 0 after response"
    );

    // New timeout should start fresh count
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    assert_eq!(
        engine.consecutive_failures(),
        1,
        "New failure should start count at 1, not continue from 3"
    );
}

#[test]
fn test_missed_heartbeat_does_not_prevent_new_generation() {
    let session_id = SessionId::new(205);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(100),
        timeout_ms: 120,
        max_consecutive_failures: 3,
        jitter_ms: 0,
        enable_suppression: false,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    // Generate and miss
    let (seq1, _) = engine.generate_heartbeat().unwrap();
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();

    assert_eq!(engine.consecutive_failures(), 1);

    // Should still be able to generate new heartbeats
    let (seq2, _) = engine.generate_heartbeat().unwrap();
    assert_eq!(seq2.0, seq1.0 + 1, "Sequence should continue");

    // Miss again
    thread::sleep(Duration::from_millis(130));
    let _ = engine.check_keepalive();
    assert_eq!(engine.consecutive_failures(), 2);

    // Still can generate
    let (seq3, _) = engine.generate_heartbeat().unwrap();
    assert_eq!(seq3.0, seq2.0 + 1, "Sequence should continue");
    assert!(engine.is_alive(), "Should be alive until max failures");
}
