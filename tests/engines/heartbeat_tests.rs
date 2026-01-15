//! Comprehensive tests for heartbeat mechanism
//!
//! Tests heartbeat packet generation, response handling, keepalive detection,
//! suppression logic, and recovery scenarios.

use buckwild_common::engines::adaptive::heartbeat::{
    HeartbeatConfig, HeartbeatEngine, HeartbeatError, HeartbeatState,
};
use buckwild_common::protocol::types::{HeartbeatInterval, HeartbeatSequence, SessionId};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_default_configuration_values() {
    let config = HeartbeatConfig::default_config();

    assert_eq!(config.interval_ms.as_millis(), 30000, "Default interval should be 30 seconds");
    assert_eq!(config.timeout_ms, 90000, "Default timeout should be 90 seconds (3x interval)");
    assert_eq!(config.max_consecutive_failures, 3, "Default max failures should be 3");
    assert_eq!(config.jitter_ms, 100, "Default jitter should be 100ms");
    assert!(config.enable_suppression, "Suppression should be enabled by default");
    assert!(!config.negotiated, "Default config should not be marked as negotiated");
}

#[test]
fn test_custom_interval_configuration() {
    let intervals = vec![1000, 5000, 15000, 60000];

    for interval in intervals {
        let config = HeartbeatConfig::with_interval(interval).unwrap();

        assert_eq!(config.interval_ms.as_millis(), interval);
        assert_eq!(config.timeout_ms, interval * 3, "Timeout should be 3x interval");
        assert!(config.validate().is_ok(), "Config should be valid");
    }
}

#[test]
fn test_zero_interval_rejected() {
    let result = HeartbeatConfig::with_interval(0);
    assert!(result.is_err(), "Zero interval should be rejected");

    match result {
        Err(HeartbeatError::InvalidInterval { interval_ms }) => {
            assert_eq!(interval_ms, 0);
        }
        _ => panic!("Expected InvalidInterval error"),
    }
}

#[test]
fn test_negotiation_uses_maximum_interval() {
    let test_cases = vec![
        (10000, 20000, 20000),
        (30000, 15000, 30000),
        (25000, 25000, 25000),
    ];

    for (local, peer, expected) in test_cases {
        let config = HeartbeatConfig::negotiate(local, peer).unwrap();

        assert_eq!(config.interval_ms.as_millis(), expected,
            "Negotiated interval should be max of local ({}) and peer ({})", local, peer);
        assert!(config.negotiated, "Config should be marked as negotiated");
    }
}

#[test]
fn test_negotiation_with_zero_interval_rejected() {
    assert!(HeartbeatConfig::negotiate(0, 0).is_err());
    assert!(HeartbeatConfig::negotiate(10000, 0).is_ok()); // Max is non-zero
    assert!(HeartbeatConfig::negotiate(0, 10000).is_ok()); // Max is non-zero
}

#[test]
fn test_configuration_validation() {
    // Valid configuration
    let valid_config = HeartbeatConfig::with_interval(10000).unwrap();
    assert!(valid_config.validate().is_ok());

    // Invalid: timeout < interval
    let mut invalid_config = HeartbeatConfig::with_interval(10000).unwrap();
    invalid_config.timeout_ms = 5000; // Less than interval
    assert!(invalid_config.validate().is_err());

    // Invalid: zero max_consecutive_failures
    let mut invalid_config2 = HeartbeatConfig::with_interval(10000).unwrap();
    invalid_config2.max_consecutive_failures = 0;
    assert!(invalid_config2.validate().is_err());
}

// ============================================================================
// Heartbeat Timing and Generation Tests
// ============================================================================

#[test]
fn test_first_heartbeat_sent_immediately() {
    let config = HeartbeatConfig::with_interval(10000).unwrap();
    let state = HeartbeatState::new(config);

    assert!(state.should_send_heartbeat(), "First heartbeat should be sent immediately");
}

#[test]
fn test_heartbeat_not_sent_before_interval() {
    let config = HeartbeatConfig::with_interval(1000).unwrap();
    let state = HeartbeatState::new(config);

    // Send first heartbeat
    state.record_send();

    // Should not send immediately after
    assert!(!state.should_send_heartbeat(), "Should not send immediately after first");

    // Wait partial interval
    thread::sleep(Duration::from_millis(500));
    assert!(!state.should_send_heartbeat(), "Should not send before interval elapses");
}

#[test]
fn test_heartbeat_sent_after_interval_with_jitter() {
    let config = HeartbeatConfig::with_interval(100).unwrap(); // 100ms for testing
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait for interval + max jitter
    thread::sleep(Duration::from_millis(250));

    assert!(state.should_send_heartbeat(), "Should send after interval + jitter");
}

#[test]
fn test_heartbeat_sequence_increments() {
    let config = HeartbeatConfig::with_interval(1000).unwrap();
    let state = HeartbeatState::new(config);

    let seq1 = state.record_send();
    let seq2 = state.record_send();
    let seq3 = state.record_send();

    assert_eq!(seq1.0, 0, "First sequence should be 0");
    assert_eq!(seq2.0, 1, "Second sequence should be 1");
    assert_eq!(seq3.0, 2, "Third sequence should be 2");
}

#[test]
fn test_heartbeat_jitter_prevents_synchronization() {
    let config = HeartbeatConfig::with_interval(100).unwrap();

    // Create multiple states and measure their intervals
    let mut intervals = vec![];

    for _ in 0..10 {
        let state = HeartbeatState::new(config.clone());
        state.record_send();

        let start = Instant::now();
        while !state.should_send_heartbeat() {
            thread::sleep(Duration::from_millis(1));
            if start.elapsed() > Duration::from_millis(300) {
                break; // Timeout
            }
        }

        intervals.push(start.elapsed().as_millis());
    }

    // Verify there's variation in intervals (jitter is working)
    let min_interval = intervals.iter().min().unwrap();
    let max_interval = intervals.iter().max().unwrap();

    assert!(max_interval - min_interval > 50,
        "Jitter should cause variation in intervals (min: {}, max: {})",
        min_interval, max_interval);
}

// ============================================================================
// Response Handling and RTT Tests
// ============================================================================

#[test]
fn test_response_updates_rtt() {
    let config = HeartbeatConfig::default_config();
    let state = HeartbeatState::new(config);

    let send_time = Instant::now();
    thread::sleep(Duration::from_millis(50));

    state.record_response(HeartbeatSequence(0), send_time);

    let rtt = state.current_rtt();
    let rtt_ms = rtt.as_millis();

    assert!(rtt_ms >= 50 && rtt_ms < 100,
        "RTT should be approximately 50ms, got {}ms", rtt_ms);
}

#[test]
fn test_response_resets_consecutive_failures() {
    let config = HeartbeatConfig::default_config();
    let state = HeartbeatState::new(config);

    // Simulate failures
    state.consecutive_failures.store(5, Ordering::SeqCst);

    // Record response
    state.record_response(HeartbeatSequence(0), Instant::now());

    assert_eq!(state.consecutive_failures(), 0,
        "Response should reset consecutive failures to 0");
}

#[test]
fn test_multiple_responses_update_rtt_progressively() {
    let config = HeartbeatConfig::default_config();
    let state = HeartbeatState::new(config);

    // First response: 10ms RTT
    let send_time1 = Instant::now();
    thread::sleep(Duration::from_millis(10));
    state.record_response(HeartbeatSequence(0), send_time1);
    let rtt1 = state.current_rtt().as_millis();

    // Second response: 50ms RTT
    let send_time2 = Instant::now();
    thread::sleep(Duration::from_millis(50));
    state.record_response(HeartbeatSequence(1), send_time2);
    let rtt2 = state.current_rtt().as_millis();

    assert!(rtt2 > rtt1, "Second RTT should be larger than first");
}

// ============================================================================
// Timeout Detection Tests
// ============================================================================

#[test]
fn test_timeout_detection_after_timeout_period() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 100, // 100ms for testing
        max_consecutive_failures: 3,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Should not timeout immediately
    assert!(state.check_timeout().is_ok(), "Should not timeout immediately");

    // Wait for timeout
    thread::sleep(Duration::from_millis(150));

    // Should detect timeout
    assert!(state.check_timeout().is_err(), "Should detect timeout after timeout_ms");
}

#[test]
fn test_no_timeout_before_timeout_period() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 200,
        max_consecutive_failures: 3,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait partial timeout
    thread::sleep(Duration::from_millis(100));

    assert!(state.check_timeout().is_ok(), "Should not timeout before timeout_ms");
}

#[test]
fn test_consecutive_failures_increment() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 50,
        max_consecutive_failures: 5,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    for expected_failures in 1..=4 {
        thread::sleep(Duration::from_millis(60));
        let result = state.check_timeout();
        assert!(result.is_err(), "Timeout should be detected");
        assert_eq!(state.consecutive_failures(), expected_failures,
            "Consecutive failures should be {}", expected_failures);
        assert!(state.is_alive(), "Connection should still be alive");
    }
}

#[test]
fn test_connection_dead_after_max_failures() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 50,
        max_consecutive_failures: 3,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // First two failures - connection still alive
    for _ in 0..2 {
        thread::sleep(Duration::from_millis(60));
        let _ = state.check_timeout();
        assert!(state.is_alive(), "Connection should be alive before max failures");
    }

    // Third failure - connection dead
    thread::sleep(Duration::from_millis(60));
    let result = state.check_timeout();

    assert!(result.is_err(), "Should detect timeout");
    assert_eq!(state.consecutive_failures(), 3);
    assert!(!state.is_alive(), "Connection should be dead after max failures");

    match result {
        Err(HeartbeatError::ConnectionDead { consecutive_failures }) => {
            assert_eq!(consecutive_failures, 3);
        }
        _ => panic!("Expected ConnectionDead error"),
    }
}

// ============================================================================
// Heartbeat Suppression Tests
// ============================================================================

#[test]
fn test_data_packet_resets_timeout_window() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 100,
        max_consecutive_failures: 3,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait partial timeout
    thread::sleep(Duration::from_millis(60));

    // Record data packet (should reset timeout window)
    state.record_data_packet();

    // Wait more (would timeout if data packet didn't reset)
    thread::sleep(Duration::from_millis(60));

    assert!(state.check_timeout().is_ok(),
        "Data packet should reset timeout window");
}

#[test]
fn test_suppression_disabled() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 100,
        max_consecutive_failures: 3,
        jitter_ms: 10,
        enable_suppression: false, // Disabled
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    // Wait partial timeout
    thread::sleep(Duration::from_millis(60));

    // Record data packet (should NOT reset since suppression disabled)
    state.record_data_packet();

    // Wait more
    thread::sleep(Duration::from_millis(60));

    assert!(state.check_timeout().is_err(),
        "Data packet should not reset timeout when suppression disabled");
}

#[test]
fn test_multiple_data_packets_extend_timeout() {
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 80,
        max_consecutive_failures: 3,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let state = HeartbeatState::new(config);

    state.record_send();

    for _ in 0..5 {
        thread::sleep(Duration::from_millis(50));
        state.record_data_packet(); // Reset timeout each time
        assert!(state.check_timeout().is_ok(), "Should not timeout with data packets");
    }
}

// ============================================================================
// HeartbeatEngine Tests
// ============================================================================

#[test]
fn test_engine_creation_with_defaults() {
    let session_id = SessionId::new(42);
    let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

    assert!(engine.is_alive(), "Engine should be alive initially");
    assert_eq!(engine.consecutive_failures(), 0);
    assert_eq!(engine.config().interval_ms.as_millis(), 30000);
}

#[test]
fn test_engine_creation_with_custom_config() {
    let session_id = SessionId::new(42);
    let config = HeartbeatConfig::with_interval(15000).unwrap();
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    assert_eq!(engine.config().interval_ms.as_millis(), 15000);
}

#[test]
fn test_engine_invalid_config_rejected() {
    let session_id = SessionId::new(42);
    let mut config = HeartbeatConfig::with_interval(10000).unwrap();
    config.max_consecutive_failures = 0; // Invalid

    let result = HeartbeatEngine::new(session_id, config);
    assert!(result.is_err(), "Invalid config should be rejected");
}

#[test]
fn test_engine_should_send_first_heartbeat() {
    let session_id = SessionId::new(42);
    let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

    assert!(engine.should_send(), "Should send first heartbeat immediately");
}

#[test]
fn test_engine_generate_heartbeat() {
    let session_id = SessionId::new(42);
    let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

    let (sequence, rtt) = engine.generate_heartbeat().unwrap();

    assert_eq!(sequence.0, 0, "First sequence should be 0");
    assert!(rtt.as_nanos() > 0, "RTT should be non-zero");
}

#[test]
fn test_engine_generate_increments_sequence() {
    let session_id = SessionId::new(42);
    let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

    let (seq1, _) = engine.generate_heartbeat().unwrap();
    let (seq2, _) = engine.generate_heartbeat().unwrap();
    let (seq3, _) = engine.generate_heartbeat().unwrap();

    assert_eq!(seq1.0, 0);
    assert_eq!(seq2.0, 1);
    assert_eq!(seq3.0, 2);
}

#[test]
fn test_engine_process_response_updates_rtt() {
    let session_id = SessionId::new(42);
    let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

    let send_time = Instant::now();
    thread::sleep(Duration::from_millis(25));

    let rtt = engine.process_response(HeartbeatSequence(0), send_time).unwrap();

    assert!(rtt.as_millis() >= 25, "RTT should be at least 25ms");
}

#[test]
fn test_engine_on_data_packet() {
    let session_id = SessionId::new(42);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 100,
        max_consecutive_failures: 3,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    engine.generate_heartbeat().unwrap();
    thread::sleep(Duration::from_millis(60));

    engine.on_data_packet(); // Should reset timeout

    thread::sleep(Duration::from_millis(60));

    assert!(engine.check_keepalive().is_ok(), "Data packet should prevent timeout");
}

#[test]
fn test_engine_reset_clears_state() {
    let session_id = SessionId::new(42);
    let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

    // Generate heartbeats and simulate failures
    engine.generate_heartbeat().unwrap();
    engine.state.consecutive_failures.store(2, Ordering::SeqCst);

    // Reset
    engine.reset();

    // State should be cleared
    assert_eq!(engine.consecutive_failures(), 0);
    assert!(engine.is_alive());
}

#[test]
fn test_engine_cannot_generate_when_dead() {
    let session_id = SessionId::new(42);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 50,
        max_consecutive_failures: 1,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    engine.generate_heartbeat().unwrap();

    // Wait for connection to die
    thread::sleep(Duration::from_millis(60));
    let _ = engine.check_keepalive(); // Trigger death

    assert!(!engine.is_alive(), "Connection should be dead");

    // Should not be able to generate heartbeat
    let result = engine.generate_heartbeat();
    assert!(result.is_err(), "Should not generate heartbeat when dead");
}

// ============================================================================
// Integration and Edge Case Tests
// ============================================================================

#[test]
fn test_rapid_heartbeat_generation() {
    let session_id = SessionId::new(42);
    let engine = HeartbeatEngine::with_defaults(session_id).unwrap();

    // Generate many heartbeats rapidly
    for i in 0..100 {
        let (sequence, _) = engine.generate_heartbeat().unwrap();
        assert_eq!(sequence.0, i as u32, "Sequence should increment correctly");
    }
}

#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;

    let session_id = SessionId::new(42);
    let engine = Arc::new(HeartbeatEngine::with_defaults(session_id).unwrap());

    let engine_clone = engine.clone();
    let generate_handle = thread::spawn(move || {
        for _ in 0..50 {
            let _ = engine_clone.generate_heartbeat();
            thread::sleep(Duration::from_micros(100));
        }
    });

    let engine_clone = engine.clone();
    let check_handle = thread::spawn(move || {
        for _ in 0..50 {
            let _ = engine_clone.check_keepalive();
            thread::sleep(Duration::from_micros(100));
        }
    });

    generate_handle.join().unwrap();
    check_handle.join().unwrap();

    assert!(engine.is_alive(), "Engine should survive concurrent operations");
}

#[test]
fn test_recovery_after_reset() {
    let session_id = SessionId::new(42);
    let config = HeartbeatConfig {
        interval_ms: HeartbeatInterval::new(1000),
        timeout_ms: 50,
        max_consecutive_failures: 2,
        jitter_ms: 10,
        enable_suppression: true,
        negotiated: false,
    };
    let engine = HeartbeatEngine::new(session_id, config).unwrap();

    // Kill the connection
    engine.generate_heartbeat().unwrap();
    thread::sleep(Duration::from_millis(60));
    let _ = engine.check_keepalive();
    thread::sleep(Duration::from_millis(60));
    let _ = engine.check_keepalive();

    assert!(!engine.is_alive(), "Connection should be dead");

    // Reset
    engine.reset();

    // Should be able to generate heartbeats again
    assert!(engine.is_alive(), "Connection should be alive after reset");
    let result = engine.generate_heartbeat();
    assert!(result.is_ok(), "Should generate heartbeat after reset");
}
