// Congestion Control Tests
//
// Tests verify slow start, congestion avoidance, fast recovery, and timeout handling
// following design/protocol/07-data-transmission.md
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use super::congestion::*;
use crate::protocol::types::*;

// =========================================================================
// Initialization Tests
// =========================================================================

#[test]
fn test_congestion_control_initialization() {
    let cc = CongestionControl::new(1460, 65536);

    assert_eq!(
        cc.get_congestion_window(),
        1460,
        "Initial cwnd should be 1 MSS"
    );
    assert_eq!(
        cc.get_slow_start_threshold(),
        65536,
        "Initial ssthresh should be 64KB"
    );
    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::SlowStart,
        "Should start in Slow Start"
    );
}

// =========================================================================
// Slow Start Tests
// =========================================================================

#[test]
fn test_slow_start_exponential_growth() {
    let cc = CongestionControl::new(1460, 65536);

    // ACK 1460 bytes (1 MSS)
    cc.process_ack(1460, 1460).unwrap();
    assert_eq!(
        cc.get_congestion_window(),
        2920,
        "cwnd should double: 1460 + 1460 = 2920"
    );

    // ACK another 1460 bytes
    cc.process_ack(2920, 1460).unwrap();
    assert_eq!(
        cc.get_congestion_window(),
        4380,
        "cwnd should grow: 2920 + 1460 = 4380"
    );

    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::SlowStart,
        "Should still be in Slow Start"
    );
}

#[test]
fn test_slow_start_transition_to_congestion_avoidance() {
    let cc = CongestionControl::new(1460, 10000); // Low ssthresh for quick transition

    // Grow cwnd past ssthresh
    cc.process_ack(1460, 1460).unwrap(); // cwnd = 2920
    cc.process_ack(2920, 1460).unwrap(); // cwnd = 4380
    cc.process_ack(4380, 1460).unwrap(); // cwnd = 5840
    cc.process_ack(5840, 1460).unwrap(); // cwnd = 7300
    cc.process_ack(7300, 1460).unwrap(); // cwnd = 8760
    cc.process_ack(8760, 1460).unwrap(); // cwnd = 10220

    assert!(
        cc.get_congestion_window() >= 10000,
        "cwnd should have grown past ssthresh"
    );
    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::CongestionAvoidance,
        "Should have transitioned to Congestion Avoidance"
    );
}

// =========================================================================
// Congestion Avoidance Tests
// =========================================================================

#[test]
fn test_congestion_avoidance_linear_growth() {
    let cc = CongestionControl::new(30000, 30000); // Start in congestion avoidance with room to grow

    let initial_cwnd = cc.get_congestion_window();

    // Process ACKs - growth should be linear (much slower than slow start)
    for i in 1..=10 {
        cc.process_ack(i * 1460, 1460).unwrap();
    }

    let final_cwnd = cc.get_congestion_window();

    // In congestion avoidance, cwnd grows by ~MSS per RTT, not per ACK
    // So growth should be much slower than exponential
    assert!(final_cwnd > initial_cwnd, "cwnd should grow");
    assert!(
        final_cwnd < initial_cwnd + 10 * 1460,
        "Growth should be much slower than exponential (not 14600 bytes)"
    );
}

// =========================================================================
// Fast Recovery Tests
// =========================================================================

#[test]
fn test_fast_recovery_on_3_duplicate_acks() {
    let cc = CongestionControl::new(65536, 65536);

    // Send first ACK (this grows cwnd)
    cc.process_ack(10000, 1460).unwrap();
    let cwnd_before_fast_recovery = cc.get_congestion_window();

    // Send 3 duplicate ACKs
    cc.process_ack(10000, 0).unwrap(); // Duplicate 1
    cc.process_ack(10000, 0).unwrap(); // Duplicate 2
    cc.process_ack(10000, 0).unwrap(); // Duplicate 3

    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::FastRecovery,
        "Should enter Fast Recovery after 3 duplicate ACKs"
    );

    let ssthresh = cc.get_slow_start_threshold();
    assert_eq!(
        ssthresh,
        cwnd_before_fast_recovery / 2,
        "ssthresh should be set to cwnd/2 at time of fast recovery"
    );

    let cwnd = cc.get_congestion_window();
    assert_eq!(cwnd, ssthresh + 3 * 1460, "cwnd should be ssthresh + 3*MSS");
}

#[test]
fn test_fast_recovery_window_inflation() {
    let cc = CongestionControl::new(65536, 65536);

    // Enter fast recovery
    cc.process_ack(10000, 1460).unwrap();
    cc.process_ack(10000, 0).unwrap(); // Dup 1
    cc.process_ack(10000, 0).unwrap(); // Dup 2
    cc.process_ack(10000, 0).unwrap(); // Dup 3

    let cwnd_before = cc.get_congestion_window();

    // Additional duplicate ACK should inflate window
    cc.process_ack(10000, 0).unwrap(); // Dup 4

    let cwnd_after = cc.get_congestion_window();
    assert_eq!(
        cwnd_after,
        cwnd_before + 1460,
        "Window should inflate by MSS for each additional dup ACK"
    );
}

#[test]
fn test_fast_recovery_exit_on_new_ack() {
    let cc = CongestionControl::new(65536, 65536);

    // Enter fast recovery
    cc.process_ack(10000, 1460).unwrap();
    cc.process_ack(10000, 0).unwrap();
    cc.process_ack(10000, 0).unwrap();
    cc.process_ack(10000, 0).unwrap();

    assert_eq!(cc.get_congestion_state(), CongestionState::FastRecovery);

    // New ACK should exit fast recovery
    cc.process_ack(12000, 2000).unwrap();

    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::CongestionAvoidance,
        "Should exit to Congestion Avoidance on new ACK"
    );

    let ssthresh = cc.get_slow_start_threshold();
    assert_eq!(
        cc.get_congestion_window(),
        ssthresh,
        "cwnd should be set to ssthresh after exiting fast recovery"
    );
}

// =========================================================================
// Timeout Handling Tests
// =========================================================================

#[test]
fn test_timeout_resets_to_slow_start() {
    let cc = CongestionControl::new(65536, 65536);

    // Grow the window
    for i in 1..=5 {
        cc.process_ack(i * 1460, 1460).unwrap();
    }

    let cwnd_before_timeout = cc.get_congestion_window();
    assert!(cwnd_before_timeout > 1460, "Window should have grown");

    // Timeout
    cc.handle_timeout().unwrap();

    assert_eq!(
        cc.get_congestion_window(),
        1460,
        "cwnd should reset to 1 MSS after timeout"
    );
    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::SlowStart,
        "Should reset to Slow Start after timeout"
    );

    let ssthresh = cc.get_slow_start_threshold();
    assert_eq!(
        ssthresh,
        cwnd_before_timeout / 2,
        "ssthresh should be set to cwnd/2"
    );
}

#[test]
fn test_timeout_from_fast_recovery() {
    let cc = CongestionControl::new(65536, 65536);

    // Enter fast recovery
    cc.process_ack(10000, 1460).unwrap();
    cc.process_ack(10000, 0).unwrap();
    cc.process_ack(10000, 0).unwrap();
    cc.process_ack(10000, 0).unwrap();

    assert_eq!(cc.get_congestion_state(), CongestionState::FastRecovery);

    // Timeout from fast recovery
    cc.handle_timeout().unwrap();

    assert_eq!(
        cc.get_congestion_window(),
        1460,
        "cwnd should reset to 1 MSS"
    );
    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::SlowStart,
        "Should reset to Slow Start"
    );
}

// =========================================================================
// RTT Measurement Tests
// =========================================================================

#[test]
fn test_rtt_measurement_update() {
    let rtt = RttMeasurement::new();

    let initial_srtt = rtt.get_srtt().as_u64();

    // Update with a measurement
    rtt.update_rtt(RoundTripTime::new(50_000_000)); // 50ms

    let new_srtt = rtt.get_srtt().as_u64();
    assert_ne!(
        new_srtt, initial_srtt,
        "SRTT should update after measurement"
    );
}

#[test]
fn test_rtt_rto_calculation() {
    let rtt = RttMeasurement::new();

    // Update with measurements
    rtt.update_rtt(RoundTripTime::new(100_000_000)); // 100ms
    rtt.update_rtt(RoundTripTime::new(120_000_000)); // 120ms

    let rto = rtt.get_rto().as_u64();

    // RTO should be reasonable (not too small, not too large)
    assert!(rto >= 200_000_000, "RTO should be at least 200ms");
    assert!(rto <= 60_000_000_000, "RTO should be at most 60s");
}

// =========================================================================
// Congestion Window Limits Tests
// =========================================================================

#[test]
fn test_cwnd_does_not_exceed_maximum() {
    let cc = CongestionControl::new(1460, 1_048_576); // max_cwnd = 1MB

    // Try to grow beyond max
    for _ in 0..1000 {
        cc.process_ack(1_000_000, 10000).unwrap();
    }

    assert!(
        cc.get_congestion_window() <= 1_048_576,
        "cwnd should not exceed maximum"
    );
}

#[test]
fn test_ssthresh_has_minimum() {
    let cc = CongestionControl::new(4000, 4000);

    // Timeout should set ssthresh to cwnd/2, but not below 2*MSS
    cc.handle_timeout().unwrap();

    let ssthresh = cc.get_slow_start_threshold();
    assert!(ssthresh >= 2 * 1460, "ssthresh should not go below 2*MSS");
}

// =========================================================================
// Edge Case Tests
// =========================================================================

#[test]
fn test_duplicate_ack_count_resets_on_new_ack() {
    let cc = CongestionControl::new(30000, 30000);

    // Send duplicate ACKs
    cc.process_ack(10000, 1460).unwrap();
    cc.process_ack(10000, 0).unwrap(); // Dup 1
    cc.process_ack(10000, 0).unwrap(); // Dup 2

    // New ACK should reset count
    cc.process_ack(12000, 2000).unwrap();

    // Send more duplicates - should need 3 more to trigger fast recovery
    cc.process_ack(12000, 0).unwrap(); // Dup 1
    cc.process_ack(12000, 0).unwrap(); // Dup 2

    assert_eq!(
        cc.get_congestion_state(),
        CongestionState::CongestionAvoidance,
        "Should not be in Fast Recovery yet (count was reset)"
    );
}

#[test]
fn test_old_acks_ignored() {
    let cc = CongestionControl::new(1460, 65536);

    cc.process_ack(10000, 1460).unwrap();
    let cwnd_after_first = cc.get_congestion_window();

    // Try to send an old ACK
    cc.process_ack(5000, 1000).unwrap();

    // cwnd should not change for old ACKs
    assert_eq!(
        cc.get_congestion_window(),
        cwnd_after_first,
        "cwnd should not change for old ACKs"
    );
}
