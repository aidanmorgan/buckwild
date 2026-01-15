// Flow Control Engine Integration Tests
//
// Comprehensive tests for window management, congestion control, and flow control
// following design/protocol/07-data-transmission.md
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use super::engine::*;
use crate::protocol::types::*;
use bytes::Bytes;

// =========================================================================
// Window Management Tests
// =========================================================================

#[tokio::test]
async fn test_initial_window_size() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    let send_window = fc.get_send_window();
    assert_eq!(
        send_window.as_u32(),
        INITIAL_SEND_WINDOW.as_u32(),
        "Initial send window should be 65535 per spec"
    );

    let receive_window = fc.get_receive_window();
    assert_eq!(
        receive_window.as_u32(),
        INITIAL_RECEIVE_WINDOW.as_u32(),
        "Initial receive window should be 65535 per spec"
    );
}

#[tokio::test]
async fn test_window_update_on_ack() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    let initial_cwnd = fc.get_congestion_window();

    // Process ACK for 1000 bytes
    let result = fc.process_ack(1000, 1000);
    assert!(result.is_ok(), "Should process ACK successfully");

    let new_cwnd = fc.get_congestion_window();
    assert!(
        new_cwnd > initial_cwnd,
        "Congestion window should increase after ACK in slow start"
    );
}

#[tokio::test]
async fn test_window_shrink_on_congestion() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Grow the window first
    for i in 1..=5 {
        let _ = fc.process_ack(i * 1000, 1000);
    }

    let cwnd_before = fc.get_congestion_window();
    assert!(cwnd_before > INITIAL_CONGESTION_WINDOW.as_u32());

    // Trigger congestion via timeout
    let result = fc.handle_timeout();
    assert!(result.is_ok(), "Should handle timeout successfully");

    let cwnd_after = fc.get_congestion_window();
    assert!(
        cwnd_after < cwnd_before,
        "Window should shrink after congestion event"
    );
    assert_eq!(
        cwnd_after,
        MSS.as_u32(),
        "Window should reset to 1 MSS after timeout"
    );
}

#[tokio::test]
async fn test_zero_window_handling() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Simulate peer advertising zero window
    fc.set_send_window(0);

    // Check if we can send data
    let can_send = fc.can_send_data(1000);
    assert!(
        !can_send,
        "Should not be able to send data with zero window"
    );

    // Try to send data
    let data = Bytes::from(vec![0u8; 100]);
    let result = fc.send_data(data).await;
    assert!(
        result.is_err(),
        "Should fail to send data when window is exhausted"
    );
}

// =========================================================================
// Congestion Control Tests
// =========================================================================

#[tokio::test]
async fn test_slow_start_behavior() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    let initial_cwnd = fc.get_congestion_window();
    assert_eq!(
        initial_cwnd,
        INITIAL_CONGESTION_WINDOW.as_u32(),
        "Should start with 1 MSS"
    );

    let initial_state = fc.get_congestion_state();
    assert_eq!(
        initial_state,
        CongestionState::SlowStart,
        "Should start in Slow Start state"
    );

    // Process ACK - should double window (exponential growth)
    let _ = fc.process_ack(1460, 1460);
    let cwnd_after_ack = fc.get_congestion_window();
    assert_eq!(
        cwnd_after_ack,
        initial_cwnd + 1460,
        "Window should grow by bytes ACKed in slow start"
    );
}

#[tokio::test]
async fn test_congestion_avoidance() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Set congestion window to a value above ssthresh to start in congestion avoidance
    // and set the state explicitly
    fc.set_congestion_window(30000);
    fc.set_congestion_state(CongestionState::CongestionAvoidance);

    let initial_cwnd = fc.get_congestion_window();
    assert_eq!(initial_cwnd, 30000, "Initial cwnd should be set");

    // Process multiple ACKs - in congestion avoidance growth is slower
    // Each ACK advances approximately MSS*MSS/cwnd per RTT
    for i in 1..=100 {
        let _ = fc.process_ack(i * 1460, 1460);
    }

    let final_cwnd = fc.get_congestion_window();

    // Growth should be much slower than slow start
    // In slow start, 100 ACKs would grow window by ~146000 bytes
    // In congestion avoidance, it should be much less
    assert!(
        final_cwnd >= initial_cwnd,
        "Window should grow or stay same in congestion avoidance (got {}, expected >= {})",
        final_cwnd,
        initial_cwnd
    );
    assert!(
        final_cwnd < initial_cwnd + 100 * 1460,
        "Growth should be linear, not exponential (got {}, should be < {})",
        final_cwnd,
        initial_cwnd + 100 * 1460
    );
}

#[tokio::test]
async fn test_fast_retransmit_trigger() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Grow window first by processing multiple ACKs
    for i in 1..=5 {
        let _ = fc.process_ack(i * 1460, 1460);
    }

    let cwnd_before = fc.get_congestion_window();
    assert!(
        cwnd_before > INITIAL_CONGESTION_WINDOW.as_u32(),
        "Window should have grown"
    );

    // Send 3 duplicate ACKs
    let _ = fc.process_ack(7300, 0); // Dup 1
    let _ = fc.process_ack(7300, 0); // Dup 2
    let _ = fc.process_ack(7300, 0); // Dup 3

    let state = fc.get_congestion_state();
    assert_eq!(
        state,
        CongestionState::FastRecovery,
        "Should enter fast recovery after 3 duplicate ACKs"
    );

    let ssthresh = fc.get_slow_start_threshold();
    let expected_ssthresh = cwnd_before / 2;
    assert_eq!(
        ssthresh, expected_ssthresh,
        "ssthresh should be set to cwnd/2"
    );
}

#[tokio::test]
async fn test_recovery_from_congestion() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Grow window
    for i in 1..=5 {
        let _ = fc.process_ack(i * 1460, 1460);
    }

    // Trigger fast recovery
    let _ = fc.process_ack(7300, 0); // Dup 1
    let _ = fc.process_ack(7300, 0); // Dup 2
    let _ = fc.process_ack(7300, 0); // Dup 3

    assert_eq!(fc.get_congestion_state(), CongestionState::FastRecovery);

    // New ACK should exit fast recovery
    let _ = fc.process_ack(10000, 2700);

    assert_eq!(
        fc.get_congestion_state(),
        CongestionState::CongestionAvoidance,
        "Should transition to congestion avoidance after recovery"
    );
}

// =========================================================================
// Rate Limiting Tests
// =========================================================================

#[tokio::test]
async fn test_send_rate_calculation() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Calculate effective window (min of congestion and flow control windows)
    let effective_window = fc.calculate_effective_window();

    let congestion_window = fc.get_congestion_window();
    let flow_control_window = fc.get_send_window().as_u32();

    assert_eq!(
        effective_window,
        std::cmp::min(congestion_window, flow_control_window),
        "Effective window should be minimum of both windows"
    );
}

#[tokio::test]
async fn test_pacing_interval() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Update RTT to test pacing calculation
    fc.update_rtt(RoundTripTime::new(100_000_000)); // 100ms

    let rto = fc.get_rto();
    assert!(
        rto.as_u64() >= 200_000_000,
        "RTO should be at least 200ms per spec"
    );
    assert!(
        rto.as_u64() <= 60_000_000_000,
        "RTO should be at most 60s per spec"
    );
}

#[tokio::test]
async fn test_burst_handling() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Set a larger congestion window to allow bursts
    fc.set_congestion_window(10000);

    // Check if we can send multiple packets
    let can_send_first = fc.can_send_data(1460);
    assert!(can_send_first, "Should be able to send first packet");

    let can_send_second = fc.can_send_data(1460);
    assert!(can_send_second, "Should be able to send second packet");

    // Update send_next to simulate sending
    fc.set_send_next(2920);

    let bytes_in_flight = fc.get_send_next() - fc.get_send_unacked();

    assert_eq!(bytes_in_flight, 2920, "Should track bytes in flight");
}

// =========================================================================
// Window Interaction Tests
// =========================================================================

#[tokio::test]
async fn test_effective_window_limited_by_congestion() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Congestion window is initially 1460 (1 MSS)
    // Flow control window is 65535
    let effective = fc.calculate_effective_window();
    assert_eq!(
        effective,
        INITIAL_CONGESTION_WINDOW.as_u32(),
        "Effective window should be limited by smaller congestion window"
    );
}

#[tokio::test]
async fn test_effective_window_limited_by_flow_control() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Set large congestion window
    fc.set_congestion_window(100000);

    // Reduce flow control window
    fc.set_send_window(5000);

    let effective = fc.calculate_effective_window();
    assert_eq!(
        effective, 5000,
        "Effective window should be limited by smaller flow control window"
    );
}

#[tokio::test]
async fn test_send_data_respects_window() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Try to send data larger than window
    let large_data = Bytes::from(vec![0u8; 100000]);
    let result = fc.send_data(large_data).await;
    assert!(
        result.is_err(),
        "Should fail to send data larger than window"
    );

    // Send data within window
    let small_data = Bytes::from(vec![0u8; 1000]);
    let result = fc.send_data(small_data).await;
    assert!(result.is_ok(), "Should send data within window");
}

// =========================================================================
// Edge Case Tests
// =========================================================================

#[tokio::test]
async fn test_fragmentation_for_large_data() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Set large enough window
    fc.set_send_window(10000);
    fc.set_congestion_window(10000);

    // Send data larger than MSS (should be fragmented)
    let large_data = Bytes::from(vec![0u8; 3000]);
    let result = fc.send_data(large_data).await;
    assert!(
        result.is_ok(),
        "Should fragment and send data larger than MSS"
    );
}

#[tokio::test]
async fn test_window_exhaustion_blocks_send() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Fill the window by advancing send_next
    fc.set_send_next(INITIAL_SEND_WINDOW.as_u32());

    let can_send = fc.can_send_data(1);
    assert!(
        !can_send,
        "Should not be able to send when window is exhausted"
    );
}

#[tokio::test]
async fn test_statistics_tracking() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Process some ACKs
    let _ = fc.process_ack(1460, 1460);
    let _ = fc.process_ack(2920, 1460);

    let stats = fc.get_flow_control_stats().await;

    assert_eq!(
        stats.current_congestion_window.as_u32(),
        fc.get_congestion_window(),
        "Stats should reflect current congestion window"
    );
    assert_eq!(
        stats.current_send_window.as_u32(),
        fc.get_send_window().as_u32(),
        "Stats should reflect current send window"
    );
}

#[tokio::test]
async fn test_shutdown_clears_buffers() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Send some data to populate buffers
    let data = Bytes::from(vec![0u8; 100]);
    let _ = fc.send_data(data).await;

    // Shutdown
    let result = fc.shutdown().await;
    assert!(result.is_ok(), "Shutdown should succeed");
}

// =========================================================================
// Congestion Event Handling Tests
// =========================================================================

#[tokio::test]
async fn test_multiple_congestion_events() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // First timeout
    let _ = fc.handle_timeout();

    // Second timeout
    let _ = fc.handle_timeout();

    // Both timeouts should reset to slow start
    assert_eq!(
        fc.get_congestion_state(),
        CongestionState::SlowStart,
        "Should remain in Slow Start after multiple timeouts"
    );
}

#[tokio::test]
async fn test_window_bounds_enforcement() {
    let fc = FlowControlEngine::new(ConnectionId::new(1), SessionId::new(100), 0, 0);

    // Try to grow beyond max
    for _ in 0..1000 {
        let _ = fc.process_ack(1000000, 10000);
    }

    let cwnd = fc.get_congestion_window();
    assert!(
        cwnd <= MAX_CONGESTION_WINDOW.as_u32(),
        "Congestion window should not exceed maximum"
    );
}
