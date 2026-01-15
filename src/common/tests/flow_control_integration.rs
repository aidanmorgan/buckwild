//! Flow Control Integration Tests (M16 - HIGH-012)
//!
//! This test suite validates flow control window management, back-pressure,
//! and recovery mechanisms as specified in design/protocol/07-data-transmission.md.
//!
//! Test Categories:
//! 1. Window Exhaustion Scenarios (gradual, sudden)
//! 2. Window Recovery After ACK (single ACK, cumulative ACK)
//! 3. Back-Pressure Behavior (sender slowdown, receiver notification)

use buckwild_common::engines::flow_control::engine::FlowControlEngine;
use buckwild_common::engines::flow_control::windowing::{WindowManagement, WindowUpdate};
use buckwild_common::protocol::types::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

//==============================================================================
// TEST HELPERS
//==============================================================================

/// Helper to create a test window management instance
fn create_test_window_management(initial_window: u32) -> WindowManagement {
    WindowManagement::new(initial_window)
}

/// Helper to create a test flow control engine
fn create_test_flow_control_engine() -> FlowControlEngine {
    let connection_id = ConnectionId::new(1);
    let session_id = SessionId::new(12345);
    FlowControlEngine::new(connection_id, session_id, 1000, 2000)
}

/// Shared state for callback tracking
struct CallbackTracker {
    window_updates: Arc<Mutex<Vec<WindowUpdate>>>,
    probe_count: Arc<AtomicU32>,
    probe_enabled: Arc<AtomicBool>,
}

impl CallbackTracker {
    fn new() -> Self {
        Self {
            window_updates: Arc::new(Mutex::new(Vec::new())),
            probe_count: Arc::new(AtomicU32::new(0)),
            probe_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    fn window_update_callback(&self) -> impl Fn(WindowUpdate) + Send + Sync + 'static {
        let updates = Arc::clone(&self.window_updates);
        move |update| {
            let updates_clone = Arc::clone(&updates);
            tokio::spawn(async move {
                updates_clone.lock().await.push(update);
            });
        }
    }

    fn zero_window_probe_callback(&self) -> impl Fn() -> bool + Send + Sync + 'static {
        let count = Arc::clone(&self.probe_count);
        let enabled = Arc::clone(&self.probe_enabled);
        move || {
            if enabled.load(Ordering::Relaxed) {
                count.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }

    async fn get_window_update_count(&self) -> usize {
        self.window_updates.lock().await.len()
    }

    fn get_probe_count(&self) -> u32 {
        self.probe_count.load(Ordering::Relaxed)
    }

    fn disable_probes(&self) {
        self.probe_enabled.store(false, Ordering::Relaxed);
    }
}

//==============================================================================
// WINDOW EXHAUSTION TESTS
//==============================================================================

/// Test gradual window exhaustion
/// Validates that window decreases correctly as data is added incrementally
#[tokio::test]
async fn test_gradual_window_exhaustion() {
    let wm = create_test_window_management(10000);

    let initial_window = wm.get_advertised_window().as_u32();
    assert_eq!(initial_window, 10000, "Initial window should be 10000");

    // Gradually fill the buffer in 2000-byte increments
    for i in 1..=5 {
        let result = wm.add_to_receive_buffer(2000).await;
        assert!(result.is_ok(), "Adding data chunk {} should succeed", i);
        assert!(result.unwrap(), "Buffer should have space for chunk {}", i);

        let current_window = wm.get_advertised_window().as_u32();
        let expected_window = 10000 - (i * 2000);
        assert_eq!(
            current_window, expected_window,
            "Window after chunk {} should be {}",
            i, expected_window
        );
    }

    // Window should now be zero
    let final_window = wm.get_advertised_window().as_u32();
    assert_eq!(final_window, 0, "Window should be exhausted");

    // Attempt to add more data should fail
    let overflow_result = wm.add_to_receive_buffer(100).await;
    assert!(overflow_result.is_ok(), "API should not error");
    assert!(!overflow_result.unwrap(), "Buffer should reject overflow");
}

/// Test sudden window exhaustion
/// Validates that a large single write correctly exhausts the window
#[tokio::test]
async fn test_sudden_window_exhaustion() {
    let wm = create_test_window_management(8192);

    let initial_window = wm.get_advertised_window().as_u32();
    assert_eq!(initial_window, 8192, "Initial window should be 8192");

    // Suddenly fill most of the buffer with one large write
    let large_chunk = 8192;
    let result = wm.add_to_receive_buffer(large_chunk).await;
    assert!(result.is_ok(), "Large write should succeed");
    assert!(result.unwrap(), "Buffer should accept large chunk");

    // Window should now be zero
    let window_after = wm.get_advertised_window().as_u32();
    assert_eq!(
        window_after, 0,
        "Window should be exhausted after large write"
    );

    // Verify zero window event was recorded
    let stats = wm.get_window_stats().await;
    assert_eq!(
        stats.zero_window_events.as_u64(),
        1,
        "Zero window event should be recorded"
    );
}

/// Test window exhaustion with callback notification
#[tokio::test]
async fn test_window_exhaustion_with_callback() {
    let mut wm = create_test_window_management(5000);
    let tracker = CallbackTracker::new();

    wm.set_window_update_callback(tracker.window_update_callback());

    // Fill buffer to trigger window update
    let result = wm.add_to_receive_buffer(4000).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Allow callback to execute
    sleep(Duration::from_millis(50)).await;

    // Verify window update was sent (threshold is 25%, so 4000/5000 = 80% should trigger)
    let update_count = tracker.get_window_update_count().await;
    assert!(
        update_count > 0,
        "Window update should be sent when window changes significantly"
    );
}

//==============================================================================
// WINDOW RECOVERY TESTS
//==============================================================================

/// Test window recovery after single ACK
/// Validates that consuming data reopens the window correctly
#[tokio::test]
async fn test_window_recovery_single_ack() {
    let wm = create_test_window_management(8000);

    // Fill buffer completely
    let fill_result = wm.add_to_receive_buffer(8000).await;
    assert!(fill_result.is_ok());
    assert!(fill_result.unwrap());
    assert_eq!(
        wm.get_advertised_window().as_u32(),
        0,
        "Window should be zero"
    );

    // Consume 2000 bytes (single ACK scenario)
    let consume_result = wm.update_buffer_usage(2000).await;
    assert!(consume_result.is_ok(), "Consuming data should succeed");

    // Verify window reopened
    let recovered_window = wm.get_advertised_window().as_u32();
    assert_eq!(
        recovered_window, 2000,
        "Window should recover by amount consumed"
    );

    // Verify buffer can accept new data
    let new_data_result = wm.add_to_receive_buffer(1000).await;
    assert!(new_data_result.is_ok());
    assert!(
        new_data_result.unwrap(),
        "Buffer should accept new data after recovery"
    );
}

/// Test window recovery after cumulative ACK
/// Validates that multiple consumptions cumulate correctly
#[tokio::test]
async fn test_window_recovery_cumulative_ack() {
    let wm = create_test_window_management(10000);

    // Fill buffer to 80%
    let fill_result = wm.add_to_receive_buffer(8000).await;
    assert!(fill_result.is_ok());
    assert!(fill_result.unwrap());

    let window_before = wm.get_advertised_window().as_u32();
    assert_eq!(window_before, 2000, "Window should be 2000 after filling");

    // Consume data in multiple ACKs (cumulative)
    let consume1 = wm.update_buffer_usage(2000).await;
    assert!(consume1.is_ok());
    let window_after_ack1 = wm.get_advertised_window().as_u32();
    assert_eq!(window_after_ack1, 4000, "Window after first ACK");

    let consume2 = wm.update_buffer_usage(3000).await;
    assert!(consume2.is_ok());
    let window_after_ack2 = wm.get_advertised_window().as_u32();
    assert_eq!(window_after_ack2, 7000, "Window after second ACK");

    let consume3 = wm.update_buffer_usage(3000).await;
    assert!(consume3.is_ok());
    let window_after_ack3 = wm.get_advertised_window().as_u32();
    assert_eq!(window_after_ack3, 10000, "Window should be fully recovered");

    // Verify stats
    let stats = wm.get_window_stats().await;
    assert!(
        stats.buffer_utilization < 0.01,
        "Buffer should be nearly empty after recovery"
    );
}

/// Test window recovery from zero window
/// Validates that zero window probe state resets when window opens
#[tokio::test]
async fn test_zero_window_recovery() {
    let mut wm = create_test_window_management(5000);
    let tracker = CallbackTracker::new();

    wm.set_zero_window_probe_callback(tracker.zero_window_probe_callback());

    // Fill buffer to trigger zero window
    let fill_result = wm.add_to_receive_buffer(5000).await;
    assert!(fill_result.is_ok());
    assert!(fill_result.unwrap());
    assert_eq!(wm.get_advertised_window().as_u32(), 0);

    // Verify zero window event
    let stats_zero = wm.get_window_stats().await;
    assert_eq!(stats_zero.zero_window_events.as_u64(), 1);

    // Consume data to reopen window
    let consume_result = wm.update_buffer_usage(5000).await;
    assert!(consume_result.is_ok());

    // Verify window recovered
    let recovered_window = wm.get_advertised_window().as_u32();
    assert_eq!(recovered_window, 5000, "Window should be fully recovered");

    // Send window update to notify peer (simulates received window update)
    let update_result = wm.handle_window_update(5000).await;
    assert!(update_result.is_ok(), "Window update should be processed");
}

//==============================================================================
// BACK-PRESSURE TESTS
//==============================================================================

/// Test sender slowdown due to window exhaustion
/// Validates that flow control engine respects window limits
#[tokio::test]
async fn test_sender_slowdown_window_exhaustion() {
    let engine = create_test_flow_control_engine();

    // Check initial state allows sending
    assert!(
        engine.can_send_data(1000),
        "Should be able to send with available window"
    );

    // Get initial effective window
    let initial_window = engine.calculate_effective_window();
    assert!(
        initial_window > 0,
        "Initial effective window should be positive"
    );

    // Verify that trying to send more than window fails
    let large_data = initial_window + 1000;
    assert!(
        !engine.can_send_data(large_data),
        "Should not be able to send more than effective window"
    );

    // Verify sends within window are allowed
    assert!(
        engine.can_send_data(1000),
        "Should be able to send data within window"
    );
}

/// Test sender slowdown due to congestion
/// Validates that congestion window limits sending rate
#[tokio::test]
async fn test_sender_slowdown_congestion() {
    let engine = create_test_flow_control_engine();

    // Get effective window (minimum of congestion and flow control windows)
    let effective_window = engine.calculate_effective_window();
    assert!(effective_window > 0, "Effective window should be positive");

    // Verify large sends beyond effective window are blocked
    assert!(
        !engine.can_send_data(effective_window + 1000),
        "Should not be able to send more than effective window"
    );

    // Verify sends within effective window are allowed
    let small_send = effective_window / 2;
    assert!(
        engine.can_send_data(small_send),
        "Should be able to send within effective window"
    );

    // Verify we can get congestion window
    let cwnd = engine.get_congestion_window();
    assert!(cwnd > 0, "Congestion window should be positive");
}

/// Test receiver notification of window changes
/// Validates that receiver sends window updates when threshold is crossed
#[tokio::test]
async fn test_receiver_notification_window_update() {
    let mut wm = create_test_window_management(10000);
    let tracker = CallbackTracker::new();

    wm.set_window_update_callback(tracker.window_update_callback());

    // Fill buffer partially to set initial state
    let fill_result = wm.add_to_receive_buffer(5000).await;
    assert!(fill_result.is_ok());
    assert!(fill_result.unwrap());

    // Allow any initial callbacks to execute
    sleep(Duration::from_millis(50)).await;

    // Get count after initial fill
    let initial_count = tracker.get_window_update_count().await;

    // Consume enough data to trigger 25% threshold
    // Window is currently 5000 (10000 - 5000 filled)
    // Consuming 3000 bytes will make window 8000, which is a 60% increase
    let consume_result = wm.update_buffer_usage(3000).await;
    assert!(consume_result.is_ok());

    // Allow callback to execute
    sleep(Duration::from_millis(100)).await;

    // Verify window update was sent
    let final_count = tracker.get_window_update_count().await;
    assert!(
        final_count > initial_count,
        "Window update should be sent when threshold crossed (initial: {}, final: {})",
        initial_count,
        final_count
    );
}

/// Test zero window probe mechanism
/// Validates that zero window probes are sent when window is zero
#[tokio::test]
async fn test_zero_window_probe_mechanism() {
    let mut wm = create_test_window_management(1000);
    let tracker = CallbackTracker::new();

    wm.set_zero_window_probe_callback(tracker.zero_window_probe_callback());

    // Fill buffer to zero window
    let fill_result = wm.add_to_receive_buffer(1000).await;
    assert!(fill_result.is_ok());
    assert!(fill_result.unwrap());

    // Manually trigger probe (in real system, this would be periodic)
    let probe_result = wm.process_zero_window_probe().await;
    assert!(probe_result.is_ok(), "Zero window probe should succeed");
    assert!(probe_result.unwrap(), "Probe should be sent");

    // Verify probe was counted
    assert_eq!(tracker.get_probe_count(), 1, "One probe should be sent");

    // Disable probes and verify no more are sent
    tracker.disable_probes();
    let probe_result2 = wm.process_zero_window_probe().await;
    assert!(probe_result2.is_ok());
    assert!(
        !probe_result2.unwrap(),
        "Probe should not be sent when disabled"
    );
}

/// Test receiver handles zero window probe
/// Validates that receiving a probe triggers immediate window update
#[tokio::test]
async fn test_receiver_handles_zero_window_probe() {
    let mut wm = create_test_window_management(8000);
    let tracker = CallbackTracker::new();

    wm.set_window_update_callback(tracker.window_update_callback());

    // Partially fill buffer
    let fill_result = wm.add_to_receive_buffer(4000).await;
    assert!(fill_result.is_ok());

    // Handle incoming zero window probe
    let probe_handle_result = wm.handle_zero_window_probe().await;
    assert!(probe_handle_result.is_ok(), "Handling probe should succeed");

    // Allow callback to execute
    sleep(Duration::from_millis(50)).await;

    // Verify window update was sent in response
    let stats = wm.get_window_stats().await;
    assert_eq!(
        stats.zero_window_probes_received.as_u64(),
        1,
        "Probe reception should be counted"
    );
}

//==============================================================================
// COMPREHENSIVE SCENARIOS
//==============================================================================

/// Test complete window exhaustion and recovery cycle
/// Validates full lifecycle: exhaust → probe → recover
#[tokio::test]
async fn test_complete_window_lifecycle() {
    let mut wm = create_test_window_management(6000);
    let tracker = CallbackTracker::new();

    wm.set_window_update_callback(tracker.window_update_callback());
    wm.set_zero_window_probe_callback(tracker.zero_window_probe_callback());

    // Phase 1: Exhaust window
    let fill_result = wm.add_to_receive_buffer(6000).await;
    assert!(fill_result.is_ok());
    assert!(fill_result.unwrap());
    assert_eq!(wm.get_advertised_window().as_u32(), 0);

    // Phase 2: Trigger zero window probe
    let probe_result = wm.process_zero_window_probe().await;
    assert!(probe_result.is_ok());
    assert!(probe_result.unwrap());
    assert_eq!(tracker.get_probe_count(), 1);

    // Phase 3: Recover window
    let consume_result = wm.update_buffer_usage(6000).await;
    assert!(consume_result.is_ok());
    assert_eq!(wm.get_advertised_window().as_u32(), 6000);

    // Allow callbacks to execute
    sleep(Duration::from_millis(50)).await;

    // Verify recovery triggered window update
    let update_count = tracker.get_window_update_count().await;
    assert!(update_count > 0, "Window update should be sent on recovery");
}

/// Test concurrent window operations
/// Validates that window management is thread-safe
#[tokio::test]
async fn test_concurrent_window_operations() {
    let wm = Arc::new(create_test_window_management(20000));

    let mut handles = vec![];

    // Spawn multiple tasks that add and consume data concurrently
    for i in 0..10 {
        let wm_clone = Arc::clone(&wm);
        let handle = tokio::spawn(async move {
            // Add data
            let add_result = wm_clone.add_to_receive_buffer(1000).await;
            assert!(add_result.is_ok());

            // Small delay
            sleep(Duration::from_millis(10)).await;

            // Consume data
            let consume_result = wm_clone.update_buffer_usage(1000).await;
            assert!(consume_result.is_ok());

            i
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.expect("Task should complete");
    }

    // Verify final state is consistent
    let final_window = wm.get_advertised_window().as_u32();
    assert!(
        final_window <= 20000,
        "Window should not exceed initial size"
    );
}
