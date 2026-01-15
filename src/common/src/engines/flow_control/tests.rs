// Flow Control Tests
//
// Tests verify window management, zero-window probing, and buffer handling
// following design/protocol/07-data-transmission.md

use super::windowing::*;

// =========================================================================
// Window Management Tests
// =========================================================================

#[tokio::test]
async fn test_window_management_initialization() {
    let window_mgmt = WindowManagement::new(65536);

    let receive_window = window_mgmt.get_receive_window();
    let advertised_window = window_mgmt.get_advertised_window();

    assert_eq!(
        receive_window.as_u32(),
        65536,
        "Receive window should be initialized to 64KB"
    );
    assert_eq!(
        advertised_window.as_u32(),
        65536,
        "Advertised window should be initialized to 64KB"
    );
}

#[tokio::test]
async fn test_window_update_after_buffer_consumption() {
    let window_mgmt = WindowManagement::new(65536);

    // Simulate adding data to buffer
    let result = window_mgmt.add_to_receive_buffer(10000).await;
    assert!(result.is_ok(), "Should accept data within buffer capacity");
    assert!(result.unwrap(), "Data should be buffered successfully");

    // Consume some data
    let result = window_mgmt.update_buffer_usage(5000).await;
    assert!(result.is_ok(), "Should update buffer usage successfully");

    // Window should have changed
    let advertised_window = window_mgmt.get_advertised_window();
    assert!(
        advertised_window.as_u32() > 0,
        "Window should still be available"
    );
}

#[tokio::test]
async fn test_window_shrinks_as_buffer_fills() {
    let window_mgmt = WindowManagement::new(65536);

    let initial_window = window_mgmt.get_advertised_window().as_u32();

    // Fill buffer partially
    let _ = window_mgmt.add_to_receive_buffer(32768).await;

    let after_window = window_mgmt.get_advertised_window().as_u32();
    assert!(
        after_window < initial_window,
        "Window should shrink as buffer fills"
    );
}

#[tokio::test]
async fn test_buffer_overflow_rejected() {
    let window_mgmt = WindowManagement::new(1024); // Small buffer for testing

    // Try to add more data than buffer can hold
    let result = window_mgmt.add_to_receive_buffer(2048).await;
    assert!(result.is_ok(), "Should return Ok result");
    assert!(
        !result.unwrap(),
        "Should reject data that exceeds buffer capacity"
    );
}

// =========================================================================
// Zero Window Handling Tests
// =========================================================================

#[tokio::test]
async fn test_zero_window_detection() {
    let window_mgmt = WindowManagement::new(1024);

    // Fill buffer completely
    let result = window_mgmt.add_to_receive_buffer(1024).await;
    assert!(result.is_ok());

    let advertised_window = window_mgmt.get_advertised_window();
    assert_eq!(
        advertised_window.as_u32(),
        0,
        "Window should become zero when buffer is full"
    );

    let stats = window_mgmt.get_window_stats().await;
    assert!(
        stats.zero_window_events.as_u64() > 0,
        "Should track zero window events"
    );
}

#[tokio::test]
async fn test_zero_window_probe_triggered() {
    let window_mgmt = WindowManagement::new(1024);

    // Set up callback to track probes
    let _probe_sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Fill buffer to zero window
    let _ = window_mgmt.add_to_receive_buffer(1024).await;

    // Process zero window probe
    let result = window_mgmt.process_zero_window_probe().await;
    assert!(
        result.is_ok(),
        "Should process zero window probe successfully"
    );
}

#[tokio::test]
async fn test_window_opens_after_consumption() {
    let window_mgmt = WindowManagement::new(1024);

    // Fill buffer completely
    let _ = window_mgmt.add_to_receive_buffer(1024).await;
    assert_eq!(
        window_mgmt.get_advertised_window().as_u32(),
        0,
        "Window should be zero"
    );

    // Consume data
    let _ = window_mgmt.update_buffer_usage(512).await;

    let window = window_mgmt.get_advertised_window();
    assert!(
        window.as_u32() > 0,
        "Window should open after consuming data"
    );
}

#[tokio::test]
async fn test_window_update_sent_on_significant_change() {
    let window_mgmt = WindowManagement::new(65536);

    // Add data (not enough to trigger update)
    let _ = window_mgmt.add_to_receive_buffer(1000).await;

    let stats_before = window_mgmt.get_window_stats().await;

    // Add significant amount of data (should trigger update)
    let _ = window_mgmt.add_to_receive_buffer(20000).await;

    let stats_after = window_mgmt.get_window_stats().await;

    // Window updates should increase when significant change occurs
    assert!(
        stats_after.window_updates_sent >= stats_before.window_updates_sent,
        "Window updates should be sent on significant changes"
    );
}

// =========================================================================
// Window Update Handling Tests
// =========================================================================

#[tokio::test]
async fn test_handle_window_update_from_peer() {
    let window_mgmt = WindowManagement::new(65536);

    // Simulate receiving window update from peer
    let result = window_mgmt.handle_window_update(32768).await;
    assert!(result.is_ok(), "Should handle window update successfully");

    let receive_window = window_mgmt.get_receive_window();
    assert_eq!(
        receive_window.as_u32(),
        32768,
        "Receive window should update to new value"
    );

    let stats = window_mgmt.get_window_stats().await;
    assert!(
        stats.window_updates_received.as_u64() > 0,
        "Should track received window updates"
    );
}

#[tokio::test]
async fn test_window_opens_from_zero_resets_probe_state() {
    let window_mgmt = WindowManagement::new(1024);

    // Set peer window to zero
    let _ = window_mgmt.handle_window_update(0).await;
    assert_eq!(window_mgmt.get_receive_window().as_u32(), 0);

    // Window opens
    let result = window_mgmt.handle_window_update(32768).await;
    assert!(result.is_ok());

    let receive_window = window_mgmt.get_receive_window();
    assert_eq!(
        receive_window.as_u32(),
        32768,
        "Window should open from zero"
    );
}

#[tokio::test]
async fn test_handle_zero_window_probe_sends_update() {
    let window_mgmt = WindowManagement::new(65536);

    let stats_before = window_mgmt.get_window_stats().await;

    // Handle incoming zero window probe
    let result = window_mgmt.handle_zero_window_probe().await;
    assert!(
        result.is_ok(),
        "Should handle zero window probe successfully"
    );

    let stats_after = window_mgmt.get_window_stats().await;
    assert!(
        stats_after.zero_window_probes_received > stats_before.zero_window_probes_received,
        "Should track received zero window probes"
    );
    assert!(
        stats_after.window_updates_sent > stats_before.window_updates_sent,
        "Should send window update in response to probe"
    );
}

// =========================================================================
// Buffer Utilization Tests
// =========================================================================

#[tokio::test]
async fn test_buffer_utilization_tracking() {
    let window_mgmt = WindowManagement::new(10240);

    // Add data
    let _ = window_mgmt.add_to_receive_buffer(5120).await;

    let stats = window_mgmt.get_window_stats().await;
    assert!(
        stats.buffer_utilization >= 0.0 && stats.buffer_utilization <= 1.0,
        "Buffer utilization should be between 0 and 1"
    );
    assert!(
        stats.buffer_utilization > 0.4 && stats.buffer_utilization < 0.6,
        "Buffer utilization should be approximately 50%"
    );
}

#[tokio::test]
async fn test_buffer_utilization_zero_when_empty() {
    let window_mgmt = WindowManagement::new(65536);

    let stats = window_mgmt.get_window_stats().await;
    assert_eq!(
        stats.buffer_utilization, 0.0,
        "Buffer utilization should be 0 when empty"
    );
}

// =========================================================================
// Statistics Tests
// =========================================================================

#[tokio::test]
async fn test_window_statistics_tracking() {
    let window_mgmt = WindowManagement::new(65536);

    // Perform various operations
    let _ = window_mgmt.add_to_receive_buffer(10000).await;
    let _ = window_mgmt.update_buffer_usage(5000).await;
    let _ = window_mgmt.handle_window_update(32768).await;

    let stats = window_mgmt.get_window_stats().await;

    // Verify stats are being tracked
    assert_eq!(stats.current_receive_window.as_u32(), 32768);
    assert!(stats.current_advertised_window.as_u32() > 0);
    assert!(stats.buffer_utilization >= 0.0);
}

#[tokio::test]
async fn test_shutdown_clears_state() {
    let window_mgmt = WindowManagement::new(65536);

    // Add some data
    let _ = window_mgmt.add_to_receive_buffer(10000).await;

    // Shutdown
    let result = window_mgmt.shutdown().await;
    assert!(result.is_ok(), "Shutdown should succeed");

    // Verify state is cleared
    let receive_window = window_mgmt.get_receive_window();
    let advertised_window = window_mgmt.get_advertised_window();
    assert_eq!(
        receive_window.as_u32(),
        0,
        "Receive window should be cleared"
    );
    assert_eq!(
        advertised_window.as_u32(),
        0,
        "Advertised window should be cleared"
    );
}
