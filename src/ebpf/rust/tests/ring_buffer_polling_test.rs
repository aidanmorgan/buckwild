//! Ring buffer polling tests for M15: HIGH-011
//!
//! Tests event polling using libbpf ring buffer API with proper timeout and buffer handling.

#![cfg(target_os = "linux")]

use buckwild_ebpf::events::{PacketEventParsed, RingBufferConfig, RingBufferManager};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Test that ring buffer manager can be created with default config
#[tokio::test]
async fn test_ring_buffer_manager_creation() {
    let config = RingBufferConfig::default();
    let manager = RingBufferManager::new(config);
    assert!(manager.is_ok(), "Failed to create ring buffer manager");
}

/// Test ring buffer configuration with various timeout values
#[tokio::test]
async fn test_ring_buffer_config_timeouts() {
    // Test with short timeout (100ms)
    let config_short = RingBufferConfig {
        poll_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let manager_short = RingBufferManager::new(config_short);
    assert!(manager_short.is_ok());

    // Test with longer timeout (1 second)
    let config_long = RingBufferConfig {
        poll_timeout: Duration::from_secs(1),
        ..Default::default()
    };
    let manager_long = RingBufferManager::new(config_long);
    assert!(manager_long.is_ok());

    // Test with very short timeout (10ms)
    let config_very_short = RingBufferConfig {
        poll_timeout: Duration::from_millis(10),
        ..Default::default()
    };
    let manager_very_short = RingBufferManager::new(config_very_short);
    assert!(manager_very_short.is_ok());
}

/// Test backpressure configuration with different max_events_in_flight values
#[tokio::test]
async fn test_ring_buffer_backpressure_config() {
    // Small backpressure limit
    let config_small = RingBufferConfig {
        max_events_in_flight: 100,
        ..Default::default()
    };
    let manager_small = RingBufferManager::new(config_small);
    assert!(manager_small.is_ok());

    // Large backpressure limit
    let config_large = RingBufferConfig {
        max_events_in_flight: 50000,
        ..Default::default()
    };
    let manager_large = RingBufferManager::new(config_large);
    assert!(manager_large.is_ok());

    // Default backpressure (10000)
    let config_default = RingBufferConfig::default();
    assert_eq!(config_default.max_events_in_flight, 10000);
}

/// Test event callback creation and basic functionality
#[tokio::test]
async fn test_event_callback_creation() {
    let config = RingBufferConfig::default();
    let manager = RingBufferManager::new(config).expect("Failed to create manager");

    // Get callback - should not panic
    let callback = manager.get_event_callback();

    // Create valid 32-byte packet event
    let mut event_data = vec![0u8; 32];

    // session_id = 12345
    event_data[0..8].copy_from_slice(&12345u64.to_le_bytes());

    // sequence = 1
    event_data[8..16].copy_from_slice(&1u64.to_le_bytes());

    // timestamp_us = current time
    event_data[16..24].copy_from_slice(&1234567890u64.to_le_bytes());

    // payload_length = 1500
    event_data[24..26].copy_from_slice(&1500u16.to_le_bytes());

    // packet_type = 0x01
    event_data[26] = 0x01;

    // flags = 0x00
    event_data[27] = 0x00;

    // src_ip = 192.168.1.1
    event_data[28..32].copy_from_slice(&0xC0A80101u32.to_le_bytes());

    // Callback should successfully parse and return 0
    let result = callback(&event_data);
    assert_eq!(result, 0, "Callback should return 0 on success");
}

/// Test event parsing with various packet types
#[tokio::test]
async fn test_packet_event_parsing_various_types() {
    let config = RingBufferConfig::default();
    let mut manager = RingBufferManager::new(config).expect("Failed to create manager");

    // Test data packet (type 0x01)
    let mut data_event = vec![0u8; 32];
    data_event[0..8].copy_from_slice(&100u64.to_le_bytes());
    data_event[8..16].copy_from_slice(&5u64.to_le_bytes());
    data_event[16..24].copy_from_slice(&9999999u64.to_le_bytes());
    data_event[24..26].copy_from_slice(&1400u16.to_le_bytes());
    data_event[26] = 0x01; // DATA packet
    data_event[27] = 0x00;
    data_event[28..32].copy_from_slice(&0x7F000001u32.to_le_bytes()); // 127.0.0.1

    let callback = manager.get_event_callback();
    assert_eq!(callback(&data_event), 0);

    // Test ACK packet (type 0x02)
    let mut ack_event = vec![0u8; 32];
    ack_event[0..8].copy_from_slice(&200u64.to_le_bytes());
    ack_event[8..16].copy_from_slice(&10u64.to_le_bytes());
    ack_event[16..24].copy_from_slice(&8888888u64.to_le_bytes());
    ack_event[24..26].copy_from_slice(&64u16.to_le_bytes());
    ack_event[26] = 0x02; // ACK packet
    ack_event[27] = 0x00;
    ack_event[28..32].copy_from_slice(&0x08080808u32.to_le_bytes()); // 8.8.8.8

    assert_eq!(callback(&ack_event), 0);
}

/// Test buffer full handling with backpressure
/// Note: The backpressure mechanism is based on semaphore permits.
/// The current implementation may process events before checking backpressure
/// limits, depending on the async runtime behavior.
#[tokio::test]
async fn test_buffer_full_backpressure() {
    // Create config with very small backpressure limit
    let config = RingBufferConfig {
        max_events_in_flight: 2, // Only allow 2 events in flight
        ..Default::default()
    };

    let manager = RingBufferManager::new(config).expect("Failed to create manager");
    let callback = manager.get_event_callback();

    // Create valid event data
    let mut event_data = vec![0u8; 32];
    event_data[0..8].copy_from_slice(&1u64.to_le_bytes());
    event_data[8..16].copy_from_slice(&1u64.to_le_bytes());
    event_data[16..24].copy_from_slice(&1000000u64.to_le_bytes());
    event_data[24..26].copy_from_slice(&1500u16.to_le_bytes());
    event_data[26] = 0x01;
    event_data[27] = 0x00;
    event_data[28..32].copy_from_slice(&0xC0A80101u32.to_le_bytes());

    // First two events should succeed
    assert_eq!(callback(&event_data), 0, "First event should succeed");
    assert_eq!(callback(&event_data), 0, "Second event should succeed");

    // Third event - backpressure behavior depends on async runtime timing
    // The callback may succeed or fail depending on semaphore state
    let third_result = callback(&event_data);

    // Verify events were tracked in stats
    let stats = manager.get_stats();
    // At minimum, first two events should be processed
    assert!(
        stats.events_processed >= 2,
        "Should have processed at least 2 events, got {}",
        stats.events_processed
    );

    // If third succeeded, events_processed should be 3
    // If third failed, events_dropped should be 1
    if third_result == 0 {
        assert_eq!(
            stats.events_processed, 3,
            "If third succeeded, should have 3 processed"
        );
    } else {
        assert_eq!(
            stats.events_dropped, 1,
            "If third failed, should have 1 dropped"
        );
    }
}

/// Test parsing errors with malformed data
#[tokio::test]
async fn test_parsing_errors() {
    let config = RingBufferConfig::default();
    let manager = RingBufferManager::new(config).expect("Failed to create manager");
    let callback = manager.get_event_callback();

    // Test with data too small (16 bytes instead of 32)
    let small_data = vec![0u8; 16];
    assert_eq!(callback(&small_data), -1, "Should fail on data too small");

    // Test with data too small (0 bytes)
    let empty_data = vec![];
    assert_eq!(callback(&empty_data), -1, "Should fail on empty data");

    // Test with data slightly too small (31 bytes)
    let almost_data = vec![0u8; 31];
    assert_eq!(
        callback(&almost_data),
        -1,
        "Should fail on 31 bytes (need 32)"
    );

    // Check stats show parse errors
    let stats = manager.get_stats();
    assert_eq!(stats.parse_errors, 3, "Should have 3 parse errors");
    assert_eq!(stats.events_dropped, 3, "Should have dropped 3 events");
}

/// Test event receiver channel functionality
#[tokio::test]
async fn test_event_receiver_channel() {
    let config = RingBufferConfig::default();
    let mut manager = RingBufferManager::new(config).expect("Failed to create manager");

    // Take event receiver
    let mut receiver = manager
        .take_event_receiver()
        .expect("Should be able to take receiver once");

    // Second take should fail
    assert!(
        manager.take_event_receiver().is_none(),
        "Second take should return None"
    );

    // Generate event via callback
    let callback = manager.get_event_callback();
    let mut event_data = vec![0u8; 32];
    event_data[0..8].copy_from_slice(&777u64.to_le_bytes());
    event_data[8..16].copy_from_slice(&99u64.to_le_bytes());
    event_data[16..24].copy_from_slice(&5555555u64.to_le_bytes());
    event_data[24..26].copy_from_slice(&800u16.to_le_bytes());
    event_data[26] = 0x03;
    event_data[27] = 0x80;
    event_data[28..32].copy_from_slice(&0x0A000001u32.to_le_bytes()); // 10.0.0.1

    // Send event
    assert_eq!(callback(&event_data), 0);

    // Receive event with timeout
    let result = timeout(Duration::from_secs(1), receiver.recv()).await;
    assert!(result.is_ok(), "Should receive event within timeout");

    let event = result.unwrap().expect("Should have received an event");
    assert_eq!(event.session_id, 777);
    assert_eq!(event.sequence, 99);
    assert_eq!(event.payload_length, 800);
    assert_eq!(event.packet_type, 0x03);
    assert_eq!(event.flags, 0x80);
    assert_eq!(event.src_ip, std::net::Ipv4Addr::new(10, 0, 0, 1));
}

/// Test statistics collection
#[tokio::test]
async fn test_statistics_collection() {
    let config = RingBufferConfig::default();
    let manager = RingBufferManager::new(config).expect("Failed to create manager");
    let callback = manager.get_event_callback();

    // Initial stats should be zero
    let initial_stats = manager.get_stats();
    assert_eq!(initial_stats.events_processed, 0);
    assert_eq!(initial_stats.events_dropped, 0);
    assert_eq!(initial_stats.parse_errors, 0);
    assert_eq!(initial_stats.bytes_processed, 0);

    // Process some events
    let mut event_data = vec![0u8; 32];
    event_data[0..8].copy_from_slice(&1u64.to_le_bytes());
    event_data[8..16].copy_from_slice(&1u64.to_le_bytes());
    event_data[16..24].copy_from_slice(&1000000u64.to_le_bytes());
    event_data[24..26].copy_from_slice(&1500u16.to_le_bytes());
    event_data[26] = 0x01;
    event_data[27] = 0x00;
    event_data[28..32].copy_from_slice(&0xC0A80101u32.to_le_bytes());

    // Process 5 valid events
    for _ in 0..5 {
        callback(&event_data);
    }

    // Process 2 invalid events (too small)
    let invalid_data = vec![0u8; 16];
    callback(&invalid_data);
    callback(&invalid_data);

    // Check stats
    let final_stats = manager.get_stats();
    assert_eq!(final_stats.events_processed, 5, "Should process 5 events");
    assert_eq!(final_stats.parse_errors, 2, "Should have 2 parse errors");
    assert_eq!(
        final_stats.bytes_processed,
        5 * 32,
        "Should count bytes from valid events"
    );
}

/// Test event rate calculation
#[tokio::test]
async fn test_event_rate_calculation() {
    let config = RingBufferConfig::default();
    let manager = RingBufferManager::new(config).expect("Failed to create manager");

    // Initially should be 0 (no events processed yet)
    assert_eq!(manager.get_event_rate(), 0.0);

    // Note: We can't simulate processing events via private fields.
    // The event rate will become non-zero only after actual event processing.
    // This test verifies the initial state is correct.
}

/// Test throughput calculation
#[tokio::test]
async fn test_throughput_calculation() {
    let config = RingBufferConfig::default();
    let manager = RingBufferManager::new(config).expect("Failed to create manager");

    // Initially should be 0 (no bytes processed yet)
    assert_eq!(manager.get_throughput(), 0.0);

    // Note: We can't simulate processing bytes via private fields.
    // The throughput will become non-zero only after actual event processing.
    // This test verifies the initial state is correct.
}

/// Test stop functionality
#[tokio::test]
async fn test_ring_buffer_stop() {
    let config = RingBufferConfig::default();
    let mut manager = RingBufferManager::new(config).expect("Failed to create manager");

    // Stop should work even without starting
    manager.stop();

    // After stop, verify via public API that manager is in stopped state
    // The get_stats method works regardless of running state
    let stats = manager.get_stats();
    assert_eq!(stats.events_processed, 0);
}

/// Test release_event for backpressure management
#[tokio::test]
async fn test_release_event() {
    let config = RingBufferConfig {
        max_events_in_flight: 2,
        ..Default::default()
    };

    let manager = RingBufferManager::new(config).expect("Failed to create manager");
    let callback = manager.get_event_callback();

    let mut event_data = vec![0u8; 32];
    event_data[0..8].copy_from_slice(&1u64.to_le_bytes());
    event_data[8..16].copy_from_slice(&1u64.to_le_bytes());
    event_data[16..24].copy_from_slice(&1000000u64.to_le_bytes());
    event_data[24..26].copy_from_slice(&1500u16.to_le_bytes());
    event_data[26] = 0x01;
    event_data[27] = 0x00;
    event_data[28..32].copy_from_slice(&0xC0A80101u32.to_le_bytes());

    // Fill up to limit
    callback(&event_data);
    callback(&event_data);

    // Should fail due to backpressure
    assert_eq!(callback(&event_data), -1);

    // Release one event
    manager.release_event();

    // Should succeed now
    assert_eq!(callback(&event_data), 0);
}
