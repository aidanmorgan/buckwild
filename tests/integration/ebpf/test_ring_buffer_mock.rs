// Ring Buffer Mock Integration Tests
//!
//! These tests validate ring buffer manager behavior without requiring
//! actual kernel interaction. They simulate ring buffer events by directly
//! calling the event callback with test data.

#[cfg(test)]
mod ring_buffer_mock_tests {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    // Import ring buffer types
    use buckwild_ebpf::events::{RingBufferManager, RingBufferConfig};

    /// Create a valid 32-byte packet event buffer
    fn create_test_event_buffer(
        session_id: u64,
        sequence: u64,
        timestamp_us: u64,
        payload_length: u16,
        packet_type: u8,
        flags: u8,
        src_ip: u32,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; 32];

        buffer[0..8].copy_from_slice(&session_id.to_le_bytes());
        buffer[8..16].copy_from_slice(&sequence.to_le_bytes());
        buffer[16..24].copy_from_slice(&timestamp_us.to_le_bytes());
        buffer[24..26].copy_from_slice(&payload_length.to_le_bytes());
        buffer[26] = packet_type;
        buffer[27] = flags;
        buffer[28..32].copy_from_slice(&src_ip.to_le_bytes());

        buffer
    }

    #[tokio::test]
    async fn test_callback_processes_valid_event() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();

        // Get the callback
        let callback = manager.get_event_callback();

        // Create a valid event
        let buffer = create_test_event_buffer(
            0x1234567890ABCDEF,
            42,
            1000000,
            1500,
            0x01,
            0x80,
            0xC0A80164, // 192.168.1.100
        );

        // Call callback to simulate ring buffer event
        let result = callback(&buffer);

        // Should return success (0)
        assert_eq!(result, 0, "Callback should return 0 for success");

        // Check that event was sent to channel
        let receiver = manager.event_receiver();
        let event = timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Channel should have event");

        assert_eq!(event.session_id, 0x1234567890ABCDEF);
        assert_eq!(event.sequence, 42);
        assert_eq!(event.timestamp_us, 1000000);
        assert_eq!(event.payload_length, 1500);
        assert_eq!(event.packet_type, 0x01);
        assert_eq!(event.flags, 0x80);
        assert_eq!(event.src_ip, std::net::Ipv4Addr::new(192, 168, 1, 100));

        // Check statistics
        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, 1);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.parse_errors, 0);
        assert_eq!(stats.bytes_processed, 32);
    }

    #[tokio::test]
    async fn test_callback_handles_invalid_data() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();

        let callback = manager.get_event_callback();

        // Create invalid data (too small)
        let buffer = vec![0u8; 16];

        // Call callback - should return error (-1)
        let result = callback(&buffer);
        assert_eq!(result, -1, "Callback should return -1 for parse error");

        // Check statistics
        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.events_dropped, 1);
        assert_eq!(stats.parse_errors, 1);
        assert_eq!(stats.bytes_processed, 0);
    }

    #[tokio::test]
    async fn test_callback_handles_truncated_event() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();

        let callback = manager.get_event_callback();

        // Create truncated event (only 31 bytes)
        let buffer = vec![0u8; 31];

        let result = callback(&buffer);
        assert_eq!(result, -1, "Callback should reject truncated event");

        let stats = manager.get_stats();
        assert_eq!(stats.parse_errors, 1);
        assert_eq!(stats.events_dropped, 1);
    }

    #[tokio::test]
    async fn test_callback_batch_processing() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();

        let callback = manager.get_event_callback();

        const BATCH_SIZE: usize = 100;

        // Process a batch of events
        for i in 0..BATCH_SIZE {
            let buffer = create_test_event_buffer(
                i as u64,
                i as u64 * 10,
                1000000 + i as u64,
                1500,
                0x01,
                0x00,
                0xC0A80100 + i as u32,
            );

            let result = callback(&buffer);
            assert_eq!(result, 0, "Event {} should be processed successfully", i);
        }

        // Verify all events received
        let receiver = manager.event_receiver();
        let mut count = 0;

        for i in 0..BATCH_SIZE {
            match timeout(Duration::from_millis(100), receiver.recv()).await {
                Ok(Some(event)) => {
                    assert_eq!(event.session_id, i as u64);
                    assert_eq!(event.sequence, i as u64 * 10);
                    count += 1;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        assert_eq!(count, BATCH_SIZE, "Should receive all batched events");

        // Check statistics
        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, BATCH_SIZE as u64);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.bytes_processed, (BATCH_SIZE * 32) as u64);
    }

    #[tokio::test]
    async fn test_backpressure_drops_events() {
        // Configure with very small backpressure limit
        let config = RingBufferConfig {
            max_events_in_flight: 10,
            ..Default::default()
        };

        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Send more events than the backpressure limit
        let total_events = 100;
        let mut successful = 0;
        let mut dropped = 0;

        for i in 0..total_events {
            let buffer = create_test_event_buffer(
                i as u64,
                i as u64,
                1000000,
                1500,
                0x01,
                0x00,
                0xC0A80164,
            );

            let result = callback(&buffer);
            if result == 0 {
                successful += 1;
            } else {
                dropped += 1;
            }
        }

        // Should have dropped some events due to backpressure
        assert!(dropped > 0, "Backpressure should have dropped some events");
        assert!(successful <= 10, "Should not exceed backpressure limit");

        // Check statistics reflect drops
        let stats = manager.get_stats();
        assert_eq!(stats.events_dropped, dropped as u64);
        assert_eq!(stats.events_processed, successful as u64);
    }

    #[tokio::test]
    async fn test_backpressure_recovery() {
        let config = RingBufferConfig {
            max_events_in_flight: 5,
            ..Default::default()
        };

        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Fill backpressure limit
        for i in 0..5 {
            let buffer = create_test_event_buffer(i, i, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
            let result = callback(&buffer);
            assert_eq!(result, 0, "Event {} should succeed", i);
        }

        // Next event should be dropped
        let buffer = create_test_event_buffer(999, 999, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
        let result = callback(&buffer);
        assert_eq!(result, -1, "Event should be dropped due to backpressure");

        // Consume events to release backpressure
        let receiver = manager.event_receiver();
        for _ in 0..5 {
            if let Ok(Some(_)) = timeout(Duration::from_millis(100), receiver.recv()).await {
                manager.release_event();
            }
        }

        // Now should be able to send again
        let buffer = create_test_event_buffer(1000, 1000, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
        let result = callback(&buffer);
        assert_eq!(result, 0, "Event should succeed after backpressure released");

        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, 6); // 5 + 1 after release
        assert_eq!(stats.events_dropped, 1);   // 1 dropped during backpressure
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Process some valid events
        for i in 0..10 {
            let buffer = create_test_event_buffer(i, i, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
            callback(&buffer);
        }

        // Process some invalid events
        for _ in 0..5 {
            callback(&vec![0u8; 10]); // Too small
        }

        // Check statistics
        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, 10, "Should track successful events");
        assert_eq!(stats.parse_errors, 5, "Should track parse errors");
        assert_eq!(stats.events_dropped, 5, "Should track dropped events");
        assert_eq!(stats.bytes_processed, 320, "Should track bytes (10 * 32)");
        assert!(stats.uptime.as_millis() > 0, "Should track uptime");
    }

    #[tokio::test]
    async fn test_event_rate_calculation() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Process events
        for i in 0..100 {
            let buffer = create_test_event_buffer(i, i, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
            callback(&buffer);
        }

        // Wait a bit for time to pass
        tokio::time::sleep(Duration::from_millis(100)).await;

        let rate = manager.get_event_rate();
        assert!(rate > 0.0, "Event rate should be positive");
        assert!(rate < 1_000_000.0, "Event rate should be reasonable");
    }

    #[tokio::test]
    async fn test_throughput_calculation() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Process events
        for i in 0..100 {
            let buffer = create_test_event_buffer(i, i, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
            callback(&buffer);
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let throughput = manager.get_throughput();
        assert!(throughput > 0.0, "Throughput should be positive");
        assert_eq!(manager.get_stats().bytes_processed, 3200); // 100 * 32
    }

    #[tokio::test]
    async fn test_zero_values_event() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Create all-zero event
        let buffer = vec![0u8; 32];

        let result = callback(&buffer);
        assert_eq!(result, 0, "Zero-value event should be valid");

        let receiver = manager.event_receiver();
        let event = timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Should receive event");

        assert_eq!(event.session_id, 0);
        assert_eq!(event.sequence, 0);
        assert_eq!(event.timestamp_us, 0);
        assert_eq!(event.payload_length, 0);
        assert_eq!(event.packet_type, 0);
        assert_eq!(event.flags, 0);
        assert_eq!(event.src_ip, std::net::Ipv4Addr::new(0, 0, 0, 0));
    }

    #[tokio::test]
    async fn test_max_values_event() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Create max-value event
        let buffer = create_test_event_buffer(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u16::MAX,
            u8::MAX,
            u8::MAX,
            u32::MAX,
        );

        let result = callback(&buffer);
        assert_eq!(result, 0, "Max-value event should be valid");

        let receiver = manager.event_receiver();
        let event = timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Should receive event");

        assert_eq!(event.session_id, u64::MAX);
        assert_eq!(event.sequence, u64::MAX);
        assert_eq!(event.timestamp_us, u64::MAX);
        assert_eq!(event.payload_length, u16::MAX);
        assert_eq!(event.packet_type, u8::MAX);
        assert_eq!(event.flags, u8::MAX);
        assert_eq!(event.src_ip, std::net::Ipv4Addr::new(255, 255, 255, 255));
    }

    #[tokio::test]
    async fn test_multiple_callbacks_isolated() {
        // Test that multiple managers have isolated callbacks
        let config1 = RingBufferConfig::default();
        let mut manager1 = RingBufferManager::new(config1).unwrap();
        let callback1 = manager1.get_event_callback();

        let config2 = RingBufferConfig::default();
        let mut manager2 = RingBufferManager::new(config2).unwrap();
        let callback2 = manager2.get_event_callback();

        // Send event to manager1
        let buffer1 = create_test_event_buffer(111, 111, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
        callback1(&buffer1);

        // Send event to manager2
        let buffer2 = create_test_event_buffer(222, 222, 2000000, 2000, 0x02, 0x01, 0xC0A80265);
        callback2(&buffer2);

        // Verify manager1 received only its event
        let receiver1 = manager1.event_receiver();
        let event1 = timeout(Duration::from_millis(100), receiver1.recv())
            .await
            .expect("Timeout waiting for event1")
            .expect("Should receive event1");
        assert_eq!(event1.session_id, 111);

        // Verify manager2 received only its event
        let receiver2 = manager2.event_receiver();
        let event2 = timeout(Duration::from_millis(100), receiver2.recv())
            .await
            .expect("Timeout waiting for event2")
            .expect("Should receive event2");
        assert_eq!(event2.session_id, 222);

        // Verify statistics are independent
        let stats1 = manager1.get_stats();
        let stats2 = manager2.get_stats();
        assert_eq!(stats1.events_processed, 1);
        assert_eq!(stats2.events_processed, 1);
    }

    #[tokio::test]
    async fn test_concurrent_callback_invocations() {
        let config = RingBufferConfig {
            max_events_in_flight: 1000,
            ..Default::default()
        };
        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = Arc::new(manager.get_event_callback());

        let mut handles = vec![];
        const THREADS: usize = 10;
        const EVENTS_PER_THREAD: usize = 100;

        // Spawn multiple tasks calling callback concurrently
        for thread_id in 0..THREADS {
            let callback_clone = Arc::clone(&callback);

            let handle = tokio::spawn(async move {
                for i in 0..EVENTS_PER_THREAD {
                    let buffer = create_test_event_buffer(
                        (thread_id * 1000 + i) as u64,
                        i as u64,
                        1000000,
                        1500,
                        0x01,
                        0x00,
                        0xC0A80164,
                    );
                    callback_clone(&buffer);
                }
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task should complete successfully");
        }

        // Check that all events were processed
        let stats = manager.get_stats();
        assert_eq!(
            stats.events_processed,
            (THREADS * EVENTS_PER_THREAD) as u64,
            "Should process all events from concurrent invocations"
        );
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.parse_errors, 0);
    }

    #[tokio::test]
    async fn test_empty_buffer_rejected() {
        let config = RingBufferConfig::default();
        let manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        let buffer = vec![];
        let result = callback(&buffer);

        assert_eq!(result, -1, "Empty buffer should be rejected");

        let stats = manager.get_stats();
        assert_eq!(stats.parse_errors, 1);
        assert_eq!(stats.events_dropped, 1);
    }

    #[tokio::test]
    async fn test_oversized_buffer_accepted() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Create buffer larger than 32 bytes (parser should read first 32)
        let mut buffer = create_test_event_buffer(
            0x1234567890ABCDEF,
            42,
            1000000,
            1500,
            0x01,
            0x80,
            0xC0A80164,
        );
        buffer.extend_from_slice(&[0xFF; 32]); // Add extra data

        let result = callback(&buffer);
        assert_eq!(result, 0, "Oversized buffer should be accepted (uses first 32 bytes)");

        let receiver = manager.event_receiver();
        let event = timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Should receive event");

        // Verify event was parsed correctly from first 32 bytes
        assert_eq!(event.session_id, 0x1234567890ABCDEF);
        assert_eq!(event.sequence, 42);

        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, 1);
        assert_eq!(stats.bytes_processed, 64); // Tracks actual buffer size
    }

    #[tokio::test]
    async fn test_release_event_updates_stats() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Send event
        let buffer = create_test_event_buffer(123, 456, 1000000, 1500, 0x01, 0x00, 0xC0A80164);
        callback(&buffer);

        // Check in-flight count
        let stats = manager.get_stats();
        assert_eq!(stats.events_in_flight, 1);

        // Release event
        manager.release_event();

        // Check in-flight count decreased
        let stats = manager.get_stats();
        assert_eq!(stats.events_in_flight, 0);
    }

    #[tokio::test]
    async fn test_mixed_valid_and_invalid_events() {
        let config = RingBufferConfig::default();
        let mut manager = RingBufferManager::new(config).unwrap();
        let callback = manager.get_event_callback();

        // Mix of valid and invalid events
        let events = vec![
            (create_test_event_buffer(1, 1, 1000000, 1500, 0x01, 0x00, 0xC0A80164), true),
            (vec![0u8; 10], false), // Too small
            (create_test_event_buffer(2, 2, 1000000, 1500, 0x01, 0x00, 0xC0A80164), true),
            (vec![0u8; 20], false), // Still too small
            (create_test_event_buffer(3, 3, 1000000, 1500, 0x01, 0x00, 0xC0A80164), true),
        ];

        for (buffer, should_succeed) in events {
            let result = callback(&buffer);
            if should_succeed {
                assert_eq!(result, 0);
            } else {
                assert_eq!(result, -1);
            }
        }

        // Verify statistics
        let stats = manager.get_stats();
        assert_eq!(stats.events_processed, 3);
        assert_eq!(stats.parse_errors, 2);
        assert_eq!(stats.events_dropped, 2);
        assert_eq!(stats.bytes_processed, 96); // 3 valid events * 32 bytes
    }
}
