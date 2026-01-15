use buckwild_common::protocol::timeout::*;
use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_rto_calculation() {
        let rto_state = RtoState::new();
        
        // First measurement
        let send_time = MicrosecondTimestampValue::now();
        sleep(Duration::from_millis(100)).await;
        let ack_time = MicrosecondTimestampValue::now();
        
        let rtt = rto_state.measure_rtt(send_time, ack_time);
        let rto = rto_state.update_rto_with_measurement(rtt);
        
        assert!(rtt.as_millis() >= 100);
        assert!(rto.as_ms() >= 100);
        
        // Second measurement
        let send_time2 = MicrosecondTimestampValue::now();
        sleep(Duration::from_millis(50)).await;
        let ack_time2 = MicrosecondTimestampValue::now();
        
        let rtt2 = rto_state.measure_rtt(send_time2, ack_time2);
        let rto2 = rto_state.update_rto_with_measurement(rtt2);
        
        assert!(rtt2.as_millis() >= 50);
        
        // RTO should be smoothed
        let stats = rto_state.get_statistics();
        assert_eq!(stats.measurement_count, 2);
    }
    
    #[tokio::test]
    async fn test_timeout_manager() {
        let manager = TimeoutManager::new();
        
        let packet_id = PacketId::new(1);
        let sequence = SequenceNumber::new(100);
        
        // Send packet with timing
        manager.send_packet_with_timing(packet_id, sequence).await.unwrap();
        
        // Simulate ACK
        manager.handle_ack_packet(sequence).await.unwrap();
        
        // Check that packet was removed from pending
        let pending = manager.pending_packets.read().await;
        assert!(!pending.contains_key(&packet_id));
    }
    
    #[tokio::test]
    async fn test_exponential_backoff() {
        let manager = TimeoutManager::new();
        
        let backoff1 = manager.calculate_exponential_backoff(0, 1000, 60000);
        let backoff2 = manager.calculate_exponential_backoff(1, 1000, 60000);
        let backoff3 = manager.calculate_exponential_backoff(2, 1000, 60000);
        
        assert!(backoff1.as_ms() >= 1000);
        assert!(backoff2.as_ms() >= 2000);
        assert!(backoff3.as_ms() >= 4000);
        assert!(backoff3.as_ms() <= 60000);
    }
    
    #[tokio::test]
    async fn test_fragment_timeout() {
        let manager = TimeoutManager::new();
        let fragment_id = FragmentId::new(1);
        
        // Set fragment timeout
        manager.set_fragment_reassembly_timeout(fragment_id).await;
        
        // Check that timeout was set
        {
            let timeouts = manager.fragment_timeouts.read().await;
            assert!(timeouts.contains_key(&fragment_id));
        }
        
        // Cancel timeout
        manager.cancel_fragment_timeout(fragment_id).await;
        
        // Check that timeout was removed
        {
            let timeouts = manager.fragment_timeouts.read().await;
            assert!(!timeouts.contains_key(&fragment_id));
        }
    }
    
    #[test]
    fn test_timestamp_validation() {
        let manager = TimeoutManager::new();
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        // Valid timestamp (recent)
        let valid_timestamp = current_time - 1000; // 1 second ago
        assert!(manager.validate_packet_timestamp_timeout(valid_timestamp).is_ok());
        
        // Invalid timestamp (too old)
        let old_timestamp = current_time - 60000; // 60 seconds ago
        assert!(manager.validate_packet_timestamp_timeout(old_timestamp).is_err());
        
        // Invalid timestamp (future)
        let future_timestamp = current_time + 10000; // 10 seconds in future
        assert!(manager.validate_packet_timestamp_timeout(future_timestamp).is_err());
    }
    
    #[tokio::test]
    async fn test_timeout_error_context() {
        let mut context = TimeoutErrorContext::new(
            TimeoutEventType::Connection,
            "test_operation".to_string(),
            Some(ConnectionId::new(1)),
            "test error".to_string(),
        );
        
        assert_eq!(context.retry_count, 0);
        assert!(!context.has_exceeded_max_retries());
        
        // Increment retries
        for i in 1..=timeout_constants::MAX_RETRY_ATTEMPTS {
            context.increment_retry();
            assert_eq!(context.retry_count, i);
        }
        
        assert!(context.has_exceeded_max_retries());
    }

    #[test]
    fn test_time_sync_tolerance_constant() {
        // Verify TIME_SYNC_TOLERANCE_MS matches the protocol specification
        // Spec: 09-time-synchronization.md, 02-core-definitions.md
        assert_eq!(timeout_constants::TIME_SYNC_TOLERANCE_MS, 50);
    }

    #[test]
    fn test_time_sync_tolerance_edge_cases() {
        let manager = TimeoutManager::new();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Test timestamp exactly at tolerance boundary (49ms in future - should pass)
        let future_49ms = current_time + 49;
        let result = manager.validate_packet_timestamp_timeout(future_49ms);
        assert!(result.is_ok(), "49ms future timestamp should be accepted");

        // Test timestamp just beyond tolerance (51ms in future - should fail)
        let future_51ms = current_time + 51;
        let result = manager.validate_packet_timestamp_timeout(future_51ms);
        assert!(result.is_err(), "51ms future timestamp should be rejected");

        // Test timestamp at exact tolerance (50ms in future - boundary case)
        let future_50ms = current_time + 50;
        let result = manager.validate_packet_timestamp_timeout(future_50ms);
        // At exact boundary, should still be accepted (<=)
        assert!(result.is_ok(), "50ms future timestamp should be accepted at boundary");
    }
