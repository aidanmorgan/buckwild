use buckwild_common::protocol::comprehensive_anti_replay::*;
use std::thread;
    use std::time::Duration;

    #[test]
    fn test_comprehensive_validation_valid_packet() {
        let system = ComprehensiveAntiReplaySystem::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        let result = system.validate_packet(
            current_time,
            EpochType::Daily,
            12345,
            1,
            Some("192.168.1.100".to_string()),
        ).unwrap();

        assert_eq!(result, AntiReplayResult::Valid);
    }

    #[test]
    fn test_timestamp_replay_detection() {
        let system = ComprehensiveAntiReplaySystem::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        // First packet should be valid
        let result1 = system.validate_packet(
            current_time,
            EpochType::Daily,
            12345,
            1,
            Some("192.168.1.100".to_string()),
        ).unwrap();
        assert_eq!(result1, AntiReplayResult::Valid);

        // Duplicate timestamp should be detected
        let result2 = system.validate_packet(
            current_time,
            EpochType::Daily,
            12345,
            1,
            Some("192.168.1.100".to_string()),
        ).unwrap();
        assert_eq!(result2, AntiReplayResult::TimestampReplay);
    }

    #[test]
    fn test_sequence_replay_detection() {
        let system = ComprehensiveAntiReplaySystem::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        // Send sequence 1, then 3, then 1 again (replay)
        system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap();
        system.validate_packet(current_time + 1, EpochType::Daily, 12345, 3, None).unwrap();
        
        let result = system.validate_packet(
            current_time + 2,
            EpochType::Daily,
            12345,
            1,
            None,
        ).unwrap();
        
        assert_eq!(result, AntiReplayResult::SequenceReplay);
    }

    #[test]
    fn test_attack_pattern_detection() {
        let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
            attack_threshold: 3,
            ..Default::default()
        });

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        let source = "192.168.1.100".to_string();

        // Generate multiple replay attacks to trigger pattern detection
        for i in 0..5 {
            let result = system.validate_packet(
                current_time,
                EpochType::Daily,
                12345,
                1,
                Some(source.clone()),
            ).unwrap();

            if i == 0 {
                assert_eq!(result, AntiReplayResult::Valid);
            } else if i < 3 {
                assert_eq!(result, AntiReplayResult::TimestampReplay);
            } else {
                // Should be blocked after threshold
                assert_eq!(result, AntiReplayResult::SourceBlocked);
            }
        }

        let attack_info = system.get_attack_info();
        assert_eq!(attack_info.blocked_sources, 1);
    }

    #[test]
    fn test_out_of_order_handling() {
        let system = ComprehensiveAntiReplaySystem::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        // Send sequence 1, 3, 2 (out of order)
        let result1 = system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap();
        assert_eq!(result1, AntiReplayResult::Valid);

        let result2 = system.validate_packet(current_time + 1, EpochType::Daily, 12345, 3, None).unwrap();
        assert_eq!(result2, AntiReplayResult::Valid);

        let result3 = system.validate_packet(current_time + 2, EpochType::Daily, 12345, 2, None).unwrap();
        assert_eq!(result3, AntiReplayResult::OutOfOrder);
    }

    #[test]
    fn test_security_event_logging() {
        let system = ComprehensiveAntiReplaySystem::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        // Generate a replay attack
        system.validate_packet(current_time, EpochType::Daily, 12345, 1, Some("192.168.1.100".to_string())).unwrap();
        system.validate_packet(current_time, EpochType::Daily, 12345, 1, Some("192.168.1.100".to_string())).unwrap();

        let events = system.get_recent_security_events(10);
        assert!(!events.is_empty());
        assert_eq!(events[0].event_type, SecurityEventType::TimestampReplay);
    }

    #[test]
    fn test_nonce_validation() {
        let system = ComprehensiveAntiReplaySystem::new();
        let session_id = 12345;
        let operation_type = "test_operation";
        let challenge_data = b"test_challenge";

        // Generate nonce
        let nonce = system.generate_nonce(session_id, operation_type, challenge_data).unwrap();

        // Validate nonce
        let result = system.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
        assert_eq!(result, AntiReplayResult::Valid);

        // Second validation should detect replay
        let result2 = system.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
        assert_eq!(result2, AntiReplayResult::DuplicateReplay);
    }

    #[test]
    fn test_cleanup_operations() {
        let system = ComprehensiveAntiReplaySystem::new();
        
        // Add some data
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        for i in 0..100 {
            system.validate_packet(current_time + i, EpochType::Daily, 12345 + i, i as u32, None).unwrap();
        }

        let stats_before = system.get_stats();
        assert_eq!(stats_before.total_packets, 100);

        // Cleanup should not remove recent data
        let cleanup_stats = system.cleanup_expired_entries().unwrap();
        
        // Most entries should still be there since they're recent
        assert!(cleanup_stats.total_removed() < 50);
    }

    #[test]
    fn test_statistics_tracking() {
        let system = ComprehensiveAntiReplaySystem::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;

        // Generate various types of events
        system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap(); // Valid
        system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap(); // Timestamp replay
        system.validate_packet(current_time + 1, EpochType::Daily, 12345, 3, None).unwrap(); // Valid
        system.validate_packet(current_time + 2, EpochType::Daily, 12345, 2, None).unwrap(); // Out of order

        let stats = system.get_stats();
        assert_eq!(stats.total_packets, 4);
        assert_eq!(stats.valid_packets, 2);
        assert_eq!(stats.timestamp_replays, 1);
        assert_eq!(stats.out_of_order_packets, 1);
    }

    #[test]
    fn test_concurrent_validation() {
        let system = Arc::new(ComprehensiveAntiReplaySystem::new());
        let num_threads = 4;
        let iterations_per_thread = 1000;

        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let system_clone = Arc::clone(&system);
            let handle = thread::spawn(move || {
                let base_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64 / 500;

                for i in 0..iterations_per_thread {
                    let timestamp = base_time + (thread_id * iterations_per_thread + i) as u64;
                    let session_id = 12345 + thread_id as u64;
                    let sequence = i as u32;

                    system_clone.validate_packet(
                        timestamp,
                        EpochType::Daily,
                        session_id,
                        sequence,
                        Some(format!("192.168.1.{}", thread_id + 1)),
                    ).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = system.get_stats();
        assert_eq!(stats.total_packets, (num_threads * iterations_per_thread) as u64);
    }
