use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use buckwild_common::protocol::{
    ComprehensiveAntiReplaySystem, AntiReplayConfig, AntiReplayResult, 
    SecurityEventType, EpochType, AttackSeverity
};

#[test]
fn test_valid_packet_processing() {
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

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 1);
    assert_eq!(stats.valid_packets, 1);
    assert_eq!(stats.timestamp_replays, 0);
    assert_eq!(stats.duplicate_replays, 0);
    assert_eq!(stats.sequence_replays, 0);
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

    // Duplicate timestamp should be detected as replay
    let result2 = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result2, AntiReplayResult::TimestampReplay);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 2);
    assert_eq!(stats.valid_packets, 1);
    assert_eq!(stats.timestamp_replays, 1);

    // Check security events
    let events = system.get_recent_security_events(10);
    assert!(!events.is_empty());
    assert_eq!(events[0].event_type, SecurityEventType::TimestampReplay);
}

#[test]
fn test_duplicate_packet_detection() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Send same packet twice with different timestamps
    let result1 = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result1, AntiReplayResult::Valid);

    let result2 = system.validate_packet(
        current_time + 1,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    // This should be detected as duplicate based on session+sequence combination
    assert!(matches!(result2, AntiReplayResult::DuplicateReplay | AntiReplayResult::SequenceReplay));

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 2);
    assert!(stats.duplicate_replays > 0 || stats.sequence_replays > 0);
}

#[test]
fn test_sequence_replay_detection() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Send sequence 1, then 3, then 1 again (replay)
    let result1 = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result1, AntiReplayResult::Valid);

    let result2 = system.validate_packet(
        current_time + 1,
        EpochType::Daily,
        12345,
        3,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result2, AntiReplayResult::Valid);

    let result3 = system.validate_packet(
        current_time + 2,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result3, AntiReplayResult::SequenceReplay);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 3);
    assert_eq!(stats.valid_packets, 2);
    assert_eq!(stats.sequence_replays, 1);
}

#[test]
fn test_out_of_order_packet_handling() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Send sequence 1, 3, 2 (out of order but legitimate)
    let result1 = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result1, AntiReplayResult::Valid);

    let result2 = system.validate_packet(
        current_time + 1,
        EpochType::Daily,
        12345,
        3,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result2, AntiReplayResult::Valid);

    let result3 = system.validate_packet(
        current_time + 2,
        EpochType::Daily,
        12345,
        2,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result3, AntiReplayResult::OutOfOrder);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 3);
    assert_eq!(stats.valid_packets, 2);
    assert_eq!(stats.out_of_order_packets, 1);
}

#[test]
fn test_old_timestamp_rejection() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Send packet with timestamp older than 30 seconds (60 * 500ms buckets)
    let old_timestamp = current_time.saturating_sub(61 * 2); // 61 seconds ago
    
    let result = system.validate_packet(
        old_timestamp,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();

    assert_eq!(result, AntiReplayResult::TimestampReplay);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 1);
    assert_eq!(stats.valid_packets, 0);
    assert_eq!(stats.timestamp_replays, 1);
}

#[test]
fn test_future_timestamp_handling() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Send packet with timestamp too far in the future (beyond clock skew tolerance)
    let future_timestamp = current_time + (20 * 2); // 20 seconds in future (beyond 5s tolerance)
    
    let result = system.validate_packet(
        future_timestamp,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();

    assert_eq!(result, AntiReplayResult::TimestampReplay);

    let stats = system.get_stats();
    assert_eq!(stats.timestamp_replays, 1);
}

#[test]
fn test_attack_pattern_detection_and_blocking() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 3,
        attack_window_seconds: 60,
        block_duration_seconds: 300,
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

    let stats = system.get_stats();
    assert_eq!(stats.attack_patterns_detected, 1);

    let attack_info = system.get_attack_info();
    assert_eq!(attack_info.blocked_sources, 1);

    // Check security events
    let events = system.get_recent_security_events(10);
    let attack_events: Vec<_> = events.iter()
        .filter(|e| e.event_type == SecurityEventType::AttackPatternDetected)
        .collect();
    assert!(!attack_events.is_empty());
}

#[test]
fn test_dual_epoch_timestamp_validation() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Test daily epoch validation
    let result_daily = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result_daily, AntiReplayResult::Valid);

    // Test monthly epoch validation
    let result_monthly = system.validate_packet(
        current_time + 1,
        EpochType::Monthly,
        12346,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result_monthly, AntiReplayResult::Valid);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 2);
    assert_eq!(stats.valid_packets, 2);
}

#[test]
fn test_nonce_validation_integration() {
    let system = ComprehensiveAntiReplaySystem::new();
    let session_id = 12345;
    let operation_type = "test_operation";
    let challenge_data = b"test_challenge_data";

    // Generate nonce
    let nonce = system.generate_nonce(session_id, operation_type, challenge_data).unwrap();
    assert_eq!(nonce.len(), 32);

    // Validate nonce
    let result = system.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
    assert_eq!(result, AntiReplayResult::Valid);

    // Second validation should detect replay
    let result2 = system.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
    assert_eq!(result2, AntiReplayResult::DuplicateReplay);

    // Check security events
    let events = system.get_recent_security_events(10);
    let replay_events: Vec<_> = events.iter()
        .filter(|e| e.event_type == SecurityEventType::SystematicReplay)
        .collect();
    assert!(!replay_events.is_empty());
}

#[test]
fn test_security_event_logging() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Generate various types of security events
    system.validate_packet(current_time, EpochType::Daily, 12345, 1, Some("192.168.1.100".to_string())).unwrap();
    system.validate_packet(current_time, EpochType::Daily, 12345, 1, Some("192.168.1.100".to_string())).unwrap(); // Timestamp replay
    system.validate_packet(current_time + 1, EpochType::Daily, 12345, 3, Some("192.168.1.100".to_string())).unwrap();
    system.validate_packet(current_time + 2, EpochType::Daily, 12345, 1, Some("192.168.1.100".to_string())).unwrap(); // Sequence replay

    let events = system.get_recent_security_events(10);
    assert!(events.len() >= 2);

    // Check event types
    let event_types: Vec<_> = events.iter().map(|e| &e.event_type).collect();
    assert!(event_types.contains(&&SecurityEventType::TimestampReplay));
    assert!(event_types.contains(&&SecurityEventType::SequenceReplay));

    // Check event details
    for event in &events {
        assert!(!event.details.is_empty());
        assert!(!event.correlation_id.is_empty());
        assert_eq!(event.session_id, 12345);
    }
}

#[test]
fn test_cleanup_operations() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Add some data to the system
    for i in 0..100 {
        system.validate_packet(
            current_time + i,
            EpochType::Daily,
            12345 + i,
            i as u32,
            Some(format!("192.168.1.{}", (i % 254) + 1)),
        ).unwrap();
    }

    let stats_before = system.get_stats();
    assert_eq!(stats_before.total_packets, 100);

    // Perform cleanup
    let cleanup_stats = system.cleanup_expired_entries().unwrap();

    // Since entries are recent, most should still be there
    assert!(cleanup_stats.total_removed() < 50);

    // System should still function after cleanup
    let result = system.validate_packet(
        current_time + 200,
        EpochType::Daily,
        99999,
        1,
        Some("192.168.1.200".to_string()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::Valid);
}

#[test]
fn test_statistics_accuracy() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Generate known patterns of events
    system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap(); // Valid
    system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap(); // Timestamp replay
    system.validate_packet(current_time + 1, EpochType::Daily, 12345, 3, None).unwrap(); // Valid
    system.validate_packet(current_time + 2, EpochType::Daily, 12345, 2, None).unwrap(); // Out of order
    system.validate_packet(current_time + 3, EpochType::Daily, 12345, 1, None).unwrap(); // Sequence replay

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 5);
    assert_eq!(stats.valid_packets, 2);
    assert_eq!(stats.timestamp_replays, 1);
    assert_eq!(stats.out_of_order_packets, 1);
    assert_eq!(stats.sequence_replays, 1);
    assert!(stats.security_events_logged >= 2);
}

#[test]
fn test_concurrent_validation() {
    let system = Arc::new(ComprehensiveAntiReplaySystem::new());
    let num_threads = 4;
    let iterations_per_thread = 250;

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

                let result = system_clone.validate_packet(
                    timestamp,
                    EpochType::Daily,
                    session_id,
                    sequence,
                    Some(format!("192.168.1.{}", thread_id + 1)),
                ).unwrap();

                // Most should be valid
                assert!(matches!(result, 
                    AntiReplayResult::Valid | 
                    AntiReplayResult::OutOfOrder
                ));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, (num_threads * iterations_per_thread) as u64);
    assert!(stats.valid_packets > 0);
}

#[test]
fn test_attack_severity_escalation() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 2,
        attack_window_seconds: 10,
        block_duration_seconds: 60,
        ..Default::default()
    });

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let source = "192.168.1.100".to_string();

    // Generate rapid attacks
    for i in 0..5 {
        let result = system.validate_packet(
            current_time,
            EpochType::Daily,
            12345,
            1,
            Some(source.clone()),
        ).unwrap();

        if i >= 2 {
            assert_eq!(result, AntiReplayResult::SourceBlocked);
        }
    }

    let attack_info = system.get_attack_info();
    assert_eq!(attack_info.blocked_sources, 1);

    // Check that blocked source remains blocked
    let result = system.validate_packet(
        current_time + 10,
        EpochType::Daily,
        99999,
        1,
        Some(source.clone()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::SourceBlocked);
}

#[test]
fn test_different_session_isolation() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Same sequence numbers but different sessions should be allowed
    let result1 = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result1, AntiReplayResult::Valid);

    let result2 = system.validate_packet(
        current_time + 1,
        EpochType::Daily,
        54321,
        1,
        Some("192.168.1.100".to_string()),
    ).unwrap();
    assert_eq!(result2, AntiReplayResult::Valid);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 2);
    assert_eq!(stats.valid_packets, 2);
    assert_eq!(stats.timestamp_replays, 0);
    assert_eq!(stats.sequence_replays, 0);
}

#[test]
fn test_reset_statistics() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Generate some activity
    system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap();
    system.validate_packet(current_time, EpochType::Daily, 12345, 1, None).unwrap(); // Replay

    let stats_before = system.get_stats();
    assert_eq!(stats_before.total_packets, 2);
    assert_eq!(stats_before.timestamp_replays, 1);

    // Reset statistics
    system.reset_stats();

    let stats_after = system.get_stats();
    assert_eq!(stats_after.total_packets, 0);
    assert_eq!(stats_after.timestamp_replays, 0);
    assert_eq!(stats_after.valid_packets, 0);
}

#[test]
fn test_memory_efficiency() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        duplicate_cache_size: 1000,
        ..Default::default()
    });

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Fill system with many unique packets
    for i in 0..2000 {
        system.validate_packet(
            current_time + i,
            EpochType::Daily,
            12345 + (i % 100),
            i as u32,
            Some(format!("192.168.{}.{}", (i / 256) % 256, i % 256)),
        ).unwrap();
    }

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 2000);
    assert!(stats.valid_packets > 1900); // Most should be valid

    // System should still function efficiently
    let result = system.validate_packet(
        current_time + 3000,
        EpochType::Daily,
        99999,
        1,
        Some("192.168.1.1".to_string()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::Valid);
}