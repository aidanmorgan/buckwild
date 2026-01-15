use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use buckwild_common::protocol::{
    ComprehensiveAntiReplaySystem, AntiReplayConfig, AntiReplayResult, 
    SecurityEventType, EpochType
};

#[test]
fn test_systematic_timestamp_replay_attack() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 5,
        attack_window_seconds: 30,
        block_duration_seconds: 300,
        ..Default::default()
    });

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();

    // Attacker captures a valid packet and replays it multiple times
    let captured_timestamp = current_time;
    let captured_session = 12345;
    let captured_sequence = 1;

    // First packet should be valid
    let result = system.validate_packet(
        captured_timestamp,
        EpochType::Daily,
        captured_session,
        captured_sequence,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::Valid);

    // Subsequent replays should be detected
    for i in 1..10 {
        let result = system.validate_packet(
            captured_timestamp,
            EpochType::Daily,
            captured_session,
            captured_sequence,
            Some(attacker_ip.clone()),
        ).unwrap();

        if i < 5 {
            assert_eq!(result, AntiReplayResult::TimestampReplay);
        } else {
            // Should be blocked after threshold
            assert_eq!(result, AntiReplayResult::SourceBlocked);
        }
    }

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 10);
    assert_eq!(stats.valid_packets, 1);
    assert_eq!(stats.timestamp_replays, 4);
    assert_eq!(stats.attack_patterns_detected, 1);

    // Verify security events
    let events = system.get_recent_security_events(20);
    let timestamp_replays = events.iter()
        .filter(|e| e.event_type == SecurityEventType::TimestampReplay)
        .count();
    let attack_patterns = events.iter()
        .filter(|e| e.event_type == SecurityEventType::AttackPatternDetected)
        .count();

    assert!(timestamp_replays >= 4);
    assert!(attack_patterns >= 1);
}

#[test]
fn test_sequence_number_replay_attack() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 3,
        sequence_window_size: 100,
        ..Default::default()
    });

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();
    let session_id = 12345;

    // Establish normal sequence progression
    for seq in 1..=5 {
        let result = system.validate_packet(
            current_time + seq,
            EpochType::Daily,
            session_id,
            seq as u32,
            Some(attacker_ip.clone()),
        ).unwrap();
        assert_eq!(result, AntiReplayResult::Valid);
    }

    // Attacker tries to replay old sequence numbers
    for i in 0..5 {
        let result = system.validate_packet(
            current_time + 10 + i,
            EpochType::Daily,
            session_id,
            2, // Replay sequence 2
            Some(attacker_ip.clone()),
        ).unwrap();

        if i < 3 {
            assert_eq!(result, AntiReplayResult::SequenceReplay);
        } else {
            // Should be blocked after threshold
            assert_eq!(result, AntiReplayResult::SourceBlocked);
        }
    }

    let stats = system.get_stats();
    assert!(stats.sequence_replays >= 3);
    assert_eq!(stats.attack_patterns_detected, 1);
}

#[test]
fn test_mixed_replay_attack_pattern() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 4,
        attack_window_seconds: 60,
        ..Default::default()
    });

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();

    // Attacker uses mixed attack strategies
    
    // 1. Valid packet
    let result1 = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result1, AntiReplayResult::Valid);

    // 2. Timestamp replay
    let result2 = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result2, AntiReplayResult::TimestampReplay);

    // 3. Different session, same sequence (should be valid)
    let result3 = system.validate_packet(
        current_time + 1,
        EpochType::Daily,
        54321,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result3, AntiReplayResult::Valid);

    // 4. Sequence replay on first session
    let result4 = system.validate_packet(
        current_time + 2,
        EpochType::Daily,
        12345,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result4, AntiReplayResult::SequenceReplay);

    // 5. Another timestamp replay
    let result5 = system.validate_packet(
        current_time,
        EpochType::Daily,
        99999,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result5, AntiReplayResult::TimestampReplay);

    // 6. Should be blocked now
    let result6 = system.validate_packet(
        current_time + 3,
        EpochType::Daily,
        11111,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result6, AntiReplayResult::SourceBlocked);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 6);
    assert_eq!(stats.valid_packets, 2);
    assert!(stats.timestamp_replays >= 2);
    assert!(stats.sequence_replays >= 1);
    assert_eq!(stats.attack_patterns_detected, 1);
}

#[test]
fn test_distributed_replay_attack() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 3,
        attack_window_seconds: 30,
        ..Default::default()
    });

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Multiple attackers from different IPs replay the same packet
    let captured_timestamp = current_time;
    let captured_session = 12345;
    let captured_sequence = 1;

    // First legitimate packet
    let result = system.validate_packet(
        captured_timestamp,
        EpochType::Daily,
        captured_session,
        captured_sequence,
        Some("192.168.1.1".to_string()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::Valid);

    // Multiple attackers replay from different IPs
    let attacker_ips = vec![
        "192.168.1.100",
        "192.168.1.101", 
        "192.168.1.102",
        "10.0.0.100",
        "10.0.0.101",
    ];

    for (i, ip) in attacker_ips.iter().enumerate() {
        // Each attacker tries multiple times
        for attempt in 0..4 {
            let result = system.validate_packet(
                captured_timestamp,
                EpochType::Daily,
                captured_session,
                captured_sequence,
                Some(ip.to_string()),
            ).unwrap();

            if attempt == 0 {
                // First attempt from each IP should be detected as timestamp replay
                assert_eq!(result, AntiReplayResult::TimestampReplay);
            } else if attempt < 3 {
                // Subsequent attempts should also be timestamp replays
                assert_eq!(result, AntiReplayResult::TimestampReplay);
            } else {
                // After threshold, IP should be blocked
                assert_eq!(result, AntiReplayResult::SourceBlocked);
            }
        }
    }

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 1 + (attacker_ips.len() * 4)); // 1 valid + attacks
    assert_eq!(stats.valid_packets, 1);
    assert!(stats.timestamp_replays >= attacker_ips.len() * 3);
    assert_eq!(stats.attack_patterns_detected, attacker_ips.len());

    let attack_info = system.get_attack_info();
    assert_eq!(attack_info.blocked_sources, attacker_ips.len());
}

#[test]
fn test_timing_based_replay_attack() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();

    // Attacker tries to replay packets at different times to avoid detection
    let valid_packet_time = current_time;
    let session_id = 12345;
    let sequence = 1;

    // Original valid packet
    let result1 = system.validate_packet(
        valid_packet_time,
        EpochType::Daily,
        session_id,
        sequence,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result1, AntiReplayResult::Valid);

    // Immediate replay (should be detected)
    let result2 = system.validate_packet(
        valid_packet_time,
        EpochType::Daily,
        session_id,
        sequence,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result2, AntiReplayResult::TimestampReplay);

    // Replay with slightly different timestamp (still within window, should be detected)
    let result3 = system.validate_packet(
        valid_packet_time + 1,
        EpochType::Daily,
        session_id,
        sequence,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result3, AntiReplayResult::SequenceReplay);

    // Try with much older timestamp (should be rejected as too old)
    let old_time = current_time.saturating_sub(70 * 2); // 70 seconds ago
    let result4 = system.validate_packet(
        old_time,
        EpochType::Daily,
        session_id,
        sequence + 1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result4, AntiReplayResult::TimestampReplay);

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 4);
    assert_eq!(stats.valid_packets, 1);
    assert!(stats.timestamp_replays >= 2);
    assert!(stats.sequence_replays >= 1);
}

#[test]
fn test_session_hijacking_attempt() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let legitimate_ip = "192.168.1.10".to_string();
    let attacker_ip = "192.168.1.100".to_string();
    let session_id = 12345;

    // Legitimate session establishment
    for seq in 1..=5 {
        let result = system.validate_packet(
            current_time + seq,
            EpochType::Daily,
            session_id,
            seq as u32,
            Some(legitimate_ip.clone()),
        ).unwrap();
        assert_eq!(result, AntiReplayResult::Valid);
    }

    // Attacker tries to hijack session by replaying packets
    for seq in 1..=5 {
        let result = system.validate_packet(
            current_time + seq + 10,
            EpochType::Daily,
            session_id,
            seq as u32,
            Some(attacker_ip.clone()),
        ).unwrap();
        
        // Should be detected as sequence replay
        assert_eq!(result, AntiReplayResult::SequenceReplay);
    }

    // Attacker tries to continue session with new sequence numbers
    let result = system.validate_packet(
        current_time + 20,
        EpochType::Daily,
        session_id,
        6,
        Some(attacker_ip.clone()),
    ).unwrap();
    
    // This might be valid if the attacker guessed the next sequence correctly
    // But the system should have blocked the attacker by now due to previous replays
    assert_eq!(result, AntiReplayResult::SourceBlocked);

    let stats = system.get_stats();
    assert_eq!(stats.valid_packets, 5); // Only legitimate packets
    assert!(stats.sequence_replays >= 5); // Attacker's replay attempts
    assert_eq!(stats.attack_patterns_detected, 1);
}

#[test]
fn test_nonce_replay_attack() {
    let system = ComprehensiveAntiReplaySystem::new();
    let session_id = 12345;
    let operation_type = "authentication";
    let challenge_data = b"challenge_data_for_auth";

    // Legitimate nonce generation and validation
    let nonce = system.generate_nonce(session_id, operation_type, challenge_data).unwrap();
    
    let result1 = system.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
    assert_eq!(result1, AntiReplayResult::Valid);

    // Attacker captures and replays the nonce
    for i in 0..5 {
        let result = system.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
        assert_eq!(result, AntiReplayResult::DuplicateReplay);
    }

    // Check security events
    let events = system.get_recent_security_events(10);
    let nonce_replays = events.iter()
        .filter(|e| e.event_type == SecurityEventType::SystematicReplay)
        .count();
    assert!(nonce_replays >= 5);
}

#[test]
fn test_clock_skew_attack() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();

    // Attacker sends packets with timestamps far in the future
    let future_times = vec![
        current_time + (20 * 2),  // 20 seconds in future
        current_time + (30 * 2),  // 30 seconds in future
        current_time + (60 * 2),  // 60 seconds in future
    ];

    for (i, future_time) in future_times.iter().enumerate() {
        let result = system.validate_packet(
            *future_time,
            EpochType::Daily,
            12345 + i as u64,
            1,
            Some(attacker_ip.clone()),
        ).unwrap();

        // Should be detected as timestamp replay (too far in future)
        assert_eq!(result, AntiReplayResult::TimestampReplay);
    }

    // After multiple clock skew attacks, source should be blocked
    let result = system.validate_packet(
        current_time + (120 * 2), // 120 seconds in future
        EpochType::Daily,
        99999,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::SourceBlocked);

    let stats = system.get_stats();
    assert!(stats.timestamp_replays >= 3);
    assert_eq!(stats.attack_patterns_detected, 1);
}

#[test]
fn test_burst_replay_attack() {
    let system = ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 10,
        attack_window_seconds: 5, // Short window for burst detection
        ..Default::default()
    });

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();

    // Legitimate packet
    let result = system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::Valid);

    // Burst of replay attacks in rapid succession
    for i in 1..20 {
        let result = system.validate_packet(
            current_time,
            EpochType::Daily,
            12345,
            1,
            Some(attacker_ip.clone()),
        ).unwrap();

        if i < 10 {
            assert_eq!(result, AntiReplayResult::TimestampReplay);
        } else {
            // Should be blocked after threshold
            assert_eq!(result, AntiReplayResult::SourceBlocked);
        }
    }

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 20);
    assert_eq!(stats.valid_packets, 1);
    assert_eq!(stats.timestamp_replays, 9);
    assert_eq!(stats.attack_patterns_detected, 1);
}

#[test]
fn test_cross_session_replay_attack() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();

    // Establish multiple legitimate sessions
    let sessions = vec![12345, 54321, 99999];
    
    for (i, &session_id) in sessions.iter().enumerate() {
        let result = system.validate_packet(
            current_time + i as u64,
            EpochType::Daily,
            session_id,
            1,
            Some(format!("192.168.1.{}", i + 1)),
        ).unwrap();
        assert_eq!(result, AntiReplayResult::Valid);
    }

    // Attacker tries to replay packets across different sessions
    for &session_id in &sessions {
        for &target_session in &sessions {
            if session_id != target_session {
                let result = system.validate_packet(
                    current_time + 10,
                    EpochType::Daily,
                    target_session,
                    1, // Same sequence as original
                    Some(attacker_ip.clone()),
                ).unwrap();
                
                // Should be detected as sequence replay
                assert_eq!(result, AntiReplayResult::SequenceReplay);
            }
        }
    }

    // Attacker should be blocked after multiple attempts
    let result = system.validate_packet(
        current_time + 20,
        EpochType::Daily,
        11111,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::SourceBlocked);

    let stats = system.get_stats();
    assert_eq!(stats.valid_packets, 3); // Only legitimate sessions
    assert!(stats.sequence_replays >= 6); // Cross-session replays
    assert_eq!(stats.attack_patterns_detected, 1);
}

#[test]
fn test_concurrent_replay_attacks() {
    let system = Arc::new(ComprehensiveAntiReplaySystem::with_config(AntiReplayConfig {
        attack_threshold: 5,
        attack_window_seconds: 30,
        ..Default::default()
    }));

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    // Legitimate packet
    system.validate_packet(
        current_time,
        EpochType::Daily,
        12345,
        1,
        Some("192.168.1.1".to_string()),
    ).unwrap();

    let num_attackers = 4;
    let attacks_per_attacker = 10;
    let mut handles = vec![];

    // Multiple concurrent attackers
    for attacker_id in 0..num_attackers {
        let system_clone = Arc::clone(&system);
        let attacker_ip = format!("192.168.1.{}", 100 + attacker_id);
        
        let handle = thread::spawn(move || {
            for i in 0..attacks_per_attacker {
                let result = system_clone.validate_packet(
                    current_time, // Same timestamp (replay)
                    EpochType::Daily,
                    12345,
                    1,
                    Some(attacker_ip.clone()),
                ).unwrap();

                // First few should be timestamp replays, then blocked
                if i < 5 {
                    assert_eq!(result, AntiReplayResult::TimestampReplay);
                } else {
                    assert_eq!(result, AntiReplayResult::SourceBlocked);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let stats = system.get_stats();
    assert_eq!(stats.total_packets, 1 + (num_attackers * attacks_per_attacker) as u64);
    assert_eq!(stats.valid_packets, 1);
    assert!(stats.timestamp_replays >= (num_attackers * 5) as u64);
    assert_eq!(stats.attack_patterns_detected, num_attackers as u64);

    let attack_info = system.get_attack_info();
    assert_eq!(attack_info.blocked_sources, num_attackers);
}

#[test]
fn test_sophisticated_timing_attack() {
    let system = ComprehensiveAntiReplaySystem::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let attacker_ip = "192.168.1.100".to_string();

    // Attacker tries to find timing patterns by varying timestamps slightly
    let base_timestamp = current_time;
    let session_id = 12345;

    // Original valid packet
    let result = system.validate_packet(
        base_timestamp,
        EpochType::Daily,
        session_id,
        1,
        Some("192.168.1.1".to_string()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::Valid);

    // Attacker tries variations around the valid timestamp
    let variations = vec![-2, -1, 0, 1, 2]; // Small variations in 500ms buckets
    
    for &variation in &variations {
        let test_timestamp = if variation < 0 {
            base_timestamp.saturating_sub((-variation) as u64)
        } else {
            base_timestamp + variation as u64
        };

        let result = system.validate_packet(
            test_timestamp,
            EpochType::Daily,
            session_id,
            1,
            Some(attacker_ip.clone()),
        ).unwrap();

        // All should be detected as replays (timestamp or sequence)
        assert!(matches!(result, 
            AntiReplayResult::TimestampReplay | 
            AntiReplayResult::SequenceReplay
        ));
    }

    // After multiple attempts, attacker should be blocked
    let result = system.validate_packet(
        current_time + 10,
        EpochType::Daily,
        99999,
        1,
        Some(attacker_ip.clone()),
    ).unwrap();
    assert_eq!(result, AntiReplayResult::SourceBlocked);

    let stats = system.get_stats();
    assert_eq!(stats.valid_packets, 1);
    assert!(stats.timestamp_replays + stats.sequence_replays >= 5);
    assert_eq!(stats.attack_patterns_detected, 1);
}