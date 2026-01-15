use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use buckwild_common::protocol::{
    TimestampValidator, DuplicateDetector, EnumerationDetector, ReplayPreventionEngine,
    EpochType, DuplicateDetectionResult, EnumerationDetectionResult, ReplayPreventionResult
};

#[test]
fn test_timestamp_validation_performance() {
    let validator = TimestampValidator::new();
    let current_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 / 500;

    let start = Instant::now();
    let iterations = 100_000;

    for i in 0..iterations {
        let result = validator.validate_timestamp(
            current_time + (i % 1000), // Vary timestamp to avoid all duplicates
            EpochType::Daily,
            12345 + (i % 100), // Vary session ID
            i as u32,
        ).unwrap();
        
        // Most should be valid (not duplicates)
        if i % 1000 != 0 {
            assert!(matches!(result, buckwild_common::protocol::TimestampValidationResult::Valid));
        }
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    
    println!("Timestamp validation: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 50,000 validations per second
    assert!(ops_per_sec > 50_000.0, "Performance too low: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_duplicate_detection_performance() {
    let detector = DuplicateDetector::new(10_000);
    
    let start = Instant::now();
    let iterations = 100_000;

    for i in 0..iterations {
        let result = detector.detect_duplicate(
            i, // Unique timestamp
            12345 + (i % 1000), // Vary session ID
            i as u32, // Unique sequence
            None,
        ).unwrap();
        
        assert_eq!(result, DuplicateDetectionResult::Unique);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    
    println!("Duplicate detection: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 75,000 detections per second
    assert!(ops_per_sec > 75_000.0, "Performance too low: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_enumeration_detection_performance() {
    let detector = EnumerationDetector::new();
    
    let start = Instant::now();
    let iterations = 50_000;

    for i in 0..iterations {
        let source_ip = IpAddr::from([192, 168, (i / 256) as u8, (i % 256) as u8]);
        let result = detector.check_connection_attempt(
            source_ip,
            8080 + (i % 1000) as u16,
            Some(12345 + i),
            None,
        ).unwrap();
        
        // Most should be allowed initially
        if i % 100 < 10 { // First 10 attempts per IP should be allowed
            assert_eq!(result, EnumerationDetectionResult::Allowed);
        }
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    
    println!("Enumeration detection: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 25,000 checks per second
    assert!(ops_per_sec > 25_000.0, "Performance too low: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_replay_prevention_performance() {
    let engine = ReplayPreventionEngine::new();
    
    let start = Instant::now();
    let iterations = 100_000;

    for i in 0..iterations {
        let session_id = 12345 + (i % 1000);
        let sequence = i as u32;
        
        let result = engine.validate_sequence(session_id, sequence).unwrap();
        
        // Should be allowed or out of order
        assert!(matches!(result, 
            ReplayPreventionResult::Allowed | 
            ReplayPreventionResult::OutOfOrder
        ));
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    
    println!("Replay prevention: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 80,000 validations per second
    assert!(ops_per_sec > 80_000.0, "Performance too low: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_concurrent_timestamp_validation() {
    let validator = Arc::new(TimestampValidator::new());
    let num_threads = 8;
    let iterations_per_thread = 10_000;
    
    let start = Instant::now();
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let validator_clone = Arc::clone(&validator);
        let handle = thread::spawn(move || {
            let base_time = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64 / 500;

            for i in 0..iterations_per_thread {
                let timestamp = base_time + (thread_id * iterations_per_thread + i) as u64;
                let session_id = 12345 + thread_id as u64;
                let sequence = i as u32;
                
                validator_clone.validate_timestamp(
                    timestamp,
                    EpochType::Daily,
                    session_id,
                    sequence,
                ).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let total_ops = num_threads * iterations_per_thread;
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();
    
    println!("Concurrent timestamp validation: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 200,000 concurrent validations per second
    assert!(ops_per_sec > 200_000.0, "Concurrent performance too low: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_concurrent_duplicate_detection() {
    let detector = Arc::new(DuplicateDetector::new(50_000));
    let num_threads = 8;
    let iterations_per_thread = 10_000;
    
    let start = Instant::now();
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let detector_clone = Arc::clone(&detector);
        let handle = thread::spawn(move || {
            for i in 0..iterations_per_thread {
                let timestamp = (thread_id * iterations_per_thread + i) as u64;
                let session_id = 12345 + thread_id as u64;
                let sequence = i as u32;
                
                detector_clone.detect_duplicate(
                    timestamp,
                    session_id,
                    sequence,
                    None,
                ).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let total_ops = num_threads * iterations_per_thread;
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();
    
    println!("Concurrent duplicate detection: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 300,000 concurrent detections per second
    assert!(ops_per_sec > 300_000.0, "Concurrent performance too low: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_memory_usage_under_load() {
    let detector = DuplicateDetector::new(100_000);
    
    // Fill detector with entries
    for i in 0..50_000 {
        detector.detect_duplicate(i, 12345, i as u32, None).unwrap();
    }
    
    let info = detector.get_cache_info();
    let memory_per_entry = info.memory_usage_bytes / info.current_size;
    
    println!("Memory usage: {} bytes for {} entries ({} bytes/entry)", 
             info.memory_usage_bytes, info.current_size, memory_per_entry);
    
    // Memory usage should be reasonable (less than 200 bytes per entry)
    assert!(memory_per_entry < 200, "Memory usage too high: {} bytes/entry", memory_per_entry);
    
    // Cache utilization should be reasonable
    assert!(info.utilization_percent > 40.0, "Cache utilization too low: {:.1}%", info.utilization_percent);
}

#[test]
fn test_cleanup_performance() {
    let detector = DuplicateDetector::new(100_000);
    
    // Fill detector with entries
    for i in 0..50_000 {
        detector.detect_duplicate(i, 12345, i as u32, None).unwrap();
    }
    
    let start = Instant::now();
    let removed = detector.cleanup_expired_entries(Duration::from_nanos(1)).unwrap();
    let elapsed = start.elapsed();
    
    println!("Cleanup: removed {} entries in {:?}", removed, elapsed);
    
    // Cleanup should be fast (less than 100ms for 50k entries)
    assert!(elapsed < Duration::from_millis(100), "Cleanup too slow: {:?}", elapsed);
    assert_eq!(removed, 50_000);
}

#[test]
fn test_nonce_generation_performance() {
    let engine = ReplayPreventionEngine::new();
    let challenge_data = b"test_challenge_data_for_performance_testing";
    
    let start = Instant::now();
    let iterations = 10_000;
    
    for i in 0..iterations {
        let nonce = engine.generate_nonce(
            12345 + i,
            "test_operation",
            challenge_data,
        ).unwrap();
        
        assert_eq!(nonce.len(), 32);
    }
    
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    
    println!("Nonce generation: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 5,000 nonce generations per second
    assert!(ops_per_sec > 5_000.0, "Nonce generation too slow: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_nonce_validation_performance() {
    let engine = ReplayPreventionEngine::new();
    let challenge_data = b"test_challenge_data_for_performance_testing";
    let session_id = 12345;
    let operation_type = "test_operation";
    
    // Generate nonces first
    let mut nonces = Vec::new();
    for i in 0..1000 {
        let nonce = engine.generate_nonce(
            session_id + i,
            operation_type,
            challenge_data,
        ).unwrap();
        nonces.push((nonce, session_id + i));
    }
    
    let start = Instant::now();
    
    for (nonce, session) in nonces {
        let result = engine.validate_nonce(
            &nonce,
            session,
            operation_type,
            challenge_data,
        ).unwrap();
        
        assert_eq!(result, ReplayPreventionResult::Allowed);
    }
    
    let elapsed = start.elapsed();
    let ops_per_sec = 1000.0 / elapsed.as_secs_f64();
    
    println!("Nonce validation: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 2,000 nonce validations per second
    assert!(ops_per_sec > 2_000.0, "Nonce validation too slow: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_attack_simulation_performance() {
    let detector = EnumerationDetector::new();
    let attacker_ip = IpAddr::from([192, 168, 1, 100]);
    
    let start = Instant::now();
    let mut allowed_count = 0;
    let mut blocked_count = 0;
    
    // Simulate rapid connection attempts from single IP
    for i in 0..1000 {
        let result = detector.check_connection_attempt(
            attacker_ip,
            8080 + (i % 100) as u16,
            Some(12345 + i),
            Some("connection_failed".to_string()),
        ).unwrap();
        
        match result {
            EnumerationDetectionResult::Allowed => allowed_count += 1,
            EnumerationDetectionResult::RateLimited | 
            EnumerationDetectionResult::Blocked(_) |
            EnumerationDetectionResult::AttackDetected => blocked_count += 1,
        }
    }
    
    let elapsed = start.elapsed();
    let ops_per_sec = 1000.0 / elapsed.as_secs_f64();
    
    println!("Attack simulation: {:.0} ops/sec, {} allowed, {} blocked", 
             ops_per_sec, allowed_count, blocked_count);
    
    // Should detect and block attacks quickly
    assert!(blocked_count > allowed_count, "Attack detection failed");
    assert!(ops_per_sec > 10_000.0, "Attack detection too slow: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_constant_time_validation_performance() {
    use buckwild_common::crypto::constant_time_security::ConstantTimeValidator;
    
    let data1 = vec![0x42u8; 32];
    let data2 = vec![0x42u8; 32];
    let data3 = vec![0x43u8; 32];
    
    let start = Instant::now();
    let iterations = 1_000_000;
    
    for i in 0..iterations {
        let result = if i % 2 == 0 {
            ConstantTimeValidator::compare_bytes(&data1, &data2)
        } else {
            ConstantTimeValidator::compare_bytes(&data1, &data3)
        };
        
        // Prevent optimization
        std::hint::black_box(result);
    }
    
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    
    println!("Constant-time comparison: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 1,000,000 comparisons per second
    assert!(ops_per_sec > 1_000_000.0, "Constant-time comparison too slow: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_mixed_workload_performance() {
    let timestamp_validator = Arc::new(TimestampValidator::new());
    let duplicate_detector = Arc::new(DuplicateDetector::new(10_000));
    let enumeration_detector = Arc::new(EnumerationDetector::new());
    let replay_engine = Arc::new(ReplayPreventionEngine::new());
    
    let start = Instant::now();
    let iterations = 10_000;
    
    for i in 0..iterations {
        let current_time = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 / 500;
        
        let session_id = 12345 + (i % 100);
        let sequence = i as u32;
        let source_ip = IpAddr::from([192, 168, (i / 256) as u8, (i % 256) as u8]);
        
        // Mixed workload simulation
        timestamp_validator.validate_timestamp(
            current_time + i,
            EpochType::Daily,
            session_id,
            sequence,
        ).unwrap();
        
        duplicate_detector.detect_duplicate(
            current_time + i,
            session_id,
            sequence,
            Some(source_ip),
        ).unwrap();
        
        if i % 10 == 0 {
            enumeration_detector.check_connection_attempt(
                source_ip,
                8080,
                Some(session_id),
                None,
            ).unwrap();
        }
        
        if i % 20 == 0 {
            replay_engine.validate_sequence(session_id, sequence).unwrap();
        }
    }
    
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    
    println!("Mixed workload: {:.0} ops/sec", ops_per_sec);
    
    // Should handle at least 15,000 mixed operations per second
    assert!(ops_per_sec > 15_000.0, "Mixed workload too slow: {:.0} ops/sec", ops_per_sec);
}