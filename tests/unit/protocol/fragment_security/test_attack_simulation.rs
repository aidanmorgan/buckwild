// Attack simulation tests for fragment security
//
// This module contains tests that simulate various fragment-based attacks
// including fragment bombs, overlap attacks, and injection attacks to
// validate the security engine's defensive capabilities.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread;

use buckwild_common::protocol::{
    FragmentSecurityValidator, FragmentSecurityConfig, FragmentValidationRequest,
    FragmentValidationResult, SessionId, FragmentMemoryManager, FragmentMemoryConfig,
    MemoryAllocationRequest, MemoryAllocationResult, FragmentRateLimiter,
    FragmentRateLimitConfig, RateLimitRequest, RateLimitResult,
    FragmentOverlapDetector, OverlapCheckRequest, OverlapDetectionResult,
    FragmentReassemblyManager, ReassemblyConfig, ReassemblyRequest, ReassemblyResult
};
use buckwild_common::crypto::hmac::HmacKey;

/// Create a test HMAC key
fn create_test_hmac_key() -> Arc<HmacKey> {
    let key_material = vec![0x42; 32];
    Arc::new(HmacKey::new(&key_material).unwrap())
}

/// Create a test fragment validation request
fn create_test_request(
    session_id: SessionId,
    fragment_id: u16,
    fragment_index: u16,
    total_fragments: u16,
    payload: Vec<u8>,
    source_ip: u32,
) -> FragmentValidationRequest {
    FragmentValidationRequest {
        session_id,
        fragment_id,
        fragment_index,
        total_fragments,
        payload,
        source_ip,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        session_key: Some(create_test_hmac_key()),
        hmac_policy: buckwild_common::protocol::HmacPolicy::Light,
    }
}

#[cfg(test)]
mod attack_simulation_tests {
    use super::*;

    #[test]
    fn test_fragment_bomb_attack_simulation() {
        // Simulate a fragment bomb attack where an attacker sends many fragments
        // to exhaust memory resources
        
        let memory_config = FragmentMemoryConfig {
            per_session_limit: 10 * 1024, // 10KB limit
            global_limit: 50 * 1024, // 50KB global limit
            ..Default::default()
        };
        
        let manager = FragmentMemoryManager::with_config(memory_config);
        let session_id = SessionId::Bits32(0x12345678);
        
        let mut successful_allocations = 0;
        let mut failed_allocations = 0;
        
        // Attempt to allocate many large fragments (bomb attack)
        for i in 0..100 {
            let request = MemoryAllocationRequest {
                session_id,
                fragment_id: i,
                size: 2048, // 2KB per fragment
                expected_fragments: 2,
                fragment_index: 0,
            };
            
            match manager.allocate_memory(&request) {
                MemoryAllocationResult::Success => {
                    successful_allocations += 1;
                }
                MemoryAllocationResult::SessionLimitExceeded |
                MemoryAllocationResult::GlobalLimitExceeded |
                MemoryAllocationResult::MemoryPressure => {
                    failed_allocations += 1;
                }
                _ => {}
            }
        }
        
        // Should have limited successful allocations due to memory limits
        assert!(successful_allocations < 10, "Too many allocations succeeded: {}", successful_allocations);
        assert!(failed_allocations > 90, "Not enough allocations failed: {}", failed_allocations);
        
        let stats = manager.get_memory_stats();
        assert!(stats.memory_exhaustion_events > 0);
        assert!(stats.global_memory_usage < 50 * 1024);
    }

    #[test]
    fn test_fragment_rate_limit_attack_simulation() {
        // Simulate a rate limiting attack where an attacker floods with fragments
        
        let rate_config = FragmentRateLimitConfig {
            fragments_per_second_per_session: 5,
            session_burst_capacity: 10,
            packets_per_second_per_source: 20,
            source_packet_burst_capacity: 30,
            ..Default::default()
        };
        
        let limiter = FragmentRateLimiter::with_config(rate_config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;
        
        let mut allowed_count = 0;
        let mut blocked_count = 0;
        
        // Flood with fragments (rate limit attack)
        for i in 0..100 {
            let request = RateLimitRequest {
                session_id,
                source_ip,
                fragment_size: 1024,
                fragment_id: i,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };
            
            match limiter.check_rate_limit(&request) {
                RateLimitResult::Allowed => {
                    allowed_count += 1;
                }
                RateLimitResult::SessionRateLimitExceeded |
                RateLimitResult::SourceRateLimitExceeded |
                RateLimitResult::SessionBlocked |
                RateLimitResult::SourceBlocked => {
                    blocked_count += 1;
                }
                _ => {}
            }
        }
        
        // Should have limited allowed requests due to rate limiting
        assert!(allowed_count < 50, "Too many requests allowed: {}", allowed_count);
        assert!(blocked_count > 50, "Not enough requests blocked: {}", blocked_count);
        
        let stats = limiter.get_rate_limit_stats();
        assert!(stats.session_violations > 0 || stats.source_violations > 0);
    }

    #[test]
    fn test_fragment_overlap_attack_simulation() {
        // Simulate fragment overlap attacks with conflicting payloads
        
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // First fragment
        let request1 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 100,
            payload: vec![0x01; 100],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        let result = detector.check_overlap(&request1).unwrap();
        assert_eq!(result, OverlapDetectionResult::NoOverlap);
        
        // Overlapping fragment with different payload (attack)
        let request2 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 1,
            fragment_offset: 50, // Overlaps with first fragment
            fragment_length: 100,
            payload: vec![0x02; 100], // Different payload
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        let result = detector.check_overlap(&request2).unwrap();
        assert_eq!(result, OverlapDetectionResult::ConflictingOverlap);
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.overlaps_detected, 1);
        assert_eq!(stats.constant_time_comparisons, 1);
    }

    #[test]
    fn test_cross_session_injection_attack_simulation() {
        // Simulate cross-session injection attacks
        
        let validator = FragmentSecurityValidator::new();
        let legitimate_session = SessionId::Bits32(0x12345678);
        let attacker_session = SessionId::Bits32(0x87654321);
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        // Register legitimate session
        validator.register_session_binding(
            legitimate_session,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        let mut injection_attempts = 0;
        let mut successful_injections = 0;
        
        // Attempt cross-session injection attacks
        for i in 0..50 {
            let request = create_test_request(
                attacker_session, // Wrong session ID
                1,
                i % 10,
                10,
                vec![0xFF; 1024], // Malicious payload
                source_ip,
            );
            
            injection_attempts += 1;
            
            match validator.validate_fragment(&request) {
                FragmentValidationResult::Valid => {
                    successful_injections += 1;
                }
                FragmentValidationResult::SessionNotFound |
                FragmentValidationResult::CrossSessionInjection => {
                    // Expected - attack blocked
                }
                _ => {}
            }
        }
        
        // All injection attempts should be blocked
        assert_eq!(successful_injections, 0, "Cross-session injection succeeded");
        assert_eq!(injection_attempts, 50);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.injection_attempts, 50);
    }

    #[test]
    fn test_source_ip_spoofing_attack_simulation() {
        // Simulate source IP spoofing attacks
        
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let legitimate_source = 0x7F000001;
        let spoofed_sources = vec![0x7F000002, 0x7F000003, 0x7F000004];
        
        // Register session with specific allowed source
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![legitimate_source],
        ).unwrap();
        
        let mut spoofing_attempts = 0;
        let mut successful_spoofs = 0;
        
        // Attempt spoofing attacks from different IPs
        for &spoofed_ip in &spoofed_sources {
            for i in 0..20 {
                let request = create_test_request(
                    session_id,
                    1,
                    i % 5,
                    5,
                    vec![0xAA; 512],
                    spoofed_ip,
                );
                
                spoofing_attempts += 1;
                
                match validator.validate_fragment(&request) {
                    FragmentValidationResult::Valid => {
                        successful_spoofs += 1;
                    }
                    FragmentValidationResult::OriginValidationFailed |
                    FragmentValidationResult::SourceBlocked => {
                        // Expected - attack blocked
                    }
                    _ => {}
                }
            }
        }
        
        // All spoofing attempts should be blocked
        assert_eq!(successful_spoofs, 0, "Source IP spoofing succeeded");
        assert_eq!(spoofing_attempts, 60);
        
        let stats = validator.get_security_stats();
        assert!(stats.origin_failures > 0);
        assert!(stats.source_violations > 0);
    }

    #[test]
    fn test_fragment_reassembly_bomb_attack_simulation() {
        // Simulate reassembly bomb attacks with many incomplete reassemblies
        
        let reassembly_config = ReassemblyConfig {
            max_fragments_per_reassembly: 100,
            max_reassembled_size: 10 * 1024, // 10KB limit
            max_concurrent_reassemblies: 50,
            ..Default::default()
        };
        
        let manager = FragmentReassemblyManager::with_config(reassembly_config);
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let mut successful_attempts = 0;
        let mut failed_attempts = 0;
        
        // Create many incomplete reassemblies (bomb attack)
        for session_num in 0..200 {
            let session_id = SessionId::Bits32(0x10000000 + session_num);
            
            // Add only first fragment of each reassembly (incomplete)
            let request = ReassemblyRequest {
                session_id,
                fragment_id: 1,
                fragment_index: 0,
                fragment_offset: 0,
                payload: vec![0xBB; 1024], // 1KB fragment
                expected_fragments: 10, // But only send first fragment
                source_ip,
                arrival_time: current_time,
            };
            
            match manager.add_fragment(&request).unwrap() {
                ReassemblyResult::FragmentAdded => {
                    successful_attempts += 1;
                }
                ReassemblyResult::ReassemblyLimitExceeded |
                ReassemblyResult::MemoryAllocationFailure => {
                    failed_attempts += 1;
                }
                _ => {}
            }
        }
        
        // Should have limited successful attempts due to reassembly limits
        assert!(successful_attempts < 100, "Too many reassemblies allowed: {}", successful_attempts);
        assert!(failed_attempts > 100, "Not enough reassemblies blocked: {}", failed_attempts);
        
        let stats = manager.get_reassembly_stats();
        assert!(stats.active_sessions < 200);
    }

    #[test]
    fn test_timing_attack_simulation() {
        // Simulate timing attacks against constant-time operations
        
        let detector = FragmentOverlapDetector::new();
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // First fragment
        let request1 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 1000,
            payload: vec![0x01; 1000],
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        detector.check_overlap(&request1).unwrap();
        
        // Measure timing for identical payload (should be constant time)
        let start_time = std::time::Instant::now();
        let request2 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 1000,
            payload: vec![0x01; 1000], // Identical payload
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        let result2 = detector.check_overlap(&request2).unwrap();
        let identical_time = start_time.elapsed();
        
        // Measure timing for different payload (should be constant time)
        let start_time = std::time::Instant::now();
        let request3 = OverlapCheckRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            fragment_offset: 0,
            fragment_length: 1000,
            payload: vec![0x02; 1000], // Different payload
            expected_fragments: 2,
            source_ip,
            arrival_time: current_time,
        };
        
        let result3 = detector.check_overlap(&request3).unwrap();
        let different_time = start_time.elapsed();
        
        // Results should be different but timing should be similar (constant-time)
        assert_eq!(result2, OverlapDetectionResult::ExactDuplicate);
        assert_eq!(result3, OverlapDetectionResult::ConflictingOverlap);
        
        // Timing difference should be minimal (within 10% tolerance)
        let time_diff = if identical_time > different_time {
            identical_time - different_time
        } else {
            different_time - identical_time
        };
        
        let max_time = std::cmp::max(identical_time, different_time);
        let tolerance = max_time / 10; // 10% tolerance
        
        assert!(time_diff <= tolerance, 
            "Timing difference too large: {:?} vs {:?} (diff: {:?})", 
            identical_time, different_time, time_diff);
        
        let stats = detector.get_overlap_stats();
        assert_eq!(stats.constant_time_comparisons, 2);
    }

    #[test]
    fn test_concurrent_attack_simulation() {
        // Simulate concurrent attacks from multiple threads
        
        let validator = Arc::new(FragmentSecurityValidator::new());
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let legitimate_source = 0x7F000001;
        
        // Register legitimate session
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![legitimate_source],
        ).unwrap();
        
        let mut handles = vec![];
        
        // Spawn multiple attacker threads
        for thread_id in 0..10 {
            let validator_clone = Arc::clone(&validator);
            let handle = thread::spawn(move || {
                let attacker_source = 0x7F000000 + thread_id + 10; // Different attacker IPs
                let mut blocked_count = 0;
                
                // Each thread attempts 50 attacks
                for i in 0..50 {
                    let request = create_test_request(
                        session_id,
                        1,
                        i % 10,
                        10,
                        vec![0xCC; 256],
                        attacker_source,
                    );
                    
                    match validator_clone.validate_fragment(&request) {
                        FragmentValidationResult::OriginValidationFailed |
                        FragmentValidationResult::SourceBlocked => {
                            blocked_count += 1;
                        }
                        _ => {}
                    }
                }
                
                blocked_count
            });
            handles.push(handle);
        }
        
        // Wait for all attacker threads and count blocked attempts
        let mut total_blocked = 0;
        for handle in handles {
            total_blocked += handle.join().unwrap();
        }
        
        // All attacks should be blocked
        assert_eq!(total_blocked, 500, "Not all concurrent attacks were blocked");
        
        let stats = validator.get_security_stats();
        assert!(stats.origin_failures >= 500);
        assert!(stats.source_violations >= 500);
    }

    #[test]
    fn test_mixed_attack_scenario_simulation() {
        // Simulate a complex attack scenario with multiple attack vectors
        
        let validator = Arc::new(FragmentSecurityValidator::new());
        let memory_manager = Arc::new(FragmentMemoryManager::new());
        let rate_limiter = Arc::new(FragmentRateLimiter::new());
        
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let legitimate_source = 0x7F000001;
        
        // Register legitimate session
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![legitimate_source],
        ).unwrap();
        
        let mut attack_results = vec![];
        
        // Attack vector 1: Cross-session injection
        for i in 0..20 {
            let fake_session = SessionId::Bits32(0x99999999);
            let request = create_test_request(
                fake_session,
                1,
                i % 5,
                5,
                vec![0xDD; 512],
                legitimate_source,
            );
            
            let result = validator.validate_fragment(&request);
            attack_results.push(("injection", result == FragmentValidationResult::SessionNotFound));
        }
        
        // Attack vector 2: Source IP spoofing
        for i in 0..20 {
            let spoofed_ip = 0x7F000000 + i + 100;
            let request = create_test_request(
                session_id,
                1,
                i % 5,
                5,
                vec![0xEE; 512],
                spoofed_ip,
            );
            
            let result = validator.validate_fragment(&request);
            attack_results.push(("spoofing", result == FragmentValidationResult::OriginValidationFailed));
        }
        
        // Attack vector 3: Rate limiting attack
        for i in 0..50 {
            let rate_request = RateLimitRequest {
                session_id,
                source_ip: legitimate_source,
                fragment_size: 1024,
                fragment_id: i,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };
            
            let result = rate_limiter.check_rate_limit(&rate_request);
            attack_results.push(("rate_limit", result != RateLimitResult::Allowed));
        }
        
        // Attack vector 4: Memory exhaustion
        for i in 0..30 {
            let mem_request = MemoryAllocationRequest {
                session_id,
                fragment_id: i,
                size: 10 * 1024, // 10KB per fragment
                expected_fragments: 2,
                fragment_index: 0,
            };
            
            let result = memory_manager.allocate_memory(&mem_request);
            attack_results.push(("memory", result != MemoryAllocationResult::Success));
        }
        
        // Analyze attack results
        let injection_blocked = attack_results.iter()
            .filter(|(attack_type, blocked)| attack_type == &"injection" && *blocked)
            .count();
        
        let spoofing_blocked = attack_results.iter()
            .filter(|(attack_type, blocked)| attack_type == &"spoofing" && *blocked)
            .count();
        
        let rate_limit_blocked = attack_results.iter()
            .filter(|(attack_type, blocked)| attack_type == &"rate_limit" && *blocked)
            .count();
        
        let memory_blocked = attack_results.iter()
            .filter(|(attack_type, blocked)| attack_type == &"memory" && *blocked)
            .count();
        
        // Verify that attacks were properly defended against
        assert_eq!(injection_blocked, 20, "Cross-session injection not fully blocked");
        assert_eq!(spoofing_blocked, 20, "Source IP spoofing not fully blocked");
        assert!(rate_limit_blocked > 30, "Rate limiting not effective: {}", rate_limit_blocked);
        assert!(memory_blocked > 20, "Memory exhaustion not prevented: {}", memory_blocked);
        
        // Verify security statistics
        let validator_stats = validator.get_security_stats();
        let memory_stats = memory_manager.get_memory_stats();
        let rate_stats = rate_limiter.get_rate_limit_stats();
        
        assert!(validator_stats.injection_attempts > 0);
        assert!(validator_stats.origin_failures > 0);
        assert!(memory_stats.memory_exhaustion_events > 0);
        assert!(rate_stats.session_violations > 0 || rate_stats.source_violations > 0);
    }
}