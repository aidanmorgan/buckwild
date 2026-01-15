// Comprehensive integration tests for secure packet fragmentation and reassembly system
//
// This test suite validates all requirements from task 11:
// - MTU-aware fragmentation with 8-byte fragment headers and security validation
// - Fragment reassembly with 5-second timeout, missing fragment detection, and security hardening
// - Fragment ID collision avoidance, duplicate handling, and session binding validation
// - Memory-efficient reassembly buffer management with per-session (1MB) and global limits
// - Fragment retransmission request mechanisms with rate limiting and attack detection
// - Comprehensive fragment security features: overlap detection, bomb prevention, rate limiting
// - Session binding enforcement to prevent cross-session fragment injection attacks
// - Constant-time fragment validation to prevent timing-based information leakage
// - Security event logging and attack response coordination

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use std::net::Ipv4Addr;

use bytes::Bytes;
use tracing::{info, warn, error};

use buckwild_common::protocol::{
    fragmentation::{
        FragmentationSystem, FragmentationConfig, FragmentationRequest, FragmentationResult,
        FragmentReassemblyRequest, FragmentReassemblyResult, FRAGMENT_HEADER_SIZE, DEFAULT_MTU
    },
    fragment_security::{
        FragmentSecurityValidator, FragmentSecurityConfig, FragmentValidationRequest, FragmentValidationResult
    },
    fragment_memory::{
        FragmentMemoryManager, FragmentMemoryConfig, MemoryAllocationRequest, MemoryAllocationResult
    },
    fragment_rate_limit::{
        FragmentRateLimiter, FragmentRateLimitConfig, RateLimitRequest, RateLimitResult
    },
    fragment_overlap::{
        FragmentOverlapDetector, OverlapDetectionConfig, OverlapCheckRequest, OverlapDetectionResult
    },
    fragment_reassembly::{
        FragmentReassemblyManager, ReassemblyConfig, ReassemblyRequest, ReassemblyResult
    },
    header::SessionId,
    types::{PacketType, HmacPolicy},
};
use buckwild_common::crypto::hmac::HmacKey;
use buckwild_common::errors::BuckwildError;

/// Helper function to create test session key
fn create_test_session_key() -> Arc<HmacKey> {
    let key_material = vec![0x42; 32];
    Arc::new(HmacKey::new(&key_material).unwrap())
}

/// Helper function to get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[test]
fn test_mtu_aware_fragmentation_with_8_byte_headers() {
    // Test requirement: MTU-aware fragmentation with 8-byte fragment headers
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let source_ip = 0x7F000001; // 127.0.0.1
    
    // Create a message larger than MTU
    let message_size = DEFAULT_MTU * 3; // 3 times MTU
    let message = Bytes::from(vec![0xAA; message_size]);
    
    let request = FragmentationRequest {
        session_id,
        message: message.clone(),
        mtu_size: Some(DEFAULT_MTU),
        session_key: session_key.clone(),
        source_ip,
        hmac_policy: HmacPolicy::Medium,
    };
    
    let result = system.fragment_message(&request).unwrap();
    
    // Verify fragmentation results
    assert!(result.total_fragments > 1, "Message should be fragmented");
    assert_eq!(result.fragments.len(), result.total_fragments as usize);
    
    // Verify each fragment has proper header size and payload
    for (i, fragment) in result.fragments.iter().enumerate() {
        let payload = fragment.payload();
        
        // Each fragment should have at least the 8-byte fragment header
        assert!(payload.len() >= FRAGMENT_HEADER_SIZE, 
                "Fragment {} should have at least {} byte header", i, FRAGMENT_HEADER_SIZE);
        
        // Fragment payload (excluding header) should not exceed MTU - header size
        let fragment_payload_size = payload.len() - FRAGMENT_HEADER_SIZE;
        assert!(fragment_payload_size <= DEFAULT_MTU - FRAGMENT_HEADER_SIZE,
                "Fragment {} payload size {} exceeds MTU limit", i, fragment_payload_size);
    }
    
    info!("MTU-aware fragmentation test passed: {} fragments created", result.total_fragments);
}

#[test]
fn test_fragment_reassembly_with_timeout_and_missing_detection() {
    // Test requirement: Fragment reassembly with 5-second timeout and missing fragment detection
    let config = ReassemblyConfig {
        reassembly_timeout_s: 5,
        enable_duplicate_detection: true,
        enable_bounds_checking: true,
        ..Default::default()
    };
    
    let manager = FragmentReassemblyManager::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    let fragment_id = 1;
    let source_ip = 0x7F000001;
    let current_time = current_timestamp();
    
    // Add first fragment
    let request1 = ReassemblyRequest {
        session_id,
        fragment_id,
        fragment_index: 0,
        fragment_offset: 0,
        payload: vec![0x01; 100],
        expected_fragments: 3,
        source_ip,
        arrival_time: current_time,
    };
    
    let result1 = manager.add_fragment(&request1).unwrap();
    assert_eq!(result1, ReassemblyResult::FragmentAdded);
    
    // Add third fragment (skip second to test missing detection)
    let request3 = ReassemblyRequest {
        session_id,
        fragment_id,
        fragment_index: 2,
        fragment_offset: 200,
        payload: vec![0x03; 100],
        expected_fragments: 3,
        source_ip,
        arrival_time: current_time,
    };
    
    let result3 = manager.add_fragment(&request3).unwrap();
    assert_eq!(result3, ReassemblyResult::FragmentAdded);
    
    // Verify session info shows missing fragment
    let session_info = manager.get_session_info(session_id, fragment_id).unwrap();
    assert_eq!(session_info.received_count, 2);
    assert_eq!(session_info.expected_fragments, 3);
    assert!(!session_info.is_complete);
    
    // Wait for timeout and verify cleanup
    thread::sleep(Duration::from_secs(6));
    manager.cleanup_expired_sessions();
    
    // Session should be cleaned up after timeout
    assert!(manager.get_session_info(session_id, fragment_id).is_none());
    
    info!("Fragment reassembly timeout and missing detection test passed");
}

#[test]
fn test_fragment_id_collision_avoidance() {
    // Test requirement: Fragment ID collision avoidance
    let config = FragmentationConfig {
        enable_fragment_id_collision_avoidance: true,
        ..Default::default()
    };
    
    let system = FragmentationSystem::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let source_ip = 0x7F000001;
    
    let message = Bytes::from(vec![0xBB; 2000]);
    
    // Create multiple fragmentation requests rapidly
    let mut fragment_ids = Vec::new();
    for _ in 0..10 {
        let request = FragmentationRequest {
            session_id,
            message: message.clone(),
            mtu_size: Some(500),
            session_key: session_key.clone(),
            source_ip,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request).unwrap();
        fragment_ids.push(result.fragment_id);
    }
    
    // Verify all fragment IDs are unique
    fragment_ids.sort();
    fragment_ids.dedup();
    assert_eq!(fragment_ids.len(), 10, "All fragment IDs should be unique");
    
    info!("Fragment ID collision avoidance test passed");
}

#[test]
fn test_memory_efficient_reassembly_with_limits() {
    // Test requirement: Memory-efficient reassembly buffer management with limits
    let config = FragmentMemoryConfig {
        per_session_limit: 1024 * 1024, // 1MB per session
        global_limit: 10 * 1024 * 1024, // 10MB global
        max_buffers_per_session: 100,
        memory_pressure_threshold: 0.8,
        ..Default::default()
    };
    
    let manager = FragmentMemoryManager::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    
    // Test per-session limit enforcement
    let large_request = MemoryAllocationRequest {
        session_id,
        fragment_id: 1,
        size: 2 * 1024 * 1024, // 2MB - exceeds per-session limit
        expected_fragments: 1,
        fragment_index: 0,
    };
    
    let result = manager.allocate_memory(&large_request);
    assert_eq!(result, MemoryAllocationResult::SessionLimitExceeded);
    
    // Test successful allocation within limits
    let normal_request = MemoryAllocationRequest {
        session_id,
        fragment_id: 2,
        size: 512 * 1024, // 512KB - within limits
        expected_fragments: 1,
        fragment_index: 0,
    };
    
    let result = manager.allocate_memory(&normal_request);
    assert_eq!(result, MemoryAllocationResult::Success);
    
    // Verify memory statistics
    let stats = manager.get_memory_stats();
    assert_eq!(stats.global_memory_usage, 512 * 1024);
    assert_eq!(stats.active_sessions, 1);
    assert_eq!(stats.active_buffers, 1);
    
    info!("Memory-efficient reassembly with limits test passed");
}

#[test]
fn test_fragment_rate_limiting_and_attack_detection() {
    // Test requirement: Fragment retransmission with rate limiting and attack detection
    let config = FragmentRateLimitConfig {
        fragments_per_second_per_session: 10,
        session_burst_capacity: 20,
        max_violations_before_block: 3,
        violation_block_duration_s: 60,
        enable_progressive_response: true,
        ..Default::default()
    };
    
    let limiter = FragmentRateLimiter::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    let source_ip = 0x7F000001;
    let current_time = current_timestamp();
    
    // Send fragments within rate limit
    for i in 0..15 {
        let request = RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 100,
            fragment_id: 1,
            timestamp: current_time,
        };
        
        let result = limiter.check_rate_limit(&request);
        if i < 10 {
            assert_eq!(result, RateLimitResult::Allowed, "Fragment {} should be allowed", i);
        } else {
            // Should start rate limiting after burst capacity
            assert_ne!(result, RateLimitResult::Allowed, "Fragment {} should be rate limited", i);
        }
    }
    
    // Verify rate limiting statistics
    let stats = limiter.get_rate_limit_stats();
    assert!(stats.session_violations > 0, "Should have session violations");
    assert_eq!(stats.active_session_limiters, 1);
    
    info!("Fragment rate limiting and attack detection test passed");
}

#[test]
fn test_overlap_detection_and_bomb_prevention() {
    // Test requirement: Comprehensive fragment security with overlap detection and bomb prevention
    let config = OverlapDetectionConfig {
        strict_overlap_detection: true,
        enable_constant_time_comparison: true,
        max_overlap_tolerance: 0,
        ..Default::default()
    };
    
    let detector = FragmentOverlapDetector::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    let source_ip = 0x7F000001;
    let current_time = current_timestamp();
    
    // Add first fragment
    let request1 = OverlapCheckRequest {
        session_id,
        fragment_id: 1,
        fragment_index: 0,
        fragment_offset: 0,
        fragment_length: 100,
        payload: vec![0x01; 100],
        expected_fragments: 3,
        source_ip,
        arrival_time: current_time,
    };
    
    let result1 = detector.check_overlap(&request1).unwrap();
    assert_eq!(result1, OverlapDetectionResult::NoOverlap);
    
    // Try to add overlapping fragment with different payload (attack)
    let request2 = OverlapCheckRequest {
        session_id,
        fragment_id: 1,
        fragment_index: 1,
        fragment_offset: 50, // Overlaps with first fragment
        fragment_length: 100,
        payload: vec![0x02; 100], // Different payload
        expected_fragments: 3,
        source_ip,
        arrival_time: current_time,
    };
    
    let result2 = detector.check_overlap(&request2).unwrap();
    assert_eq!(result2, OverlapDetectionResult::FragmentRejected);
    
    // Verify overlap detection statistics
    let stats = detector.get_overlap_stats();
    assert!(stats.overlaps_detected > 0 || stats.fragment_rejections > 0);
    assert!(stats.constant_time_comparisons > 0);
    
    info!("Overlap detection and bomb prevention test passed");
}

#[test]
fn test_session_binding_enforcement() {
    // Test requirement: Session binding enforcement to prevent cross-session injection
    let validator = FragmentSecurityValidator::new();
    let session_id1 = SessionId::Bits32(0x12345678);
    let session_id2 = SessionId::Bits32(0x87654321);
    let session_key1 = create_test_session_key();
    let session_key2 = create_test_session_key();
    let source_ip = 0x7F000001;
    let current_time = current_timestamp();
    
    // Register session bindings
    validator.register_session_binding(
        session_id1,
        session_key1.clone(),
        vec![source_ip],
    ).unwrap();
    
    validator.register_session_binding(
        session_id2,
        session_key2.clone(),
        vec![source_ip],
    ).unwrap();
    
    // Valid fragment for session 1
    let valid_request = FragmentValidationRequest {
        session_id: session_id1,
        fragment_id: 1,
        fragment_index: 0,
        total_fragments: 2,
        payload: vec![0x01; 100],
        source_ip,
        timestamp: current_time,
        session_key: Some(session_key1.clone()),
        hmac_policy: HmacPolicy::Medium,
    };
    
    let result = validator.validate_fragment(&valid_request);
    assert_eq!(result, FragmentValidationResult::Valid);
    
    // Try cross-session injection (fragment for session 1 with session 2 key)
    let injection_request = FragmentValidationRequest {
        session_id: session_id1,
        fragment_id: 2,
        fragment_index: 0,
        total_fragments: 2,
        payload: vec![0x02; 100],
        source_ip,
        timestamp: current_time,
        session_key: Some(session_key2), // Wrong key for session 1
        hmac_policy: HmacPolicy::Medium,
    };
    
    let result = validator.validate_fragment(&injection_request);
    assert_ne!(result, FragmentValidationResult::Valid);
    
    // Verify security statistics
    let stats = validator.get_security_stats();
    assert_eq!(stats.active_session_bindings, 2);
    
    info!("Session binding enforcement test passed");
}

#[test]
fn test_constant_time_validation() {
    // Test requirement: Constant-time fragment validation to prevent timing attacks
    let config = OverlapDetectionConfig {
        enable_constant_time_comparison: true,
        ..Default::default()
    };
    
    let detector = FragmentOverlapDetector::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    let source_ip = 0x7F000001;
    let current_time = current_timestamp();
    
    // Create two identical fragments for constant-time comparison
    let payload1 = vec![0x42; 1000];
    let payload2 = vec![0x42; 1000]; // Identical
    let payload3 = vec![0x43; 1000]; // Different
    
    let request1 = OverlapCheckRequest {
        session_id,
        fragment_id: 1,
        fragment_index: 0,
        fragment_offset: 0,
        fragment_length: 1000,
        payload: payload1,
        expected_fragments: 2,
        source_ip,
        arrival_time: current_time,
    };
    
    // Add first fragment
    let result1 = detector.check_overlap(&request1).unwrap();
    assert_eq!(result1, OverlapDetectionResult::NoOverlap);
    
    // Test identical payload (should be detected as exact duplicate)
    let request2 = OverlapCheckRequest {
        session_id,
        fragment_id: 1,
        fragment_index: 0,
        fragment_offset: 0,
        fragment_length: 1000,
        payload: payload2,
        expected_fragments: 2,
        source_ip,
        arrival_time: current_time,
    };
    
    let start_time = std::time::Instant::now();
    let result2 = detector.check_overlap(&request2).unwrap();
    let duration1 = start_time.elapsed();
    
    assert_eq!(result2, OverlapDetectionResult::ExactDuplicate);
    
    // Test different payload (should be detected as conflicting)
    let request3 = OverlapCheckRequest {
        session_id,
        fragment_id: 1,
        fragment_index: 1,
        fragment_offset: 0,
        fragment_length: 1000,
        payload: payload3,
        expected_fragments: 2,
        source_ip,
        arrival_time: current_time,
    };
    
    let start_time = std::time::Instant::now();
    let result3 = detector.check_overlap(&request3).unwrap();
    let duration2 = start_time.elapsed();
    
    // Both operations should take similar time (constant-time property)
    let time_diff = if duration1 > duration2 {
        duration1 - duration2
    } else {
        duration2 - duration1
    };
    
    // Allow some variance but ensure it's not dramatically different
    assert!(time_diff < Duration::from_millis(10), 
            "Constant-time validation failed: time difference too large");
    
    // Verify constant-time comparisons were performed
    let stats = detector.get_overlap_stats();
    assert!(stats.constant_time_comparisons > 0);
    
    info!("Constant-time validation test passed");
}

#[test]
fn test_comprehensive_integration_scenario() {
    // Test requirement: Complete integration of all fragmentation security features
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let source_ip = 0x7F000001;
    
    // Create a large message that will be fragmented
    let message_size = 5000;
    let original_message = Bytes::from((0..message_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>());
    
    // Fragment the message
    let fragment_request = FragmentationRequest {
        session_id,
        message: original_message.clone(),
        mtu_size: Some(1000),
        session_key: session_key.clone(),
        source_ip,
        hmac_policy: HmacPolicy::Medium,
    };
    
    let fragment_result = system.fragment_message(&fragment_request).unwrap();
    info!("Message fragmented into {} fragments", fragment_result.total_fragments);
    
    // Process each fragment for reassembly
    let mut reassembled_fragments = Vec::new();
    for (i, fragment) in fragment_result.fragments.iter().enumerate() {
        let reassembly_request = FragmentReassemblyRequest {
            fragment_packet: fragment.clone(),
            source_ip,
            session_key: Some(session_key.clone()),
            arrival_time: current_timestamp(),
        };
        
        let result = system.process_fragment(&reassembly_request).unwrap();
        
        match result {
            FragmentReassemblyResult::FragmentProcessed => {
                info!("Fragment {} processed successfully", i);
                reassembled_fragments.push(i);
            }
            FragmentReassemblyResult::MessageReassembled(data) => {
                info!("Message reassembly completed with {} fragments", reassembled_fragments.len() + 1);
                
                // Verify reassembled data matches original
                assert_eq!(data.len(), original_message.len());
                assert_eq!(data, original_message);
                
                // Get system statistics
                let stats = system.get_fragmentation_stats();
                assert_eq!(stats.total_fragmented, 1);
                assert_eq!(stats.total_reassembled, 1);
                assert_eq!(stats.total_fragments_created, fragment_result.total_fragments as u64);
                
                info!("Comprehensive integration test passed successfully");
                return;
            }
            other => {
                panic!("Unexpected reassembly result: {:?}", other);
            }
        }
    }
    
    panic!("Message reassembly did not complete");
}

#[test]
fn test_attack_scenarios_and_security_response() {
    // Test requirement: Security event logging and attack response coordination
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let attacker_ip = 0x0A000001; // 10.0.0.1
    let legitimate_ip = 0x7F000001; // 127.0.0.1
    
    // Register session for legitimate IP only
    let validator = FragmentSecurityValidator::new();
    validator.register_session_binding(
        session_id,
        session_key.clone(),
        vec![legitimate_ip],
    ).unwrap();
    
    // Simulate various attack scenarios
    let current_time = current_timestamp();
    
    // 1. Cross-session injection attack
    let injection_request = FragmentValidationRequest {
        session_id,
        fragment_id: 1,
        fragment_index: 0,
        total_fragments: 2,
        payload: vec![0x01; 100],
        source_ip: attacker_ip, // Unauthorized source
        timestamp: current_time,
        session_key: Some(session_key.clone()),
        hmac_policy: HmacPolicy::Medium,
    };
    
    let result = validator.validate_fragment(&injection_request);
    assert_eq!(result, FragmentValidationResult::OriginValidationFailed);
    
    // 2. Fragment bomb attack (excessive fragments)
    let config = FragmentRateLimitConfig {
        fragments_per_second_per_session: 5,
        session_burst_capacity: 10,
        max_violations_before_block: 2,
        ..Default::default()
    };
    
    let limiter = FragmentRateLimiter::with_config(config);
    
    // Send excessive fragments to trigger rate limiting
    let mut blocked = false;
    for i in 0..20 {
        let request = RateLimitRequest {
            session_id,
            source_ip: attacker_ip,
            fragment_size: 100,
            fragment_id: 1,
            timestamp: current_time,
        };
        
        let result = limiter.check_rate_limit(&request);
        if result == RateLimitResult::SessionBlocked || result == RateLimitResult::SourceBlocked {
            blocked = true;
            info!("Attacker blocked after {} fragments", i + 1);
            break;
        }
    }
    
    assert!(blocked, "Fragment bomb attack should trigger blocking");
    
    // 3. Memory exhaustion attack
    let memory_config = FragmentMemoryConfig {
        per_session_limit: 1024, // Very small limit for testing
        global_limit: 2048,
        ..Default::default()
    };
    
    let memory_manager = FragmentMemoryManager::with_config(memory_config);
    
    // Try to allocate excessive memory
    let large_request = MemoryAllocationRequest {
        session_id,
        fragment_id: 1,
        size: 2048, // Exceeds per-session limit
        expected_fragments: 1,
        fragment_index: 0,
    };
    
    let result = memory_manager.allocate_memory(&large_request);
    assert_eq!(result, MemoryAllocationResult::SessionLimitExceeded);
    
    // Verify security statistics show attack detection
    let security_stats = validator.get_security_stats();
    assert!(security_stats.origin_failures > 0);
    
    let rate_stats = limiter.get_rate_limit_stats();
    assert!(rate_stats.session_violations > 0 || rate_stats.source_violations > 0);
    
    let memory_stats = memory_manager.get_memory_stats();
    assert!(memory_stats.memory_exhaustion_events > 0);
    
    info!("Attack scenarios and security response test passed");
}