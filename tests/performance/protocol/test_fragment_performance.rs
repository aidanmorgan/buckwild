// Performance tests for fragment processing under load
//
// This module contains performance tests for the fragment security engine
// to validate that it can handle high-throughput fragment processing
// while maintaining security guarantees.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
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

/// Performance test configuration
struct PerformanceTestConfig {
    /// Number of fragments to process
    fragment_count: usize,
    /// Number of concurrent threads
    thread_count: usize,
    /// Fragment payload size
    payload_size: usize,
    /// Number of sessions
    session_count: usize,
    /// Test duration limit
    max_duration: Duration,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        Self {
            fragment_count: 10000,
            thread_count: 4,
            payload_size: 1024,
            session_count: 100,
            max_duration: Duration::from_secs(30),
        }
    }
}

/// Performance test results
#[derive(Debug)]
struct PerformanceTestResults {
    /// Total fragments processed
    fragments_processed: usize,
    /// Test duration
    duration: Duration,
    /// Fragments per second
    fragments_per_second: f64,
    /// Average latency per fragment
    avg_latency_us: f64,
    /// Memory usage (bytes)
    memory_usage: u64,
    /// Success rate (0.0 to 1.0)
    success_rate: f64,
}

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
mod performance_tests {
    use super::*;

    #[test]
    fn test_fragment_security_validation_performance() {
        let config = PerformanceTestConfig::default();
        let validator = Arc::new(FragmentSecurityValidator::new());
        
        // Register test sessions
        for i in 0..config.session_count {
            let session_id = SessionId::Bits32(0x10000000 + i as u32);
            let session_key = create_test_hmac_key();
            let source_ip = 0x7F000001 + (i as u32 % 256);
            
            validator.register_session_binding(
                session_id,
                session_key,
                vec![source_ip],
            ).unwrap();
        }
        
        let start_time = Instant::now();
        let mut successful_validations = 0;
        let mut total_validations = 0;
        
        // Single-threaded performance test
        for i in 0..config.fragment_count {
            let session_id = SessionId::Bits32(0x10000000 + (i % config.session_count) as u32);
            let source_ip = 0x7F000001 + ((i % config.session_count) as u32 % 256);
            
            let request = create_test_request(
                session_id,
                (i % 1000) as u16,
                (i % 10) as u16,
                10,
                vec![0x01; config.payload_size],
                source_ip,
            );
            
            let validation_start = Instant::now();
            let result = validator.validate_fragment(&request);
            let _validation_duration = validation_start.elapsed();
            
            total_validations += 1;
            if result == FragmentValidationResult::Valid {
                successful_validations += 1;
            }
            
            // Check timeout
            if start_time.elapsed() > config.max_duration {
                break;
            }
        }
        
        let total_duration = start_time.elapsed();
        let fragments_per_second = total_validations as f64 / total_duration.as_secs_f64();
        let success_rate = successful_validations as f64 / total_validations as f64;
        
        let results = PerformanceTestResults {
            fragments_processed: total_validations,
            duration: total_duration,
            fragments_per_second,
            avg_latency_us: total_duration.as_micros() as f64 / total_validations as f64,
            memory_usage: 0, // Would need memory profiling
            success_rate,
        };
        
        println!("Fragment Security Validation Performance:");
        println!("  Fragments processed: {}", results.fragments_processed);
        println!("  Duration: {:?}", results.duration);
        println!("  Fragments/sec: {:.2}", results.fragments_per_second);
        println!("  Avg latency: {:.2} μs", results.avg_latency_us);
        println!("  Success rate: {:.2}%", results.success_rate * 100.0);
        
        // Performance assertions
        assert!(results.fragments_per_second > 1000.0, "Fragment validation too slow: {:.2} fps", results.fragments_per_second);
        assert!(results.avg_latency_us < 1000.0, "Average latency too high: {:.2} μs", results.avg_latency_us);
        assert!(results.success_rate > 0.95, "Success rate too low: {:.2}%", results.success_rate * 100.0);
        
        let stats = validator.get_security_stats();
        println!("  Security stats: {:?}", stats);
    }

    #[test]
    fn test_concurrent_fragment_validation_performance() {
        let config = PerformanceTestConfig {
            fragment_count: 50000,
            thread_count: 8,
            ..Default::default()
        };
        
        let validator = Arc::new(FragmentSecurityValidator::new());
        
        // Register test sessions
        for i in 0..config.session_count {
            let session_id = SessionId::Bits32(0x20000000 + i as u32);
            let session_key = create_test_hmac_key();
            let source_ip = 0x7F000001 + (i as u32 % 256);
            
            validator.register_session_binding(
                session_id,
                session_key,
                vec![source_ip],
            ).unwrap();
        }
        
        let start_time = Instant::now();
        let fragments_per_thread = config.fragment_count / config.thread_count;
        let mut handles = vec![];
        
        // Spawn worker threads
        for thread_id in 0..config.thread_count {
            let validator_clone = Arc::clone(&validator);
            let thread_config = config.clone();
            
            let handle = thread::spawn(move || {
                let mut successful_validations = 0;
                let mut total_validations = 0;
                
                for i in 0..fragments_per_thread {
                    let session_idx = (thread_id * fragments_per_thread + i) % thread_config.session_count;
                    let session_id = SessionId::Bits32(0x20000000 + session_idx as u32);
                    let source_ip = 0x7F000001 + (session_idx as u32 % 256);
                    
                    let request = create_test_request(
                        session_id,
                        ((thread_id * fragments_per_thread + i) % 1000) as u16,
                        (i % 10) as u16,
                        10,
                        vec![0x02; thread_config.payload_size],
                        source_ip,
                    );
                    
                    let result = validator_clone.validate_fragment(&request);
                    total_validations += 1;
                    
                    if result == FragmentValidationResult::Valid {
                        successful_validations += 1;
                    }
                }
                
                (successful_validations, total_validations)
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        let mut total_successful = 0;
        let mut total_processed = 0;
        
        for handle in handles {
            let (successful, processed) = handle.join().unwrap();
            total_successful += successful;
            total_processed += processed;
        }
        
        let total_duration = start_time.elapsed();
        let fragments_per_second = total_processed as f64 / total_duration.as_secs_f64();
        let success_rate = total_successful as f64 / total_processed as f64;
        
        let results = PerformanceTestResults {
            fragments_processed: total_processed,
            duration: total_duration,
            fragments_per_second,
            avg_latency_us: total_duration.as_micros() as f64 / total_processed as f64,
            memory_usage: 0,
            success_rate,
        };
        
        println!("Concurrent Fragment Validation Performance:");
        println!("  Threads: {}", config.thread_count);
        println!("  Fragments processed: {}", results.fragments_processed);
        println!("  Duration: {:?}", results.duration);
        println!("  Fragments/sec: {:.2}", results.fragments_per_second);
        println!("  Avg latency: {:.2} μs", results.avg_latency_us);
        println!("  Success rate: {:.2}%", results.success_rate * 100.0);
        
        // Performance assertions for concurrent processing
        assert!(results.fragments_per_second > 5000.0, "Concurrent validation too slow: {:.2} fps", results.fragments_per_second);
        assert!(results.avg_latency_us < 500.0, "Average latency too high: {:.2} μs", results.avg_latency_us);
        assert!(results.success_rate > 0.95, "Success rate too low: {:.2}%", results.success_rate * 100.0);
        
        let stats = validator.get_security_stats();
        println!("  Security stats: {:?}", stats);
    }

    #[test]
    fn test_memory_allocation_performance() {
        let config = PerformanceTestConfig {
            fragment_count: 20000,
            payload_size: 2048,
            ..Default::default()
        };
        
        let memory_config = FragmentMemoryConfig {
            per_session_limit: 10 * 1024 * 1024, // 10MB per session
            global_limit: 100 * 1024 * 1024, // 100MB global
            ..Default::default()
        };
        
        let manager = FragmentMemoryManager::with_config(memory_config);
        let start_time = Instant::now();
        
        let mut successful_allocations = 0;
        let mut total_allocations = 0;
        
        for i in 0..config.fragment_count {
            let session_id = SessionId::Bits32(0x30000000 + (i % config.session_count) as u32);
            
            let request = MemoryAllocationRequest {
                session_id,
                fragment_id: (i % 1000) as u16,
                size: config.payload_size as u64,
                expected_fragments: 10,
                fragment_index: (i % 10) as u16,
            };
            
            let result = manager.allocate_memory(&request);
            total_allocations += 1;
            
            if result == MemoryAllocationResult::Success {
                successful_allocations += 1;
            }
            
            // Periodically deallocate to prevent exhaustion
            if i % 100 == 99 {
                let dealloc_request = buckwild_common::protocol::MemoryDeallocationRequest {
                    session_id,
                    fragment_id: ((i - 50) % 1000) as u16,
                    size: config.payload_size as u64,
                };
                let _ = manager.deallocate_memory(&dealloc_request);
            }
            
            if start_time.elapsed() > config.max_duration {
                break;
            }
        }
        
        let total_duration = start_time.elapsed();
        let allocations_per_second = total_allocations as f64 / total_duration.as_secs_f64();
        let success_rate = successful_allocations as f64 / total_allocations as f64;
        
        let results = PerformanceTestResults {
            fragments_processed: total_allocations,
            duration: total_duration,
            fragments_per_second: allocations_per_second,
            avg_latency_us: total_duration.as_micros() as f64 / total_allocations as f64,
            memory_usage: manager.get_memory_stats().global_memory_usage,
            success_rate,
        };
        
        println!("Memory Allocation Performance:");
        println!("  Allocations processed: {}", results.fragments_processed);
        println!("  Duration: {:?}", results.duration);
        println!("  Allocations/sec: {:.2}", results.fragments_per_second);
        println!("  Avg latency: {:.2} μs", results.avg_latency_us);
        println!("  Memory usage: {} bytes", results.memory_usage);
        println!("  Success rate: {:.2}%", results.success_rate * 100.0);
        
        // Performance assertions
        assert!(results.fragments_per_second > 10000.0, "Memory allocation too slow: {:.2} aps", results.fragments_per_second);
        assert!(results.avg_latency_us < 100.0, "Average latency too high: {:.2} μs", results.avg_latency_us);
        
        let stats = manager.get_memory_stats();
        println!("  Memory stats: {:?}", stats);
    }

    #[test]
    fn test_rate_limiting_performance() {
        let config = PerformanceTestConfig {
            fragment_count: 30000,
            ..Default::default()
        };
        
        let rate_config = FragmentRateLimitConfig {
            fragments_per_second_per_session: 1000,
            session_burst_capacity: 2000,
            packets_per_second_per_source: 5000,
            source_packet_burst_capacity: 10000,
            ..Default::default()
        };
        
        let limiter = FragmentRateLimiter::with_config(rate_config);
        let start_time = Instant::now();
        
        let mut allowed_requests = 0;
        let mut total_requests = 0;
        
        for i in 0..config.fragment_count {
            let session_id = SessionId::Bits32(0x40000000 + (i % config.session_count) as u32);
            let source_ip = 0x7F000001 + ((i % config.session_count) as u32 % 256);
            
            let request = RateLimitRequest {
                session_id,
                source_ip,
                fragment_size: config.payload_size as u32,
                fragment_id: (i % 1000) as u16,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };
            
            let result = limiter.check_rate_limit(&request);
            total_requests += 1;
            
            if result == RateLimitResult::Allowed {
                allowed_requests += 1;
            }
            
            if start_time.elapsed() > config.max_duration {
                break;
            }
        }
        
        let total_duration = start_time.elapsed();
        let requests_per_second = total_requests as f64 / total_duration.as_secs_f64();
        let success_rate = allowed_requests as f64 / total_requests as f64;
        
        let results = PerformanceTestResults {
            fragments_processed: total_requests,
            duration: total_duration,
            fragments_per_second: requests_per_second,
            avg_latency_us: total_duration.as_micros() as f64 / total_requests as f64,
            memory_usage: 0,
            success_rate,
        };
        
        println!("Rate Limiting Performance:");
        println!("  Requests processed: {}", results.fragments_processed);
        println!("  Duration: {:?}", results.duration);
        println!("  Requests/sec: {:.2}", results.fragments_per_second);
        println!("  Avg latency: {:.2} μs", results.avg_latency_us);
        println!("  Success rate: {:.2}%", results.success_rate * 100.0);
        
        // Performance assertions
        assert!(results.fragments_per_second > 20000.0, "Rate limiting too slow: {:.2} rps", results.fragments_per_second);
        assert!(results.avg_latency_us < 50.0, "Average latency too high: {:.2} μs", results.avg_latency_us);
        
        let stats = limiter.get_rate_limit_stats();
        println!("  Rate limit stats: {:?}", stats);
    }

    #[test]
    fn test_overlap_detection_performance() {
        let config = PerformanceTestConfig {
            fragment_count: 15000,
            payload_size: 1024,
            ..Default::default()
        };
        
        let detector = FragmentOverlapDetector::new();
        let start_time = Instant::now();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let mut successful_checks = 0;
        let mut total_checks = 0;
        
        for i in 0..config.fragment_count {
            let session_id = SessionId::Bits32(0x50000000 + (i % config.session_count) as u32);
            let source_ip = 0x7F000001 + ((i % config.session_count) as u32 % 256);
            
            let request = OverlapCheckRequest {
                session_id,
                fragment_id: (i % 100) as u16,
                fragment_index: (i % 10) as u16,
                fragment_offset: ((i % 10) * config.payload_size) as u32,
                fragment_length: config.payload_size as u32,
                payload: vec![0x03; config.payload_size],
                expected_fragments: 10,
                source_ip,
                arrival_time: current_time,
            };
            
            let result = detector.check_overlap(&request);
            total_checks += 1;
            
            if result.is_ok() {
                successful_checks += 1;
            }
            
            if start_time.elapsed() > config.max_duration {
                break;
            }
        }
        
        let total_duration = start_time.elapsed();
        let checks_per_second = total_checks as f64 / total_duration.as_secs_f64();
        let success_rate = successful_checks as f64 / total_checks as f64;
        
        let results = PerformanceTestResults {
            fragments_processed: total_checks,
            duration: total_duration,
            fragments_per_second: checks_per_second,
            avg_latency_us: total_duration.as_micros() as f64 / total_checks as f64,
            memory_usage: 0,
            success_rate,
        };
        
        println!("Overlap Detection Performance:");
        println!("  Checks processed: {}", results.fragments_processed);
        println!("  Duration: {:?}", results.duration);
        println!("  Checks/sec: {:.2}", results.fragments_per_second);
        println!("  Avg latency: {:.2} μs", results.avg_latency_us);
        println!("  Success rate: {:.2}%", results.success_rate * 100.0);
        
        // Performance assertions
        assert!(results.fragments_per_second > 8000.0, "Overlap detection too slow: {:.2} cps", results.fragments_per_second);
        assert!(results.avg_latency_us < 125.0, "Average latency too high: {:.2} μs", results.avg_latency_us);
        
        let stats = detector.get_overlap_stats();
        println!("  Overlap stats: {:?}", stats);
    }

    #[test]
    fn test_fragment_reassembly_performance() {
        let config = PerformanceTestConfig {
            fragment_count: 10000,
            payload_size: 512,
            session_count: 50,
            ..Default::default()
        };
        
        let reassembly_config = ReassemblyConfig {
            max_fragments_per_reassembly: 20,
            max_reassembled_size: 20 * 1024, // 20KB
            max_concurrent_reassemblies: 200,
            ..Default::default()
        };
        
        let manager = FragmentReassemblyManager::with_config(reassembly_config);
        let start_time = Instant::now();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let mut successful_additions = 0;
        let mut completed_reassemblies = 0;
        let mut total_attempts = 0;
        
        for i in 0..config.fragment_count {
            let session_id = SessionId::Bits32(0x60000000 + (i % config.session_count) as u32);
            let source_ip = 0x7F000001 + ((i % config.session_count) as u32 % 256);
            let fragment_id = (i / 10) as u16; // 10 fragments per reassembly
            let fragment_index = (i % 10) as u16;
            
            let request = ReassemblyRequest {
                session_id,
                fragment_id,
                fragment_index,
                fragment_offset: (fragment_index as u32) * (config.payload_size as u32),
                payload: vec![0x04; config.payload_size],
                expected_fragments: 10,
                source_ip,
                arrival_time: current_time,
            };
            
            match manager.add_fragment(&request) {
                Ok(ReassemblyResult::FragmentAdded) => {
                    successful_additions += 1;
                }
                Ok(ReassemblyResult::ReassemblyComplete(_)) => {
                    successful_additions += 1;
                    completed_reassemblies += 1;
                }
                _ => {}
            }
            
            total_attempts += 1;
            
            if start_time.elapsed() > config.max_duration {
                break;
            }
        }
        
        let total_duration = start_time.elapsed();
        let fragments_per_second = total_attempts as f64 / total_duration.as_secs_f64();
        let success_rate = successful_additions as f64 / total_attempts as f64;
        
        let results = PerformanceTestResults {
            fragments_processed: total_attempts,
            duration: total_duration,
            fragments_per_second,
            avg_latency_us: total_duration.as_micros() as f64 / total_attempts as f64,
            memory_usage: 0,
            success_rate,
        };
        
        println!("Fragment Reassembly Performance:");
        println!("  Fragments processed: {}", results.fragments_processed);
        println!("  Completed reassemblies: {}", completed_reassemblies);
        println!("  Duration: {:?}", results.duration);
        println!("  Fragments/sec: {:.2}", results.fragments_per_second);
        println!("  Avg latency: {:.2} μs", results.avg_latency_us);
        println!("  Success rate: {:.2}%", results.success_rate * 100.0);
        
        // Performance assertions
        assert!(results.fragments_per_second > 5000.0, "Reassembly too slow: {:.2} fps", results.fragments_per_second);
        assert!(results.avg_latency_us < 200.0, "Average latency too high: {:.2} μs", results.avg_latency_us);
        assert!(results.success_rate > 0.90, "Success rate too low: {:.2}%", results.success_rate * 100.0);
        
        let stats = manager.get_reassembly_stats();
        println!("  Reassembly stats: {:?}", stats);
    }

    #[test]
    fn test_integrated_fragment_processing_performance() {
        // Test the complete fragment processing pipeline
        let config = PerformanceTestConfig {
            fragment_count: 5000,
            thread_count: 4,
            payload_size: 1024,
            session_count: 20,
            max_duration: Duration::from_secs(60),
        };
        
        // Initialize all components
        let validator = Arc::new(FragmentSecurityValidator::new());
        let memory_manager = Arc::new(FragmentMemoryManager::new());
        let rate_limiter = Arc::new(FragmentRateLimiter::new());
        let overlap_detector = Arc::new(FragmentOverlapDetector::new());
        let reassembly_manager = Arc::new(FragmentReassemblyManager::new());
        
        // Register test sessions
        for i in 0..config.session_count {
            let session_id = SessionId::Bits32(0x70000000 + i as u32);
            let session_key = create_test_hmac_key();
            let source_ip = 0x7F000001 + (i as u32 % 256);
            
            validator.register_session_binding(
                session_id,
                session_key,
                vec![source_ip],
            ).unwrap();
        }
        
        let start_time = Instant::now();
        let fragments_per_thread = config.fragment_count / config.thread_count;
        let mut handles = vec![];
        
        // Spawn worker threads for integrated processing
        for thread_id in 0..config.thread_count {
            let validator_clone = Arc::clone(&validator);
            let memory_clone = Arc::clone(&memory_manager);
            let rate_clone = Arc::clone(&rate_limiter);
            let overlap_clone = Arc::clone(&overlap_detector);
            let reassembly_clone = Arc::clone(&reassembly_manager);
            let thread_config = config.clone();
            
            let handle = thread::spawn(move || {
                let mut processed_count = 0;
                let mut successful_count = 0;
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                
                for i in 0..fragments_per_thread {
                    let session_idx = (thread_id * fragments_per_thread + i) % thread_config.session_count;
                    let session_id = SessionId::Bits32(0x70000000 + session_idx as u32);
                    let source_ip = 0x7F000001 + (session_idx as u32 % 256);
                    let fragment_id = ((thread_id * fragments_per_thread + i) / 5) as u16;
                    let fragment_index = (i % 5) as u16;
                    
                    // Step 1: Security validation
                    let security_request = create_test_request(
                        session_id,
                        fragment_id,
                        fragment_index,
                        5,
                        vec![0x05; thread_config.payload_size],
                        source_ip,
                    );
                    
                    if validator_clone.validate_fragment(&security_request) != FragmentValidationResult::Valid {
                        processed_count += 1;
                        continue;
                    }
                    
                    // Step 2: Rate limiting
                    let rate_request = RateLimitRequest {
                        session_id,
                        source_ip,
                        fragment_size: thread_config.payload_size as u32,
                        fragment_id,
                        timestamp: current_time,
                    };
                    
                    if rate_clone.check_rate_limit(&rate_request) != RateLimitResult::Allowed {
                        processed_count += 1;
                        continue;
                    }
                    
                    // Step 3: Memory allocation
                    let memory_request = buckwild_common::protocol::MemoryAllocationRequest {
                        session_id,
                        fragment_id,
                        size: thread_config.payload_size as u64,
                        expected_fragments: 5,
                        fragment_index,
                    };
                    
                    if memory_clone.allocate_memory(&memory_request) != MemoryAllocationResult::Success {
                        processed_count += 1;
                        continue;
                    }
                    
                    // Step 4: Overlap detection
                    let overlap_request = OverlapCheckRequest {
                        session_id,
                        fragment_id,
                        fragment_index,
                        fragment_offset: (fragment_index as u32) * (thread_config.payload_size as u32),
                        fragment_length: thread_config.payload_size as u32,
                        payload: vec![0x05; thread_config.payload_size],
                        expected_fragments: 5,
                        source_ip,
                        arrival_time: current_time,
                    };
                    
                    if overlap_clone.check_overlap(&overlap_request).is_err() {
                        processed_count += 1;
                        continue;
                    }
                    
                    // Step 5: Fragment reassembly
                    let reassembly_request = ReassemblyRequest {
                        session_id,
                        fragment_id,
                        fragment_index,
                        fragment_offset: (fragment_index as u32) * (thread_config.payload_size as u32),
                        payload: vec![0x05; thread_config.payload_size],
                        expected_fragments: 5,
                        source_ip,
                        arrival_time: current_time,
                    };
                    
                    if reassembly_clone.add_fragment(&reassembly_request).is_ok() {
                        successful_count += 1;
                    }
                    
                    processed_count += 1;
                }
                
                (processed_count, successful_count)
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        let mut total_processed = 0;
        let mut total_successful = 0;
        
        for handle in handles {
            let (processed, successful) = handle.join().unwrap();
            total_processed += processed;
            total_successful += successful;
        }
        
        let total_duration = start_time.elapsed();
        let fragments_per_second = total_processed as f64 / total_duration.as_secs_f64();
        let success_rate = total_successful as f64 / total_processed as f64;
        
        let results = PerformanceTestResults {
            fragments_processed: total_processed,
            duration: total_duration,
            fragments_per_second,
            avg_latency_us: total_duration.as_micros() as f64 / total_processed as f64,
            memory_usage: memory_manager.get_memory_stats().global_memory_usage,
            success_rate,
        };
        
        println!("Integrated Fragment Processing Performance:");
        println!("  Threads: {}", config.thread_count);
        println!("  Fragments processed: {}", results.fragments_processed);
        println!("  Duration: {:?}", results.duration);
        println!("  Fragments/sec: {:.2}", results.fragments_per_second);
        println!("  Avg latency: {:.2} μs", results.avg_latency_us);
        println!("  Memory usage: {} bytes", results.memory_usage);
        println!("  Success rate: {:.2}%", results.success_rate * 100.0);
        
        // Performance assertions for integrated processing
        assert!(results.fragments_per_second > 1000.0, "Integrated processing too slow: {:.2} fps", results.fragments_per_second);
        assert!(results.avg_latency_us < 2000.0, "Average latency too high: {:.2} μs", results.avg_latency_us);
        
        // Print component statistics
        println!("Component Statistics:");
        println!("  Security: {:?}", validator.get_security_stats());
        println!("  Memory: {:?}", memory_manager.get_memory_stats());
        println!("  Rate Limit: {:?}", rate_limiter.get_rate_limit_stats());
        println!("  Overlap: {:?}", overlap_detector.get_overlap_stats());
        println!("  Reassembly: {:?}", reassembly_manager.get_reassembly_stats());
    }
}

impl Clone for PerformanceTestConfig {
    fn clone(&self) -> Self {
        Self {
            fragment_count: self.fragment_count,
            thread_count: self.thread_count,
            payload_size: self.payload_size,
            session_count: self.session_count,
            max_duration: self.max_duration,
        }
    }
}