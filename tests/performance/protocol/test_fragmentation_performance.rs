// Performance tests for fragmentation and reassembly system
//
// This module tests fragmentation performance under various load conditions,
// MTU constraints, and concurrent scenarios to ensure the system can handle
// high-throughput fragmentation and reassembly operations.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::thread;
use bytes::Bytes;

use buckwild_common::protocol::{
    FragmentationSystem, FragmentationConfig, FragmentationRequest, FragmentReassemblyRequest,
    FragmentReassemblyResult, SessionId, HmacPolicy,
};
use buckwild_common::crypto::hmac::HmacKey;
use buckwild_common::protocol::types::{
    PacketCount, ByteCount, SessionCount, FragmentCount, MtuSize, TimeoutMs, FailureCount
};

fn create_test_session_key() -> Arc<HmacKey> {
    let key_material = vec![0x42; 32];
    Arc::new(HmacKey::new(&key_material).unwrap())
}

fn create_test_message(size: usize) -> Bytes {
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        data.push((i % 256) as u8);
    }
    Bytes::from(data)
}

#[test]
fn test_fragmentation_throughput() {
    let system = FragmentationSystem::new();
    let session_key = create_test_session_key();
    let message_count = PacketCount::new(1000);
    let message_size = ByteCount::new(5000); // 5KB messages
    
    let start_time = Instant::now();
    
    for i in 0..message_count.as_u64() {
        let session_id = SessionId::Bits32(0x12345678 + i as u32);
        let message = create_test_message(message_size.as_u64() as usize);
        
        let request = FragmentationRequest {
            session_id,
            message,
            mtu_size: Some(MtuSize::new(1500)),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request);
        assert!(result.is_ok());
    }
    
    let elapsed = start_time.elapsed();
    let throughput = (message_count.as_u64() as f64) / elapsed.as_secs_f64();
    
    println!("Fragmentation throughput: {:.2} messages/sec", throughput);
    println!("Average fragmentation time: {:.2} ms", elapsed.as_millis() as f64 / message_count.as_u64() as f64);
    
    // Verify reasonable performance (adjust threshold as needed)
    assert!(throughput > 100.0, "Fragmentation throughput too low: {:.2} msg/sec", throughput);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragmented, message_count.as_u64());
}

#[test]
fn test_reassembly_throughput() {
    let system = FragmentationSystem::new();
    let session_key = create_test_session_key();
    let message_count = PacketCount::new(100);
    let message_size = ByteCount::new(10000); // 10KB messages
    
    // First, fragment all messages
    let mut all_fragments = Vec::new();
    
    for i in 0..message_count.as_u64() {
        let session_id = SessionId::Bits32(0x12345678 + i as u32);
        let message = create_test_message(message_size.as_u64() as usize);
        
        let request = FragmentationRequest {
            session_id,
            message,
            mtu_size: Some(MtuSize::new(1000)), // 1KB MTU to create multiple fragments
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request).unwrap();
        all_fragments.extend(result.fragments);
    }
    
    // Now measure reassembly performance
    let start_time = Instant::now();
    let mut reassembled_count = 0;
    
    for fragment in all_fragments {
        let request = FragmentReassemblyRequest {
            fragment_packet: fragment,
            source_ip: 0x7F000001,
            session_key: Some(session_key.clone()),
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = system.process_fragment(&request).unwrap();
        
        if matches!(result, FragmentReassemblyResult::MessageReassembled(_)) {
            reassembled_count += 1;
        }
    }
    
    let elapsed = start_time.elapsed();
    let fragment_throughput = (system.get_fragmentation_stats().total_fragments_received as f64) / elapsed.as_secs_f64();
    let message_throughput = (reassembled_count as f64) / elapsed.as_secs_f64();
    
    println!("Fragment processing throughput: {:.2} fragments/sec", fragment_throughput);
    println!("Message reassembly throughput: {:.2} messages/sec", message_throughput);
    println!("Average fragment processing time: {:.2} μs", 
             elapsed.as_micros() as f64 / system.get_fragmentation_stats().total_fragments_received as f64);
    
    // Verify reasonable performance
    assert!(fragment_throughput > 1000.0, "Fragment processing throughput too low: {:.2} frag/sec", fragment_throughput);
    assert_eq!(reassembled_count, message_count.as_u64() as usize);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_reassembled, message_count.as_u64());
}

#[test]
fn test_concurrent_fragmentation_performance() {
    let system = Arc::new(FragmentationSystem::new());
    let session_key = create_test_session_key();
    let thread_count = SessionCount::new(4);
    let messages_per_thread = PacketCount::new(250);
    let message_size = ByteCount::new(8000); // 8KB messages
    
    let start_time = Instant::now();
    let mut handles = Vec::new();
    
    for thread_id in 0..thread_count.as_u64() {
        let system_clone = Arc::clone(&system);
        let session_key_clone = session_key.clone();
        
        let handle = thread::spawn(move || {
            for i in 0..messages_per_thread.as_u64() {
                let session_id = SessionId::Bits32(((thread_id as u32) << 16) | (i as u32));
                let message = create_test_message(message_size.as_u64() as usize);
                
                let request = FragmentationRequest {
                    session_id,
                    message,
                    mtu_size: Some(MtuSize::new(1200)),
                    session_key: session_key_clone.clone(),
                    source_ip: 0x7F000001 + (thread_id as u32),
                    hmac_policy: HmacPolicy::Light,
                };
                
                let result = system_clone.fragment_message(&request);
                assert!(result.is_ok());
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    let elapsed = start_time.elapsed();
    let total_messages = thread_count.as_u64() * messages_per_thread.as_u64();
    let throughput = (total_messages as f64) / elapsed.as_secs_f64();
    
    println!("Concurrent fragmentation throughput: {:.2} messages/sec", throughput);
    println!("Threads: {}, Messages per thread: {}", thread_count.as_u64(), messages_per_thread.as_u64());
    println!("Average time per message: {:.2} ms", elapsed.as_millis() as f64 / total_messages as f64);
    
    // Verify reasonable concurrent performance
    assert!(throughput > 200.0, "Concurrent fragmentation throughput too low: {:.2} msg/sec", throughput);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragmented, total_messages);
}

#[test]
fn test_concurrent_reassembly_performance() {
    let system = Arc::new(FragmentationSystem::new());
    let session_key = create_test_session_key();
    let thread_count = 4;
    let messages_per_thread = 100;
    let message_size = 12000; // 12KB messages
    
    // First, fragment all messages
    let mut all_fragments_by_thread = vec![Vec::new(); thread_count];
    
    for thread_id in 0..thread_count {
        for i in 0..messages_per_thread {
            let session_id = SessionId::Bits32((thread_id << 16) | i);
            let message = create_test_message(message_size);
            
            let request = FragmentationRequest {
                session_id,
                message,
                mtu_size: Some(800), // Smaller MTU to create more fragments
                session_key: session_key.clone(),
                source_ip: 0x7F000001 + thread_id,
                hmac_policy: HmacPolicy::Light,
            };
            
            let result = system.fragment_message(&request).unwrap();
            all_fragments_by_thread[thread_id].extend(result.fragments);
        }
    }
    
    // Now measure concurrent reassembly performance
    let start_time = Instant::now();
    let reassembled_counts = Arc::new(Mutex::new(vec![0; thread_count]));
    let mut handles = Vec::new();
    
    for thread_id in 0..thread_count {
        let system_clone = Arc::clone(&system);
        let session_key_clone = session_key.clone();
        let fragments = all_fragments_by_thread[thread_id].clone();
        let counts_clone = Arc::clone(&reassembled_counts);
        
        let handle = thread::spawn(move || {
            let mut local_reassembled = 0;
            
            for fragment in fragments {
                let request = FragmentReassemblyRequest {
                    fragment_packet: fragment,
                    source_ip: 0x7F000001 + thread_id,
                    session_key: Some(session_key_clone.clone()),
                    arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                };
                
                let result = system_clone.process_fragment(&request).unwrap();
                
                if matches!(result, FragmentReassemblyResult::MessageReassembled(_)) {
                    local_reassembled += 1;
                }
            }
            
            let mut counts = counts_clone.lock().unwrap();
            counts[thread_id] = local_reassembled;
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    let elapsed = start_time.elapsed();
    let total_reassembled: usize = reassembled_counts.lock().unwrap().iter().sum();
    let total_fragments = system.get_fragmentation_stats().total_fragments_received;
    
    let fragment_throughput = (total_fragments as f64) / elapsed.as_secs_f64();
    let message_throughput = (total_reassembled as f64) / elapsed.as_secs_f64();
    
    println!("Concurrent fragment processing throughput: {:.2} fragments/sec", fragment_throughput);
    println!("Concurrent message reassembly throughput: {:.2} messages/sec", message_throughput);
    println!("Threads: {}, Messages per thread: {}", thread_count, messages_per_thread);
    
    // Verify reasonable concurrent performance
    assert!(fragment_throughput > 2000.0, "Concurrent fragment processing throughput too low: {:.2} frag/sec", fragment_throughput);
    assert_eq!(total_reassembled, thread_count * messages_per_thread);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_reassembled, total_reassembled as u64);
}

#[test]
fn test_memory_usage_under_load() {
    let config = FragmentationConfig {
        max_concurrent_sessions: 10000,
        ..Default::default()
    };
    
    let system = FragmentationSystem::with_config(config);
    let session_key = create_test_session_key();
    let session_count = 1000;
    let message_size = 5000; // 5KB messages
    
    // Create many concurrent fragmentation sessions
    for i in 0..session_count {
        let session_id = SessionId::Bits32(0x12345678 + i);
        let message = create_test_message(message_size);
        
        let request = FragmentationRequest {
            session_id,
            message,
            mtu_size: Some(1000),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request);
        assert!(result.is_ok());
    }
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.active_sessions, session_count as u64);
    
    // Check memory usage is reasonable
    let memory_stats = stats.memory_stats;
    println!("Global memory usage: {} bytes", memory_stats.global_memory_usage);
    println!("Active sessions: {}", memory_stats.active_sessions);
    println!("Active buffers: {}", memory_stats.active_buffers);
    println!("Peak memory usage: {} bytes", memory_stats.peak_memory_usage);
    
    // Verify memory usage is within reasonable bounds
    let expected_max_memory = (session_count as u64) * (message_size as u64) * 2; // Allow 2x overhead
    assert!(memory_stats.global_memory_usage < expected_max_memory, 
            "Memory usage too high: {} bytes", memory_stats.global_memory_usage);
}

#[test]
fn test_fragmentation_with_various_mtu_sizes() {
    let system = FragmentationSystem::new();
    let session_key = create_test_session_key();
    let message_size = 10000; // 10KB message
    let mtu_sizes = vec![500, 1000, 1500, 2000, 4000, 8000];
    
    for mtu_size in mtu_sizes {
        let start_time = Instant::now();
        let iterations = 100;
        
        for i in 0..iterations {
            let session_id = SessionId::Bits32(0x12345678 + i);
            let message = create_test_message(message_size);
            
            let request = FragmentationRequest {
                session_id,
                message,
                mtu_size: Some(mtu_size),
                session_key: session_key.clone(),
                source_ip: 0x7F000001,
                hmac_policy: HmacPolicy::Light,
            };
            
            let result = system.fragment_message(&request);
            assert!(result.is_ok());
        }
        
        let elapsed = start_time.elapsed();
        let throughput = (iterations as f64) / elapsed.as_secs_f64();
        
        println!("MTU {}: {:.2} messages/sec, {:.2} ms/message", 
                 mtu_size, throughput, elapsed.as_millis() as f64 / iterations as f64);
        
        // Verify performance doesn't degrade significantly with different MTU sizes
        assert!(throughput > 50.0, "Performance too low for MTU {}: {:.2} msg/sec", mtu_size, throughput);
    }
}

#[test]
fn test_large_message_fragmentation_performance() {
    let system = FragmentationSystem::new();
    let session_key = create_test_session_key();
    let message_sizes = vec![
        10 * 1024,      // 10KB
        100 * 1024,     // 100KB
        1024 * 1024,    // 1MB
        10 * 1024 * 1024, // 10MB
    ];
    
    for message_size in message_sizes {
        let session_id = SessionId::Bits32(0x12345678);
        let message = create_test_message(message_size);
        
        let start_time = Instant::now();
        
        let request = FragmentationRequest {
            session_id,
            message,
            mtu_size: Some(1500),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request).unwrap();
        let fragmentation_time = start_time.elapsed();
        
        // Measure reassembly time
        let reassembly_start = Instant::now();
        
        for fragment in result.fragments {
            let request = FragmentReassemblyRequest {
                fragment_packet: fragment,
                source_ip: 0x7F000001,
                session_key: Some(session_key.clone()),
                arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };
            
            let _ = system.process_fragment(&request).unwrap();
        }
        
        let reassembly_time = reassembly_start.elapsed();
        let total_time = fragmentation_time + reassembly_time;
        
        let throughput_mbps = (message_size as f64) / (1024.0 * 1024.0) / total_time.as_secs_f64();
        
        println!("Message size: {} bytes", message_size);
        println!("  Fragments: {}", result.total_fragments);
        println!("  Fragmentation time: {:.2} ms", fragmentation_time.as_millis());
        println!("  Reassembly time: {:.2} ms", reassembly_time.as_millis());
        println!("  Total time: {:.2} ms", total_time.as_millis());
        println!("  Throughput: {:.2} MB/s", throughput_mbps);
        
        // Verify reasonable performance for large messages
        assert!(throughput_mbps > 1.0, "Throughput too low for {} byte message: {:.2} MB/s", 
                message_size, throughput_mbps);
    }
}

#[test]
fn test_security_validation_performance_impact() {
    let system = FragmentationSystem::new();
    let session_key = create_test_session_key();
    let message_count = 500;
    let message_size = 2000;
    
    // Fragment messages
    let mut all_fragments = Vec::new();
    
    for i in 0..message_count {
        let session_id = SessionId::Bits32(0x12345678 + i);
        let message = create_test_message(message_size);
        
        let request = FragmentationRequest {
            session_id,
            message,
            mtu_size: Some(800),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Strong, // Use strong HMAC for security validation
        };
        
        let result = system.fragment_message(&request).unwrap();
        all_fragments.extend(result.fragments);
    }
    
    // Measure reassembly with full security validation
    let start_time = Instant::now();
    
    for fragment in all_fragments {
        let request = FragmentReassemblyRequest {
            fragment_packet: fragment,
            source_ip: 0x7F000001,
            session_key: Some(session_key.clone()), // Enable security validation
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = system.process_fragment(&request);
        assert!(result.is_ok());
    }
    
    let elapsed = start_time.elapsed();
    let fragment_count = system.get_fragmentation_stats().total_fragments_received;
    let throughput = (fragment_count as f64) / elapsed.as_secs_f64();
    
    println!("Security validation performance:");
    println!("  Fragment processing throughput: {:.2} fragments/sec", throughput);
    println!("  Average processing time: {:.2} μs/fragment", 
             elapsed.as_micros() as f64 / fragment_count as f64);
    
    let stats = system.get_fragmentation_stats();
    println!("  Security violations: {}", stats.security_violations);
    println!("  Rate limit violations: {}", stats.rate_limit_violations);
    
    // Verify security validation doesn't severely impact performance
    assert!(throughput > 500.0, "Security validation impact too high: {:.2} frag/sec", throughput);
    assert_eq!(stats.security_violations, FailureCount::new(0));
}

#[test]
fn test_cleanup_performance() {
    let config = FragmentationConfig {
        fragment_timeout_s: 1, // Short timeout for testing
        cleanup_interval_s: 1,
        ..Default::default()
    };
    
    let system = FragmentationSystem::with_config(config);
    let session_key = create_test_session_key();
    let session_count = 1000;
    
    // Create many sessions
    for i in 0..session_count {
        let session_id = SessionId::Bits32(0x12345678 + i);
        let message = create_test_message(1000);
        
        let request = FragmentationRequest {
            session_id,
            message,
            mtu_size: Some(500),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let _ = system.fragment_message(&request).unwrap();
    }
    
    // Verify sessions exist
    let stats_before = system.get_fragmentation_stats();
    assert_eq!(stats_before.active_sessions, session_count as u64);
    
    // Wait for timeout
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Measure cleanup performance
    let start_time = Instant::now();
    system.cleanup_expired_resources();
    let cleanup_time = start_time.elapsed();
    
    // Verify cleanup completed
    let stats_after = system.get_fragmentation_stats();
    assert_eq!(stats_after.active_sessions, SessionCount::new(0));
    
    let cleanup_rate = (session_count as f64) / cleanup_time.as_secs_f64();
    
    println!("Cleanup performance:");
    println!("  Sessions cleaned: {}", session_count);
    println!("  Cleanup time: {:.2} ms", cleanup_time.as_millis());
    println!("  Cleanup rate: {:.2} sessions/sec", cleanup_rate);
    
    // Verify cleanup is reasonably fast
    assert!(cleanup_rate > 1000.0, "Cleanup too slow: {:.2} sessions/sec", cleanup_rate);
}