// Comprehensive tests for the fragmentation and reassembly system
//
// This module tests fragmentation under various MTU constraints, loss conditions,
// and attack scenarios to ensure comprehensive security and functionality.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;

use buckwild_common::protocol::{
    FragmentationSystem, FragmentationConfig, FragmentationRequest, FragmentReassemblyRequest,
    FragmentReassemblyResult, FragmentHeader, FRAGMENT_HEADER_SIZE,
    SessionId, Packet, PacketType, HmacPolicy, PacketFlags,
};
use buckwild_common::crypto::hmac::HmacKey;
use buckwild_common::errors::BuckwildError;
use buckwild_common::protocol::types::{
    FragmentId, FragmentIndex, FragmentCount, MtuSize, ByteCount, 
    SessionCount, PacketCount, SequenceNumber, TimeoutMs
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
fn test_fragmentation_system_creation() {
    let system = FragmentationSystem::new();
    let stats = system.get_fragmentation_stats();
    
    assert_eq!(stats.total_fragmented, PacketCount::new(0));
    assert_eq!(stats.total_fragments_created, FragmentCount::new(0));
    assert_eq!(stats.total_reassembled, PacketCount::new(0));
    assert_eq!(stats.active_sessions, SessionCount::new(0));
}

#[test]
fn test_fragment_header_operations() {
    let header = FragmentHeader::new(FragmentId::new(0x1234), FragmentIndex::new(5), FragmentCount::new(10), 0x01);
    
    // Test serialization/deserialization
    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), FRAGMENT_HEADER_SIZE);
    
    let deserialized = FragmentHeader::from_bytes(&bytes).unwrap();
    assert_eq!(deserialized.fragment_id, FragmentId::new(0x1234));
    assert_eq!(deserialized.fragment_index, FragmentIndex::new(5));
    assert_eq!(deserialized.total_fragments, FragmentCount::new(10));
    assert_eq!(deserialized.flags, 0x01);
    
    // Test fragment position checks
    assert!(!deserialized.is_first_fragment());
    assert!(!deserialized.is_last_fragment());
    
    // Test first fragment
    let first_header = FragmentHeader::new(FragmentId::new(0x1234), FragmentIndex::new(0), FragmentCount::new(10), 0x00);
    assert!(first_header.is_first_fragment());
    assert!(!first_header.is_last_fragment());
    
    // Test last fragment
    let last_header = FragmentHeader::new(FragmentId::new(0x1234), FragmentIndex::new(9), FragmentCount::new(10), 0x01);
    assert!(!last_header.is_first_fragment());
    assert!(last_header.is_last_fragment());
}

#[test]
fn test_small_message_fragmentation() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = create_test_message(ByteCount::new(100).as_u64() as usize); // Small message
    
    let request = FragmentationRequest {
        session_id,
        message: message.clone(),
        mtu_size: Some(MtuSize::new(1500)), // Large MTU
        session_key,
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let result = system.fragment_message(&request).unwrap();
    
    // Small message should create only one fragment
    assert_eq!(result.total_fragments, FragmentCount::new(1));
    assert_eq!(result.fragments.len(), 1);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragmented, PacketCount::new(1));
    assert_eq!(stats.total_fragments_created, FragmentCount::new(1));
}

#[test]
fn test_large_message_fragmentation() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = create_test_message(10000); // 10KB message
    
    let request = FragmentationRequest {
        session_id,
        message: message.clone(),
        mtu_size: Some(1000), // 1KB MTU
        session_key,
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let result = system.fragment_message(&request).unwrap();
    
    // Should create multiple fragments
    assert!(result.total_fragments > FragmentCount::new(1));
    assert_eq!(result.fragments.len(), result.total_fragments.as_u16() as usize);
    
    // Verify fragment headers
    for (i, fragment) in result.fragments.iter().enumerate() {
        let payload = fragment.payload();
        assert!(payload.len() >= FRAGMENT_HEADER_SIZE);
        
        let header = FragmentHeader::from_bytes(&payload[..FRAGMENT_HEADER_SIZE]).unwrap();
        assert_eq!(header.fragment_id, result.fragment_id);
        assert_eq!(header.fragment_index, i as u16);
        assert_eq!(header.total_fragments, result.total_fragments);
        
        if i == 0 {
            assert!(header.is_first_fragment());
        }
        if i == result.total_fragments as usize - 1 {
            assert!(header.is_last_fragment());
        }
    }
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragmented, 1);
    assert_eq!(stats.total_fragments_created, result.total_fragments as u64);
}

#[test]
fn test_various_mtu_constraints() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = create_test_message(5000); // 5KB message
    
    let mtu_sizes = vec![500, 1000, 1500, 2000];
    
    for mtu_size in mtu_sizes {
        let request = FragmentationRequest {
            session_id,
            message: message.clone(),
            mtu_size: Some(mtu_size),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request).unwrap();
        
        // Verify fragment count is reasonable for MTU
        let max_payload_per_fragment = mtu_size - FRAGMENT_HEADER_SIZE;
        let expected_fragments = (message.len() + max_payload_per_fragment - 1) / max_payload_per_fragment;
        assert_eq!(result.total_fragments as usize, expected_fragments);
        
        // Verify no fragment exceeds MTU
        for fragment in &result.fragments {
            assert!(fragment.payload().len() <= mtu_size);
        }
    }
}

#[test]
fn test_mtu_too_small_error() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = create_test_message(100);
    
    let request = FragmentationRequest {
        session_id,
        message,
        mtu_size: Some(FRAGMENT_HEADER_SIZE - 1), // Too small
        session_key,
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let result = system.fragment_message(&request);
    assert!(matches!(result, Err(BuckwildError::MtuTooSmall)));
}

#[test]
fn test_empty_message_error() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = Bytes::new(); // Empty message
    
    let request = FragmentationRequest {
        session_id,
        message,
        mtu_size: Some(1500),
        session_key,
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let result = system.fragment_message(&request);
    assert!(matches!(result, Err(BuckwildError::EmptyMessage)));
}

#[test]
fn test_fragment_processing_success() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    
    // Create a fragment packet manually
    let fragment_header = FragmentHeader::new(0x1234, 0, 2, 0x00);
    let fragment_data = vec![0x01; 100];
    
    let mut fragment_payload = bytes::BytesMut::with_capacity(FRAGMENT_HEADER_SIZE + fragment_data.len());
    fragment_payload.extend_from_slice(&fragment_header.to_bytes());
    fragment_payload.extend_from_slice(&fragment_data);
    
    let fragment_packet = Packet::builder(PacketType::Data)
        .session_id(session_id)
        .sequence_number(0)
        .hmac_policy(HmacPolicy::Light)
        .payload(fragment_payload.freeze())
        .flag(PacketFlags::FRAG)
        .build()
        .unwrap();
    
    let request = FragmentReassemblyRequest {
        fragment_packet,
        source_ip: 0x7F000001,
        session_key: Some(session_key),
        arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };
    
    let result = system.process_fragment(&request).unwrap();
    assert_eq!(result, FragmentReassemblyResult::FragmentProcessed);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragments_received, 1);
}

#[test]
fn test_complete_fragmentation_and_reassembly() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let original_message = create_test_message(2000);
    
    // Fragment the message
    let frag_request = FragmentationRequest {
        session_id,
        message: original_message.clone(),
        mtu_size: Some(800),
        session_key: session_key.clone(),
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let frag_result = system.fragment_message(&frag_request).unwrap();
    assert!(frag_result.total_fragments > 1);
    
    // Process all fragments except the last one
    let mut reassembled_message = None;
    for (i, fragment) in frag_result.fragments.iter().enumerate() {
        let request = FragmentReassemblyRequest {
            fragment_packet: fragment.clone(),
            source_ip: 0x7F000001,
            session_key: Some(session_key.clone()),
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = system.process_fragment(&request).unwrap();
        
        if i == frag_result.total_fragments as usize - 1 {
            // Last fragment should complete reassembly
            match result {
                FragmentReassemblyResult::MessageReassembled(message) => {
                    reassembled_message = Some(message);
                }
                _ => panic!("Expected message reassembly completion"),
            }
        } else {
            assert_eq!(result, FragmentReassemblyResult::FragmentProcessed);
        }
    }
    
    // Verify reassembled message matches original
    let reassembled = reassembled_message.expect("Message should be reassembled");
    assert_eq!(reassembled, original_message);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragmented, 1);
    assert_eq!(stats.total_reassembled, 1);
    assert_eq!(stats.total_fragments_received, frag_result.total_fragments as u64);
}

#[test]
fn test_duplicate_fragment_handling() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    
    // Create a fragment packet
    let fragment_header = FragmentHeader::new(0x1234, 0, 2, 0x00);
    let fragment_data = vec![0x01; 100];
    
    let mut fragment_payload = bytes::BytesMut::with_capacity(FRAGMENT_HEADER_SIZE + fragment_data.len());
    fragment_payload.extend_from_slice(&fragment_header.to_bytes());
    fragment_payload.extend_from_slice(&fragment_data);
    
    let fragment_packet = Packet::builder(PacketType::Data)
        .session_id(session_id)
        .sequence_number(0)
        .hmac_policy(HmacPolicy::Light)
        .payload(fragment_payload.freeze())
        .flag(PacketFlags::FRAG)
        .build()
        .unwrap();
    
    let request = FragmentReassemblyRequest {
        fragment_packet: fragment_packet.clone(),
        source_ip: 0x7F000001,
        session_key: Some(session_key),
        arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };
    
    // First fragment should be processed
    let result1 = system.process_fragment(&request).unwrap();
    assert_eq!(result1, FragmentReassemblyResult::FragmentProcessed);
    
    // Duplicate fragment should be ignored
    let result2 = system.process_fragment(&request).unwrap();
    assert_eq!(result2, FragmentReassemblyResult::DuplicateIgnored);
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragments_received, 2);
}

#[test]
fn test_invalid_fragment_parameters() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    
    // Create fragment with invalid parameters (index >= total)
    let fragment_header = FragmentHeader::new(0x1234, 5, 3, 0x00); // index 5 >= total 3
    let fragment_data = vec![0x01; 100];
    
    let mut fragment_payload = bytes::BytesMut::with_capacity(FRAGMENT_HEADER_SIZE + fragment_data.len());
    fragment_payload.extend_from_slice(&fragment_header.to_bytes());
    fragment_payload.extend_from_slice(&fragment_data);
    
    let fragment_packet = Packet::builder(PacketType::Data)
        .session_id(session_id)
        .sequence_number(0)
        .hmac_policy(HmacPolicy::Light)
        .payload(fragment_payload.freeze())
        .flag(PacketFlags::FRAG)
        .build()
        .unwrap();
    
    let request = FragmentReassemblyRequest {
        fragment_packet,
        source_ip: 0x7F000001,
        session_key: Some(session_key),
        arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };
    
    let result = system.process_fragment(&request).unwrap();
    assert_eq!(result, FragmentReassemblyResult::InvalidParameters);
}

#[test]
fn test_fragment_too_small_for_header() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    
    // Create fragment with payload smaller than header size
    let small_payload = vec![0x01; FRAGMENT_HEADER_SIZE - 1];
    
    let fragment_packet = Packet::builder(PacketType::Data)
        .session_id(session_id)
        .sequence_number(0)
        .hmac_policy(HmacPolicy::Light)
        .payload(Bytes::from(small_payload))
        .flag(PacketFlags::FRAG)
        .build()
        .unwrap();
    
    let request = FragmentReassemblyRequest {
        fragment_packet,
        source_ip: 0x7F000001,
        session_key: Some(session_key),
        arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };
    
    let result = system.process_fragment(&request).unwrap();
    assert_eq!(result, FragmentReassemblyResult::InvalidParameters);
}

#[test]
fn test_concurrent_fragmentation_sessions() {
    let system = FragmentationSystem::new();
    let session_key = create_test_session_key();
    let message = create_test_message(1000);
    
    // Create multiple concurrent fragmentation sessions
    let session_ids = vec![
        SessionId::Bits32(0x12345678),
        SessionId::Bits32(0x87654321),
        SessionId::Bits32(0xABCDEF00),
    ];
    
    let mut results = Vec::new();
    
    for session_id in session_ids {
        let request = FragmentationRequest {
            session_id,
            message: message.clone(),
            mtu_size: Some(500),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request).unwrap();
        results.push(result);
    }
    
    // Verify all sessions were created successfully
    assert_eq!(results.len(), 3);
    
    // Verify each has unique fragment IDs
    let mut fragment_ids = std::collections::HashSet::new();
    for result in &results {
        assert!(fragment_ids.insert(result.fragment_id));
    }
    
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.total_fragmented, 3);
    assert_eq!(stats.active_sessions, 3);
}

#[test]
fn test_fragmentation_session_limit() {
    let config = FragmentationConfig {
        max_concurrent_sessions: 2,
        ..Default::default()
    };
    
    let system = FragmentationSystem::with_config(config);
    let session_key = create_test_session_key();
    let message = create_test_message(1000);
    
    // Create sessions up to the limit
    for i in 0..2 {
        let request = FragmentationRequest {
            session_id: SessionId::Bits32(0x12345678 + i),
            message: message.clone(),
            mtu_size: Some(500),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request);
        assert!(result.is_ok());
    }
    
    // Third session should fail
    let request = FragmentationRequest {
        session_id: SessionId::Bits32(0x12345678 + 2),
        message: message.clone(),
        mtu_size: Some(500),
        session_key: session_key.clone(),
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let result = system.fragment_message(&request);
    assert!(matches!(result, Err(BuckwildError::FragmentationLimitExceeded)));
}

#[test]
fn test_fragment_id_collision_avoidance() {
    let config = FragmentationConfig {
        enable_fragment_id_collision_avoidance: true,
        ..Default::default()
    };
    
    let system = FragmentationSystem::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = create_test_message(1000);
    
    let mut fragment_ids = std::collections::HashSet::new();
    
    // Create multiple fragmentation sessions for the same session ID
    for _ in 0..10 {
        let request = FragmentationRequest {
            session_id,
            message: message.clone(),
            mtu_size: Some(500),
            session_key: session_key.clone(),
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request).unwrap();
        
        // Each should have a unique fragment ID
        assert!(fragment_ids.insert(result.fragment_id));
    }
    
    // Verify all fragment IDs are unique
    assert_eq!(fragment_ids.len(), 10);
}

#[test]
fn test_fragmentation_statistics() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = create_test_message(2000);
    
    // Initial stats
    let initial_stats = system.get_fragmentation_stats();
    assert_eq!(initial_stats.total_fragmented, 0);
    assert_eq!(initial_stats.total_fragments_created, 0);
    assert_eq!(initial_stats.total_reassembled, 0);
    
    // Fragment a message
    let frag_request = FragmentationRequest {
        session_id,
        message: message.clone(),
        mtu_size: Some(800),
        session_key: session_key.clone(),
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let frag_result = system.fragment_message(&frag_request).unwrap();
    
    // Check fragmentation stats
    let frag_stats = system.get_fragmentation_stats();
    assert_eq!(frag_stats.total_fragmented, 1);
    assert_eq!(frag_stats.total_fragments_created, frag_result.total_fragments as u64);
    assert_eq!(frag_stats.active_sessions, 1);
    
    // Process all fragments for reassembly
    for fragment in &frag_result.fragments {
        let request = FragmentReassemblyRequest {
            fragment_packet: fragment.clone(),
            source_ip: 0x7F000001,
            session_key: Some(session_key.clone()),
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let _ = system.process_fragment(&request).unwrap();
    }
    
    // Check final stats
    let final_stats = system.get_fragmentation_stats();
    assert_eq!(final_stats.total_fragmented, 1);
    assert_eq!(final_stats.total_fragments_created, frag_result.total_fragments as u64);
    assert_eq!(final_stats.total_reassembled, 1);
    assert_eq!(final_stats.total_fragments_received, frag_result.total_fragments as u64);
}

#[test]
fn test_out_of_order_fragment_processing() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let original_message = create_test_message(1500);
    
    // Fragment the message
    let frag_request = FragmentationRequest {
        session_id,
        message: original_message.clone(),
        mtu_size: Some(600),
        session_key: session_key.clone(),
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let frag_result = system.fragment_message(&frag_request).unwrap();
    assert!(frag_result.total_fragments >= 3);
    
    // Process fragments out of order (last, first, middle)
    let fragments = &frag_result.fragments;
    let indices = vec![
        fragments.len() - 1, // Last
        0,                   // First
        1,                   // Middle
    ];
    
    let mut reassembled_message = None;
    
    for &i in &indices {
        let request = FragmentReassemblyRequest {
            fragment_packet: fragments[i].clone(),
            source_ip: 0x7F000001,
            session_key: Some(session_key.clone()),
            arrival_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = system.process_fragment(&request).unwrap();
        
        if i == indices.len() - 1 {
            // Last processed fragment should complete reassembly
            match result {
                FragmentReassemblyResult::MessageReassembled(message) => {
                    reassembled_message = Some(message);
                }
                _ => panic!("Expected message reassembly completion"),
            }
        } else {
            assert_eq!(result, FragmentReassemblyResult::FragmentProcessed);
        }
    }
    
    // Verify reassembled message matches original
    let reassembled = reassembled_message.expect("Message should be reassembled");
    assert_eq!(reassembled, original_message);
}

#[test]
fn test_retransmission_request() {
    let system = FragmentationSystem::new();
    let session_id = SessionId::Bits32(0x12345678);
    let fragment_id = 0x1234;
    let missing_fragments = vec![1, 3, 5];
    
    let result = system.request_retransmission(session_id, fragment_id, missing_fragments);
    assert!(result.is_ok());
    
    // Verify retransmission tracking is set up
    // (This would require access to internal state in a real implementation)
}

#[test]
fn test_resource_cleanup() {
    let config = FragmentationConfig {
        fragment_timeout_s: 1, // Very short timeout for testing
        cleanup_interval_s: 1,
        ..Default::default()
    };
    
    let system = FragmentationSystem::with_config(config);
    let session_id = SessionId::Bits32(0x12345678);
    let session_key = create_test_session_key();
    let message = create_test_message(1000);
    
    // Create a fragmentation session
    let request = FragmentationRequest {
        session_id,
        message,
        mtu_size: Some(500),
        session_key,
        source_ip: 0x7F000001,
        hmac_policy: HmacPolicy::Light,
    };
    
    let _result = system.fragment_message(&request).unwrap();
    
    // Verify session exists
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.active_sessions, 1);
    
    // Wait for cleanup (in a real test, we'd trigger cleanup manually)
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Manually trigger cleanup for testing
    system.cleanup_expired_resources();
    
    // Verify session was cleaned up
    let stats = system.get_fragmentation_stats();
    assert_eq!(stats.active_sessions, 0);
}