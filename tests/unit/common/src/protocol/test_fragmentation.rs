use buckwild_common::protocol::fragmentation::*;
use crate::crypto::hmac::HmacKey;
    
    fn create_test_session_key() -> Arc<HmacKey> {
        let key_material = vec![0x42; 32];
        Arc::new(HmacKey::new(&key_material).unwrap())
    }
    
    #[test]
    fn test_fragment_header_serialization() {
        let header = FragmentHeader::new(0x1234, 5, 10, 0x01);
        let bytes = header.to_bytes();
        let deserialized = FragmentHeader::from_bytes(&bytes).unwrap();
        
        // Use local variables to avoid packed field alignment issues
        let fragment_id = deserialized.fragment_id;
        let fragment_index = deserialized.fragment_index;
        let total_fragments = deserialized.total_fragments;
        
        assert_eq!(fragment_id, 0x1234);
        assert_eq!(fragment_index, 5);
        assert_eq!(total_fragments, 10);
        assert_eq!(deserialized.flags, 0x01);
        assert!(deserialized.is_last_fragment());
        assert!(!deserialized.is_first_fragment());
    }
    
    #[test]
    fn test_fragmentation_system_creation() {
        let system = FragmentationSystem::new();
        let stats = system.get_fragmentation_stats();
        
        assert_eq!(stats.total_fragmented, 0);
        assert_eq!(stats.total_fragments_created, 0);
        assert_eq!(stats.active_sessions, 0);
    }
    
    #[test]
    fn test_message_fragmentation() {
        let system = FragmentationSystem::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        let message = Bytes::from(vec![0x01; 2000]); // 2KB message
        
        let request = FragmentationRequest {
            session_id,
            message,
            mtu_size: Some(1000), // 1KB MTU
            session_key,
            source_ip: 0x7F000001,
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = system.fragment_message(&request).unwrap();
        
        // Should create 3 fragments (2000 bytes / ~992 bytes per fragment)
        assert!(result.total_fragments >= 2);
        assert_eq!(result.fragments.len(), result.total_fragments as usize);
        
        let stats = system.get_fragmentation_stats();
        assert_eq!(stats.total_fragmented, 1);
        assert_eq!(stats.total_fragments_created, result.total_fragments as u64);
    }
    
    #[test]
    fn test_fragment_processing() {
        let system = FragmentationSystem::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        
        // Create a fragment packet manually
        let fragment_header = FragmentHeader::new(0x1234, 0, 2, 0x00);
        let fragment_data = vec![0x01; 100];
        
        let mut fragment_payload = BytesMut::with_capacity(FRAGMENT_HEADER_SIZE + fragment_data.len());
        fragment_payload.put_slice(&fragment_header.to_bytes());
        fragment_payload.put_slice(&fragment_data);
        
        let fragment_packet = Packet::builder(super::types::PacketType::Data)
            .session_id(session_id)
            .sequence_number(0)
            .hmac_policy(HmacPolicy::Light)
            .payload(fragment_payload.freeze())
            .flag(super::types::PacketFlags::FRAG)
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
