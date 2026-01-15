use buckwild_common::protocol:fragmentation::security::*;
use crate::protocol::packet::{PacketBuilderEngine, SessionId, PacketFlags};

    #[test]
    fn test_security_engine_creation() {
        let engine = FragmentSecurityEngine::new();
        let stats = engine.get_stats();
        assert_eq!(stats.total_validated, 0);
    }

    #[test]
    fn test_valid_fragment_validation() {
        let engine = FragmentSecurityEngine::new();
        let builder_engine = PacketBuilderEngine::new();
        
        let fragment = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .fragmentation(0x1234, 0, 2)
            .payload_string("Fragment data")
            .build()
            .unwrap();

        let result = engine.validate_fragment(&fragment).unwrap();
        match result {
            SecurityValidationResult::Valid => {
                // Expected
            }
            _ => panic!("Expected valid fragment"),
        }

        let stats = engine.get_stats();
        assert_eq!(stats.total_validated, 1);
        assert_eq!(stats.valid_fragments, 1);
    }

    #[test]
    fn test_oversized_fragment_rejection() {
        let mut policies = FragmentSecurityPolicies::default();
        policies.max_fragment_size = 100; // Very small limit
        
        let engine = FragmentSecurityEngine::with_policies(policies);
        let builder_engine = PacketBuilderEngine::new();
        
        // Create a fragment with large payload
        let large_payload = vec![0u8; 200];
        let fragment = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .fragmentation(0x1234, 0, 2)
            .payload_slice(&large_payload)
            .build()
            .unwrap();

        let result = engine.validate_fragment(&fragment).unwrap();
        match result {
            SecurityValidationResult::Rejected { reason } => {
                assert!(reason.contains("exceeds maximum"));
            }
            _ => panic!("Expected rejected fragment"),
        }

        let stats = engine.get_stats();
        assert_eq!(stats.rejected_fragments, 1);
    }

    #[test]
    fn test_excessive_fragments_rejection() {
        let mut policies = FragmentSecurityPolicies::default();
        policies.max_fragments_per_session = 2; // Very small limit
        
        let engine = FragmentSecurityEngine::with_policies(policies);
        let builder_engine = PacketBuilderEngine::new();
        
        let fragment = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .fragmentation(0x1234, 0, 10) // More than allowed
            .payload_string("Fragment data")
            .build()
            .unwrap();

        let result = engine.validate_fragment(&fragment).unwrap();
        match result {
            SecurityValidationResult::Rejected { reason } => {
                assert!(reason.contains("exceeds maximum"));
            }
            _ => panic!("Expected rejected fragment"),
        }
    }

    #[test]
    fn test_invalid_fragment_index() {
        let engine = FragmentSecurityEngine::new();
        let builder_engine = PacketBuilderEngine::new();
        
        let fragment = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .fragmentation(0x1234, 5, 2) // Index >= total
            .payload_string("Fragment data")
            .build()
            .unwrap();

        let result = engine.validate_fragment(&fragment).unwrap();
        match result {
            SecurityValidationResult::Rejected { reason } => {
                assert!(reason.contains("Invalid fragment index"));
            }
            _ => panic!("Expected rejected fragment"),
        }
    }

    #[test]
    fn test_non_fragmented_packet_error() {
        let engine = FragmentSecurityEngine::new();
        let builder_engine = PacketBuilderEngine::new();
        
        // Create a non-fragmented packet
        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_string("Regular data")
            .build()
            .unwrap();

        let result = engine.validate_fragment(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not fragmented"));
    }

    #[test]
    fn test_cleanup_expired_states() {
        let engine = FragmentSecurityEngine::new();
        let builder_engine = PacketBuilderEngine::new();
        
        // Process a fragment to create state
        let fragment = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .fragmentation(0x1234, 0, 2)
            .payload_string("Fragment data")
            .build()
            .unwrap();

        let _ = engine.validate_fragment(&fragment).unwrap();
        
        // Verify state exists
        {
            let detector = engine.attack_detector.read().unwrap();
            assert_eq!(detector.session_fragment_counts.len(), 1);
        }
        
        // Cleanup should not remove recent state
        engine.cleanup_expired_states();
        
        {
            let detector = engine.attack_detector.read().unwrap();
            assert_eq!(detector.session_fragment_counts.len(), 1);
        }
    }
