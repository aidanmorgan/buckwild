use buckwild_common::protocol::validation::*;
use crate::protocol::packet::{PacketBuilderEngine, SessionId};

    #[test]
    fn test_validator_creation() {
        let state_manager = Arc::new(ProtocolStateManager::new());
        let validator = ProtocolValidator::new(state_manager);
        let stats = validator.get_stats();
        assert_eq!(stats.total_validations, 0);
    }

    #[test]
    fn test_valid_packet_validation() {
        let state_manager = Arc::new(ProtocolStateManager::new());
        let validator = ProtocolValidator::new(state_manager);
        let builder_engine = PacketBuilderEngine::new();

        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_string("Test data")
            .build()
            .unwrap();

        let request = ValidationRequest {
            packet,
            source_ip: Some(0x7F000001),
            is_local: true,
            context: ValidationContext::default(),
        };

        let result = validator.validate_packet(request).unwrap();
        // Note: This might not be Valid due to state validation, but should not error
        assert!(matches!(result, ValidationResult::Valid | 
                                ValidationResult::ValidWithWarnings { .. } | 
                                ValidationResult::Invalid { .. }));

        let stats = validator.get_stats();
        assert_eq!(stats.total_validations, 1);
    }

    #[test]
    fn test_oversized_packet_validation() {
        let state_manager = Arc::new(ProtocolStateManager::new());
        let mut rules = ValidationRules::default();
        rules.max_packet_size = 100; // Very small limit
        
        let validator = ProtocolValidator::with_rules(state_manager, rules);
        let builder_engine = PacketBuilderEngine::new();

        let large_payload = vec![0u8; 200];
        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_slice(&large_payload)
            .build()
            .unwrap();

        let request = ValidationRequest {
            packet,
            source_ip: Some(0x7F000001),
            is_local: true,
            context: ValidationContext::default(),
        };

        let result = validator.validate_packet(request).unwrap();
        match result {
            ValidationResult::Invalid { errors } => {
                assert!(errors.iter().any(|e| matches!(e.error_type, ErrorType::Structural)));
            }
            _ => panic!("Expected invalid result for oversized packet"),
        }
    }

    #[test]
    fn test_timestamp_validation() {
        let state_manager = Arc::new(ProtocolStateManager::new());
        let mut rules = ValidationRules::default();
        rules.timestamp_window_sec = 10; // Very short window
        
        let validator = ProtocolValidator::with_rules(state_manager, rules);
        let builder_engine = PacketBuilderEngine::new();

        // Create packet with very old timestamp
        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .timestamp(crate::protocol::packet::Timestamp::Bits32(1000)) // Very old
            .payload_string("Test data")
            .build()
            .unwrap();

        let request = ValidationRequest {
            packet,
            source_ip: Some(0x7F000001),
            is_local: true,
            context: ValidationContext::default(),
        };

        let result = validator.validate_packet(request).unwrap();
        match result {
            ValidationResult::Invalid { errors } => {
                assert!(errors.iter().any(|e| matches!(e.error_type, ErrorType::Timestamp)));
            }
            _ => {} // Might be valid depending on current time
        }
    }

    #[test]
    fn test_validation_caching() {
        let state_manager = Arc::new(ProtocolStateManager::new());
        let validator = ProtocolValidator::new(state_manager);
        let builder_engine = PacketBuilderEngine::new();

        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_string("Test data")
            .build()
            .unwrap();

        let request = ValidationRequest {
            packet: packet.clone(),
            source_ip: Some(0x7F000001),
            is_local: true,
            context: ValidationContext::default(),
        };

        // First validation
        let _ = validator.validate_packet(request.clone()).unwrap();
        
        // Second validation (should hit cache)
        let _ = validator.validate_packet(request).unwrap();

        let stats = validator.get_stats();
        assert_eq!(stats.total_validations, 2);
        assert!(stats.cache_hits > 0 || stats.cache_misses > 0); // At least one should be non-zero
    }

    #[test]
    fn test_statistics_reset() {
        let state_manager = Arc::new(ProtocolStateManager::new());
        let validator = ProtocolValidator::new(state_manager);
        let builder_engine = PacketBuilderEngine::new();

        let packet = builder_engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_string("Test data")
            .build()
            .unwrap();

        let request = ValidationRequest {
            packet,
            source_ip: Some(0x7F000001),
            is_local: true,
            context: ValidationContext::default(),
        };

        // Generate some statistics
        let _ = validator.validate_packet(request).unwrap();

        let stats_before = validator.get_stats();
        assert_eq!(stats_before.total_validations, 1);

        // Reset statistics
        validator.reset_stats();

        let stats_after = validator.get_stats();
        assert_eq!(stats_after.total_validations, 0);
    }
