use buckwild_common::protocol::security::*;
#[test]
    fn test_security_validator_creation() {
        let validator = SecurityValidator::new();
        let stats = validator.get_security_stats();
        
        assert_eq!(stats.fragment_bombs, 0);
        assert_eq!(stats.replay_attacks, 0);
        assert_eq!(stats.rate_limit_violations, 0);
        assert_eq!(stats.global_fragment_memory, 0);
    }
    
    #[test]
    fn test_rate_limit_validation() {
        let config = SecurityConfig {
            packet_rate_limit: 2,
            byte_rate_limit: 2048,
            rate_limit_window_s: 1,
            ..Default::default()
        };
        
        let validator = SecurityValidator::with_config(config);
        
        let metadata = SecurityMetadata {
            source_ip: 0x7F000001, // 127.0.0.1
            arrival_time_us: 0,
            security_class: SecurityClass::Data,
            hmac_policy_override: None,
            fragment_info: None,
            replay_validation: ReplayValidation {
                composite_key: 1,
                timestamp_window: TimestampWindow {
                    packet_timestamp: 0,
                    epoch_type: EpochType::Monthly,
                    window_start: 0,
                    window_end: 1000,
                    is_valid: true,
                },
                sequence_validation: SequenceValidation {
                    sequence_number: 1,
                    expected_range: (0, 10),
                    out_of_order_tolerance: 5,
                    is_valid: true,
                },
            },
        };
        
        // First two packets should pass
        assert!(validator.validate_security(&metadata).is_ok());
        assert!(validator.validate_security(&metadata).is_ok());
        
        // Third packet should fail due to rate limit
        assert_eq!(
            validator.validate_security(&metadata),
            Err(SecurityError::RateLimitViolation)
        );
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.rate_limit_violations, 1);
    }
    
    #[test]
    fn test_fragment_security_validation() {
        let config = SecurityConfig {
            fragment_memory_limit_per_session: 1000,
            global_fragment_memory_limit: 2000,
            ..Default::default()
        };
        
        let validator = SecurityValidator::with_config(config);
        
        let fragment_info = FragmentInfo {
            fragment_id: 1,
            fragment_index: 0,
            total_fragments: 2,
            payload_size: 600,
            session_binding: SessionId::Bits32(0x12345678),
        };
        
        let metadata = SecurityMetadata {
            source_ip: 0x7F000001,
            arrival_time_us: 0,
            security_class: SecurityClass::Data,
            hmac_policy_override: None,
            fragment_info: Some(fragment_info.clone()),
            replay_validation: ReplayValidation {
                composite_key: 1,
                timestamp_window: TimestampWindow {
                    packet_timestamp: 0,
                    epoch_type: EpochType::Monthly,
                    window_start: 0,
                    window_end: 1000,
                    is_valid: true,
                },
                sequence_validation: SequenceValidation {
                    sequence_number: 1,
                    expected_range: (0, 10),
                    out_of_order_tolerance: 5,
                    is_valid: true,
                },
            },
        };
        
        // First fragment should pass
        assert!(validator.validate_security(&metadata).is_ok());
        
        // Second fragment should fail due to per-session memory limit
        assert_eq!(
            validator.validate_security(&metadata),
            Err(SecurityError::FragmentBomb)
        );
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.fragment_bombs, 1);
        assert_eq!(stats.global_fragment_memory, 600);
    }
    
    #[test]
    fn test_anti_replay_validation() {
        let validator = SecurityValidator::new();
        
        let replay_validation = ReplayValidation {
            composite_key: 1,
            timestamp_window: TimestampWindow {
                packet_timestamp: 0,
                epoch_type: EpochType::Monthly,
                window_start: 0,
                window_end: 1000,
                is_valid: true,
            },
            sequence_validation: SequenceValidation {
                sequence_number: 1,
                expected_range: (0, 10),
                out_of_order_tolerance: 5,
                is_valid: true,
            },
        };
        
        let metadata = SecurityMetadata {
            source_ip: 0x7F000001,
            arrival_time_us: 0,
            security_class: SecurityClass::Data,
            hmac_policy_override: None,
            fragment_info: None,
            replay_validation: replay_validation.clone(),
        };
        
        // First packet should pass
        assert!(validator.validate_security(&metadata).is_ok());
        
        // Second packet with same composite key should fail (duplicate)
        assert_eq!(
            validator.validate_security(&metadata),
            Err(SecurityError::DuplicatePacket)
        );
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.replay_attacks, 1);
    }
