use buckwild_common::protocol::fragment_security::*;
use crate::crypto::hmac::HmacKey;
    use std::net::Ipv4Addr;
    
    fn create_test_session_key() -> Arc<HmacKey> {
        let key_material = vec![0x42; 32];
        Arc::new(HmacKey::new(&key_material).unwrap())
    }
    
    #[test]
    fn test_fragment_security_validator_creation() {
        let validator = FragmentSecurityValidator::new();
        let stats = validator.get_security_stats();
        
        assert_eq!(stats.injection_attempts, 0);
        assert_eq!(stats.binding_failures, 0);
        assert_eq!(stats.active_session_bindings, 0);
        assert_eq!(stats.tracked_origins, 0);
    }
    
    #[test]
    fn test_session_binding_registration() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        let allowed_sources = vec![0x7F000001]; // 127.0.0.1
        
        let result = validator.register_session_binding(
            session_id,
            session_key,
            allowed_sources,
        );
        
        assert!(result.is_ok());
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.active_session_bindings, 1);
        assert_eq!(stats.tracked_origins, 1);
    }
    
    #[test]
    fn test_valid_fragment_validation() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        let source_ip = 0x7F000001; // 127.0.0.1
        let allowed_sources = vec![source_ip];
        
        // Register session binding
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            allowed_sources,
        ).unwrap();
        
        // Create validation request
        let request = FragmentValidationRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            total_fragments: 2,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            session_key: Some(session_key),
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::Valid);
    }
    
    #[test]
    fn test_cross_session_injection_detection() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let wrong_session_id = SessionId::Bits32(0x87654321);
        let session_key = create_test_session_key();
        let source_ip = 0x7F000001;
        
        // Register only one session
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        // Try to validate fragment for different session
        let request = FragmentValidationRequest {
            session_id: wrong_session_id,
            fragment_id: 1,
            fragment_index: 0,
            total_fragments: 2,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            session_key: Some(session_key),
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::SessionNotFound);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.injection_attempts, 1);
    }
    
    #[test]
    fn test_origin_validation_failure() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        let allowed_source = 0x7F000001; // 127.0.0.1
        let unauthorized_source = 0x7F000002; // 127.0.0.2
        
        // Register session with specific allowed source
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![allowed_source],
        ).unwrap();
        
        // Try to validate fragment from unauthorized source
        let request = FragmentValidationRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            total_fragments: 2,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            source_ip: unauthorized_source,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            session_key: Some(session_key),
            hmac_policy: HmacPolicy::Light,
        };
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::OriginValidationFailed);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.origin_failures, 1);
        assert_eq!(stats.source_violations, 1);
    }
    
    #[test]
    fn test_source_blocking_after_violations() {
        let config = FragmentSecurityConfig {
            max_violations_before_block: 2,
            violation_block_duration_s: 60,
            ..Default::default()
        };
        
        let validator = FragmentSecurityValidator::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        let allowed_source = 0x7F000001;
        let violating_source = 0x7F000002;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![allowed_source],
        ).unwrap();
        
        let request = FragmentValidationRequest {
            session_id,
            fragment_id: 1,
            fragment_index: 0,
            total_fragments: 2,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            source_ip: violating_source,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            session_key: Some(session_key),
            hmac_policy: HmacPolicy::Light,
        };
        
        // First violation
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::OriginValidationFailed);
        
        // Second violation should trigger blocking
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::OriginValidationFailed);
        
        // Third attempt should be blocked
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::SourceBlocked);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.source_violations, 2);
    }
    
    #[test]
    fn test_fragment_limit_enforcement() {
        let config = FragmentSecurityConfig {
            max_fragments_per_session: 2,
            ..Default::default()
        };
        
        let validator = FragmentSecurityValidator::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        let source_ip = 0x7F000001;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        let create_request = |fragment_index: u16| FragmentValidationRequest {
            session_id,
            fragment_id: 1,
            fragment_index,
            total_fragments: 5,
            payload: vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            session_key: Some(session_key.clone()),
            hmac_policy: HmacPolicy::Light,
        };
        
        // First two fragments should pass
        assert_eq!(validator.validate_fragment(&create_request(0)), FragmentValidationResult::Valid);
        assert_eq!(validator.validate_fragment(&create_request(1)), FragmentValidationResult::Valid);
        
        // Third fragment should exceed limit
        assert_eq!(validator.validate_fragment(&create_request(2)), FragmentValidationResult::FragmentLimitExceeded);
    }
    
    #[test]
    fn test_cleanup_expired_entries() {
        let config = FragmentSecurityConfig {
            session_binding_timeout_s: 1, // 1 second timeout for testing
            origin_tracking_timeout_s: 1,
            ..Default::default()
        };
        
        let validator = FragmentSecurityValidator::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_session_key();
        let source_ip = 0x7F000001;
        
        validator.register_session_binding(
            session_id,
            session_key,
            vec![source_ip],
        ).unwrap();
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.active_session_bindings, 1);
        assert_eq!(stats.tracked_origins, 1);
        
        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Clean up expired entries
        validator.cleanup_expired_entries();
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.active_session_bindings, 0);
        assert_eq!(stats.tracked_origins, 0);
    }
