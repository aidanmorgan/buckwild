// Unit tests for fragment security validation
//
// This module contains comprehensive unit tests for the fragment security
// engine, including session binding validation, cryptographic binding
// verification, and origin validation.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use buckwild_common::protocol::{
    FragmentSecurityValidator, FragmentSecurityConfig, FragmentValidationRequest,
    FragmentValidationResult, SessionId
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
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let validator = FragmentSecurityValidator::new();
        let stats = validator.get_security_stats();
        
        assert_eq!(stats.injection_attempts, 0);
        assert_eq!(stats.binding_failures, 0);
        assert_eq!(stats.origin_failures, 0);
        assert_eq!(stats.active_session_bindings, 0);
        assert_eq!(stats.tracked_origins, 0);
    }

    #[test]
    fn test_validator_with_custom_config() {
        let config = FragmentSecurityConfig {
            max_fragments_per_session: 500,
            max_sessions_per_source: 5,
            session_binding_timeout_s: 120,
            origin_tracking_timeout_s: 240,
            max_violations_before_block: 3,
            violation_block_duration_s: 180,
            strict_source_validation: false,
            enable_crypto_binding: false,
        };
        
        let validator = FragmentSecurityValidator::with_config(config);
        let stats = validator.get_security_stats();
        
        assert_eq!(stats.injection_attempts, 0);
        assert_eq!(stats.binding_failures, 0);
    }

    #[test]
    fn test_session_binding_registration() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let allowed_sources = vec![0x7F000001, 0x7F000002]; // 127.0.0.1, 127.0.0.2
        
        let result = validator.register_session_binding(
            session_id,
            session_key,
            allowed_sources,
        );
        
        assert!(result.is_ok());
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.active_session_bindings, 1);
        assert_eq!(stats.tracked_origins, 2);
    }

    #[test]
    fn test_valid_fragment_validation() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001; // 127.0.0.1
        let allowed_sources = vec![source_ip];
        
        // Register session binding
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            allowed_sources,
        ).unwrap();
        
        // Create validation request
        let request = create_test_request(
            session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
        );
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::Valid);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.injection_attempts, 0);
        assert_eq!(stats.binding_failures, 0);
        assert_eq!(stats.origin_failures, 0);
    }

    #[test]
    fn test_cross_session_injection_detection() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let wrong_session_id = SessionId::Bits32(0x87654321);
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        // Register only one session
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        // Try to validate fragment for different session
        let request = create_test_request(
            wrong_session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
        );
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::SessionNotFound);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.injection_attempts, 1);
    }

    #[test]
    fn test_origin_validation_failure() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let allowed_source = 0x7F000001; // 127.0.0.1
        let unauthorized_source = 0x7F000002; // 127.0.0.2
        
        // Register session with specific allowed source
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![allowed_source],
        ).unwrap();
        
        // Try to validate fragment from unauthorized source
        let request = create_test_request(
            session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            unauthorized_source,
        );
        
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
        let session_key = create_test_hmac_key();
        let allowed_source = 0x7F000001;
        let violating_source = 0x7F000002;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![allowed_source],
        ).unwrap();
        
        let create_request = || create_test_request(
            session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            violating_source,
        );
        
        // First violation
        let result = validator.validate_fragment(&create_request());
        assert_eq!(result, FragmentValidationResult::OriginValidationFailed);
        
        // Second violation should trigger blocking
        let result = validator.validate_fragment(&create_request());
        assert_eq!(result, FragmentValidationResult::OriginValidationFailed);
        
        // Third attempt should be blocked
        let result = validator.validate_fragment(&create_request());
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
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        let create_request = |fragment_index: u16| create_test_request(
            session_id,
            1,
            fragment_index,
            5,
            vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
        );
        
        // First two fragments should pass
        assert_eq!(validator.validate_fragment(&create_request(0)), FragmentValidationResult::Valid);
        assert_eq!(validator.validate_fragment(&create_request(1)), FragmentValidationResult::Valid);
        
        // Third fragment should exceed limit
        assert_eq!(validator.validate_fragment(&create_request(2)), FragmentValidationResult::FragmentLimitExceeded);
    }

    #[test]
    fn test_invalid_fragment_parameters() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        // Fragment index >= total fragments
        let request = create_test_request(
            session_id,
            1,
            2, // index >= total_fragments
            2, // total_fragments
            vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
        );
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::InvalidParameters);
    }

    #[test]
    fn test_session_unregistration() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        // Register session
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.active_session_bindings, 1);
        
        // Unregister session
        validator.unregister_session_binding(session_id);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.active_session_bindings, 0);
        
        // Validation should now fail
        let request = create_test_request(
            session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
        );
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::SessionNotFound);
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
        let session_key = create_test_hmac_key();
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

    #[test]
    fn test_multiple_sessions_same_source() {
        let validator = FragmentSecurityValidator::new();
        let session_id1 = SessionId::Bits32(0x12345678);
        let session_id2 = SessionId::Bits32(0x87654321);
        let session_key1 = create_test_hmac_key();
        let session_key2 = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        // Register two sessions with same source IP
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
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.active_session_bindings, 2);
        assert_eq!(stats.tracked_origins, 1); // Same source IP
        
        // Both sessions should validate successfully
        let request1 = create_test_request(
            session_id1,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            source_ip,
        );
        
        let request2 = create_test_request(
            session_id2,
            1,
            0,
            2,
            vec![0x05, 0x06, 0x07, 0x08],
            source_ip,
        );
        
        assert_eq!(validator.validate_fragment(&request1), FragmentValidationResult::Valid);
        assert_eq!(validator.validate_fragment(&request2), FragmentValidationResult::Valid);
    }

    #[test]
    fn test_cryptographic_binding_disabled() {
        let config = FragmentSecurityConfig {
            enable_crypto_binding: false,
            ..Default::default()
        };
        
        let validator = FragmentSecurityValidator::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        // Fragment should validate even without proper cryptographic binding
        let request = create_test_request(
            session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04], // No HMAC appended
            source_ip,
        );
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::Valid);
    }

    #[test]
    fn test_strict_source_validation_disabled() {
        let config = FragmentSecurityConfig {
            strict_source_validation: false,
            ..Default::default()
        };
        
        let validator = FragmentSecurityValidator::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let allowed_source = 0x7F000001;
        let unauthorized_source = 0x7F000002;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![allowed_source],
        ).unwrap();
        
        // Fragment from unauthorized source should still validate when strict validation is disabled
        let request = create_test_request(
            session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            unauthorized_source,
        );
        
        let result = validator.validate_fragment(&request);
        assert_eq!(result, FragmentValidationResult::Valid);
    }

    #[test]
    fn test_concurrent_validation() {
        use std::sync::Arc;
        use std::thread;
        
        let validator = Arc::new(FragmentSecurityValidator::new());
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let source_ip = 0x7F000001;
        
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![source_ip],
        ).unwrap();
        
        let mut handles = vec![];
        
        // Spawn multiple threads to validate fragments concurrently
        for i in 0..10 {
            let validator_clone = Arc::clone(&validator);
            let handle = thread::spawn(move || {
                let request = create_test_request(
                    session_id,
                    1,
                    i % 2, // Alternate between fragment indices 0 and 1
                    2,
                    vec![0x01, 0x02, 0x03, 0x04],
                    source_ip,
                );
                
                validator_clone.validate_fragment(&request)
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        let mut valid_count = 0;
        for handle in handles {
            let result = handle.join().unwrap();
            if result == FragmentValidationResult::Valid {
                valid_count += 1;
            }
        }
        
        // All validations should succeed
        assert_eq!(valid_count, 10);
    }

    #[test]
    fn test_session_hijacking_detection() {
        let validator = FragmentSecurityValidator::new();
        let session_id = SessionId::Bits32(0x12345678);
        let session_key = create_test_hmac_key();
        let legitimate_source = 0x7F000001;
        let attacker_source = 0x7F000002;
        
        // Register session with legitimate source
        validator.register_session_binding(
            session_id,
            session_key.clone(),
            vec![legitimate_source],
        ).unwrap();
        
        // Legitimate fragment should validate
        let legitimate_request = create_test_request(
            session_id,
            1,
            0,
            2,
            vec![0x01, 0x02, 0x03, 0x04],
            legitimate_source,
        );
        
        assert_eq!(validator.validate_fragment(&legitimate_request), FragmentValidationResult::Valid);
        
        // Attacker trying to hijack session should fail
        let attack_request = create_test_request(
            session_id,
            1,
            1,
            2,
            vec![0x05, 0x06, 0x07, 0x08],
            attacker_source,
        );
        
        assert_eq!(validator.validate_fragment(&attack_request), FragmentValidationResult::OriginValidationFailed);
        
        let stats = validator.get_security_stats();
        assert_eq!(stats.hijacking_attempts, 1);
    }
}