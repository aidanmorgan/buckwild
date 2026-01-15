use buckwild_common::crypto::constant_time_security::*;
#[test]
    fn test_constant_time_byte_comparison() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello there";

        assert!(ConstantTimeValidator::compare_bytes(a, b));
        assert!(!ConstantTimeValidator::compare_bytes(a, c));
        assert!(!ConstantTimeValidator::compare_bytes(a, b"short"));
    }

    #[test]
    fn test_constant_time_u64_comparison() {
        assert!(ConstantTimeValidator::compare_u64(12345, 12345));
        assert!(!ConstantTimeValidator::compare_u64(12345, 54321));
    }

    #[test]
    fn test_session_id_validation() {
        assert!(ConstantTimeValidator::validate_session_id(100, 50, 150));
        assert!(!ConstantTimeValidator::validate_session_id(25, 50, 150));
        assert!(!ConstantTimeValidator::validate_session_id(200, 50, 150));
    }

    #[test]
    fn test_sequence_validation() {
        let result = ConstantTimeValidator::validate_sequence_number(100, 100, 10);
        assert_eq!(result, SequenceValidationResult::Exact);

        let result = ConstantTimeValidator::validate_sequence_number(105, 100, 10);
        assert_eq!(result, SequenceValidationResult::Future);

        let result = ConstantTimeValidator::validate_sequence_number(95, 100, 10);
        assert_eq!(result, SequenceValidationResult::Past);

        let result = ConstantTimeValidator::validate_sequence_number(120, 100, 10);
        assert_eq!(result, SequenceValidationResult::OutOfWindow);
    }

    #[test]
    fn test_conditional_select() {
        assert_eq!(ConstantTimeValidator::conditional_select_u64(true, 100, 200), 100);
        assert_eq!(ConstantTimeValidator::conditional_select_u64(false, 100, 200), 200);
    }

    #[test]
    fn test_header_validation() {
        let result = ConstantTimeValidator::validate_packet_header(
            1, 1,           // version
            12345, 1000, 20000,  // session_id
            54321, 50000, 60000, // timestamp
        );

        assert!(result.version_valid);
        assert!(result.session_valid);
        assert!(result.timestamp_valid);
        assert!(result.overall_valid);
    }

    #[test]
    fn test_hmac_validation() {
        let hmac1 = b"0123456789abcdef";
        let hmac2 = b"0123456789abcdef";
        let hmac3 = b"fedcba9876543210";

        assert!(ConstantTimeValidator::validate_hmac(hmac1, hmac2).unwrap());
        assert!(!ConstantTimeValidator::validate_hmac(hmac1, hmac3).unwrap());
        
        // Test error cases
        assert!(ConstantTimeValidator::validate_hmac(&[], hmac1).is_err());
    }

    #[test]
    fn test_timing_safe_operation() {
        let operation = TimingSafeOperation::new(
            || Ok(42u32),
            100, // 100ms minimum
        );

        let start = Instant::now();
        let result = operation.execute().unwrap();
        let elapsed = start.elapsed();

        assert_eq!(result, 42);
        assert!(elapsed >= std::time::Duration::from_millis(100));
    }

    #[test]
    fn test_secure_memory_compare() {
        let a = b"secret_data_123";
        let b = b"secret_data_123";
        let c = b"secret_data_456";

        assert!(ConstantTimeValidator::secure_memory_compare(a, b, 20));
        assert!(!ConstantTimeValidator::secure_memory_compare(a, c, 20));
        
        // Test length mismatch
        assert!(!ConstantTimeValidator::secure_memory_compare(a, b"short", 20));
    }

    #[test]
    fn test_multiple_conditions() {
        assert!(ConstantTimeValidator::validate_multiple_conditions(&[true, true, true]));
        assert!(!ConstantTimeValidator::validate_multiple_conditions(&[true, false, true]));
        assert!(ConstantTimeValidator::validate_multiple_conditions(&[]));
    }
