use buckwild_common::protocol::replay_prevention::*;
#[test]
    fn test_sequence_validation_in_order() {
        let engine = ReplayPreventionEngine::new();
        let session_id = 12345;

        // Sequential packets should be allowed
        for seq in 1..=10 {
            let result = engine.validate_sequence(session_id, seq).unwrap();
            assert_eq!(result, ReplayPreventionResult::Allowed);
        }
    }

    #[test]
    fn test_sequence_validation_out_of_order() {
        let engine = ReplayPreventionEngine::new();
        let session_id = 12345;

        // Send sequence 1, 3, 2
        assert_eq!(engine.validate_sequence(session_id, 1).unwrap(), ReplayPreventionResult::Allowed);
        assert_eq!(engine.validate_sequence(session_id, 3).unwrap(), ReplayPreventionResult::Allowed);
        assert_eq!(engine.validate_sequence(session_id, 2).unwrap(), ReplayPreventionResult::OutOfOrder);
    }

    #[test]
    fn test_replay_detection() {
        let engine = ReplayPreventionEngine::new();
        let session_id = 12345;

        // First packet should be allowed
        assert_eq!(engine.validate_sequence(session_id, 1).unwrap(), ReplayPreventionResult::Allowed);
        
        // Duplicate packet should be detected as replay
        assert_eq!(engine.validate_sequence(session_id, 1).unwrap(), ReplayPreventionResult::ReplayDetected);
    }

    #[test]
    fn test_nonce_generation_and_validation() {
        let engine = ReplayPreventionEngine::new();
        let session_id = 12345;
        let operation_type = "test_operation";
        let challenge_data = b"test_challenge";

        // Generate nonce
        let nonce = engine.generate_nonce(session_id, operation_type, challenge_data).unwrap();
        assert_eq!(nonce.len(), 32);

        // Validate nonce
        let result = engine.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
        assert_eq!(result, ReplayPreventionResult::Allowed);

        // Second validation should detect replay
        let result2 = engine.validate_nonce(&nonce, session_id, operation_type, challenge_data).unwrap();
        assert_eq!(result2, ReplayPreventionResult::ReplayDetected);
    }

    #[test]
    fn test_time_sensitive_operations() {
        let engine = ReplayPreventionEngine::new();
        let session_id = 12345;
        let operation_id = "test_op_1".to_string();
        let operation_data = b"test_operation_data";
        let timeout = Duration::from_secs(60);

        // Register operation
        engine.register_time_sensitive_operation(
            operation_id.clone(),
            session_id,
            operation_data,
            timeout,
        ).unwrap();

        // Validate operation
        let result = engine.validate_time_sensitive_operation(
            &operation_id,
            session_id,
            operation_data,
        ).unwrap();
        assert_eq!(result, ReplayPreventionResult::Allowed);

        // Complete operation
        let was_present = engine.complete_time_sensitive_operation(&operation_id).unwrap();
        assert!(was_present);

        // Validation after completion should fail
        let result2 = engine.validate_time_sensitive_operation(
            &operation_id,
            session_id,
            operation_data,
        ).unwrap();
        assert_eq!(result2, ReplayPreventionResult::InvalidNonce);
    }

    #[test]
    fn test_cleanup() {
        let engine = ReplayPreventionEngine::new();
        let session_id = 12345;

        // Add some data
        engine.validate_sequence(session_id, 1).unwrap();
        engine.generate_nonce(session_id, "test", b"data").unwrap();

        // Cleanup should not remove recent data
        let (sessions, nonces, ops) = engine.cleanup_expired_entries().unwrap();
        assert_eq!(sessions, 0);
        assert_eq!(nonces, 0);
        assert_eq!(ops, 0);
    }
