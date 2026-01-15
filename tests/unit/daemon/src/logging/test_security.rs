use buckwild_daemon::logging::security::*;
#[test]
    fn test_security_event_creation() {
        let event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Medium,
            "Test authentication failure".to_string(),
            None,
        );
        
        assert_eq!(event.event_type, SecurityEventType::AuthenticationFailure);
        assert_eq!(event.severity, SecuritySeverity::Medium);
        assert_eq!(event.message, "Test authentication failure");
        assert!(!event.id.is_empty());
    }

    #[test]
    fn test_cef_format() {
        let event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::High,
            "Authentication failed".to_string(),
            None,
        )
        .with_source_ip("192.168.1.100".to_string());
        
        let cef = event.to_cef();
        assert!(cef.starts_with("CEF:0|Buckwild|FrequencyHoppingNetwork|1.0|"));
        assert!(cef.contains("src=192.168.1.100"));
        assert!(cef.contains("Authentication failed"));
    }

    #[tokio::test]
    async fn test_security_logger() {
        let logger = SecurityLogger::new().unwrap();
        
        logger.log_authentication_failure("192.168.1.100", "Invalid credentials", None);
        
        assert_eq!(logger.get_event_count(), 1);
    }

    #[test]
    fn test_hash_chain_calculation() {
        let logger = SecurityLogger::new().unwrap();
        
        let event1 = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Medium,
            "Test event 1".to_string(),
            None,
        );
        
        let event2 = SecurityEvent::new(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Low,
            "Test event 2".to_string(),
            None,
        );
        
        let initial_hash = SecurityLogger::calculate_initial_hash();
        let hash1 = logger.calculate_chain_hash(&event1, &initial_hash);
        let hash2 = logger.calculate_chain_hash(&event2, &hash1);
        
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, initial_hash);
        assert_ne!(hash2, initial_hash);
    }

    #[test]
    fn test_chain_integrity_verification() {
        let logger = SecurityLogger::new().unwrap();
        
        let mut event1 = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Medium,
            "Test event 1".to_string(),
            None,
        );
        
        let mut event2 = SecurityEvent::new(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Low,
            "Test event 2".to_string(),
            None,
        );
        
        // Simulate proper hash chain
        let initial_hash = SecurityLogger::calculate_initial_hash();
        event1.chain_hash = logger.calculate_chain_hash(&event1, &initial_hash);
        event2.chain_hash = logger.calculate_chain_hash(&event2, &event1.chain_hash);
        
        let events = vec![event1, event2];
        assert!(logger.verify_chain_integrity(&events));
    }
