use buckwild_daemon::logging::correlation::*;
#[test]
    fn test_correlation_id_creation() {
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::new();
        
        assert_ne!(id1, id2);
        assert!(!id1.to_string().is_empty());
    }

    #[test]
    fn test_correlation_id_from_string() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let id = CorrelationId::from_string(uuid_str).unwrap();
        assert_eq!(id.to_string(), uuid_str);
    }

    #[test]
    fn test_correlation_context() {
        let mut context = CorrelationContext::new("test_operation".to_string());
        assert_eq!(context.operation, "test_operation");
        assert_eq!(context.events.len(), 0);
        
        // Test event addition
        let event = super::LogEvent {
            timestamp: chrono::Utc::now(),
            level: "INFO".to_string(),
            message: "Test message".to_string(),
            correlation_id: Some(context.correlation_id.clone()),
            component: "test".to_string(),
            session_id: None,
            fields: std::collections::HashMap::new(),
        };
        
        context.add_event(event);
        assert_eq!(context.events.len(), 1);
    }

    #[test]
    fn test_correlation_context_max_events() {
        let mut context = CorrelationContext::new("test_operation".to_string());
        context.max_events = 2; // Set small limit for testing
        
        // Add events beyond the limit
        for i in 0..5 {
            let event = super::LogEvent {
                timestamp: chrono::Utc::now(),
                level: "INFO".to_string(),
                message: format!("Test message {}", i),
                correlation_id: Some(context.correlation_id.clone()),
                component: "test".to_string(),
                session_id: None,
                fields: std::collections::HashMap::new(),
            };
            context.add_event(event);
        }
        
        // Should only keep the last 2 events
        assert_eq!(context.events.len(), 2);
        assert_eq!(context.events[0].message, "Test message 3");
        assert_eq!(context.events[1].message, "Test message 4");
    }

    #[test]
    fn test_correlation_span() {
        let span = CorrelationSpan::new("test_operation");
        assert!(!span.correlation_id().to_string().is_empty());
    }
