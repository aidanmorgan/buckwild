use buckwild_common::protocol::timeout_test::*;

    use super::timeout::*;
    use std::time::Duration;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_rto_state_basic() {
        let rto_state = RtoState::new();
        
        // Test initial state
        let stats = rto_state.get_statistics();
        assert_eq!(stats.srtt_ms, rfc6298_constants::RTT_INITIAL_MS);
        assert_eq!(stats.rttvar_ms, rfc6298_constants::RTT_INITIAL_MS / 2);
        assert_eq!(stats.rto_ms, rfc6298_constants::RTT_INITIAL_MS);
        assert_eq!(stats.measurement_count, 0);
        
        // Test current RTO
        let rto = rto_state.get_current_rto();
        assert_eq!(rto.as_ms(), rfc6298_constants::RTT_INITIAL_MS as u64);
    }
    
    #[tokio::test]
    async fn test_rto_exponential_backoff() {
        let rto_state = RtoState::new();
        
        let initial_rto = rto_state.get_current_rto();
        let rto1 = rto_state.handle_retransmission_timeout();
        let rto2 = rto_state.handle_retransmission_timeout();
        
        assert_eq!(initial_rto.as_ms(), rfc6298_constants::RTT_INITIAL_MS as u64);
        assert_eq!(rto1.as_ms(), (rfc6298_constants::RTT_INITIAL_MS * 2) as u64);
        assert_eq!(rto2.as_ms(), (rfc6298_constants::RTT_INITIAL_MS * 4) as u64);
    }
    
    #[tokio::test]
    async fn test_timeout_manager_basic() {
        let manager = TimeoutManager::new();
        
        // Test RTO statistics
        let stats = manager.get_rto_statistics();
        assert_eq!(stats.measurement_count, 0);
        
        // Test exponential backoff calculation
        let backoff = manager.calculate_exponential_backoff(1, 1000, 60000);
        assert!(backoff.as_ms() >= 2000);
        assert!(backoff.as_ms() <= 2200); // With 10% jitter
    }
    
    #[test]
    fn test_timeout_constants() {
        // Verify timeout constants are reasonable
        assert!(timeout_constants::CONNECTION_TIMEOUT_MS > 0);
        assert!(timeout_constants::HEARTBEAT_TIMEOUT_MS > 0);
        assert!(timeout_constants::SESSION_IDLE_TIMEOUT_MS > timeout_constants::HEARTBEAT_TIMEOUT_MS);
        assert!(timeout_constants::FRAGMENT_TIMEOUT_MS > 0);
        
        // Verify RFC 6298 constants
        assert!(rfc6298_constants::RTT_INITIAL_MS > 0);
        assert!(rfc6298_constants::MIN_RETRANSMISSION_TIMEOUT_MS > 0);
        assert!(rfc6298_constants::MAX_RETRANSMISSION_TIMEOUT_MS > rfc6298_constants::MIN_RETRANSMISSION_TIMEOUT_MS);
        assert!(rfc6298_constants::MAX_RETRANSMISSION_ATTEMPTS > 0);
    }
    
    #[test]
    fn test_timeout_event_types() {
        // Test timeout event type creation
        let event = TimeoutEvent::new(
            TimeoutEventType::Connection,
            TimeoutOutcome::Success,
            1000,
            None,
            "Test event".to_string(),
        );
        
        assert_eq!(event.event_type, TimeoutEventType::Connection);
        assert_eq!(event.outcome, TimeoutOutcome::Success);
        assert_eq!(event.duration_ms, 1000);
        assert_eq!(event.additional_info, "Test event");
    }
    
    #[test]
    fn test_recovery_type_timeouts() {
        assert_eq!(
            RecoveryType::TimeResync.get_timeout_limit().as_ms(),
            timeout_constants::TIME_RESYNC_TIMEOUT_MS
        );
        
        assert_eq!(
            RecoveryType::Rekey.get_timeout_limit().as_ms(),
            timeout_constants::REKEY_TIMEOUT_MS
        );
        
        assert_eq!(
            RecoveryType::SequenceRepair.get_timeout_limit().as_ms(),
            timeout_constants::SEQUENCE_REPAIR_TIMEOUT_MS
        );
        
        assert_eq!(
            RecoveryType::Emergency.get_timeout_limit().as_ms(),
            timeout_constants::EMERGENCY_RECOVERY_TIMEOUT_MS
        );
    }
    
    #[test]
    fn test_timeout_error_context() {
        let mut context = TimeoutErrorContext::new(
            TimeoutEventType::Connection,
            "test_operation".to_string(),
            None,
            "test error".to_string(),
        );
        
        assert_eq!(context.retry_count, 0);
        assert!(!context.has_exceeded_max_retries());
        
        // Test retry increment
        context.increment_retry();
        assert_eq!(context.retry_count, 1);
        
        // Test max retries
        context.retry_count = timeout_constants::MAX_RETRY_ATTEMPTS;
        assert!(context.has_exceeded_max_retries());
    }
