use buckwild_common::protocol::recovery_engine::*;
use std::sync::Arc;
    use tokio::sync::Mutex;
    
    // Mock session manager for testing
    struct MockSessionManager {
        sessions: Arc<Mutex<HashMap<SessionId, Arc<SessionState>>>>,
    }
    
    impl MockSessionManager {
        fn new() -> Self {
            Self {
                sessions: Arc::new(Mutex::new(HashMap::new())),
            }
        }
        
        async fn add_session(&self, session_id: SessionId, state: Arc<SessionState>) {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(session_id, state);
        }
    }
    
    impl SessionManagerTrait for MockSessionManager {
        fn get_session_state(&self, session_id: &SessionId) -> Option<Arc<SessionState>> {
            // This is a simplified implementation for testing
            // In reality, this would need proper async handling
            None
        }

        fn update_session_state(&self, _session_id: &SessionId, _state: Arc<SessionState>) -> Result<(), BuckwildError> {
            Ok(())
        }

        fn is_connection_established(&self) -> bool {
            // Default to true for existing tests
            true
        }
    }
    
    #[tokio::test]
    async fn test_recovery_level_escalation() {
        assert_eq!(RecoveryLevel::None.escalate(), RecoveryLevel::TimeSync);
        assert_eq!(RecoveryLevel::TimeSync.escalate(), RecoveryLevel::SequenceRepair);
        assert_eq!(RecoveryLevel::SequenceRepair.escalate(), RecoveryLevel::SessionRekey);
        assert_eq!(RecoveryLevel::SessionRekey.escalate(), RecoveryLevel::Emergency);
        assert_eq!(RecoveryLevel::Emergency.escalate(), RecoveryLevel::ConnectionTerminate);
        assert_eq!(RecoveryLevel::ConnectionTerminate.escalate(), RecoveryLevel::Failed);
        assert_eq!(RecoveryLevel::Failed.escalate(), RecoveryLevel::Failed);
    }
    
    #[tokio::test]
    async fn test_recovery_level_properties() {
        assert!(!RecoveryLevel::TimeSync.is_critical());
        assert!(!RecoveryLevel::SequenceRepair.is_critical());
        assert!(!RecoveryLevel::SessionRekey.is_critical());
        assert!(RecoveryLevel::Emergency.is_critical());
        assert!(RecoveryLevel::ConnectionTerminate.is_critical());
        assert!(RecoveryLevel::Failed.is_critical());
        
        assert_eq!(RecoveryLevel::TimeSync.timeout_ms(), 10000);
        assert_eq!(RecoveryLevel::SequenceRepair.timeout_ms(), 15000);
        assert_eq!(RecoveryLevel::SessionRekey.timeout_ms(), 20000);
        assert_eq!(RecoveryLevel::Emergency.timeout_ms(), 30000);
    }
    
    #[tokio::test]
    async fn test_recovery_engine_creation() {
        use std::net::{IpAddr, Ipv4Addr};
        
        let connection_id = ConnectionId::generate();
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
        let hmac_calculator = Arc::new(HmacCalculator::new());
        let session_manager = Arc::new(MockSessionManager::new());
        
        let recovery_engine = RecoveryEngine::new_for_connection(
            connection_id,
            local_endpoint,
            remote_endpoint,
            ecdh_manager,
            hmac_calculator,
            session_manager,
        );
        
        assert_eq!(recovery_engine.connection_id, connection_id);
        assert_eq!(recovery_engine.local_endpoint, local_endpoint);
        assert_eq!(recovery_engine.remote_endpoint, remote_endpoint);
    }
    
    #[tokio::test]
    async fn test_session_management() {
        use std::net::{IpAddr, Ipv4Addr};
        
        let connection_id = ConnectionId::generate();
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
        let hmac_calculator = Arc::new(HmacCalculator::new());
        let session_manager = Arc::new(MockSessionManager::new());
        
        let recovery_engine = RecoveryEngine::new_for_connection(
            connection_id,
            local_endpoint,
            remote_endpoint,
            ecdh_manager,
            hmac_calculator,
            session_manager,
        );
        
        let session_id = SessionId::Bits64(12345);
        let session_state = Arc::new(SessionState::new());
        
        // Test adding session
        recovery_engine.add_session(session_id, session_state).await.unwrap();
        
        let stats = recovery_engine.get_recovery_stats().await;
        assert_eq!(stats.active_sessions, 1);
        
        // Test removing session
        recovery_engine.remove_session(&session_id).await;
        
        let stats = recovery_engine.get_recovery_stats().await;
        assert_eq!(stats.active_sessions, 0);
    }
    
    #[tokio::test]
    async fn test_recovery_config_defaults() {
        let config = RecoveryConfig::default();
        
        assert_eq!(config.max_recovery_attempts_per_level, recovery_constants::MAX_RECOVERY_ATTEMPTS_PER_LEVEL);
        assert_eq!(config.recovery_retry_interval_ms, recovery_constants::RECOVERY_RETRY_INTERVAL_MS);
        assert_eq!(config.max_time_drift_interval, recovery_constants::MAX_TIME_DRIFT_INTERVAL);
        assert_eq!(config.max_auth_failures_before_rekey, recovery_constants::MAX_AUTH_FAILURES_BEFORE_REKEY);
        assert_eq!(config.max_hmac_failure_rate, recovery_constants::MAX_HMAC_FAILURE_RATE);
        assert_eq!(config.max_repair_window_size, recovery_constants::MAX_REPAIR_WINDOW_SIZE);
    }
    
    #[tokio::test]
    async fn test_failure_condition_recording() {
        use std::net::{IpAddr, Ipv4Addr};
        
        let connection_id = ConnectionId::generate();
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
        let hmac_calculator = Arc::new(HmacCalculator::new());
        let session_manager = Arc::new(MockSessionManager::new());
        
        let recovery_engine = RecoveryEngine::new_for_connection(
            connection_id,
            local_endpoint,
            remote_endpoint,
            ecdh_manager,
            hmac_calculator,
            session_manager,
        );
        
        let session_id = SessionId::Bits64(12345);
        let session_state = Arc::new(SessionState::new());
        
        recovery_engine.add_session(session_id, session_state).await.unwrap();
        
        // Test failure condition recording
        if let Some(recovery_state_arc) = recovery_engine.session_states.get(&session_id) {
            let mut recovery_state = recovery_state_arc.lock().await;
            
            recovery_engine.record_failure_condition(
                &mut recovery_state,
                "test_condition",
                "test_details"
            ).await;
            
            assert_eq!(recovery_state.failure_conditions.len(), 1);
            assert_eq!(recovery_state.failure_conditions[0].condition, "test_condition");
            assert_eq!(recovery_state.failure_conditions[0].details, "test_details");
        }
    }
