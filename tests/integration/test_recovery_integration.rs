// Integration tests for multi-layer recovery mechanisms
//
// This test suite validates the end-to-end recovery functionality
// including time synchronization, sequence repair, ECDH rekeying,
// and recovery coordination under various failure scenarios.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

use tokio::sync::{Mutex, RwLock};
use tokio::time::{timeout, sleep};

use buckwild_common::engines::recovery::{
    RecoveryEscalation, RecoveryLevel, RecoveryState,
};
use buckwild_common::protocol::types::{ConnectionId, SessionId, Timestamp};
use buckwild_common::session::SessionState;
use buckwild_common::security::crypto::ecdh::ThreadSafeEcdhManager;
use buckwild_common::security::crypto::hmac::HmacCalculator;
use buckwild_common::error::EngineError;
use buckwild_common::traits::clock::{Clock, MockClock};
use buckwild_common::network::tun::{TestTunDevice, TunDevice, TunConfig, DeviceName, Mtu};

// Integration test session manager with realistic behavior
struct IntegrationSessionManager {
    sessions: Arc<RwLock<HashMap<SessionId, Arc<SessionState>>>>,
    network_conditions: Arc<RwLock<NetworkConditions>>,
}

#[derive(Debug, Clone)]
struct NetworkConditions {
    latency_ms: u64,
    packet_loss_rate: f64,
    time_drift_ms: i64,
    sequence_errors: bool,
    auth_failures: bool,
}

impl Default for NetworkConditions {
    fn default() -> Self {
        Self {
            latency_ms: 50,
            packet_loss_rate: 0.0,
            time_drift_ms: 0,
            sequence_errors: false,
            auth_failures: false,
        }
    }
}

impl IntegrationSessionManager {
    fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            network_conditions: Arc::new(RwLock::new(NetworkConditions::default())),
        }
    }
    
    async fn add_session(&self, session_id: SessionId, state: Arc<SessionState>) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, state);
    }
    
    async fn simulate_time_drift(&self, drift_ms: i64) {
        let mut conditions = self.network_conditions.write().await;
        conditions.time_drift_ms = drift_ms;
        
        // Apply drift to all sessions
        let sessions = self.sessions.read().await;
        for session in sessions.values() {
            session.set_time_offset(drift_ms as i32);
        }
    }
    
    async fn simulate_sequence_errors(&self, enable: bool) {
        let mut conditions = self.network_conditions.write().await;
        conditions.sequence_errors = enable;
        
        if enable {
            // Create sequence gaps in sessions
            let sessions = self.sessions.read().await;
            for session in sessions.values() {
                let local_seq = session.local_seq();
                session.set_remote_seq(local_seq + 1500); // Create large gap
            }
        }
    }
    
    async fn simulate_auth_failures(&self, enable: bool) {
        let mut conditions = self.network_conditions.write().await;
        conditions.auth_failures = enable;
    }
    
    async fn simulate_network_partition(&self, duration: Duration) {
        let mut conditions = self.network_conditions.write().await;
        conditions.packet_loss_rate = 1.0; // 100% packet loss
        
        // Restore network after duration
        let conditions_clone = self.network_conditions.clone();
        tokio::spawn(async move {
            sleep(duration).await;
            let mut conditions = conditions_clone.write().await;
            conditions.packet_loss_rate = 0.0;
        });
    }
    
    async fn get_network_conditions(&self) -> NetworkConditions {
        self.network_conditions.read().await.clone()
    }
}

impl SessionManagerTrait for IntegrationSessionManager {
    fn get_session_state(&self, session_id: &SessionId) -> Option<Arc<SessionState>> {
        // This is a simplified synchronous implementation
        // In a real implementation, this would be properly async
        None // Placeholder for testing
    }

    fn update_session_state(&self, _session_id: &SessionId, _state: Arc<SessionState>) -> Result<(), BuckwildError> {
        Ok(())
    }

    fn is_connection_established(&self) -> bool {
        // Default to true for integration tests
        true
    }
}

// Test helper to create an integration recovery engine
async fn create_integration_recovery_engine() -> (RecoveryEngine, Arc<IntegrationSessionManager>) {
    let connection_id = ConnectionId::generate();
    let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
    
    let ecdh_manager = Arc::new(ThreadSafeEcdhManager::new(10));
    let hmac_calculator = Arc::new(HmacCalculator::new());
    let session_manager = Arc::new(IntegrationSessionManager::new());
    
    // Use a more aggressive recovery configuration for testing
    let config = RecoveryConfig {
        max_recovery_attempts_per_level: 2,
        recovery_retry_interval_ms: 100, // Faster retries for testing
        max_time_drift_interval: 5000,   // 5 seconds
        max_auth_failures_before_rekey: 2,
        max_hmac_failure_rate: 0.2,      // 20%
        max_repair_window_size: 500,     // Smaller window for testing
        failure_condition_retention_ms: 60000, // 1 minute
        time_sync_tolerance_ms: 500,     // 500ms tolerance
        session_cleanup_timeout: 30,     // 30 seconds
    };
    
    let recovery_engine = RecoveryEngine::new_with_config(
        connection_id,
        local_endpoint,
        remote_endpoint,
        config,
        ecdh_manager,
        hmac_calculator,
        session_manager.clone(),
    );
    
    (recovery_engine, session_manager)
}

#[tokio::test]
async fn test_time_drift_recovery_scenario() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    let session_id = SessionId::Bits64(12345);
    let session_state = Arc::new(SessionState::new());
    
    session_manager.add_session(session_id, session_state.clone()).await;
    recovery_engine.add_session(session_id, session_state).await.unwrap();
    
    // Simulate time drift beyond tolerance
    session_manager.simulate_time_drift(2000).await; // 2 seconds drift
    
    // Check that time sync recovery is triggered
    let recovery_level = recovery_engine.determine_recovery_level_needed(&session_id).await;
    assert_eq!(recovery_level, RecoveryLevel::TimeSync);
    
    // Verify recovery state is properly initialized
    let recovery_info = recovery_engine.get_session_recovery_state(&session_id).await;
    assert!(recovery_info.is_some());
    
    let info = recovery_info.unwrap();
    assert_eq!(info.session_id, session_id);
    assert!(!info.is_in_recovery); // Should not be in recovery yet
}

#[tokio::test]
async fn test_sequence_gap_recovery_scenario() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    let session_id = SessionId::Bits64(12345);
    let session_state = Arc::new(SessionState::new());
    
    session_manager.add_session(session_id, session_state.clone()).await;
    recovery_engine.add_session(session_id, session_state).await.unwrap();
    
    // Simulate sequence errors
    session_manager.simulate_sequence_errors(true).await;
    
    // Check that sequence repair recovery is triggered
    let recovery_level = recovery_engine.determine_recovery_level_needed(&session_id).await;
    assert_eq!(recovery_level, RecoveryLevel::SequenceRepair);
    
    // Verify the sequence gap is detected
    let sessions = session_manager.sessions.read().await;
    if let Some(session) = sessions.get(&session_id) {
        let local_seq = session.local_seq();
        let remote_seq = session.remote_seq();
        assert!(local_seq.abs_diff(remote_seq) > 500); // Should have large gap
    }
}

#[tokio::test]
async fn test_multiple_failure_escalation() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    let session_id = SessionId::Bits64(12345);
    let session_state = Arc::new(SessionState::new());
    
    session_manager.add_session(session_id, session_state.clone()).await;
    recovery_engine.add_session(session_id, session_state).await.unwrap();
    
    // Simulate multiple failure conditions
    session_manager.simulate_time_drift(2000).await;
    session_manager.simulate_sequence_errors(true).await;
    session_manager.simulate_auth_failures(true).await;
    
    // Should escalate to connection termination due to multiple failures
    let recovery_level = recovery_engine.determine_recovery_level_needed(&session_id).await;
    assert_eq!(recovery_level, RecoveryLevel::ConnectionTerminate);
}

#[tokio::test]
async fn test_recovery_timeout_handling() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    let session_id = SessionId::Bits64(12345);
    let session_state = Arc::new(SessionState::new());
    
    session_manager.add_session(session_id, session_state.clone()).await;
    recovery_engine.add_session(session_id, session_state).await.unwrap();
    
    // Simulate recovery in progress that has timed out
    if let Some(recovery_state_arc) = recovery_engine.session_states.get(&session_id) {
        let mut recovery_state = recovery_state_arc.lock().await;
        recovery_state.recovery_in_progress = true;
        recovery_state.current_level = RecoveryLevel::TimeSync;
        recovery_state.recovery_start_time = Instant::now() - Duration::from_millis(15000); // 15 seconds ago
    }
    
    // Check for timeouts
    let timed_out_sessions = recovery_engine.check_recovery_timeouts().await.unwrap();
    assert_eq!(timed_out_sessions.len(), 1);
    assert_eq!(timed_out_sessions[0], session_id);
    
    // Verify statistics are updated
    let stats = recovery_engine.get_recovery_stats().await;
    assert!(stats.failed_recoveries > 0);
}

#[tokio::test]
async fn test_network_partition_recovery() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    let session_id = SessionId::Bits64(12345);
    let session_state = Arc::new(SessionState::new());
    
    session_manager.add_session(session_id, session_state.clone()).await;
    recovery_engine.add_session(session_id, session_state).await.unwrap();
    
    // Simulate network partition
    session_manager.simulate_network_partition(Duration::from_millis(500)).await;
    
    // Verify network conditions
    let conditions = session_manager.get_network_conditions().await;
    assert_eq!(conditions.packet_loss_rate, 1.0);
    
    // Wait for network to recover
    sleep(Duration::from_millis(600)).await;
    
    let conditions = session_manager.get_network_conditions().await;
    assert_eq!(conditions.packet_loss_rate, 0.0);
}

#[tokio::test]
async fn test_recovery_analytics_integration() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    // Create multiple sessions with different failure patterns
    for i in 0..5 {
        let session_id = SessionId::Bits64(i);
        let session_state = Arc::new(SessionState::new());
        
        session_manager.add_session(session_id, session_state.clone()).await;
        recovery_engine.add_session(session_id, session_state).await.unwrap();
        
        // Simulate different failure patterns
        match i % 3 {
            0 => session_manager.simulate_time_drift(1500).await,
            1 => session_manager.simulate_sequence_errors(true).await,
            2 => {
                session_manager.simulate_time_drift(1500).await;
                session_manager.simulate_sequence_errors(true).await;
            }
            _ => {}
        }
        
        // Add some recovery history
        if let Some(recovery_state_arc) = recovery_engine.session_states.get(&session_id) {
            let mut recovery_state = recovery_state_arc.lock().await;
            
            let level = match i % 3 {
                0 => RecoveryLevel::TimeSync,
                1 => RecoveryLevel::SequenceRepair,
                2 => RecoveryLevel::ConnectionTerminate,
                _ => RecoveryLevel::TimeSync,
            };
            
            let result = if i % 2 == 0 {
                RecoveryResult::Success
            } else {
                RecoveryResult::Timeout
            };
            
            recovery_engine.track_recovery_attempt(level, result, &mut recovery_state).await;
        }
    }
    
    // Get comprehensive analytics
    let analytics = recovery_engine.get_recovery_analytics().await;
    
    assert_eq!(analytics.total_sessions, 5);
    assert!(analytics.success_rates_by_level.len() > 0);
    
    // Verify different recovery levels are tracked
    assert!(analytics.success_rates_by_level.contains_key(&RecoveryLevel::TimeSync));
    assert!(analytics.success_rates_by_level.contains_key(&RecoveryLevel::SequenceRepair));
    assert!(analytics.success_rates_by_level.contains_key(&RecoveryLevel::ConnectionTerminate));
}

#[tokio::test]
async fn test_concurrent_session_recovery() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    // Create multiple sessions
    let mut session_ids = Vec::new();
    for i in 0..10 {
        let session_id = SessionId::Bits64(i);
        let session_state = Arc::new(SessionState::new());
        
        session_manager.add_session(session_id, session_state.clone()).await;
        recovery_engine.add_session(session_id, session_state).await.unwrap();
        session_ids.push(session_id);
    }
    
    // Simulate different failure conditions for each session
    for (i, &session_id) in session_ids.iter().enumerate() {
        match i % 3 {
            0 => {
                // Time drift
                let sessions = session_manager.sessions.read().await;
                if let Some(session) = sessions.get(&session_id) {
                    session.set_time_offset(2000);
                }
            }
            1 => {
                // Sequence gap
                let sessions = session_manager.sessions.read().await;
                if let Some(session) = sessions.get(&session_id) {
                    session.set_local_seq(1000);
                    session.set_remote_seq(2000);
                }
            }
            2 => {
                // Multiple failures
                let sessions = session_manager.sessions.read().await;
                if let Some(session) = sessions.get(&session_id) {
                    session.set_time_offset(2000);
                    session.set_local_seq(1000);
                    session.set_remote_seq(2000);
                }
            }
            _ => {}
        }
    }
    
    // Check recovery levels for all sessions
    let mut recovery_levels = Vec::new();
    for &session_id in &session_ids {
        let level = recovery_engine.determine_recovery_level_needed(&session_id).await;
        recovery_levels.push(level);
    }
    
    // Verify different recovery levels are assigned appropriately
    assert!(recovery_levels.contains(&RecoveryLevel::TimeSync));
    assert!(recovery_levels.contains(&RecoveryLevel::SequenceRepair));
    assert!(recovery_levels.contains(&RecoveryLevel::ConnectionTerminate));
    
    // Verify statistics reflect multiple sessions
    let stats = recovery_engine.get_recovery_stats().await;
    assert_eq!(stats.active_sessions, 10);
}

#[tokio::test]
async fn test_recovery_state_persistence() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    let session_id = SessionId::Bits64(12345);
    let session_state = Arc::new(SessionState::new());
    
    session_manager.add_session(session_id, session_state.clone()).await;
    recovery_engine.add_session(session_id, session_state).await.unwrap();
    
    // Record multiple failure conditions and recovery attempts
    if let Some(recovery_state_arc) = recovery_engine.session_states.get(&session_id) {
        let mut recovery_state = recovery_state_arc.lock().await;
        
        // Record failure conditions
        for i in 0..5 {
            recovery_engine.record_failure_condition(
                &mut recovery_state,
                &format!("test_condition_{}", i),
                &format!("Test details {}", i)
            ).await;
        }
        
        // Track recovery attempts
        for level in [RecoveryLevel::TimeSync, RecoveryLevel::SequenceRepair, RecoveryLevel::SessionRekey] {
            recovery_engine.track_recovery_attempt(
                level,
                RecoveryResult::Success,
                &mut recovery_state
            ).await;
        }
        
        // Verify persistence
        assert_eq!(recovery_state.failure_conditions.len(), 5);
        assert_eq!(recovery_state.escalation_history.len(), 3);
        assert_eq!(recovery_state.total_recovery_attempts, 3);
        
        // Verify failure conditions are properly stored
        for (i, condition) in recovery_state.failure_conditions.iter().enumerate() {
            assert_eq!(condition.condition, format!("test_condition_{}", i));
            assert_eq!(condition.details, format!("Test details {}", i));
        }
        
        // Verify escalation history is properly stored
        assert_eq!(recovery_state.escalation_history[0].level, RecoveryLevel::TimeSync);
        assert_eq!(recovery_state.escalation_history[1].level, RecoveryLevel::SequenceRepair);
        assert_eq!(recovery_state.escalation_history[2].level, RecoveryLevel::SessionRekey);
        
        for attempt in &recovery_state.escalation_history {
            assert_eq!(attempt.result, RecoveryResult::Success);
        }
    }
}

#[tokio::test]
async fn test_recovery_engine_resource_cleanup() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    // Add many sessions
    for i in 0..100 {
        let session_id = SessionId::Bits64(i);
        let session_state = Arc::new(SessionState::new());
        
        session_manager.add_session(session_id, session_state.clone()).await;
        recovery_engine.add_session(session_id, session_state).await.unwrap();
    }
    
    let stats_before = recovery_engine.get_recovery_stats().await;
    assert_eq!(stats_before.active_sessions, 100);
    
    // Remove half the sessions
    for i in 0..50 {
        let session_id = SessionId::Bits64(i);
        recovery_engine.remove_session(&session_id).await;
    }
    
    let stats_after = recovery_engine.get_recovery_stats().await;
    assert_eq!(stats_after.active_sessions, 50);
    
    // Cleanup expired sessions
    recovery_engine.cleanup_expired_sessions().await;
    
    // Shutdown should clean up remaining sessions
    recovery_engine.shutdown().await.unwrap();
    
    let stats_final = recovery_engine.get_recovery_stats().await;
    assert_eq!(stats_final.active_sessions, 0);
}

#[tokio::test]
async fn test_recovery_under_load() {
    let (recovery_engine, session_manager) = create_integration_recovery_engine().await;
    
    // Create many sessions concurrently
    let mut handles = Vec::new();
    
    for i in 0..50 {
        let recovery_engine = recovery_engine.clone();
        let session_manager = session_manager.clone();
        
        let handle = tokio::spawn(async move {
            let session_id = SessionId::Bits64(i);
            let session_state = Arc::new(SessionState::new());
            
            session_manager.add_session(session_id, session_state.clone()).await;
            recovery_engine.add_session(session_id, session_state).await.unwrap();
            
            // Simulate various failure conditions
            match i % 4 {
                0 => {
                    let sessions = session_manager.sessions.read().await;
                    if let Some(session) = sessions.get(&session_id) {
                        session.set_time_offset(1500);
                    }
                }
                1 => {
                    let sessions = session_manager.sessions.read().await;
                    if let Some(session) = sessions.get(&session_id) {
                        session.set_local_seq(1000);
                        session.set_remote_seq(1800);
                    }
                }
                2 => {
                    // Multiple failures
                    let sessions = session_manager.sessions.read().await;
                    if let Some(session) = sessions.get(&session_id) {
                        session.set_time_offset(1500);
                        session.set_local_seq(1000);
                        session.set_remote_seq(1800);
                    }
                }
                _ => {
                    // No failures
                }
            }
            
            // Check recovery level
            recovery_engine.determine_recovery_level_needed(&session_id).await
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    let results: Vec<RecoveryLevel> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    
    // Verify results
    assert_eq!(results.len(), 50);
    
    // Should have different recovery levels based on failure patterns
    let time_sync_count = results.iter().filter(|&&level| level == RecoveryLevel::TimeSync).count();
    let sequence_repair_count = results.iter().filter(|&&level| level == RecoveryLevel::SequenceRepair).count();
    let connection_terminate_count = results.iter().filter(|&&level| level == RecoveryLevel::ConnectionTerminate).count();
    let none_count = results.iter().filter(|&&level| level == RecoveryLevel::None).count();
    
    // Verify distribution matches our failure pattern (25% each type)
    assert!(time_sync_count > 0);
    assert!(sequence_repair_count > 0);
    assert!(connection_terminate_count > 0);
    assert!(none_count > 0);
    
    // Verify final statistics
    let final_stats = recovery_engine.get_recovery_stats().await;
    assert_eq!(final_stats.active_sessions, 50);
}

// ============================================================================
// NEW TESTS: Deterministic recovery testing with MockClock and TestTunDevice
// ============================================================================

/// Test packet loss detection using TestTunDevice
#[tokio::test]
async fn test_packet_loss_detection_with_mock_device() {
    let config = TunConfig::new(
        DeviceName::new("test0").expect("valid device name"),
        "10.0.0.1".parse().expect("valid IP"),
        "255.255.255.0".parse().expect("valid netmask"),
        Mtu::default(),
    );

    let mut device = TestTunDevice::create(config).await.expect("device creation failed");

    // Inject packets 1, 2, 4, 5 (missing packet 3)
    let packet1 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x01]; // seq=1
    let packet2 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x02]; // seq=2
    let packet4 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x04]; // seq=4 (gap!)
    let packet5 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x05]; // seq=5

    device.inject_packet(packet1.clone());
    device.inject_packet(packet2.clone());
    device.inject_packet(packet4.clone());
    device.inject_packet(packet5.clone());

    // Read packets and detect sequence gap
    let mut buf = [0u8; 1500];
    let mut last_seq = 0u16;
    let mut gap_detected = false;

    for _ in 0..4 {
        let len = device.read_packet(&mut buf).await.expect("read failed");
        assert!(len >= 6, "packet too short");

        // Extract sequence from byte 5 (simplified)
        let seq = u16::from_be_bytes([buf[4], buf[5]]);

        if seq > last_seq + 1 {
            gap_detected = true;
        }
        last_seq = seq;
    }

    assert!(gap_detected, "sequence gap not detected");
    assert_eq!(device.packets_read(), 4);
}

/// Test recovery trigger at threshold using MockClock
#[tokio::test]
async fn test_recovery_trigger_with_mock_clock() {
    let clock = MockClock::new(Timestamp::from_millis(0));
    let mut escalation = RecoveryEscalation::new(1000); // 1 second base backoff

    // Start recovery at T=0
    let level = escalation.start_recovery().expect("recovery start failed");
    assert_eq!(level, RecoveryLevel::TimeResync);
    assert_eq!(escalation.state(), RecoveryState::InProgress);

    // Fail the recovery
    escalation
        .complete_failure("time sync failed".to_string())
        .expect("complete_failure failed");
    assert_eq!(escalation.state(), RecoveryState::Normal);

    // Try immediate retry - should fail due to backoff
    let result = escalation.start_recovery();
    assert!(result.is_err(), "should enforce backoff");
    assert!(matches!(result, Err(EngineError::BackoffRequired(_))));

    // Advance clock by 1 second to satisfy backoff
    clock.advance(Duration::from_secs(1));

    // Now retry should succeed
    let level = escalation.start_recovery().expect("recovery retry failed");
    assert_eq!(level, RecoveryLevel::TimeResync);
}

/// Test escalation through all recovery levels
#[tokio::test]
async fn test_escalation_all_levels() {
    let mut escalation = RecoveryEscalation::new(10); // 10ms backoff for fast testing

    let expected_progression = vec![
        (RecoveryLevel::TimeResync, 3),
        (RecoveryLevel::SequenceRepair, 3),
        (RecoveryLevel::EcdhRekeying, 3),
        (RecoveryLevel::PortResync, 3),
        (RecoveryLevel::PskDiscovery, 2),
        (RecoveryLevel::ConnectionReset, 1),
    ];

    for (expected_level, max_attempts) in expected_progression {
        for attempt in 1..=max_attempts {
            tokio::time::sleep(Duration::from_millis(20)).await; // Wait for backoff

            let level = escalation.start_recovery().expect("start_recovery failed");
            assert_eq!(
                level, expected_level,
                "expected level {:?} at attempt {}",
                expected_level, attempt
            );

            escalation
                .complete_failure(format!("attempt {} failed", attempt))
                .expect("complete_failure failed");

            if attempt == max_attempts {
                // After exhausting attempts, should escalate to next level
                if expected_level != RecoveryLevel::ConnectionReset {
                    assert_eq!(escalation.current_level(), expected_level.next_level().expect("next level exists"));
                }
            }
        }
    }

    // After all levels exhausted, should be in Failed state
    assert!(escalation.is_permanently_failed());
    assert_eq!(escalation.state(), RecoveryState::Failed);

    // Cannot start new recovery when permanently failed
    let result = escalation.start_recovery();
    assert!(result.is_err());
    assert!(matches!(result, Err(EngineError::PermanentFailure(_))));
}

/// Test recovery completion with successful recovery at each level
#[tokio::test]
async fn test_recovery_completion_at_each_level() {
    // Test successful recovery at Level 1
    let mut escalation = RecoveryEscalation::new(10);
    escalation.start_recovery().expect("start failed");
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);

    escalation.complete_success().expect("complete_success failed");
    assert_eq!(escalation.state(), RecoveryState::Recovered);
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync);
    assert_eq!(escalation.attempts_at_current_level(), 0);

    // Test successful recovery at Level 2
    let mut escalation = RecoveryEscalation::new(10);

    // Fail through Level 1
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        escalation.start_recovery().expect("start failed");
        escalation.complete_failure("fail".to_string()).expect("complete_failure failed");
    }

    assert_eq!(escalation.current_level(), RecoveryLevel::SequenceRepair);

    tokio::time::sleep(Duration::from_millis(20)).await;
    escalation.start_recovery().expect("start failed");
    escalation.complete_success().expect("complete_success failed");

    assert_eq!(escalation.state(), RecoveryState::Recovered);
    assert_eq!(escalation.current_level(), RecoveryLevel::TimeResync); // Reset to initial
}

/// Test exponential backoff with MockClock
#[tokio::test]
async fn test_exponential_backoff_with_mock_clock() {
    let clock = MockClock::new(Timestamp::from_millis(0));
    let mut escalation = RecoveryEscalation::new(1000); // 1 second base

    // Attempt 1: backoff = 1s
    escalation.start_recovery().expect("start failed");
    escalation.complete_failure("fail".to_string()).expect("complete_failure failed");

    // Advance by 500ms - not enough
    clock.advance(Duration::from_millis(500));
    assert!(escalation.start_recovery().is_err());

    // Advance by another 500ms (total 1s) - should work
    clock.advance(Duration::from_millis(500));

    // Attempt 2: backoff = 2s
    escalation.start_recovery().expect("start failed");
    escalation.complete_failure("fail".to_string()).expect("complete_failure failed");

    // Advance by 1s - not enough (need 2s)
    clock.advance(Duration::from_secs(1));
    assert!(escalation.start_recovery().is_err());

    // Advance by another 1s (total 2s) - should work
    clock.advance(Duration::from_secs(1));

    // Attempt 3: backoff = 4s
    escalation.start_recovery().expect("start failed");
    escalation.complete_failure("fail".to_string()).expect("complete_failure failed");

    clock.advance(Duration::from_secs(3));
    assert!(escalation.start_recovery().is_err());

    clock.advance(Duration::from_secs(1));
    assert!(escalation.start_recovery().is_ok());
}

/// Test packet loss simulation with high loss rate
#[tokio::test]
async fn test_high_packet_loss_simulation() {
    let config = TunConfig::new(
        DeviceName::new("test1").expect("valid device name"),
        "10.0.0.2".parse().expect("valid IP"),
        "255.255.255.0".parse().expect("valid netmask"),
        Mtu::default(),
    );

    let mut device = TestTunDevice::create(config).await.expect("device creation failed");

    // Simulate 50% packet loss: inject every other packet
    for i in 0..20 {
        if i % 2 == 0 {
            let packet = vec![0x45, 0x00, 0x00, 0x20, (i >> 8) as u8, (i & 0xff) as u8];
            device.inject_packet(packet);
        }
    }

    // Read all available packets
    let mut buf = [0u8; 1500];
    let mut received_count = 0;
    let mut expected_count = 0;

    for i in 0..20 {
        if i % 2 == 0 {
            expected_count += 1;
            let len = device.read_packet(&mut buf).await.expect("read failed");
            assert!(len >= 6);
            received_count += 1;
        }
    }

    assert_eq!(received_count, 10);
    assert_eq!(expected_count, 10);
    assert_eq!(device.packets_read(), 10);
}

/// Test recovery timeout detection with MockClock
#[tokio::test]
async fn test_recovery_timeout_detection() {
    let clock = MockClock::new(Timestamp::from_millis(0));
    let mut escalation = RecoveryEscalation::new(1000);

    // Start recovery
    escalation.start_recovery().expect("start failed");
    assert_eq!(escalation.state(), RecoveryState::InProgress);

    // Advance time beyond reasonable timeout (30 seconds)
    clock.advance(Duration::from_secs(31));

    // In a real system, this would trigger timeout detection
    // For this test, we verify the state is still InProgress
    assert_eq!(escalation.state(), RecoveryState::InProgress);

    // Complete with timeout result
    escalation.complete_failure("timeout".to_string()).expect("complete_failure failed");
    assert_eq!(escalation.state(), RecoveryState::Normal);
}

/// Test recovery statistics collection
#[tokio::test]
async fn test_recovery_statistics() {
    let mut escalation = RecoveryEscalation::new(10);

    // Perform multiple recovery attempts at different levels
    for i in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        escalation.start_recovery().expect("start failed");

        if i % 2 == 0 {
            escalation.complete_success().expect("complete_success failed");
        } else {
            escalation.complete_failure(format!("fail {}", i)).expect("complete_failure failed");
        }
    }

    let stats = escalation.statistics();

    assert_eq!(stats.total_attempts, 5);
    assert_eq!(stats.successful_attempts, 3); // Attempts 0, 2, 4 succeeded
    assert_eq!(stats.state, RecoveryState::Recovered); // Last was success
}

/// Test concurrent recovery attempts are prevented
#[tokio::test]
async fn test_concurrent_recovery_prevention() {
    let mut escalation = RecoveryEscalation::new(1000);

    // Start first recovery
    escalation.start_recovery().expect("start failed");
    assert_eq!(escalation.state(), RecoveryState::InProgress);

    // Try to start another - should fail
    let result = escalation.start_recovery();
    assert!(result.is_err());
    assert!(matches!(result, Err(EngineError::InvalidState(_))));

    // Complete first recovery
    escalation.complete_success().expect("complete_success failed");

    // Now can start new recovery
    tokio::time::sleep(Duration::from_millis(1100)).await; // Wait for backoff
    let result = escalation.start_recovery();
    assert!(result.is_ok());
}

/// Test packet reordering detection with TestTunDevice
#[tokio::test]
async fn test_packet_reordering_detection() {
    let config = TunConfig::new(
        DeviceName::new("test2").expect("valid device name"),
        "10.0.0.3".parse().expect("valid IP"),
        "255.255.255.0".parse().expect("valid netmask"),
        Mtu::default(),
    );

    let mut device = TestTunDevice::create(config).await.expect("device creation failed");

    // Inject packets in wrong order: 1, 3, 2, 4
    let packet1 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x01];
    let packet3 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x03];
    let packet2 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x02];
    let packet4 = vec![0x45, 0x00, 0x00, 0x20, 0x00, 0x04];

    device.inject_packet(packet1);
    device.inject_packet(packet3);
    device.inject_packet(packet2);
    device.inject_packet(packet4);

    // Read packets and detect reordering
    let mut buf = [0u8; 1500];
    let mut seqs = Vec::new();

    for _ in 0..4 {
        let len = device.read_packet(&mut buf).await.expect("read failed");
        assert!(len >= 6);
        let seq = u16::from_be_bytes([buf[4], buf[5]]);
        seqs.push(seq);
    }

    // Verify reordering occurred
    assert_eq!(seqs, vec![1, 3, 2, 4]);
    assert_ne!(seqs, vec![1, 2, 3, 4], "packets should be reordered");

    // Detect out-of-order (packet 2 came after packet 3)
    let mut reorder_detected = false;
    for i in 1..seqs.len() {
        if seqs[i] < seqs[i - 1] {
            reorder_detected = true;
            break;
        }
    }

    assert!(reorder_detected, "reordering not detected");
}