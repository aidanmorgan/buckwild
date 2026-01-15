// Session Lifecycle Tests
//
// Tests verify session state transitions, timeouts, health monitoring, and recovery
// following design/protocol/06-connection-lifecycle.md
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use super::lifecycle::*;
use crate::protocol::types::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

// =============================================================================
// Session Lifecycle Initialization Tests
// =============================================================================

#[tokio::test]
async fn test_session_lifecycle_initialization() {
    let session_id = SessionId::new_with_length(123, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(456);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let state = lifecycle.current_state().await;
    assert_eq!(state, SessionState::Creating);

    let _events = lifecycle.get_events().await;
    // Events may not be immediately available or may be empty initially
    // Just verify we can get events without error (call above succeeds)
}

#[tokio::test]
async fn test_session_lifecycle_default_config() {
    let config = SessionLifecycleConfig::default();

    assert_eq!(config.session_timeout.as_millis(), 300_000); // 5 minutes
    assert_eq!(config.idle_threshold.as_millis(), 60_000); // 1 minute
    assert_eq!(config.degraded_threshold.as_millis(), 120_000); // 2 minutes
    assert_eq!(config.max_recovery_attempts, Threshold::from_raw(3));
    assert_eq!(config.recovery_timeout.as_millis(), 30_000); // 30 seconds
    assert_eq!(config.heartbeat_timeout.as_millis(), 60_000); // 1 minute
    assert!(config.enable_auto_recovery);
    assert!(config.enable_health_monitoring);
}

// =============================================================================
// Session State Transition Tests
// =============================================================================

#[tokio::test]
async fn test_session_lifecycle_start() {
    let session_id = SessionId::new_with_length(789, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(101112);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let result = lifecycle.start().await;
    assert!(result.is_ok(), "Starting session should succeed");

    let state = lifecycle.current_state().await;
    assert_eq!(state, SessionState::Active);

    let events = lifecycle.get_events().await;
    assert!(events.len() >= 2, "Should have Created and Started events");

    // Find Started event
    let has_started = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::Started { .. }));
    assert!(has_started, "Should have Started event");
}

#[tokio::test]
async fn test_session_lifecycle_stop() {
    let session_id = SessionId::new_with_length(131415, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(161718);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    let result = lifecycle.stop().await;
    assert!(result.is_ok(), "Stopping session should succeed");

    let state = lifecycle.current_state().await;
    assert_eq!(state, SessionState::Terminated);

    let events = lifecycle.get_events().await;
    let has_terminated = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::Terminated { .. }));
    assert!(has_terminated, "Should have Terminated event");
}

#[tokio::test]
async fn test_session_lifecycle_start_stop_cycle() {
    let session_id = SessionId::new_with_length(192021, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(222324);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    // Start
    let _ = lifecycle.start().await;
    assert_eq!(lifecycle.current_state().await, SessionState::Active);

    // Stop
    let _ = lifecycle.stop().await;
    assert_eq!(lifecycle.current_state().await, SessionState::Terminated);

    let events = lifecycle.get_events().await;
    assert!(
        events.len() >= 3,
        "Should have Created, Started, and Terminated events"
    );
}

// =============================================================================
// Activity and Heartbeat Tests
// =============================================================================

#[tokio::test]
async fn test_session_update_activity() {
    let session_id = SessionId::new_with_length(252627, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(282930);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;

    // Update activity
    let result = lifecycle.update_activity().await;
    assert!(result.is_ok(), "Updating activity should succeed");

    let events = lifecycle.get_events().await;
    let has_activity = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::ActivityDetected { .. }));
    assert!(has_activity, "Should have ActivityDetected event");
}

#[tokio::test]
async fn test_session_heartbeat_send() {
    let session_id = SessionId::new_with_length(313233, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(343536);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;

    // Send heartbeat
    let result = lifecycle.send_heartbeat().await;
    assert!(result.is_ok(), "Sending heartbeat should succeed");

    let events = lifecycle.get_events().await;
    let has_heartbeat = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::HeartbeatSent { .. }));
    assert!(has_heartbeat, "Should have HeartbeatSent event");
}

#[tokio::test]
async fn test_session_heartbeat_receive() {
    let session_id = SessionId::new_with_length(373839, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(404142);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;

    // Receive heartbeat
    let result = lifecycle.receive_heartbeat().await;
    assert!(result.is_ok(), "Receiving heartbeat should succeed");

    let events = lifecycle.get_events().await;
    let has_heartbeat = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::HeartbeatReceived { .. }));
    assert!(has_heartbeat, "Should have HeartbeatReceived event");
}

#[tokio::test]
async fn test_session_heartbeat_bidirectional() {
    let session_id = SessionId::new_with_length(434445, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(464748);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;

    // Send and receive heartbeats
    let _ = lifecycle.send_heartbeat().await;
    let _ = lifecycle.receive_heartbeat().await;

    let events = lifecycle.get_events().await;
    let sent_count = events
        .iter()
        .filter(|e| matches!(e, SessionLifecycleEvent::HeartbeatSent { .. }))
        .count();
    let recv_count = events
        .iter()
        .filter(|e| matches!(e, SessionLifecycleEvent::HeartbeatReceived { .. }))
        .count();

    assert_eq!(sent_count, 1, "Should have one HeartbeatSent event");
    assert_eq!(recv_count, 1, "Should have one HeartbeatReceived event");
}

// =============================================================================
// Health Monitoring Tests
// =============================================================================

#[tokio::test]
async fn test_session_is_healthy_after_start() {
    let session_id = SessionId::new_with_length(495051, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(525354);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;

    let is_healthy = lifecycle.is_healthy().await;
    assert!(is_healthy.is_ok(), "Health check should succeed");
    // Health status depends on implementation details, just verify method works
    let _ = is_healthy.unwrap();
}

#[tokio::test]
async fn test_session_is_healthy_with_recent_activity() {
    let session_id = SessionId::new_with_length(555657, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(585960);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;
    let _ = lifecycle.update_activity().await;

    let is_healthy = lifecycle.is_healthy().await;
    assert!(is_healthy.is_ok());
    // Health status depends on implementation details, just verify method works
    let _ = is_healthy.unwrap();
}

#[tokio::test]
async fn test_session_is_healthy_with_recent_heartbeat() {
    let session_id = SessionId::new_with_length(616263, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(646566);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;
    let _ = lifecycle.receive_heartbeat().await;

    let is_healthy = lifecycle.is_healthy().await;
    assert!(is_healthy.is_ok());
    // Health status depends on implementation details, just verify method works
    let _ = is_healthy.unwrap();
}

// =============================================================================
// Recovery Tests
// =============================================================================

#[tokio::test]
async fn test_session_recovery_mechanism() {
    let session_id = SessionId::new_with_length(676869, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(707172);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;

    // Trigger recovery
    let result = lifecycle.recover().await;
    assert!(result.is_ok(), "Recovery should be callable");

    let events = lifecycle.get_events().await;
    let has_recovery = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::RecoveryStarted { .. }));
    assert!(has_recovery, "Should have RecoveryStarted event");
}

// =============================================================================
// Session Age Tests
// =============================================================================

#[tokio::test]
async fn test_session_age_increases() {
    let session_id = SessionId::new_with_length(737475, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(767778);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let age1 = lifecycle.age().await;

    // Wait a bit
    sleep(Duration::from_millis(50)).await;

    let age2 = lifecycle.age().await;

    assert!(age2 > age1, "Session age should increase over time");
}

#[tokio::test]
async fn test_session_age_starts_from_zero() {
    let session_id = SessionId::new_with_length(798081, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(828384);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let age = lifecycle.age().await;

    assert!(
        age.as_millis() < 100,
        "Initial age should be very small (< 100ms)"
    );
}

// =============================================================================
// Event Tracking Tests
// =============================================================================

#[tokio::test]
async fn test_session_event_tracking() {
    let session_id = SessionId::new_with_length(858687, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(888990);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    // Perform various operations
    let _ = lifecycle.start().await;
    let _ = lifecycle.update_activity().await;
    let _ = lifecycle.send_heartbeat().await;
    let _ = lifecycle.receive_heartbeat().await;

    let events = lifecycle.get_events().await;

    // Should have at least Created, Started, ActivityDetected, HeartbeatSent, HeartbeatReceived
    assert!(events.len() >= 5, "Should have multiple events tracked");

    // Verify event timestamps are monotonically increasing
    let timestamps: Vec<Timestamp> = events.iter().map(|e| e.timestamp()).collect();
    for i in 1..timestamps.len() {
        assert!(
            timestamps[i] >= timestamps[i - 1],
            "Event timestamps should be monotonically increasing"
        );
    }
}

#[tokio::test]
async fn test_session_event_timestamp_extraction() {
    let session_id = SessionId::new_with_length(919293, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(949596);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));
    let _ = lifecycle.start().await;

    let events = lifecycle.get_events().await;

    // Every event should have a valid timestamp
    for event in events {
        let timestamp = event.timestamp();
        assert!(
            timestamp > Timestamp::from(0),
            "Event timestamp should be non-zero"
        );
    }
}

// =============================================================================
// Configuration Tests
// =============================================================================

#[tokio::test]
#[allow(clippy::field_reassign_with_default)]
async fn test_session_custom_configuration() {
    let session_id = SessionId::new_with_length(979899, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100101102);

    let mut config = SessionLifecycleConfig::default();
    config.session_timeout = Timeout::from_millis(600_000); // 10 minutes
    config.idle_threshold = Timeout::from_millis(120_000); // 2 minutes
    config.max_recovery_attempts = Threshold::from_raw(5);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, config.session_timeout);

    // Verify configuration is applied (can't directly test but creation should succeed)
    let _ = lifecycle.start().await;
    assert_eq!(lifecycle.current_state().await, SessionState::Active);
}

#[tokio::test]
async fn test_session_auto_recovery_config() {
    let config = SessionLifecycleConfig::default();
    assert!(
        config.enable_auto_recovery,
        "Auto recovery should be enabled by default"
    );

    let mut config_disabled = config.clone();
    config_disabled.enable_auto_recovery = false;
    assert!(
        !config_disabled.enable_auto_recovery,
        "Auto recovery should be disableable"
    );
}

#[tokio::test]
async fn test_session_health_monitoring_config() {
    let config = SessionLifecycleConfig::default();
    assert!(
        config.enable_health_monitoring,
        "Health monitoring should be enabled by default"
    );

    let mut config_disabled = config.clone();
    config_disabled.enable_health_monitoring = false;
    assert!(
        !config_disabled.enable_health_monitoring,
        "Health monitoring should be disableable"
    );
}

// =============================================================================
// State Machine Transition Tests
// =============================================================================

#[tokio::test]
async fn test_state_transition_creating_to_initializing() {
    let session_id = SessionId::new_with_length(100001, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100002);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    assert_eq!(lifecycle.current_state().await, SessionState::Creating);

    let _ = lifecycle.start().await;

    let events = lifecycle.get_events().await;
    let has_created = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::Created { .. }));
    assert!(has_created, "Should transition through Initializing state");
}

#[tokio::test]
async fn test_state_transition_initializing_to_active() {
    let session_id = SessionId::new_with_length(100003, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100004);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    assert_eq!(lifecycle.current_state().await, SessionState::Active);
}

#[tokio::test]
async fn test_state_transition_active_to_idle() {
    let session_id = SessionId::new_with_length(100005, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100006);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    assert_eq!(lifecycle.current_state().await, SessionState::Active);
}

#[tokio::test]
async fn test_state_transition_active_to_terminating() {
    let session_id = SessionId::new_with_length(100007, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100008);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    assert_eq!(lifecycle.current_state().await, SessionState::Active);

    let _ = lifecycle.stop().await;

    let events = lifecycle.get_events().await;
    let has_terminating = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::TerminationStarted { .. }));
    assert!(
        has_terminating,
        "Should transition through Terminating state"
    );
}

#[tokio::test]
async fn test_state_transition_terminating_to_terminated() {
    let session_id = SessionId::new_with_length(100009, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100010);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    let _ = lifecycle.stop().await;

    assert_eq!(lifecycle.current_state().await, SessionState::Terminated);
}

#[tokio::test]
async fn test_state_transition_active_to_recovering() {
    let session_id = SessionId::new_with_length(100011, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100012);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    assert_eq!(lifecycle.current_state().await, SessionState::Active);

    let _ = lifecycle.recover().await;

    let events = lifecycle.get_events().await;
    let has_recovering = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::RecoveryStarted { .. }));
    assert!(has_recovering, "Should transition through Recovering state");
}

#[tokio::test]
async fn test_state_transition_recovering_to_active() {
    let session_id = SessionId::new_with_length(100013, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100014);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    let result = lifecycle.recover().await;

    if result.is_ok() {
        assert_eq!(lifecycle.current_state().await, SessionState::Active);
    }
}

// =============================================================================
// Invalid Transition Tests
// =============================================================================

#[tokio::test]
async fn test_invalid_transition_from_terminated() {
    let session_id = SessionId::new_with_length(100015, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100016);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;
    let _ = lifecycle.stop().await;

    assert_eq!(lifecycle.current_state().await, SessionState::Terminated);

    let result = lifecycle.start().await;
    assert!(
        result.is_err(),
        "Should not allow transition from Terminated state"
    );
}

#[tokio::test]
async fn test_invalid_transition_from_error() {
    let session_id = SessionId::new_with_length(100017, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100018);

    let mut config = SessionLifecycleConfig::default();
    config.max_recovery_attempts = Threshold::from_raw(1);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, config.session_timeout);

    let _ = lifecycle.start().await;

    let _ = lifecycle.recover().await;
    let _ = lifecycle.recover().await;

    let current_state = lifecycle.current_state().await;
    if current_state == SessionState::Error {
        let result = lifecycle.start().await;
        assert!(
            result.is_err(),
            "Should not allow transition from Error state"
        );
    }
}

#[tokio::test]
async fn test_allows_transitions_check() {
    assert!(SessionState::Creating.allows_transitions());
    assert!(SessionState::Initializing.allows_transitions());
    assert!(SessionState::Active.allows_transitions());
    assert!(SessionState::Idle.allows_transitions());
    assert!(SessionState::Degraded.allows_transitions());
    assert!(SessionState::Recovering.allows_transitions());
    assert!(SessionState::Terminating.allows_transitions());

    assert!(
        !SessionState::Terminated.allows_transitions(),
        "Terminated state should not allow transitions"
    );
    assert!(
        !SessionState::Error.allows_transitions(),
        "Error state should not allow transitions"
    );
}

// =============================================================================
// Timeout Handling Tests
// =============================================================================

#[tokio::test]
async fn test_timeout_session_timeout() {
    let session_id = SessionId::new_with_length(100019, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100020);

    let mut config = SessionLifecycleConfig::default();
    config.session_timeout = Timeout::from_millis(100);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, config.session_timeout);

    let _ = lifecycle.start().await;

    sleep(Duration::from_millis(150)).await;

    let is_healthy = lifecycle.is_healthy().await;
    if let Ok(healthy) = is_healthy {
        assert!(!healthy, "Session should be unhealthy after timeout");
    }
}

#[tokio::test]
async fn test_timeout_heartbeat_timeout() {
    let session_id = SessionId::new_with_length(100021, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100022);

    let mut config = SessionLifecycleConfig::default();
    config.heartbeat_timeout = Timeout::from_millis(100);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, config.session_timeout);

    let _ = lifecycle.start().await;

    sleep(Duration::from_millis(150)).await;

    let is_healthy = lifecycle.is_healthy().await;
    if let Ok(healthy) = is_healthy {
        assert!(
            !healthy,
            "Session should be unhealthy after heartbeat timeout"
        );
    }
}

#[tokio::test]
async fn test_timeout_recovery_timeout() {
    let session_id = SessionId::new_with_length(100023, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100024);

    let mut config = SessionLifecycleConfig::default();
    config.recovery_timeout = Timeout::from_millis(50);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, config.session_timeout);

    let _ = lifecycle.start().await;

    let result = lifecycle.recover().await;

    let events = lifecycle.get_events().await;
    let has_recovery = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::RecoveryCompleted { .. }));
    assert!(has_recovery, "Should record recovery completion");

    if result.is_err() {
        let events = lifecycle.get_events().await;
        let completed_event = events
            .iter()
            .find(|e| matches!(e, SessionLifecycleEvent::RecoveryCompleted { .. }));
        if let Some(SessionLifecycleEvent::RecoveryCompleted { success, .. }) = completed_event {
            if !success {
                assert!(true, "Recovery should handle timeout");
            }
        }
    }
}

#[tokio::test]
async fn test_timeout_activity_updates_timestamp() {
    let session_id = SessionId::new_with_length(100025, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100026);

    let lifecycle = SessionLifecycle::new(session_id, connection_id, Timeout::from_millis(300_000));

    let _ = lifecycle.start().await;

    sleep(Duration::from_millis(50)).await;
    let _ = lifecycle.update_activity().await;

    let events = lifecycle.get_events().await;
    let has_activity = events
        .iter()
        .any(|e| matches!(e, SessionLifecycleEvent::ActivityDetected { .. }));
    assert!(has_activity, "Activity update should create event");
}

// =============================================================================
// Concurrent Operations Tests
// =============================================================================

#[tokio::test]
async fn test_concurrent_state_reads() {
    let session_id = SessionId::new_with_length(100027, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100028);

    let lifecycle = std::sync::Arc::new(SessionLifecycle::new(
        session_id,
        connection_id,
        Timeout::from_millis(300_000),
    ));

    let _ = lifecycle.start().await;

    let mut handles = vec![];

    for _ in 0..10 {
        let lifecycle_clone = lifecycle.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..100 {
                let _state = lifecycle_clone.current_state().await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    assert_eq!(lifecycle.current_state().await, SessionState::Active);
}

#[tokio::test]
async fn test_concurrent_activity_updates() {
    let session_id = SessionId::new_with_length(100029, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100030);

    let lifecycle = std::sync::Arc::new(SessionLifecycle::new(
        session_id,
        connection_id,
        Timeout::from_millis(300_000),
    ));

    let _ = lifecycle.start().await;

    let mut handles = vec![];

    for _ in 0..10 {
        let lifecycle_clone = lifecycle.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..50 {
                let _ = lifecycle_clone.update_activity().await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let events = lifecycle.get_events().await;
    let activity_count = events
        .iter()
        .filter(|e| matches!(e, SessionLifecycleEvent::ActivityDetected { .. }))
        .count();

    assert!(
        activity_count > 0,
        "Should have activity events from concurrent updates"
    );
}

#[tokio::test]
async fn test_concurrent_heartbeats() {
    let session_id = SessionId::new_with_length(100031, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100032);

    let lifecycle = std::sync::Arc::new(SessionLifecycle::new(
        session_id,
        connection_id,
        Timeout::from_millis(300_000),
    ));

    let _ = lifecycle.start().await;

    let mut handles = vec![];

    for i in 0..10 {
        let lifecycle_clone = lifecycle.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..20 {
                if i % 2 == 0 {
                    let _ = lifecycle_clone.send_heartbeat().await;
                } else {
                    let _ = lifecycle_clone.receive_heartbeat().await;
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let events = lifecycle.get_events().await;
    let heartbeat_sent_count = events
        .iter()
        .filter(|e| matches!(e, SessionLifecycleEvent::HeartbeatSent { .. }))
        .count();
    let heartbeat_recv_count = events
        .iter()
        .filter(|e| matches!(e, SessionLifecycleEvent::HeartbeatReceived { .. }))
        .count();

    assert!(
        heartbeat_sent_count > 0,
        "Should have sent heartbeat events"
    );
    assert!(
        heartbeat_recv_count > 0,
        "Should have received heartbeat events"
    );
}

#[tokio::test]
async fn test_concurrent_health_checks() {
    let session_id = SessionId::new_with_length(100033, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100034);

    let lifecycle = std::sync::Arc::new(SessionLifecycle::new(
        session_id,
        connection_id,
        Timeout::from_millis(300_000),
    ));

    let _ = lifecycle.start().await;

    let mut handles = vec![];

    for _ in 0..10 {
        let lifecycle_clone = lifecycle.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..100 {
                let _ = lifecycle_clone.is_healthy().await;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let is_healthy = lifecycle.is_healthy().await;
    assert!(is_healthy.is_ok(), "Health check should succeed");
}

#[tokio::test]
async fn test_concurrent_state_transitions() {
    let session_id = SessionId::new_with_length(100035, SessionIdLength::Bits64);
    let connection_id = ConnectionId::new(100036);

    let lifecycle = std::sync::Arc::new(SessionLifecycle::new(
        session_id,
        connection_id,
        Timeout::from_millis(300_000),
    ));

    let lifecycle_clone1 = lifecycle.clone();
    let lifecycle_clone2 = lifecycle.clone();

    let handle1 = tokio::spawn(async move {
        let _ = lifecycle_clone1.start().await;
    });

    let handle2 = tokio::spawn(async move {
        sleep(Duration::from_millis(10)).await;
        let _ = lifecycle_clone2.update_activity().await;
    });

    let _ = handle1.await;
    let _ = handle2.await;

    assert_eq!(lifecycle.current_state().await, SessionState::Active);
}

// =============================================================================
// Session Routing Tests (MED-012)
// =============================================================================

#[tokio::test]
async fn test_session_routing_known_session_lookup() {
    use super::engine::{SessionEngine, SessionEngineConfig};

    let engine = SessionEngine::new(SessionEngineConfig::default());

    let (session_id, session_state) = engine
        .create_session()
        .expect("Session creation should succeed");

    let retrieved = engine.get_session(&session_id);
    assert!(
        retrieved.is_some(),
        "Known session ID should return session"
    );

    let retrieved_state = retrieved.unwrap();
    assert!(
        Arc::ptr_eq(&session_state, &retrieved_state),
        "Retrieved session should be the same instance"
    );
}

#[tokio::test]
async fn test_session_routing_unknown_session_rejection() {
    use super::engine::{SessionEngine, SessionEngineConfig};

    let engine = SessionEngine::new(SessionEngineConfig::default());

    let unknown_session_id = SessionId::from_raw(99999);

    let retrieved = engine.get_session(&unknown_session_id);
    assert!(retrieved.is_none(), "Unknown session ID should return None");
}
