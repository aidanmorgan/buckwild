//! Multi-session integration tests
//!
//! Tests multiple concurrent sessions with isolation, resource sharing, and cleanup.
//! Uses MockClock for deterministic time control and TestTunDevice for packet testing.

//! Multi-session integration tests
//!
//! Tests multiple concurrent sessions with isolation, resource sharing, and cleanup.
//! Note: MockClock and TestTunDevice are cfg(test) and not available in integration tests.

use buckwild_common::protocol::types::ConnectionId;
use buckwild_common::session::{SessionManager, SessionManagerConfig};

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

/// Helper to create session manager with test config
fn create_test_session_manager(
    connection_id: ConnectionId,
    local_endpoint: Option<SocketAddr>,
    remote_endpoint: Option<SocketAddr>,
) -> SessionManager {
    let config = SessionManagerConfig {
        max_sessions: buckwild_common::protocol::types::Threshold::from_raw(100),
        cleanup_interval: buckwild_common::protocol::types::Timeout::new(30_000),
        default_session_timeout: buckwild_common::protocol::types::Timeout::new(300_000),
        enable_session_pooling: true,
        session_pool_size: buckwild_common::protocol::types::Threshold::from_raw(10),
        enable_auto_recovery: true,
        heartbeat_interval: buckwild_common::protocol::types::Timeout::new(30_000),
        enable_state_persistence: false,
        local_endpoint,
        remote_endpoint,
    };

    SessionManager::new(connection_id, config)
}

#[tokio::test]
async fn test_multiple_concurrent_sessions() {
    // Create session manager for connection
    let connection_id = ConnectionId::new(1);
    let manager = Arc::new(create_test_session_manager(connection_id, None, None));

    manager.start().await.expect("start session manager");

    // Create 5 concurrent sessions
    let session_count = 5;
    let mut session_ids = Vec::new();

    for i in 0..session_count {
        let (session_id, session_state) = manager
            .create_session()
            .await
            .expect("create session should succeed");

        assert_eq!(
            session_state.status(),
            buckwild_common::session::SessionStatus::Initializing,
            "new session should be in Initializing state"
        );

        // Verify session is tracked before moving session_id
        assert!(
            manager.get_session(session_id.clone()).is_some(),
            "session {} should be retrievable",
            i
        );

        session_ids.push(session_id);
    }

    // Verify all sessions are active
    assert_eq!(
        manager.session_count(),
        session_count,
        "should have {} active sessions",
        session_count
    );

    let active_ids = manager.get_active_session_ids();
    assert_eq!(
        active_ids.len(),
        session_count,
        "active session IDs should match count"
    );

    // Verify each session is in the active list
    for session_id in &session_ids {
        assert!(
            active_ids.contains(session_id),
            "session {:?} should be in active list",
            session_id
        );
    }

    // Cleanup
    for session_id in session_ids {
        let closed = manager
            .close_session(session_id.clone())
            .await
            .expect("close session should succeed");
        assert!(closed, "session should be closed successfully");
    }

    assert_eq!(manager.session_count(), 0, "all sessions should be closed");

    manager.stop().await.expect("stop session manager");
}

#[tokio::test]
async fn test_session_isolation() {
    // Create two session managers for different connections
    let conn_id_1 = ConnectionId::new(1);
    let conn_id_2 = ConnectionId::new(2);

    let manager1 = Arc::new(create_test_session_manager(conn_id_1, None, None));
    let manager2 = Arc::new(create_test_session_manager(conn_id_2, None, None));

    manager1.start().await.expect("start manager 1");
    manager2.start().await.expect("start manager 2");

    // Create sessions in each manager
    let (session_id_1, state_1) = manager1
        .create_session()
        .await
        .expect("create session in manager 1");

    let (session_id_2, state_2) = manager2
        .create_session()
        .await
        .expect("create session in manager 2");

    // Verify isolation: sessions should not be visible across managers
    assert!(
        manager1.get_session(session_id_1.clone()).is_some(),
        "manager 1 should see its own session"
    );
    assert!(
        manager1.get_session(session_id_2.clone()).is_none(),
        "manager 1 should NOT see manager 2's session"
    );

    assert!(
        manager2.get_session(session_id_2.clone()).is_some(),
        "manager 2 should see its own session"
    );
    assert!(
        manager2.get_session(session_id_1.clone()).is_none(),
        "manager 2 should NOT see manager 1's session"
    );

    // Verify session counts are isolated
    assert_eq!(manager1.session_count(), 1, "manager 1 has 1 session");
    assert_eq!(manager2.session_count(), 1, "manager 2 has 1 session");

    // Modify state in session 1
    state_1.set_local_seq(buckwild_common::protocol::types::SequenceNumber::new(100));

    // Verify session 2 state is unchanged
    assert_eq!(
        state_2.local_seq().as_u32(),
        0,
        "session 2 state should be unaffected by session 1 changes"
    );

    // Cleanup
    manager1
        .close_session(session_id_1)
        .await
        .expect("close session 1");
    manager2
        .close_session(session_id_2)
        .await
        .expect("close session 2");

    manager1.stop().await.expect("stop manager 1");
    manager2.stop().await.expect("stop manager 2");
}

#[tokio::test]
async fn test_session_resource_sharing() {
    // Create session manager with shared resources (engines)
    let connection_id = ConnectionId::new(1);
    let local_endpoint: SocketAddr = "127.0.0.1:5000".parse().expect("valid socket addr");
    let remote_endpoint: SocketAddr = "127.0.0.1:6000".parse().expect("valid socket addr");

    let manager = Arc::new(create_test_session_manager(
        connection_id,
        Some(local_endpoint),
        Some(remote_endpoint),
    ));

    manager.start().await.expect("start session manager");

    // Create multiple sessions
    let session_count = 3;
    let mut session_ids = Vec::new();

    for _ in 0..session_count {
        let (session_id, _) = manager
            .create_session()
            .await
            .expect("create session should succeed");
        session_ids.push(session_id);
    }

    // Verify shared resources are accessible to all sessions
    let time_sync = manager.time_sync_engine();
    assert!(
        Arc::strong_count(&time_sync) >= 1,
        "time sync engine should be accessible, count: {}",
        Arc::strong_count(&time_sync)
    );

    let adaptive = manager.adaptive_engine();
    assert!(
        Arc::strong_count(&adaptive) >= 1,
        "adaptive engine should be accessible, count: {}",
        Arc::strong_count(&adaptive)
    );

    // Verify each session has its own flow control engine
    let mut flow_control_engines = HashSet::new();
    for session_id in &session_ids {
        let flow_engine = manager
            .flow_control_engine(session_id.clone())
            .expect("each session should have flow control engine");

        let engine_ptr = Arc::as_ptr(&flow_engine);
        assert!(
            flow_control_engines.insert(engine_ptr),
            "flow control engines should be unique per session"
        );
    }

    // Cleanup
    for session_id in session_ids {
        manager
            .close_session(session_id)
            .await
            .expect("close session");
    }

    manager.stop().await.expect("stop session manager");
}

#[tokio::test]
async fn test_session_cleanup_on_close() {
    let connection_id = ConnectionId::new(1);
    let manager = Arc::new(create_test_session_manager(connection_id, None, None));

    manager.start().await.expect("start session manager");

    // Create session
    let (session_id, _session_state) = manager.create_session().await.expect("create session");

    // Verify session exists
    assert_eq!(manager.session_count(), 1, "should have 1 session");
    assert!(
        manager.get_session(session_id.clone()).is_some(),
        "session should exist"
    );
    assert!(
        manager.get_session_lifecycle(session_id.clone()).is_some(),
        "session lifecycle should exist"
    );
    assert!(
        manager.flow_control_engine(session_id.clone()).is_some(),
        "flow control engine should exist"
    );

    // Close session
    let closed = manager
        .close_session(session_id.clone())
        .await
        .expect("close session should succeed");

    assert!(closed, "session should be closed");

    // Verify session is completely cleaned up
    assert_eq!(manager.session_count(), 0, "session count should be 0");
    assert!(
        manager.get_session(session_id.clone()).is_none(),
        "session state should be removed"
    );
    assert!(
        manager.get_session_lifecycle(session_id.clone()).is_none(),
        "session lifecycle should be removed"
    );
    assert!(
        manager.flow_control_engine(session_id.clone()).is_none(),
        "flow control engine should be removed"
    );

    // Verify session is not in active list
    let active_ids = manager.get_active_session_ids();
    assert!(
        !active_ids.contains(&session_id),
        "closed session should not be in active list"
    );

    manager.stop().await.expect("stop session manager");
}

#[tokio::test]
async fn test_manager_stop_closes_all_sessions() {
    let connection_id = ConnectionId::new(1);
    let manager = Arc::new(create_test_session_manager(connection_id, None, None));

    manager.start().await.expect("start session manager");

    // Create multiple sessions
    let session_count = 5;
    let mut session_ids = Vec::new();

    for _ in 0..session_count {
        let (session_id, _) = manager.create_session().await.expect("create session");
        session_ids.push(session_id);
    }

    assert_eq!(
        manager.session_count(),
        session_count,
        "should have {} sessions before stop",
        session_count
    );

    // Stop manager (should close all sessions)
    manager.stop().await.expect("stop session manager");

    // Verify all sessions are closed
    assert_eq!(
        manager.session_count(),
        0,
        "all sessions should be closed after stop"
    );

    for session_id in session_ids {
        assert!(
            manager.get_session(session_id.clone()).is_none(),
            "session should be removed after manager stop"
        );
    }
}

#[tokio::test]
async fn test_session_capacity_limit() {
    let connection_id = ConnectionId::new(1);

    // Create manager with low session limit
    let config = SessionManagerConfig {
        max_sessions: buckwild_common::protocol::types::Threshold::from_raw(3),
        cleanup_interval: buckwild_common::protocol::types::Timeout::new(30_000),
        default_session_timeout: buckwild_common::protocol::types::Timeout::new(300_000),
        enable_session_pooling: false,
        session_pool_size: buckwild_common::protocol::types::Threshold::from_raw(10),
        enable_auto_recovery: false,
        heartbeat_interval: buckwild_common::protocol::types::Timeout::new(30_000),
        enable_state_persistence: false,
        local_endpoint: None,
        remote_endpoint: None,
    };

    let manager = Arc::new(SessionManager::new(connection_id, config));
    manager.start().await.expect("start session manager");

    // Create sessions up to limit
    let mut session_ids = Vec::new();
    for i in 0..3 {
        let result = manager.create_session().await;
        assert!(result.is_ok(), "session {} should succeed within limit", i);
        session_ids.push(result.expect("session created").0);
    }

    assert_eq!(manager.session_count(), 3, "should have 3 sessions");

    // Attempt to exceed limit
    let result = manager.create_session().await;
    assert!(
        result.is_err(),
        "session creation should fail when limit exceeded"
    );

    match result {
        Err(buckwild_common::error::SessionError::SessionCapacityExceeded { current, max }) => {
            assert_eq!(current.as_u32(), 3, "current count should be 3");
            assert_eq!(max.as_u32(), 3, "max should be 3");
        }
        _ => panic!("expected SessionCapacityExceeded error"),
    }

    // Close one session
    manager
        .close_session(session_ids[0].clone())
        .await
        .expect("close session");

    assert_eq!(manager.session_count(), 2, "should have 2 sessions");

    // Now we should be able to create another session
    let result = manager.create_session().await;
    assert!(
        result.is_ok(),
        "session creation should succeed after closing one"
    );

    manager.stop().await.expect("stop session manager");
}

#[tokio::test]
async fn test_concurrent_session_operations() {
    let connection_id = ConnectionId::new(1);
    let manager = Arc::new(create_test_session_manager(connection_id, None, None));

    manager.start().await.expect("start session manager");

    // Spawn multiple tasks creating sessions concurrently
    let mut handles = Vec::new();
    let sessions_per_task = 5;
    let task_count = 3;

    for task_id in 0..task_count {
        let manager_clone = manager.clone();
        let handle = tokio::spawn(async move {
            let mut local_session_ids = Vec::new();

            for i in 0..sessions_per_task {
                match manager_clone.create_session().await {
                    Ok((session_id, _)) => {
                        local_session_ids.push(session_id);
                    }
                    Err(e) => {
                        panic!("task {} failed to create session {}: {}", task_id, i, e);
                    }
                }
            }

            local_session_ids
        });

        handles.push(handle);
    }

    // Collect all session IDs
    let mut all_session_ids = Vec::new();
    for handle in handles {
        let session_ids = handle.await.expect("task should complete");
        all_session_ids.extend(session_ids);
    }

    // Verify total session count
    let expected_count = sessions_per_task * task_count;
    assert_eq!(
        manager.session_count(),
        expected_count,
        "should have {} sessions from concurrent creation",
        expected_count
    );

    // Verify all session IDs are unique by converting to raw values
    let unique_ids: HashSet<_> = all_session_ids.iter().map(|id| id.as_u64()).collect();
    assert_eq!(
        unique_ids.len(),
        all_session_ids.len(),
        "all session IDs should be unique"
    );

    // Close all sessions concurrently
    let close_handles: Vec<_> = all_session_ids
        .into_iter()
        .map(|session_id| {
            let manager_clone = manager.clone();
            tokio::spawn(async move {
                manager_clone
                    .close_session(session_id)
                    .await
                    .expect("close session should succeed")
            })
        })
        .collect();

    for handle in close_handles {
        handle.await.expect("close task should complete");
    }

    assert_eq!(manager.session_count(), 0, "all sessions should be closed");

    manager.stop().await.expect("stop session manager");
}
