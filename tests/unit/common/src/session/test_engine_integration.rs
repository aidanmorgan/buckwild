// Test engine integration with SessionManager
#![cfg(test)]

use std::net::SocketAddr;
use std::str::FromStr;

use buckwild_common::protocol::types::{ConnectionId, Threshold, Timeout};
use buckwild_common::session::manager::{SessionManager, SessionManagerConfig};

#[tokio::test]
async fn test_session_manager_with_engines() {
    // Create config with endpoints for engine initialization
    let config = SessionManagerConfig {
        max_sessions: Threshold::from_raw(10),
        cleanup_interval: Timeout::new(30_000),
        default_session_timeout: Timeout::new(300_000),
        enable_session_pooling: true,
        session_pool_size: Threshold::from_raw(10),
        enable_auto_recovery: true,
        heartbeat_interval: Timeout::new(30_000),
        enable_state_persistence: false,
        local_endpoint: Some(
            SocketAddr::from_str("127.0.0.1:5000").expect("Failed to parse local endpoint"),
        ),
        remote_endpoint: Some(
            SocketAddr::from_str("127.0.0.1:6000").expect("Failed to parse remote endpoint"),
        ),
    };

    let connection_id = ConnectionId::new(1);
    let manager = SessionManager::new(connection_id, config);

    // Start the session manager
    manager.start().await.expect("Failed to start manager");

    // Verify engines are initialized
    assert!(
        manager.port_hopping_engine().is_some(),
        "Port hopping engine should be initialized"
    );
    assert!(
        manager.time_sync_engine().state().status()
            != buckwild_common::engines::time_sync::engine::TimeSyncStatus::Failed,
        "Time sync engine should be operational"
    );
    assert!(
        manager.adaptive_engine().state().is_initialized(),
        "Adaptive engine should be initialized"
    );

    // Create a session
    let (session_id, _session_state) = manager
        .create_session()
        .await
        .expect("Failed to create session");

    // Verify flow control engine was created for the session
    assert!(
        manager.flow_control_engine(session_id.clone()).is_some(),
        "Flow control engine should be created for session"
    );

    // Close session
    manager
        .close_session(session_id.clone())
        .await
        .expect("Failed to close session");

    // Verify flow control engine was cleaned up
    assert!(
        manager.flow_control_engine(session_id).is_none(),
        "Flow control engine should be cleaned up after session close"
    );

    // Stop the manager
    manager.stop().await.expect("Failed to stop manager");
}

#[tokio::test]
async fn test_session_manager_without_endpoints() {
    // Create config without endpoints
    let config = SessionManagerConfig::default();

    let connection_id = ConnectionId::new(2);
    let manager = SessionManager::new(connection_id, config);

    // Start the session manager
    manager.start().await.expect("Failed to start manager");

    // Verify port hopping engine is NOT initialized without endpoints
    assert!(
        manager.port_hopping_engine().is_none(),
        "Port hopping engine should not be initialized without endpoints"
    );

    // Verify other engines are still initialized
    assert!(
        manager.time_sync_engine().state().status()
            != buckwild_common::engines::time_sync::engine::TimeSyncStatus::Failed,
        "Time sync engine should be operational even without endpoints"
    );

    // Stop the manager
    manager.stop().await.expect("Failed to stop manager");
}

#[tokio::test]
async fn test_multiple_sessions_with_flow_control_engines() {
    let config = SessionManagerConfig::default();

    let connection_id = ConnectionId::new(3);
    let manager = SessionManager::new(connection_id, config);

    manager.start().await.expect("Failed to start manager");

    // Create multiple sessions
    let (session_id1, _) = manager
        .create_session()
        .await
        .expect("Failed to create session 1");
    let (session_id2, _) = manager
        .create_session()
        .await
        .expect("Failed to create session 2");
    let (session_id3, _) = manager
        .create_session()
        .await
        .expect("Failed to create session 3");

    // Verify each has its own flow control engine
    assert!(
        manager.flow_control_engine(session_id1.clone()).is_some(),
        "Session 1 should have flow control engine"
    );
    assert!(
        manager.flow_control_engine(session_id2.clone()).is_some(),
        "Session 2 should have flow control engine"
    );
    assert!(
        manager.flow_control_engine(session_id3.clone()).is_some(),
        "Session 3 should have flow control engine"
    );

    // Close one session
    manager
        .close_session(session_id2.clone())
        .await
        .expect("Failed to close session 2");

    // Verify only that session's engine is cleaned up
    assert!(
        manager.flow_control_engine(session_id1).is_some(),
        "Session 1 engine should still exist"
    );
    assert!(
        manager.flow_control_engine(session_id2).is_none(),
        "Session 2 engine should be cleaned up"
    );
    assert!(
        manager.flow_control_engine(session_id3).is_some(),
        "Session 3 engine should still exist"
    );

    manager.stop().await.expect("Failed to stop manager");
}
