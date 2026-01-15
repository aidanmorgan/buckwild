use buckwild_common::session::lifecycle::*;
use crate::types::{SessionId, ConnectionId};
    
    #[tokio::test]
    async fn test_lifecycle_creation() {
        let session_id = SessionId(1);
        let connection_id = ConnectionId(1);
        let lifecycle = SessionLifecycle::new(session_id, connection_id, 60000);
        
        assert_eq!(lifecycle.current_state().await, SessionLifecycleState::Creating);
        assert!(lifecycle.age().await.as_millis() < 100);
    }
    
    #[tokio::test]
    async fn test_lifecycle_start_stop() {
        let session_id = SessionId(1);
        let connection_id = ConnectionId(1);
        let lifecycle = SessionLifecycle::new(session_id, connection_id, 60000);
        
        // Start lifecycle
        lifecycle.start().await.unwrap();
        assert_eq!(lifecycle.current_state().await, SessionLifecycleState::Active);
        
        // Stop lifecycle
        lifecycle.stop().await.unwrap();
        assert_eq!(lifecycle.current_state().await, SessionLifecycleState::Terminated);
    }
    
    #[tokio::test]
    async fn test_activity_updates() {
        let session_id = SessionId(1);
        let connection_id = ConnectionId(1);
        let lifecycle = SessionLifecycle::new(session_id, connection_id, 60000);
        
        lifecycle.start().await.unwrap();
        
        // Update activity
        lifecycle.update_activity().await.unwrap();
        assert!(lifecycle.is_healthy().await.unwrap());
        
        lifecycle.stop().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_heartbeat() {
        let session_id = SessionId(1);
        let connection_id = ConnectionId(1);
        let lifecycle = SessionLifecycle::new(session_id, connection_id, 60000);
        
        lifecycle.start().await.unwrap();
        
        // Send and receive heartbeat
        lifecycle.send_heartbeat().await.unwrap();
        lifecycle.receive_heartbeat().await.unwrap();
        
        assert!(lifecycle.is_healthy().await.unwrap());
        
        lifecycle.stop().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_state_transitions() {
        let session_id = SessionId(1);
        let connection_id = ConnectionId(1);
        let lifecycle = SessionLifecycle::new(session_id, connection_id, 60000);
        
        // Test valid transitions
        lifecycle.transition_to_state(SessionLifecycleState::Initializing).await.unwrap();
        lifecycle.transition_to_state(SessionLifecycleState::Active).await.unwrap();
        lifecycle.transition_to_state(SessionLifecycleState::Idle).await.unwrap();
        
        // Test invalid transition from terminal state
        lifecycle.transition_to_state(SessionLifecycleState::Terminated).await.unwrap();
        let result = lifecycle.transition_to_state(SessionLifecycleState::Active).await;
        assert!(result.is_err());
    }
