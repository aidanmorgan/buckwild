use buckwild_common::session::manager::*;
use crate::types::ConnectionId;
    
    #[tokio::test]
    async fn test_session_creation() {
        let connection_id = ConnectionId(1);
        let config = SessionManagerConfig::default();
        let manager = SessionManager::new(connection_id, config);
        
        // Start manager
        manager.start().await.unwrap();
        
        // Create session
        let (session_id, session_state) = manager.create_session().await.unwrap();
        
        // Verify session exists
        assert!(manager.get_session(session_id).is_some());
        assert_eq!(manager.session_count(), 1);
        
        // Close session
        assert!(manager.close_session(session_id).await.unwrap());
        assert_eq!(manager.session_count(), 0);
        
        // Stop manager
        manager.stop().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_session_limit() {
        let connection_id = ConnectionId(1);
        let mut config = SessionManagerConfig::default();
        config.max_sessions = 2;
        
        let manager = SessionManager::new(connection_id, config);
        manager.start().await.unwrap();
        
        // Create sessions up to limit
        let (session1, _) = manager.create_session().await.unwrap();
        let (session2, _) = manager.create_session().await.unwrap();
        
        // Try to exceed limit
        let result = manager.create_session().await;
        assert!(result.is_err());
        
        // Close one session and try again
        manager.close_session(session1).await.unwrap();
        let (session3, _) = manager.create_session().await.unwrap();
        
        assert_eq!(manager.session_count(), 2);
        
        manager.stop().await.unwrap();
    }
