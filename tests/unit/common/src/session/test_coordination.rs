use buckwild_common::session::coordination::*;
use crate::types::{SessionId, ConnectionId};
    use crate::session::SessionState;
    
    #[tokio::test]
    async fn test_session_registration() {
        let connection_id = ConnectionId(1);
        let coordination = SessionCoordination::new(connection_id);
        
        coordination.start().await.unwrap();
        
        let session_id = SessionId(1);
        let session_state = Arc::new(SessionState::new());
        
        // Register session
        coordination.register_session(session_id, session_state).await.unwrap();
        assert_eq!(coordination.session_count(), 1);
        
        // Unregister session
        coordination.unregister_session(session_id).await.unwrap();
        assert_eq!(coordination.session_count(), 0);
        
        coordination.stop().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_resource_allocation() {
        let connection_id = ConnectionId(1);
        let coordination = SessionCoordination::new(connection_id);
        
        coordination.start().await.unwrap();
        
        let session_id = SessionId(1);
        let session_state = Arc::new(SessionState::new());
        
        // Register session
        coordination.register_session(session_id, session_state).await.unwrap();
        
        // Allocate resource
        coordination.allocate_resource(
            session_id,
            SessionResourceType::Port,
            "port_8080".to_string(),
            HashMap::new(),
        ).await.unwrap();
        
        // Deallocate resource
        coordination.deallocate_resource("port_8080").await.unwrap();
        
        coordination.stop().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_session_priority() {
        let connection_id = ConnectionId(1);
        let coordination = SessionCoordination::new(connection_id);
        
        let session_id = SessionId(1);
        let session_state = Arc::new(SessionState::new());
        
        coordination.register_session(session_id, session_state).await.unwrap();
        
        // Set priority
        coordination.set_session_priority(session_id, 200).await.unwrap();
        assert_eq!(coordination.get_session_priority(session_id), Some(200));
    }
