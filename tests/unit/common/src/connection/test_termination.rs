use buckwild_common::connection::termination::*;
use crate::types::{ConnectionId, SessionId};
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_termination_creation() {
        let connection_id = ConnectionId(1);
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let reason = TerminationReason::NormalShutdown;
        let config = TerminationConfig::default();
        
        let termination = ConnectionTermination::new(
            connection_id,
            local_endpoint,
            remote_endpoint,
            reason,
            config,
        );
        
        assert_eq!(termination.current_state().await, TerminationState::Active);
        assert!(!termination.is_complete().await);
        assert!(!termination.is_successful().await);
    }
    
    #[tokio::test]
    async fn test_session_callbacks() {
        let connection_id = ConnectionId(1);
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let reason = TerminationReason::NormalShutdown;
        let config = TerminationConfig::default();
        
        let termination = ConnectionTermination::new(
            connection_id,
            local_endpoint,
            remote_endpoint,
            reason,
            config,
        );
        
        // Add session callback
        termination.add_session_callback(|session_id| {
            println!("Terminating session: {}", session_id);
            Ok(())
        }).await;
        
        // Set active sessions
        termination.set_active_sessions(vec![SessionId(1), SessionId(2)]).await;
        
        // Test session cleanup
        termination.cleanup_sessions().await.unwrap();
        
        let context = termination.context.read().await;
        assert_eq!(context.terminated_sessions.len(), 2);
        assert_eq!(context.failed_sessions.len(), 0);
    }
    
    #[tokio::test]
    async fn test_state_transitions() {
        let connection_id = ConnectionId(1);
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let reason = TerminationReason::NormalShutdown;
        let config = TerminationConfig::default();
        
        let termination = ConnectionTermination::new(
            connection_id,
            local_endpoint,
            remote_endpoint,
            reason,
            config,
        );
        
        // Test state transitions
        termination.transition_to_state(TerminationState::Initiated).await.unwrap();
        assert_eq!(termination.current_state().await, TerminationState::Initiated);
        
        termination.transition_to_state(TerminationState::FinSent).await.unwrap();
        assert_eq!(termination.current_state().await, TerminationState::FinSent);
        
        termination.transition_to_state(TerminationState::Terminated).await.unwrap();
        assert_eq!(termination.current_state().await, TerminationState::Terminated);
        assert!(termination.is_complete().await);
        assert!(termination.is_successful().await);
    }
