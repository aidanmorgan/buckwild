use buckwild_common::connection::establishment::*;
use crate::types::ConnectionId;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_establishment_creation() {
        let connection_id = ConnectionId(1);
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let config = EstablishmentConfig::default();
        
        let establishment = ConnectionEstablishment::new(
            connection_id,
            local_endpoint,
            remote_endpoint,
            config,
        );
        
        assert_eq!(establishment.current_state().await, EstablishmentState::Initial);
        assert!(!establishment.is_complete().await);
        assert!(!establishment.is_successful().await);
    }
    
    #[tokio::test]
    async fn test_key_generation() {
        let connection_id = ConnectionId(1);
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let config = EstablishmentConfig::default();
        
        let establishment = ConnectionEstablishment::new(
            connection_id,
            local_endpoint,
            remote_endpoint,
            config,
        );
        
        // Generate key pair
        establishment.generate_local_keypair().await.unwrap();
        
        // Verify key pair was generated
        let context = establishment.context.read().await;
        assert!(context.local_keypair.is_some());
    }
    
    #[tokio::test]
    async fn test_state_transitions() {
        let connection_id = ConnectionId(1);
        let local_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let config = EstablishmentConfig::default();
        
        let establishment = ConnectionEstablishment::new(
            connection_id,
            local_endpoint,
            remote_endpoint,
            config,
        );
        
        // Test state transitions
        establishment.transition_to_state(EstablishmentState::SynSent).await.unwrap();
        assert_eq!(establishment.current_state().await, EstablishmentState::SynSent);
        
        establishment.transition_to_state(EstablishmentState::KeyExchange).await.unwrap();
        assert_eq!(establishment.current_state().await, EstablishmentState::KeyExchange);
        
        establishment.transition_to_state(EstablishmentState::Established).await.unwrap();
        assert_eq!(establishment.current_state().await, EstablishmentState::Established);
        assert!(establishment.is_complete().await);
        assert!(establishment.is_successful().await);
    }
