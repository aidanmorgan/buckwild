use buckwild_common::connection::coordinator::*;
use crate::connection::{Connection, ConnectionConfig};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    #[tokio::test]
    async fn test_coordinator_creation() {
        let connection_id = ConnectionId(1);
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000);
        
        let connection = Arc::new(Connection::new(
            connection_id,
            local_addr,
            remote_addr,
            ConnectionConfig::default(),
        ));
        
        let fragmentation_system = Arc::new(FragmentationSystem::new());
        
        let coordinator = ConnectionEngineCoordinator::new(
            connection_id,
            connection,
            fragmentation_system,
        );
        
        assert_eq!(coordinator.connection_id, connection_id);
        
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.packets_coordinated, 0);
        assert_eq!(stats.coordination_errors, 0);
    }
    
    #[tokio::test]
    async fn test_stats_tracking() {
        let connection_id = ConnectionId(1);
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000);
        
        let connection = Arc::new(Connection::new(
            connection_id,
            local_addr,
            remote_addr,
            ConnectionConfig::default(),
        ));
        
        let fragmentation_system = Arc::new(FragmentationSystem::new());
        
        let coordinator = ConnectionEngineCoordinator::new(
            connection_id,
            connection,
            fragmentation_system,
        );
        
        // Record an error
        coordinator.record_coordination_error().await;
        
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.coordination_errors, 1);
        
        // Reset stats
        coordinator.reset_stats().await;
        
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.coordination_errors, 0);
    }
