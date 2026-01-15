use buckwild_daemon::tun:routing::manager::*;
use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[tokio::test]
    #[ignore] // Requires root privileges
    async fn test_routing_manager() {
        // Create manager
        let manager = RoutingManager::new("tun0").await.unwrap();
        
        // Create test route
        let route = Route {
            destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            prefix_len: 32,
            gateway: None,
            interface: "tun0".to_string(),
            metric: 100,
        };
        
        // Add route
        manager.add_route(&route).await.unwrap();
        
        // Check route count
        assert_eq!(manager.route_count().await, 1);
        
        // Remove route
        manager.remove_route(&route).await.unwrap();
        
        // Check route count
        assert_eq!(manager.route_count().await, 0);
    }
    
    #[tokio::test]
    #[ignore] // Requires root privileges
    async fn test_update_from_config() {
        // Create manager
        let manager = RoutingManager::new("tun0").await.unwrap();
        
        // Create test config
        let mut config = HostsConfig::default();
        
        // Add hosts
        use crate::config::hosts::parser::Host;
        
        config.hosts.push(Host {
            ip: "192.168.1.100".to_string(),
            psk_fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            description: Some("Test Host 1".to_string()),
            port_range: None,
            hmac_policy: None,
            priority: 100,
        });
        
        config.hosts.push(Host {
            ip: "192.168.1.101".to_string(),
            psk_fingerprint: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            description: Some("Test Host 2".to_string()),
            port_range: None,
            hmac_policy: None,
            priority: 100,
        });
        
        // Update routes
        manager.update_from_config(&config).await.unwrap();
        
        // Check route count
        assert_eq!(manager.route_count().await, 2);
        
        // Clear routes
        manager.clear_routes().await.unwrap();
        
        // Check route count
        assert_eq!(manager.route_count().await, 0);
    }
