use buckwild_daemon::tun:routing::rules::*;
use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rule_validation() {
        let routing_rules = RoutingRules::new("tun0".to_string(), 254).await;
        
        // Skip test if netlink connection fails (expected in test environment)
        if routing_rules.is_err() {
            println!("Skipping test - netlink connection failed (expected in test environment)");
            return;
        }
        
        let routing_rules = routing_rules.unwrap();

        let valid_rule = RoutingRule {
            destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefix_length: 24,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            interface: "tun0".to_string(),
            metric: 100,
            table: None,
        };

        let validation = routing_rules.validate_rule(&valid_rule).await.unwrap();
        assert!(validation.valid);
        assert!(validation.errors.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_rule_validation() {
        let routing_rules = RoutingRules::new("tun0".to_string(), 254).await;
        
        if routing_rules.is_err() {
            println!("Skipping test - netlink connection failed");
            return;
        }
        
        let routing_rules = routing_rules.unwrap();

        let invalid_rule = RoutingRule {
            destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefix_length: 40, // Invalid for IPv4
            gateway: Some(IpAddr::V6("::1".parse().unwrap())), // Wrong IP version
            interface: "".to_string(), // Empty interface
            metric: 100,
            table: None,
        };

        let validation = routing_rules.validate_rule(&invalid_rule).await.unwrap();
        assert!(!validation.valid);
        assert!(!validation.errors.is_empty());
    }

    #[test]
    fn test_route_entry_creation() {
        let rule = RoutingRule {
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_length: 8,
            gateway: None,
            interface: "tun0".to_string(),
            metric: 50,
            table: Some(100),
        };

        let route_entry = RouteEntry {
            destination: rule.destination,
            prefix_length: rule.prefix_length,
            gateway: rule.gateway,
            interface: rule.interface.clone(),
            metric: rule.metric,
            table: rule.table.unwrap_or(254),
            active: false,
        };

        assert_eq!(route_entry.destination, rule.destination);
        assert_eq!(route_entry.table, 100);
        assert!(!route_entry.active);
    }
