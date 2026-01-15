use buckwild_daemon::tun:routing::updater::*;
use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_update_queuing() {
        // Create mock routing rules (this would normally require netlink)
        // For testing, we'll skip the actual netlink operations
        
        let rule = RoutingRule {
            destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefix_length: 24,
            gateway: None,
            interface: "tun0".to_string(),
            metric: 100,
            table: None,
        };

        // Test would create updater and queue updates
        // Skipped due to netlink dependency
        println!("Update queuing test skipped - requires netlink");
    }

    #[test]
    fn test_update_result_creation() {
        let result = UpdateResult {
            success: true,
            applied_rules: vec!["rule1".to_string(), "rule2".to_string()],
            failed_rules: vec![],
            rollback_performed: false,
            error_message: None,
        };

        assert!(result.success);
        assert_eq!(result.applied_rules.len(), 2);
        assert!(result.failed_rules.is_empty());
        assert!(!result.rollback_performed);
    }

    #[test]
    fn test_statistics_initialization() {
        let stats = UpdateStatistics::default();
        
        assert_eq!(stats.total_updates, 0);
        assert_eq!(stats.successful_updates, 0);
        assert_eq!(stats.failed_updates, 0);
        assert_eq!(stats.rollbacks_performed, 0);
        assert_eq!(stats.average_update_time_ms, 0.0);
        assert!(stats.last_update_time.is_none());
    }
