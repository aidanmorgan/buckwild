use buckwild_common::protocol::enumeration_detection::*;
use std::net::Ipv4Addr;

    #[test]
    fn test_allowed_connection_attempt() {
        let detector = EnumerationDetector::new();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let result = detector.check_connection_attempt(
            source_ip,
            8080,
            Some(12345),
            None,
        ).unwrap();

        assert_eq!(result, EnumerationDetectionResult::Allowed);
    }

    #[test]
    fn test_rate_limiting() {
        let mut config = EnumerationConfig::default();
        config.max_attempts_per_window = 3;
        let detector = EnumerationDetector::with_config(config);
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 attempts should be allowed
        for _ in 0..3 {
            let result = detector.check_connection_attempt(source_ip, 8080, None, None).unwrap();
            assert_eq!(result, EnumerationDetectionResult::Allowed);
        }

        // 4th attempt should be rate limited
        let result = detector.check_connection_attempt(source_ip, 8080, None, None).unwrap();
        assert_eq!(result, EnumerationDetectionResult::RateLimited);
    }

    #[test]
    fn test_port_scanning_detection() {
        let detector = EnumerationDetector::new();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Simulate sequential port scanning
        for port in 8000..8025 {
            detector.check_connection_attempt(source_ip, port, None, None).unwrap();
        }

        // Next attempt should detect attack pattern
        let result = detector.check_connection_attempt(source_ip, 8025, None, None).unwrap();
        assert_eq!(result, EnumerationDetectionResult::AttackDetected);
    }

    #[test]
    fn test_block_expiration() {
        let mut config = EnumerationConfig::default();
        config.initial_block_duration_seconds = 1; // 1 second block
        let detector = EnumerationDetector::with_config(config);
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Trigger rate limiting
        detector.block_source(source_ip, BlockReason::RateLimitExceeded).unwrap();

        // Should be blocked initially
        let result1 = detector.check_blocked_source(source_ip).unwrap();
        assert!(result1.is_some());

        // Wait for block to expire
        std::thread::sleep(Duration::from_secs(2));

        // Should not be blocked after expiration
        let result2 = detector.check_blocked_source(source_ip).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn test_manual_unblock() {
        let detector = EnumerationDetector::new();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Block source
        detector.block_source(source_ip, BlockReason::ManualBlock).unwrap();

        // Verify blocked
        let result1 = detector.check_blocked_source(source_ip).unwrap();
        assert!(result1.is_some());

        // Unblock manually
        let was_blocked = detector.unblock_source(source_ip).unwrap();
        assert!(was_blocked);

        // Verify unblocked
        let result2 = detector.check_blocked_source(source_ip).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn test_cleanup() {
        let detector = EnumerationDetector::new();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Add some data
        detector.check_connection_attempt(source_ip, 8080, None, None).unwrap();
        detector.block_source(source_ip, BlockReason::RateLimitExceeded).unwrap();

        // Cleanup should not remove recent data
        let (blocks_removed, attempts_removed) = detector.cleanup_expired_entries().unwrap();
        assert_eq!(blocks_removed, 0);
        assert_eq!(attempts_removed, 0);
    }
