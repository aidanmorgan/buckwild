use buckwild_common::protocol:fragmentation::rate_limit::*;
use crate::protocol::packet::SessionId;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = FragmentRateLimiter::new();
        let stats = limiter.get_rate_limit_stats();
        assert_eq!(stats.total_checks, 0);
        assert_eq!(stats.session_violations, 0);
        assert_eq!(stats.source_violations, 0);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 5); // 10 capacity, 5 tokens/sec
        
        // Should be able to consume initial tokens
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(5));
        
        // Should not be able to consume more
        assert!(!bucket.try_consume(1));
        
        // Wait and refill
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(bucket.try_consume(5)); // Should have refilled
    }

    #[test]
    fn test_session_rate_limiting() {
        let mut config = RateLimitConfig::default();
        config.fragments_per_second_per_session = 2;
        config.session_burst_capacity = 2;
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001; // 127.0.0.1

        // First two requests should pass
        for i in 0..2 {
            let request = RateLimitRequest {
                session_id,
                source_ip,
                fragment_size: 100,
                fragment_id: i,
                timestamp: SystemTime::now(),
            };
            
            assert!(limiter.check_rate_limit(&request).is_none());
        }

        // Third request should be rate limited
        let request = RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 100,
            fragment_id: 2,
            timestamp: SystemTime::now(),
        };
        
        let violation = limiter.check_rate_limit(&request);
        assert!(violation.is_some());
        
        let violation = violation.unwrap();
        assert!(matches!(violation.violation_type, ViolationType::SessionFragmentRate));
        assert_eq!(violation.session_id, session_id);

        let stats = limiter.get_rate_limit_stats();
        assert_eq!(stats.session_violations, 1);
    }

    #[test]
    fn test_source_rate_limiting() {
        let mut config = RateLimitConfig::default();
        config.packets_per_second_per_source = 2;
        config.source_burst_capacity = 2;
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;

        // First two requests should pass
        for i in 0..2 {
            let request = RateLimitRequest {
                session_id,
                source_ip,
                fragment_size: 100,
                fragment_id: i,
                timestamp: SystemTime::now(),
            };
            
            assert!(limiter.check_rate_limit(&request).is_none());
        }

        // Third request should be rate limited
        let request = RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 100,
            fragment_id: 2,
            timestamp: SystemTime::now(),
        };
        
        let violation = limiter.check_rate_limit(&request);
        assert!(violation.is_some());
        
        let violation = violation.unwrap();
        assert!(matches!(violation.violation_type, ViolationType::SourcePacketRate));

        let stats = limiter.get_rate_limit_stats();
        assert_eq!(stats.source_violations, 1);
    }

    #[test]
    fn test_cleanup_expired_limiters() {
        let mut config = RateLimitConfig::default();
        config.cleanup_interval_sec = 1; // Very short timeout
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;

        let request = RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 100,
            fragment_id: 0,
            timestamp: SystemTime::now(),
        };

        // Make a request to create limiters
        let _ = limiter.check_rate_limit(&request);
        
        let stats_before = limiter.get_rate_limit_stats();
        assert_eq!(stats_before.active_session_limiters, 1);
        assert_eq!(stats_before.active_source_limiters, 1);

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Cleanup
        limiter.cleanup_expired_limiters();

        let stats_after = limiter.get_rate_limit_stats();
        assert_eq!(stats_after.active_session_limiters, 0);
        assert_eq!(stats_after.active_source_limiters, 0);
    }

    #[test]
    fn test_byte_rate_limiting() {
        let mut config = RateLimitConfig::default();
        config.packets_per_second_per_source = 100; // High packet limit
        config.source_burst_capacity = 1; // Low burst capacity for bytes
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;

        // Large fragment that should trigger byte rate limit
        let request = RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 10000, // Very large fragment
            fragment_id: 0,
            timestamp: SystemTime::now(),
        };

        let violation = limiter.check_rate_limit(&request);
        if let Some(violation) = violation {
            assert!(matches!(violation.violation_type, ViolationType::SourceByteRate));
        }
    }

    #[test]
    fn test_statistics_reset() {
        let limiter = FragmentRateLimiter::new();
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;

        let request = RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 100,
            fragment_id: 0,
            timestamp: SystemTime::now(),
        };

        // Generate some statistics
        let _ = limiter.check_rate_limit(&request);
        
        let stats_before = limiter.get_rate_limit_stats();
        assert_eq!(stats_before.total_checks, 1);

        // Reset statistics
        limiter.reset_stats();

        let stats_after = limiter.get_rate_limit_stats();
        assert_eq!(stats_after.total_checks, 0);
    }
