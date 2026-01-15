use buckwild_common::protocol::fragment_rate_limit::*;
#[test]
    fn test_token_bucket_creation() {
        let bucket = TokenBucket::new(100, 10);
        assert_eq!(bucket.current_tokens(), 100);
        assert_eq!(bucket.total_consumed(), 0);
    }
    
    #[test]
    fn test_token_bucket_consumption() {
        let bucket = TokenBucket::new(100, 10);
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Should be able to consume tokens
        assert!(bucket.try_consume(50, current_time));
        assert_eq!(bucket.current_tokens(), 50);
        assert_eq!(bucket.total_consumed(), 50);
        
        // Should not be able to consume more than available
        assert!(!bucket.try_consume(60, current_time));
        assert_eq!(bucket.current_tokens(), 50);
        assert_eq!(bucket.total_consumed(), 50);
    }
    
    #[test]
    fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(100, 10); // 10 tokens per second
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Consume all tokens
        assert!(bucket.try_consume(100, current_time));
        assert_eq!(bucket.current_tokens(), 0);
        
        // Wait 5 seconds and refill
        let future_time = current_time + 5;
        bucket.refill_tokens(future_time);
        assert_eq!(bucket.current_tokens(), 50); // 5 seconds * 10 tokens/second
    }
    
    #[test]
    fn test_sliding_window() {
        let window = SlidingWindow::new();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Add some counts
        window.add_count(5, current_time);
        window.add_count(3, current_time);
        assert_eq!(window.total_count(current_time), 8);
        
        // Advance time and check that old counts are cleared
        let future_time = current_time + 11; // Beyond window size
        assert_eq!(window.total_count(future_time), 0);
    }
    
    #[test]
    fn test_fragment_rate_limiter_creation() {
        let limiter = FragmentRateLimiter::new();
        let stats = limiter.get_rate_limit_stats();
        
        assert_eq!(stats.total_checks, 0);
        assert_eq!(stats.session_violations, 0);
        assert_eq!(stats.source_violations, 0);
        assert_eq!(stats.active_session_limiters, 0);
        assert_eq!(stats.active_source_limiters, 0);
    }
    
    #[test]
    fn test_session_rate_limiting() {
        let config = FragmentRateLimitConfig {
            fragments_per_second_per_session: 2,
            session_burst_capacity: 2,
            ..Default::default()
        };
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001; // 127.0.0.1
        
        let create_request = |fragment_id: u16| RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 1024,
            fragment_id,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First two requests should pass (burst capacity)
        assert_eq!(limiter.check_rate_limit(&create_request(1)), RateLimitResult::Allowed);
        assert_eq!(limiter.check_rate_limit(&create_request(2)), RateLimitResult::Allowed);
        
        // Third request should exceed rate limit
        assert_eq!(limiter.check_rate_limit(&create_request(3)), RateLimitResult::SessionRateLimitExceeded);
        
        let stats = limiter.get_rate_limit_stats();
        assert_eq!(stats.session_violations, 1);
    }
    
    #[test]
    fn test_source_rate_limiting() {
        let config = FragmentRateLimitConfig {
            packets_per_second_per_source: 2,
            source_packet_burst_capacity: 2,
            bytes_per_second_per_source: 2048,
            source_byte_burst_capacity: 2048,
            ..Default::default()
        };
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;
        
        let create_request = |fragment_id: u16| RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 1024,
            fragment_id,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First two requests should pass
        assert_eq!(limiter.check_rate_limit(&create_request(1)), RateLimitResult::Allowed);
        assert_eq!(limiter.check_rate_limit(&create_request(2)), RateLimitResult::Allowed);
        
        // Third request should exceed packet rate limit
        assert_eq!(limiter.check_rate_limit(&create_request(3)), RateLimitResult::SourceRateLimitExceeded);
        
        let stats = limiter.get_rate_limit_stats();
        assert_eq!(stats.source_violations, 1);
    }
    
    #[test]
    fn test_session_blocking() {
        let config = FragmentRateLimitConfig {
            fragments_per_second_per_session: 1,
            session_burst_capacity: 1,
            max_violations_before_block: 2,
            ..Default::default()
        };
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;
        
        let create_request = |fragment_id: u16| RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 1024,
            fragment_id,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // First request should pass
        assert_eq!(limiter.check_rate_limit(&create_request(1)), RateLimitResult::Allowed);
        
        // Next two requests should exceed rate limit
        assert_eq!(limiter.check_rate_limit(&create_request(2)), RateLimitResult::SessionRateLimitExceeded);
        assert_eq!(limiter.check_rate_limit(&create_request(3)), RateLimitResult::SessionBlocked);
        
        // Subsequent requests should be blocked
        assert_eq!(limiter.check_rate_limit(&create_request(4)), RateLimitResult::SessionBlocked);
        
        let stats = limiter.get_rate_limit_stats();
        assert_eq!(stats.blocked_sessions, 1);
    }
    
    #[test]
    fn test_emergency_block() {
        let config = FragmentRateLimitConfig {
            packets_per_second_per_source: 100,
            source_packet_burst_capacity: 100,
            emergency_block_threshold: 5,
            sliding_window_size_s: 10,
            ..Default::default()
        };
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;
        
        let create_request = |fragment_id: u16| RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 100,
            fragment_id,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // Send requests to trigger emergency block
        for i in 1..=6 {
            let result = limiter.check_rate_limit(&create_request(i));
            if i <= 5 {
                assert_eq!(result, RateLimitResult::Allowed);
            } else {
                assert_eq!(result, RateLimitResult::EmergencyBlock);
                break;
            }
        }
        
        let stats = limiter.get_rate_limit_stats();
        assert_eq!(stats.emergency_blocks, 1);
    }
    
    #[test]
    fn test_manual_unblocking() {
        let config = FragmentRateLimitConfig {
            fragments_per_second_per_session: 1,
            session_burst_capacity: 1,
            max_violations_before_block: 1,
            ..Default::default()
        };
        
        let limiter = FragmentRateLimiter::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let source_ip = 0x7F000001;
        
        let request = RateLimitRequest {
            session_id,
            source_ip,
            fragment_size: 1024,
            fragment_id: 1,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        // Trigger blocking
        assert_eq!(limiter.check_rate_limit(&request), RateLimitResult::Allowed);
        assert_eq!(limiter.check_rate_limit(&request), RateLimitResult::SessionBlocked);
        
        // Unblock session
        limiter.unblock_session(session_id);
        
        // Should be allowed again
        assert_eq!(limiter.check_rate_limit(&request), RateLimitResult::Allowed);
    }
