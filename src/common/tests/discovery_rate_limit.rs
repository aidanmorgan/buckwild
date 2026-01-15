// Simplified tests for discovery rate limiting
//
// These tests verify rate limiting works independently of the full discovery stack.

use buckwild_common::engines::discovery::{DiscoveryRateLimiter, RateLimitConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[test]
fn test_discovery_rate_limit() {
    let limiter = DiscoveryRateLimiter::new();
    let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // Should allow 5 requests
    for _ in 0..5 {
        assert!(limiter.check_rate_limit(source_ip).is_ok());
    }

    // 6th should fail
    assert!(limiter.check_rate_limit(source_ip).is_err());
}

#[test]
fn test_rate_limit_per_ip() {
    let limiter = DiscoveryRateLimiter::new();
    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // Exhaust IP1
    for _ in 0..5 {
        limiter.check_rate_limit(ip1).ok();
    }
    assert!(limiter.check_rate_limit(ip1).is_err());

    // IP2 should work
    assert!(limiter.check_rate_limit(ip2).is_ok());
}

#[test]
fn test_rate_limit_blocks_abusive_ip() {
    let config = RateLimitConfig {
        max_attempts_per_minute: 3,
        block_duration: Duration::from_millis(100),
        cleanup_interval: Duration::from_secs(60),
    };
    let limiter = DiscoveryRateLimiter::with_config(config);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Exhaust
    for _ in 0..3 {
        limiter.check_rate_limit(ip).ok();
    }
    assert!(limiter.check_rate_limit(ip).is_err());

    // Should be blocked
    assert!(limiter.is_blocked(&ip));

    // Wait for unblock
    std::thread::sleep(Duration::from_millis(150));
    assert!(!limiter.is_blocked(&ip));
}
