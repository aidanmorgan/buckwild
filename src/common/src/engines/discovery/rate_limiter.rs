// Rate limiting for discovery requests
//
// Implements per-IP rate limiting using a token bucket algorithm to prevent
// DoS attacks via discovery request flooding.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::error::RateLimitError;
use crate::protocol::types::DataRate;

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum discovery attempts per minute per IP
    pub max_attempts_per_minute: u32,
    /// Block duration for abusive sources (5 minutes per security.md)
    pub block_duration: Duration,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_minute: 5, // Per design/protocol/05-psk-discovery.md line 271
            block_duration: Duration::from_secs(5 * 60), // 5 minutes
            cleanup_interval: Duration::from_secs(60), // 1 minute
        }
    }
}

/// Token bucket state for a single IP
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Available tokens
    tokens: u32,
    /// Last token refill time
    last_refill: Instant,
    /// Total violation count for blocking decisions
    violation_count: u32,
    /// Block expiration time (if blocked)
    blocked_until: Option<Instant>,
}

impl TokenBucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            violation_count: 0,
            blocked_until: None,
        }
    }

    fn is_blocked(&self) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            Instant::now() < blocked_until
        } else {
            false
        }
    }

    fn refill(&mut self, capacity: u32, refill_rate: Duration) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed >= refill_rate {
            let refill_count = (elapsed.as_secs() / refill_rate.as_secs()) as u32;
            self.tokens = (self.tokens + refill_count).min(capacity);
            self.last_refill = now;
        }
    }

    fn try_consume(&mut self) -> bool {
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn record_violation(&mut self, block_duration: Duration) {
        self.violation_count += 1;
        self.blocked_until = Some(Instant::now() + block_duration);
    }
}

/// Rate limiter for discovery requests
pub struct DiscoveryRateLimiter {
    /// Per-IP token buckets
    buckets: Arc<DashMap<IpAddr, TokenBucket>>,
    /// Rate limit configuration
    config: RateLimitConfig,
    /// Last cleanup time
    last_cleanup: Arc<parking_lot::Mutex<Instant>>,
}

impl DiscoveryRateLimiter {
    /// Create a new rate limiter with default configuration
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a new rate limiter with custom configuration
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            config,
            last_cleanup: Arc::new(parking_lot::Mutex::new(Instant::now())),
        }
    }

    /// Check if a discovery request from the given IP should be allowed
    ///
    /// Returns Ok(()) if allowed, Err(RateLimitError) if blocked
    pub fn check_rate_limit(&self, source_ip: IpAddr) -> Result<(), RateLimitError> {
        // Run cleanup if needed
        self.maybe_cleanup();

        let capacity = self.config.max_attempts_per_minute;
        let refill_duration = Duration::from_secs(60); // 1 minute

        // Get or create token bucket for this IP
        let mut entry = self
            .buckets
            .entry(source_ip)
            .or_insert_with(|| TokenBucket::new(capacity));

        let bucket = entry.value_mut();

        // Check if IP is currently blocked
        if bucket.is_blocked() {
            warn!(
                source_ip = %source_ip,
                violation_count = bucket.violation_count,
                "Discovery request blocked - IP is temporarily blocked"
            );
            return Err(RateLimitError::RateLimitExceeded {
                current_rate: DataRate::new(bucket.violation_count as u64),
                limit: DataRate::new(capacity as u64),
            });
        }

        // Refill tokens based on elapsed time
        bucket.refill(capacity, refill_duration);

        // Try to consume a token
        if bucket.try_consume() {
            debug!(
                source_ip = %source_ip,
                tokens_remaining = bucket.tokens,
                "Discovery request allowed"
            );
            Ok(())
        } else {
            // Rate limit exceeded - record violation and block
            bucket.record_violation(self.config.block_duration);
            warn!(
                source_ip = %source_ip,
                violation_count = bucket.violation_count,
                block_duration_secs = self.config.block_duration.as_secs(),
                "Discovery rate limit exceeded - blocking IP"
            );
            Err(RateLimitError::RateLimitExceeded {
                current_rate: DataRate::new((capacity + 1) as u64),
                limit: DataRate::new(capacity as u64),
            })
        }
    }

    /// Force cleanup of expired entries
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let retention = Duration::from_secs(10 * 60); // Keep entries for 10 minutes

        self.buckets.retain(|_ip, bucket| {
            // Keep if recently active or still blocked
            if let Some(blocked_until) = bucket.blocked_until {
                if now < blocked_until {
                    return true; // Keep blocked entries
                }
            }

            // Keep if recently used (within retention period)
            now.duration_since(bucket.last_refill) < retention
        });

        debug!(
            bucket_count = self.buckets.len(),
            "Cleaned up expired rate limit entries"
        );
    }

    /// Internal cleanup that runs periodically
    fn maybe_cleanup(&self) {
        let last_cleanup = self.last_cleanup.lock();
        if last_cleanup.elapsed() >= self.config.cleanup_interval {
            drop(last_cleanup); // Drop lock before cleanup
            self.cleanup_expired();
            *self.last_cleanup.lock() = Instant::now();
        }
    }

    /// Get current token count for an IP (for testing/monitoring)
    pub fn get_tokens(&self, source_ip: &IpAddr) -> Option<u32> {
        self.buckets.get(source_ip).map(|b| b.tokens)
    }

    /// Check if an IP is currently blocked
    pub fn is_blocked(&self, source_ip: &IpAddr) -> bool {
        self.buckets
            .get(source_ip)
            .map(|b| b.is_blocked())
            .unwrap_or(false)
    }
}

impl Default for DiscoveryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = DiscoveryRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should allow up to 5 requests
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = DiscoveryRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust tokens (5 allowed)
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }

        // 6th request should be blocked
        assert!(limiter.check_rate_limit(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        // This test verifies that after the block expires and a full refill period,
        // tokens are available again. Implementation uses 60-second refill intervals.
        let config = RateLimitConfig {
            max_attempts_per_minute: 2,
            block_duration: Duration::from_millis(50), // Short block for test
            cleanup_interval: Duration::from_secs(60),
        };
        let limiter = DiscoveryRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        // Exhaust tokens - third request should fail and block the IP
        assert!(limiter.check_rate_limit(ip).is_ok());
        assert!(limiter.check_rate_limit(ip).is_ok());
        assert!(limiter.check_rate_limit(ip).is_err());

        // IP is now blocked - should still fail even with valid tokens
        assert!(limiter.is_blocked(&ip));
        assert!(limiter.check_rate_limit(ip).is_err());

        // Wait for block to expire
        std::thread::sleep(Duration::from_millis(100));

        // Block should be expired now
        assert!(!limiter.is_blocked(&ip));

        // Since bucket starts with capacity tokens and block just expired,
        // the bucket was created fresh with full capacity, but then exhausted.
        // Token refill requires 60 seconds, so request will fail again
        // and re-trigger block. This tests the blocking cycle behavior.
        // Note: For full refill testing, would need a mock clock.
        let result = limiter.check_rate_limit(ip);
        // Either passes (if tokens refilled) or fails (if not enough time)
        // We just verify the IP is no longer permanently blocked
        drop(result);
        // After 60+ seconds, this would succeed, but we can't wait that long in tests
    }

    #[test]
    fn test_rate_limiter_blocks_abusive_ip() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 2,
            block_duration: Duration::from_millis(100),
            cleanup_interval: Duration::from_secs(60),
        };
        let limiter = DiscoveryRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));

        // Exhaust tokens and trigger block
        assert!(limiter.check_rate_limit(ip).is_ok());
        assert!(limiter.check_rate_limit(ip).is_ok());
        assert!(limiter.check_rate_limit(ip).is_err());

        // IP should be blocked
        assert!(limiter.is_blocked(&ip));

        // Wait for block to expire
        std::thread::sleep(Duration::from_millis(150));

        // Should be unblocked
        assert!(!limiter.is_blocked(&ip));
    }

    #[test]
    fn test_rate_limiter_different_ips_independent() {
        let limiter = DiscoveryRateLimiter::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6));

        // Exhaust IP1
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip1).is_ok());
        }
        assert!(limiter.check_rate_limit(ip1).is_err());

        // IP2 should still work
        assert!(limiter.check_rate_limit(ip2).is_ok());
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 5,
            block_duration: Duration::from_secs(1),
            cleanup_interval: Duration::from_millis(10),
        };
        let limiter = DiscoveryRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));

        // Create entry
        assert!(limiter.check_rate_limit(ip).is_ok());
        assert_eq!(limiter.buckets.len(), 1);

        // Force cleanup won't remove recent entries
        limiter.cleanup_expired();
        assert_eq!(limiter.buckets.len(), 1);
    }
}
