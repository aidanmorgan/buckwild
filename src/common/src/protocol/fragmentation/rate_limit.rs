// Fragment rate limiting
//
// This module provides rate limiting for fragment processing to prevent
// fragment flood attacks and ensure fair resource usage.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

// Import ALL types from the authoritative consolidated types module
use crate::protocol::types::*;

/// Fragment rate limiter
pub struct FragmentRateLimiter {
    /// Per-session rate limiters
    session_limiters: Arc<RwLock<HashMap<SessionId, SessionRateLimiter>>>,
    /// Per-source IP rate limiters
    source_limiters: Arc<RwLock<HashMap<IpAddress, SourceRateLimiter>>>,
    /// Configuration
    config: RateLimitConfig,
    /// Statistics
    stats: Arc<RwLock<FragmentRateLimitStats>>,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Fragments per second per session
    pub fragments_per_second_per_session: PacketRate,
    /// Burst capacity for session fragments
    pub session_burst_capacity: Capacity,
    /// Packets per second per source IP
    pub packets_per_second_per_source: PacketRate,
    /// Burst capacity for source packets
    pub source_burst_capacity: Capacity,
    /// Cleanup interval in seconds
    pub cleanup_interval_sec: ProtocolDuration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            fragments_per_second_per_session: PacketRate::new(20),
            session_burst_capacity: Capacity::from_raw(50),
            packets_per_second_per_source: PacketRate::new(100),
            source_burst_capacity: Capacity::from_raw(200),
            cleanup_interval_sec: ProtocolDuration::from_nanos(60 * 1_000_000_000),
        }
    }
}

/// Per-session rate limiter
#[derive(Debug)]
struct SessionRateLimiter {
    /// Token bucket for rate limiting
    token_bucket: TokenBucket,
    /// Last activity timestamp
    last_activity: SystemTime,
    /// Total fragments processed
    fragment_count: PacketCount,
    /// Violations count
    violations: ViolationCount,
}

/// Per-source IP rate limiter
#[derive(Debug)]
struct SourceRateLimiter {
    /// Token bucket for packet rate limiting
    packet_bucket: TokenBucket,
    /// Token bucket for byte rate limiting
    byte_bucket: TokenBucket,
    /// Last activity timestamp
    last_activity: SystemTime,
    /// Violations count
    violations: ViolationCount,
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Current tokens
    tokens: TokenCount,
    /// Maximum capacity
    capacity: TokenCapacity,
    /// Refill rate (tokens per second)
    refill_rate: RefillRate,
    /// Last refill time
    last_refill: SystemTime,
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            tokens: TokenCount::new(capacity as f64),
            capacity: TokenCapacity::new(capacity as f64),
            refill_rate: RefillRate::new(refill_rate as f64),
            last_refill: SystemTime::now(),
        }
    }

    /// Try to consume tokens
    fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();

        let tokens_needed = tokens as f64;
        if self.tokens.has_tokens(tokens_needed) {
            self.tokens.consume(tokens_needed);
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = SystemTime::now();
        let elapsed = now.duration_since(self.last_refill).unwrap_or_default();
        let tokens_to_add = elapsed.as_secs_f64() * self.refill_rate.as_f64();

        self.tokens.add(tokens_to_add);
        let capped_tokens = self.capacity.cap(self.tokens.as_f64());
        self.tokens = TokenCount::new(capped_tokens);
        self.last_refill = now;
    }

    /// Get current token count
    #[allow(dead_code)]
    fn current_tokens(&self) -> u32 {
        self.tokens.as_f64() as u32
    }
}

/// Rate limit request
#[derive(Debug)]
pub struct RateLimitRequest {
    /// Session ID
    pub session_id: SessionId,
    /// Source IP address
    pub source_ip: IpAddress,
    /// Fragment size in bytes
    pub fragment_size: PacketSize,
    /// Fragment ID
    pub fragment_id: FragmentId,
    /// Request timestamp
    pub timestamp: SystemTime,
}

/// Rate limit violation
#[derive(Debug, Clone)]
pub struct RateLimitViolation {
    /// Violation type
    pub violation_type: ViolationType,
    /// Session ID
    pub session_id: SessionId,
    /// Source IP
    pub source_ip: IpAddress,
    /// Current rate
    pub current_rate: PacketRate,
    /// Rate limit
    pub rate_limit: PacketRate,
    /// Suggested retry after duration
    pub retry_after: Duration,
}

/// Types of rate limit violations
#[derive(Debug, Clone)]
pub enum ViolationType {
    /// Session fragment rate exceeded
    SessionFragmentRate,
    /// Source packet rate exceeded
    SourcePacketRate,
    /// Source byte rate exceeded
    SourceByteRate,
}

/// Fragment rate limiting statistics
#[derive(Debug, Clone)]
pub struct FragmentRateLimitStats {
    /// Total rate limit checks
    pub total_checks: PacketCount,
    /// Session violations
    pub session_violations: ViolationCount,
    /// Source violations
    pub source_violations: ViolationCount,
    /// Active session limiters
    pub active_session_limiters: Capacity,
    /// Active source limiters
    pub active_source_limiters: Capacity,
}

impl FragmentRateLimiter {
    /// Create a new fragment rate limiter
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a new fragment rate limiter with custom configuration
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            session_limiters: Arc::new(RwLock::new(HashMap::new())),
            source_limiters: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(FragmentRateLimitStats {
                total_checks: PacketCount::new(0),
                session_violations: ViolationCount::new(0),
                source_violations: ViolationCount::new(0),
                active_session_limiters: Capacity::new(0),
                active_source_limiters: Capacity::new(0),
            })),
        }
    }

    /// Check rate limits for a fragment request
    pub fn check_rate_limit(&self, request: &RateLimitRequest) -> Option<RateLimitViolation> {
        // Update statistics
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.total_checks += 1;
        }

        // Check session rate limit
        if let Some(violation) = self.check_session_rate_limit(request) {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.session_violations.increment();
            return Some(violation);
        }

        // Check source IP rate limit
        if let Some(violation) = self.check_source_rate_limit(request) {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.source_violations.increment();
            return Some(violation);
        }

        None
    }

    /// Check session-specific rate limit
    fn check_session_rate_limit(&self, request: &RateLimitRequest) -> Option<RateLimitViolation> {
        let mut session_limiters = self
            .session_limiters
            .write()
            .unwrap_or_else(|e| e.into_inner());

        let session_limiter = session_limiters
            .entry(request.session_id.clone())
            .or_insert_with(|| SessionRateLimiter {
                token_bucket: TokenBucket::new(
                    self.config.session_burst_capacity.as_u32(),
                    self.config.fragments_per_second_per_session.as_u32(),
                ),
                last_activity: SystemTime::now(),
                fragment_count: PacketCount::new(0),
                violations: ViolationCount::new(0),
            });

        // Try to consume a token for this fragment
        if !session_limiter.token_bucket.try_consume(1) {
            session_limiter.violations.increment();

            return Some(RateLimitViolation {
                violation_type: ViolationType::SessionFragmentRate,
                session_id: request.session_id.clone(),
                source_ip: request.source_ip,
                current_rate: PacketRate::new(
                    self.config.fragments_per_second_per_session.as_u32() + 1,
                ),
                rate_limit: self.config.fragments_per_second_per_session,
                retry_after: Duration::from_secs(1),
            });
        }

        // Update session state
        session_limiter.last_activity = request.timestamp;
        session_limiter
            .fragment_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        None
    }

    /// Check source IP rate limit
    fn check_source_rate_limit(&self, request: &RateLimitRequest) -> Option<RateLimitViolation> {
        let mut source_limiters = self
            .source_limiters
            .write()
            .unwrap_or_else(|e| e.into_inner());

        let source_limiter = source_limiters.entry(request.source_ip).or_insert_with(|| {
            SourceRateLimiter {
                packet_bucket: TokenBucket::new(
                    self.config.source_burst_capacity.as_u32(),
                    self.config.packets_per_second_per_source.as_u32(),
                ),
                byte_bucket: TokenBucket::new(
                    self.config.source_burst_capacity.as_u32() * 1400, // Assume MTU-sized packets
                    self.config.packets_per_second_per_source.as_u32() * 1400,
                ),
                last_activity: SystemTime::now(),
                violations: ViolationCount::new(0),
            }
        });

        // Check packet rate limit
        if !source_limiter.packet_bucket.try_consume(1) {
            source_limiter.violations.increment();

            return Some(RateLimitViolation {
                violation_type: ViolationType::SourcePacketRate,
                session_id: request.session_id.clone(),
                source_ip: request.source_ip,
                current_rate: PacketRate::new(
                    self.config.packets_per_second_per_source.as_u32() + 1,
                ),
                rate_limit: self.config.packets_per_second_per_source,
                retry_after: Duration::from_secs(1),
            });
        }

        // Check byte rate limit
        if !source_limiter
            .byte_bucket
            .try_consume(request.fragment_size.as_u16() as u32)
        {
            source_limiter.violations.increment();

            return Some(RateLimitViolation {
                violation_type: ViolationType::SourceByteRate,
                session_id: request.session_id.clone(),
                source_ip: request.source_ip,
                current_rate: PacketRate::new(self.config.packets_per_second_per_source.as_u32()),
                rate_limit: self.config.packets_per_second_per_source,
                retry_after: Duration::from_secs(1),
            });
        }

        // Update source state
        source_limiter.last_activity = request.timestamp;

        None
    }

    /// Clean up expired rate limiters
    pub fn cleanup_expired_limiters(&self) {
        let cleanup_timeout = Duration::from_secs(self.config.cleanup_interval_sec.as_u64());
        let now = SystemTime::now();

        // Clean up session limiters
        {
            let mut session_limiters = self
                .session_limiters
                .write()
                .unwrap_or_else(|e| e.into_inner());
            session_limiters.retain(|_, limiter| {
                now.duration_since(limiter.last_activity)
                    .unwrap_or_default()
                    < cleanup_timeout
            });
        }

        // Clean up source limiters
        {
            let mut source_limiters = self
                .source_limiters
                .write()
                .unwrap_or_else(|e| e.into_inner());
            source_limiters.retain(|_, limiter| {
                now.duration_since(limiter.last_activity)
                    .unwrap_or_default()
                    < cleanup_timeout
            });
        }

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.active_session_limiters = Capacity::new(
                self.session_limiters
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .len() as u32,
            );
            stats.active_source_limiters = Capacity::new(
                self.source_limiters
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .len() as u32,
            );
        }
    }

    /// Get rate limiting statistics
    pub fn get_rate_limit_stats(&self) -> FragmentRateLimitStats {
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.active_session_limiters = Capacity::new(
            self.session_limiters
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .len() as u32,
        );
        stats.active_source_limiters = Capacity::new(
            self.source_limiters
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .len() as u32,
        );
        stats.clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.total_checks = PacketCount::new(0);
        stats.session_violations = ViolationCount::new(0);
        stats.source_violations = ViolationCount::new(0);
        // Keep active limiter counts
    }

    /// Update configuration
    pub fn update_config(&mut self, config: RateLimitConfig) {
        self.config = config;
    }
}

impl Default for FragmentRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
