// Timestamp validation for anti-replay protection
//
// This module provides timestamp validation utilities to prevent
// replay attacks using time-based validation.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::error::SecurityError;
use crate::protocol::types::*;
use std::time::{SystemTime, UNIX_EPOCH};

/// Result type for timestamp validation operations
pub type TimestampResult<T> = Result<T, SecurityError>;

/// Timestamp validation configuration
#[derive(Debug, Clone)]
pub struct TimestampValidationConfig {
    /// Maximum allowed clock drift in seconds
    pub max_drift: TimeDriftTolerance,

    /// Maximum packet age in seconds
    pub max_age: TimeDriftTolerance,

    /// Enable strict monotonic timestamp checking
    pub strict_monotonic: SecurityFlag,

    /// Tolerance for timestamp regression in seconds
    pub regression_tolerance: TimeDriftTolerance,
}

impl Default for TimestampValidationConfig {
    fn default() -> Self {
        Self {
            max_drift: TimeDriftTolerance::new(30),
            max_age: TimeDriftTolerance::new(300),
            strict_monotonic: SecurityFlag::new(false),
            regression_tolerance: TimeDriftTolerance::new(5),
        }
    }
}

/// Timestamp validator
pub struct TimestampValidator {
    /// Configuration
    config: TimestampValidationConfig,
}

impl TimestampValidator {
    /// Create a new timestamp validator with default config
    pub fn new() -> Self {
        Self {
            config: TimestampValidationConfig::default(),
        }
    }
}

impl Default for TimestampValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl TimestampValidator {
    /// Create a new timestamp validator with custom config
    pub fn with_config(config: TimestampValidationConfig) -> Self {
        Self { config }
    }

    /// Validate packet timestamp according to design/protocol/14-replay-protection.md
    pub fn validate(&self, header: &crate::protocol::packet::PacketHeader) -> TimestampResult<()> {
        let packet_timestamp = header.timestamp();
        let current_time_ms = Timestamp::now();

        // Calculate time difference
        let time_diff = if packet_timestamp > current_time_ms {
            // Future timestamp
            -(packet_timestamp.wrapping_sub(current_time_ms).as_u64() as i64)
        } else {
            // Past timestamp
            current_time_ms.wrapping_sub(packet_timestamp).as_u64() as i64
        };

        // Check if handshake packet (stricter window: 10s instead of 30s)
        // Note: timestamps are in nanoseconds, so convert seconds to nanoseconds
        let window_ns = if header.packet_type() == PacketType::Syn
            || header.packet_type() == PacketType::SynAck
        {
            10_000_000_000i64 // Handshake: 10 seconds in nanoseconds
        } else {
            30_000_000_000i64 // Normal: 30 seconds in nanoseconds
        };

        // Reject if timestamp is too old
        if time_diff > window_ns {
            return Err(SecurityError::timestamp_too_old());
        }

        // Reject if timestamp is far in the future (>50ms clock skew tolerance)
        if time_diff < -50_000_000 {
            // 50ms in nanoseconds
            return Err(SecurityError::timestamp_invalid());
        }

        Ok(())
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new()
    }

    /// Validate a timestamp against current time
    pub fn validate_timestamp(&self, timestamp: Timestamp) -> TimestampResult<()> {
        let now = SystemTime::now();
        let packet_time = UNIX_EPOCH + std::time::Duration::from_nanos(timestamp.as_nanos());

        // Check if packet is too old
        if let Ok(age) = now.duration_since(packet_time) {
            if age.as_secs() > self.config.max_age.as_u64() {
                return Err(SecurityError::timestamp_validation_failed(
                    timestamp,
                    self.config.max_age.as_u64() * 1_000_000_000, // Convert to nanoseconds
                ));
            }
        }

        // Check if packet is too far in the future
        if let Ok(drift) = packet_time.duration_since(now) {
            if drift.as_secs() > self.config.max_drift.as_u64() {
                return Err(SecurityError::timestamp_validation_failed(
                    timestamp,
                    self.config.max_drift.as_u64() * 1_000_000_000, // Convert to nanoseconds
                ));
            }
        }

        Ok(())
    }

    /// Validate timestamp against a previous timestamp
    pub fn validate_against_previous(
        &self,
        timestamp: Timestamp,
        previous: Timestamp,
    ) -> TimestampResult<()> {
        let current_time = UNIX_EPOCH + std::time::Duration::from_nanos(timestamp.as_nanos());
        let previous_time = UNIX_EPOCH + std::time::Duration::from_nanos(previous.as_nanos());

        // Check for timestamp regression
        if current_time < previous_time {
            let regression = previous_time
                .duration_since(current_time)
                .unwrap_or(std::time::Duration::ZERO);

            if self.config.strict_monotonic.as_bool()
                || regression.as_secs() > self.config.regression_tolerance.as_nanos()
            {
                return Err(SecurityError::timestamp_validation_failed(
                    timestamp,
                    self.config.regression_tolerance.as_u64() * 1_000_000_000,
                ));
            }
        }

        Ok(())
    }

    /// Check if a timestamp is within acceptable bounds
    pub fn is_timestamp_valid(&self, timestamp: Timestamp) -> bool {
        self.validate_timestamp(timestamp).is_ok()
    }

    /// Get the current timestamp
    pub fn current_timestamp() -> Timestamp {
        Timestamp::now()
    }

    /// Calculate timestamp difference in nanoseconds
    pub fn timestamp_diff(ts1: Timestamp, ts2: Timestamp) -> i64 {
        (ts1.as_nanos() as i64) - (ts2.as_nanos() as i64)
    }

    /// Check if timestamp is within drift tolerance
    pub fn is_within_drift(&self, timestamp: Timestamp) -> bool {
        let now = SystemTime::now();
        let packet_time = UNIX_EPOCH + std::time::Duration::from_nanos(timestamp.as_nanos());

        // Check both directions
        if let Ok(age) = now.duration_since(packet_time) {
            age.as_secs() <= self.config.max_drift.as_u64()
        } else if let Ok(drift) = packet_time.duration_since(now) {
            drift.as_secs() <= self.config.max_drift.as_u64()
        } else {
            false
        }
    }

    /// Update configuration
    pub fn update_config(&mut self, config: TimestampValidationConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &TimestampValidationConfig {
        &self.config
    }
}

/// Timestamp window for tracking valid timestamp ranges
#[derive(Debug, Clone)]
pub struct TimestampWindow {
    /// Earliest valid timestamp
    earliest: Timestamp,

    /// Latest valid timestamp
    latest: Timestamp,

    /// Window size in seconds
    window_size: WindowSizeSeconds,
}

impl TimestampWindow {
    /// Create a new timestamp window
    pub fn new(window_size: u64) -> Self {
        let window_size_typed = WindowSizeSeconds::new(window_size);
        let now = TimestampValidator::current_timestamp();
        Self {
            earliest: Timestamp::from_raw(
                now.as_nanos()
                    .saturating_sub(window_size_typed.as_u64() * 1_000_000_000),
            ),
            latest: now,
            window_size: window_size_typed,
        }
    }

    /// Update the window with a new timestamp
    pub fn update(&mut self, timestamp: Timestamp) {
        if timestamp.as_nanos() > self.latest.as_nanos() {
            self.latest = timestamp;
            self.earliest = Timestamp::from_raw(
                timestamp
                    .as_nanos()
                    .saturating_sub(self.window_size.as_u64() * 1_000_000_000),
            );
        }
    }

    /// Check if a timestamp is within the window
    pub fn contains(&self, timestamp: Timestamp) -> bool {
        timestamp.as_nanos() >= self.earliest.as_nanos()
            && timestamp.as_nanos() <= self.latest.as_nanos()
    }

    /// Get the window bounds
    pub fn bounds(&self) -> (Timestamp, Timestamp) {
        (self.earliest, self.latest)
    }

    /// Reset the window to current time
    pub fn reset(&mut self) {
        let now = TimestampValidator::current_timestamp();
        self.latest = now;
        self.earliest = Timestamp::from_raw(
            now.as_nanos()
                .saturating_sub(self.window_size.as_u64() * 1_000_000_000),
        );
    }
}
