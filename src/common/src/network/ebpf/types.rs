//! eBPF loader domain types
//!
//! This module defines domain types for eBPF program loading and port hopping
//! following the newtype pattern specified in design/rules.md.

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::fmt;

/// Adaptive delay window statistics
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdaptiveStats {
    /// Count of packets that arrived early (future time bucket)
    pub early_count: u32,
    /// Count of packets that arrived late (past time bucket)
    pub late_count: u32,
}

/// Time bucket for port hopping
///
/// Represents a discrete time interval for port validation.
/// Calculated as `(milliseconds_since_midnight_UTC) / HOP_INTERVAL_MS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeBucket(u32);

impl TimeBucket {
    /// Create a new time bucket
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get the bucket value
    pub fn get(&self) -> u32 {
        self.0
    }

    /// Calculate time bucket from milliseconds since midnight UTC
    ///
    /// # Arguments
    ///
    /// * `millis_since_midnight` - Milliseconds since midnight UTC
    /// * `hop_interval_ms` - Hop interval in milliseconds (typically 500ms)
    pub fn from_millis(millis_since_midnight: u64, hop_interval_ms: u32) -> Self {
        let bucket = (millis_since_midnight / u64::from(hop_interval_ms)) as u32;
        Self(bucket)
    }
}

impl fmt::Display for TimeBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TimeBucket({})", self.0)
    }
}

/// Adaptive delay window configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveWindowConfig {
    /// Past window size in milliseconds
    pub past_window_ms: u32,
    /// Future window size in milliseconds
    pub future_window_ms: u32,
}

impl AdaptiveWindowConfig {
    /// Create a new adaptive window configuration
    ///
    /// # Arguments
    ///
    /// * `past_window_ms` - Past window size in milliseconds
    /// * `future_window_ms` - Future window size in milliseconds
    pub fn new(past_window_ms: u32, future_window_ms: u32) -> Self {
        Self {
            past_window_ms,
            future_window_ms,
        }
    }
}

impl Default for AdaptiveWindowConfig {
    fn default() -> Self {
        Self {
            past_window_ms: 500,
            future_window_ms: 500,
        }
    }
}

/// Port hopping configuration
#[derive(Debug, Clone)]
pub struct PortHoppingConfig {
    /// Daily key for HMAC-SHA256 calculation (32 bytes)
    pub daily_key: Vec<u8>,
    /// Hop interval in milliseconds
    pub hop_interval_ms: u32,
    /// Adaptive delay window configuration
    pub adaptive_window: AdaptiveWindowConfig,
}

impl PortHoppingConfig {
    /// Create a new port hopping configuration
    ///
    /// # Arguments
    ///
    /// * `daily_key` - Daily key for HMAC calculation (must be 32 bytes)
    /// * `hop_interval_ms` - Hop interval in milliseconds
    /// * `adaptive_window` - Adaptive delay window configuration
    ///
    /// # Errors
    ///
    /// Returns error if daily_key is not 32 bytes
    pub fn new(
        daily_key: Vec<u8>,
        hop_interval_ms: u32,
        adaptive_window: AdaptiveWindowConfig,
    ) -> Result<Self, &'static str> {
        if daily_key.len() != 32 {
            return Err("daily_key must be 32 bytes");
        }

        Ok(Self {
            daily_key,
            hop_interval_ms,
            adaptive_window,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_bucket_calculation() {
        let bucket = TimeBucket::from_millis(1000, 500);
        assert_eq!(bucket.get(), 2);

        let bucket = TimeBucket::from_millis(500, 500);
        assert_eq!(bucket.get(), 1);

        let bucket = TimeBucket::from_millis(0, 500);
        assert_eq!(bucket.get(), 0);
    }

    #[test]
    fn test_adaptive_window_config_default() {
        let config = AdaptiveWindowConfig::default();
        assert_eq!(config.past_window_ms, 500);
        assert_eq!(config.future_window_ms, 500);
    }

    #[test]
    fn test_port_hopping_config_validation() {
        let valid_key = vec![0x42; 32];
        let config = PortHoppingConfig::new(valid_key, 500, AdaptiveWindowConfig::default());
        assert!(config.is_ok());

        let invalid_key = vec![0x42; 16];
        let config = PortHoppingConfig::new(invalid_key, 500, AdaptiveWindowConfig::default());
        assert!(config.is_err());
    }

    // MED-011: Time bucket tests

    #[test]
    fn test_bucket_index_calculation() {
        let hop_interval_ms = 500;

        // Test various timestamps
        let test_cases = vec![
            (0, 0),           // Midnight
            (500, 1),         // 500ms after midnight
            (1000, 2),        // 1 second after midnight
            (1500, 3),        // 1.5 seconds
            (3600_000, 7200), // 1 hour (3600 seconds = 7200 buckets at 500ms)
        ];

        for (millis, expected_bucket) in test_cases {
            let bucket = TimeBucket::from_millis(millis, hop_interval_ms);
            assert_eq!(
                bucket.get(),
                expected_bucket,
                "Bucket calculation failed for {} millis",
                millis
            );
        }
    }

    #[test]
    fn test_bucket_boundary_conditions() {
        let hop_interval_ms = 500;

        // Test boundary at 0
        let bucket = TimeBucket::from_millis(0, hop_interval_ms);
        assert_eq!(bucket.get(), 0);

        // Test just before bucket boundary (499ms)
        let bucket = TimeBucket::from_millis(499, hop_interval_ms);
        assert_eq!(bucket.get(), 0);

        // Test exactly at bucket boundary (500ms)
        let bucket = TimeBucket::from_millis(500, hop_interval_ms);
        assert_eq!(bucket.get(), 1);

        // Test just after bucket boundary (501ms)
        let bucket = TimeBucket::from_millis(501, hop_interval_ms);
        assert_eq!(bucket.get(), 1);

        // Test large timestamp (end of day: 86400000ms = 24 hours)
        let bucket = TimeBucket::from_millis(86_400_000, hop_interval_ms);
        assert_eq!(bucket.get(), 172_800); // 86400000 / 500 = 172800

        // Test timestamp at day boundary minus 1ms
        let bucket = TimeBucket::from_millis(86_399_999, hop_interval_ms);
        assert_eq!(bucket.get(), 172_799);
    }
}
