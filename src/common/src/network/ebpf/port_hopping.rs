//! Port hopping algorithm implementation
//!
//! Implements HMAC-SHA256-based port calculation per design/protocol/10-port-hopping.md

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use super::types::TimeBucket;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Calculate port number for a given time bucket using HMAC-SHA256
///
/// Per design/protocol/10-port-hopping.md:
/// - Uses HMAC-SHA256(daily_key, time_bucket)
/// - Maps result to valid port range [1024, 65535]
///
/// # Arguments
///
/// * `daily_key` - 32-byte daily key for HMAC
/// * `time_bucket` - Time bucket to calculate port for
///
/// # Returns
///
/// Port number in range [1024, 65535]
///
/// # Panics
///
/// Panics if daily_key is not 32 bytes (caller must validate)
/// Calculate port number for a given time bucket using HMAC-SHA256
///
/// Per design/protocol/10-port-hopping.md:
/// - Uses HMAC-SHA256(daily_key, time_bucket)
/// - Maps result to valid port range [1024, 65535]
///
/// # Arguments
///
/// * `daily_key` - 32-byte daily key for HMAC (must be 32 bytes)
/// * `time_bucket` - Time bucket to calculate port for
///
/// # Returns
///
/// Port number in range [1024, 65535], or None if key length invalid
pub fn calculate_port(daily_key: &[u8], time_bucket: TimeBucket) -> Option<u16> {
    // Create HMAC instance with daily key
    let mut mac = HmacSha256::new_from_slice(daily_key).ok()?;

    // Update with time bucket as little-endian bytes
    mac.update(&time_bucket.get().to_le_bytes());

    // Finalize HMAC and get result
    let result = mac.finalize();
    let bytes = result.into_bytes();

    // Take first 2 bytes as u16 (little-endian)
    let raw_port = u16::from_le_bytes([bytes[0], bytes[1]]);

    // Map to valid port range [1024, 65535]
    // Range size = 65535 - 1024 + 1 = 64512
    let port_range = 64512u32;
    let port = 1024 + (raw_port as u32 % port_range);

    Some(port as u16)
}

/// Calculate ports for a time bucket plus adaptive window range
///
/// Returns ports for:
/// - Past buckets (current - past_buckets..current)
/// - Current bucket
/// - Future buckets (current+1..current + future_buckets + 1)
///
/// # Arguments
///
/// * `daily_key` - 32-byte daily key for HMAC
/// * `current_bucket` - Current time bucket
/// * `past_buckets` - Number of past buckets to include
/// * `future_buckets` - Number of future buckets to include
pub fn calculate_port_window(
    daily_key: &[u8],
    current_bucket: TimeBucket,
    past_buckets: u32,
    future_buckets: u32,
) -> Vec<u16> {
    let mut ports = Vec::with_capacity((1 + past_buckets + future_buckets) as usize);

    let current_val = current_bucket.get();

    // Past buckets (with underflow protection)
    let start = current_val.saturating_sub(past_buckets);
    for bucket_val in start..current_val {
        let bucket = TimeBucket::new(bucket_val);
        if let Some(port) = calculate_port(daily_key, bucket) {
            ports.push(port);
        }
    }

    // Current bucket
    if let Some(port) = calculate_port(daily_key, current_bucket) {
        ports.push(port);
    }

    // Future buckets
    for bucket_val in (current_val + 1)..=(current_val + future_buckets) {
        let bucket = TimeBucket::new(bucket_val);
        if let Some(port) = calculate_port(daily_key, bucket) {
            ports.push(port);
        }
    }

    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_port_deterministic() {
        let key = vec![0x42; 32];
        let bucket = TimeBucket::new(100);

        let port1 = calculate_port(&key, bucket).expect("Port calculation should succeed");
        let port2 = calculate_port(&key, bucket).expect("Port calculation should succeed");

        assert_eq!(port1, port2, "Port calculation should be deterministic");
    }

    #[test]
    fn test_calculate_port_range() {
        let key = vec![0x42; 32];

        for i in 0..1000 {
            let bucket = TimeBucket::new(i);
            let port = calculate_port(&key, bucket).expect("Port calculation should succeed");

            assert!(
                port >= 1024,
                "Port {} below minimum (1024) for bucket {}",
                port,
                i
            );
        }
    }

    #[test]
    fn test_calculate_port_different_buckets() {
        let key = vec![0x42; 32];

        let port1 =
            calculate_port(&key, TimeBucket::new(100)).expect("Port calculation should succeed");
        let port2 =
            calculate_port(&key, TimeBucket::new(101)).expect("Port calculation should succeed");

        assert_ne!(
            port1, port2,
            "Different buckets should produce different ports"
        );
    }

    #[test]
    fn test_calculate_port_different_keys() {
        let key1 = vec![0x42; 32];
        let key2 = vec![0x43; 32];
        let bucket = TimeBucket::new(100);

        let port1 = calculate_port(&key1, bucket).expect("Port calculation should succeed");
        let port2 = calculate_port(&key2, bucket).expect("Port calculation should succeed");

        assert_ne!(
            port1, port2,
            "Different keys should produce different ports"
        );
    }

    #[test]
    fn test_calculate_port_window() {
        let key = vec![0x42; 32];
        let current = TimeBucket::new(10);

        let ports = calculate_port_window(&key, current, 2, 2);

        // Should have past(2) + current(1) + future(2) = 5 ports
        assert_eq!(ports.len(), 5);

        // All ports should be in valid range (>= 1024)
        for port in &ports {
            assert!(*port >= 1024, "Port {} below minimum", port);
        }
    }

    #[test]
    fn test_calculate_port_window_underflow() {
        let key = vec![0x42; 32];
        let current = TimeBucket::new(1);

        let ports = calculate_port_window(&key, current, 5, 2);

        // Should handle underflow gracefully (past_buckets=5 but current=1)
        // Result: buckets 0, 1, 2, 3 = 4 ports
        assert_eq!(ports.len(), 4);
    }
}
