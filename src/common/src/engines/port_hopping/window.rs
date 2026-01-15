#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Asymmetric Window Calculation - RTT and jitter-based window sizing
//
// Implements asymmetric window calculation for port hopping based on measured
// network conditions (RTT, jitter). Allows client and server to have different
// window sizes to account for network asymmetry.

use crate::protocol::types::*;

/// Minimum window size (time windows)
pub const MIN_WINDOW_SIZE: usize = 1;

/// Maximum window size (time windows)
pub const MAX_WINDOW_SIZE: usize = 16;

/// Default window size
pub const DEFAULT_WINDOW_SIZE: usize = 3;

/// Base RTT for minimum window (milliseconds)
const BASE_RTT_MS: f64 = 50.0;

/// RTT contribution factor (windows per 100ms RTT)
const RTT_CONTRIBUTION_FACTOR: f64 = 1.0;

/// Jitter contribution factor (windows per 50ms jitter)
const JITTER_CONTRIBUTION_FACTOR: f64 = 2.0;

/// Asymmetric window configuration
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AsymmetricWindow {
    /// Window size for past time slots (late packets)
    pub past_window_size: usize,

    /// Window size for future time slots (early packets)
    pub future_window_size: usize,

    /// Total window size (past + current + future)
    pub total_window_size: usize,

    /// RTT used for calculation (nanoseconds)
    pub rtt_nanos: u64,

    /// Jitter used for calculation (milliseconds)
    pub jitter_millis: u32,
}

impl AsymmetricWindow {
    /// Calculate asymmetric window from RTT and jitter measurements
    ///
    /// Window sizing algorithm:
    /// - Base window: 3 (1 past + 1 current + 1 future)
    /// - Add windows based on RTT (1 window per 100ms above 50ms baseline)
    /// - Add windows based on jitter (2 windows per 50ms)
    /// - Cap at MIN_WINDOW_SIZE to MAX_WINDOW_SIZE
    pub fn from_measurements(rtt: RoundTripTime, jitter: NetworkJitter) -> Self {
        let rtt_ms = rtt.as_millis() as f64;
        let jitter_ms = jitter.as_millis() as f64;

        // Calculate total window size
        let base_window = DEFAULT_WINDOW_SIZE as f64;

        // Add windows based on RTT (above baseline)
        let rtt_excess = (rtt_ms - BASE_RTT_MS).max(0.0);
        let rtt_windows = (rtt_excess / 100.0 * RTT_CONTRIBUTION_FACTOR).ceil();

        // Add windows based on jitter
        let jitter_windows = (jitter_ms / 50.0 * JITTER_CONTRIBUTION_FACTOR).ceil();

        // Calculate total window size
        let total_window = base_window + rtt_windows + jitter_windows;
        let total_window_size = (total_window as usize).clamp(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE);

        // For symmetric case, split evenly
        let past_window_size = total_window_size / 2;
        let future_window_size = total_window_size - past_window_size - 1; // -1 for current window

        Self {
            past_window_size,
            future_window_size,
            total_window_size,
            rtt_nanos: rtt.as_nanos(),
            jitter_millis: jitter.as_millis(),
        }
    }

    /// Calculate asymmetric window with custom RTT/jitter values
    ///
    /// This allows for asymmetric network paths where client and server
    /// may observe different RTT/jitter values.
    pub fn from_measurements_asymmetric(
        client_rtt: RoundTripTime,
        client_jitter: NetworkJitter,
        server_rtt: RoundTripTime,
        server_jitter: NetworkJitter,
    ) -> Self {
        let client_rtt_ms = client_rtt.as_millis() as f64;
        let client_jitter_ms = client_jitter.as_millis() as f64;
        let server_rtt_ms = server_rtt.as_millis() as f64;
        let server_jitter_ms = server_jitter.as_millis() as f64;

        // Calculate window sizes independently for each direction
        let base_window = DEFAULT_WINDOW_SIZE as f64;

        // Past window (server -> client, based on client measurements)
        let client_rtt_excess = (client_rtt_ms - BASE_RTT_MS).max(0.0);
        let client_rtt_windows = (client_rtt_excess / 100.0 * RTT_CONTRIBUTION_FACTOR).ceil();
        let client_jitter_windows = (client_jitter_ms / 50.0 * JITTER_CONTRIBUTION_FACTOR).ceil();
        let past_window = (base_window / 2.0) + client_rtt_windows + client_jitter_windows;
        let past_window_size = (past_window as usize).clamp(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE / 2);

        // Future window (client -> server, based on server measurements)
        let server_rtt_excess = (server_rtt_ms - BASE_RTT_MS).max(0.0);
        let server_rtt_windows = (server_rtt_excess / 100.0 * RTT_CONTRIBUTION_FACTOR).ceil();
        let server_jitter_windows = (server_jitter_ms / 50.0 * JITTER_CONTRIBUTION_FACTOR).ceil();
        let future_window = (base_window / 2.0) + server_rtt_windows + server_jitter_windows;
        let future_window_size =
            (future_window as usize).clamp(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE / 2);

        // Total window includes current + past + future
        let total_window_size =
            (past_window_size + 1 + future_window_size).clamp(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE);

        Self {
            past_window_size,
            future_window_size,
            total_window_size,
            rtt_nanos: client_rtt.as_nanos().max(server_rtt.as_nanos()),
            jitter_millis: client_jitter.as_millis().max(server_jitter.as_millis()),
        }
    }

    /// Create symmetric window with equal past/future sizes
    pub fn symmetric(window_size: usize) -> Self {
        let clamped_size = window_size.clamp(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE);
        let past_window_size = clamped_size / 2;
        let future_window_size = clamped_size - past_window_size - 1; // -1 for current

        Self {
            past_window_size,
            future_window_size,
            total_window_size: clamped_size,
            rtt_nanos: 0,
            jitter_millis: 0,
        }
    }

    /// Create minimum window
    pub fn minimum() -> Self {
        Self::symmetric(MIN_WINDOW_SIZE)
    }

    /// Create maximum window
    pub fn maximum() -> Self {
        Self::symmetric(MAX_WINDOW_SIZE)
    }

    /// Check if window is symmetric
    pub fn is_symmetric(&self) -> bool {
        self.past_window_size == self.future_window_size
    }

    /// Calculate time range covered by this window (in milliseconds)
    ///
    /// Assumes 500ms per time window as per protocol spec
    pub fn time_range_ms(&self) -> u64 {
        (self.total_window_size as u64) * 500
    }
}

impl Default for AsymmetricWindow {
    fn default() -> Self {
        Self::symmetric(DEFAULT_WINDOW_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_equal_rtt() {
        // Equal RTT should give symmetric window
        let rtt = RoundTripTime::new(100_000_000); // 100ms
        let jitter = NetworkJitter::new(10); // 10ms

        let window = AsymmetricWindow::from_measurements(rtt, jitter);

        assert_eq!(window.past_window_size, window.future_window_size);
        assert_eq!(
            window.total_window_size,
            window.past_window_size + window.future_window_size + 1
        );
    }

    #[test]
    fn test_asymmetric_unequal_rtt() {
        // Unequal RTT should give asymmetric window
        let client_rtt = RoundTripTime::new(50_000_000); // 50ms
        let client_jitter = NetworkJitter::new(5); // 5ms
        let server_rtt = RoundTripTime::new(150_000_000); // 150ms
        let server_jitter = NetworkJitter::new(20); // 20ms

        let window = AsymmetricWindow::from_measurements_asymmetric(
            client_rtt,
            client_jitter,
            server_rtt,
            server_jitter,
        );

        // Future window (based on server RTT) should be larger
        assert!(window.future_window_size >= window.past_window_size);
        assert_eq!(
            window.total_window_size,
            window.past_window_size + window.future_window_size + 1
        );
    }

    #[test]
    fn test_jitter_expansion() {
        // High jitter should expand window
        let rtt = RoundTripTime::new(100_000_000); // 100ms
        let low_jitter = NetworkJitter::new(5); // 5ms
        let high_jitter = NetworkJitter::new(100); // 100ms

        let low_window = AsymmetricWindow::from_measurements(rtt, low_jitter);
        let high_window = AsymmetricWindow::from_measurements(rtt, high_jitter);

        assert!(high_window.total_window_size > low_window.total_window_size);
    }

    #[test]
    fn test_minimum_window() {
        // Very low RTT and jitter should give minimum window
        let rtt = RoundTripTime::new(10_000_000); // 10ms
        let jitter = NetworkJitter::new(1); // 1ms

        let window = AsymmetricWindow::from_measurements(rtt, jitter);

        assert!(window.total_window_size >= MIN_WINDOW_SIZE);
    }

    #[test]
    fn test_maximum_window() {
        // Very high RTT and jitter should be capped at maximum
        let rtt = RoundTripTime::new(5_000_000_000); // 5000ms
        let jitter = NetworkJitter::new(1000); // 1000ms

        let window = AsymmetricWindow::from_measurements(rtt, jitter);

        assert_eq!(window.total_window_size, MAX_WINDOW_SIZE);
    }

    #[test]
    fn test_symmetric_constructor() {
        let window = AsymmetricWindow::symmetric(5);

        assert_eq!(window.total_window_size, 5);
        assert_eq!(window.past_window_size, 2);
        assert_eq!(window.future_window_size, 2); // 5 - 2 - 1 = 2
        assert!(window.is_symmetric());
    }

    #[test]
    fn test_minimum_constructor() {
        let window = AsymmetricWindow::minimum();

        assert_eq!(window.total_window_size, MIN_WINDOW_SIZE);
        assert!(window.total_window_size >= MIN_WINDOW_SIZE);
    }

    #[test]
    fn test_maximum_constructor() {
        let window = AsymmetricWindow::maximum();

        assert_eq!(window.total_window_size, MAX_WINDOW_SIZE);
        assert!(window.total_window_size <= MAX_WINDOW_SIZE);
    }

    #[test]
    fn test_time_range() {
        let window = AsymmetricWindow::symmetric(5);

        // 5 windows * 500ms = 2500ms
        assert_eq!(window.time_range_ms(), 2500);
    }

    #[test]
    fn test_default_window() {
        let window = AsymmetricWindow::default();

        assert_eq!(window.total_window_size, DEFAULT_WINDOW_SIZE);
        assert!(window.is_symmetric());
    }

    #[test]
    fn test_rtt_based_adjustment() {
        // Test that RTT properly increases window size
        let low_rtt = RoundTripTime::new(50_000_000); // 50ms (baseline)
        let high_rtt = RoundTripTime::new(250_000_000); // 250ms (+200ms = +2 windows)
        let jitter = NetworkJitter::new(0);

        let low_window = AsymmetricWindow::from_measurements(low_rtt, jitter);
        let high_window = AsymmetricWindow::from_measurements(high_rtt, jitter);

        // High RTT should have larger window
        assert!(high_window.total_window_size >= low_window.total_window_size + 2);
    }

    #[test]
    fn test_window_bounds() {
        // Test various combinations stay within bounds
        let test_cases = vec![
            (10_000_000, 0),        // 10ms, 0 jitter
            (100_000_000, 50),      // 100ms, 50ms jitter
            (500_000_000, 100),     // 500ms, 100ms jitter
            (1_000_000_000, 200),   // 1000ms, 200ms jitter
            (10_000_000_000, 1000), // 10000ms, 1000ms jitter
        ];

        for (rtt_nanos, jitter_ms) in test_cases {
            let rtt = RoundTripTime::new(rtt_nanos);
            let jitter = NetworkJitter::new(jitter_ms);

            let window = AsymmetricWindow::from_measurements(rtt, jitter);

            assert!(
                window.total_window_size >= MIN_WINDOW_SIZE,
                "Window size {} below minimum {} for RTT {}ms, jitter {}ms",
                window.total_window_size,
                MIN_WINDOW_SIZE,
                rtt.as_millis(),
                jitter_ms
            );
            assert!(
                window.total_window_size <= MAX_WINDOW_SIZE,
                "Window size {} above maximum {} for RTT {}ms, jitter {}ms",
                window.total_window_size,
                MAX_WINDOW_SIZE,
                rtt.as_millis(),
                jitter_ms
            );
        }
    }
}
