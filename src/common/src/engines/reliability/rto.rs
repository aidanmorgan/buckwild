// RTT measurement and RTO calculation per RFC 6298
//
// Implements the standard algorithm for calculating Retransmission Timeout (RTO)
// based on measured Round-Trip Time (RTT) samples.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::*;
use std::time::{Duration, Instant};

/// RFC 6298 RTO calculation constants
const RTT_ALPHA: f64 = 0.125; // RTT smoothing factor (1/8)
const RTT_BETA: f64 = 0.25; // RTT variance factor (1/4)
const RTT_K: f64 = 4.0; // RTT variance multiplier
const RTT_G: f64 = 0.1; // Clock granularity in milliseconds

/// RTO bounds from protocol specification
const RTT_INITIAL_MS: Timeout = Timeout::new(1000); // 1 second initial RTO
const MIN_RETRANSMISSION_TIMEOUT_MS: Timeout = Timeout::new(200); // 200ms minimum
const MAX_RETRANSMISSION_TIMEOUT_MS: Timeout = Timeout::new(60000); // 60 seconds maximum
const RTT_MIN_MS: Duration = Duration::from_millis(100); // 100ms minimum RTT
const RTT_MAX_MS: Duration = Duration::from_millis(60000); // 60 seconds maximum RTT

/// RTO calculation state per RFC 6298
#[derive(Debug, Clone)]
pub struct RtoState {
    /// Smoothed RTT estimate (SRTT)
    srtt: Duration,

    /// RTT variation estimate (RTTVAR)
    rttvar: Duration,

    /// Current retransmission timeout (RTO)
    rto: Timeout,

    /// Flag indicating first measurement
    first_measurement: bool,

    /// Last measurement timestamp
    last_measurement_time: Option<Instant>,

    /// Total number of measurements
    measurement_count: Counter,
}

impl RtoState {
    /// Create new RTO state with initial values
    pub fn new() -> Self {
        Self {
            srtt: Duration::from_millis(RTT_INITIAL_MS.as_u64()),
            rttvar: Duration::from_millis(RTT_INITIAL_MS.as_u64() / 2),
            rto: RTT_INITIAL_MS,
            first_measurement: true,
            last_measurement_time: None,
            measurement_count: Counter::new(0),
        }
    }

    /// Get current RTO value
    pub fn rto(&self) -> Timeout {
        self.rto
    }

    /// Get smoothed RTT estimate
    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// Get RTT variation estimate
    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// Get measurement count
    pub fn measurement_count(&self) -> u64 {
        self.measurement_count.as_u64()
    }
}

impl Default for RtoState {
    fn default() -> Self {
        Self::new()
    }
}

/// RTO calculator implementing RFC 6298 algorithm
#[derive(Debug)]
pub struct RtoCalculator {
    state: RtoState,
}

impl RtoCalculator {
    /// Create new RTO calculator
    pub fn new() -> Self {
        Self {
            state: RtoState::new(),
        }
    }

    /// Measure RTT from send time to acknowledgment time
    ///
    /// Returns validated RTT sample within bounds [RTT_MIN_MS, RTT_MAX_MS]
    pub fn measure_rtt(&mut self, send_time: Instant, ack_time: Instant) -> Duration {
        let rtt_sample = ack_time.saturating_duration_since(send_time);

        // Validate RTT sample within reasonable bounds
        let rtt_sample = if rtt_sample < RTT_MIN_MS {
            RTT_MIN_MS
        } else if rtt_sample > RTT_MAX_MS {
            RTT_MAX_MS
        } else {
            rtt_sample
        };

        // Update measurement statistics
        self.state.last_measurement_time = Some(ack_time);
        self.state.measurement_count = Counter::new(self.state.measurement_count.as_u64() + 1);

        rtt_sample
    }

    /// Update RTO using RFC 6298 algorithm with measured RTT
    ///
    /// Implements the standard RTO calculation:
    /// - First measurement: Initialize SRTT and RTTVAR
    /// - Subsequent measurements: Update using exponential averaging
    /// - RTO = SRTT + max(G, K * RTTVAR)
    /// - Clamp to [MIN_RTO, MAX_RTO]
    pub fn update_rto(&mut self, rtt_sample: Duration) -> Timeout {
        if self.state.first_measurement {
            // First RTT measurement - initialize estimates
            self.state.srtt = rtt_sample;
            self.state.rttvar = Duration::from_secs_f64(rtt_sample.as_secs_f64() / 2.0);
            self.state.first_measurement = false;
        } else {
            // Update smoothed RTT and variation using exponential averaging
            // RTTVAR = (1 - β) * RTTVAR + β * |SRTT - R'|
            let rtt_variation = rtt_sample.abs_diff(self.state.srtt);

            let old_rttvar_component = self.state.rttvar.as_secs_f64() * (1.0 - RTT_BETA);
            let new_rttvar_component = rtt_variation.as_secs_f64() * RTT_BETA;
            self.state.rttvar =
                Duration::from_secs_f64(old_rttvar_component + new_rttvar_component);

            // SRTT = (1 - α) * SRTT + α * R'
            let old_srtt_component = self.state.srtt.as_secs_f64() * (1.0 - RTT_ALPHA);
            let new_srtt_component = rtt_sample.as_secs_f64() * RTT_ALPHA;
            self.state.srtt = Duration::from_secs_f64(old_srtt_component + new_srtt_component);
        }

        // Calculate RTO: RTO = SRTT + max(G, K * RTTVAR)
        let g_value = Duration::from_secs_f64(RTT_G / 1000.0);
        let k_rttvar = Duration::from_secs_f64(self.state.rttvar.as_secs_f64() * RTT_K);
        let max_component = if g_value > k_rttvar {
            g_value
        } else {
            k_rttvar
        };

        let rto_value = self.state.srtt + max_component;

        // Ensure RTO is within acceptable bounds
        let rto_ms = rto_value.as_millis() as u64;
        let clamped_rto = if rto_ms < MIN_RETRANSMISSION_TIMEOUT_MS.as_u64() {
            MIN_RETRANSMISSION_TIMEOUT_MS
        } else if rto_ms > MAX_RETRANSMISSION_TIMEOUT_MS.as_u64() {
            MAX_RETRANSMISSION_TIMEOUT_MS
        } else {
            Timeout::new(rto_ms)
        };

        self.state.rto = clamped_rto;
        clamped_rto
    }

    /// Handle retransmission timeout with exponential backoff
    ///
    /// Doubles the RTO for next retransmission attempt per RFC 6298.
    /// Does NOT update SRTT/RTTVAR until a valid ACK is received.
    pub fn handle_retransmission_timeout(&mut self) -> Timeout {
        // Double the RTO for next retransmission attempt
        let new_rto_ms = self.state.rto.as_u64() * 2;
        let clamped_rto = if new_rto_ms > MAX_RETRANSMISSION_TIMEOUT_MS.as_u64() {
            MAX_RETRANSMISSION_TIMEOUT_MS
        } else {
            Timeout::new(new_rto_ms)
        };

        self.state.rto = clamped_rto;
        clamped_rto
    }

    /// Get current RTO value
    pub fn current_rto(&self) -> Timeout {
        self.state.rto
    }

    /// Reset RTO estimates to initial values
    ///
    /// Used after connection establishment or major state changes
    pub fn reset(&mut self) {
        self.state = RtoState::new();
    }

    /// Get current state for inspection
    pub fn state(&self) -> &RtoState {
        &self.state
    }
}

impl Default for RtoCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rto_initial_state() {
        let calculator = RtoCalculator::new();
        assert_eq!(calculator.current_rto().as_u64(), 1000);
        assert!(calculator.state().first_measurement);
        assert_eq!(calculator.state().measurement_count(), 0);
    }

    #[test]
    fn test_rto_first_measurement() {
        let mut calculator = RtoCalculator::new();
        let send_time = Instant::now();
        let ack_time = send_time + Duration::from_millis(100);

        let rtt = calculator.measure_rtt(send_time, ack_time);
        assert_eq!(rtt, Duration::from_millis(100));

        let rto = calculator.update_rto(rtt);
        assert!(rto.as_u64() >= MIN_RETRANSMISSION_TIMEOUT_MS.as_u64());
        assert_eq!(calculator.state().measurement_count(), 1);
    }

    #[test]
    fn test_rto_bounds() {
        let mut calculator = RtoCalculator::new();

        // Test minimum bound
        let rtt = Duration::from_millis(50); // Below RTT_MIN_MS
        calculator.update_rto(rtt);
        assert!(calculator.current_rto().as_u64() >= MIN_RETRANSMISSION_TIMEOUT_MS.as_u64());

        // Test maximum bound
        let rtt = Duration::from_secs(100); // Above RTT_MAX_MS
        calculator.update_rto(rtt);
        assert!(calculator.current_rto().as_u64() <= MAX_RETRANSMISSION_TIMEOUT_MS.as_u64());
    }

    #[test]
    fn test_rto_exponential_backoff() {
        let mut calculator = RtoCalculator::new();
        let initial_rto = calculator.current_rto();

        let backoff1 = calculator.handle_retransmission_timeout();
        assert_eq!(backoff1.as_u64(), initial_rto.as_u64() * 2);

        let backoff2 = calculator.handle_retransmission_timeout();
        assert_eq!(backoff2.as_u64(), backoff1.as_u64() * 2);

        // Test maximum bound
        for _ in 0..10 {
            calculator.handle_retransmission_timeout();
        }
        assert_eq!(
            calculator.current_rto().as_u64(),
            MAX_RETRANSMISSION_TIMEOUT_MS.as_u64()
        );
    }

    #[test]
    fn test_rto_reset() {
        let mut calculator = RtoCalculator::new();

        // Make some measurements
        let rtt = Duration::from_millis(200);
        calculator.update_rto(rtt);
        calculator.handle_retransmission_timeout();

        // Reset should restore initial state
        calculator.reset();
        assert_eq!(calculator.current_rto().as_u64(), 1000);
        assert!(calculator.state().first_measurement);
    }
}
