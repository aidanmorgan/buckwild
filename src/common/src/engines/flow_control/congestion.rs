// Congestion Control - TCP-compatible congestion control algorithms
//
// This module implements congestion control algorithms including slow start,
// congestion avoidance, fast recovery, and congestion window management.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::cmp::{max, min};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::error::EngineError;
use crate::protocol::types::*;

// Use consolidated CongestionState from protocol types

/// RTT measurement for congestion control
#[derive(Debug)]
pub struct RttMeasurement {
    /// Smoothed RTT (SRTT)
    srtt: AtomicU64,

    /// RTT variation (RTTVAR)
    rttvar: AtomicU64,

    /// Retransmission timeout (RTO)
    rto: AtomicU64,

    /// Last RTT measurement
    last_rtt: AtomicU64,

    /// RTT measurement timestamp
    last_measurement_time: std::sync::Mutex<Option<Instant>>,
}

impl RttMeasurement {
    pub fn new() -> Self {
        Self {
            srtt: AtomicU64::new(100_000_000),     // 100ms in nanoseconds
            rttvar: AtomicU64::new(50_000_000),    // 50ms in nanoseconds
            rto: AtomicU64::new(1_000_000_000),    // 1 second in nanoseconds
            last_rtt: AtomicU64::new(100_000_000), // 100ms in nanoseconds
            last_measurement_time: std::sync::Mutex::new(None),
        }
    }

    /// Update RTT measurement
    pub fn update_rtt(&self, rtt: RoundTripTime) {
        let rtt_nanos = rtt.as_u64();
        let current_srtt = self.srtt.load(Ordering::Relaxed);
        let current_rttvar = self.rttvar.load(Ordering::Relaxed);

        // RFC 6298 RTT calculation
        let new_rttvar = if current_srtt == 0 {
            // First measurement
            rtt_nanos / 2
        } else {
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
            let beta = 0.25;
            let diff = current_srtt.abs_diff(rtt_nanos);
            ((1.0 - beta) * current_rttvar as f64 + beta * diff as f64) as u64
        };

        let new_srtt = if current_srtt == 0 {
            // First measurement
            rtt_nanos
        } else {
            // SRTT = (1 - alpha) * SRTT + alpha * R'
            let alpha = 0.125;
            ((1.0 - alpha) * current_srtt as f64 + alpha * rtt_nanos as f64) as u64
        };

        // Calculate RTO = SRTT + max(G, K * RTTVAR)
        let k = 4;
        let g = 10_000_000; // Clock granularity in nanoseconds (10ms)
        let new_rto = new_srtt + max(g, k * new_rttvar);

        // Clamp RTO to reasonable bounds (200ms to 60s in nanoseconds)
        let clamped_rto = new_rto.clamp(200_000_000, 60_000_000_000);

        self.srtt.store(new_srtt, Ordering::Relaxed);
        self.rttvar.store(new_rttvar, Ordering::Relaxed);
        self.rto.store(clamped_rto, Ordering::Relaxed);
        self.last_rtt.store(rtt_nanos, Ordering::Relaxed);

        // Recover from poisoned mutex - the data is still usable
        if let Ok(mut guard) = self.last_measurement_time.lock() {
            *guard = Some(Instant::now());
        } else {
            warn!("last_measurement_time mutex poisoned, updating anyway");
            *self
                .last_measurement_time
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        }

        debug!(
            rtt_ms = rtt.as_millis(),
            srtt_ms = new_srtt / 1_000_000,
            rttvar_ms = new_rttvar / 1_000_000,
            rto_ms = clamped_rto / 1_000_000,
            "Updated RTT measurement"
        );
    }

    /// Get current RTO
    pub fn get_rto(&self) -> RoundTripTime {
        RoundTripTime::new(self.rto.load(Ordering::Relaxed))
    }

    /// Get current SRTT
    pub fn get_srtt(&self) -> RoundTripTime {
        RoundTripTime::new(self.srtt.load(Ordering::Relaxed))
    }

    /// Get current RTTVAR
    pub fn get_rttvar(&self) -> RoundTripTime {
        RoundTripTime::new(self.rttvar.load(Ordering::Relaxed))
    }
}

impl Default for RttMeasurement {
    fn default() -> Self {
        Self::new()
    }
}

/// Congestion control state management
#[derive(Debug)]
pub struct CongestionControlState {
    /// Current congestion window
    pub congestion_window: AtomicCongestionWindow,

    /// Slow start threshold
    pub slow_start_threshold: AtomicSlowStartThreshold,

    /// Current congestion state
    pub state: std::sync::Mutex<CongestionState>,

    /// Duplicate ACK count (functional state for fast retransmit, not a metric)
    pub duplicate_ack_count: AtomicU64,

    /// Last acknowledged sequence number
    pub last_ack: AckNumber,

    /// Congestion event count (functional state for algorithm, not a metric)
    pub congestion_events: AtomicU64,

    /// Bytes acknowledged in current RTT
    pub bytes_acked_in_rtt: ByteCount,

    /// RTT start time for congestion avoidance
    pub rtt_start_time: std::sync::Mutex<Option<Instant>>,
}

impl CongestionControlState {
    pub fn new(initial_cwnd: u32, initial_ssthresh: u32) -> Self {
        Self {
            congestion_window: AtomicCongestionWindow::new(initial_cwnd),
            slow_start_threshold: AtomicSlowStartThreshold::new(initial_ssthresh),
            state: std::sync::Mutex::new(CongestionState::SlowStart),
            duplicate_ack_count: AtomicU64::new(0),
            last_ack: AckNumber::new(0),
            congestion_events: AtomicU64::new(0),
            bytes_acked_in_rtt: ByteCount::new(0),
            rtt_start_time: std::sync::Mutex::new(None),
        }
    }
}

/// Congestion Control Engine
pub struct CongestionControl {
    /// Congestion control state
    state: CongestionControlState,

    /// RTT measurement
    rtt_measurement: RttMeasurement,

    /// Maximum segment size
    mss: MaxSegmentSize,

    /// Maximum congestion window
    max_cwnd: CongestionWindow,
}

impl CongestionControl {
    /// Create new congestion control engine
    pub fn new(initial_cwnd: u32, initial_ssthresh: u32) -> Self {
        Self {
            state: CongestionControlState::new(initial_cwnd, initial_ssthresh),
            rtt_measurement: RttMeasurement::new(),
            mss: MaxSegmentSize::new(1460),         // Standard MSS
            max_cwnd: CongestionWindow::new(65535), // Max window per spec
        }
    }

    /// Get current congestion window
    pub fn get_congestion_window(&self) -> u32 {
        self.state.congestion_window.load(Ordering::Relaxed)
    }

    /// Get current slow start threshold
    pub fn get_slow_start_threshold(&self) -> u32 {
        self.state.slow_start_threshold.load(Ordering::Relaxed)
    }

    /// Get current congestion state
    pub fn get_congestion_state(&self) -> CongestionState {
        // Recover from poisoned mutex - the state is still readable
        *self.state.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Process acknowledgment
    pub fn process_ack(&self, ack_number: u32, bytes_acked: u32) -> Result<(), EngineError> {
        let last_ack = self.state.last_ack.load(Ordering::Relaxed);

        if ack_number == last_ack {
            // Duplicate ACK
            self.handle_duplicate_ack(ack_number)?;
        } else if ack_number > last_ack {
            // New ACK
            self.handle_new_ack(ack_number, bytes_acked)?;
        }
        // Ignore old ACKs

        Ok(())
    }

    /// Handle new acknowledgment
    fn handle_new_ack(&self, ack_number: u32, bytes_acked: u32) -> Result<(), EngineError> {
        self.state.last_ack.store(ack_number, Ordering::Relaxed);
        self.state
            .duplicate_ack_count
            .store(0, std::sync::atomic::Ordering::Relaxed);

        let current_state = self.get_congestion_state();

        match current_state {
            CongestionState::SlowStart => {
                self.slow_start_ack(bytes_acked)?;
            }
            CongestionState::CongestionAvoidance => {
                self.congestion_avoidance_ack(bytes_acked)?;
            }
            CongestionState::FastRecovery => {
                self.fast_recovery_ack(ack_number, bytes_acked)?;
            }
        }

        debug!(
            ack_number = %ack_number,
            bytes_acked,
            cwnd = self.get_congestion_window(),
            state = ?current_state,
            "Processed new ACK"
        );

        Ok(())
    }

    /// Handle duplicate acknowledgment
    fn handle_duplicate_ack(&self, ack_number: u32) -> Result<(), EngineError> {
        let prev_count = self
            .state
            .duplicate_ack_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dup_count = prev_count + 1;

        if dup_count == 3 {
            // Fast retransmit threshold reached
            self.enter_fast_recovery()?;
        } else if self.get_congestion_state() == CongestionState::FastRecovery {
            // Inflate congestion window during fast recovery
            let current_cwnd = self.state.congestion_window.load(Ordering::Relaxed);
            let new_cwnd = min(current_cwnd + self.mss.as_u32(), self.max_cwnd.as_u32());
            self.state
                .congestion_window
                .store(new_cwnd, std::sync::atomic::Ordering::Relaxed);
        }

        debug!(
            ack_number = %ack_number,
            dup_count,
            cwnd = self.get_congestion_window(),
            "Processed duplicate ACK"
        );

        Ok(())
    }

    /// Slow start acknowledgment processing
    fn slow_start_ack(&self, bytes_acked: u32) -> Result<(), EngineError> {
        let current_cwnd = self.state.congestion_window.load(Ordering::Relaxed);
        let ssthresh = self.state.slow_start_threshold.load(Ordering::Relaxed);

        // Increase cwnd by bytes_acked (exponential growth)
        let new_cwnd = min(current_cwnd + bytes_acked, self.max_cwnd.as_u32());
        self.state
            .congestion_window
            .store(new_cwnd, std::sync::atomic::Ordering::Relaxed);

        // Check if we should transition to congestion avoidance
        if new_cwnd >= ssthresh {
            // Recover from poisoned mutex - the state is simple and can be safely updated
            *self.state.state.lock().unwrap_or_else(|e| e.into_inner()) =
                CongestionState::CongestionAvoidance;
            *self
                .state
                .rtt_start_time
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

            info!(
                cwnd = new_cwnd,
                ssthresh, "Transitioned from slow start to congestion avoidance"
            );
        }

        Ok(())
    }

    /// Congestion avoidance acknowledgment processing
    fn congestion_avoidance_ack(&self, bytes_acked: u32) -> Result<(), EngineError> {
        let current_cwnd = self.state.congestion_window.load(Ordering::Relaxed);

        // Additive increase: cwnd += MSS * MSS / cwnd per RTT
        let bytes_in_rtt = self
            .state
            .bytes_acked_in_rtt
            .fetch_add(bytes_acked as u64, std::sync::atomic::Ordering::Relaxed)
            + bytes_acked as u64;

        // Check if we've completed an RTT
        let rtt_completed = {
            // Recover from poisoned mutex - the time is still readable
            let rtt_start = self
                .state
                .rtt_start_time
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(start_time) = *rtt_start {
                start_time.elapsed()
                    >= Duration::from_nanos(self.rtt_measurement.get_srtt().as_u64())
            } else {
                false
            }
        };

        if rtt_completed {
            // Increase cwnd by MSS for the completed RTT
            let new_cwnd = min(current_cwnd + self.mss.as_u32(), self.max_cwnd.as_u32());
            self.state
                .congestion_window
                .store(new_cwnd, std::sync::atomic::Ordering::Relaxed);

            // Reset RTT tracking
            self.state
                .bytes_acked_in_rtt
                .store(0, std::sync::atomic::Ordering::Relaxed);
            *self
                .state
                .rtt_start_time
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

            debug!(
                cwnd = new_cwnd,
                bytes_in_rtt, "Congestion avoidance: increased cwnd"
            );
        }

        Ok(())
    }

    /// Fast recovery acknowledgment processing
    fn fast_recovery_ack(&self, ack_number: u32, _bytes_acked: u32) -> Result<(), EngineError> {
        // Exit fast recovery
        // Recover from poisoned mutex - the state is simple and can be safely updated
        *self.state.state.lock().unwrap_or_else(|e| e.into_inner()) =
            CongestionState::CongestionAvoidance;
        *self
            .state
            .rtt_start_time
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

        // Set cwnd to ssthresh
        let ssthresh = self.state.slow_start_threshold.load(Ordering::Relaxed);
        self.state
            .congestion_window
            .store(ssthresh, std::sync::atomic::Ordering::Relaxed);

        info!(
            ack_number = %ack_number,
            cwnd = ssthresh,
            "Exited fast recovery"
        );

        Ok(())
    }

    /// Enter fast recovery state
    fn enter_fast_recovery(&self) -> Result<(), EngineError> {
        let current_cwnd = self.state.congestion_window.load(Ordering::Relaxed);

        // Set ssthresh = max(cwnd/2, 2*MSS)
        let new_ssthresh = max(current_cwnd / 2, 2 * self.mss.as_u32());
        self.state
            .slow_start_threshold
            .store(new_ssthresh, std::sync::atomic::Ordering::Relaxed);

        // Set cwnd = ssthresh + 3*MSS (for the 3 duplicate ACKs)
        let new_cwnd = new_ssthresh + 3 * self.mss.as_u32();
        self.state
            .congestion_window
            .store(new_cwnd, std::sync::atomic::Ordering::Relaxed);

        // Change state to fast recovery
        // Recover from poisoned mutex - the state is simple and can be safely updated
        *self.state.state.lock().unwrap_or_else(|e| e.into_inner()) = CongestionState::FastRecovery;

        // Increment congestion event counter
        self.state
            .congestion_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        warn!(
            old_cwnd = current_cwnd,
            new_cwnd, new_ssthresh, "Entered fast recovery due to 3 duplicate ACKs"
        );

        Ok(())
    }

    /// Handle timeout (congestion event)
    pub fn handle_timeout(&self) -> Result<(), EngineError> {
        let current_cwnd = self.state.congestion_window.load(Ordering::Relaxed);

        // Set ssthresh = max(cwnd/2, 2*MSS)
        let new_ssthresh = max(current_cwnd / 2, 2 * self.mss.as_u32());
        self.state
            .slow_start_threshold
            .store(new_ssthresh, std::sync::atomic::Ordering::Relaxed);

        // Set cwnd = MSS (restart slow start)
        self.state
            .congestion_window
            .store(self.mss.as_u32(), std::sync::atomic::Ordering::Relaxed);

        // Change state to slow start
        // Recover from poisoned mutex - the state is simple and can be safely updated
        *self.state.state.lock().unwrap_or_else(|e| e.into_inner()) = CongestionState::SlowStart;

        // Reset duplicate ACK count
        self.state
            .duplicate_ack_count
            .store(0, std::sync::atomic::Ordering::Relaxed);

        // Increment congestion event counter
        self.state
            .congestion_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        warn!(
            old_cwnd = current_cwnd,
            new_cwnd = self.mss.as_u32(),
            new_ssthresh,
            "Handled timeout: reset to slow start"
        );

        Ok(())
    }

    /// Update RTT measurement
    pub fn update_rtt(&self, rtt: RoundTripTime) {
        self.rtt_measurement.update_rtt(rtt);
    }

    /// Get current RTO
    pub fn get_rto(&self) -> RoundTripTime {
        self.rtt_measurement.get_rto()
    }

    /// Get congestion control statistics
    pub fn get_congestion_stats(&self) -> CongestionStats {
        CongestionStats {
            congestion_window: CongestionWindow::new(self.get_congestion_window()),
            slow_start_threshold: SlowStartThreshold::new(self.get_slow_start_threshold()),
            congestion_state: self.get_congestion_state(),
            duplicate_ack_count: Counter::new(
                self.state.duplicate_ack_count.load(Ordering::Relaxed),
            ),
            congestion_events: Counter::new(self.state.congestion_events.load(Ordering::Relaxed)),
            srtt: self.rtt_measurement.get_srtt(),
            rttvar: self.rtt_measurement.get_rttvar(),
            rto: self.rtt_measurement.get_rto(),
        }
    }

    /// Set congestion window (for testing)
    #[cfg(test)]
    pub fn set_congestion_window(&self, window: u32) {
        self.state
            .congestion_window
            .store(window, Ordering::Relaxed);
    }

    /// Set congestion state (for testing)
    #[cfg(test)]
    pub fn set_congestion_state(&self, state: CongestionState) {
        *self.state.state.lock().unwrap_or_else(|e| e.into_inner()) = state;
    }
}

/// Congestion control statistics
#[derive(Debug, Clone)]
pub struct CongestionStats {
    pub congestion_window: CongestionWindow,
    pub slow_start_threshold: SlowStartThreshold,
    pub congestion_state: CongestionState,
    pub duplicate_ack_count: Counter,
    pub congestion_events: Counter,
    pub srtt: RoundTripTime,
    pub rttvar: RoundTripTime,
    pub rto: RoundTripTime,
}
