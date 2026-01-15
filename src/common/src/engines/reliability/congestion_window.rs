// Congestion window management for reliability engine
//
// Implements window-based congestion control:
// - Multiplicative decrease on loss (halve window)
// - AIMD (Additive Increase, Multiplicative Decrease)
// - Slow start with exponential growth
// - Transition to congestion avoidance at threshold
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::*;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, info, warn};

/// Congestion state for the window controller
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionWindowState {
    /// Slow start - exponential window growth
    SlowStart,
    /// Congestion avoidance - linear window growth
    CongestionAvoidance,
    /// Fast recovery - after detecting loss via duplicate ACKs
    FastRecovery,
}

/// Congestion window controller for reliability engine
///
/// Manages congestion window with AIMD and slow start algorithms
#[derive(Debug)]
pub struct CongestionWindowController {
    /// Current congestion window (in bytes)
    congestion_window: AtomicU32,

    /// Slow start threshold (in bytes)
    slow_start_threshold: AtomicU32,

    /// Current congestion state
    state: std::sync::Mutex<CongestionWindowState>,

    /// Maximum segment size (MSS) in bytes
    mss: u32,

    /// Maximum window size (in bytes)
    max_window: u32,

    /// Minimum window size (in bytes)
    min_window: u32,

    /// Bytes acknowledged in current RTT (for congestion avoidance)
    bytes_acked_in_rtt: AtomicU32,
}

impl CongestionWindowController {
    /// Create new congestion window controller
    ///
    /// # Arguments
    /// * `initial_window` - Initial congestion window in bytes
    /// * `mss` - Maximum segment size in bytes
    pub fn new(initial_window: u32, mss: u32) -> Self {
        let max_window = 65535; // Per spec
        let min_window = 2 * mss; // Minimum is 2*MSS

        Self {
            congestion_window: AtomicU32::new(initial_window),
            slow_start_threshold: AtomicU32::new(max_window),
            state: std::sync::Mutex::new(CongestionWindowState::SlowStart),
            mss,
            max_window,
            min_window,
            bytes_acked_in_rtt: AtomicU32::new(0),
        }
    }

    /// Get current congestion window size
    pub fn window(&self) -> u32 {
        self.congestion_window.load(Ordering::Relaxed)
    }

    /// Get current slow start threshold
    pub fn slow_start_threshold(&self) -> u32 {
        self.slow_start_threshold.load(Ordering::Relaxed)
    }

    /// Get current congestion state
    pub fn state(&self) -> CongestionWindowState {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Handle packet acknowledgment - grow window
    ///
    /// # Arguments
    /// * `bytes_acked` - Number of bytes acknowledged
    pub fn on_ack(&self, bytes_acked: u32) {
        let current_state = self.state();

        match current_state {
            CongestionWindowState::SlowStart => {
                self.slow_start_ack(bytes_acked);
            }
            CongestionWindowState::CongestionAvoidance => {
                self.congestion_avoidance_ack(bytes_acked);
            }
            CongestionWindowState::FastRecovery => {
                // In fast recovery, window inflation handled by duplicate ACK processing
                self.exit_fast_recovery();
            }
        }
    }

    /// Slow start acknowledgment processing
    ///
    /// Exponential growth: cwnd += bytes_acked
    fn slow_start_ack(&self, bytes_acked: u32) {
        let current_cwnd = self.congestion_window.load(Ordering::Relaxed);
        let ssthresh = self.slow_start_threshold.load(Ordering::Relaxed);

        // Exponential growth: increase by bytes_acked
        let new_cwnd = (current_cwnd + bytes_acked).min(self.max_window);
        self.congestion_window.store(new_cwnd, Ordering::Relaxed);

        debug!(
            old_cwnd = current_cwnd,
            new_cwnd, bytes_acked, "Slow start: increased window"
        );

        // Transition to congestion avoidance if we reach threshold
        if new_cwnd >= ssthresh {
            *self.state.lock().unwrap_or_else(|e| e.into_inner()) =
                CongestionWindowState::CongestionAvoidance;

            info!(
                cwnd = new_cwnd,
                ssthresh, "Transitioned from slow start to congestion avoidance"
            );
        }
    }

    /// Congestion avoidance acknowledgment processing
    ///
    /// Additive increase: cwnd += MSS * MSS / cwnd per RTT
    fn congestion_avoidance_ack(&self, bytes_acked: u32) {
        let bytes_in_rtt = self
            .bytes_acked_in_rtt
            .fetch_add(bytes_acked, Ordering::Relaxed)
            + bytes_acked;

        let current_cwnd = self.congestion_window.load(Ordering::Relaxed);

        // Simple approximation: increase by 1 MSS when we've acked roughly cwnd bytes
        if bytes_in_rtt >= current_cwnd {
            let new_cwnd = (current_cwnd + self.mss).min(self.max_window);
            self.congestion_window.store(new_cwnd, Ordering::Relaxed);
            self.bytes_acked_in_rtt.store(0, Ordering::Relaxed);

            debug!(
                old_cwnd = current_cwnd,
                new_cwnd, bytes_in_rtt, "Congestion avoidance: increased window"
            );
        }
    }

    /// Handle loss detection - reduce window (multiplicative decrease)
    ///
    /// Halves the congestion window and sets slow start threshold
    pub fn on_loss(&self) {
        let current_cwnd = self.congestion_window.load(Ordering::Relaxed);

        // Multiplicative decrease: ssthresh = cwnd/2 (can be less than min_window)
        let new_ssthresh = current_cwnd / 2;
        self.slow_start_threshold
            .store(new_ssthresh, Ordering::Relaxed);

        // Reset to slow start with minimum window
        let new_cwnd = self.min_window;
        self.congestion_window.store(new_cwnd, Ordering::Relaxed);

        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = CongestionWindowState::SlowStart;

        warn!(
            old_cwnd = current_cwnd,
            new_cwnd, new_ssthresh, "Loss detected: reduced window and reset to slow start"
        );

        // Reset RTT tracking
        self.bytes_acked_in_rtt.store(0, Ordering::Relaxed);
    }

    /// Handle duplicate ACK (fast retransmit trigger)
    ///
    /// Enters fast recovery with reduced threshold
    pub fn on_duplicate_ack(&self) {
        let current_state = self.state();

        // Only enter fast recovery if not already in it
        if current_state != CongestionWindowState::FastRecovery {
            let current_cwnd = self.congestion_window.load(Ordering::Relaxed);

            // Set ssthresh = cwnd/2 (standard multiplicative decrease)
            let new_ssthresh = current_cwnd / 2;
            self.slow_start_threshold
                .store(new_ssthresh, Ordering::Relaxed);

            // Set cwnd = ssthresh + 3*MSS (for the 3 duplicate ACKs)
            let new_cwnd = new_ssthresh + 3 * self.mss;
            self.congestion_window.store(new_cwnd, Ordering::Relaxed);

            *self.state.lock().unwrap_or_else(|e| e.into_inner()) =
                CongestionWindowState::FastRecovery;

            warn!(
                old_cwnd = current_cwnd,
                new_cwnd, new_ssthresh, "Entered fast recovery after duplicate ACKs"
            );
        } else {
            // Already in fast recovery, inflate window
            let current_cwnd = self.congestion_window.load(Ordering::Relaxed);
            let new_cwnd = (current_cwnd + self.mss).min(self.max_window);
            self.congestion_window.store(new_cwnd, Ordering::Relaxed);

            debug!(
                old_cwnd = current_cwnd,
                new_cwnd, "Fast recovery: inflated window"
            );
        }
    }

    /// Exit fast recovery
    fn exit_fast_recovery(&self) {
        let ssthresh = self.slow_start_threshold.load(Ordering::Relaxed);
        self.congestion_window.store(ssthresh, Ordering::Relaxed);

        *self.state.lock().unwrap_or_else(|e| e.into_inner()) =
            CongestionWindowState::CongestionAvoidance;

        info!(cwnd = ssthresh, "Exited fast recovery");

        // Reset RTT tracking
        self.bytes_acked_in_rtt.store(0, Ordering::Relaxed);
    }

    /// Reset congestion window to initial state
    pub fn reset(&self, initial_window: u32) {
        self.congestion_window
            .store(initial_window, Ordering::Relaxed);
        self.slow_start_threshold
            .store(self.max_window, Ordering::Relaxed);
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = CongestionWindowState::SlowStart;
        self.bytes_acked_in_rtt.store(0, Ordering::Relaxed);

        debug!(initial_window, "Reset congestion window");
    }

    /// Get congestion window statistics
    pub fn stats(&self) -> CongestionWindowStats {
        CongestionWindowStats {
            congestion_window: CongestionWindow::new(self.window()),
            slow_start_threshold: SlowStartThreshold::new(self.slow_start_threshold()),
            state: self.state(),
        }
    }
}

/// Congestion window statistics snapshot
#[derive(Debug, Clone)]
pub struct CongestionWindowStats {
    pub congestion_window: CongestionWindow,
    pub slow_start_threshold: SlowStartThreshold,
    pub state: CongestionWindowState,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MSS: u32 = 1460;
    const INITIAL_CWND: u32 = 2920; // 2 * MSS

    #[test]
    fn test_window_creation() {
        let controller = CongestionWindowController::new(INITIAL_CWND, TEST_MSS);

        assert_eq!(controller.window(), INITIAL_CWND);
        assert_eq!(controller.state(), CongestionWindowState::SlowStart);
        assert_eq!(controller.slow_start_threshold(), 65535);
    }

    #[test]
    fn test_window_reduction_on_loss() {
        let controller = CongestionWindowController::new(10000, TEST_MSS);

        let initial_window = controller.window();
        controller.on_loss();

        let new_window = controller.window();
        let new_ssthresh = controller.slow_start_threshold();

        // Window should be reset to min_window (2*MSS)
        assert_eq!(new_window, 2 * TEST_MSS);

        // ssthresh should be half of old window
        assert_eq!(new_ssthresh, initial_window / 2);

        // Should be back in slow start
        assert_eq!(controller.state(), CongestionWindowState::SlowStart);
    }

    #[test]
    fn test_slow_start_exponential_growth() {
        let controller = CongestionWindowController::new(INITIAL_CWND, TEST_MSS);

        let initial = controller.window();

        // Ack 1 MSS worth of data
        controller.on_ack(TEST_MSS);
        assert_eq!(controller.window(), initial + TEST_MSS);

        // Ack another MSS
        controller.on_ack(TEST_MSS);
        assert_eq!(controller.window(), initial + 2 * TEST_MSS);

        // Still in slow start
        assert_eq!(controller.state(), CongestionWindowState::SlowStart);
    }

    #[test]
    fn test_transition_to_congestion_avoidance() {
        let controller = CongestionWindowController::new(INITIAL_CWND, TEST_MSS);

        // Set a low threshold
        controller
            .slow_start_threshold
            .store(INITIAL_CWND + TEST_MSS, Ordering::Relaxed);

        // This ACK should push us past threshold
        controller.on_ack(TEST_MSS);

        // Should transition to congestion avoidance
        assert_eq!(
            controller.state(),
            CongestionWindowState::CongestionAvoidance
        );
    }

    #[test]
    fn test_congestion_avoidance_linear_growth() {
        let controller = CongestionWindowController::new(10000, TEST_MSS);

        // Force into congestion avoidance
        *controller.state.lock().unwrap_or_else(|e| e.into_inner()) =
            CongestionWindowState::CongestionAvoidance;

        let initial = controller.window();

        // Ack a full window worth of data (should increase by 1 MSS)
        controller.on_ack(initial);

        assert_eq!(controller.window(), initial + TEST_MSS);
        assert_eq!(
            controller.state(),
            CongestionWindowState::CongestionAvoidance
        );
    }

    #[test]
    fn test_fast_recovery_entry() {
        let controller = CongestionWindowController::new(10000, TEST_MSS);

        let initial_window = controller.window();
        controller.on_duplicate_ack();

        let new_window = controller.window();
        let new_ssthresh = controller.slow_start_threshold();

        // ssthresh = cwnd / 2
        assert_eq!(new_ssthresh, initial_window / 2);

        // cwnd = ssthresh + 3*MSS
        assert_eq!(new_window, new_ssthresh + 3 * TEST_MSS);

        // Should be in fast recovery
        assert_eq!(controller.state(), CongestionWindowState::FastRecovery);
    }

    #[test]
    fn test_fast_recovery_window_inflation() {
        let controller = CongestionWindowController::new(10000, TEST_MSS);

        // Enter fast recovery
        controller.on_duplicate_ack();
        let window_after_entry = controller.window();

        // Additional duplicate ACK should inflate window
        controller.on_duplicate_ack();
        assert_eq!(controller.window(), window_after_entry + TEST_MSS);
    }

    #[test]
    fn test_aimd_pattern() {
        let controller = CongestionWindowController::new(INITIAL_CWND, TEST_MSS);

        // Slow start growth
        for _ in 0..5 {
            controller.on_ack(TEST_MSS);
        }
        let after_slow_start = controller.window();
        assert!(after_slow_start > INITIAL_CWND);

        // Trigger loss
        controller.on_loss();
        let after_loss = controller.window();
        assert_eq!(after_loss, 2 * TEST_MSS); // Reset to min

        // Grow again (multiplicative decrease worked, now additive increase)
        for _ in 0..3 {
            controller.on_ack(TEST_MSS);
        }
        assert!(controller.window() > after_loss);
    }

    #[test]
    fn test_reset() {
        let controller = CongestionWindowController::new(INITIAL_CWND, TEST_MSS);

        // Make some changes
        controller.on_ack(TEST_MSS);
        controller.on_loss();

        // Reset
        let new_initial = 5000;
        controller.reset(new_initial);

        assert_eq!(controller.window(), new_initial);
        assert_eq!(controller.state(), CongestionWindowState::SlowStart);
        assert_eq!(controller.slow_start_threshold(), 65535);
    }

    #[test]
    fn test_window_bounds() {
        let controller = CongestionWindowController::new(INITIAL_CWND, TEST_MSS);

        // Set window near max
        controller.congestion_window.store(65000, Ordering::Relaxed);

        // Try to grow beyond max
        controller.on_ack(TEST_MSS);

        // Should be clamped to max
        assert!(controller.window() <= 65535);

        // Loss should respect minimum
        controller.on_loss();
        assert_eq!(controller.window(), 2 * TEST_MSS);
    }
}
