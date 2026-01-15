// Complete Congestion Control Algorithm Tests
// Tests for TCP-style congestion control as defined in design/protocol/07-data-transmission.md

use std::time::{Duration, Instant};

/// Congestion control constants from design spec
const INITIAL_CWND: u32 = 2;           // Initial congestion window (in MSS)
const INITIAL_SSTHRESH: u32 = 65535;   // Initial slow start threshold
const MSS: usize = 1460;               // Maximum segment size
const MIN_CWND: u32 = 1;               // Minimum congestion window
const MAX_CWND: u32 = 65535;           // Maximum congestion window

/// Congestion control states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    FastRecovery,
}

/// Congestion control engine for testing
struct CongestionControl {
    cwnd: u32,                          // Congestion window (in MSS)
    ssthresh: u32,                      // Slow start threshold
    state: CongestionState,
    duplicate_acks: u32,                // Count of duplicate ACKs
    recover_seq: u32,                   // Highest seq sent before entering recovery
    bytes_acked_in_recovery: u32,       // Bytes acked during fast recovery (for PRR)
    prr_delivered: u32,                 // PRR: bytes delivered during recovery
    prr_out: u32,                       // PRR: bytes sent during recovery
    flight_size: u32,                   // Current bytes in flight
    last_ack_time: Instant,
}

impl CongestionControl {
    fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            state: CongestionState::SlowStart,
            duplicate_acks: 0,
            recover_seq: 0,
            bytes_acked_in_recovery: 0,
            prr_delivered: 0,
            prr_out: 0,
            flight_size: 0,
            last_ack_time: Instant::now(),
        }
    }

    /// Process ACK during slow start
    fn process_ack_slow_start(&mut self, bytes_acked: u32) {
        // Slow start: cwnd += bytes_acked (exponential growth)
        self.cwnd += bytes_acked / MSS as u32;
        self.cwnd = self.cwnd.min(MAX_CWND);

        // Transition to congestion avoidance if cwnd >= ssthresh
        if self.cwnd >= self.ssthresh {
            self.state = CongestionState::CongestionAvoidance;
        }
    }

    /// Process ACK during congestion avoidance (AIMD)
    fn process_ack_congestion_avoidance(&mut self, bytes_acked: u32) {
        // AIMD: Additive Increase - cwnd += MSS * (bytes_acked / cwnd)
        // This approximates increasing cwnd by 1 MSS per RTT
        let increment = (MSS as u32 * bytes_acked) / (self.cwnd * MSS as u32);
        self.cwnd += increment.max(1);
        self.cwnd = self.cwnd.min(MAX_CWND);
    }

    /// Process ACK during fast recovery with PRR
    fn process_ack_fast_recovery(&mut self, bytes_acked: u32) {
        self.bytes_acked_in_recovery += bytes_acked;
        self.prr_delivered += bytes_acked;

        // PRR: Proportional Rate Reduction
        // Calculate how many bytes we can send
        let snd_cnt = if self.prr_delivered > self.prr_out {
            self.prr_delivered - self.prr_out
        } else {
            0
        };

        // Limit sending rate during recovery
        let allowed_bytes = snd_cnt.min(self.cwnd * MSS as u32);
        self.prr_out += allowed_bytes;
    }

    /// Handle duplicate ACK
    fn process_duplicate_ack(&mut self, seq: u32) {
        self.duplicate_acks += 1;

        if self.duplicate_acks == 3 {
            // Triple duplicate ACK: enter fast recovery
            self.enter_fast_recovery(seq);
        } else if self.duplicate_acks > 3 && self.state == CongestionState::FastRecovery {
            // Inflate cwnd for additional duplicate ACKs
            self.cwnd += 1;
        }
    }

    /// Enter fast recovery
    fn enter_fast_recovery(&mut self, seq: u32) {
        // Set ssthresh to max(flight_size/2, 2*MSS)
        self.ssthresh = (self.flight_size / 2).max(2 * MSS as u32) / MSS as u32;

        // Set cwnd to ssthresh + 3*MSS (for the 3 duplicate ACKs)
        self.cwnd = self.ssthresh + 3;

        self.state = CongestionState::FastRecovery;
        self.recover_seq = seq;

        // Initialize PRR
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.bytes_acked_in_recovery = 0;
    }

    /// Exit fast recovery
    fn exit_fast_recovery(&mut self) {
        // Deflate cwnd back to ssthresh
        self.cwnd = self.ssthresh;
        self.state = CongestionState::CongestionAvoidance;
        self.duplicate_acks = 0;
    }

    /// Handle timeout (multiplicative decrease)
    fn handle_timeout(&mut self) {
        // Set ssthresh to max(flight_size/2, 2*MSS)
        self.ssthresh = (self.flight_size / 2).max(2 * MSS as u32) / MSS as u32;

        // Reset cwnd to initial value
        self.cwnd = INITIAL_CWND;

        // Back to slow start
        self.state = CongestionState::SlowStart;
        self.duplicate_acks = 0;
    }

    /// Process new ACK (advances window)
    fn process_new_ack(&mut self, bytes_acked: u32, ack_seq: u32) {
        self.flight_size = self.flight_size.saturating_sub(bytes_acked);
        self.last_ack_time = Instant::now();

        match self.state {
            CongestionState::SlowStart => {
                self.process_ack_slow_start(bytes_acked);
            }
            CongestionState::CongestionAvoidance => {
                self.process_ack_congestion_avoidance(bytes_acked);
            }
            CongestionState::FastRecovery => {
                // Check if we've recovered
                if ack_seq >= self.recover_seq {
                    self.exit_fast_recovery();
                } else {
                    self.process_ack_fast_recovery(bytes_acked);
                }
            }
        }

        self.duplicate_acks = 0;
    }

    /// Send data (update flight size)
    fn send_data(&mut self, bytes: u32) {
        self.flight_size += bytes;
    }

    /// Get current congestion window in bytes
    fn get_cwnd_bytes(&self) -> u32 {
        self.cwnd * MSS as u32
    }

    /// Check if we can send more data
    fn can_send(&self) -> bool {
        self.flight_size < self.get_cwnd_bytes()
    }
}

#[test]
fn test_slow_start_exponential_growth() {
    let mut cc = CongestionControl::new();

    assert_eq!(cc.state, CongestionState::SlowStart);
    assert_eq!(cc.cwnd, INITIAL_CWND);

    // Send initial window
    cc.send_data(INITIAL_CWND * MSS as u32);

    // ACK first segment - cwnd should increase by 1 MSS
    cc.process_new_ack(MSS as u32, 1);
    assert_eq!(cc.cwnd, INITIAL_CWND + 1);

    // ACK second segment - cwnd should increase by 1 MSS
    cc.process_new_ack(MSS as u32, 2);
    assert_eq!(cc.cwnd, INITIAL_CWND + 2);

    // Verify exponential growth pattern
    let initial_cwnd = cc.cwnd;
    for _ in 0..initial_cwnd {
        cc.process_new_ack(MSS as u32, 0);
    }

    // After acking all segments, cwnd should roughly double
    assert!(cc.cwnd >= initial_cwnd * 2 - 1);
}

#[test]
fn test_slow_start_to_congestion_avoidance_transition() {
    let mut cc = CongestionControl::new();
    cc.ssthresh = 10; // Set low threshold for testing

    assert_eq!(cc.state, CongestionState::SlowStart);

    // Grow cwnd until it reaches ssthresh
    while cc.cwnd < cc.ssthresh {
        cc.process_new_ack(MSS as u32, 0);
    }

    // Should transition to congestion avoidance
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);
    assert!(cc.cwnd >= cc.ssthresh);
}

#[test]
fn test_congestion_avoidance_aimd_additive_increase() {
    let mut cc = CongestionControl::new();
    cc.state = CongestionState::CongestionAvoidance;
    cc.cwnd = 20;

    let initial_cwnd = cc.cwnd;

    // ACK one full window worth of data
    let window_bytes = cc.cwnd * MSS as u32;
    for _ in 0..cc.cwnd {
        cc.process_new_ack(MSS as u32, 0);
    }

    // After one RTT (one full window acked), cwnd should increase by approximately 1 MSS
    // Due to integer math, allow some tolerance
    assert!(cc.cwnd >= initial_cwnd);
    assert!(cc.cwnd <= initial_cwnd + 2); // Allow +1 or +2 due to rounding
}

#[test]
fn test_congestion_avoidance_aimd_growth_rate() {
    let mut cc = CongestionControl::new();
    cc.state = CongestionState::CongestionAvoidance;
    cc.cwnd = 100;

    let mut cwnd_history = vec![cc.cwnd];

    // Simulate 10 RTTs
    for _ in 0..10 {
        let window_size = cc.cwnd;
        for _ in 0..window_size {
            cc.process_new_ack(MSS as u32, 0);
        }
        cwnd_history.push(cc.cwnd);
    }

    // Verify linear growth (AIMD additive increase)
    // Each RTT should add approximately 1 MSS
    for i in 1..cwnd_history.len() {
        let growth = cwnd_history[i] as i32 - cwnd_history[i - 1] as i32;
        assert!(growth >= 0 && growth <= 2, "Growth should be ~1 MSS per RTT, got {}", growth);
    }
}

#[test]
fn test_triple_duplicate_ack_detection() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 20;
    cc.flight_size = 10 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    // First duplicate ACK
    cc.process_duplicate_ack(100);
    assert_eq!(cc.duplicate_acks, 1);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);

    // Second duplicate ACK
    cc.process_duplicate_ack(100);
    assert_eq!(cc.duplicate_acks, 2);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);

    // Third duplicate ACK - should trigger fast recovery
    cc.process_duplicate_ack(100);
    assert_eq!(cc.duplicate_acks, 3);
    assert_eq!(cc.state, CongestionState::FastRecovery);
}

#[test]
fn test_fast_recovery_entry_cwnd_adjustment() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 20;
    cc.flight_size = 15 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    let initial_cwnd = cc.cwnd;

    // Trigger fast recovery with triple duplicate ACK
    for _ in 0..3 {
        cc.process_duplicate_ack(100);
    }

    assert_eq!(cc.state, CongestionState::FastRecovery);

    // ssthresh should be set to flight_size / 2
    let expected_ssthresh = (15 * MSS as u32 / 2) / MSS as u32;
    assert_eq!(cc.ssthresh, expected_ssthresh);

    // cwnd should be ssthresh + 3 (for the 3 dup acks)
    assert_eq!(cc.cwnd, expected_ssthresh + 3);
}

#[test]
fn test_fast_recovery_cwnd_inflation() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 20;
    cc.flight_size = 15 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    // Enter fast recovery
    for _ in 0..3 {
        cc.process_duplicate_ack(100);
    }

    let cwnd_after_entry = cc.cwnd;

    // Additional duplicate ACKs should inflate cwnd
    cc.process_duplicate_ack(100);
    assert_eq!(cc.cwnd, cwnd_after_entry + 1);

    cc.process_duplicate_ack(100);
    assert_eq!(cc.cwnd, cwnd_after_entry + 2);

    cc.process_duplicate_ack(100);
    assert_eq!(cc.cwnd, cwnd_after_entry + 3);
}

#[test]
fn test_fast_recovery_exit_cwnd_deflation() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 20;
    cc.flight_size = 15 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    // Enter fast recovery
    for _ in 0..3 {
        cc.process_duplicate_ack(100);
    }

    let ssthresh = cc.ssthresh;

    // Inflate cwnd with additional dup acks
    for _ in 0..5 {
        cc.process_duplicate_ack(100);
    }

    assert!(cc.cwnd > ssthresh);

    // Exit fast recovery with new ACK
    cc.process_new_ack(MSS as u32, 100);

    // cwnd should be deflated back to ssthresh
    assert_eq!(cc.cwnd, ssthresh);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);
    assert_eq!(cc.duplicate_acks, 0);
}

#[test]
fn test_proportional_rate_reduction_basic() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 20;
    cc.flight_size = 15 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    // Enter fast recovery
    for _ in 0..3 {
        cc.process_duplicate_ack(100);
    }

    assert_eq!(cc.state, CongestionState::FastRecovery);
    assert_eq!(cc.prr_delivered, 0);
    assert_eq!(cc.prr_out, 0);

    // ACK some data during recovery
    cc.process_ack_fast_recovery(MSS as u32);
    assert_eq!(cc.prr_delivered, MSS as u32);
    assert!(cc.prr_out > 0);
}

#[test]
fn test_proportional_rate_reduction_rate_limiting() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 10;
    cc.flight_size = 8 * MSS as u32;

    // Enter fast recovery
    for _ in 0..3 {
        cc.process_duplicate_ack(100);
    }

    // Process multiple ACKs during recovery
    for _ in 0..5 {
        let prr_out_before = cc.prr_out;
        cc.process_ack_fast_recovery(MSS as u32);
        let prr_out_after = cc.prr_out;

        // PRR should limit the sending rate
        let sent = prr_out_after - prr_out_before;
        assert!(sent <= cc.cwnd * MSS as u32, "PRR should limit sending rate");
    }
}

#[test]
fn test_timeout_multiplicative_decrease() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 50;
    cc.flight_size = 40 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    let initial_cwnd = cc.cwnd;
    let flight_size = cc.flight_size;

    // Handle timeout
    cc.handle_timeout();

    // ssthresh should be set to max(flight_size/2, 2*MSS)
    let expected_ssthresh = (flight_size / 2).max(2 * MSS as u32) / MSS as u32;
    assert_eq!(cc.ssthresh, expected_ssthresh);

    // cwnd should be reset to initial value
    assert_eq!(cc.cwnd, INITIAL_CWND);
    assert!(cc.cwnd < initial_cwnd);

    // Should return to slow start
    assert_eq!(cc.state, CongestionState::SlowStart);
    assert_eq!(cc.duplicate_acks, 0);
}

#[test]
fn test_timeout_with_low_flight_size() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 50;
    cc.flight_size = MSS as u32; // Very low flight size
    cc.state = CongestionState::CongestionAvoidance;

    cc.handle_timeout();

    // ssthresh should be at least 2*MSS
    assert!(cc.ssthresh >= 2);
}

#[test]
fn test_cwnd_min_max_bounds() {
    let mut cc = CongestionControl::new();

    // Test minimum bound
    cc.cwnd = MIN_CWND;
    cc.handle_timeout();
    assert!(cc.cwnd >= MIN_CWND);

    // Test maximum bound
    cc.cwnd = MAX_CWND - 10;
    cc.state = CongestionState::SlowStart;

    // Try to grow beyond max
    for _ in 0..100 {
        cc.process_new_ack(MSS as u32, 0);
    }

    assert!(cc.cwnd <= MAX_CWND);
}

#[test]
fn test_flight_size_tracking() {
    let mut cc = CongestionControl::new();

    assert_eq!(cc.flight_size, 0);

    // Send data
    cc.send_data(5 * MSS as u32);
    assert_eq!(cc.flight_size, 5 * MSS as u32);

    // ACK some data
    cc.process_new_ack(2 * MSS as u32, 2);
    assert_eq!(cc.flight_size, 3 * MSS as u32);

    // ACK remaining data
    cc.process_new_ack(3 * MSS as u32, 5);
    assert_eq!(cc.flight_size, 0);
}

#[test]
fn test_can_send_flow_control() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 10;

    // Initially can send
    assert!(cc.can_send());

    // Send up to cwnd
    cc.send_data(10 * MSS as u32);
    assert!(!cc.can_send());

    // ACK some data
    cc.process_new_ack(5 * MSS as u32, 5);
    assert!(cc.can_send());
}

#[test]
fn test_complete_congestion_cycle() {
    let mut cc = CongestionControl::new();

    // Phase 1: Slow start
    assert_eq!(cc.state, CongestionState::SlowStart);
    cc.ssthresh = 20;

    while cc.cwnd < cc.ssthresh {
        cc.send_data(MSS as u32);
        cc.process_new_ack(MSS as u32, 0);
    }

    // Phase 2: Congestion avoidance
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);
    let ca_cwnd = cc.cwnd;

    for _ in 0..10 {
        cc.process_new_ack(MSS as u32, 0);
    }

    assert!(cc.cwnd > ca_cwnd);

    // Phase 3: Packet loss - enter fast recovery
    cc.flight_size = 15 * MSS as u32;
    for _ in 0..3 {
        cc.process_duplicate_ack(100);
    }

    assert_eq!(cc.state, CongestionState::FastRecovery);

    // Phase 4: Exit fast recovery
    cc.process_new_ack(MSS as u32, 100);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);
}

#[test]
fn test_fast_recovery_with_sack_integration() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 30;
    cc.flight_size = 25 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    // Enter fast recovery due to triple dup ack
    for _ in 0..3 {
        cc.process_duplicate_ack(1000);
    }

    assert_eq!(cc.state, CongestionState::FastRecovery);

    // Simulate selective ACKs during recovery
    // SACK indicates some packets received out of order
    cc.process_ack_fast_recovery(3 * MSS as u32);

    assert!(cc.prr_delivered > 0);
    assert!(cc.bytes_acked_in_recovery > 0);

    // Continue receiving SACKs
    cc.process_ack_fast_recovery(2 * MSS as u32);

    // Exit when all retransmitted data is acked
    cc.process_new_ack(MSS as u32, 1000);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);
}

#[test]
fn test_exactly_three_duplicate_acks() {
    let mut cc = CongestionControl::new();
    cc.state = CongestionState::CongestionAvoidance;
    cc.flight_size = 10 * MSS as u32;

    // Less than 3 dup acks should not trigger fast recovery
    cc.process_duplicate_ack(100);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);

    cc.process_duplicate_ack(100);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);

    // Exactly 3 should trigger
    cc.process_duplicate_ack(100);
    assert_eq!(cc.state, CongestionState::FastRecovery);
    assert_eq!(cc.duplicate_acks, 3);
}

#[test]
fn test_new_ack_resets_duplicate_ack_counter() {
    let mut cc = CongestionControl::new();
    cc.state = CongestionState::CongestionAvoidance;

    // Receive 2 duplicate ACKs
    cc.process_duplicate_ack(100);
    cc.process_duplicate_ack(100);
    assert_eq!(cc.duplicate_acks, 2);

    // New ACK should reset counter
    cc.process_new_ack(MSS as u32, 101);
    assert_eq!(cc.duplicate_acks, 0);

    // Should not enter fast recovery now
    cc.process_duplicate_ack(102);
    cc.process_duplicate_ack(102);
    assert_eq!(cc.state, CongestionState::CongestionAvoidance);
}

#[test]
fn test_ssthresh_update_on_loss() {
    let mut cc = CongestionControl::new();
    cc.cwnd = 50;
    cc.flight_size = 40 * MSS as u32;
    cc.state = CongestionState::CongestionAvoidance;

    let flight_size = cc.flight_size;

    // Trigger fast recovery
    for _ in 0..3 {
        cc.process_duplicate_ack(1000);
    }

    // ssthresh should be set to flight_size / 2
    let expected_ssthresh = (flight_size / 2) / MSS as u32;
    assert_eq!(cc.ssthresh, expected_ssthresh);
}

#[test]
fn test_congestion_window_growth_rate_validation() {
    let mut cc = CongestionControl::new();
    cc.state = CongestionState::CongestionAvoidance;
    cc.cwnd = 50;

    let initial_cwnd = cc.cwnd;

    // Simulate 100 RTTs worth of ACKs
    for _ in 0..100 {
        let window_size = cc.cwnd;
        for _ in 0..window_size {
            cc.process_new_ack(MSS as u32, 0);
        }
    }

    // In congestion avoidance, cwnd should grow by approximately 100 MSS (1 per RTT)
    // Allow some tolerance for integer math
    let expected_cwnd = initial_cwnd + 100;
    let tolerance = 10; // Allow ±10 MSS due to rounding

    assert!(
        cc.cwnd >= expected_cwnd - tolerance && cc.cwnd <= expected_cwnd + tolerance,
        "Expected cwnd ~{}, got {}", expected_cwnd, cc.cwnd
    );
}
