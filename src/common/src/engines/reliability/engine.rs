// Reliability engine - high-level interface composing all reliability components
//
// Provides unified interface for retransmission management, SACK processing,
// and statistics tracking.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::engines::reliability::{
    CongestionWindowController, RetransmissionEngine, RetransmissionStats, SackBlock, SackProcessor,
};
use crate::error::EngineError;
use crate::protocol::types::*;
use std::time::Instant;

const DEFAULT_MSS: u32 = 1460;
const DEFAULT_INITIAL_CWND: u32 = 2920; // 2 * MSS

/// Unified reliability engine composing retransmission and SACK functionality
#[derive(Debug)]
pub struct ReliabilityEngine {
    /// Retransmission tracking and timeout management
    retransmission: RetransmissionEngine,

    /// SACK processing for selective acknowledgments
    sack: SackProcessor,

    /// Congestion window management
    congestion_window: CongestionWindowController,

    /// Statistics tracking
    stats: RetransmissionStats,
}

impl ReliabilityEngine {
    /// Create new reliability engine
    pub fn new(initial_sequence: SequenceNumber, initial_ack: SequenceNumber) -> Self {
        Self {
            retransmission: RetransmissionEngine::new(initial_sequence),
            sack: SackProcessor::new(initial_ack),
            congestion_window: CongestionWindowController::new(DEFAULT_INITIAL_CWND, DEFAULT_MSS),
            stats: RetransmissionStats::new(),
        }
    }

    /// Track a sent packet
    ///
    /// Returns the RTO value for setting the retransmission timer
    pub fn track_sent_packet(&mut self, sequence_number: SequenceNumber) -> Timeout {
        self.stats.record_sent();
        self.retransmission.track_sent_packet(sequence_number)
    }

    /// Handle acknowledgment of a packet
    ///
    /// Updates RTO, advances SACK state, records statistics, and adjusts congestion window
    pub fn handle_acknowledgment(&mut self, sequence_number: SequenceNumber) {
        let ack_time = Instant::now();

        // Update retransmission state and RTO
        self.retransmission
            .handle_acknowledgment(sequence_number, ack_time);

        // Update SACK state
        let advanced = self.sack.record_received(sequence_number);

        // Record statistics
        self.stats.record_ack();

        // Update congestion window (assume 1 MSS worth of data per packet)
        self.congestion_window.on_ack(DEFAULT_MSS);

        // If we advanced cumulative ACK, may have more packets to acknowledge
        if advanced {
            // Additional packets were acknowledged by advancing window
            // (handled by SACK processor internally)
        }
    }

    /// Handle selective acknowledgment blocks
    ///
    /// Processes SACK blocks and returns sequence numbers needing retransmission
    pub fn handle_sack_blocks(
        &mut self,
        sack_blocks: &[SackBlock],
        send_unacked: SequenceNumber,
        send_next: SequenceNumber,
    ) -> Vec<SequenceNumber> {
        // Acknowledge packets in SACK blocks
        for block in sack_blocks {
            for seq in block.start.as_u32()..block.end.as_u32() {
                let seq_num = SequenceNumber::new(seq);
                self.retransmission
                    .handle_acknowledgment(seq_num, Instant::now());
                self.stats.record_ack();
            }
        }

        // Identify missing packets for selective retransmission
        self.sack
            .identify_missing_packets(sack_blocks, send_unacked, send_next)
    }

    /// Generate SACK blocks for current receive state
    pub fn generate_sack_blocks(&self) -> Vec<SackBlock> {
        self.sack.generate_sack_blocks()
    }

    /// Check for retransmission timeouts
    ///
    /// Returns sequence numbers of packets that need retransmission
    pub fn check_timeouts(
        &mut self,
        current_time: Instant,
    ) -> Result<Vec<SequenceNumber>, EngineError> {
        self.retransmission.check_timeouts(current_time)
    }

    /// Handle timeout for a specific packet
    ///
    /// Applies exponential backoff, reduces congestion window, and returns whether to retransmit
    pub fn handle_packet_timeout(
        &mut self,
        sequence_number: SequenceNumber,
    ) -> Result<bool, EngineError> {
        // Reduce congestion window on timeout (loss detection)
        self.congestion_window.on_loss();

        match self.retransmission.handle_timeout(sequence_number) {
            Ok(should_retransmit) => {
                if should_retransmit {
                    self.stats.record_retransmission();
                }
                Ok(should_retransmit)
            }
            Err(e) => {
                // Max retransmissions exceeded
                self.stats.record_lost();
                Err(e)
            }
        }
    }

    /// Trigger fast retransmit for specific packets
    ///
    /// Used when SACK indicates packet loss (enters fast recovery)
    pub fn fast_retransmit(&mut self, sequence_numbers: &[SequenceNumber]) {
        if !sequence_numbers.is_empty() {
            // Enter fast recovery on first missing packet
            self.congestion_window.on_duplicate_ack();
        }

        for _seq in sequence_numbers {
            self.stats.record_fast_retransmit();
            self.stats.record_retransmission();
        }
    }

    /// Get current cumulative ACK value
    pub fn cumulative_ack(&self) -> SequenceNumber {
        self.sack.cumulative_ack()
    }

    /// Get current RTO value
    pub fn current_rto(&self) -> Timeout {
        self.retransmission.current_rto()
    }

    /// Get number of pending packets
    pub fn pending_count(&self) -> usize {
        self.retransmission.pending_count()
    }

    /// Get number of out-of-order packets
    pub fn out_of_order_count(&self) -> usize {
        self.sack.out_of_order_count()
    }

    /// Get statistics
    pub fn stats(&self) -> &RetransmissionStats {
        &self.stats
    }

    /// Get current congestion window size
    pub fn congestion_window(&self) -> u32 {
        self.congestion_window.window()
    }

    /// Get current slow start threshold
    pub fn slow_start_threshold(&self) -> u32 {
        self.congestion_window.slow_start_threshold()
    }

    /// Get current congestion window state
    pub fn congestion_state(&self) -> crate::engines::reliability::CongestionWindowState {
        self.congestion_window.state()
    }

    /// Reset engine state
    pub fn reset(&mut self, initial_sequence: SequenceNumber, initial_ack: SequenceNumber) {
        self.retransmission.reset(initial_sequence);
        self.sack.reset(initial_ack);
        self.congestion_window.reset(DEFAULT_INITIAL_CWND);
        self.stats.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        assert_eq!(engine.cumulative_ack().as_u32(), 1000);
        assert_eq!(engine.pending_count(), 0);
    }

    #[test]
    fn test_track_and_acknowledge() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        let seq = SequenceNumber::new(1000);
        engine.track_sent_packet(seq);
        assert_eq!(engine.pending_count(), 1);

        engine.handle_acknowledgment(seq);
        assert_eq!(engine.pending_count(), 0);
        assert_eq!(engine.cumulative_ack().as_u32(), 1001);
    }

    #[test]
    fn test_sack_processing() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        // Send packets 1000-1005
        for i in 0..6 {
            engine.track_sent_packet(SequenceNumber::new(1000 + i));
        }

        // Receive 1002-1004 (out of order)
        let sack_blocks = vec![SackBlock::new(
            SequenceNumber::new(1002),
            SequenceNumber::new(1005),
        )];

        let missing = engine.handle_sack_blocks(
            &sack_blocks,
            SequenceNumber::new(1000),
            SequenceNumber::new(1006),
        );

        // Should identify 1000, 1001, 1005 as missing
        assert_eq!(missing.len(), 3);
        assert!(missing.contains(&SequenceNumber::new(1000)));
        assert!(missing.contains(&SequenceNumber::new(1001)));
        assert!(missing.contains(&SequenceNumber::new(1005)));
    }

    #[test]
    fn test_timeout_handling() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        let seq = SequenceNumber::new(1000);
        engine.track_sent_packet(seq);

        // Simulate timeout
        let result = engine.handle_packet_timeout(seq);
        assert!(result.is_ok());
        assert_eq!(engine.stats().retransmissions(), 1);
    }

    #[test]
    fn test_statistics() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        // Send and acknowledge packets
        for i in 0..5 {
            let seq = SequenceNumber::new(1000 + i);
            engine.track_sent_packet(seq);
            engine.handle_acknowledgment(seq);
        }

        assert_eq!(engine.stats().packets_sent(), 5);
        assert_eq!(engine.stats().packets_acked(), 5);
        assert!((engine.stats().ack_success_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_reset() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        engine.track_sent_packet(SequenceNumber::new(1000));
        assert_eq!(engine.pending_count(), 1);

        engine.reset(SequenceNumber::new(2000), SequenceNumber::new(2000));
        assert_eq!(engine.pending_count(), 0);
        assert_eq!(engine.cumulative_ack().as_u32(), 2000);
    }

    // Congestion window tests

    #[test]
    fn test_window_reduction_on_timeout() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        // Track a packet
        let seq = SequenceNumber::new(1000);
        engine.track_sent_packet(seq);

        // Get initial window
        let initial_window = engine.congestion_window();
        assert_eq!(initial_window, DEFAULT_INITIAL_CWND);

        // Trigger timeout (loss detection)
        let result = engine.handle_packet_timeout(seq);
        assert!(result.is_ok());

        // Window should be reduced to minimum (2*MSS)
        let new_window = engine.congestion_window();
        assert_eq!(new_window, 2 * DEFAULT_MSS);

        // Slow start threshold should be half of old window
        let ssthresh = engine.slow_start_threshold();
        assert_eq!(ssthresh, initial_window / 2);
    }

    #[test]
    fn test_window_growth_on_ack() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        let initial_window = engine.congestion_window();

        // Send and ack a packet
        let seq = SequenceNumber::new(1000);
        engine.track_sent_packet(seq);
        engine.handle_acknowledgment(seq);

        // Window should grow (slow start)
        let new_window = engine.congestion_window();
        assert!(new_window > initial_window);
        assert_eq!(new_window, initial_window + DEFAULT_MSS);
    }

    #[test]
    fn test_slow_start_exponential_growth() {
        use crate::engines::reliability::CongestionWindowState;

        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        let initial_window = engine.congestion_window();
        assert_eq!(engine.congestion_state(), CongestionWindowState::SlowStart);

        // Send and ack multiple packets
        for i in 0..5 {
            let seq = SequenceNumber::new(1000 + i);
            engine.track_sent_packet(seq);
            engine.handle_acknowledgment(seq);
        }

        // Window should grow exponentially
        let new_window = engine.congestion_window();
        assert_eq!(new_window, initial_window + 5 * DEFAULT_MSS);
    }

    #[test]
    fn test_transition_to_congestion_avoidance() {
        use crate::engines::reliability::CongestionWindowState;

        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        // Start in slow start
        assert_eq!(engine.congestion_state(), CongestionWindowState::SlowStart);

        // Ack packets until we exceed threshold
        let mut seq = 1000;
        loop {
            let sequence = SequenceNumber::new(seq);
            engine.track_sent_packet(sequence);
            engine.handle_acknowledgment(sequence);
            seq += 1;

            // Check if we've transitioned
            if engine.congestion_state() == CongestionWindowState::CongestionAvoidance {
                break;
            }

            // Safety limit
            if seq > 2000 {
                panic!("Should have transitioned to congestion avoidance");
            }
        }

        assert_eq!(
            engine.congestion_state(),
            CongestionWindowState::CongestionAvoidance
        );
    }

    #[test]
    fn test_aimd_pattern() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        let initial_window = engine.congestion_window();

        // Grow window in slow start
        for i in 0..10 {
            let seq = SequenceNumber::new(1000 + i);
            engine.track_sent_packet(seq);
            engine.handle_acknowledgment(seq);
        }

        let after_growth = engine.congestion_window();
        assert!(after_growth > initial_window);

        // Trigger loss (multiplicative decrease)
        let seq_loss = SequenceNumber::new(2000);
        engine.track_sent_packet(seq_loss);
        let _ = engine.handle_packet_timeout(seq_loss);

        let after_loss = engine.congestion_window();
        assert_eq!(after_loss, 2 * DEFAULT_MSS); // Back to minimum

        // Grow again (additive increase)
        for i in 0..5 {
            let seq = SequenceNumber::new(3000 + i);
            engine.track_sent_packet(seq);
            engine.handle_acknowledgment(seq);
        }

        let after_recovery = engine.congestion_window();
        assert!(after_recovery > after_loss);
    }

    #[test]
    fn test_fast_recovery_on_sack_loss() {
        use crate::engines::reliability::CongestionWindowState;

        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        // Send packets 1000-1005
        for i in 0..6 {
            engine.track_sent_packet(SequenceNumber::new(1000 + i));
        }

        // Get initial window
        let initial_window = engine.congestion_window();

        // SACK indicates missing packets (triggers fast retransmit)
        let missing = vec![SequenceNumber::new(1000), SequenceNumber::new(1001)];
        engine.fast_retransmit(&missing);

        // Should enter fast recovery
        assert_eq!(
            engine.congestion_state(),
            CongestionWindowState::FastRecovery
        );

        // Window should be reduced but not to minimum
        let new_window = engine.congestion_window();
        let new_ssthresh = engine.slow_start_threshold();

        // ssthresh = cwnd / 2
        assert_eq!(new_ssthresh, initial_window / 2);

        // cwnd = ssthresh + 3*MSS
        assert_eq!(new_window, new_ssthresh + 3 * DEFAULT_MSS);
    }

    #[test]
    fn test_congestion_window_bounds() {
        let mut engine =
            ReliabilityEngine::new(SequenceNumber::new(1000), SequenceNumber::new(1000));

        // Loss should respect minimum
        let seq = SequenceNumber::new(1000);
        engine.track_sent_packet(seq);
        let _ = engine.handle_packet_timeout(seq);

        assert_eq!(engine.congestion_window(), 2 * DEFAULT_MSS);

        // Window should not exceed maximum (tested implicitly through normal operation)
        // The controller internally clamps to max_window
    }
}
