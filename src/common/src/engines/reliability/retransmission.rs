// Packet retransmission management
//
// Tracks sent packets, manages retransmission timers, and handles
// retransmission attempts with exponential backoff.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::engines::reliability::RtoCalculator;
use crate::error::EngineError;
use crate::protocol::types::*;
use std::collections::HashMap;
use std::time::Instant;

/// Maximum retransmission attempts before connection failure
const MAX_RETRANSMISSION_ATTEMPTS: u8 = 8;

/// Information about a sent packet awaiting acknowledgment
#[derive(Debug, Clone)]
pub struct PacketTimingInfo {
    /// Sequence number of the packet
    pub sequence_number: SequenceNumber,

    /// Time when packet was sent
    pub send_time: Instant,

    /// Number of retransmission attempts
    pub retransmit_count: Counter,

    /// Whether this packet has been retransmitted
    pub retransmitted: bool,

    /// When the retransmission timer expires
    pub timer_expiry: Option<Instant>,
}

impl PacketTimingInfo {
    /// Create new timing info for a sent packet
    pub fn new(sequence_number: SequenceNumber, send_time: Instant) -> Self {
        Self {
            sequence_number,
            send_time,
            retransmit_count: Counter::new(0),
            retransmitted: false,
            timer_expiry: None,
        }
    }

    /// Mark packet as retransmitted
    pub fn mark_retransmitted(&mut self, new_send_time: Instant) {
        self.retransmitted = true;
        self.send_time = new_send_time;
        self.retransmit_count = Counter::new(self.retransmit_count.as_u64() + 1);
    }

    /// Check if maximum retransmission attempts reached
    pub fn max_attempts_reached(&self) -> bool {
        self.retransmit_count.as_u64() >= MAX_RETRANSMISSION_ATTEMPTS as u64
    }
}

/// Retransmission state tracking
#[derive(Debug)]
pub struct RetransmissionState {
    /// RTO calculator for timeout calculation
    rto_calculator: RtoCalculator,

    /// Packets awaiting acknowledgment
    pending_packets: HashMap<u32, PacketTimingInfo>,

    /// Next sequence number to assign
    next_sequence: SequenceNumber,
}

impl RetransmissionState {
    /// Create new retransmission state
    pub fn new(initial_sequence: SequenceNumber) -> Self {
        Self {
            rto_calculator: RtoCalculator::new(),
            pending_packets: HashMap::new(),
            next_sequence: initial_sequence,
        }
    }

    /// Get current RTO value
    pub fn current_rto(&self) -> Timeout {
        self.rto_calculator.current_rto()
    }

    /// Get number of pending packets
    pub fn pending_count(&self) -> usize {
        self.pending_packets.len()
    }

    /// Get reference to RTO calculator
    pub fn rto_calculator(&self) -> &RtoCalculator {
        &self.rto_calculator
    }

    /// Get mutable reference to RTO calculator
    pub fn rto_calculator_mut(&mut self) -> &mut RtoCalculator {
        &mut self.rto_calculator
    }
}

/// Retransmission engine for managing packet retransmissions
#[derive(Debug)]
pub struct RetransmissionEngine {
    state: RetransmissionState,
}

impl RetransmissionEngine {
    /// Create new retransmission engine
    pub fn new(initial_sequence: SequenceNumber) -> Self {
        Self {
            state: RetransmissionState::new(initial_sequence),
        }
    }

    /// Track a sent packet for potential retransmission
    ///
    /// Returns the RTO value for setting the retransmission timer
    pub fn track_sent_packet(&mut self, sequence_number: SequenceNumber) -> Timeout {
        let send_time = Instant::now();
        let rto = self.state.rto_calculator.current_rto();

        let mut timing_info = PacketTimingInfo::new(sequence_number, send_time);
        timing_info.timer_expiry = Some(send_time + std::time::Duration::from_millis(rto.as_u64()));

        self.state
            .pending_packets
            .insert(sequence_number.as_u32(), timing_info);

        rto
    }

    /// Handle acknowledgment of a packet
    ///
    /// Updates RTO based on RTT measurement if packet was not retransmitted
    pub fn handle_acknowledgment(&mut self, sequence_number: SequenceNumber, ack_time: Instant) {
        if let Some(timing_info) = self.state.pending_packets.remove(&sequence_number.as_u32()) {
            // Only measure RTT for non-retransmitted packets
            if !timing_info.retransmitted {
                let rtt_sample = self
                    .state
                    .rto_calculator
                    .measure_rtt(timing_info.send_time, ack_time);
                self.state.rto_calculator.update_rto(rtt_sample);
            }
        }
    }

    /// Check for expired retransmission timers
    ///
    /// Returns sequence numbers of packets that need retransmission
    pub fn check_timeouts(
        &mut self,
        current_time: Instant,
    ) -> Result<Vec<SequenceNumber>, EngineError> {
        let mut expired = Vec::new();

        for (seq_num, timing_info) in &self.state.pending_packets {
            if let Some(expiry) = timing_info.timer_expiry {
                if current_time >= expiry {
                    expired.push(*seq_num);
                }
            }
        }

        Ok(expired.into_iter().map(SequenceNumber::new).collect())
    }

    /// Handle retransmission timer expiry for a packet
    ///
    /// Returns Ok(should_retransmit) or Err if max attempts exceeded
    pub fn handle_timeout(&mut self, sequence_number: SequenceNumber) -> Result<bool, EngineError> {
        let timing_info = self
            .state
            .pending_packets
            .get_mut(&sequence_number.as_u32())
            .ok_or_else(|| {
                EngineError::flow_control_error("Packet not found for timeout handling")
            })?;

        // Check if maximum retries exceeded
        if timing_info.max_attempts_reached() {
            return Err(EngineError::flow_control_error(
                "Maximum retransmission attempts exceeded",
            ));
        }

        // Handle RTO timeout (exponential backoff)
        let new_rto = self.state.rto_calculator.handle_retransmission_timeout();

        // Mark packet as retransmitted
        let send_time = Instant::now();
        timing_info.mark_retransmitted(send_time);
        timing_info.timer_expiry =
            Some(send_time + std::time::Duration::from_millis(new_rto.as_u64()));

        Ok(true)
    }

    /// Remove a packet from tracking (connection termination or cleanup)
    pub fn remove_packet(&mut self, sequence_number: SequenceNumber) {
        self.state.pending_packets.remove(&sequence_number.as_u32());
    }

    /// Get packet timing info if exists
    pub fn get_packet_info(&self, sequence_number: SequenceNumber) -> Option<&PacketTimingInfo> {
        self.state.pending_packets.get(&sequence_number.as_u32())
    }

    /// Get current RTO value
    pub fn current_rto(&self) -> Timeout {
        self.state.current_rto()
    }

    /// Get number of pending packets
    pub fn pending_count(&self) -> usize {
        self.state.pending_count()
    }

    /// Reset state (for connection establishment or recovery)
    pub fn reset(&mut self, initial_sequence: SequenceNumber) {
        self.state.pending_packets.clear();
        self.state.rto_calculator.reset();
        self.state.next_sequence = initial_sequence;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_track_sent_packet() {
        let mut engine = RetransmissionEngine::new(SequenceNumber::new(1000));
        let seq = SequenceNumber::new(1000);

        let rto = engine.track_sent_packet(seq);
        assert!(rto.as_u64() > 0);
        assert_eq!(engine.pending_count(), 1);
    }

    #[test]
    fn test_handle_acknowledgment() {
        let mut engine = RetransmissionEngine::new(SequenceNumber::new(1000));
        let seq = SequenceNumber::new(1000);

        engine.track_sent_packet(seq);
        assert_eq!(engine.pending_count(), 1);

        let ack_time = Instant::now();
        engine.handle_acknowledgment(seq, ack_time);
        assert_eq!(engine.pending_count(), 0);
    }

    #[test]
    fn test_timeout_handling() {
        let mut engine = RetransmissionEngine::new(SequenceNumber::new(1000));
        let seq = SequenceNumber::new(1000);

        engine.track_sent_packet(seq);

        // Should succeed first time
        let result = engine.handle_timeout(seq);
        assert!(result.is_ok());

        // Get packet info
        let info = engine.get_packet_info(seq);
        assert!(info.is_some());
        assert_eq!(info.map(|i| i.retransmit_count.as_u64()), Some(1));
    }

    #[test]
    fn test_max_retransmission_attempts() {
        let mut engine = RetransmissionEngine::new(SequenceNumber::new(1000));
        let seq = SequenceNumber::new(1000);

        engine.track_sent_packet(seq);

        // Exhaust retransmission attempts
        for _ in 0..MAX_RETRANSMISSION_ATTEMPTS {
            let result = engine.handle_timeout(seq);
            assert!(result.is_ok());
        }

        // Next attempt should fail
        let result = engine.handle_timeout(seq);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_packet() {
        let mut engine = RetransmissionEngine::new(SequenceNumber::new(1000));
        let seq = SequenceNumber::new(1000);

        engine.track_sent_packet(seq);
        assert_eq!(engine.pending_count(), 1);

        engine.remove_packet(seq);
        assert_eq!(engine.pending_count(), 0);
    }

    #[test]
    fn test_reset() {
        let mut engine = RetransmissionEngine::new(SequenceNumber::new(1000));

        engine.track_sent_packet(SequenceNumber::new(1000));
        engine.track_sent_packet(SequenceNumber::new(1001));
        assert_eq!(engine.pending_count(), 2);

        engine.reset(SequenceNumber::new(2000));
        assert_eq!(engine.pending_count(), 0);
    }
}
