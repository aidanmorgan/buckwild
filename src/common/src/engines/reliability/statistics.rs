// Retransmission statistics tracking
//
// Tracks metrics about packet retransmissions, RTT measurements,
// and reliability performance.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Statistics about individual packet lifecycle
#[derive(Debug, Clone)]
pub struct PacketStats {
    /// Number of transmission attempts
    pub attempts: Counter,

    /// Time from first send to acknowledgment
    pub total_time: Duration,

    /// Whether packet was acknowledged
    pub acknowledged: bool,

    /// RTT measurement if available
    pub rtt: Option<Duration>,
}

impl PacketStats {
    /// Create new packet stats
    pub fn new() -> Self {
        Self {
            attempts: Counter::new(1),
            total_time: Duration::ZERO,
            acknowledged: false,
            rtt: None,
        }
    }

    /// Record retransmission attempt
    pub fn record_attempt(&mut self) {
        self.attempts = Counter::new(self.attempts.as_u64() + 1);
    }

    /// Record successful acknowledgment
    pub fn record_ack(&mut self, total_time: Duration, rtt: Option<Duration>) {
        self.acknowledged = true;
        self.total_time = total_time;
        self.rtt = rtt;
    }
}

impl Default for PacketStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate retransmission statistics
#[derive(Debug)]
pub struct RetransmissionStats {
    /// Total packets sent
    packets_sent: AtomicU64,

    /// Total packets acknowledged
    packets_acked: AtomicU64,

    /// Total packets lost (max retries exceeded)
    packets_lost: AtomicU64,

    /// Total retransmission attempts
    retransmissions: AtomicU64,

    /// Total RTT samples collected
    rtt_samples: AtomicU64,

    /// Sum of RTT samples (for average calculation)
    rtt_sum_ms: AtomicU64,

    /// Minimum observed RTT
    rtt_min_ms: AtomicU64,

    /// Maximum observed RTT
    rtt_max_ms: AtomicU64,

    /// Number of spurious retransmissions (ACK arrived after retransmit)
    spurious_retransmits: AtomicU64,

    /// Number of fast retransmits (triggered by SACK)
    fast_retransmits: AtomicU64,
}

impl RetransmissionStats {
    /// Create new statistics tracker
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            packets_acked: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            retransmissions: AtomicU64::new(0),
            rtt_samples: AtomicU64::new(0),
            rtt_sum_ms: AtomicU64::new(0),
            rtt_min_ms: AtomicU64::new(u64::MAX),
            rtt_max_ms: AtomicU64::new(0),
            spurious_retransmits: AtomicU64::new(0),
            fast_retransmits: AtomicU64::new(0),
        }
    }

    /// Record a packet sent
    pub fn record_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet acknowledged
    pub fn record_ack(&self) {
        self.packets_acked.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet lost (max retries exceeded)
    pub fn record_lost(&self) {
        self.packets_lost.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a retransmission attempt
    pub fn record_retransmission(&self) {
        self.retransmissions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an RTT sample
    pub fn record_rtt(&self, rtt: Duration) {
        let rtt_ms = rtt.as_millis() as u64;

        self.rtt_samples.fetch_add(1, Ordering::Relaxed);
        self.rtt_sum_ms.fetch_add(rtt_ms, Ordering::Relaxed);

        // Update min RTT
        let mut current_min = self.rtt_min_ms.load(Ordering::Relaxed);
        while rtt_ms < current_min {
            match self.rtt_min_ms.compare_exchange(
                current_min,
                rtt_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_min = actual,
            }
        }

        // Update max RTT
        let mut current_max = self.rtt_max_ms.load(Ordering::Relaxed);
        while rtt_ms > current_max {
            match self.rtt_max_ms.compare_exchange(
                current_max,
                rtt_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }
    }

    /// Record a spurious retransmission
    pub fn record_spurious_retransmit(&self) {
        self.spurious_retransmits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a fast retransmit (triggered by SACK)
    pub fn record_fast_retransmit(&self) {
        self.fast_retransmits.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total packets sent
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get total packets acknowledged
    pub fn packets_acked(&self) -> u64 {
        self.packets_acked.load(Ordering::Relaxed)
    }

    /// Get total packets lost
    pub fn packets_lost(&self) -> u64 {
        self.packets_lost.load(Ordering::Relaxed)
    }

    /// Get total retransmissions
    pub fn retransmissions(&self) -> u64 {
        self.retransmissions.load(Ordering::Relaxed)
    }

    /// Get retransmission rate (retransmissions / packets_sent)
    pub fn retransmission_rate(&self) -> f64 {
        let sent = self.packets_sent();
        if sent == 0 {
            0.0
        } else {
            self.retransmissions() as f64 / sent as f64
        }
    }

    /// Get acknowledgment success rate (packets_acked / packets_sent)
    pub fn ack_success_rate(&self) -> f64 {
        let sent = self.packets_sent();
        if sent == 0 {
            0.0
        } else {
            self.packets_acked() as f64 / sent as f64
        }
    }

    /// Get average RTT
    pub fn average_rtt(&self) -> Option<Duration> {
        let samples = self.rtt_samples.load(Ordering::Relaxed);
        if samples == 0 {
            None
        } else {
            let sum = self.rtt_sum_ms.load(Ordering::Relaxed);
            Some(Duration::from_millis(sum / samples))
        }
    }

    /// Get minimum RTT
    pub fn min_rtt(&self) -> Option<Duration> {
        let min_ms = self.rtt_min_ms.load(Ordering::Relaxed);
        if min_ms == u64::MAX {
            None
        } else {
            Some(Duration::from_millis(min_ms))
        }
    }

    /// Get maximum RTT
    pub fn max_rtt(&self) -> Option<Duration> {
        let max_ms = self.rtt_max_ms.load(Ordering::Relaxed);
        if max_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(max_ms))
        }
    }

    /// Get spurious retransmit count
    pub fn spurious_retransmits(&self) -> u64 {
        self.spurious_retransmits.load(Ordering::Relaxed)
    }

    /// Get fast retransmit count
    pub fn fast_retransmits(&self) -> u64 {
        self.fast_retransmits.load(Ordering::Relaxed)
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_acked.store(0, Ordering::Relaxed);
        self.packets_lost.store(0, Ordering::Relaxed);
        self.retransmissions.store(0, Ordering::Relaxed);
        self.rtt_samples.store(0, Ordering::Relaxed);
        self.rtt_sum_ms.store(0, Ordering::Relaxed);
        self.rtt_min_ms.store(u64::MAX, Ordering::Relaxed);
        self.rtt_max_ms.store(0, Ordering::Relaxed);
        self.spurious_retransmits.store(0, Ordering::Relaxed);
        self.fast_retransmits.store(0, Ordering::Relaxed);
    }
}

impl Default for RetransmissionStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_stats() {
        let mut stats = PacketStats::new();
        assert_eq!(stats.attempts.as_u64(), 1);
        assert!(!stats.acknowledged);

        stats.record_attempt();
        assert_eq!(stats.attempts.as_u64(), 2);

        stats.record_ack(Duration::from_millis(100), Some(Duration::from_millis(50)));
        assert!(stats.acknowledged);
        assert_eq!(stats.total_time, Duration::from_millis(100));
        assert_eq!(stats.rtt, Some(Duration::from_millis(50)));
    }

    #[test]
    fn test_retransmission_stats() {
        let stats = RetransmissionStats::new();

        stats.record_sent();
        stats.record_sent();
        stats.record_sent();
        assert_eq!(stats.packets_sent(), 3);

        stats.record_ack();
        stats.record_ack();
        assert_eq!(stats.packets_acked(), 2);

        stats.record_retransmission();
        assert_eq!(stats.retransmissions(), 1);

        stats.record_lost();
        assert_eq!(stats.packets_lost(), 1);
    }

    #[test]
    fn test_retransmission_rate() {
        let stats = RetransmissionStats::new();

        stats.record_sent();
        stats.record_sent();
        stats.record_retransmission();

        let rate = stats.retransmission_rate();
        assert!((rate - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_rtt_tracking() {
        let stats = RetransmissionStats::new();

        stats.record_rtt(Duration::from_millis(100));
        stats.record_rtt(Duration::from_millis(200));
        stats.record_rtt(Duration::from_millis(150));

        assert_eq!(stats.average_rtt(), Some(Duration::from_millis(150)));
        assert_eq!(stats.min_rtt(), Some(Duration::from_millis(100)));
        assert_eq!(stats.max_rtt(), Some(Duration::from_millis(200)));
    }

    #[test]
    fn test_success_rate() {
        let stats = RetransmissionStats::new();

        stats.record_sent();
        stats.record_sent();
        stats.record_sent();
        stats.record_sent();

        stats.record_ack();
        stats.record_ack();
        stats.record_ack();

        let rate = stats.ack_success_rate();
        assert!((rate - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_reset() {
        let stats = RetransmissionStats::new();

        stats.record_sent();
        stats.record_ack();
        stats.record_rtt(Duration::from_millis(100));

        stats.reset();

        assert_eq!(stats.packets_sent(), 0);
        assert_eq!(stats.packets_acked(), 0);
        assert_eq!(stats.average_rtt(), None);
    }
}
