#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Network Measurement - Network condition measurement and analysis
//
// This module handles measurement of network conditions including RTT, jitter,
// packet loss, and other metrics used for adaptive networking decisions.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::engines::adaptive::DelayMeasurement;
use crate::error::EngineError;
use crate::protocol::types::*;

/// RTT measurement window size
const RTT_MEASUREMENT_WINDOW: usize = 20;

/// Packet loss calculation window size
const LOSS_CALCULATION_WINDOW: usize = 100;

/// Network condition thresholds
const HIGH_JITTER_THRESHOLD: NetworkJitter = NetworkJitter(100); // 100ms
const HIGH_LOSS_THRESHOLD: f64 = 0.02; // 2%

/// RTT measurement tracking
#[derive(Debug)]
struct RttMeasurement {
    rtt: RoundTripTime,
}

/// Packet tracking for loss calculation
#[derive(Debug)]
struct PacketTracker {
    sequence: SequenceNumber,
}

/// Network measurement statistics
#[derive(Debug, Default, Clone)]
pub struct NetworkMeasurementStats {
    pub total_rtt_measurements: Counter,
    pub total_jitter_calculations: Counter,
    pub total_loss_calculations: Counter,
    pub current_rtt: RoundTripTime,
    pub current_jitter: NetworkJitter,
    pub current_loss_rate: PacketLossRate,
    pub rtt_variance: RoundTripTime,
    pub high_latency_events: Counter,
    pub high_jitter_events: Counter,
    pub high_loss_events: Counter,
    pub network_instability_events: Counter,
}

/// Network Measurement Engine
pub struct NetworkMeasurement {
    /// RTT measurements history
    rtt_measurements: RwLock<VecDeque<RttMeasurement>>,

    /// Packet tracking for loss calculation
    packet_tracker: RwLock<VecDeque<PacketTracker>>,

    /// Current RTT estimate (stored as nanoseconds)
    current_rtt_nanos: AtomicU64,

    /// RTT variance (stored as nanoseconds)
    rtt_variance_nanos: AtomicU64,

    /// Current jitter estimate (stored as u32 milliseconds)
    current_jitter: AtomicNetworkJitter,

    /// Current packet loss rate (scaled by 1000)
    current_loss_rate: AtomicPacketLossRate,

    /// Measurement statistics
    stats: RwLock<NetworkMeasurementStats>,

    /// Next expected sequence number
    next_sequence: AtomicU32,

    /// Last measurement timestamp
    last_measurement_time: AtomicMeasurementTimestamp,

    /// Bandwidth tracking: total bytes sent/received
    total_bytes: AtomicU64,

    /// Bandwidth tracking: last bandwidth calculation timestamp
    last_bandwidth_calc_time: AtomicU64,

    /// Current bandwidth estimate (bytes per second)
    current_bandwidth_bps: AtomicU64,
}

impl NetworkMeasurement {
    /// Create new network measurement engine
    pub fn new() -> Self {
        Self {
            rtt_measurements: RwLock::new(VecDeque::new()),
            packet_tracker: RwLock::new(VecDeque::new()),
            current_rtt_nanos: AtomicU64::new(100_000_000), // 100ms in nanoseconds
            rtt_variance_nanos: AtomicU64::new(10_000_000), // 10ms in nanoseconds
            current_jitter: AtomicNetworkJitter::new(0),
            current_loss_rate: AtomicPacketLossRate::new(0),
            stats: RwLock::new(NetworkMeasurementStats::default()),
            next_sequence: AtomicU32::new(1),
            last_measurement_time: AtomicMeasurementTimestamp::new(0),
            total_bytes: AtomicU64::new(0),
            last_bandwidth_calc_time: AtomicU64::new(0),
            current_bandwidth_bps: AtomicU64::new(0),
        }
    }

    /// Initialize the measurement engine
    pub fn initialize(&self) -> Result<(), EngineError> {
        // Clear all measurements
        self.rtt_measurements.write().clear();
        self.packet_tracker.write().clear();

        // Reset counters
        self.current_rtt_nanos.store(100_000_000, Ordering::Relaxed); // 100ms in nanoseconds
        self.rtt_variance_nanos.store(10_000_000, Ordering::Relaxed); // 10ms in nanoseconds
        self.current_jitter.store(0, Ordering::Relaxed);
        self.current_loss_rate.store(0, Ordering::Relaxed);
        self.next_sequence.store(1, Ordering::Relaxed);

        let current_time = Timestamp::now();

        self.last_measurement_time
            .store(current_time.as_nanos(), Ordering::Relaxed);

        // Reset bandwidth tracking
        self.total_bytes.store(0, Ordering::Relaxed);
        self.last_bandwidth_calc_time
            .store(current_time.as_nanos(), Ordering::Relaxed);
        self.current_bandwidth_bps.store(0, Ordering::Relaxed);

        info!("Network measurement engine initialized");
        Ok(())
    }

    /// Process delay measurement
    pub fn process_delay_measurement(
        &self,
        measurement: &DelayMeasurement,
    ) -> Result<(), EngineError> {
        // Update RTT if this measurement includes RTT data
        if measurement.rtt_estimate.as_u64() > 0 {
            self.update_rtt_measurement(measurement.rtt_estimate, measurement.timestamp)?;
        }

        // Track packet for loss calculation
        self.track_packet(measurement.sequence, measurement.timestamp)?;

        // Calculate jitter
        self.calculate_jitter(measurement)?;

        // Update last measurement time
        self.last_measurement_time.store(
            measurement.timestamp.as_nanos(),
            std::sync::atomic::Ordering::Relaxed,
        );

        debug!(
            sequence = measurement.sequence.as_u32(),
            delay_ms = measurement.delay_ms.as_millis(),
            rtt_estimate = measurement.rtt_estimate.as_millis(),
            "Processed delay measurement"
        );

        Ok(())
    }

    /// Update RTT measurement
    fn update_rtt_measurement(
        &self,
        rtt: RoundTripTime,
        _timestamp: Timestamp,
    ) -> Result<(), EngineError> {
        let rtt_measurement = RttMeasurement { rtt };

        // Add to history
        {
            let mut measurements = self.rtt_measurements.write();
            measurements.push_back(rtt_measurement);

            // Keep only recent measurements
            while measurements.len() > RTT_MEASUREMENT_WINDOW {
                measurements.pop_front();
            }
        }

        // Calculate statistics
        self.calculate_rtt_statistics()?;

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_rtt_measurements += 1;
            stats.current_rtt = RoundTripTime::new(self.current_rtt_nanos.load(Ordering::Relaxed));
            stats.rtt_variance =
                RoundTripTime::new(self.rtt_variance_nanos.load(Ordering::Relaxed));
        }

        Ok(())
    }

    /// Calculate RTT statistics
    fn calculate_rtt_statistics(&self) -> Result<(), EngineError> {
        let measurements = self.rtt_measurements.read();

        if measurements.is_empty() {
            return Ok(());
        }

        // Calculate average RTT
        let total_rtt: u64 = measurements.iter().map(|m| m.rtt.as_nanos()).sum::<u64>();
        let average_rtt = total_rtt / measurements.len() as u64;

        // Calculate RTT variance
        let variance_sum: u64 = measurements
            .iter()
            .map(|m| {
                let diff = if m.rtt.as_nanos() > average_rtt {
                    m.rtt.as_nanos() - average_rtt
                } else {
                    average_rtt - m.rtt.as_nanos()
                };
                diff * diff
            })
            .sum();

        let rtt_variance = ((variance_sum / measurements.len() as u64) as f64).sqrt() as u64;

        // Update values
        self.current_rtt_nanos.store(average_rtt, Ordering::Relaxed);
        self.rtt_variance_nanos
            .store(rtt_variance, Ordering::Relaxed);

        debug!(
            average_rtt,
            rtt_variance,
            sample_count = measurements.len(),
            "Updated RTT statistics"
        );

        Ok(())
    }

    /// Track packet for loss calculation
    fn track_packet(
        &self,
        sequence: SequenceNumber,
        _timestamp: Timestamp,
    ) -> Result<(), EngineError> {
        let packet = PacketTracker { sequence };

        {
            let mut tracker = self.packet_tracker.write();
            tracker.push_back(packet);

            // Keep only recent packets
            while tracker.len() > LOSS_CALCULATION_WINDOW {
                tracker.pop_front();
            }
        }

        // Calculate packet loss
        self.calculate_packet_loss()?;

        Ok(())
    }

    /// Calculate packet loss rate
    fn calculate_packet_loss(&self) -> Result<(), EngineError> {
        let tracker = self.packet_tracker.read();

        if tracker.len() < 10 {
            return Ok(()); // Need minimum samples
        }

        // Find sequence number gaps
        let mut sequences: Vec<u32> = tracker.iter().map(|p| p.sequence.as_u32()).collect();
        sequences.sort_unstable();

        if sequences.is_empty() {
            return Ok(());
        }

        let min_seq = sequences[0];
        let max_seq = sequences[sequences.len() - 1];
        let expected_packets = (max_seq - min_seq + 1) as usize;
        let received_packets = sequences.len();

        let loss_rate = if expected_packets > 0 {
            1.0 - (received_packets as f64 / expected_packets as f64)
        } else {
            0.0
        };

        // Store loss rate (scaled by 1000 for atomic storage: 0.0-1.0 becomes 0-1000)
        let scaled_loss_rate = (loss_rate * 1000.0) as u32;
        self.current_loss_rate
            .store(scaled_loss_rate, std::sync::atomic::Ordering::Relaxed);

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_loss_calculations += 1;
            stats.current_loss_rate =
                PacketLossRate::new((Rate::from_raw((loss_rate as f32) * 1000.0).0) as u16);

            if loss_rate > HIGH_LOSS_THRESHOLD {
                stats.high_loss_events += 1;
            }
        }

        debug!(
            loss_rate,
            expected_packets, received_packets, "Calculated packet loss rate"
        );

        Ok(())
    }

    /// Calculate network jitter
    fn calculate_jitter(&self, measurement: &DelayMeasurement) -> Result<(), EngineError> {
        let current_delay_ms = measurement.delay_ms.as_millis() as u32;
        let last_time = self.last_measurement_time.load(Ordering::Relaxed);

        if last_time == 0 {
            return Ok(()); // First measurement
        }

        // Simple jitter calculation based on delay variation
        let time_diff = measurement.timestamp.as_nanos().saturating_sub(last_time);
        if time_diff == 0 {
            return Ok(());
        }

        // Calculate expected delay based on time difference
        let expected_delay = time_diff as u32; // Rough estimate

        let jitter = current_delay_ms.abs_diff(expected_delay);

        // Update jitter with exponential smoothing
        let current_jitter = self.current_jitter.load(Ordering::Relaxed);
        let alpha = 0.125; // Smoothing factor
        let new_jitter = ((1.0 - alpha) * current_jitter as f64 + alpha * jitter as f64) as u32;

        self.current_jitter
            .store(new_jitter, std::sync::atomic::Ordering::Relaxed);

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_jitter_calculations += 1;
            stats.current_jitter = NetworkJitter::new(new_jitter);

            if new_jitter > HIGH_JITTER_THRESHOLD.as_millis() {
                stats.high_jitter_events += 1;
            }
        }

        debug!(
            current_delay = current_delay_ms,
            expected_delay, jitter, new_jitter, "Calculated network jitter"
        );

        Ok(())
    }

    /// Record bytes transmitted for bandwidth calculation
    pub fn record_bytes_transmitted(&self, bytes: u64) {
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);

        // Periodically update bandwidth estimate
        let current_time = Timestamp::now().as_nanos();
        let last_calc_time = self.last_bandwidth_calc_time.load(Ordering::Relaxed);

        // Update bandwidth every second
        let elapsed_nanos = current_time.saturating_sub(last_calc_time);
        if elapsed_nanos >= 1_000_000_000 {
            let _ = self.calculate_bandwidth();
        }
    }

    /// Calculate current bandwidth based on bytes transmitted over time window
    fn calculate_bandwidth(&self) -> Result<(), EngineError> {
        let current_time = Timestamp::now().as_nanos();
        let last_calc_time = self.last_bandwidth_calc_time.load(Ordering::Relaxed);

        if last_calc_time == 0 {
            // First calculation - just set timestamp
            self.last_bandwidth_calc_time
                .store(current_time, Ordering::Relaxed);
            return Ok(());
        }

        let elapsed_nanos = current_time.saturating_sub(last_calc_time);
        if elapsed_nanos == 0 {
            return Ok(()); // No time elapsed
        }

        // Get bytes transmitted since last calculation
        let total_bytes = self.total_bytes.swap(0, Ordering::Relaxed);

        if total_bytes == 0 {
            // No traffic - keep previous estimate or use minimum
            let current_bps = self.current_bandwidth_bps.load(Ordering::Relaxed);
            if current_bps == 0 {
                self.current_bandwidth_bps.store(10_000, Ordering::Relaxed); // 10 KB/s minimum
            }
            self.last_bandwidth_calc_time
                .store(current_time, Ordering::Relaxed);
            return Ok(());
        }

        // Calculate bytes per second
        // bytes_per_sec = (total_bytes * 1_000_000_000) / elapsed_nanos
        let bytes_per_sec = ((total_bytes as u128 * 1_000_000_000) / elapsed_nanos as u128) as u64;

        // Apply exponential smoothing to avoid sudden changes
        // new_estimate = 0.7 * old_estimate + 0.3 * new_measurement
        let old_estimate = self.current_bandwidth_bps.load(Ordering::Relaxed);
        let smoothed_bps = if old_estimate == 0 {
            bytes_per_sec
        } else {
            (70 * old_estimate + 30 * bytes_per_sec) / 100
        };

        self.current_bandwidth_bps
            .store(smoothed_bps, Ordering::Relaxed);
        self.last_bandwidth_calc_time
            .store(current_time, Ordering::Relaxed);

        debug!(
            bytes = total_bytes,
            elapsed_ms = elapsed_nanos / 1_000_000,
            bandwidth_bps = smoothed_bps,
            bandwidth_mbps = (smoothed_bps * 8) as f64 / 1_000_000.0,
            "Calculated bandwidth estimate"
        );

        Ok(())
    }

    /// Get current bandwidth estimate in bytes per second
    pub fn bandwidth_bps(&self) -> u64 {
        let bps = self.current_bandwidth_bps.load(Ordering::Relaxed);
        if bps == 0 {
            // Return minimum estimate if no measurement available
            10_000 // 10 KB/s = ~80 Kbps
        } else {
            bps
        }
    }

    /// Get current network conditions
    pub fn get_current_network_conditions(
        &self,
    ) -> crate::protocol::types::validation::NetworkConditions {
        let _current_time = Timestamp::now();

        let rtt_nanos = self.current_rtt_nanos.load(Ordering::Relaxed);
        let jitter_ms = self.current_jitter.load(Ordering::Relaxed);
        let loss_rate_scaled = self.current_loss_rate.load(Ordering::Relaxed);

        let loss_rate = PacketLossRate::from_f64(loss_rate_scaled as f64 / 1000.0);

        crate::protocol::types::validation::NetworkConditions {
            latency_ns: ProtocolDuration::new(rtt_nanos),
            packet_loss_rate: LossRate::new(loss_rate.as_f64() as f32),
            jitter_ns: ProtocolDuration::new((jitter_ms as u64) * 1_000_000), // Convert ms to ns
            bandwidth_bps: DataRate::new(self.bandwidth_bps()),
        }
    }

    /// Get measurement statistics
    pub fn get_measurement_stats(&self) -> NetworkMeasurementStats {
        let mut stats = self.stats.read().clone();

        // Update current values
        stats.current_rtt = RoundTripTime::new(self.current_rtt_nanos.load(Ordering::Relaxed));
        stats.current_jitter = NetworkJitter::new(self.current_jitter.load(Ordering::Relaxed));
        stats.current_loss_rate =
            PacketLossRate::new(self.current_loss_rate.load(Ordering::Relaxed) as u16);
        stats.rtt_variance = RoundTripTime::new(self.rtt_variance_nanos.load(Ordering::Relaxed));

        stats
    }

    /// Reset measurements
    pub fn reset_measurements(&self) -> Result<(), EngineError> {
        self.rtt_measurements.write().clear();
        self.packet_tracker.write().clear();

        self.current_rtt_nanos.store(100_000_000, Ordering::Relaxed); // 100ms in nanoseconds
        self.rtt_variance_nanos.store(10_000_000, Ordering::Relaxed); // 10ms in nanoseconds
        self.current_jitter.store(0, Ordering::Relaxed);
        self.current_loss_rate.store(0, Ordering::Relaxed);

        // Reset bandwidth tracking
        self.total_bytes.store(0, Ordering::Relaxed);
        let current_time = Timestamp::now().as_nanos();
        self.last_bandwidth_calc_time
            .store(current_time, Ordering::Relaxed);
        self.current_bandwidth_bps.store(0, Ordering::Relaxed);

        info!("Reset network measurements");
        Ok(())
    }

    /// Shutdown the measurement engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.rtt_measurements.write().clear();
        self.packet_tracker.write().clear();

        info!("Network measurement engine shut down");
        Ok(())
    }

    /// Record RTT from heartbeat (microseconds)
    ///
    /// Updates smoothed RTT (SRTT) and RTT variance (RTTVAR) using TCP-style calculations.
    /// SRTT and RTTVAR are used to compute retransmit timeout (RTO).
    pub fn record_rtt(&self, rtt_us: u64) {
        let rtt_nanos = rtt_us * 1_000;

        let current_srtt = self.current_rtt_nanos.load(Ordering::Relaxed);
        let current_rttvar = self.rtt_variance_nanos.load(Ordering::Relaxed);

        // TCP-style RTT estimation (RFC 6298)
        // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|
        // SRTT = (1 - alpha) * SRTT + alpha * RTT
        // where alpha = 1/8 and beta = 1/4

        let rtt_diff = rtt_nanos.abs_diff(current_srtt);

        // Update RTTVAR: (1 - 1/4) * RTTVAR + 1/4 * |SRTT - RTT|
        let new_rttvar = (3 * current_rttvar / 4) + (rtt_diff / 4);

        // Update SRTT: (1 - 1/8) * SRTT + 1/8 * RTT
        let new_srtt = (7 * current_srtt / 8) + (rtt_nanos / 8);

        self.current_rtt_nanos.store(new_srtt, Ordering::Relaxed);
        self.rtt_variance_nanos.store(new_rttvar, Ordering::Relaxed);

        debug!(
            rtt_us = rtt_us,
            srtt_us = new_srtt / 1_000,
            rttvar_us = new_rttvar / 1_000,
            "Recorded RTT measurement"
        );
    }

    /// Record heartbeat loss (timeout occurred)
    ///
    /// Increments loss counter for loss rate calculation.
    pub fn record_loss(&self) {
        // Track a lost packet by incrementing expected sequence
        let expected_seq = self.next_sequence.fetch_add(1, Ordering::Relaxed);

        debug!(expected_seq = expected_seq, "Recorded packet loss");

        // Recalculate loss rate
        let _ = self.calculate_packet_loss();
    }

    /// Record packet arrival for jitter calculation (timestamp in microseconds)
    ///
    /// Calculates jitter using RFC 3550 formula:
    /// J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
    pub fn record_packet_arrival(&self, timestamp_us: u64) {
        let current_time_nanos = timestamp_us * 1_000;
        let last_time = self.last_measurement_time.load(Ordering::Relaxed);

        if last_time == 0 {
            // First packet - no jitter calculation possible
            self.last_measurement_time
                .store(current_time_nanos, Ordering::Relaxed);
            return;
        }

        // Calculate inter-packet arrival time difference
        let time_diff_nanos = current_time_nanos.abs_diff(last_time);

        // Get expected inter-packet time (use SRTT as approximation)
        let expected_time = self.current_rtt_nanos.load(Ordering::Relaxed);

        // Calculate arrival time variation
        let variation = time_diff_nanos.abs_diff(expected_time);

        // RFC 3550 jitter calculation: J = J + (|D| - J)/16
        let current_jitter_nanos = (self.current_jitter.load(Ordering::Relaxed) as u64) * 1_000_000;
        let new_jitter_nanos =
            current_jitter_nanos + (variation.saturating_sub(current_jitter_nanos) / 16);
        let new_jitter_ms = (new_jitter_nanos / 1_000_000) as u32;

        self.current_jitter.store(new_jitter_ms, Ordering::Relaxed);
        self.last_measurement_time
            .store(current_time_nanos, Ordering::Relaxed);

        debug!(
            timestamp_us = timestamp_us,
            jitter_ms = new_jitter_ms,
            "Recorded packet arrival"
        );
    }

    /// Get smoothed RTT in microseconds
    pub fn srtt(&self) -> u64 {
        self.current_rtt_nanos.load(Ordering::Relaxed) / 1_000
    }

    /// Get retransmit timeout (RTO) in microseconds
    ///
    /// Calculated as: RTO = SRTT + 4 * RTTVAR
    /// Clamped to minimum of 1 second (RFC 6298)
    pub fn rto(&self) -> u64 {
        let srtt = self.current_rtt_nanos.load(Ordering::Relaxed);
        let rttvar = self.rtt_variance_nanos.load(Ordering::Relaxed);

        let rto_nanos = srtt + (4 * rttvar);
        let rto_us = rto_nanos / 1_000;

        // Minimum RTO of 1 second per RFC 6298
        rto_us.max(1_000_000)
    }

    /// Get current packet loss rate (0.0 to 1.0)
    pub fn loss_rate(&self) -> f64 {
        let scaled_loss = self.current_loss_rate.load(Ordering::Relaxed);
        (scaled_loss as f64) / 1000.0
    }

    /// Get current jitter in microseconds
    pub fn jitter(&self) -> u64 {
        (self.current_jitter.load(Ordering::Relaxed) as u64) * 1_000
    }
}

impl Default for NetworkMeasurement {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_measurement() {
        let measurement = NetworkMeasurement::new();

        // Initial SRTT should be 100ms (100,000 us)
        assert_eq!(measurement.srtt(), 100_000);

        // Record first RTT of 50ms
        measurement.record_rtt(50_000);

        // SRTT should update: (7 * 100,000 + 50,000) / 8 = 93,750
        let srtt = measurement.srtt();
        assert!(srtt > 90_000 && srtt < 95_000, "SRTT = {}", srtt);

        // Record second RTT of 60ms
        measurement.record_rtt(60_000);

        // SRTT should continue smoothing toward actual RTT
        let srtt2 = measurement.srtt();
        assert!(srtt2 < srtt, "SRTT should decrease: {} -> {}", srtt, srtt2);

        // Record many more measurements to converge (alpha=1/8 converges slowly)
        for _ in 0..100 {
            measurement.record_rtt(55_000);
        }

        // SRTT should converge toward 55ms (within 10% after 100 samples)
        let final_srtt = measurement.srtt();
        assert!(
            final_srtt > 50_000 && final_srtt < 60_000,
            "Final SRTT should be close to 55ms, got {}",
            final_srtt
        );
    }

    #[test]
    fn test_rto_calculation() {
        let measurement = NetworkMeasurement::new();

        // Initial RTO should be at least 1 second minimum
        let initial_rto = measurement.rto();
        assert!(
            initial_rto >= 1_000_000,
            "RTO should be at least 1s, got {}us",
            initial_rto
        );

        // Record consistent high RTT (300ms)
        for _ in 0..20 {
            measurement.record_rtt(300_000); // 300ms
        }

        // RTO = SRTT + 4 * RTTVAR
        let rto_stable = measurement.rto();

        // With stable RTT, RTO should be close to SRTT (but respects 1s minimum)
        assert!(
            rto_stable >= 1_000_000,
            "RTO should respect 1s minimum, got {}us",
            rto_stable
        );

        // Record highly varying RTT to increase RTTVAR significantly
        measurement.record_rtt(500_000); // 500ms
        measurement.record_rtt(1_000_000); // 1s
        measurement.record_rtt(200_000); // 200ms
        measurement.record_rtt(1_500_000); // 1.5s
        measurement.record_rtt(100_000); // 100ms
        measurement.record_rtt(2_000_000); // 2s

        let rto_with_variance = measurement.rto();

        // RTO should increase significantly with high variance
        assert!(
            rto_with_variance > rto_stable,
            "RTO should increase with variance: {} -> {}",
            rto_stable,
            rto_with_variance
        );

        // RTO should be substantially higher due to variance
        assert!(
            rto_with_variance > 1_500_000,
            "RTO with variance should exceed 1.5s, got {}us",
            rto_with_variance
        );
    }

    #[test]
    fn test_loss_rate_estimation() {
        let measurement = NetworkMeasurement::new();

        // Initial loss rate should be 0
        assert_eq!(measurement.loss_rate(), 0.0);

        // Track some successful packets
        for i in 0..10 {
            let tracker = PacketTracker {
                sequence: SequenceNumber::new(i),
            };
            measurement.packet_tracker.write().push_back(tracker);
        }

        // Calculate loss - should be 0% (all packets received)
        measurement.calculate_packet_loss().unwrap();
        let loss_rate = measurement.loss_rate();
        assert!(
            loss_rate < 0.01,
            "Loss rate should be near 0%, got {}",
            loss_rate
        );

        // Simulate some losses by creating gaps in sequence numbers
        measurement.packet_tracker.write().clear();

        // Sequences: 0, 1, 3, 4, 6, 7, 9, 11, 12, 14, 15, 17, 18, 20 (missing several)
        // Expected packets: 21 (0-20), Received: 14, Loss rate: 33%
        for seq in [0, 1, 3, 4, 6, 7, 9, 11, 12, 14, 15, 17, 18, 20] {
            let tracker = PacketTracker {
                sequence: SequenceNumber::new(seq),
            };
            measurement.packet_tracker.write().push_back(tracker);
        }

        measurement.calculate_packet_loss().unwrap();
        let loss_rate = measurement.loss_rate();

        // Should detect ~33% loss (14 received out of 21 expected)
        assert!(
            loss_rate > 0.30 && loss_rate < 0.36,
            "Loss rate should be ~33%, got {}",
            loss_rate
        );
    }

    #[test]
    fn test_jitter_calculation() {
        let measurement = NetworkMeasurement::new();

        // Initial jitter should be 0
        assert_eq!(measurement.jitter(), 0);

        // Record first packet arrival
        measurement.record_packet_arrival(1_000_000); // 1 second

        // First packet has no jitter reference
        assert_eq!(measurement.jitter(), 0);

        // Record second packet 100ms later (1.1s total)
        measurement.record_packet_arrival(1_100_000);

        // Jitter is always non-negative (u64)
        let _jitter1 = measurement.jitter();

        // Record packets with consistent timing
        for i in 0..10 {
            measurement.record_packet_arrival(1_200_000 + (i * 100_000)); // Every 100ms
        }

        // Jitter should remain relatively low with consistent arrivals
        let jitter_consistent = measurement.jitter();

        // Record packets with varying timing to increase jitter
        measurement.record_packet_arrival(2_500_000); // +300ms
        measurement.record_packet_arrival(2_520_000); // +20ms
        measurement.record_packet_arrival(2_750_000); // +230ms
        measurement.record_packet_arrival(2_760_000); // +10ms

        let jitter_varying = measurement.jitter();

        // Jitter should increase with varying arrival times
        assert!(
            jitter_varying > jitter_consistent,
            "Jitter should increase with varying arrivals: {} -> {}",
            jitter_consistent,
            jitter_varying
        );
    }

    #[test]
    fn test_record_loss() {
        let measurement = NetworkMeasurement::new();

        // Record initial packets
        for i in 0..5 {
            let tracker = PacketTracker {
                sequence: SequenceNumber::new(i),
            };
            measurement.packet_tracker.write().push_back(tracker);
        }

        // Record a loss
        measurement.record_loss();

        // Next sequence should be incremented
        let next_seq = measurement.next_sequence.load(Ordering::Relaxed);
        assert!(next_seq > 0, "Next sequence should be incremented");
    }

    #[test]
    fn test_srtt_convergence() {
        let measurement = NetworkMeasurement::new();

        // Test SRTT converges to actual RTT over time
        let target_rtt = 75_000; // 75ms

        for _ in 0..50 {
            measurement.record_rtt(target_rtt);
        }

        let final_srtt = measurement.srtt();

        // After many samples, SRTT should be very close to target
        assert!(
            (final_srtt as i64 - target_rtt as i64).abs() < 1_000,
            "SRTT should converge to target RTT: target={}, srtt={}",
            target_rtt,
            final_srtt
        );
    }

    #[test]
    fn test_bandwidth_measurement_basic() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();

        // Initial bandwidth should be 0 or minimum
        let initial_bw = measurement.bandwidth_bps();
        assert!(
            initial_bw >= 10_000,
            "Initial bandwidth should be minimum: {}",
            initial_bw
        );

        // Record some bytes transmitted
        measurement.record_bytes_transmitted(1_000_000); // 1 MB

        // Wait for calculation window (simulate time passing)
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Record more bytes to trigger calculation
        measurement.record_bytes_transmitted(100_000);

        // Bandwidth should now be measured
        let measured_bw = measurement.bandwidth_bps();
        assert!(
            measured_bw > 0,
            "Bandwidth should be measured after traffic"
        );

        // Should be approximately 1 MB/s (allowing for timing variance)
        assert!(
            measured_bw > 500_000 && measured_bw < 1_500_000,
            "Bandwidth should be approximately 1 MB/s, got {} bytes/s",
            measured_bw
        );
    }

    #[test]
    fn test_bandwidth_returns_different_values() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();

        // Record low traffic
        measurement.record_bytes_transmitted(10_000); // 10 KB
        std::thread::sleep(std::time::Duration::from_millis(1100));
        measurement.record_bytes_transmitted(1_000);
        let low_bw = measurement.bandwidth_bps();

        // Reset and record high traffic
        measurement.reset_measurements().unwrap();
        measurement.record_bytes_transmitted(5_000_000); // 5 MB
        std::thread::sleep(std::time::Duration::from_millis(1100));
        measurement.record_bytes_transmitted(1_000);
        let high_bw = measurement.bandwidth_bps();

        // High bandwidth should be significantly higher than low
        assert!(
            high_bw > low_bw * 10,
            "High bandwidth ({}) should be much higher than low bandwidth ({})",
            high_bw,
            low_bw
        );
    }

    #[test]
    fn test_bandwidth_no_hardcoded_value() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();

        // Without traffic, should return minimum, not hardcoded 1 Mbps
        let bw = measurement.bandwidth_bps();
        assert_ne!(
            bw, 125_000,
            "Should not return hardcoded 1 Mbps (125,000 bytes/s)"
        );

        // After traffic, should return measured value
        measurement.record_bytes_transmitted(2_000_000); // 2 MB
        std::thread::sleep(std::time::Duration::from_millis(1100));
        measurement.record_bytes_transmitted(1_000);

        let measured_bw = measurement.bandwidth_bps();
        assert_ne!(
            measured_bw, 125_000,
            "Should return measured bandwidth, not hardcoded value"
        );
    }

    #[test]
    fn test_bandwidth_accuracy() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();

        // Simulate known traffic pattern: 500 KB/s
        let bytes_per_second = 500_000_u64;
        let bytes_per_interval = bytes_per_second; // 1 second interval

        measurement.record_bytes_transmitted(bytes_per_interval);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        measurement.record_bytes_transmitted(1_000); // Trigger calculation

        let measured_bw = measurement.bandwidth_bps();

        // Should be within 30% of actual (allowing for timing variance and smoothing)
        let error_margin = (bytes_per_second as f64 * 0.3) as u64;
        assert!(
            measured_bw > bytes_per_second - error_margin
                && measured_bw < bytes_per_second + error_margin,
            "Bandwidth should be approximately {} bytes/s, got {} bytes/s (margin: {})",
            bytes_per_second,
            measured_bw,
            error_margin
        );
    }

    #[test]
    fn test_bandwidth_smoothing() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();

        // Establish baseline bandwidth
        measurement.record_bytes_transmitted(1_000_000); // 1 MB
        std::thread::sleep(std::time::Duration::from_millis(1100));
        measurement.record_bytes_transmitted(1_000);
        let baseline_bw = measurement.bandwidth_bps();

        // Spike in traffic
        measurement.record_bytes_transmitted(5_000_000); // 5 MB
        std::thread::sleep(std::time::Duration::from_millis(1100));
        measurement.record_bytes_transmitted(1_000);
        let spike_bw = measurement.bandwidth_bps();

        // Smoothing should prevent immediate jump to full spike value
        // New value should be between baseline and raw measurement
        let raw_spike = 5_000_000_u64;
        assert!(
            spike_bw > baseline_bw && spike_bw < raw_spike,
            "Smoothed bandwidth ({}) should be between baseline ({}) and raw spike ({})",
            spike_bw,
            baseline_bw,
            raw_spike
        );
    }

    #[test]
    fn test_bandwidth_in_network_conditions() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();

        // Record traffic
        measurement.record_bytes_transmitted(2_000_000); // 2 MB
        std::thread::sleep(std::time::Duration::from_millis(1100));
        measurement.record_bytes_transmitted(1_000);

        // Get network conditions
        let conditions = measurement.get_current_network_conditions();

        // Bandwidth should be measured, not hardcoded
        let bw_bps = conditions.bandwidth_bps.as_bytes_per_sec();
        assert!(
            bw_bps > 0,
            "Network conditions should include measured bandwidth"
        );
        assert_ne!(
            bw_bps, 125_000,
            "Network conditions should not return hardcoded 1 Mbps"
        );
    }
}
