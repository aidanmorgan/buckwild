#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Adaptive Networking - Asymmetric Window Adaptation and Network Condition Assessment
//
// Implements adaptive networking per design/protocol/11-adaptive-networking.md:
// - Asymmetric window adaptation (past/future independently adjusted)
// - Network condition assessment (RTT, packet loss, jitter)
// - HEARTBEAT delay negotiation
// - Adaptive smoothing with bias toward smaller windows

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

use crate::error::EngineError;
use crate::protocol::types::*;

/// Packet timing measurement
#[derive(Debug, Clone, Copy)]
pub struct TimingMeasurement {
    /// Delay in milliseconds
    pub delay_ms: i64,

    /// Timestamp when measured
    pub timestamp: SystemTime,

    /// Whether packet arrived early (before current hop)
    pub early: bool,

    /// Whether packet arrived late (after current hop)
    pub late: bool,
}

impl TimingMeasurement {
    pub fn new(delay_ms: i64, early: bool, late: bool) -> Self {
        Self {
            delay_ms,
            timestamp: SystemTime::now(),
            early,
            late,
        }
    }
}

/// Network condition metrics
#[derive(Debug, Clone, Copy)]
pub struct NetworkConditions {
    /// Round-trip time (milliseconds)
    pub rtt_ms: f64,

    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f64,

    /// Network jitter (milliseconds)
    pub jitter_ms: f64,

    /// Quality score (0-100)
    pub quality_score: f64,

    /// Last updated
    pub updated_at: SystemTime,
}

impl NetworkConditions {
    pub fn new() -> Self {
        Self {
            rtt_ms: 0.0,
            packet_loss_rate: 0.0,
            jitter_ms: 0.0,
            quality_score: 100.0,
            updated_at: SystemTime::now(),
        }
    }

    /// Calculate quality score from metrics
    /// Score: 100 = perfect, 0 = unusable
    pub fn calculate_quality(&mut self) {
        let mut score = 100.0;

        // Penalize high RTT
        if self.rtt_ms > 500.0 {
            score -= 30.0;
        } else if self.rtt_ms > 200.0 {
            score -= 15.0;
        } else if self.rtt_ms > 100.0 {
            score -= 5.0;
        }

        // Penalize packet loss
        score -= self.packet_loss_rate * 100.0 * 2.0; // 2x weight on loss

        // Penalize jitter
        if self.jitter_ms > 100.0 {
            score -= 20.0;
        } else if self.jitter_ms > 50.0 {
            score -= 10.0;
        } else if self.jitter_ms > 20.0 {
            score -= 5.0;
        }

        self.quality_score = score.max(0.0).min(100.0);
    }
}

/// Asymmetric window state
#[derive(Debug, Clone)]
pub struct AsymmetricWindow {
    /// Past window size (number of hop intervals before current)
    pub past_window_size: u32,

    /// Future window size (number of hop intervals after current)
    pub future_window_size: u32,

    /// Total window size (past + 1 + future)
    pub total_window_size: u32,

    /// Early packet count
    pub early_count: u32,

    /// Late packet count
    pub late_count: u32,

    /// Last update time
    pub last_update: SystemTime,
}

impl AsymmetricWindow {
    pub fn new(past_window_size: u32, future_window_size: u32) -> Self {
        let total = past_window_size + 1 + future_window_size;
        Self {
            past_window_size,
            future_window_size,
            total_window_size: total,
            early_count: 0,
            late_count: 0,
            last_update: SystemTime::now(),
        }
    }

    /// Get default window (2 past + 1 current + 2 future = 5 total)
    pub fn default() -> Self {
        Self::new(2, 2)
    }

    /// Convert to milliseconds
    pub fn past_window_ms(&self, hop_interval_ms: u32) -> u32 {
        self.past_window_size * hop_interval_ms
    }

    pub fn future_window_ms(&self, hop_interval_ms: u32) -> u32 {
        self.future_window_size * hop_interval_ms
    }
}

/// Adaptive networking manager
#[derive(Debug)]
pub struct AdaptiveNetworking {
    /// Asymmetric window state
    window: AsymmetricWindow,

    /// Hop interval (milliseconds)
    hop_interval_ms: u32,

    /// Recent timing measurements (for window adaptation)
    timing_measurements: VecDeque<TimingMeasurement>,

    /// Maximum measurements to track
    max_measurements: usize,

    /// Network conditions
    conditions: NetworkConditions,

    /// Minimum window size
    min_window_size: u32,

    /// Maximum window size
    max_window_size: u32,

    /// Adaptive smoothing factor for increases (slower)
    increase_smoothing: f64,

    /// Adaptive smoothing factor for decreases (faster)
    decrease_smoothing: f64,

    /// Safety margin (milliseconds)
    safety_margin_ms: u32,

    /// Delay percentile target (95%)
    delay_percentile: f64,
}

impl AdaptiveNetworking {
    /// Create new adaptive networking manager
    pub fn new(
        hop_interval_ms: u32,
        initial_past: u32,
        initial_future: u32,
        min_window_size: u32,
        max_window_size: u32,
    ) -> Self {
        Self {
            window: AsymmetricWindow::new(initial_past, initial_future),
            hop_interval_ms,
            timing_measurements: VecDeque::with_capacity(1000),
            max_measurements: 1000,
            conditions: NetworkConditions::new(),
            min_window_size,
            max_window_size,
            increase_smoothing: 0.3, // Slow increase
            decrease_smoothing: 0.5, // Fast decrease
            safety_margin_ms: 50,    // 50ms safety margin
            delay_percentile: 95.0,   // 95th percentile
        }
    }

    /// Create with default settings (500ms hops, 2+2 windows, 3-10 range)
    pub fn default() -> Self {
        Self::new(500, 2, 2, 3, 10)
    }

    /// Add timing measurement
    pub fn add_measurement(&mut self, measurement: TimingMeasurement) {
        // Update early/late counts
        if measurement.early {
            self.window.early_count += 1;
        }
        if measurement.late {
            self.window.late_count += 1;
        }

        self.timing_measurements.push_back(measurement);

        // Trim old measurements
        while self.timing_measurements.len() > self.max_measurements {
            self.timing_measurements.pop_front();
        }

        debug!(
            "Added timing measurement: delay={}ms, early={}, late={}",
            measurement.delay_ms, measurement.early, measurement.late
        );
    }

    /// Update asymmetric window based on recent measurements
    pub fn update_window(&mut self) -> Result<(), EngineError> {
        if self.timing_measurements.len() < 10 {
            return Ok(()); // Need minimum measurements
        }

        // Separate early and late packets
        let early_packets: Vec<_> = self.timing_measurements
            .iter()
            .filter(|m| m.early)
            .cloned()
            .collect();

        let late_packets: Vec<_> = self.timing_measurements
            .iter()
            .filter(|m| m.late)
            .cloned()
            .collect();

        // Calculate ratios
        let total_packets = self.timing_measurements.len() as f64;
        let early_ratio = early_packets.len() as f64 / total_packets;
        let late_ratio = late_packets.len() as f64 / total_packets;

        // Calculate 95th percentile delays for each direction
        let early_p95 = self.calculate_percentile_delay(&early_packets);
        let late_p95 = self.calculate_percentile_delay(&late_packets);

        // Calculate jitter for each direction
        let early_jitter = self.calculate_jitter(&early_packets);
        let late_jitter = self.calculate_jitter(&late_packets);

        // Calculate required windows
        let early_safety = self.safety_margin_ms.max(early_jitter as u32);
        let late_safety = self.safety_margin_ms.max(late_jitter as u32);

        let required_future = ((early_p95 + early_safety as f64) / self.hop_interval_ms as f64).ceil() as u32;
        let required_past = ((late_p95 + late_safety as f64) / self.hop_interval_ms as f64).ceil() as u32;

        // Apply adaptive bias based on packet ratios
        let bias_factor = 1.5;
        let mut adjusted_future = required_future;
        let mut adjusted_past = required_past;

        if early_ratio > late_ratio + 0.1 {
            // More early packets - bias toward future windows
            let future_bias = 1.0 + (early_ratio - late_ratio) * bias_factor;
            adjusted_future = (required_future as f64 * future_bias) as u32;
        } else if late_ratio > early_ratio + 0.1 {
            // More late packets - bias toward past windows
            let past_bias = 1.0 + (late_ratio - early_ratio) * bias_factor;
            adjusted_past = (required_past as f64 * past_bias) as u32;
        }

        // Apply bounds
        let max_individual = self.max_window_size - 1; // Reserve 1 for current
        let bounded_future = adjusted_future.min(max_individual);
        let bounded_past = adjusted_past.min(max_individual);

        // Ensure total doesn't exceed maximum
        let mut final_past = bounded_past;
        let mut final_future = bounded_future;

        let total = final_past + 1 + final_future;
        if total > self.max_window_size {
            let scale_factor = (self.max_window_size - 1) as f64 / (final_past + final_future) as f64;
            final_past = (final_past as f64 * scale_factor) as u32;
            final_future = (final_future as f64 * scale_factor) as u32;
        }

        // Apply adaptive smoothing
        let past_smoothing = self.calculate_smoothing_factor(self.window.past_window_size, final_past);
        let future_smoothing = self.calculate_smoothing_factor(self.window.future_window_size, final_future);

        let new_past = ((1.0 - past_smoothing) * self.window.past_window_size as f64
            + past_smoothing * final_past as f64) as u32;
        let new_future = ((1.0 - future_smoothing) * self.window.future_window_size as f64
            + future_smoothing * final_future as f64) as u32;

        // Ensure minimum total window
        let mut final_new_past = new_past;
        let mut final_new_future = new_future;
        let total_new = final_new_past + 1 + final_new_future;

        if total_new < self.min_window_size {
            let extra_needed = self.min_window_size - total_new;
            let past_share = extra_needed / 2;
            let future_share = extra_needed - past_share;
            final_new_past += past_share;
            final_new_future += future_share;
        }

        // Update window
        let old_past = self.window.past_window_size;
        let old_future = self.window.future_window_size;

        self.window.past_window_size = final_new_past;
        self.window.future_window_size = final_new_future;
        self.window.total_window_size = final_new_past + 1 + final_new_future;
        self.window.last_update = SystemTime::now();

        if old_past != final_new_past || old_future != final_new_future {
            info!(
                "Updated asymmetric window: past {}→{} ({:.1}%), future {}→{} ({:.1}%), early_ratio={:.1}%, late_ratio={:.1}%",
                old_past, final_new_past, late_ratio * 100.0,
                old_future, final_new_future, early_ratio * 100.0,
                early_ratio * 100.0, late_ratio * 100.0
            );
        }

        // Reset counters
        self.window.early_count = 0;
        self.window.late_count = 0;

        Ok(())
    }

    /// Calculate percentile delay from measurements
    fn calculate_percentile_delay(&self, measurements: &[TimingMeasurement]) -> f64 {
        if measurements.is_empty() {
            return 0.0;
        }

        let mut delays: Vec<i64> = measurements.iter().map(|m| m.delay_ms).collect();
        delays.sort();

        let index = ((delays.len() as f64) * self.delay_percentile / 100.0) as usize;
        let index = index.min(delays.len() - 1);

        delays[index] as f64
    }

    /// Calculate jitter from measurements
    fn calculate_jitter(&self, measurements: &[TimingMeasurement]) -> f64 {
        if measurements.len() < 2 {
            return 0.0;
        }

        let delays: Vec<f64> = measurements.iter().map(|m| m.delay_ms as f64).collect();
        let mean = delays.iter().sum::<f64>() / delays.len() as f64;

        let variance = delays
            .iter()
            .map(|d| (d - mean).powi(2))
            .sum::<f64>()
            / delays.len() as f64;

        variance.sqrt()
    }

    /// Calculate adaptive smoothing factor
    /// Use slower smoothing for increases, faster for decreases
    fn calculate_smoothing_factor(&self, current: u32, target: u32) -> f64 {
        if target > current {
            self.increase_smoothing // Slow increase
        } else {
            self.decrease_smoothing // Fast decrease
        }
    }

    /// Update network conditions
    pub fn update_network_conditions(&mut self, rtt_ms: f64, packet_loss_rate: f64) {
        self.conditions.rtt_ms = rtt_ms;
        self.conditions.packet_loss_rate = packet_loss_rate;

        // Calculate jitter from recent measurements
        let all_delays: Vec<_> = self.timing_measurements
            .iter()
            .map(|m| m.delay_ms as f64)
            .collect();

        if all_delays.len() >= 2 {
            let mean = all_delays.iter().sum::<f64>() / all_delays.len() as f64;
            let variance = all_delays
                .iter()
                .map(|d| (d - mean).powi(2))
                .sum::<f64>()
                / all_delays.len() as f64;
            self.conditions.jitter_ms = variance.sqrt();
        }

        self.conditions.calculate_quality();
        self.conditions.updated_at = SystemTime::now();

        debug!(
            "Updated network conditions: RTT={:.1}ms, loss={:.2}%, jitter={:.1}ms, quality={:.1}",
            self.conditions.rtt_ms,
            self.conditions.packet_loss_rate * 100.0,
            self.conditions.jitter_ms,
            self.conditions.quality_score
        );
    }

    /// Get current window
    pub fn window(&self) -> &AsymmetricWindow {
        &self.window
    }

    /// Get network conditions
    pub fn conditions(&self) -> &NetworkConditions {
        &self.conditions
    }

    /// Create HEARTBEAT delay proposal
    /// Proposes heartbeat interval based on network conditions
    pub fn create_heartbeat_proposal(&self) -> u32 {
        // Base heartbeat: 10 seconds
        let mut heartbeat_ms = 10_000;

        // Adjust based on network quality
        if self.conditions.quality_score < 50.0 {
            // Poor network - more frequent heartbeats
            heartbeat_ms = 5_000;
        } else if self.conditions.quality_score > 80.0 {
            // Good network - less frequent heartbeats
            heartbeat_ms = 15_000;
        }

        // Adjust based on RTT
        if self.conditions.rtt_ms > 200.0 {
            heartbeat_ms = heartbeat_ms.max(self.conditions.rtt_ms as u32 * 50);
        }

        heartbeat_ms
    }

    /// Evaluate HEARTBEAT proposal from peer
    /// Returns true if acceptable
    pub fn evaluate_heartbeat_proposal(&self, proposed_ms: u32) -> bool {
        let our_proposal = self.create_heartbeat_proposal();

        // Accept if within 50% of our proposal
        let min_acceptable = our_proposal / 2;
        let max_acceptable = our_proposal * 2;

        proposed_ms >= min_acceptable && proposed_ms <= max_acceptable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asymmetric_window_creation() {
        let window = AsymmetricWindow::new(2, 3);
        assert_eq!(window.past_window_size, 2);
        assert_eq!(window.future_window_size, 3);
        assert_eq!(window.total_window_size, 6); // 2 + 1 + 3
    }

    #[test]
    fn test_adaptive_networking_measurements() {
        let mut adaptive = AdaptiveNetworking::default();

        // Add some early packets
        for _ in 0..5 {
            adaptive.add_measurement(TimingMeasurement::new(-10, true, false));
        }

        // Add some late packets
        for _ in 0..3 {
            adaptive.add_measurement(TimingMeasurement::new(10, false, true));
        }

        assert_eq!(adaptive.timing_measurements.len(), 8);
        assert_eq!(adaptive.window.early_count, 5);
        assert_eq!(adaptive.window.late_count, 3);
    }

    #[test]
    fn test_network_condition_quality() {
        let mut conditions = NetworkConditions::new();

        // Good conditions
        conditions.rtt_ms = 50.0;
        conditions.packet_loss_rate = 0.01;
        conditions.jitter_ms = 5.0;
        conditions.calculate_quality();
        assert!(conditions.quality_score > 80.0);

        // Poor conditions
        conditions.rtt_ms = 600.0;
        conditions.packet_loss_rate = 0.10;
        conditions.jitter_ms = 150.0;
        conditions.calculate_quality();
        assert!(conditions.quality_score < 50.0);
    }

    #[test]
    fn test_heartbeat_proposal() {
        let mut adaptive = AdaptiveNetworking::default();

        // Good network should propose longer heartbeats
        adaptive.update_network_conditions(50.0, 0.01);
        let good_proposal = adaptive.create_heartbeat_proposal();
        assert!(good_proposal >= 10_000);

        // Poor network should propose shorter heartbeats
        adaptive.update_network_conditions(300.0, 0.15);
        let poor_proposal = adaptive.create_heartbeat_proposal();
        assert!(poor_proposal <= good_proposal);
    }
}
