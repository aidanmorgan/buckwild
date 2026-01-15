#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Adaptive Networking Engine - Consolidated adaptive networking logic
//
// This implements adaptive delay measurement and tuning mechanisms that optimize
// port hopping timing based on real-time network conditions.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::engines::adaptive::{NetworkMeasurement, ParameterOptimization};
use crate::error::EngineError;
use crate::protocol::types::*;

/// Adaptive networking constants
pub const ADAPTIVE_DELAY_WINDOW_MIN: u32 = 1;
pub const ADAPTIVE_DELAY_WINDOW_MAX: u32 = 16;
pub const DELAY_MEASUREMENT_SAMPLES: usize = 10;
pub const DELAY_NEGOTIATION_INTERVAL_MS: Interval = Interval(60_000_000_000); // 60 seconds in nanoseconds
pub const DELAY_PERCENTILE_TARGET: u8 = 95; // 95th percentile for delay allowance per protocol spec
pub const BASE_HEARTBEAT_PAYLOAD_SIZE: usize = 8;
pub const SAFETY_MARGIN_MS: u32 = 100;
pub const BASE_TRANSMISSION_DELAY_ALLOWANCE_MS: u32 = 1000;
pub const HOP_INTERVAL_MS: u32 = 500; // 500ms port hopping interval
pub const NETWORK_CONDITION_HISTORY_SIZE: usize = 50;
pub const PERFORMANCE_ADAPTATION_THRESHOLD: f64 = 0.05; // 5% threshold

// Performance monitoring constants
pub const HIGH_LATENCY_THRESHOLD_MS: u64 = 200;
pub const HIGH_JITTER_THRESHOLD: NetworkJitter = NetworkJitter(100); // 100ms
pub const HIGH_LOSS_THRESHOLD: f64 = 0.02; // 2%
pub const HIGH_RTT_VARIANCE_THRESHOLD_MS: u64 = 50;

// NOTE: MTU Discovery is a planned future enhancement.
// Current implementation uses fixed MTU values configured per connection.
// Dynamic MTU discovery would require:
// - ICMP packet handling for PMTU discovery (RFC 1191)
// - Path MTU detection via ICMP Type 3 Code 4 (Fragmentation Needed)
// - Dynamic MTU adjustment based on network path (RFC 8899)
// - Integration with network layer for ICMP packet processing

/// Network performance measurement for adaptive delay calculation
#[derive(Debug, Clone)]
pub struct DelayMeasurement {
    /// Measured delay in milliseconds
    pub delay_ms: Duration,
    /// Timestamp when measurement was taken
    pub timestamp: Timestamp,
    /// Sequence number for measurement ordering
    pub sequence: SequenceNumber,
    /// Type of packet that was measured
    pub packet_type: PacketType,
    /// Size of the packet in bytes
    pub packet_size: PacketSize,
    /// RTT estimate at time of measurement
    pub rtt_estimate: RoundTripTime,
    /// Whether this was an early packet (negative delay)
    pub is_early: bool,
}

/// Network condition assessment for adaptive optimization
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    /// Timestamp of assessment
    pub timestamp: Timestamp,
    /// Current packet loss rate (0.0-1.0)
    pub packet_loss_rate: PacketLossRate,
    /// Average RTT in milliseconds
    pub average_rtt: RoundTripTime,
    /// RTT variance
    pub rtt_variance: RoundTripTime,
    /// Network jitter in milliseconds
    pub network_jitter: NetworkJitter,
    /// High latency indicator (>200ms)
    pub high_latency: bool,
    /// High jitter indicator (>100ms)
    pub high_jitter: bool,
    /// High loss indicator (>2%)
    pub high_loss: bool,
    /// Unstable network indicator (high RTT variance)
    pub unstable_network: bool,
    /// Congested network indicator
    pub congested_network: bool,
}

impl NetworkConditions {
    /// Convert to protocol types NetworkConditions for optimization calculations
    pub fn to_protocol_conditions(&self) -> crate::protocol::types::validation::NetworkConditions {
        crate::protocol::types::validation::NetworkConditions {
            latency_ns: ProtocolDuration::new((self.average_rtt.as_u64()) * 1_000_000), // Convert ms to ns
            packet_loss_rate: LossRate::new(self.packet_loss_rate.as_f64() as f32),
            jitter_ns: ProtocolDuration::new((self.network_jitter.as_u32() as u64) * 1_000_000), // Convert ms to ns
            bandwidth_bps: DataRate::new(1_000_000), // Default 1 Mbps, should be measured
        }
    }
}

/// Adaptive delay state management with asymmetric window support
#[derive(Debug)]
pub struct AdaptiveDelayState {
    /// Current locally calculated window (total)
    pub current_delay_window: AtomicU32,

    /// Past window size (for late packets)
    pub past_window_size: AtomicU32,

    /// Future window size (for early packets)
    pub future_window_size: AtomicU32,

    /// Negotiated delay window with peer
    pub negotiated_delay_window: AtomicU32,

    /// Delay measurements history
    pub delay_measurements: RwLock<VecDeque<DelayMeasurement>>,

    /// Last negotiation time (nanoseconds since epoch)
    pub last_negotiation_time: AtomicU64,

    /// Peer's delay window
    pub peer_delay_window: AtomicU32,

    /// Network jitter measurement (stored as u32 milliseconds)
    pub network_jitter: AtomicU32,

    /// Packet loss rate (scaled by 1000)
    pub packet_loss_rate: AtomicU32,

    /// RTT measurement (nanoseconds)
    pub rtt_measurement: AtomicU64,

    /// RTT variance (nanoseconds)
    pub rtt_variance: AtomicU64,

    /// Adaptation enabled flag
    pub is_adaptation_enabled: AtomicFlag,

    /// Performance history for optimization
    pub performance_history: RwLock<VecDeque<f64>>,

    /// Network conditions history
    pub network_conditions_history: RwLock<VecDeque<NetworkConditions>>,
}

impl Default for AdaptiveDelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveDelayState {
    /// Create new adaptive delay state with default values
    pub fn new() -> Self {
        let current_time = Timestamp::now();

        Self {
            current_delay_window: AtomicU32::new(ADAPTIVE_DELAY_WINDOW_MIN),
            past_window_size: AtomicU32::new(ADAPTIVE_DELAY_WINDOW_MIN / 2),
            future_window_size: AtomicU32::new(ADAPTIVE_DELAY_WINDOW_MIN / 2),
            negotiated_delay_window: AtomicU32::new(ADAPTIVE_DELAY_WINDOW_MIN),
            delay_measurements: RwLock::new(VecDeque::new()),
            last_negotiation_time: AtomicU64::new(current_time.as_nanos()),
            peer_delay_window: AtomicU32::new(ADAPTIVE_DELAY_WINDOW_MIN),
            network_jitter: AtomicU32::new(0),
            packet_loss_rate: AtomicU32::new(0),
            rtt_measurement: AtomicU64::new(100_000_000), // 100ms in nanoseconds
            rtt_variance: AtomicU64::new(10_000_000),     // 10ms in nanoseconds
            is_adaptation_enabled: AtomicFlag::new(true),
            performance_history: RwLock::new(VecDeque::new()),
            network_conditions_history: RwLock::new(VecDeque::new()),
        }
    }

    /// Initialize adaptive networking system
    pub fn initialize(&self) {
        let current_time = Timestamp::now();

        self.current_delay_window
            .store(ADAPTIVE_DELAY_WINDOW_MIN, Ordering::Relaxed);
        self.negotiated_delay_window
            .store(ADAPTIVE_DELAY_WINDOW_MIN, Ordering::Relaxed);
        self.delay_measurements.write().clear();
        self.last_negotiation_time
            .store(current_time.as_nanos(), Ordering::Relaxed);
        self.peer_delay_window
            .store(ADAPTIVE_DELAY_WINDOW_MIN, Ordering::Relaxed);
        self.network_jitter.store(0, Ordering::Relaxed);
        self.packet_loss_rate.store(0, Ordering::Relaxed);
        self.rtt_measurement.store(100_000_000, Ordering::Relaxed); // 100ms in nanoseconds
        self.rtt_variance.store(10_000_000, Ordering::Relaxed); // 10ms in nanoseconds
        self.is_adaptation_enabled.store(true, Ordering::Relaxed);
        self.performance_history.write().clear();
        self.network_conditions_history.write().clear();

        info!("Adaptive networking system initialized");
    }

    /// Get effective delay window
    pub fn get_effective_delay_window(&self) -> u32 {
        if !self.is_adaptation_enabled.load(Ordering::Relaxed) {
            return ADAPTIVE_DELAY_WINDOW_MIN;
        }

        let local_window = self.current_delay_window.load(Ordering::Relaxed);
        let negotiated_window = self.negotiated_delay_window.load(Ordering::Relaxed);
        let peer_window = self.peer_delay_window.load(Ordering::Relaxed);

        // Use the minimum of local calculation, negotiated value, and peer's window
        std::cmp::min(std::cmp::min(local_window, negotiated_window), peer_window)
    }

    /// Add delay measurement
    pub fn add_delay_measurement(&self, measurement: DelayMeasurement) {
        let mut measurements = self.delay_measurements.write();
        measurements.push_back(measurement);

        // Keep only recent measurements
        while measurements.len() > DELAY_MEASUREMENT_SAMPLES {
            measurements.pop_front();
        }
    }

    /// Get recent delay measurements
    pub fn get_recent_delay_measurements(&self) -> Vec<DelayMeasurement> {
        self.delay_measurements.read().iter().cloned().collect()
    }

    /// Update network conditions
    pub fn update_network_conditions(&self, conditions: NetworkConditions) {
        let mut history = self.network_conditions_history.write();
        history.push_back(conditions);

        // Keep only recent history
        while history.len() > NETWORK_CONDITION_HISTORY_SIZE {
            history.pop_front();
        }
    }

    /// Get current network conditions
    pub fn get_current_network_conditions(&self) -> Option<NetworkConditions> {
        self.network_conditions_history.read().back().cloned()
    }
}

/// Adaptive networking configuration
#[derive(Debug, Clone)]
pub struct AdaptiveNetworkingConfig {
    pub min_delay_window: DelayWindow,
    pub max_delay_window: DelayWindow,
    pub measurement_samples: SampleCount,
    pub negotiation_interval_ms: ProtocolDuration,
    pub percentile_target: PercentileValue,
    pub safety_margin_ms: ProtocolDuration,
    pub performance_threshold: MetricValue,
    pub adaptation_enabled: bool,
}

impl Default for AdaptiveNetworkingConfig {
    fn default() -> Self {
        Self {
            min_delay_window: DelayWindow::new(ADAPTIVE_DELAY_WINDOW_MIN as u8),
            max_delay_window: DelayWindow::new(ADAPTIVE_DELAY_WINDOW_MAX as u8),
            measurement_samples: SampleCount::new(DELAY_MEASUREMENT_SAMPLES),
            negotiation_interval_ms: ProtocolDuration::new(
                DELAY_NEGOTIATION_INTERVAL_MS.as_u64() * 1_000_000,
            ),
            percentile_target: PercentileValue::new(DELAY_PERCENTILE_TARGET),
            safety_margin_ms: ProtocolDuration::from_millis(SAFETY_MARGIN_MS as u64),
            performance_threshold: MetricValue::new(PERFORMANCE_ADAPTATION_THRESHOLD),
            adaptation_enabled: true,
        }
    }
}

/// Adaptive networking statistics
#[derive(Debug, Default, Clone)]
pub struct AdaptiveNetworkingStats {
    pub current_delay_window: DelayWindow,
    pub negotiated_delay_window: DelayWindow,
    pub peer_delay_window: DelayWindow,
    pub total_measurements: PacketCount,
    pub total_adaptations: PacketCount,
    pub total_negotiations: PacketCount,
    pub current_rtt_ms: ProtocolDuration,
    pub current_jitter_ms: ProtocolDuration,
    pub current_loss_rate: MetricValue,
    pub adaptation_enabled: bool,
    pub last_negotiation_time: Timestamp,
    pub performance_score: MetricValue,
}

/// Performance monitoring data structure
#[derive(Debug, Clone)]
pub struct PerformanceMonitoringData {
    /// Timestamp of monitoring data
    pub timestamp: Timestamp,

    /// Adaptive networking statistics
    pub adaptive_stats: AdaptiveNetworkingStats,

    /// Network measurement statistics
    pub measurement_stats: crate::engines::adaptive::NetworkMeasurementStats,

    /// Optimization statistics
    pub optimization_stats: crate::engines::adaptive::OptimizationStats,

    /// Current network conditions
    pub network_conditions: NetworkConditions,

    /// Performance alerts
    pub performance_alerts: Vec<PerformanceAlert>,
}

/// Performance alert types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerformanceAlertType {
    /// High network latency
    HighLatency,

    /// High network jitter
    HighJitter,

    /// High packet loss rate
    HighPacketLoss,

    /// Network instability
    NetworkInstability,

    /// Low overall performance
    LowPerformance,

    /// Adaptation disabled
    AdaptationDisabled,
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertSeverity {
    /// Informational alert
    Info,

    /// Warning alert
    Warning,

    /// Critical alert
    Critical,
}

/// Performance alert
#[derive(Debug, Clone)]
pub struct PerformanceAlert {
    /// Type of alert
    pub alert_type: PerformanceAlertType,

    /// Severity level
    pub severity: AlertSeverity,

    /// Alert message
    pub message: String,

    /// Timestamp when alert was generated
    pub timestamp: Timestamp,

    /// Current value that triggered the alert
    pub value: MetricValue,

    /// Threshold that was exceeded
    pub threshold: MetricValue,
}

/// Adaptive Networking Engine for dynamic delay tuning
pub struct AdaptiveNetworkingEngine {
    /// Adaptive delay state
    state: Arc<AdaptiveDelayState>,

    /// Network measurement engine
    measurement: NetworkMeasurement,

    /// Parameter optimization engine
    optimization: ParameterOptimization,

    /// Configuration
    config: AdaptiveNetworkingConfig,

    /// Statistics
    stats: RwLock<AdaptiveNetworkingStats>,
}

impl AdaptiveNetworkingEngine {
    /// Create new adaptive networking engine
    pub fn new() -> Self {
        Self {
            state: Arc::new(AdaptiveDelayState::new()),
            measurement: NetworkMeasurement::new(),
            optimization: ParameterOptimization::new(),
            config: AdaptiveNetworkingConfig::default(),
            stats: RwLock::new(AdaptiveNetworkingStats::default()),
        }
    }

    /// Initialize the adaptive networking system
    pub fn initialize(&self) -> Result<(), EngineError> {
        self.state.initialize();
        self.measurement.initialize()?;
        self.optimization.initialize()?;
        Ok(())
    }

    /// Measure packet delay for adaptive delay window calculation
    pub fn measure_packet_delay(
        &self,
        packet_timestamp: Timestamp,
        packet_type: PacketType,
        packet_size: PacketSize,
    ) -> Result<(), EngineError> {
        let current_time = Timestamp::now();

        // Calculate delay (current time - packet timestamp)
        // Handle potential clock skew or reordering
        let delay_nanos = if u64::from(current_time) >= packet_timestamp.as_u64() {
            u64::from(current_time) - packet_timestamp.as_u64()
        } else {
            0 // Clock skew or early packet
        };

        // Check if packet arrived earlier than expected (negative delay)
        let is_early = u64::from(current_time) < packet_timestamp.as_u64();
        let rtt_estimate_nanos = self.state.rtt_measurement.load(Ordering::Relaxed);

        // Create measurement
        let measurement = DelayMeasurement {
            delay_ms: Duration::from_nanos(delay_nanos),
            timestamp: current_time,
            sequence: SequenceNumber::new(u64::from(current_time) as u32), // Use timestamp as sequence for now
            packet_type,
            packet_size,
            rtt_estimate: RoundTripTime::new(rtt_estimate_nanos),
            is_early,
        };

        // Add measurement to state
        self.state.add_delay_measurement(measurement.clone());

        // Process measurement with network measurement engine
        self.measurement.process_delay_measurement(&measurement)?;

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_measurements += 1;
        }

        debug!(
            delay_ms = %measurement.delay_ms.as_millis(),
            packet_type = %packet_type,
            packet_size = %packet_size,
            is_early,
            "Measured packet delay"
        );

        // Check if we should update the adaptive delay window
        let measurement_count = self.state.delay_measurements.read().len();
        if measurement_count >= self.config.measurement_samples.as_usize() {
            self.update_adaptive_delay_window()?;
            self.evaluate_window_optimization_test()?;
            self.periodic_window_optimization()?;
        }

        Ok(())
    }

    /// Update adaptive delay window based on statistical analysis
    fn update_adaptive_delay_window(&self) -> Result<(), EngineError> {
        let recent_measurements = self.state.get_recent_delay_measurements();

        if recent_measurements.is_empty() {
            return Ok(());
        }

        // Calculate statistics from measurements
        let mut delays: Vec<u64> = recent_measurements
            .iter()
            .map(|m| m.delay_ms.as_nanos() as u64)
            .collect();
        delays.sort_unstable();

        let percentile_index = (delays.len() * self.config.percentile_target.as_usize()) / 100;
        let percentile_delay_nanos = delays.get(percentile_index).copied().unwrap_or(0);

        // Calculate required windows based on delay percentiles
        let late_p95 = (percentile_delay_nanos / 1_000_000) as u32; // Convert to milliseconds
        let late_safety = (self.config.safety_margin_ms.as_nanos() / 1_000_000) as u32; // Convert to milliseconds

        // Calculate required past windows (for late packets)
        let required_past_windows =
            ((late_p95 + late_safety) as f64 / HOP_INTERVAL_MS as f64).ceil() as u32;

        // Apply adaptive bias based on packet ratios
        let early_count = recent_measurements.iter().filter(|m| m.is_early).count();
        let late_count = recent_measurements.len() - early_count;

        let early_ratio = early_count as f64 / recent_measurements.len() as f64;
        let late_ratio = late_count as f64 / recent_measurements.len() as f64;

        // Adjust windows based on packet distribution
        let adjusted_past = if late_ratio > 0.1 {
            required_past_windows + 1
        } else {
            required_past_windows
        };

        let adjusted_future = if early_ratio > 0.1 {
            2 // Increase future window for early packets
        } else {
            1
        };

        // Clamp to valid ranges
        let final_past = adjusted_past.clamp(1, (self.config.max_delay_window.as_u8() / 2) as u32);
        let final_future =
            adjusted_future.clamp(1, (self.config.max_delay_window.as_u8() / 2) as u32);
        let total_window = (final_past + final_future).clamp(
            self.config.min_delay_window.as_u8() as u32,
            self.config.max_delay_window.as_u8() as u32,
        );

        // Update state
        self.state
            .past_window_size
            .store(final_past, Ordering::Relaxed);
        self.state
            .future_window_size
            .store(final_future, Ordering::Relaxed);
        self.state
            .current_delay_window
            .store(total_window, Ordering::Relaxed);

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.current_delay_window = DelayWindow::new(total_window as u8);
            stats.total_adaptations += 1;
        }

        info!(
            total_window,
            past_window = final_past,
            future_window = final_future,
            percentile_delay = late_p95,
            early_ratio,
            late_ratio,
            "Updated adaptive delay window"
        );

        Ok(())
    }

    /// Evaluate window optimization test
    fn evaluate_window_optimization_test(&self) -> Result<(), EngineError> {
        // Check if we have enough measurements
        if self.state.delay_measurements.read().len() < self.config.measurement_samples.as_usize() {
            return Ok(());
        }

        // Get current network conditions
        let conditions = self.get_current_network_conditions();

        // Only run optimization test if network is stable
        if conditions.unstable_network || conditions.congested_network {
            debug!("Network unstable/congested, skipping window optimization test");
            return Ok(());
        }

        // Check if we are already optimizing
        if self.optimization.is_optimizing() {
            return Ok(());
        }

        // Trigger optimization if conditions are good
        // This effectively probes for better window sizes
        if conditions.packet_loss_rate.as_f64() < 0.01 && conditions.average_rtt.as_millis() < 100 {
            debug!("Conditions good, triggering optimization probe");
            self.trigger_optimization()?;
        }

        Ok(())
    }

    /// Perform periodic window optimization
    fn periodic_window_optimization(&self) -> Result<(), EngineError> {
        // Check if it's time to negotiate
        let current_time = Timestamp::now();
        let last_negotiation = self.state.last_negotiation_time.load(Ordering::Relaxed);

        if current_time.as_nanos().saturating_sub(last_negotiation)
            < DELAY_NEGOTIATION_INTERVAL_MS.as_u64()
        {
            return Ok(());
        }

        self.negotiate_delay_window()?;

        // Run parameter optimization
        self.optimization.optimize_parameters(&self.state)?;

        Ok(())
    }

    /// Negotiate delay window with peer
    fn negotiate_delay_window(&self) -> Result<(), EngineError> {
        let current_window = self.state.current_delay_window.load(Ordering::Relaxed);
        let peer_window = self.state.peer_delay_window.load(Ordering::Relaxed);

        // Negotiate to the minimum of our calculated window and the peer's advertised window
        // This ensures we don't overwhelm the peer or ourselves
        let negotiated = std::cmp::min(current_window, peer_window);

        // If peer window is 0 (not yet received), stick to our current window
        // but clamp it to a safe default if needed
        let final_negotiated = if peer_window == 0 {
            current_window
        } else {
            negotiated
        };

        self.state
            .negotiated_delay_window
            .store(final_negotiated, Ordering::Relaxed);

        let current_time = Timestamp::now();
        self.state
            .last_negotiation_time
            .store(current_time.as_nanos(), Ordering::Relaxed);

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_negotiations += 1;
            stats.negotiated_delay_window = DelayWindow::new(final_negotiated as u8);
            stats.last_negotiation_time = Timestamp::from_nanos(current_time.as_nanos());
        }

        info!(
            negotiated_window = final_negotiated,
            local_window = current_window,
            peer_window = peer_window,
            "Negotiated delay window with peer"
        );

        Ok(())
    }

    /// Get adaptive networking statistics
    pub fn get_adaptive_stats(&self) -> AdaptiveNetworkingStats {
        let mut stats = self.stats.read().clone();

        // Update current values
        stats.current_delay_window =
            DelayWindow::new(self.state.current_delay_window.load(Ordering::Relaxed) as u8);
        stats.negotiated_delay_window =
            DelayWindow::new(self.state.negotiated_delay_window.load(Ordering::Relaxed) as u8);
        stats.peer_delay_window =
            DelayWindow::new(self.state.peer_delay_window.load(Ordering::Relaxed) as u8);
        stats.current_rtt_ms = ProtocolDuration::from_millis(
            self.state.rtt_measurement.load(Ordering::Relaxed) / 1_000_000,
        ); // Convert from nanoseconds to milliseconds
        stats.current_jitter_ms =
            ProtocolDuration::from_millis(self.state.network_jitter.load(Ordering::Relaxed) as u64);
        stats.current_loss_rate =
            MetricValue::new(self.state.packet_loss_rate.load(Ordering::Relaxed) as f64 / 1000.0);
        stats.adaptation_enabled = self.state.is_adaptation_enabled.load(Ordering::Relaxed);
        stats.last_negotiation_time =
            Timestamp::from_nanos(self.state.last_negotiation_time.load(Ordering::Relaxed));

        stats
    }

    /// Enable or disable adaptation
    pub fn set_adaptation_enabled(&self, enabled: bool) {
        self.state
            .is_adaptation_enabled
            .store(enabled, Ordering::Relaxed);

        info!(enabled, "Adaptive networking adaptation enabled/disabled");
    }

    /// Get effective delay window
    pub fn get_effective_delay_window(&self) -> u32 {
        self.state.get_effective_delay_window()
    }

    /// Update peer delay window from negotiation
    pub fn update_peer_delay_window(&self, peer_window: u32) {
        self.state
            .peer_delay_window
            .store(peer_window, Ordering::Relaxed);

        info!(peer_window, "Updated peer delay window");
    }

    /// Get current network conditions from measurement engine
    pub fn get_current_network_conditions(&self) -> NetworkConditions {
        // Convert from protocol types to local adaptive engine types
        let protocol_conditions = self.measurement.get_current_network_conditions();

        // Create local NetworkConditions from protocol types
        NetworkConditions {
            timestamp: Timestamp::now(),
            packet_loss_rate: PacketLossRate::from_f64(
                protocol_conditions.packet_loss_rate.as_f32() as f64,
            ),
            average_rtt: RoundTripTime::new(protocol_conditions.latency_ns.as_nanos() / 1_000_000), // Convert ns to ms
            rtt_variance: RoundTripTime::new(protocol_conditions.jitter_ns.as_nanos() / 1_000_000), // Use jitter as variance approximation
            network_jitter: NetworkJitter::new(
                (protocol_conditions.jitter_ns.as_nanos() / 1_000_000) as u32,
            ), // Convert ns to ms
            high_latency: protocol_conditions.latency_ns.as_nanos() > 200_000_000, // >200ms in ns
            high_jitter: protocol_conditions.jitter_ns.as_nanos() > 100_000_000,   // >100ms in ns
            high_loss: protocol_conditions.packet_loss_rate.as_f32() > 0.02,       // >2%
            unstable_network: protocol_conditions.jitter_ns.as_nanos() > 50_000_000, // >50ms jitter indicates instability
            congested_network: protocol_conditions.packet_loss_rate.as_f32() > 0.01, // >1% loss indicates congestion
        }
    }

    /// Get network measurement statistics
    pub fn get_measurement_stats(&self) -> crate::engines::adaptive::NetworkMeasurementStats {
        self.measurement.get_measurement_stats()
    }

    /// Get optimization statistics
    pub fn get_optimization_stats(&self) -> crate::engines::adaptive::OptimizationStats {
        self.optimization.get_optimization_stats()
    }

    /// Reset all measurements and optimization state
    pub fn reset_adaptive_state(&self) -> Result<(), EngineError> {
        self.measurement.reset_measurements()?;
        self.optimization.reset_optimization()?;

        // Reset local state
        self.state.delay_measurements.write().clear();
        self.state.performance_history.write().clear();
        self.state.network_conditions_history.write().clear();

        info!("Reset adaptive networking state");
        Ok(())
    }

    /// Configure adaptive networking parameters
    pub fn configure(&mut self, config: AdaptiveNetworkingConfig) {
        self.config = config;

        info!(
            min_window = self.config.min_delay_window.as_u8(),
            max_window = self.config.max_delay_window.as_u8(),
            samples = self.config.measurement_samples.as_usize(),
            negotiation_interval_ns = self.config.negotiation_interval_ms.as_nanos(),
            "Configured adaptive networking parameters"
        );
    }

    /// Get current configuration
    pub fn get_config(&self) -> &AdaptiveNetworkingConfig {
        &self.config
    }

    /// Enable or disable parameter optimization
    pub fn set_optimization_enabled(&self, enabled: bool) {
        self.optimization.set_optimization_enabled(enabled);
    }

    /// Set optimization strategy
    pub fn set_optimization_strategy(
        &self,
        strategy: crate::engines::adaptive::OptimizationStrategy,
    ) {
        self.optimization.set_optimization_strategy(strategy);
    }

    /// Get optimization history
    pub fn get_optimization_history(&self) -> Vec<crate::engines::adaptive::OptimizationRecord> {
        self.optimization.get_optimization_history()
    }

    /// Get performance history
    pub fn get_performance_history(&self) -> Vec<crate::engines::adaptive::PerformanceMetrics> {
        self.optimization.get_performance_history()
    }

    /// Perform manual optimization trigger
    pub fn trigger_optimization(&self) -> Result<(), EngineError> {
        self.optimization.optimize_parameters(&self.state)
    }

    /// Get comprehensive performance monitoring data
    pub fn get_performance_monitoring_data(&self) -> PerformanceMonitoringData {
        let adaptive_stats = self.get_adaptive_stats();
        let measurement_stats = self.get_measurement_stats();
        let optimization_stats = self.get_optimization_stats();
        let network_conditions = self.get_current_network_conditions();

        PerformanceMonitoringData {
            timestamp: Timestamp::now(),
            adaptive_stats,
            measurement_stats,
            optimization_stats,
            network_conditions,
            performance_alerts: self.check_performance_alerts(),
        }
    }

    /// Check for performance alerts based on current conditions
    fn check_performance_alerts(&self) -> Vec<PerformanceAlert> {
        let mut alerts = Vec::new();
        let conditions = self.get_current_network_conditions();
        let stats = self.get_adaptive_stats();

        // High latency alert
        if conditions.high_latency {
            alerts.push(PerformanceAlert {
                alert_type: PerformanceAlertType::HighLatency,
                severity: AlertSeverity::Warning,
                message: format!(
                    "High network latency detected: {}ms",
                    conditions.average_rtt.as_millis()
                ),
                timestamp: conditions.timestamp,
                value: MetricValue::new(conditions.average_rtt.as_millis() as f64),
                threshold: MetricValue::new(HIGH_LATENCY_THRESHOLD_MS as f64),
            });
        }

        // High jitter alert
        if conditions.high_jitter {
            alerts.push(PerformanceAlert {
                alert_type: PerformanceAlertType::HighJitter,
                severity: AlertSeverity::Warning,
                message: format!(
                    "High network jitter detected: {}ms",
                    conditions.network_jitter.as_millis()
                ),
                timestamp: conditions.timestamp,
                value: MetricValue::new(conditions.network_jitter.as_millis() as f64),
                threshold: MetricValue::new(HIGH_JITTER_THRESHOLD.as_millis() as f64),
            });
        }

        // High packet loss alert
        if conditions.high_loss {
            alerts.push(PerformanceAlert {
                alert_type: PerformanceAlertType::HighPacketLoss,
                severity: AlertSeverity::Critical,
                message: format!(
                    "High packet loss detected: {:.2}%",
                    conditions.packet_loss_rate.as_per_mille() as f64 / 10.0
                ),
                timestamp: conditions.timestamp,
                value: MetricValue::new(conditions.packet_loss_rate.as_per_mille() as f64 / 1000.0),
                threshold: MetricValue::new(HIGH_LOSS_THRESHOLD),
            });
        }

        // Network instability alert
        if conditions.unstable_network {
            alerts.push(PerformanceAlert {
                alert_type: PerformanceAlertType::NetworkInstability,
                severity: AlertSeverity::Warning,
                message: format!(
                    "Network instability detected: RTT variance {}ms",
                    conditions.rtt_variance.as_millis()
                ),
                timestamp: conditions.timestamp,
                value: MetricValue::new(conditions.rtt_variance.as_millis() as f64),
                threshold: MetricValue::new(HIGH_RTT_VARIANCE_THRESHOLD_MS as f64),
            });
        }

        // Low performance score alert
        if stats.performance_score < MetricValue::new(0.5) {
            alerts.push(PerformanceAlert {
                alert_type: PerformanceAlertType::LowPerformance,
                severity: AlertSeverity::Critical,
                message: format!(
                    "Low overall performance score: {:.2}",
                    stats.performance_score
                ),
                timestamp: stats.last_negotiation_time,
                value: stats.performance_score,
                threshold: MetricValue::new(0.5),
            });
        }

        // Adaptation disabled alert
        if !stats.adaptation_enabled {
            alerts.push(PerformanceAlert {
                alert_type: PerformanceAlertType::AdaptationDisabled,
                severity: AlertSeverity::Info,
                message: "Adaptive networking is disabled".to_string(),
                timestamp: stats.last_negotiation_time,
                value: MetricValue::new(0.0),
                threshold: MetricValue::new(1.0),
            });
        }

        alerts
    }

    /// Shutdown the adaptive networking engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        // Clear all state
        self.state.delay_measurements.write().clear();
        self.state.performance_history.write().clear();
        self.state.network_conditions_history.write().clear();

        // Shutdown sub-engines
        self.measurement.shutdown().await?;
        self.optimization.shutdown().await?;

        info!("Adaptive networking engine shut down");
        Ok(())
    }
}

impl Default for AdaptiveNetworkingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_initialization() {
        let engine = AdaptiveNetworkingEngine::new();
        assert!(engine.initialize().is_ok());

        let stats = engine.get_adaptive_stats();
        assert_eq!(
            stats.current_delay_window.as_u8() as u32,
            ADAPTIVE_DELAY_WINDOW_MIN
        );
    }

    #[test]
    fn test_negotiate_delay_window() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        // Set up initial state
        engine
            .state
            .current_delay_window
            .store(10, Ordering::Relaxed);
        engine.update_peer_delay_window(5);

        // Run negotiation
        assert!(engine.negotiate_delay_window().is_ok());

        // Should negotiate to min(local, peer) = 5
        let stats = engine.get_adaptive_stats();
        assert_eq!(stats.negotiated_delay_window.as_u8(), 5);

        // Test with peer window larger than local
        engine.update_peer_delay_window(15);
        assert!(engine.negotiate_delay_window().is_ok());

        // Should negotiate to min(local, peer) = 10
        let stats = engine.get_adaptive_stats();
        assert_eq!(stats.negotiated_delay_window.as_u8(), 10);
    }

    #[test]
    fn test_evaluate_window_optimization_test() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        // Should not trigger if not enough measurements
        assert!(engine.evaluate_window_optimization_test().is_ok());

        // Add some measurements
        for _ in 0..DELAY_MEASUREMENT_SAMPLES + 1 {
            let measurement = DelayMeasurement {
                delay_ms: Duration::from_millis(50),
                timestamp: Timestamp::now(),
                sequence: SequenceNumber::new(1),
                packet_type: PacketType::Data,
                packet_size: PacketSize::new(100),
                rtt_estimate: RoundTripTime::from_millis(50),
                is_early: false,
            };
            engine.state.add_delay_measurement(measurement);
        }

        // We need to mock network conditions or ensure they are calculated
        // Since get_current_network_conditions relies on history which is populated by update_network_conditions
        // we need to populate that.

        let conditions = NetworkConditions {
            timestamp: Timestamp::now(),
            packet_loss_rate: PacketLossRate::new(0),
            average_rtt: RoundTripTime::from_millis(50),
            rtt_variance: RoundTripTime::from_millis(5),
            network_jitter: NetworkJitter::new(5),
            high_latency: false,
            high_jitter: false,
            high_loss: false,
            unstable_network: false,
            congested_network: false,
        };
        engine.state.update_network_conditions(conditions);

        // Now it should trigger optimization (we can't easily verify the trigger without mocking,
        // but we can verify it doesn't error)
        assert!(engine.evaluate_window_optimization_test().is_ok());
    }
}
