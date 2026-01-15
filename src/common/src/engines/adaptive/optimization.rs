#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Parameter Optimization - Adaptive parameter optimization and tuning
//
// This module handles optimization of network parameters based on measured
// conditions and performance metrics to improve adaptive networking performance.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::engines::adaptive::AdaptiveDelayState;
use crate::error::EngineError;
use crate::protocol::types::*;

/// Optimization constants
const OPTIMIZATION_HISTORY_SIZE: usize = 20;
const PERFORMANCE_IMPROVEMENT_THRESHOLD: f64 = 0.05; // 5%
const OPTIMIZATION_COOLDOWN_MS: Duration = Duration::from_nanos(30_000_000_000); // 30 seconds in nanoseconds
const MIN_SAMPLES_FOR_OPTIMIZATION: usize = 10;

/// Parameter optimization record
#[derive(Debug, Clone)]
pub struct OptimizationRecord {
    /// Timestamp of optimization
    pub timestamp: Timestamp,

    /// Parameter that was optimized
    pub parameter: String,

    /// Old value
    pub old_value: MetricValue,

    /// New value
    pub new_value: MetricValue,

    /// Performance before optimization
    pub performance_before: Score,

    /// Performance after optimization
    pub performance_after: Score,

    /// Whether optimization was successful
    pub successful: bool,
}

/// Performance metrics for optimization
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Packet delivery success rate
    pub delivery_success_rate: Score,

    /// Average latency
    pub average_latency: RoundTripTime,

    /// Jitter level
    pub jitter_level: NetworkJitter,

    /// Throughput efficiency
    pub throughput_efficiency: Score,

    /// Overall performance score (0.0-1.0)
    pub overall_score: Score,
}

impl PerformanceMetrics {
    /// Calculate overall performance score
    pub fn calculate_overall_score(&mut self) {
        // Weighted combination of metrics
        let weights = [0.3, 0.25, 0.2, 0.25]; // delivery, latency, jitter, throughput
        let metrics = [
            self.delivery_success_rate.as_f32(),
            1.0 - (self.average_latency.as_millis() as f32 / 1000.0).min(1.0), // Normalize latency
            1.0 - (self.jitter_level.as_millis() as f32 / 500.0).min(1.0),     // Normalize jitter
            self.throughput_efficiency.as_f32(),
        ];

        let score = weights
            .iter()
            .zip(metrics.iter())
            .map(|(w, m)| w * m)
            .sum::<f32>()
            .clamp(0.0, 1.0);

        self.overall_score = Score::new(score as f64);
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        let mut metrics = Self {
            delivery_success_rate: Score::new(0.95), // 95% default
            average_latency: RoundTripTime::new(100_000_000), // 100ms in nanoseconds
            jitter_level: NetworkJitter::new(20),    // 20ms default
            throughput_efficiency: Score::new(0.8),  // 80% default
            overall_score: Score::new(0.0),
        };
        metrics.calculate_overall_score();
        metrics
    }
}

/// Optimization strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationStrategy {
    /// Conservative optimization (small changes)
    Conservative,

    /// Aggressive optimization (larger changes)
    Aggressive,

    /// Adaptive optimization (changes based on conditions)
    Adaptive,
}

/// Parameter optimization statistics
#[derive(Debug, Default, Clone)]
pub struct OptimizationStats {
    pub total_optimizations: Counter,
    pub successful_optimizations: Counter,
    pub failed_optimizations: Counter,
    pub last_optimization_time: Timestamp,
    pub current_performance_score: Score,
    pub best_performance_score: Score,
    pub optimization_strategy: String,
    pub parameters_optimized: Counter,
}

/// Parameter Optimization Engine
pub struct ParameterOptimization {
    /// Optimization history
    optimization_history: RwLock<VecDeque<OptimizationRecord>>,

    /// Performance metrics history
    performance_history: RwLock<VecDeque<PerformanceMetrics>>,

    /// Current optimization strategy
    strategy: RwLock<OptimizationStrategy>,

    /// Last optimization time (stored as nanoseconds)
    last_optimization_time_nanos: AtomicU64,

    /// Optimization cooldown period (constant after initialization)
    cooldown_period_nanos: u64,

    /// Best performance score achieved
    best_performance_score: RwLock<Score>,

    /// Current performance metrics
    current_metrics: RwLock<PerformanceMetrics>,

    /// Optimization statistics
    stats: RwLock<OptimizationStats>,

    /// Optimization enabled flag
    optimization_enabled: AtomicFlag,
}

impl ParameterOptimization {
    /// Create new parameter optimization engine
    pub fn new() -> Self {
        Self {
            optimization_history: RwLock::new(VecDeque::new()),
            performance_history: RwLock::new(VecDeque::new()),
            strategy: RwLock::new(OptimizationStrategy::Adaptive),
            last_optimization_time_nanos: AtomicU64::new(0),
            cooldown_period_nanos: OPTIMIZATION_COOLDOWN_MS.as_nanos() as u64,
            best_performance_score: RwLock::new(Score::new(0.0)),
            current_metrics: RwLock::new(PerformanceMetrics::default()),
            stats: RwLock::new(OptimizationStats::default()),
            optimization_enabled: AtomicFlag::new(true),
        }
    }

    /// Initialize the optimization engine
    pub fn initialize(&self) -> Result<(), EngineError> {
        // Clear history
        self.optimization_history.write().clear();
        self.performance_history.write().clear();

        // Reset state
        self.last_optimization_time_nanos
            .store(0, Ordering::Relaxed);
        *self.best_performance_score.write() = Score::new(0.0);
        *self.current_metrics.write() = PerformanceMetrics::default();

        info!("Parameter optimization engine initialized");
        Ok(())
    }

    /// Check if optimization is currently in progress
    pub fn is_optimizing(&self) -> bool {
        // For synchronous implementation, we are never "optimizing" in the background.
        // However, we can check if optimization is enabled.
        // If this method is used to prevent concurrent optimization, we might need a lock or flag.
        // For now, return false as optimize_parameters handles its own concurrency.
        false
    }

    /// Optimize parameters based on current state
    pub fn optimize_parameters(&self, state: &AdaptiveDelayState) -> Result<(), EngineError> {
        if !self.optimization_enabled.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Check cooldown period
        let current_time = Timestamp::now();

        let last_optimization_nanos = self.last_optimization_time_nanos.load(Ordering::Relaxed);
        let cooldown = self.cooldown_period_nanos;

        if current_time
            .as_nanos()
            .saturating_sub(last_optimization_nanos)
            < cooldown
        {
            return Ok(());
        }

        // Calculate current performance metrics
        let current_metrics = self.calculate_performance_metrics(state)?;

        // Update performance history
        {
            let mut history = self.performance_history.write();
            history.push_back(current_metrics.clone());

            while history.len() > OPTIMIZATION_HISTORY_SIZE {
                history.pop_front();
            }
        }

        // Check if we have enough data for optimization
        if self.performance_history.read().len() < MIN_SAMPLES_FOR_OPTIMIZATION {
            return Ok(());
        }

        // Determine optimization strategy
        let strategy = self.determine_optimization_strategy(&current_metrics)?;
        *self.strategy.write() = strategy;

        // Perform optimization based on strategy
        match strategy {
            OptimizationStrategy::Conservative => {
                self.perform_conservative_optimization(state, &current_metrics)?;
            }
            OptimizationStrategy::Aggressive => {
                self.perform_aggressive_optimization(state, &current_metrics)?;
            }
            OptimizationStrategy::Adaptive => {
                self.perform_adaptive_optimization(state, &current_metrics)?;
            }
        }

        // Update state
        self.last_optimization_time_nanos
            .store(current_time.as_nanos(), Ordering::Relaxed);
        *self.current_metrics.write() = current_metrics;

        Ok(())
    }

    /// Calculate performance metrics from current state
    fn calculate_performance_metrics(
        &self,
        state: &AdaptiveDelayState,
    ) -> Result<PerformanceMetrics, EngineError> {
        let network_conditions = state.get_current_network_conditions();

        let mut metrics = if let Some(conditions) = network_conditions {
            PerformanceMetrics {
                delivery_success_rate: Score::new(
                    1.0 - (conditions.packet_loss_rate.as_per_mille() as f64 / 1000.0),
                ),
                average_latency: conditions.average_rtt,
                jitter_level: conditions.network_jitter,
                throughput_efficiency: Score::new(
                    self.calculate_throughput_efficiency(&conditions),
                ),
                overall_score: Score::new(0.0),
            }
        } else {
            PerformanceMetrics::default()
        };

        metrics.calculate_overall_score();

        debug!(
            delivery_rate = metrics.delivery_success_rate.as_f32(),
            latency = metrics.average_latency.as_millis(),
            jitter = metrics.jitter_level.as_millis(),
            throughput = metrics.throughput_efficiency.as_f32(),
            overall_score = metrics.overall_score.as_f32(),
            "Calculated performance metrics"
        );

        Ok(metrics)
    }

    /// Calculate throughput efficiency
    fn calculate_throughput_efficiency(
        &self,
        conditions: &crate::engines::adaptive::engine::NetworkConditions,
    ) -> f64 {
        // Simple throughput efficiency calculation based on network conditions
        let base_efficiency = 1.0;

        // Reduce efficiency based on loss rate
        let loss_penalty = conditions.packet_loss_rate.as_f64() * 2.0; // 2x penalty for loss

        // Reduce efficiency based on high latency (>100ms)
        let latency_penalty = if conditions.average_rtt.as_u64() > 100_000_000 {
            0.1
        } else {
            0.0
        };

        // Reduce efficiency based on high jitter (>10ms)
        let jitter_penalty = if conditions.network_jitter.as_u32() as u64 > 10_000_000 {
            0.05
        } else {
            0.0
        };

        (base_efficiency - loss_penalty - latency_penalty - jitter_penalty).clamp(0.0f64, 1.0)
    }

    /// Determine optimization strategy based on current performance
    fn determine_optimization_strategy(
        &self,
        metrics: &PerformanceMetrics,
    ) -> Result<OptimizationStrategy, EngineError> {
        let performance_history = self.performance_history.read();

        if performance_history.len() < 3 {
            return Ok(OptimizationStrategy::Conservative);
        }

        // Calculate performance trend
        let recent_scores: Vec<f32> = performance_history
            .iter()
            .rev()
            .take(3)
            .map(|m| m.overall_score.as_f32())
            .collect();

        let trend = if recent_scores.len() >= 2 {
            recent_scores[0] - recent_scores[recent_scores.len() - 1]
        } else {
            0.0
        };

        let strategy = if metrics.overall_score.as_f32() < 0.5 {
            // Poor performance - be aggressive
            OptimizationStrategy::Aggressive
        } else if trend < -PERFORMANCE_IMPROVEMENT_THRESHOLD as f32 {
            // Performance declining - be conservative
            OptimizationStrategy::Conservative
        } else {
            // Stable or improving - be adaptive
            OptimizationStrategy::Adaptive
        };

        debug!(
            current_score = metrics.overall_score.as_f32(),
            trend,
            strategy = ?strategy,
            "Determined optimization strategy"
        );

        Ok(strategy)
    }

    /// Perform conservative optimization
    fn perform_conservative_optimization(
        &self,
        state: &AdaptiveDelayState,
        metrics: &PerformanceMetrics,
    ) -> Result<(), EngineError> {
        // Small adjustments to delay window based on network measurements
        let current_window = state.current_delay_window.load(Ordering::Relaxed);

        let loss_rate = metrics.delivery_success_rate.as_f32();
        let rtt_ms = metrics.average_latency.as_millis();
        let jitter_ms = metrics.jitter_level.as_millis();

        // Conservative optimization: only adjust if significantly outside target ranges
        let adjustment = if loss_rate < 0.95 {
            // High loss: increase window by 1 for more tolerance
            1
        } else if rtt_ms > 200 && current_window > 1 {
            // High latency with large window: decrease by 1 to reduce overhead
            -1
        } else if jitter_ms > 100 {
            // High jitter: increase window by 1 for stability
            1
        } else {
            0 // No change needed
        };

        if adjustment != 0 {
            let new_window = (current_window as i32 + adjustment).clamp(1, 16) as u32;
            // Apply EWMA smoothing for conservative changes
            let smoothed_window = self.apply_ewma_smoothing(current_window, new_window, 0.1);

            self.apply_window_optimization(state, current_window, smoothed_window, "conservative")?;
        }

        Ok(())
    }

    /// Perform aggressive optimization
    fn perform_aggressive_optimization(
        &self,
        state: &AdaptiveDelayState,
        metrics: &PerformanceMetrics,
    ) -> Result<(), EngineError> {
        // Larger adjustments to delay window based on network measurements
        let current_window = state.current_delay_window.load(Ordering::Relaxed);

        let loss_rate = metrics.delivery_success_rate.as_f32();
        let rtt_ms = metrics.average_latency.as_millis();
        let jitter_ms = metrics.jitter_level.as_millis();

        // Aggressive optimization: respond strongly to poor conditions
        let adjustment = if loss_rate < 0.9 {
            // High loss: increase window significantly
            3
        } else if rtt_ms > 300 && current_window > 2 {
            // Very high latency: decrease window for performance
            -2
        } else if jitter_ms > 100 {
            // High jitter: increase window for stability
            2
        } else if loss_rate > 0.98 && rtt_ms < 100 && jitter_ms < 50 && current_window > 1 {
            // Excellent conditions: try reducing window
            -1
        } else {
            0
        };

        if adjustment != 0 {
            let new_window = (current_window as i32 + adjustment).clamp(1, 16) as u32;
            // Apply EWMA smoothing for aggressive changes (higher alpha)
            let smoothed_window = self.apply_ewma_smoothing(current_window, new_window, 0.3);

            self.apply_window_optimization(state, current_window, smoothed_window, "aggressive")?;
        }

        Ok(())
    }

    /// Perform adaptive optimization
    fn perform_adaptive_optimization(
        &self,
        state: &AdaptiveDelayState,
        metrics: &PerformanceMetrics,
    ) -> Result<(), EngineError> {
        // Adaptive optimization based on RTT, loss rate, and jitter with EWMA smoothing
        let current_window = state.current_delay_window.load(Ordering::Relaxed);

        let loss_rate = metrics.delivery_success_rate.as_f32();
        let rtt_ms = metrics.average_latency.as_millis();
        let jitter_ms = metrics.jitter_level.as_millis();

        // Calculate optimal window size based on network measurements
        let optimal_window =
            self.calculate_optimal_window_size(rtt_ms, loss_rate, jitter_ms as u64);

        // Apply EWMA smoothing to prevent oscillation
        // Alpha = 0.2 provides good balance between responsiveness and stability
        let smoothed_window = self.apply_ewma_smoothing(current_window, optimal_window, 0.2);

        // Only apply if change is significant (> 1 window)
        if (smoothed_window as i32 - current_window as i32).abs() >= 1 {
            self.apply_window_optimization(state, current_window, smoothed_window, "adaptive")?;

            debug!(
                current_window,
                optimal_window,
                smoothed_window,
                rtt_ms,
                loss_rate,
                jitter_ms,
                "Applied adaptive window optimization"
            );
        }

        Ok(())
    }

    /// Calculate optimal window size based on network measurements
    fn calculate_optimal_window_size(&self, rtt_ms: u64, loss_rate: f32, jitter_ms: u64) -> u32 {
        // Base window size calculation using RTT
        // Each window is 500ms, so we need enough windows to cover RTT + margin
        let rtt_windows = ((rtt_ms as f64 / 500.0).ceil() as u32).max(1);

        // Adjust for packet loss using multiplicative increase
        let loss_adjustment = if loss_rate < 0.95 {
            // For loss rate > 5%, increase window
            // Linear scaling: 5% loss = +1, 10% loss = +2, etc.
            let loss_pct = (1.0 - loss_rate) * 100.0;
            (loss_pct / 5.0).ceil() as u32
        } else {
            0
        };

        // Adjust for jitter
        let jitter_adjustment = if jitter_ms > 50 {
            // Add 1 window per 50ms of jitter above threshold
            ((jitter_ms - 50) / 50) as u32
        } else {
            0
        };

        // Combine adjustments with safety margins
        let calculated_window = rtt_windows + loss_adjustment + jitter_adjustment;

        // Clamp to valid range
        calculated_window.clamp(1, 16)
    }

    /// Apply EWMA (Exponential Weighted Moving Average) smoothing to prevent oscillation
    ///
    /// EWMA formula: smoothed = (1 - alpha) * current + alpha * target
    ///
    /// Alpha values:
    /// - 0.1: Very smooth, slow response (conservative)
    /// - 0.2: Balanced smoothing (adaptive)
    /// - 0.3: Faster response (aggressive)
    fn apply_ewma_smoothing(&self, current: u32, target: u32, alpha: f64) -> u32 {
        let smoothed = (1.0 - alpha) * current as f64 + alpha * target as f64;
        smoothed.round() as u32
    }

    /// Apply window optimization
    fn apply_window_optimization(
        &self,
        state: &AdaptiveDelayState,
        old_window: u32,
        new_window: u32,
        strategy: &str,
    ) -> Result<(), EngineError> {
        if old_window == new_window {
            return Ok(());
        }

        // Apply the change
        state
            .current_delay_window
            .store(new_window, std::sync::atomic::Ordering::Relaxed);

        // Record optimization
        let current_time = Timestamp::now();

        let current_performance = self.current_metrics.read().overall_score;

        let record = OptimizationRecord {
            timestamp: current_time,
            parameter: "delay_window".to_string(),
            old_value: MetricValue::new(old_window as f64),
            new_value: MetricValue::new(new_window as f64),
            performance_before: current_performance,
            performance_after: Score::new(0.0), // Will be updated later
            successful: true,                   // Assume successful for now
        };

        // Add to history
        {
            let mut history = self.optimization_history.write();
            history.push_back(record);

            while history.len() > OPTIMIZATION_HISTORY_SIZE {
                history.pop_front();
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_optimizations += 1;
            stats.successful_optimizations += 1;
            stats.last_optimization_time = current_time;
            stats.optimization_strategy = strategy.to_string();
            stats.parameters_optimized += 1;
        }

        info!(
            old_window,
            new_window, strategy, "Applied window optimization"
        );

        Ok(())
    }

    /// Get optimization statistics
    pub fn get_optimization_stats(&self) -> OptimizationStats {
        let mut stats = self.stats.read().clone();

        // Update current values
        stats.current_performance_score = self.current_metrics.read().overall_score;
        stats.best_performance_score = *self.best_performance_score.read();

        stats
    }

    /// Enable or disable optimization
    pub fn set_optimization_enabled(&self, enabled: bool) {
        self.optimization_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);

        info!(enabled, "Parameter optimization enabled/disabled");
    }

    /// Set optimization strategy
    pub fn set_optimization_strategy(&self, strategy: OptimizationStrategy) {
        *self.strategy.write() = strategy;

        info!(
            strategy = ?strategy,
            "Set optimization strategy"
        );
    }

    /// Get optimization history
    pub fn get_optimization_history(&self) -> Vec<OptimizationRecord> {
        self.optimization_history.read().iter().cloned().collect()
    }

    /// Get performance history
    pub fn get_performance_history(&self) -> Vec<PerformanceMetrics> {
        self.performance_history.read().iter().cloned().collect()
    }

    /// Reset optimization state
    pub fn reset_optimization(&self) -> Result<(), EngineError> {
        self.optimization_history.write().clear();
        self.performance_history.write().clear();

        self.last_optimization_time_nanos
            .store(0, Ordering::Relaxed);
        *self.best_performance_score.write() = Score::new(0.0);
        *self.current_metrics.write() = PerformanceMetrics::default();

        info!("Reset parameter optimization state");
        Ok(())
    }

    /// Shutdown the optimization engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.optimization_history.write().clear();
        self.performance_history.write().clear();

        info!("Parameter optimization engine shut down");
        Ok(())
    }
}

impl Default for ParameterOptimization {
    fn default() -> Self {
        Self::new()
    }
}
