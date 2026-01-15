#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Adaptive networking engine errors
//!
//! This module defines errors for the adaptive networking engine, including network
//! measurement, parameter optimization, and adaptive behavior control. Errors include
//! context about the specific metric or optimization that failed.

use crate::protocol::types::*;
use thiserror::Error;

/// Adaptive networking engine error types
#[derive(Error, Debug, Clone)]
pub enum AdaptiveError {
    #[error("Network measurement failed: {metric} - {reason}")]
    MeasurementFailed { metric: String, reason: String },

    #[error("Measurement timeout: {metric} after {timeout_ms:?}ms")]
    MeasurementTimeout {
        metric: String,
        timeout_ms: std::time::Duration,
    },

    #[error("Measurement quality too low: {metric} quality {quality}")]
    MeasurementQualityLow { metric: String, quality: u8 },

    #[error("Insufficient measurement data: {metric} samples {samples}/{required}")]
    InsufficientMeasurementData {
        metric: String,
        samples: u32,
        required: u32,
    },

    #[error("Measurement outlier detected: {metric} value {value}")]
    MeasurementOutlier { metric: String, value: String },

    #[error("Parameter optimization failed: {parameter} - {reason}")]
    ParameterOptimizationFailed { parameter: String, reason: String },

    #[error("Parameter value invalid: {parameter} = {value} (range: {min}-{max})")]
    ParameterValueInvalid {
        parameter: String,
        value: String,
        min: String,
        max: String,
    },

    #[error("Parameter convergence failed: {parameter} after {iterations} iterations")]
    ParameterConvergenceFailed { parameter: String, iterations: u32 },

    #[error("Optimization algorithm failed: {algorithm} - {reason}")]
    OptimizationAlgorithmFailed { algorithm: String, reason: String },

    #[error("Adaptation strategy failed: {strategy} - {reason}")]
    AdaptationStrategyFailed { strategy: String, reason: String },

    #[error("Adaptation rate too high: {rate}/s (max: {max}/s)")]
    AdaptationRateTooHigh { rate: u32, max: u32 },

    #[error("Adaptation not converging: {metric} variance {variance}")]
    AdaptationNotConverging { metric: String, variance: f64 },

    #[error("Network conditions unstable: {reason}")]
    NetworkConditionsUnstable { reason: String },

    #[error("Bandwidth estimation failed: {reason}")]
    BandwidthEstimationFailed { reason: String },

    #[error("Bandwidth estimate invalid: {estimate} bps (range: {min}-{max} bps)")]
    BandwidthEstimateInvalid {
        estimate: DataRate,
        min: DataRate,
        max: DataRate,
    },

    #[error("Latency measurement failed: {reason}")]
    LatencyMeasurementFailed { reason: String },

    #[error("Latency estimate invalid: {estimate} ms (max: {max} ms)")]
    LatencyEstimateInvalid { estimate: u64, max: u64 },

    #[error("Packet loss estimation failed: {reason}")]
    PacketLossEstimationFailed { reason: String },

    #[error("Packet loss too high: {loss_rate}% (max: {max_rate}%)")]
    PacketLossTooHigh { loss_rate: f64, max_rate: f64 },

    #[error("Congestion detection failed: {reason}")]
    CongestionDetectionFailed { reason: String },

    #[error("Congestion control adjustment failed: {reason}")]
    CongestionControlAdjustmentFailed { reason: String },

    #[error("Flow rate adjustment failed: {reason}")]
    FlowRateAdjustmentFailed { reason: String },

    #[error("Window size adjustment failed: {reason}")]
    WindowSizeAdjustmentFailed { reason: String },

    #[error("RTT prediction failed: {reason}")]
    RttPredictionFailed { reason: String },

    #[error("Jitter measurement failed: {reason}")]
    JitterMeasurementFailed { reason: String },

    #[error("Metric correlation failed: {metric1} vs {metric2}")]
    MetricCorrelationFailed { metric1: String, metric2: String },

    #[error("Adaptive model invalid: {model_name} - {reason}")]
    AdaptiveModelInvalid { model_name: String, reason: String },

    #[error("Adaptive state inconsistent: {details}")]
    AdaptiveStateInconsistent { details: String },

    #[error("Adaptive history insufficient: {available} samples (min: {required})")]
    AdaptiveHistoryInsufficient { available: u32, required: u32 },

    #[error("Adaptive metrics reset required: {reason}")]
    AdaptiveMetricsResetRequired { reason: String },

    #[error("Adaptive engine not calibrated")]
    AdaptiveEngineNotCalibrated,

    #[error("Adaptive engine calibration failed: {reason}")]
    AdaptiveEngineCalibrationFailed { reason: String },

    #[error("Adaptive engine not initialized")]
    AdaptiveEngineNotInitialized,

    #[error("Adaptive engine shutdown")]
    AdaptiveEngineShutdown,
}

impl AdaptiveError {
    /// Create a measurement failed error
    pub fn measurement_failed(metric: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::MeasurementFailed {
            metric: metric.into(),
            reason: reason.into(),
        }
    }

    /// Create a parameter optimization failed error
    pub fn parameter_optimization_failed(
        parameter: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::ParameterOptimizationFailed {
            parameter: parameter.into(),
            reason: reason.into(),
        }
    }

    /// Create an adaptation strategy failed error
    pub fn adaptation_strategy_failed(
        strategy: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::AdaptationStrategyFailed {
            strategy: strategy.into(),
            reason: reason.into(),
        }
    }

    /// Create a bandwidth estimation failed error
    pub fn bandwidth_estimation_failed(reason: impl Into<String>) -> Self {
        Self::BandwidthEstimationFailed {
            reason: reason.into(),
        }
    }

    /// Create a latency measurement failed error
    pub fn latency_measurement_failed(reason: impl Into<String>) -> Self {
        Self::LatencyMeasurementFailed {
            reason: reason.into(),
        }
    }

    /// Create a network conditions unstable error
    pub fn network_conditions_unstable(reason: impl Into<String>) -> Self {
        Self::NetworkConditionsUnstable {
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::MeasurementFailed { .. } => true,
            Self::MeasurementTimeout { .. } => true,
            Self::MeasurementQualityLow { .. } => true,
            Self::InsufficientMeasurementData { .. } => true,
            Self::MeasurementOutlier { .. } => true,
            Self::ParameterOptimizationFailed { .. } => true,
            Self::ParameterValueInvalid { .. } => false,
            Self::ParameterConvergenceFailed { .. } => true,
            Self::OptimizationAlgorithmFailed { .. } => true,
            Self::AdaptationStrategyFailed { .. } => true,
            Self::AdaptationRateTooHigh { .. } => true,
            Self::AdaptationNotConverging { .. } => true,
            Self::NetworkConditionsUnstable { .. } => true,
            Self::BandwidthEstimationFailed { .. } => true,
            Self::BandwidthEstimateInvalid { .. } => true,
            Self::LatencyMeasurementFailed { .. } => true,
            Self::LatencyEstimateInvalid { .. } => true,
            Self::PacketLossEstimationFailed { .. } => true,
            Self::PacketLossTooHigh { .. } => true,
            Self::CongestionDetectionFailed { .. } => true,
            Self::CongestionControlAdjustmentFailed { .. } => true,
            Self::FlowRateAdjustmentFailed { .. } => true,
            Self::WindowSizeAdjustmentFailed { .. } => true,
            Self::RttPredictionFailed { .. } => true,
            Self::JitterMeasurementFailed { .. } => true,
            Self::MetricCorrelationFailed { .. } => true,
            Self::AdaptiveModelInvalid { .. } => false,
            Self::AdaptiveStateInconsistent { .. } => false,
            Self::AdaptiveHistoryInsufficient { .. } => true,
            Self::AdaptiveMetricsResetRequired { .. } => true,
            Self::AdaptiveEngineNotCalibrated => false,
            Self::AdaptiveEngineCalibrationFailed { .. } => true,
            Self::AdaptiveEngineNotInitialized => false,
            Self::AdaptiveEngineShutdown => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::MeasurementFailed { .. } => Some("Retry measurement with fallback method"),
            Self::MeasurementTimeout { .. } => Some("Increase measurement timeout"),
            Self::MeasurementQualityLow { .. } => Some("Collect more measurement samples"),
            Self::InsufficientMeasurementData { .. } => Some("Wait for more measurement data"),
            Self::MeasurementOutlier { .. } => Some("Discard outlier and remeasure"),
            Self::ParameterOptimizationFailed { .. } => Some("Use cached optimal parameters"),
            Self::ParameterConvergenceFailed { .. } => Some("Extend convergence iterations"),
            Self::OptimizationAlgorithmFailed { .. } => {
                Some("Use alternative optimization algorithm")
            }
            Self::AdaptationStrategyFailed { .. } => Some("Switch to conservative strategy"),
            Self::AdaptationRateTooHigh { .. } => Some("Reduce adaptation rate"),
            Self::AdaptationNotConverging { .. } => Some("Reset adaptation state"),
            Self::NetworkConditionsUnstable { .. } => Some("Wait for network stabilization"),
            Self::BandwidthEstimationFailed { .. } => Some("Use historical bandwidth estimate"),
            Self::BandwidthEstimateInvalid { .. } => Some("Clamp bandwidth to valid range"),
            Self::LatencyMeasurementFailed { .. } => Some("Use cached latency estimate"),
            Self::LatencyEstimateInvalid { .. } => Some("Clamp latency to valid range"),
            Self::PacketLossEstimationFailed { .. } => Some("Use conservative loss estimate"),
            Self::PacketLossTooHigh { .. } => Some("Reduce transmission rate"),
            Self::CongestionDetectionFailed { .. } => Some("Use fallback congestion detection"),
            Self::CongestionControlAdjustmentFailed { .. } => Some("Reset congestion window"),
            Self::FlowRateAdjustmentFailed { .. } => Some("Use default flow rate"),
            Self::WindowSizeAdjustmentFailed { .. } => Some("Use default window size"),
            Self::RttPredictionFailed { .. } => Some("Use measured RTT instead of prediction"),
            Self::JitterMeasurementFailed { .. } => Some("Use cached jitter estimate"),
            Self::MetricCorrelationFailed { .. } => Some("Use metrics independently"),
            Self::AdaptiveHistoryInsufficient { .. } => {
                Some("Wait for sufficient history accumulation")
            }
            Self::AdaptiveMetricsResetRequired { .. } => Some("Reset adaptive metrics"),
            Self::AdaptiveEngineCalibrationFailed { .. } => Some("Use default calibration"),
            _ => None,
        }
    }

    /// Get the adaptive component that caused this error
    pub fn adaptive_component(&self) -> &'static str {
        match self {
            Self::MeasurementFailed { .. }
            | Self::MeasurementTimeout { .. }
            | Self::MeasurementQualityLow { .. }
            | Self::InsufficientMeasurementData { .. }
            | Self::MeasurementOutlier { .. } => "measurement",

            Self::ParameterOptimizationFailed { .. }
            | Self::ParameterValueInvalid { .. }
            | Self::ParameterConvergenceFailed { .. }
            | Self::OptimizationAlgorithmFailed { .. } => "optimization",

            Self::AdaptationStrategyFailed { .. }
            | Self::AdaptationRateTooHigh { .. }
            | Self::AdaptationNotConverging { .. } => "adaptation_control",

            Self::BandwidthEstimationFailed { .. } | Self::BandwidthEstimateInvalid { .. } => {
                "bandwidth_estimation"
            }

            Self::LatencyMeasurementFailed { .. } | Self::LatencyEstimateInvalid { .. } => {
                "latency_measurement"
            }

            Self::PacketLossEstimationFailed { .. } | Self::PacketLossTooHigh { .. } => {
                "packet_loss_tracking"
            }

            Self::CongestionDetectionFailed { .. }
            | Self::CongestionControlAdjustmentFailed { .. } => "congestion_management",

            Self::FlowRateAdjustmentFailed { .. } | Self::WindowSizeAdjustmentFailed { .. } => {
                "parameter_adjustment"
            }

            Self::RttPredictionFailed { .. } | Self::JitterMeasurementFailed { .. } => {
                "timing_analysis"
            }

            Self::NetworkConditionsUnstable { .. }
            | Self::MetricCorrelationFailed { .. }
            | Self::AdaptiveHistoryInsufficient { .. }
            | Self::AdaptiveMetricsResetRequired { .. } => "network_analysis",

            Self::AdaptiveModelInvalid { .. }
            | Self::AdaptiveStateInconsistent { .. }
            | Self::AdaptiveEngineNotCalibrated
            | Self::AdaptiveEngineCalibrationFailed { .. }
            | Self::AdaptiveEngineNotInitialized
            | Self::AdaptiveEngineShutdown => "engine_lifecycle",
        }
    }

    /// Get the metric name for measurement-related errors
    pub fn metric_name(&self) -> Option<&str> {
        match self {
            Self::MeasurementFailed { metric, .. }
            | Self::MeasurementTimeout { metric, .. }
            | Self::MeasurementQualityLow { metric, .. }
            | Self::InsufficientMeasurementData { metric, .. }
            | Self::MeasurementOutlier { metric, .. }
            | Self::AdaptationNotConverging { metric, .. } => Some(metric),
            _ => None,
        }
    }

    /// Get the parameter name for optimization-related errors
    pub fn parameter_name(&self) -> Option<&str> {
        match self {
            Self::ParameterOptimizationFailed { parameter, .. }
            | Self::ParameterValueInvalid { parameter, .. }
            | Self::ParameterConvergenceFailed { parameter, .. } => Some(parameter),
            _ => None,
        }
    }
}

/// Adaptive networking layer result type
pub type AdaptiveResult<T> = Result<T, AdaptiveError>;
