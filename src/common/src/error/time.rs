// Time synchronization layer errors
use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Time synchronization layer error types
#[derive(Error, Debug, Clone)]
pub enum TimeError {
    #[error("Clock drift too large: {drift} ppm (max: {max_drift} ppm)")]
    ClockDriftTooLarge {
        drift: TimeDrift,
        max_drift: TimeDrift,
    },

    #[error("Clock skew too large: {skew}ns (max: {max_skew}ns)")]
    ClockSkewTooLarge {
        skew: ClockSkew,
        max_skew: ClockSkew,
    },

    #[error("Time synchronization failed: {reason}")]
    TimeSyncFailed { reason: String },

    #[error("Time adjustment failed: offset {offset}ns")]
    TimeAdjustmentFailed { offset: TimeOffset },

    #[error("Timestamp validation failed: {timestamp:?} outside window")]
    TimestampValidationFailed { timestamp: Timestamp },

    #[error("Timestamp window expired: {timestamp:?} vs {current}")]
    TimestampWindowExpired {
        timestamp: Timestamp,
        current: Timestamp,
    },

    #[error("Epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch { expected: Epoch, actual: Epoch },

    #[error("Epoch transition failed: {from} -> {to}")]
    EpochTransitionFailed { from: Epoch, to: Epoch },

    #[error("Time bucket calculation failed: {timestamp:?}")]
    TimeBucketCalculationFailed { timestamp: Timestamp },

    #[error("RTT measurement failed: {reason}")]
    RttMeasurementFailed { reason: String },

    #[error("RTT too large: {rtt}ns (max: {max_rtt}ns)")]
    RttTooLarge {
        rtt: RoundTripTime,
        max_rtt: RoundTripTime,
    },

    #[error("Network delay too large: {delay}ns (max: {max_delay}ns)")]
    NetworkDelayTooLarge {
        delay: NetworkDelay,
        max_delay: NetworkDelay,
    },

    #[error("Sync quality too low: {quality} (min: {min_quality})")]
    SyncQualityTooLow {
        quality: SyncQuality,
        min_quality: SyncQuality,
    },

    #[error("Time source unavailable: {source_name}")]
    TimeSourceUnavailable { source_name: String },

    #[error("Time source unreliable: {source_name}")]
    TimeSourceUnreliable { source_name: String },

    #[error("Sync state transition error: {from:?} -> {to:?}")]
    SyncStateTransitionError { from: String, to: String },

    #[error("Time negotiation failed: {reason}")]
    TimeNegotiationFailed { reason: String },

    #[error("Time protocol error: {reason}")]
    TimeProtocolError { reason: String },

    #[error("Heartbeat timeout: expected every {interval}ms")]
    HeartbeatTimeout { interval: HeartbeatInterval },

    #[error("Time resync required: drift {drift} ppm")]
    TimeResyncRequired { drift: TimeDrift },
}

impl TimeError {
    /// Create a clock drift too large error
    pub fn clock_drift_too_large(drift: TimeDrift, max_drift: TimeDrift) -> Self {
        Self::ClockDriftTooLarge { drift, max_drift }
    }

    /// Create a time sync failed error
    pub fn time_sync_failed(reason: impl Into<String>) -> Self {
        Self::TimeSyncFailed {
            reason: reason.into(),
        }
    }

    /// Create a timestamp validation failed error
    pub fn timestamp_validation_failed(timestamp: Timestamp) -> Self {
        Self::TimestampValidationFailed { timestamp }
    }

    /// Create an epoch mismatch error
    pub fn epoch_mismatch(expected: Epoch, actual: Epoch) -> Self {
        Self::EpochMismatch { expected, actual }
    }

    /// Create an RTT measurement failed error
    pub fn rtt_measurement_failed(reason: impl Into<String>) -> Self {
        Self::RttMeasurementFailed {
            reason: reason.into(),
        }
    }

    /// Create a time negotiation failed error
    pub fn time_negotiation_failed(reason: impl Into<String>) -> Self {
        Self::TimeNegotiationFailed {
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ClockDriftTooLarge { .. } => true,
            Self::ClockSkewTooLarge { .. } => true,
            Self::TimeSyncFailed { .. } => true,
            Self::TimeAdjustmentFailed { .. } => true,
            Self::TimestampValidationFailed { .. } => false,
            Self::TimestampWindowExpired { .. } => false,
            Self::EpochMismatch { .. } => true,
            Self::EpochTransitionFailed { .. } => true,
            Self::TimeBucketCalculationFailed { .. } => true,
            Self::RttMeasurementFailed { .. } => true,
            Self::RttTooLarge { .. } => true,
            Self::NetworkDelayTooLarge { .. } => true,
            Self::SyncQualityTooLow { .. } => true,
            Self::TimeSourceUnavailable { .. } => true,
            Self::TimeSourceUnreliable { .. } => true,
            Self::SyncStateTransitionError { .. } => false,
            Self::TimeNegotiationFailed { .. } => true,
            Self::TimeProtocolError { .. } => true,
            Self::HeartbeatTimeout { .. } => true,
            Self::TimeResyncRequired { .. } => true,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::ClockDriftTooLarge { .. } => Some("Perform clock adjustment"),
            Self::ClockSkewTooLarge { .. } => Some("Resynchronize clocks"),
            Self::TimeSyncFailed { .. } => Some("Retry time synchronization"),
            Self::TimeAdjustmentFailed { .. } => Some("Use alternative time source"),
            Self::EpochMismatch { .. } => Some("Resynchronize epoch"),
            Self::EpochTransitionFailed { .. } => Some("Retry epoch transition"),
            Self::TimeBucketCalculationFailed { .. } => Some("Recalculate time bucket"),
            Self::RttMeasurementFailed { .. } => Some("Retry RTT measurement"),
            Self::RttTooLarge { .. } => Some("Check network conditions"),
            Self::NetworkDelayTooLarge { .. } => Some("Check network path"),
            Self::SyncQualityTooLow { .. } => Some("Improve time source quality"),
            Self::TimeSourceUnavailable { .. } => Some("Use backup time source"),
            Self::TimeSourceUnreliable { .. } => Some("Switch to reliable time source"),
            Self::TimeNegotiationFailed { .. } => Some("Retry time negotiation"),
            Self::TimeProtocolError { .. } => Some("Reset time protocol state"),
            Self::HeartbeatTimeout { .. } => Some("Send heartbeat immediately"),
            Self::TimeResyncRequired { .. } => Some("Perform full time resync"),
            _ => None,
        }
    }

    /// Get the time component that caused this error
    pub fn component_type(&self) -> &'static str {
        match self {
            Self::ClockDriftTooLarge { .. }
            | Self::ClockSkewTooLarge { .. }
            | Self::TimeAdjustmentFailed { .. } => "clock_adjustment",

            Self::TimeSyncFailed { .. }
            | Self::TimeNegotiationFailed { .. }
            | Self::TimeProtocolError { .. }
            | Self::TimeResyncRequired { .. } => "synchronization",

            Self::TimestampValidationFailed { .. } | Self::TimestampWindowExpired { .. } => {
                "timestamp_validation"
            }

            Self::EpochMismatch { .. }
            | Self::EpochTransitionFailed { .. }
            | Self::TimeBucketCalculationFailed { .. } => "epoch_management",

            Self::RttMeasurementFailed { .. }
            | Self::RttTooLarge { .. }
            | Self::NetworkDelayTooLarge { .. } => "network_measurement",

            Self::SyncQualityTooLow { .. }
            | Self::TimeSourceUnavailable { .. }
            | Self::TimeSourceUnreliable { .. } => "time_source",

            Self::HeartbeatTimeout { .. } => "heartbeat",

            _ => "general",
        }
    }
}

/// Time synchronization layer result type
pub type TimeResult<T> = Result<T, TimeError>;
