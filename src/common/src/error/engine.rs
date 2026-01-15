#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Engine layer errors
//!
//! This module defines errors for port hopping, time synchronization, recovery,
//! flow control, and adaptive networking engines. Errors include context about
//! the specific engine and operation that failed.

use thiserror::Error;

// Import specific types to avoid circular dependencies
use crate::protocol::types::{ClockSkew, Epoch, Port, ProtocolDuration, TimeOffset, WindowSize};

/// Engine layer error types
#[derive(Error, Debug, Clone)]
pub enum EngineError {
    #[error("Port hopping engine error: {reason}")]
    PortHoppingError { reason: String },

    #[error("Invalid port range: {start}-{end}")]
    InvalidPortRange { start: Port, end: Port },

    #[error("Port calculation failed: {reason}")]
    PortCalculationFailed { reason: String },

    #[error("Port coordination error: {reason}")]
    PortCoordinationError { reason: String },

    #[error("Time synchronization error: {reason}")]
    TimeSyncError { reason: String },

    #[error("Clock drift too large: {drift_ns}ns (max: {max_drift_ns}ns)")]
    ClockDriftTooLarge {
        drift_ns: ClockSkew,
        max_drift_ns: ClockSkew,
    },

    #[error("Time adjustment failed: {offset}")]
    TimeAdjustmentFailed { offset: TimeOffset },

    #[error("Epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch { expected: Epoch, actual: Epoch },

    #[error("Recovery engine error: {reason}")]
    RecoveryError { reason: String },

    #[error("Recovery strategy failed: {strategy}")]
    RecoveryStrategyFailed { strategy: String },

    #[error("Recovery coordination error: {reason}")]
    RecoveryCoordinationError { reason: String },

    #[error("Flow control error: {reason}")]
    FlowControlError { reason: String },

    #[error("Congestion detected: window size {window_size}")]
    CongestionDetected { window_size: WindowSize },

    #[error("Flow control window exhausted")]
    WindowExhausted,

    #[error("Adaptive networking error: {reason}")]
    AdaptiveNetworkingError { reason: String },

    #[error("Network measurement failed: {metric}")]
    NetworkMeasurementFailed { metric: String },

    #[error("Parameter optimization failed: {parameter}")]
    ParameterOptimizationFailed { parameter: String },

    #[error("Engine coordination error: {reason}")]
    EngineCoordinationError { reason: String },

    #[error("Engine state inconsistency: {details}")]
    StateInconsistency { details: String },

    #[error("Engine timeout: {engine} after {timeout_ms:?}ms")]
    EngineTimeout {
        engine: String,
        timeout_ms: ProtocolDuration,
    },

    #[error("Resource exhaustion: {resource}")]
    ResourceExhaustion { resource: String },

    #[error("Configuration error: {parameter} = {value}")]
    ConfigurationError { parameter: String, value: String },

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Permanent failure: {0}")]
    PermanentFailure(String),

    #[error("Backoff required: {0:?}")]
    BackoffRequired(std::time::Duration),

    #[error("Insufficient data: {0}")]
    InsufficientData(String),

    #[error("Invalid calculation: {0}")]
    InvalidCalculation(String),

    #[error("Protocol version mismatch: {0}")]
    ProtocolMismatch(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Challenge expired")]
    ChallengeExpired,

    #[error("Time error: {0}")]
    TimeError(String),

    #[error("State transition error: from {from} to {to}")]
    StateTransitionError { from: String, to: String },

    #[error("Invalid hop sequence: {reason}")]
    InvalidHopSequence { reason: String },

    #[error("Timing synchronization failed: {reason}")]
    TimingSyncFailed { reason: String },

    #[error("Engine not initialized: {engine}")]
    EngineNotInitialized { engine: String },

    #[error("Engine shutdown: {engine}")]
    EngineShutdown { engine: String },
}

impl EngineError {
    /// Create a port hopping error
    pub fn port_hopping_error(reason: impl Into<String>) -> Self {
        Self::PortHoppingError {
            reason: reason.into(),
        }
    }

    /// Create a port calculation error
    pub fn port_calculation_failed(reason: impl Into<String>) -> Self {
        Self::PortCalculationFailed {
            reason: reason.into(),
        }
    }

    /// Create a time sync error
    pub fn time_sync_error(reason: impl Into<String>) -> Self {
        Self::TimeSyncError {
            reason: reason.into(),
        }
    }

    /// Create a recovery error
    pub fn recovery_error(reason: impl Into<String>) -> Self {
        Self::RecoveryError {
            reason: reason.into(),
        }
    }

    /// Create a flow control error
    pub fn flow_control_error(reason: impl Into<String>) -> Self {
        Self::FlowControlError {
            reason: reason.into(),
        }
    }

    /// Create an adaptive networking error
    pub fn adaptive_networking_error(reason: impl Into<String>) -> Self {
        Self::AdaptiveNetworkingError {
            reason: reason.into(),
        }
    }

    /// Create an engine coordination error
    pub fn engine_coordination_error(reason: impl Into<String>) -> Self {
        Self::EngineCoordinationError {
            reason: reason.into(),
        }
    }

    /// Create a state inconsistency error
    pub fn state_inconsistency(details: impl Into<String>) -> Self {
        Self::StateInconsistency {
            details: details.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration_error(parameter: impl Into<String>, value: impl Into<String>) -> Self {
        Self::ConfigurationError {
            parameter: parameter.into(),
            value: value.into(),
        }
    }

    /// Create a window exhausted error
    pub fn window_exhausted() -> Self {
        Self::WindowExhausted
    }

    /// Create an invalid port range error
    pub fn invalid_port_range(start: Port, end: Port) -> Self {
        Self::InvalidPortRange { start, end }
    }

    /// Create a port coordination error
    pub fn port_coordination_error(reason: impl Into<String>) -> Self {
        Self::PortCoordinationError {
            reason: reason.into(),
        }
    }

    /// Create a recovery coordination error
    pub fn recovery_coordination_error(reason: impl Into<String>) -> Self {
        Self::RecoveryCoordinationError {
            reason: reason.into(),
        }
    }

    /// Create an invalid hop sequence error
    pub fn invalid_hop_sequence(reason: impl Into<String>) -> Self {
        Self::InvalidHopSequence {
            reason: reason.into(),
        }
    }

    /// Create a timing sync failed error
    pub fn timing_sync_failed(reason: impl Into<String>) -> Self {
        Self::TimingSyncFailed {
            reason: reason.into(),
        }
    }

    /// Create an engine not initialized error
    pub fn engine_not_initialized(engine: impl Into<String>) -> Self {
        Self::EngineNotInitialized {
            engine: engine.into(),
        }
    }

    /// Create an engine shutdown error
    pub fn engine_shutdown(engine: impl Into<String>) -> Self {
        Self::EngineShutdown {
            engine: engine.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::PortHoppingError { .. } => true,
            Self::InvalidPortRange { .. } => false,
            Self::PortCalculationFailed { .. } => true,
            Self::PortCoordinationError { .. } => true,
            Self::TimeSyncError { .. } => true,
            Self::ClockDriftTooLarge { .. } => true,
            Self::TimeAdjustmentFailed { .. } => true,
            Self::EpochMismatch { .. } => true,
            Self::RecoveryError { .. } => true,
            Self::RecoveryStrategyFailed { .. } => true,
            Self::RecoveryCoordinationError { .. } => true,
            Self::FlowControlError { .. } => true,
            Self::CongestionDetected { .. } => true,
            Self::WindowExhausted => true,
            Self::AdaptiveNetworkingError { .. } => true,
            Self::NetworkMeasurementFailed { .. } => true,
            Self::ParameterOptimizationFailed { .. } => true,
            Self::EngineCoordinationError { .. } => true,
            Self::StateInconsistency { .. } => false,
            Self::EngineTimeout { .. } => true,
            Self::ResourceExhaustion { .. } => true,
            Self::ConfigurationError { .. } => false,
            Self::InvalidState { .. } => false,
            Self::InvalidConfiguration { .. } => false,
            Self::PermanentFailure { .. } => false,
            Self::BackoffRequired { .. } => true,
            Self::InsufficientData { .. } => true,
            Self::InvalidCalculation { .. } => true,
            Self::ProtocolMismatch { .. } => false,
            Self::CryptoError { .. } => false,
            Self::ChallengeExpired => true,
            Self::TimeError { .. } => true,
            Self::StateTransitionError { .. } => false,
            Self::InvalidHopSequence { .. } => false,
            Self::TimingSyncFailed { .. } => true,
            Self::EngineNotInitialized { .. } => false,
            Self::EngineShutdown { .. } => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::PortHoppingError { .. } => Some("Reinitialize port hopping sequence"),
            Self::PortCalculationFailed { .. } => Some("Use fallback port calculation"),
            Self::PortCoordinationError { .. } => Some("Resynchronize port coordination"),
            Self::TimeSyncError { .. } => Some("Restart time synchronization"),
            Self::ClockDriftTooLarge { .. } => Some("Perform clock adjustment"),
            Self::TimeAdjustmentFailed { .. } => Some("Use alternative time source"),
            Self::EpochMismatch { .. } => Some("Resynchronize epoch"),
            Self::RecoveryError { .. } => Some("Try alternative recovery strategy"),
            Self::RecoveryStrategyFailed { .. } => Some("Escalate to next recovery level"),
            Self::FlowControlError { .. } => Some("Reset flow control state"),
            Self::CongestionDetected { .. } => Some("Reduce transmission rate"),
            Self::WindowExhausted => Some("Wait for window to open"),
            Self::AdaptiveNetworkingError { .. } => Some("Reset adaptive parameters"),
            Self::NetworkMeasurementFailed { .. } => Some("Use cached measurements"),
            Self::ParameterOptimizationFailed { .. } => Some("Use default parameters"),
            Self::EngineCoordinationError { .. } => Some("Restart engine coordination"),
            Self::EngineTimeout { .. } => Some("Restart engine with longer timeout"),
            Self::ResourceExhaustion { .. } => Some("Free resources and retry"),
            Self::TimingSyncFailed { .. } => Some("Retry timing synchronization"),
            _ => None,
        }
    }

    /// Get the engine type that caused this error
    pub fn engine_type(&self) -> &'static str {
        match self {
            Self::PortHoppingError { .. }
            | Self::InvalidPortRange { .. }
            | Self::PortCalculationFailed { .. }
            | Self::PortCoordinationError { .. }
            | Self::InvalidHopSequence { .. } => "port_hopping",

            Self::TimeSyncError { .. }
            | Self::ClockDriftTooLarge { .. }
            | Self::TimeAdjustmentFailed { .. }
            | Self::EpochMismatch { .. }
            | Self::TimingSyncFailed { .. } => "time_sync",

            Self::RecoveryError { .. }
            | Self::RecoveryStrategyFailed { .. }
            | Self::RecoveryCoordinationError { .. } => "recovery",

            Self::FlowControlError { .. }
            | Self::CongestionDetected { .. }
            | Self::WindowExhausted => "flow_control",

            Self::AdaptiveNetworkingError { .. }
            | Self::NetworkMeasurementFailed { .. }
            | Self::ParameterOptimizationFailed { .. } => "adaptive",

            _ => "general",
        }
    }
}

// From implementations for error conversions
impl From<crate::protocol::types::ValidationError> for EngineError {
    fn from(err: crate::protocol::types::ValidationError) -> Self {
        use crate::protocol::types::ValidationError;
        match err {
            ValidationError::InvalidPort => Self::PortCalculationFailed {
                reason: "Invalid port value".into(),
            },
            ValidationError::InvalidHmacLength => Self::FlowControlError {
                reason: "Invalid HMAC length".into(),
            },
            ValidationError::SessionIdTooLarge => Self::FlowControlError {
                reason: "Session ID too large".into(),
            },
            ValidationError::TimestampTooLarge => Self::TimeSyncError {
                reason: "Timestamp too large".into(),
            },
            ValidationError::BufferTooSmall => Self::FlowControlError {
                reason: "Buffer too small".into(),
            },
            ValidationError::InvalidSequenceNumber => Self::FlowControlError {
                reason: "Invalid sequence number".into(),
            },
            ValidationError::InvalidSessionId => Self::FlowControlError {
                reason: "Invalid session ID".into(),
            },
            ValidationError::InvalidTimestamp => Self::TimeSyncError {
                reason: "Invalid timestamp".into(),
            },
            ValidationError::InvalidPacketType => Self::FlowControlError {
                reason: "Invalid packet type".into(),
            },
            ValidationError::InvalidLength => Self::FlowControlError {
                reason: "Invalid length".into(),
            },
            ValidationError::InvalidState => Self::StateInconsistency {
                details: "Invalid state".into(),
            },
            ValidationError::InvalidConfiguration => Self::FlowControlError {
                reason: "Invalid configuration".into(),
            },
            ValidationError::InvalidProtocolVersion => Self::FlowControlError {
                reason: "Invalid protocol version".into(),
            },
            ValidationError::InvalidPayloadLength => Self::FlowControlError {
                reason: "Invalid payload length".into(),
            },
            ValidationError::InvalidWindowSize => Self::FlowControlError {
                reason: "Invalid window size".into(),
            },
            ValidationError::InvalidFragmentIndex => Self::FlowControlError {
                reason: "Invalid fragment index".into(),
            },
            ValidationError::InvalidFragmentCount => Self::FlowControlError {
                reason: "Invalid fragment count".into(),
            },
            ValidationError::InvalidChecksum => Self::FlowControlError {
                reason: "Invalid checksum".into(),
            },
            ValidationError::InvalidHmacTag => Self::FlowControlError {
                reason: "Invalid HMAC tag".into(),
            },
            ValidationError::InvalidKeyLength => Self::FlowControlError {
                reason: "Invalid key length".into(),
            },
            ValidationError::InvalidSecretLength => Self::FlowControlError {
                reason: "Invalid secret length".into(),
            },
            ValidationError::InvalidMaterialLength => Self::FlowControlError {
                reason: "Invalid material length".into(),
            },
            ValidationError::InvalidPublicKey => Self::FlowControlError {
                reason: "Invalid public key".into(),
            },
            ValidationError::InvalidPrivateKey => Self::FlowControlError {
                reason: "Invalid private key".into(),
            },
            ValidationError::InvalidNonce => Self::FlowControlError {
                reason: "Invalid nonce".into(),
            },
            ValidationError::MissingPublicKey => Self::FlowControlError {
                reason: "Missing public key".into(),
            },
            ValidationError::PortOutOfRange { port } => Self::PortCalculationFailed {
                reason: format!("Port {} out of range", port),
            },
            ValidationError::UnsupportedFeature(feature) => Self::FlowControlError {
                reason: format!("Unsupported feature: {}", feature),
            },
            ValidationError::InvalidTerminationReason => Self::FlowControlError {
                reason: "Invalid termination reason".into(),
            },
            ValidationError::InvalidResetReason => Self::FlowControlError {
                reason: "Invalid reset reason".into(),
            },
            ValidationError::InvalidErrorCode => Self::FlowControlError {
                reason: "Invalid error code".into(),
            },
            ValidationError::InvalidErrorDescription => Self::FlowControlError {
                reason: "Invalid error description".into(),
            },
            ValidationError::ReplayAttackDetected => Self::FlowControlError {
                reason: "Replay attack detected".into(),
            },
        }
    }
}

/// Engine layer result type
pub type EngineResult<T> = Result<T, EngineError>;
