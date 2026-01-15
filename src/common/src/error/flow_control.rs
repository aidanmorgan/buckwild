// Flow control layer errors
use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Flow control layer error types
#[derive(Error, Debug, Clone)]
pub enum FlowControlError {
    #[error("Window exhausted: {window_type}")]
    WindowExhausted { window_type: String },

    #[error("Window overflow: {current_size} + {increment} > {max_size}")]
    WindowOverflow {
        current_size: WindowSize,
        increment: WindowSize,
        max_size: WindowSize,
    },

    #[error("Window underflow: {current_size} - {decrement} < 0")]
    WindowUnderflow {
        current_size: WindowSize,
        decrement: WindowSize,
    },

    #[error("Invalid window size: {size} (min: {min}, max: {max})")]
    InvalidWindowSize {
        size: WindowSize,
        min: WindowSize,
        max: WindowSize,
    },

    #[error("Congestion detected: state {state:?}")]
    CongestionDetected { state: CongestionState },

    #[error("Congestion window exceeded: {current} > {limit}")]
    CongestionWindowExceeded {
        current: CongestionWindow,
        limit: CongestionWindow,
    },

    #[error("Slow start threshold exceeded: {current} > {threshold}")]
    SlowStartThresholdExceeded {
        current: CongestionWindow,
        threshold: SlowStartThreshold,
    },

    #[error("Flow control violation: {violation}")]
    FlowControlViolation { violation: String },

    #[error("Rate limit exceeded: {current_rate} > {limit}")]
    RateLimitExceeded {
        current_rate: DataRate,
        limit: DataRate,
    },

    #[error("Bandwidth limit exceeded: {current} > {limit}")]
    BandwidthLimitExceeded { current: DataRate, limit: DataRate },

    #[error("Zero window probe timeout")]
    ZeroWindowProbeTimeout,

    #[error("Window update timeout")]
    WindowUpdateTimeout,

    #[error("Flow control state error: {current_state} -> {attempted_transition}")]
    FlowControlStateError {
        current_state: String,
        attempted_transition: String,
    },

    #[error("Receive window advertisement error: {advertised} vs {actual}")]
    ReceiveWindowAdvertisementError {
        advertised: AdvertisedWindow,
        actual: ReceiveWindow,
    },

    #[error("Send window calculation error: {reason}")]
    SendWindowCalculationError { reason: String },

    #[error("Effective window calculation error: {reason}")]
    EffectiveWindowCalculationError { reason: String },

    #[error("Window scaling error: scale factor {scale}")]
    WindowScalingError { scale: WindowScale },

    #[error("MSS negotiation failed: {offered} vs {accepted}")]
    MssNegotiationFailed {
        offered: MaxSegmentSize,
        accepted: MaxSegmentSize,
    },
}

impl FlowControlError {
    /// Create a window exhausted error
    pub fn window_exhausted(window_type: impl Into<String>) -> Self {
        Self::WindowExhausted {
            window_type: window_type.into(),
        }
    }

    /// Create a congestion detected error
    pub fn congestion_detected(state: CongestionState) -> Self {
        Self::CongestionDetected { state }
    }

    /// Create a flow control violation error
    pub fn flow_control_violation(violation: impl Into<String>) -> Self {
        Self::FlowControlViolation {
            violation: violation.into(),
        }
    }

    /// Create a send window calculation error
    pub fn send_window_calculation_error(reason: impl Into<String>) -> Self {
        Self::SendWindowCalculationError {
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::WindowExhausted { .. } => true,
            Self::WindowOverflow { .. } => false,
            Self::WindowUnderflow { .. } => false,
            Self::InvalidWindowSize { .. } => false,
            Self::CongestionDetected { .. } => true,
            Self::CongestionWindowExceeded { .. } => true,
            Self::SlowStartThresholdExceeded { .. } => true,
            Self::FlowControlViolation { .. } => false,
            Self::RateLimitExceeded { .. } => true,
            Self::BandwidthLimitExceeded { .. } => true,
            Self::ZeroWindowProbeTimeout => true,
            Self::WindowUpdateTimeout => true,
            Self::FlowControlStateError { .. } => false,
            Self::ReceiveWindowAdvertisementError { .. } => true,
            Self::SendWindowCalculationError { .. } => true,
            Self::EffectiveWindowCalculationError { .. } => true,
            Self::WindowScalingError { .. } => false,
            Self::MssNegotiationFailed { .. } => true,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::WindowExhausted { .. } => Some("Wait for window to open"),
            Self::CongestionDetected { .. } => Some("Reduce transmission rate"),
            Self::CongestionWindowExceeded { .. } => Some("Enter congestion avoidance"),
            Self::SlowStartThresholdExceeded { .. } => Some("Switch to congestion avoidance"),
            Self::RateLimitExceeded { .. } => Some("Reduce transmission rate"),
            Self::BandwidthLimitExceeded { .. } => Some("Throttle bandwidth usage"),
            Self::ZeroWindowProbeTimeout => Some("Retry zero window probe"),
            Self::WindowUpdateTimeout => Some("Request window update"),
            Self::ReceiveWindowAdvertisementError { .. } => {
                Some("Recalculate window advertisement")
            }
            Self::SendWindowCalculationError { .. } => Some("Recalculate send window"),
            Self::EffectiveWindowCalculationError { .. } => Some("Recalculate effective window"),
            Self::MssNegotiationFailed { .. } => Some("Use default MSS"),
            _ => None,
        }
    }

    /// Get the flow control component that caused this error
    pub fn component_type(&self) -> &'static str {
        match self {
            Self::WindowExhausted { .. }
            | Self::WindowOverflow { .. }
            | Self::WindowUnderflow { .. }
            | Self::InvalidWindowSize { .. }
            | Self::ReceiveWindowAdvertisementError { .. }
            | Self::SendWindowCalculationError { .. }
            | Self::EffectiveWindowCalculationError { .. }
            | Self::WindowScalingError { .. }
            | Self::ZeroWindowProbeTimeout
            | Self::WindowUpdateTimeout => "windowing",

            Self::CongestionDetected { .. }
            | Self::CongestionWindowExceeded { .. }
            | Self::SlowStartThresholdExceeded { .. } => "congestion_control",

            Self::RateLimitExceeded { .. } | Self::BandwidthLimitExceeded { .. } => "rate_limiting",

            Self::MssNegotiationFailed { .. } => "mss_negotiation",

            _ => "general",
        }
    }
}

/// Flow control layer result type
pub type FlowControlResult<T> = Result<T, FlowControlError>;
