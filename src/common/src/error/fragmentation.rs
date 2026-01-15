// Fragmentation layer errors
use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Fragmentation layer error types
#[derive(Error, Debug, Clone)]
pub enum FragmentationError {
    #[error("Fragment too large: {size} > {max_size}")]
    FragmentTooLarge {
        size: FragmentSize,
        max_size: FragmentSize,
    },

    #[error("Fragment too small: {size} < {min_size}")]
    FragmentTooSmall {
        size: FragmentSize,
        min_size: FragmentSize,
    },

    #[error("Invalid fragment index: {index} >= {fragment_count}")]
    InvalidFragmentIndex {
        index: FragmentIndex,
        fragment_count: FragmentCount,
    },

    #[error("Fragment count exceeded: {count} > {max_count}")]
    FragmentCountExceeded {
        count: FragmentCount,
        max_count: FragmentCount,
    },

    #[error("Fragment overlap detected: fragment {fragment_id} at offset {offset}")]
    FragmentOverlap {
        fragment_id: FragmentId,
        offset: FragmentIndex,
    },

    #[error("Fragment gap detected: missing fragments {start}-{end}")]
    FragmentGap {
        start: FragmentIndex,
        end: FragmentIndex,
    },

    #[error("Fragment timeout: fragment {fragment_id} after {timeout_ms:?}ms")]
    FragmentTimeout {
        fragment_id: FragmentId,
        timeout_ms: FragmentTimeout,
    },

    #[error("Reassembly failed: {reason}")]
    ReassemblyFailed { reason: String },

    #[error("Reassembly buffer full: {used}/{max} bytes")]
    ReassemblyBufferFull {
        used: ReassemblyBufferSize,
        max: ReassemblyBufferSize,
    },

    #[error("Reassembly memory exhausted: {session_id}")]
    ReassemblyMemoryExhausted { session_id: SessionId },

    #[error("Invalid fragment state: {state:?}")]
    InvalidFragmentState { state: FragmentationState },

    #[error("Fragment ID collision: {fragment_id}")]
    FragmentIdCollision { fragment_id: FragmentId },

    #[error("Fragment sequence error: expected {expected}, got {actual}")]
    FragmentSequenceError {
        expected: FragmentIndex,
        actual: FragmentIndex,
    },

    #[error("Fragment checksum mismatch: fragment {fragment_id}")]
    FragmentChecksumMismatch { fragment_id: FragmentId },

    #[error("Fragment rate limit exceeded: {session_id}")]
    FragmentRateLimitExceeded { session_id: SessionId },

    #[error("Fragment security violation: {violation}")]
    FragmentSecurityViolation { violation: String },

    #[error("Fragment compression failed: {reason}")]
    FragmentCompressionFailed { reason: String },

    #[error("Fragment decompression failed: {reason}")]
    FragmentDecompressionFailed { reason: String },
}

impl FragmentationError {
    /// Create a fragment too large error
    pub fn fragment_too_large(size: FragmentSize, max_size: FragmentSize) -> Self {
        Self::FragmentTooLarge { size, max_size }
    }

    /// Create a fragment overlap error
    pub fn fragment_overlap(fragment_id: FragmentId, offset: FragmentIndex) -> Self {
        Self::FragmentOverlap {
            fragment_id,
            offset,
        }
    }

    /// Create a fragment timeout error
    pub fn fragment_timeout(fragment_id: FragmentId, timeout_ms: FragmentTimeout) -> Self {
        Self::FragmentTimeout {
            fragment_id,
            timeout_ms,
        }
    }

    /// Create a reassembly failed error
    pub fn reassembly_failed(reason: impl Into<String>) -> Self {
        Self::ReassemblyFailed {
            reason: reason.into(),
        }
    }

    /// Create a fragment security violation error
    pub fn fragment_security_violation(violation: impl Into<String>) -> Self {
        Self::FragmentSecurityViolation {
            violation: violation.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::FragmentTooLarge { .. } => false,
            Self::FragmentTooSmall { .. } => false,
            Self::InvalidFragmentIndex { .. } => false,
            Self::FragmentCountExceeded { .. } => false,
            Self::FragmentOverlap { .. } => false,
            Self::FragmentGap { .. } => true,
            Self::FragmentTimeout { .. } => true,
            Self::ReassemblyFailed { .. } => true,
            Self::ReassemblyBufferFull { .. } => true,
            Self::ReassemblyMemoryExhausted { .. } => true,
            Self::InvalidFragmentState { .. } => false,
            Self::FragmentIdCollision { .. } => true,
            Self::FragmentSequenceError { .. } => true,
            Self::FragmentChecksumMismatch { .. } => false,
            Self::FragmentRateLimitExceeded { .. } => true,
            Self::FragmentSecurityViolation { .. } => false,
            Self::FragmentCompressionFailed { .. } => true,
            Self::FragmentDecompressionFailed { .. } => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::FragmentGap { .. } => Some("Request missing fragments"),
            Self::FragmentTimeout { .. } => Some("Retransmit timed out fragments"),
            Self::ReassemblyFailed { .. } => Some("Restart reassembly process"),
            Self::ReassemblyBufferFull { .. } => Some("Clear old reassembly buffers"),
            Self::ReassemblyMemoryExhausted { .. } => Some("Free reassembly memory"),
            Self::FragmentIdCollision { .. } => Some("Generate new fragment ID"),
            Self::FragmentSequenceError { .. } => Some("Resynchronize fragment sequence"),
            Self::FragmentRateLimitExceeded { .. } => Some("Reduce fragmentation rate"),
            Self::FragmentCompressionFailed { .. } => Some("Disable compression"),
            _ => None,
        }
    }

    /// Check if this error indicates a potential attack
    pub fn is_potential_attack(&self) -> bool {
        matches!(
            self,
            Self::FragmentOverlap { .. }
                | Self::FragmentCountExceeded { .. }
                | Self::FragmentRateLimitExceeded { .. }
                | Self::FragmentSecurityViolation { .. }
                | Self::FragmentIdCollision { .. }
        )
    }
}

/// Fragmentation layer result type
pub type FragmentationResult<T> = Result<T, FragmentationError>;
