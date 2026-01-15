//! Platform-specific error types
//!
//! This module defines errors that occur when platform-specific functionality
//! is unavailable or unsupported on the current platform.

use thiserror::Error;

/// Errors that occur when platform-specific functionality is unavailable
#[derive(Error, Debug)]
pub enum PlatformError {
    /// Feature requires Linux but current platform is different
    #[error("feature '{feature}' requires Linux (current platform: {current_platform})")]
    UnsupportedPlatform {
        /// Name of the feature that requires Linux
        feature: String,
        /// Current platform name (from std::env::consts::OS)
        current_platform: String,
    },

    /// Feature requires specific kernel version
    #[error(
        "feature '{feature}' requires Linux kernel {required_version}+ (detected: {detected_version})"
    )]
    InsufficientKernelVersion {
        /// Name of the feature
        feature: String,
        /// Required kernel version
        required_version: String,
        /// Detected kernel version
        detected_version: String,
    },

    /// Feature requires specific capabilities
    #[error("feature '{feature}' requires capabilities: {capabilities}")]
    InsufficientCapabilities {
        /// Name of the feature
        feature: String,
        /// Required capabilities (comma-separated)
        capabilities: String,
    },

    /// Platform detection failed
    #[error("failed to detect platform capabilities: {reason}")]
    DetectionFailed {
        /// Reason why detection failed
        reason: String,
        /// Underlying error if available
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

/// Result type for platform operations
pub type PlatformResult<T> = Result<T, PlatformError>;
