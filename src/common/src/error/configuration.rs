// Configuration layer errors
use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Configuration layer error types
#[derive(Error, Debug, Clone)]
pub enum ConfigurationError {
    #[error("Configuration file not found: {path}")]
    ConfigFileNotFound { path: String },

    #[error("Configuration file read error: {path}")]
    ConfigFileReadError { path: String },

    #[error("Configuration file write error: {path}")]
    ConfigFileWriteError { path: String },

    #[error("Configuration parse error: {reason}")]
    ConfigParseError { reason: String },

    #[error("Configuration validation error: {field} = {value}")]
    ConfigValidationError { field: String, value: String },

    #[error("Invalid configuration value: {parameter} = {value}")]
    InvalidConfigValue { parameter: String, value: String },

    #[error("Missing required configuration: {parameter}")]
    MissingRequiredConfig { parameter: String },

    #[error("Configuration schema mismatch: expected {expected}, got {actual}")]
    ConfigSchemaMismatch { expected: String, actual: String },

    #[error("Configuration version mismatch: expected {expected}, got {actual}")]
    ConfigVersionMismatch {
        expected: ConfigurationVersion,
        actual: ConfigurationVersion,
    },

    #[error("Configuration lock error: {reason}")]
    ConfigLockError { reason: String },

    #[error("Configuration backup failed: {reason}")]
    ConfigBackupFailed { reason: String },

    #[error("Configuration restore failed: {reason}")]
    ConfigRestoreFailed { reason: String },

    #[error("Configuration migration failed: from {from} to {to}")]
    ConfigMigrationFailed { from: String, to: String },

    #[error("Configuration reload failed: {reason}")]
    ConfigReloadFailed { reason: String },

    #[error("Configuration watch error: {path}")]
    ConfigWatchError { path: String },

    #[error("Configuration permission denied: {path}")]
    ConfigPermissionDenied { path: String },

    #[error("Configuration directory not found: {path}")]
    ConfigDirectoryNotFound { path: String },

    #[error("Configuration format not supported: {format}")]
    ConfigFormatNotSupported { format: String },

    #[error("Configuration encryption failed: {reason}")]
    ConfigEncryptionFailed { reason: String },

    #[error("Configuration decryption failed: {reason}")]
    ConfigDecryptionFailed { reason: String },

    #[error("Configuration integrity check failed: {path}")]
    ConfigIntegrityCheckFailed { path: String },
}

impl ConfigurationError {
    /// Create a config file not found error
    pub fn config_file_not_found(path: impl Into<String>) -> Self {
        Self::ConfigFileNotFound { path: path.into() }
    }

    /// Create a config parse error
    pub fn config_parse_error(reason: impl Into<String>) -> Self {
        Self::ConfigParseError {
            reason: reason.into(),
        }
    }

    /// Create a config validation error
    pub fn config_validation_error(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self::ConfigValidationError {
            field: field.into(),
            value: value.into(),
        }
    }

    /// Create an invalid config value error
    pub fn invalid_config_value(parameter: impl Into<String>, value: impl Into<String>) -> Self {
        Self::InvalidConfigValue {
            parameter: parameter.into(),
            value: value.into(),
        }
    }

    /// Create a missing required config error
    pub fn missing_required_config(parameter: impl Into<String>) -> Self {
        Self::MissingRequiredConfig {
            parameter: parameter.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ConfigFileNotFound { .. } => false,
            Self::ConfigFileReadError { .. } => true,
            Self::ConfigFileWriteError { .. } => true,
            Self::ConfigParseError { .. } => false,
            Self::ConfigValidationError { .. } => false,
            Self::InvalidConfigValue { .. } => false,
            Self::MissingRequiredConfig { .. } => false,
            Self::ConfigSchemaMismatch { .. } => false,
            Self::ConfigVersionMismatch { .. } => true,
            Self::ConfigLockError { .. } => true,
            Self::ConfigBackupFailed { .. } => true,
            Self::ConfigRestoreFailed { .. } => true,
            Self::ConfigMigrationFailed { .. } => true,
            Self::ConfigReloadFailed { .. } => true,
            Self::ConfigWatchError { .. } => true,
            Self::ConfigPermissionDenied { .. } => false,
            Self::ConfigDirectoryNotFound { .. } => false,
            Self::ConfigFormatNotSupported { .. } => false,
            Self::ConfigEncryptionFailed { .. } => true,
            Self::ConfigDecryptionFailed { .. } => true,
            Self::ConfigIntegrityCheckFailed { .. } => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::ConfigFileReadError { .. } => Some("Check file permissions and retry"),
            Self::ConfigFileWriteError { .. } => Some("Check disk space and permissions"),
            Self::ConfigVersionMismatch { .. } => Some("Migrate configuration to new version"),
            Self::ConfigLockError { .. } => Some("Wait for lock to be released"),
            Self::ConfigBackupFailed { .. } => Some("Check backup directory permissions"),
            Self::ConfigRestoreFailed { .. } => Some("Verify backup file integrity"),
            Self::ConfigMigrationFailed { .. } => Some("Manually migrate configuration"),
            Self::ConfigReloadFailed { .. } => Some("Fix configuration errors and retry"),
            Self::ConfigWatchError { .. } => Some("Restart configuration watcher"),
            Self::ConfigEncryptionFailed { .. } => Some("Check encryption key"),
            Self::ConfigDecryptionFailed { .. } => Some("Verify decryption key"),
            _ => None,
        }
    }

    /// Get the configuration component that caused this error
    pub fn component_type(&self) -> &'static str {
        match self {
            Self::ConfigFileNotFound { .. }
            | Self::ConfigFileReadError { .. }
            | Self::ConfigFileWriteError { .. }
            | Self::ConfigDirectoryNotFound { .. }
            | Self::ConfigPermissionDenied { .. } => "file_system",

            Self::ConfigParseError { .. } | Self::ConfigFormatNotSupported { .. } => "parsing",

            Self::ConfigValidationError { .. }
            | Self::InvalidConfigValue { .. }
            | Self::MissingRequiredConfig { .. } => "validation",

            Self::ConfigSchemaMismatch { .. }
            | Self::ConfigVersionMismatch { .. }
            | Self::ConfigMigrationFailed { .. } => "schema",

            Self::ConfigLockError { .. }
            | Self::ConfigReloadFailed { .. }
            | Self::ConfigWatchError { .. } => "management",

            Self::ConfigBackupFailed { .. } | Self::ConfigRestoreFailed { .. } => "backup",

            Self::ConfigEncryptionFailed { .. }
            | Self::ConfigDecryptionFailed { .. }
            | Self::ConfigIntegrityCheckFailed { .. } => "security",
        }
    }
}

/// Configuration layer result type
pub type ConfigurationResult<T> = Result<T, ConfigurationError>;
