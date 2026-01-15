// Validation layer errors
use thiserror::Error;

// Import specific types to avoid circular dependencies
use crate::protocol::types::{Checksum, MemorySize};
use std::time::Duration;

/// Validation layer error types
#[derive(Error, Debug, Clone)]
pub enum ValidationError {
    #[error("Invalid input: {field} = {value}")]
    InvalidInput { field: String, value: String },

    #[error("Input too large: {field} = {size} (max: {max_size})")]
    InputTooLarge {
        field: String,
        size: MemorySize,
        max_size: MemorySize,
    },

    #[error("Input too small: {field} = {size} (min: {min_size})")]
    InputTooSmall {
        field: String,
        size: MemorySize,
        min_size: MemorySize,
    },

    #[error("Required field missing: {field}")]
    RequiredFieldMissing { field: String },

    #[error("Invalid format: {field} does not match expected format")]
    InvalidFormat { field: String },

    #[error("Invalid range: {field} = {value} not in range [{min}, {max}]")]
    InvalidRange {
        field: String,
        value: String,
        min: String,
        max: String,
    },

    #[error("Invalid checksum: expected {expected:x}, got {actual:x}")]
    InvalidChecksum {
        expected: Checksum,
        actual: Checksum,
    },

    #[error("Invalid hash: {field}")]
    InvalidHash { field: String },

    #[error("Validation timeout: {field} after {timeout_ms:?}ms")]
    ValidationTimeout { field: String, timeout_ms: Duration },

    #[error("Validation failed: {reason}")]
    ValidationFailed { reason: String },

    #[error("Schema validation failed: {schema} does not match")]
    SchemaValidationFailed { schema: String },

    #[error("Type validation failed: expected {expected}, got {actual}")]
    TypeValidationFailed { expected: String, actual: String },

    #[error("Constraint violation: {constraint}")]
    ConstraintViolation { constraint: String },

    #[error("Business rule violation: {rule}")]
    BusinessRuleViolation { rule: String },

    #[error("Cross-field validation failed: {fields}")]
    CrossFieldValidationFailed { fields: String },

    #[error("Validation context missing: {context}")]
    ValidationContextMissing { context: String },
}

impl ValidationError {
    /// Create an invalid input error
    pub fn invalid_input(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self::InvalidInput {
            field: field.into(),
            value: value.into(),
        }
    }

    /// Create a required field missing error
    pub fn required_field_missing(field: impl Into<String>) -> Self {
        Self::RequiredFieldMissing {
            field: field.into(),
        }
    }

    /// Create a validation failed error
    pub fn validation_failed(reason: impl Into<String>) -> Self {
        Self::ValidationFailed {
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::InvalidInput { .. } => false,
            Self::InputTooLarge { .. } => false,
            Self::InputTooSmall { .. } => false,
            Self::RequiredFieldMissing { .. } => false,
            Self::InvalidFormat { .. } => false,
            Self::InvalidRange { .. } => false,
            Self::InvalidChecksum { .. } => false,
            Self::InvalidHash { .. } => false,
            Self::ValidationTimeout { .. } => true,
            Self::ValidationFailed { .. } => false,
            Self::SchemaValidationFailed { .. } => false,
            Self::TypeValidationFailed { .. } => false,
            Self::ConstraintViolation { .. } => false,
            Self::BusinessRuleViolation { .. } => false,
            Self::CrossFieldValidationFailed { .. } => false,
            Self::ValidationContextMissing { .. } => true,
        }
    }
}

/// Validation layer result type
pub type ValidationResult<T> = Result<T, ValidationError>;
