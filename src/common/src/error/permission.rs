// Permission and authorization errors
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum PermissionError {
    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },

    #[error("Access forbidden: {resource}")]
    AccessForbidden { resource: String },

    #[error("Authorization failed: {reason}")]
    AuthorizationFailed { reason: String },
}

pub type PermissionResult<T> = Result<T, PermissionError>;
