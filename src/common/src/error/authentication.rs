// Authentication layer errors
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum AuthenticationError {
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Invalid credentials: {credential_type}")]
    InvalidCredentials { credential_type: String },

    #[error("Authentication timeout: after {timeout_ms:?}ms")]
    AuthenticationTimeout { timeout_ms: Duration },
}

pub type AuthenticationResult<T> = Result<T, AuthenticationError>;
