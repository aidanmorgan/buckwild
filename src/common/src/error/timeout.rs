// Timeout errors
use crate::protocol::types::*;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum TimeoutError {
    #[error("Operation timeout: {operation} after {timeout_ms:?}ms")]
    OperationTimeout {
        operation: String,
        timeout_ms: Duration,
    },

    #[error("Connection timeout: {endpoint} after {timeout_ms:?}ms")]
    ConnectionTimeout {
        endpoint: NetworkEndpoint,
        timeout_ms: Duration,
    },
}

pub type TimeoutResult<T> = Result<T, TimeoutError>;
