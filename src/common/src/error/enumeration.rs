// Enumeration attack detection errors
use crate::protocol::types::*;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum EnumerationError {
    #[error("Enumeration attack detected: {attack_type} from {endpoint}")]
    EnumerationAttackDetected {
        attack_type: String,
        endpoint: NetworkEndpoint,
    },

    #[error("Suspicious pattern detected: {pattern}")]
    SuspiciousPatternDetected { pattern: String },
}

pub type EnumerationResult<T> = Result<T, EnumerationError>;
