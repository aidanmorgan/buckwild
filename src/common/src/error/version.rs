// Version compatibility errors
use crate::protocol::types::*;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum VersionError {
    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        expected: ProtocolVersion,
        actual: ProtocolVersion,
    },

    #[error("Unsupported version: {version}")]
    UnsupportedVersion { version: ProtocolVersion },
}

pub type VersionResult<T> = Result<T, VersionError>;
