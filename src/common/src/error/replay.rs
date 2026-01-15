// Replay attack detection errors
use thiserror::Error;
// Import specific types to avoid circular dependencies
use crate::protocol::types::{SequenceNumber, SessionId, Timestamp};

#[derive(Error, Debug, Clone)]
pub enum ReplayError {
    #[error("Replay attack detected: session {session_id}, sequence {sequence}")]
    ReplayAttackDetected {
        session_id: SessionId,
        sequence: SequenceNumber,
    },

    #[error("Duplicate packet: session {session_id}, sequence {sequence}")]
    DuplicatePacket {
        session_id: SessionId,
        sequence: SequenceNumber,
    },

    #[error("Timestamp replay: {timestamp:?}")]
    TimestampReplay { timestamp: Timestamp },
}

pub type ReplayResult<T> = Result<T, ReplayError>;
