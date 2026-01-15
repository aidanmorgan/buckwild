// Buffer management errors
use crate::protocol::types::*;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum BufferError {
    #[error("Buffer overflow: {size} > {capacity}")]
    BufferOverflow {
        size: BufferSize,
        capacity: BufferSize,
    },

    #[error("Buffer underflow: attempted to read {requested} bytes from {available}")]
    BufferUnderflow {
        requested: BufferSize,
        available: BufferSize,
    },
}

pub type BufferResult<T> = Result<T, BufferError>;
