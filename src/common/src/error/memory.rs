// Memory management errors
use crate::protocol::types::*;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum MemoryError {
    #[error("Memory allocation failed: {size} bytes")]
    AllocationFailed { size: MemorySize },

    #[error("Memory exhausted: {used}/{total} bytes")]
    MemoryExhausted { used: MemorySize, total: MemorySize },

    #[error("Buffer overflow: {size} > {capacity}")]
    BufferOverflow {
        size: BufferSize,
        capacity: BufferSize,
    },
}

pub type MemoryResult<T> = Result<T, MemoryError>;
