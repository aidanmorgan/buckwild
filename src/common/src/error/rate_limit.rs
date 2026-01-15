// Rate limiting errors
use crate::protocol::types::*;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum RateLimitError {
    #[error("Rate limit exceeded: {current_rate} > {limit}")]
    RateLimitExceeded {
        current_rate: DataRate,
        limit: DataRate,
    },

    #[error("Request quota exceeded: {requests} requests")]
    RequestQuotaExceeded { requests: PacketCount },
}

pub type RateLimitResult<T> = Result<T, RateLimitError>;
