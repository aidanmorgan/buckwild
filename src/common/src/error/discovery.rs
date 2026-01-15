// Discovery layer errors
use crate::protocol::types::*;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum DiscoveryError {
    #[error("Discovery timeout: {discovery_id} after {timeout_ms:?}ms")]
    DiscoveryTimeout {
        discovery_id: DiscoveryId,
        timeout_ms: DiscoveryTimeout,
    },

    #[error("PSK proof verification failed: {psk_id:?}")]
    PskProofVerificationFailed { psk_id: String },

    #[error("Bloom filter error: {reason}")]
    BloomFilterError { reason: String },

    #[error("Discovery challenge failed: {challenge:?}")]
    DiscoveryChallengeeFailed { challenge: DiscoveryChallenge },
}

pub type DiscoveryResult<T> = Result<T, DiscoveryError>;
