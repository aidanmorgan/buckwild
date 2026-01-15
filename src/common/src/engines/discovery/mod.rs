#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Discovery Engine - PSK Discovery with Privacy-Preserving Set Intersection
//
// This module implements the privacy-preserving PSK discovery mechanism that enables
// peers to find shared pre-shared keys without revealing their complete PSK collections
// using hash-based set intersection and Bloom filters.

pub mod bloom;
pub mod engine;
pub mod protocol;
pub mod psk_cache;
pub mod puzzle;
pub mod rate_limiter;
pub mod timeout;

#[cfg(test)]
mod psi_tests;

pub use bloom::{BloomFilterBuilder, CandidateIntersection, PskFingerprint, PskHintFilter};
pub use engine::DiscoveryEngine;
pub use protocol::{
    BlindedHint, DiscoveryProtocol, DiscoveryRequest, DiscoveryResponse, ProtocolError,
    ProtocolResult, PskMatch,
};
pub use psk_cache::{CachedPsk, PskCache};
pub use puzzle::{PuzzleChallenge, PuzzleDifficulty, PuzzleSolution, PuzzleSolver};
pub use rate_limiter::{DiscoveryRateLimiter, RateLimitConfig};
pub use timeout::{DiscoveryPhase, DiscoveryTimeoutManager, TimeoutConfig};

use crate::protocol::types::*;

/// Discovery result after PSK discovery protocol
#[derive(Debug, Clone)]
pub enum DiscoveryResult {
    /// PSK discovery succeeded with selected PSK
    Success {
        psk_id: PskId,
        psk_fingerprint: PskFingerprint,
    },
    /// No common PSKs found
    NoIntersection,
    /// Discovery timeout
    Timeout,
    /// Protocol error during discovery
    ProtocolError { reason: String },
}

/// Discovery state for tracking ongoing discovery operations
#[derive(Debug, Clone)]
pub enum DiscoveryState {
    /// No discovery in progress
    Idle,
    /// Request sent, waiting for response
    AwaitingResponse {
        discovery_id: DiscoveryId,
        sent_at: std::time::Instant,
    },
    /// Response received, sending confirmation
    SendingConfirmation {
        discovery_id: DiscoveryId,
        selected_psk: PskId,
    },
    /// Awaiting final confirmation
    AwaitingConfirmation {
        discovery_id: DiscoveryId,
        sent_at: std::time::Instant,
    },
    /// Discovery completed
    Completed { psk_id: PskId },
}
