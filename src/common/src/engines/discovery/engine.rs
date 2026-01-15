// Discovery Engine Implementation

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

use super::bloom::BloomFilterBuilder;
use super::psk_cache::PskCache;
use super::puzzle::{PuzzleChallenge, PuzzleDifficulty, PuzzleSolution, PuzzleSolver};
use super::rate_limiter::{DiscoveryRateLimiter, RateLimitConfig};
use super::timeout::{DiscoveryTimeoutManager, TimeoutConfig};
use super::{DiscoveryState, PskFingerprint};
use crate::error::EngineError;
use crate::protocol::packet::{
    DiscoveryConfirmPayload, DiscoveryPayload, DiscoveryRequestPayload, PacketBuilderEngine,
};
use crate::protocol::types::*;

/// Discovery engine for PSK discovery operations with DoS protection
pub struct DiscoveryEngine {
    /// Packet builder for creating discovery packets
    packet_builder: PacketBuilderEngine,
    /// Bloom filter builder for privacy-preserving set intersection
    bloom_builder: BloomFilterBuilder,
    /// Active discovery operations
    active_discoveries: DashMap<DiscoveryId, DiscoveryState>,
    /// Local PSK fingerprints for discovery
    local_psk_fingerprints: Arc<Vec<PskFingerprint>>,
    /// Cache for validated PSKs
    psk_cache: PskCache,
    /// Rate limiter for discovery requests
    rate_limiter: DiscoveryRateLimiter,
    /// Timeout manager for stale discovery cleanup
    timeout_manager: DiscoveryTimeoutManager,
    /// Puzzle solver for proof-of-work verification
    puzzle_solver: PuzzleSolver,
}

impl DiscoveryEngine {
    /// Create a new discovery engine with PSK fingerprints
    pub fn new(psk_fingerprints: Vec<PskFingerprint>) -> Self {
        Self::with_config(
            psk_fingerprints,
            RateLimitConfig::default(),
            TimeoutConfig::default(),
            PuzzleDifficulty::default(),
        )
    }

    /// Create a new discovery engine with custom DoS protection configuration
    pub fn with_config(
        psk_fingerprints: Vec<PskFingerprint>,
        rate_limit_config: RateLimitConfig,
        timeout_config: TimeoutConfig,
        puzzle_difficulty: PuzzleDifficulty,
    ) -> Self {
        Self {
            packet_builder: PacketBuilderEngine::new(),
            bloom_builder: BloomFilterBuilder::default(),
            active_discoveries: DashMap::new(),
            local_psk_fingerprints: Arc::new(psk_fingerprints),
            psk_cache: PskCache::new(),
            rate_limiter: DiscoveryRateLimiter::with_config(rate_limit_config),
            timeout_manager: DiscoveryTimeoutManager::with_config(timeout_config),
            puzzle_solver: PuzzleSolver::new(puzzle_difficulty),
        }
    }

    /// Check rate limit for discovery request from source IP
    pub fn check_rate_limit(&self, source_ip: IpAddr) -> Result<(), EngineError> {
        self.rate_limiter.check_rate_limit(source_ip).map_err(|e| {
            EngineError::EngineCoordinationError {
                reason: format!("Discovery rate limit exceeded: {}", e),
            }
        })
    }

    /// Generate a puzzle challenge for discovery request
    pub fn generate_puzzle_challenge(
        &self,
        session_salt: u32,
    ) -> Result<PuzzleChallenge, EngineError> {
        PuzzleChallenge::generate(self.puzzle_solver.difficulty, session_salt)
    }

    /// Verify a puzzle solution
    pub fn verify_puzzle_solution(
        &self,
        challenge: &PuzzleChallenge,
        solution: &PuzzleSolution,
    ) -> Result<(), EngineError> {
        self.puzzle_solver.verify(challenge, solution)
    }

    /// Register a discovery attempt for timeout tracking
    pub fn register_discovery_attempt(&self, discovery_id: DiscoveryId) {
        self.timeout_manager.register_attempt(discovery_id);
    }

    /// Check if a discovery attempt has timed out
    pub fn is_discovery_timed_out(&self, discovery_id: &DiscoveryId) -> bool {
        self.timeout_manager.is_timed_out(discovery_id)
    }

    /// Clean up stale discovery attempts
    pub fn cleanup_stale_discoveries(&self) {
        self.timeout_manager.cleanup_expired();
        self.rate_limiter.cleanup_expired();
    }

    /// Get puzzle solver difficulty
    pub fn puzzle_difficulty(&self) -> PuzzleDifficulty {
        self.puzzle_solver.difficulty
    }

    /// Initiate PSK discovery with a remote peer
    pub async fn initiate_discovery(&self, session_id: SessionId) -> Result<Vec<u8>, EngineError> {
        // Generate discovery ID and session salt
        let discovery_id = DiscoveryId::new(Timestamp::now().as_nanos() >> 32);
        let session_salt = (Timestamp::now().as_nanos() & 0xFFFFFFFF) as u32;

        // Create Bloom filter from local PSK fingerprints
        let bloom_filter = self.bloom_builder.build_from_fingerprints(
            &self.local_psk_fingerprints,
            discovery_id,
            session_salt,
        );

        // Build discovery request payload
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes[0..8].copy_from_slice(&discovery_id.to_be_bytes());
        let payload = DiscoveryRequestPayload {
            challenge: DiscoveryChallenge::new(challenge_bytes),
            bloom_filter,
            timeout: DiscoveryTimeout::default(),
        };

        // Build discovery packet
        let packet = self
            .packet_builder
            .discovery()
            .session_id(session_id.clone())
            .payload(DiscoveryPayload::Request(payload))
            .build()
            .map_err(|e| EngineError::EngineCoordinationError {
                reason: format!("Failed to build discovery request: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size =
            packet
                .serialize(&mut buffer)
                .map_err(|e| EngineError::EngineCoordinationError {
                    reason: format!("Failed to serialize discovery request: {:?}", e),
                })?;

        buffer.truncate(size);

        // Track discovery state
        self.active_discoveries.insert(
            discovery_id,
            DiscoveryState::AwaitingResponse {
                discovery_id,
                sent_at: Instant::now(),
            },
        );

        debug!(
            session_id = %session_id,
            discovery_id = ?discovery_id,
            size,
            "Created PSK discovery request packet"
        );

        Ok(buffer)
    }

    /// Handle discovery response (simplified - would verify candidates in real implementation)
    pub async fn handle_discovery_response(
        &self,
        _session_id: SessionId,
        discovery_id: DiscoveryId,
        candidate_hashes: Vec<CandidateHash>,
    ) -> Result<Option<PskId>, EngineError> {
        // In a real implementation, this would:
        // 1. Verify candidates against local PSK fingerprints
        // 2. Select the optimal PSK
        // 3. Create confirmation packet

        if candidate_hashes.is_empty() {
            info!("No PSK intersection found");
            return Ok(None);
        }

        // For now, select the first candidate
        // In real implementation: verify and select optimal PSK
        let selected_psk = PskId::from_u32(1); // Placeholder

        // Update discovery state
        self.active_discoveries.insert(
            discovery_id,
            DiscoveryState::SendingConfirmation {
                discovery_id,
                selected_psk: selected_psk.clone(),
            },
        );

        Ok(Some(selected_psk))
    }

    /// Create discovery confirmation packet
    pub async fn create_confirmation(
        &self,
        session_id: SessionId,
        discovery_id: DiscoveryId,
        selected_psk: PskId,
    ) -> Result<Vec<u8>, EngineError> {
        // Build confirmation payload
        let payload = DiscoveryConfirmPayload {
            selected_psk,
            confirmation_proof: PskProof::new([0u8; 16]), // Placeholder
            session_params: SessionParams::new(),
        };

        // Build discovery packet
        let packet = self
            .packet_builder
            .discovery()
            .session_id(session_id.clone())
            .payload(DiscoveryPayload::Confirm(payload))
            .build()
            .map_err(|e| EngineError::EngineCoordinationError {
                reason: format!("Failed to build discovery confirmation: {:?}", e),
            })?;

        // Serialize packet
        let mut buffer = vec![0u8; 1500];
        let size =
            packet
                .serialize(&mut buffer)
                .map_err(|e| EngineError::EngineCoordinationError {
                    reason: format!("Failed to serialize discovery confirmation: {:?}", e),
                })?;

        buffer.truncate(size);

        debug!(
            session_id = %session_id,
            discovery_id = ?discovery_id,
            size,
            "Created PSK discovery confirmation packet"
        );

        Ok(buffer)
    }

    /// Check if a discovery operation has timed out
    pub fn check_timeout(&self, discovery_id: &DiscoveryId) -> bool {
        if let Some(state) = self.active_discoveries.get(discovery_id) {
            match state.value() {
                DiscoveryState::AwaitingResponse { sent_at, .. }
                | DiscoveryState::AwaitingConfirmation { sent_at, .. } => {
                    sent_at.elapsed() > Duration::from_millis(DISCOVERY_TIMEOUT_MS)
                }
                _ => false,
            }
        } else {
            false
        }
    }

    /// Complete a discovery operation and cache the validated PSK
    pub fn complete_discovery(&self, discovery_id: &DiscoveryId, psk_id: PskId) {
        self.active_discoveries
            .insert(*discovery_id, DiscoveryState::Completed { psk_id });
    }

    /// Cache a validated PSK for session duration
    pub fn cache_psk(&self, psk_id: PskId, psk: [u8; 32], session_id: SessionId) {
        self.psk_cache.insert(psk_id, psk, session_id);
    }

    /// Get a cached PSK if it exists and has not expired
    pub fn get_cached_psk(&self, psk_id: &PskId) -> Option<super::psk_cache::CachedPsk> {
        self.psk_cache.get(psk_id)
    }

    /// Clean up expired PSKs from the cache
    pub fn cleanup_expired_psks(&self) {
        self.psk_cache.cleanup_expired();
    }

    /// Get reference to the PSK cache
    pub fn psk_cache(&self) -> &PskCache {
        &self.psk_cache
    }
}

impl Default for DiscoveryEngine {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}
