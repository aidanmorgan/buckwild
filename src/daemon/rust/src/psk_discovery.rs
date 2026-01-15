//! Privacy-Preserving PSK Discovery using Hash-Based Set Intersection
//!
//! This module implements the privacy-preserving PSK discovery mechanism that enables
//! peers to find shared pre-shared keys without revealing their complete PSK collections
//! using hash-based set intersection and Bloom filters.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bit_vec::BitVec;
use dashmap::DashMap;
use ring::hmac;
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

// Import consolidated types from common crate
use buckwild_common::protocol::types::*;

use crate::crypto::{SecureBytes, constant_time_compare};
use crate::protocol::DiscoverySubType;
use crate::types::{BlindedFingerprint, PskFingerprint, SessionSalt};

/// Discovery session timeout (10 seconds)
pub const DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum number of PSKs per peer

const MAX_PSK_COUNT: usize = 256;

/// Default Bloom filter size in bits (256 bytes)

const BLOOM_FILTER_SIZE_BITS_DEFAULT: usize = 2048;

/// Maximum Bloom filter size in bits (512 bytes)

const BLOOM_FILTER_SIZE_BITS_MAX: usize = 4096;

/// Number of hash functions for Bloom filter
const BLOOM_FILTER_HASH_FUNCTIONS: usize = 3;

/// Target false positive rate (1%)

const BLOOM_FILTER_FALSE_POSITIVE_RATE: f64 = 0.01;

/// Size of blinded PSK fingerprint (128-bit)
const PSI_BLINDED_FINGERPRINT_SIZE: usize = 16;

/// Size of PSI session salt (32-bit)

const PSI_SESSION_SALT_SIZE: usize = 4;

/// Size of candidate intersection hash (256-bit)
const PSI_CANDIDATE_HASH_SIZE: usize = 32;

/// Maximum candidates in response packet
const PSI_MAX_CANDIDATES_PER_RESPONSE: usize = 16;

/// Discovery retry count

pub const DISCOVERY_RETRY_COUNT: usize = 3;

/// Discovery cache TTL (1 hour)
const DISCOVERY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

// Import consolidated types from common crate

/// Discovery session status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum DiscoveryStatus {
    Initiated,
    CandidatesFound,
    NoIntersection,
    Confirmed,
    Failed,
    Timeout,
}

/// Discovery session information
#[derive(Debug)]

pub struct DiscoverySession {
    pub discovery_id: DiscoveryId,
    pub session_salt: SessionSalt,
    pub local_fingerprints: Vec<PskFingerprint>,
    pub blinded_fingerprints: Vec<BlindedFingerprint>,
    pub bloom_filter: BitVec,
    pub filter_size: usize,
    pub num_hash_functions: usize,
    pub status: DiscoveryStatus,
    pub created_at: Instant,
    pub response_sender: Option<oneshot::Sender<DiscoveryResult>>,
}

/// Discovery result
#[derive(Debug, Clone)]

pub enum DiscoveryResult {
    Success {
        psk_fingerprint: PskFingerprint,
        psk: Arc<SecureBytes>,
    },
    NoSharedPsk,
    Timeout,
    Error(String),
}

/// Intersection verification result
#[derive(Debug, Clone)]

pub struct IntersectionResult {
    pub original_fingerprint: PskFingerprint,
    pub blinded_fingerprint: BlindedFingerprint,
    pub candidate_hash: CandidateHash,
}

/// PSK Discovery Engine
#[derive(Debug)]
pub struct PskDiscoveryEngine {
    /// Active discovery sessions
    sessions: DashMap<DiscoveryId, Arc<RwLock<DiscoverySession>>>,

    /// Local PSK fingerprints
    local_psks: Arc<RwLock<HashMap<PskFingerprint, Arc<SecureBytes>>>>,

    /// Discovery cache (fingerprint -> PSK)
    discovery_cache: DashMap<PskFingerprint, (Arc<SecureBytes>, Instant)>,

    /// Packet sender for outgoing discovery packets
    packet_sender: mpsc::UnboundedSender<DiscoveryPacket>,

    /// Packet receiver for incoming discovery packets
    packet_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<DiscoveryPacket>>>>,
}

/// Discovery packet structure
#[derive(Debug, Clone)]
pub struct DiscoveryPacket {
    pub sub_type: DiscoverySubType,
    pub discovery_id: DiscoveryId,
    pub session_salt: Option<SessionSalt>,
    pub bloom_filter: Option<BitVec>,
    pub fingerprint_count: Option<u32>,
    pub candidate_hashes: Option<Vec<CandidateHash>>,
    pub confirmation_hash: Option<CandidateHash>,
    pub confirmation_status: Option<bool>,
    pub intersection_status: Option<DiscoveryStatus>,
}

impl PskDiscoveryEngine {
    /// Create a new PSK discovery engine
    pub fn new() -> Self {
        let (packet_sender, packet_receiver) = mpsc::unbounded_channel();

        Self {
            sessions: DashMap::new(),
            local_psks: Arc::new(RwLock::new(HashMap::new())),
            discovery_cache: DashMap::new(),
            packet_sender,
            packet_receiver: Arc::new(RwLock::new(Some(packet_receiver))),
        }
    }

    /// Add a PSK to the local collection
    pub async fn add_psk(&self, fingerprint: PskFingerprint, psk: Arc<SecureBytes>) {
        let mut psks = self.local_psks.write().await;
        psks.insert(fingerprint.clone(), psk.clone());

        // Also add to cache
        self.discovery_cache
            .insert(fingerprint.clone(), (psk, Instant::now()));

        debug!("Added PSK with fingerprint: {}", fingerprint);
    }

    /// Remove a PSK from the local collection
    pub async fn remove_psk(&self, fingerprint: &PskFingerprint) {
        let mut psks = self.local_psks.write().await;
        psks.remove(fingerprint);
        self.discovery_cache.remove(fingerprint);

        debug!("Removed PSK with fingerprint: {}", fingerprint);
    }

    /// Get all local PSK fingerprints
    pub async fn get_local_fingerprints(&self) -> Vec<PskFingerprint> {
        let psks = self.local_psks.read().await;
        psks.keys().cloned().collect()
    }

    /// Initiate PSK discovery with a remote peer
    #[tracing::instrument(name = "discovery.initiate", skip(self), fields(remote_endpoint = %remote_endpoint, discovery_id, local_psk_count))]
    pub async fn initiate_discovery(
        &self,
        remote_endpoint: String,
    ) -> Result<DiscoveryResult, Box<dyn std::error::Error + Send + Sync>> {
        let local_fingerprints = self.get_local_fingerprints().await;

        if local_fingerprints.is_empty() {
            return Ok(DiscoveryResult::NoSharedPsk);
        }

        if local_fingerprints.len() > MAX_PSK_COUNT {
            return Err("Too many PSKs for discovery".into());
        }

        // Generate discovery session parameters
        let discovery_id = self.generate_discovery_id();
        let session_salt = self.generate_session_salt();

        // Record span fields
        tracing::Span::current().record("discovery_id", discovery_id.to_string());
        tracing::Span::current().record("local_psk_count", local_fingerprints.len());

        info!(
            "Initiating PSK discovery with {} (session: {}, salt: {})",
            remote_endpoint, discovery_id, session_salt
        );

        // Create blinded fingerprint set
        let blinded_fingerprints =
            self.create_blinded_fingerprint_set(&local_fingerprints, discovery_id, session_salt);

        // Generate Bloom filter
        let (bloom_filter, filter_size, num_hash_functions) =
            self.create_adaptive_bloom_filter(&blinded_fingerprints, local_fingerprints.len());

        // Create response channel
        let (response_sender, response_receiver) = oneshot::channel();

        // Create discovery session
        let session = Arc::new(RwLock::new(DiscoverySession {
            discovery_id,
            session_salt,
            local_fingerprints: local_fingerprints.clone(),
            blinded_fingerprints,
            bloom_filter: bloom_filter.clone(),
            filter_size,
            num_hash_functions,
            status: DiscoveryStatus::Initiated,
            created_at: Instant::now(),
            response_sender: Some(response_sender),
        }));

        // Store session
        self.sessions.insert(discovery_id, session.clone());

        // Send discovery request
        let request_packet = DiscoveryPacket {
            sub_type: DiscoverySubType::Request,
            discovery_id,
            session_salt: Some(session_salt),
            bloom_filter: Some(bloom_filter),
            fingerprint_count: Some(local_fingerprints.len() as u32),
            candidate_hashes: None,
            confirmation_hash: None,
            confirmation_status: None,
            intersection_status: None,
        };

        self.packet_sender.send(request_packet)?;

        // Wait for response with timeout
        match timeout(DISCOVERY_TIMEOUT, response_receiver).await {
            Ok(Ok(result)) => {
                self.sessions.remove(&discovery_id);
                Ok(result)
            }
            Ok(Err(_)) => {
                self.sessions.remove(&discovery_id);
                Ok(DiscoveryResult::Error(
                    "Response channel closed".to_string(),
                ))
            }
            Err(_) => {
                self.sessions.remove(&discovery_id);
                Ok(DiscoveryResult::Timeout)
            }
        }
    }

    /// Handle incoming discovery packet
    pub async fn handle_discovery_packet(
        &self,
        packet: DiscoveryPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match packet.sub_type {
            DiscoverySubType::Request => self.handle_discovery_request(packet).await,
            DiscoverySubType::Response => self.handle_discovery_response(packet).await,
            DiscoverySubType::Confirm => self.handle_discovery_confirm(packet).await,
        }
    }

    /// Handle discovery request
    #[tracing::instrument(name = "discovery.handle_request", skip(self, packet), fields(discovery_id = %packet.discovery_id, session_salt, peer_fingerprint_count))]
    async fn handle_discovery_request(
        &self,
        packet: DiscoveryPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let discovery_id = packet.discovery_id;
        let session_salt = packet.session_salt.ok_or("Missing session salt")?;
        let peer_bloom_filter = packet.bloom_filter.ok_or("Missing bloom filter")?;
        let peer_fingerprint_count = packet
            .fingerprint_count
            .ok_or("Missing fingerprint count")?;

        // Record span fields
        tracing::Span::current().record("session_salt", session_salt);
        tracing::Span::current().record("peer_fingerprint_count", peer_fingerprint_count);

        debug!(
            "Handling discovery request (session: {}, salt: {}, peer_count: {})",
            discovery_id, session_salt, peer_fingerprint_count
        );

        let local_fingerprints = self.get_local_fingerprints().await;

        if local_fingerprints.is_empty() {
            // Send response with no intersection
            let response_packet = DiscoveryPacket {
                sub_type: DiscoverySubType::Response,
                discovery_id,
                session_salt: None,
                bloom_filter: None,
                fingerprint_count: None,
                candidate_hashes: Some(Vec::new()),
                confirmation_hash: None,
                confirmation_status: None,
                intersection_status: Some(DiscoveryStatus::NoIntersection),
            };

            self.packet_sender.send(response_packet)?;
            return Ok(());
        }

        // Create our blinded fingerprint set using same parameters
        let local_blinded_fingerprints =
            self.create_blinded_fingerprint_set(&local_fingerprints, discovery_id, session_salt);

        // Test our fingerprints against peer's Bloom filter to find candidates
        let mut candidate_intersections = Vec::new();

        for blinded_fp in local_blinded_fingerprints.iter() {
            if self.bloom_filter_test(&peer_bloom_filter, blinded_fp) {
                // Potential intersection - add to candidates
                let candidate_hash = self.calculate_candidate_hash(blinded_fp);
                candidate_intersections.push(candidate_hash);

                if candidate_intersections.len() >= PSI_MAX_CANDIDATES_PER_RESPONSE {
                    break;
                }
            }
        }

        let intersection_status = if candidate_intersections.is_empty() {
            DiscoveryStatus::NoIntersection
        } else {
            DiscoveryStatus::CandidatesFound
        };

        // Send response with candidate intersection hashes
        let response_packet = DiscoveryPacket {
            sub_type: DiscoverySubType::Response,
            discovery_id,
            session_salt: None,
            bloom_filter: None,
            fingerprint_count: None,
            candidate_hashes: Some(candidate_intersections),
            confirmation_hash: None,
            confirmation_status: None,
            intersection_status: Some(intersection_status),
        };

        self.packet_sender.send(response_packet)?;

        // Store session for confirmation handling
        if intersection_status == DiscoveryStatus::CandidatesFound {
            let session = Arc::new(RwLock::new(DiscoverySession {
                discovery_id,
                session_salt,
                local_fingerprints,
                blinded_fingerprints: local_blinded_fingerprints,
                bloom_filter: BitVec::new(), // Not needed for responder
                filter_size: 0,
                num_hash_functions: 0,
                status: DiscoveryStatus::CandidatesFound,
                created_at: Instant::now(),
                response_sender: None,
            }));

            self.sessions.insert(discovery_id, session);
        }

        Ok(())
    }

    /// Handle discovery response
    #[tracing::instrument(name = "discovery.handle_response", skip(self, packet), fields(discovery_id = %packet.discovery_id, candidate_count, intersection_status))]
    async fn handle_discovery_response(
        &self,
        packet: DiscoveryPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let discovery_id = packet.discovery_id;
        let candidate_hashes = packet.candidate_hashes.ok_or("Missing candidate hashes")?;
        let intersection_status = packet
            .intersection_status
            .ok_or("Missing intersection status")?;

        // Record span fields
        tracing::Span::current().record("candidate_count", candidate_hashes.len());
        tracing::Span::current()
            .record("intersection_status", format!("{:?}", intersection_status));

        debug!(
            "Handling discovery response (session: {}, candidates: {}, status: {:?})",
            discovery_id,
            candidate_hashes.len(),
            intersection_status
        );

        let session_arc = self
            .sessions
            .get(&discovery_id)
            .ok_or("Discovery session not found")?
            .clone();

        let mut session = session_arc.write().await;

        if intersection_status == DiscoveryStatus::NoIntersection || candidate_hashes.is_empty() {
            // No shared PSKs found
            if let Some(sender) = session.response_sender.take() {
                let _ = sender.send(DiscoveryResult::NoSharedPsk);
            }
            return Ok(());
        }

        // Find actual intersections from candidates
        let intersection_results = self.verify_psi_candidates(
            &candidate_hashes,
            &session.local_fingerprints,
            discovery_id,
            session.session_salt,
        );

        if intersection_results.is_empty() {
            // No actual intersections (false positives)
            if let Some(sender) = session.response_sender.take() {
                let _ = sender.send(DiscoveryResult::NoSharedPsk);
            }
            return Ok(());
        }

        // Select best PSK from intersection
        let selected_fingerprint = self.select_optimal_psk(&intersection_results);

        // Calculate confirmation hash
        let confirmation_hash = self.calculate_psk_confirmation_hash(
            &selected_fingerprint,
            discovery_id,
            session.session_salt,
        );

        // Send confirmation
        let confirmation_packet = DiscoveryPacket {
            sub_type: DiscoverySubType::Confirm,
            discovery_id,
            session_salt: None,
            bloom_filter: None,
            fingerprint_count: None,
            candidate_hashes: None,
            confirmation_hash: Some(confirmation_hash),
            confirmation_status: None,
            intersection_status: None,
        };

        self.packet_sender.send(confirmation_packet)?;

        // Update session status
        session.status = DiscoveryStatus::Confirmed;

        Ok(())
    }

    /// Handle discovery confirmation
    async fn handle_discovery_confirm(
        &self,
        packet: DiscoveryPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let discovery_id = packet.discovery_id;

        debug!(
            "Handling discovery confirmation (session: {})",
            discovery_id
        );

        let session_arc = self
            .sessions
            .get(&discovery_id)
            .ok_or("Discovery session not found")?
            .clone();

        let session = session_arc.read().await;

        if let Some(confirmation_hash) = packet.confirmation_hash {
            // Verify the confirmed PSK is actually in our intersection
            let selected_fingerprint = self
                .verify_psk_confirmation(
                    &confirmation_hash,
                    &session.local_fingerprints,
                    discovery_id,
                    session.session_salt,
                )
                .await;

            if let Some(_fingerprint) = selected_fingerprint {
                // Send final confirmation
                let final_confirmation = DiscoveryPacket {
                    sub_type: DiscoverySubType::Confirm,
                    discovery_id,
                    session_salt: None,
                    bloom_filter: None,
                    fingerprint_count: None,
                    candidate_hashes: None,
                    confirmation_hash: None,
                    confirmation_status: Some(true),
                    intersection_status: None,
                };

                self.packet_sender.send(final_confirmation)?;

                info!("PSK discovery successful (session: {})", discovery_id);
            } else {
                // Invalid confirmation
                let final_confirmation = DiscoveryPacket {
                    sub_type: DiscoverySubType::Confirm,
                    discovery_id,
                    session_salt: None,
                    bloom_filter: None,
                    fingerprint_count: None,
                    candidate_hashes: None,
                    confirmation_hash: None,
                    confirmation_status: Some(false),
                    intersection_status: None,
                };

                self.packet_sender.send(final_confirmation)?;

                warn!("Invalid PSK confirmation (session: {})", discovery_id);
            }
        } else if let Some(status) = packet.confirmation_status {
            // Final confirmation from initiator
            if status {
                info!("PSK discovery confirmed (session: {})", discovery_id);
            } else {
                warn!("PSK discovery rejected (session: {})", discovery_id);
            }
        }

        Ok(())
    }
    /// Generate a secure random discovery ID
    fn generate_discovery_id(&self) -> DiscoveryId {
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();
        let mut bytes = [0u8; 8];
        // SAFETY: SystemRandom::fill only fails if the system RNG is unavailable,
        // which is a critical system failure that cannot be recovered from.
        // Using expect here is appropriate as continuing without randomness would be insecure.
        rng.fill(&mut bytes)
            .expect("System RNG unavailable - critical failure");
        DiscoveryId::new(u64::from_be_bytes(bytes))
    }

    /// Generate a secure random session salt
    fn generate_session_salt(&self) -> SessionSalt {
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();
        let mut bytes = [0u8; 4];
        // SAFETY: SystemRandom::fill only fails if the system RNG is unavailable,
        // which is a critical system failure that cannot be recovered from.
        // Using expect here is appropriate as continuing without randomness would be insecure.
        rng.fill(&mut bytes)
            .expect("System RNG unavailable - critical failure");
        u32::from_be_bytes(bytes)
    }

    /// Create blinded fingerprint set using HMAC with session context
    #[tracing::instrument(name = "discovery.blind_fingerprints", skip(self, psk_fingerprints), fields(fingerprint_count = psk_fingerprints.len(), discovery_id = %discovery_id, session_salt))]
    fn create_blinded_fingerprint_set(
        &self,
        psk_fingerprints: &[PskFingerprint],
        discovery_id: DiscoveryId,
        session_salt: SessionSalt,
    ) -> Vec<BlindedFingerprint> {
        let mut blinded_set = Vec::with_capacity(psk_fingerprints.len());

        // Create discovery context
        let mut discovery_context = Vec::with_capacity(12);
        discovery_context.extend_from_slice(&discovery_id.to_be_bytes());
        discovery_context.extend_from_slice(&session_salt.to_be_bytes());

        for fingerprint in psk_fingerprints {
            // Create blinded fingerprint using HMAC with discovery context
            let key = hmac::Key::new(hmac::HMAC_SHA256, fingerprint.as_bytes());
            let mut data = discovery_context.clone();
            data.extend_from_slice(b"psi_blinding_v1");

            let signature = hmac::sign(&key, &data);
            let signature_bytes = signature.as_ref();

            // Take first 16 bytes for blinded fingerprint
            let mut blinded_fp = [0u8; PSI_BLINDED_FINGERPRINT_SIZE];
            blinded_fp.copy_from_slice(&signature_bytes[..PSI_BLINDED_FINGERPRINT_SIZE]);

            blinded_set.push(blinded_fp);
        }

        blinded_set
    }

    /// Calculate optimal Bloom filter parameters
    fn calculate_optimal_bloom_parameters(
        &self,
        expected_items: usize,
        desired_false_positive_rate: f64,
    ) -> (usize, usize) {
        // Optimal filter size: m = -(n * ln(p)) / (ln(2)^2)
        let filter_size_bits = (-(expected_items as f64) * desired_false_positive_rate.ln()
            / (2.0_f64.ln().powi(2))) as usize;

        // Optimal number of hash functions: k = (m/n) * ln(2)
        let num_hash_functions =
            ((filter_size_bits as f64 / expected_items as f64) * 2.0_f64.ln()) as usize;

        // Ensure reasonable bounds
        let filter_size_bits =
            filter_size_bits.clamp(BLOOM_FILTER_SIZE_BITS_DEFAULT, BLOOM_FILTER_SIZE_BITS_MAX);
        let num_hash_functions = num_hash_functions.clamp(1, 8);

        (filter_size_bits, num_hash_functions)
    }

    /// Create adaptive Bloom filter based on PSK count
    fn create_adaptive_bloom_filter(
        &self,
        blinded_fingerprints: &[BlindedFingerprint],
        psk_count: usize,
    ) -> (BitVec, usize, usize) {
        let (filter_size, num_hashes) =
            self.calculate_optimal_bloom_parameters(psk_count, BLOOM_FILTER_FALSE_POSITIVE_RATE);

        let bloom_filter =
            self.create_psk_bloom_filter(blinded_fingerprints, filter_size, num_hashes);

        (bloom_filter, filter_size, num_hashes)
    }

    /// Create Bloom filter for efficient set intersection testing
    #[tracing::instrument(name = "discovery.create_bloom_filter", skip(self, blinded_fingerprints), fields(fingerprint_count = blinded_fingerprints.len(), filter_size_bits, num_hash_functions))]
    fn create_psk_bloom_filter(
        &self,
        blinded_fingerprints: &[BlindedFingerprint],
        filter_size_bits: usize,
        num_hash_functions: usize,
    ) -> BitVec {
        let mut bloom_filter = BitVec::from_elem(filter_size_bits, false);

        for blinded_fp in blinded_fingerprints {
            // Apply multiple hash functions to each fingerprint
            for i in 0..num_hash_functions {
                let hash_input = self.create_bloom_hash_input(blinded_fp, i as u8);
                let hash_output = Sha256::digest(&hash_input);

                // Map hash to bit position in filter
                let bit_position = u32::from_be_bytes([
                    hash_output[0],
                    hash_output[1],
                    hash_output[2],
                    hash_output[3],
                ]) as usize
                    % filter_size_bits;

                bloom_filter.set(bit_position, true);
            }
        }

        bloom_filter
    }

    /// Test if blinded fingerprint might be in the Bloom filter set
    fn bloom_filter_test(
        &self,
        bloom_filter: &BitVec,
        blinded_fingerprint: &BlindedFingerprint,
    ) -> bool {
        let filter_size_bits = bloom_filter.len();

        for i in 0..BLOOM_FILTER_HASH_FUNCTIONS {
            let hash_input = self.create_bloom_hash_input(blinded_fingerprint, i as u8);
            let hash_output = Sha256::digest(&hash_input);

            let bit_position = u32::from_be_bytes([
                hash_output[0],
                hash_output[1],
                hash_output[2],
                hash_output[3],
            ]) as usize
                % filter_size_bits;

            // SAFETY: bit_position is computed modulo filter_size_bits, so it's always in bounds.
            // The unwrap_or is defensive but should never trigger.
            if !bloom_filter.get(bit_position).unwrap_or(false) {
                return false; // Definitely not in set
            }
        }

        true // Possibly in set (could be false positive)
    }

    /// Create hash input for Bloom filter hash function
    fn create_bloom_hash_input(
        &self,
        blinded_fingerprint: &BlindedFingerprint,
        index: u8,
    ) -> Vec<u8> {
        let mut hash_input = Vec::with_capacity(blinded_fingerprint.len() + 1 + 13);
        hash_input.extend_from_slice(blinded_fingerprint);
        hash_input.push(index);
        hash_input.extend_from_slice(b"bloom_hash_v1");
        hash_input
    }

    /// Calculate candidate hash for intersection verification
    fn calculate_candidate_hash(&self, blinded_fingerprint: &BlindedFingerprint) -> CandidateHash {
        let mut hasher = Sha256::new();
        hasher.update(blinded_fingerprint);
        hasher.update(b"candidate_v1");

        let result = hasher.finalize();
        let mut candidate_hash = [0u8; PSI_CANDIDATE_HASH_SIZE];
        candidate_hash.copy_from_slice(&result);
        CandidateHash::new(candidate_hash)
    }

    /// Verify which candidates are actual intersections
    #[tracing::instrument(name = "discovery.verify_candidates", skip(self, candidate_hashes, local_psk_fingerprints), fields(candidate_count = candidate_hashes.len(), local_psk_count = local_psk_fingerprints.len(), discovery_id = %discovery_id, verified_count))]
    fn verify_psi_candidates(
        &self,
        candidate_hashes: &[CandidateHash],
        local_psk_fingerprints: &[PskFingerprint],
        discovery_id: DiscoveryId,
        session_salt: SessionSalt,
    ) -> Vec<IntersectionResult> {
        let mut verified_intersections = Vec::new();

        // Recreate our blinded fingerprints
        let local_blinded_fps =
            self.create_blinded_fingerprint_set(local_psk_fingerprints, discovery_id, session_salt);

        // Check each candidate against our actual fingerprints
        for (i, blinded_fp) in local_blinded_fps.iter().enumerate() {
            let expected_candidate_hash = self.calculate_candidate_hash(blinded_fp);

            if candidate_hashes.contains(&expected_candidate_hash) {
                // This is a real intersection
                verified_intersections.push(IntersectionResult {
                    original_fingerprint: local_psk_fingerprints[i].clone(),
                    blinded_fingerprint: *blinded_fp,
                    candidate_hash: expected_candidate_hash,
                });
            }
        }

        // Record verified count
        tracing::Span::current().record("verified_count", verified_intersections.len());

        verified_intersections
    }

    /// Select the optimal PSK from intersection results
    ///
    /// # Panics
    /// Panics if intersection_results is empty. Caller must ensure non-empty results.
    fn select_optimal_psk(&self, intersection_results: &[IntersectionResult]) -> PskFingerprint {
        // SAFETY: This is a logic error - we should never call this with empty results.
        // The caller (handle_discovery_response) checks for empty results before calling.
        // This assertion catches programmer errors rather than runtime conditions.
        assert!(
            !intersection_results.is_empty(),
            "Cannot select PSK from empty intersection results"
        );

        if intersection_results.len() == 1 {
            return intersection_results[0].original_fingerprint.clone();
        }

        // For now, select the first one (lexicographically smallest)
        // In a real implementation, this could consider PSK priority, recency, etc.
        let mut sorted_results = intersection_results.to_vec();
        sorted_results.sort_by_key(|r| r.original_fingerprint.clone());

        sorted_results[0].original_fingerprint.clone()
    }

    /// Calculate confirmation hash for selected PSK
    fn calculate_psk_confirmation_hash(
        &self,
        psk_fingerprint: &PskFingerprint,
        discovery_id: DiscoveryId,
        session_salt: SessionSalt,
    ) -> CandidateHash {
        let mut hasher = Sha256::new();
        hasher.update(psk_fingerprint);
        hasher.update(discovery_id.to_be_bytes());
        hasher.update(session_salt.to_be_bytes());
        hasher.update(b"psk_confirmation_v1");

        let result = hasher.finalize();
        let mut confirmation_hash = [0u8; PSI_CANDIDATE_HASH_SIZE];
        confirmation_hash.copy_from_slice(&result);
        CandidateHash::new(confirmation_hash)
    }

    /// Verify PSK confirmation hash
    async fn verify_psk_confirmation(
        &self,
        confirmation_hash: &CandidateHash,
        local_psk_fingerprints: &[PskFingerprint],
        discovery_id: DiscoveryId,
        session_salt: SessionSalt,
    ) -> Option<PskFingerprint> {
        for fingerprint in local_psk_fingerprints {
            let expected_hash =
                self.calculate_psk_confirmation_hash(fingerprint, discovery_id, session_salt);

            if constant_time_compare(confirmation_hash.as_bytes(), expected_hash.as_bytes()) {
                return Some(fingerprint.clone());
            }
        }

        None
    }

    /// Resolve PSK from fingerprint
    async fn resolve_psk_from_fingerprint(
        &self,
        psk_fingerprint: &PskFingerprint,
    ) -> Option<Arc<SecureBytes>> {
        // First check cache
        if let Some(entry) = self.discovery_cache.get(psk_fingerprint) {
            let (psk, cached_at) = entry.value();
            if cached_at.elapsed() < DISCOVERY_CACHE_TTL {
                return Some(psk.clone());
            }
            // Remove expired entry
            drop(entry);
            self.discovery_cache.remove(psk_fingerprint);
        }

        // Check local PSKs
        let psks = self.local_psks.read().await;
        if let Some(psk) = psks.get(psk_fingerprint) {
            let psk_clone = psk.clone();
            drop(psks);

            // Update cache
            self.discovery_cache
                .insert(psk_fingerprint.clone(), (psk_clone.clone(), Instant::now()));

            return Some(psk_clone);
        }

        None
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let now = Instant::now();
        let mut expired_sessions = Vec::new();

        // Find expired sessions
        for entry in self.sessions.iter() {
            let session_arc = entry.value();
            let session = session_arc.read().await;

            if now.duration_since(session.created_at) > DISCOVERY_TIMEOUT {
                expired_sessions.push(*entry.key());
            }
        }

        // Remove expired sessions
        for session_id in expired_sessions {
            if let Some((_, session_arc)) = self.sessions.remove(&session_id) {
                let mut session = session_arc.write().await;

                // Send timeout result if response sender exists
                if let Some(sender) = session.response_sender.take() {
                    let _ = sender.send(DiscoveryResult::Timeout);
                }

                debug!("Cleaned up expired discovery session: {}", session_id);
            }
        }

        // Clean up expired cache entries
        let mut expired_cache_entries = Vec::new();

        for entry in self.discovery_cache.iter() {
            let (_, cached_at) = entry.value();
            if now.duration_since(*cached_at) > DISCOVERY_CACHE_TTL {
                expired_cache_entries.push(entry.key().clone());
            }
        }

        for fingerprint in expired_cache_entries {
            self.discovery_cache.remove(&fingerprint);
        }
    }

    /// Get discovery statistics
    pub async fn get_statistics(&self) -> PskDiscoveryStatistics {
        let local_psks = self.local_psks.read().await;

        PskDiscoveryStatistics {
            active_sessions: self.sessions.len(),
            cached_psks: self.discovery_cache.len(),
            local_psks: local_psks.len(),
        }
    }

    /// Get packet receiver for processing incoming packets
    pub async fn take_packet_receiver(&self) -> Option<mpsc::UnboundedReceiver<DiscoveryPacket>> {
        let mut receiver = self.packet_receiver.write().await;
        receiver.take()
    }

    /// Send a discovery packet
    pub fn send_packet(
        &self,
        packet: DiscoveryPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.packet_sender.send(packet)?;
        Ok(())
    }

    /// Start the discovery engine packet processing
    pub async fn start_packet_processing(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut packet_receiver = self
            .packet_receiver
            .write()
            .await
            .take()
            .ok_or("Packet processing already started")?;

        let engine = self.clone();

        tokio::spawn(async move {
            while let Some(packet) = packet_receiver.recv().await {
                if let Err(e) = engine.handle_discovery_packet(packet).await {
                    error!("Error handling discovery packet: {}", e);
                }
            }
        });

        Ok(())
    }
}

impl Clone for PskDiscoveryEngine {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            local_psks: self.local_psks.clone(),
            discovery_cache: self.discovery_cache.clone(),
            packet_sender: self.packet_sender.clone(),
            packet_receiver: self.packet_receiver.clone(),
        }
    }
}

/// PSK Discovery Engine statistics
#[derive(Debug, Clone)]

pub struct PskDiscoveryStatistics {
    pub active_sessions: usize,
    pub cached_psks: usize,
    pub local_psks: usize,
}
