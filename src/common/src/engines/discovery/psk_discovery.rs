#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// PSK Discovery - Privacy-Preserving Set Intersection Protocol
//
// Implements complete PSK discovery per design/protocol/05-psk-discovery.md:
// - Blinded fingerprint creation (HKDF + HMAC)
// - Bloom filter operations (adaptive parameters)
// - Discovery protocol (4 phases: request, response, verification, confirmation)
// - Privacy-preserving: no PSK exposure during discovery

use std::collections::HashSet;
use ring::{digest, hkdf, hmac};
use tracing::{debug, info, warn};

use crate::error::EngineError;
use crate::protocol::types::*;

/// PSK fingerprint (SHA-256 hash of PSK)
pub type PskFingerprint = [u8; 32];

/// Blinded fingerprint (HMAC of PSK with session-specific key)
pub type BlindedFingerprint = [u8; 32];

/// Discovery ID (unique per discovery session)
pub type DiscoveryId = u64;

/// Session salt (32 bytes random)
pub type SessionSalt = [u8; 32];

/// Blinded fingerprint creator
/// Creates privacy-preserving fingerprints using HKDF + HMAC
#[derive(Debug)]
pub struct BlindedFingerprintCreator {
    /// Discovery ID
    discovery_id: DiscoveryId,

    /// Session salt
    session_salt: SessionSalt,
}

impl BlindedFingerprintCreator {
    /// Create new blinded fingerprint creator
    pub fn new(discovery_id: DiscoveryId, session_salt: SessionSalt) -> Self {
        Self {
            discovery_id,
            session_salt,
        }
    }

    /// Create blinded fingerprint from PSK
    /// Formula: HMAC-SHA256(HKDF-SHA256(psk, "psk_discovery"), session_salt)
    pub fn create_blinded_fingerprint(&self, psk: &[u8]) -> Result<BlindedFingerprint, EngineError> {
        // Step 1: Derive discovery key from PSK using HKDF
        let salt = hmac::Key::new(hmac::HMAC_SHA256, b"buckwild_psk_discovery_salt");
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref())
            .extract(psk);

        let info = b"psk_discovery";
        let okm = prk.expand(&[info], &hmac::HMAC_SHA256)
            .map_err(|_| EngineError::CryptoError("Hkdf expand failed".to_string()))?;

        let mut discovery_key = [0u8; 32];
        okm.fill(&mut discovery_key)
            .map_err(|_| EngineError::CryptoError("Hkdf fill failed".to_string()))?;

        // Step 2: HMAC the session salt with the discovery key
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &discovery_key);
        let signature = hmac::sign(&hmac_key, &self.session_salt);

        let mut blinded_fp = [0u8; 32];
        blinded_fp.copy_from_slice(signature.as_ref());

        debug!("Created blinded fingerprint for PSK");
        Ok(blinded_fp)
    }

    /// Create blinded fingerprints for multiple PSKs
    pub fn create_blinded_fingerprint_set(&self, psks: &[Vec<u8>]) -> Result<Vec<BlindedFingerprint>, EngineError> {
        let mut blinded_fps = Vec::with_capacity(psks.len());
        for psk in psks {
            blinded_fps.push(self.create_blinded_fingerprint(psk)?);
        }
        Ok(blinded_fps)
    }
}

/// Bloom filter for efficient set membership testing
#[derive(Debug, Clone)]
pub struct BloomFilter {
    /// Bit array
    bits: Vec<u8>,

    /// Filter size in bits
    size_bits: usize,

    /// Number of hash functions
    num_hash_functions: usize,
}

impl BloomFilter {
    /// Create new Bloom filter
    pub fn new(size_bits: usize, num_hash_functions: usize) -> Self {
        let num_bytes = (size_bits + 7) / 8;
        Self {
            bits: vec![0u8; num_bytes],
            size_bits,
            num_hash_functions,
        }
    }

    /// Calculate optimal parameters for given number of items
    /// Formula: m = -(n * ln(p)) / (ln(2)^2), k = (m/n) * ln(2)
    pub fn optimal_parameters(expected_items: usize, false_positive_rate: f64) -> (usize, usize) {
        let n = expected_items as f64;
        let p = false_positive_rate;

        // Optimal filter size
        let m = (-(n * p.ln()) / (2.0_f64.ln().powi(2))).ceil() as usize;

        // Optimal number of hash functions
        let k = ((m as f64 / n) * 2.0_f64.ln()).ceil() as usize;

        // Ensure reasonable bounds
        let size_bits = m.max(1024).min(65536); // 1KB to 8KB
        let num_hashes = k.max(1).min(8);       // 1 to 8 hash functions

        (size_bits, num_hashes)
    }

    /// Create optimal Bloom filter for given items
    pub fn create_optimal(expected_items: usize, false_positive_rate: f64) -> Self {
        let (size_bits, num_hash_functions) = Self::optimal_parameters(expected_items, false_positive_rate);
        Self::new(size_bits, num_hash_functions)
    }

    /// Hash function for Bloom filter
    /// Creates multiple hash values from single fingerprint
    fn hash_value(&self, fingerprint: &[u8], hash_index: usize) -> usize {
        // Create hash input: fingerprint || hash_index || "bloom_hash_v1"
        let mut input = Vec::with_capacity(fingerprint.len() + 1 + 13);
        input.extend_from_slice(fingerprint);
        input.push(hash_index as u8);
        input.extend_from_slice(b"bloom_hash_v1");

        // SHA-256 hash
        let hash = digest::digest(&digest::SHA256, &input);
        let hash_bytes = hash.as_ref();

        // Convert first 4 bytes to u32
        let hash_u32 = u32::from_be_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
        ]);

        (hash_u32 as usize) % self.size_bits
    }

    /// Add item to Bloom filter
    pub fn add(&mut self, fingerprint: &BlindedFingerprint) {
        for i in 0..self.num_hash_functions {
            let bit_pos = self.hash_value(fingerprint, i);
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            self.bits[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Test if item might be in set
    /// Returns true if possibly in set, false if definitely not in set
    pub fn test(&self, fingerprint: &BlindedFingerprint) -> bool {
        for i in 0..self.num_hash_functions {
            let bit_pos = self.hash_value(fingerprint, i);
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;

            if (self.bits[byte_idx] & (1 << bit_idx)) == 0 {
                return false; // Definitely not in set
            }
        }

        true // Possibly in set (could be false positive)
    }

    /// Get raw bit array
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Get size in bits
    pub fn size_bits(&self) -> usize {
        self.size_bits
    }

    /// Get number of hash functions
    pub fn num_hash_functions(&self) -> usize {
        self.num_hash_functions
    }

    /// Calculate false positive rate
    pub fn false_positive_rate(&self, num_items: usize) -> f64 {
        let k = self.num_hash_functions as f64;
        let m = self.size_bits as f64;
        let n = num_items as f64;

        // Formula: (1 - e^(-k*n/m))^k
        (1.0 - (-k * n / m).exp()).powf(k)
    }
}

/// PSK discovery protocol manager
#[derive(Debug)]
pub struct PskDiscoveryProtocol {
    /// Local PSKs
    local_psks: Vec<Vec<u8>>,

    /// Discovery ID
    discovery_id: DiscoveryId,

    /// Session salt
    session_salt: SessionSalt,

    /// Blinded fingerprint creator
    fingerprint_creator: BlindedFingerprintCreator,

    /// Local blinded fingerprints
    local_blinded_fps: Vec<BlindedFingerprint>,

    /// Discovery phase
    phase: DiscoveryPhase,

    /// Discovered PSK (after successful discovery)
    discovered_psk: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryPhase {
    /// Initial state
    Initial,

    /// Sent discovery request
    RequestSent,

    /// Received discovery response
    ResponseReceived,

    /// Verified candidates
    CandidatesVerified,

    /// Discovery complete
    Complete,

    /// Discovery failed
    Failed,
}

impl PskDiscoveryProtocol {
    /// Create new PSK discovery protocol
    pub fn new(local_psks: Vec<Vec<u8>>) -> Result<Self, EngineError> {
        if local_psks.is_empty() {
            return Err(EngineError::InvalidConfiguration("Must have at least one PSK".to_string()));
        }

        // Generate discovery ID (random)
        let discovery_id = {
            let mut bytes = [0u8; 8];
            ring::rand::SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| EngineError::CryptoError("Failed to generate discovery ID".to_string()))?;
            u64::from_be_bytes(bytes)
        };

        // Generate session salt (32 bytes random)
        let mut session_salt = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut session_salt)
            .map_err(|_| EngineError::CryptoError("Failed to generate session salt".to_string()))?;

        let fingerprint_creator = BlindedFingerprintCreator::new(discovery_id, session_salt);
        let local_blinded_fps = fingerprint_creator.create_blinded_fingerprint_set(&local_psks)?;

        info!(
            "Created PSK discovery protocol: id={}, local_psks={}, salt_len={}",
            discovery_id,
            local_psks.len(),
            session_salt.len()
        );

        Ok(Self {
            local_psks,
            discovery_id,
            session_salt,
            fingerprint_creator,
            local_blinded_fps,
            phase: DiscoveryPhase::Initial,
            discovered_psk: None,
        })
    }

    /// Get discovery ID
    pub fn discovery_id(&self) -> DiscoveryId {
        self.discovery_id
    }

    /// Get session salt
    pub fn session_salt(&self) -> &SessionSalt {
        &self.session_salt
    }

    /// Phase 1: Create discovery request with Bloom filter
    pub fn create_discovery_request(&mut self) -> Result<BloomFilter, EngineError> {
        if self.phase != DiscoveryPhase::Initial {
            return Err(EngineError::InvalidState(
                format!("Cannot create request from phase {:?}", self.phase)
            ));
        }

        // Create optimal Bloom filter (3% false positive rate)
        let mut bloom = BloomFilter::create_optimal(self.local_psks.len(), 0.03);

        // Add all local blinded fingerprints
        for blinded_fp in &self.local_blinded_fps {
            bloom.add(blinded_fp);
        }

        self.phase = DiscoveryPhase::RequestSent;

        info!(
            "Created discovery request: items={}, filter_size={} bits, hashes={}, fp_rate={:.3}%",
            self.local_psks.len(),
            bloom.size_bits(),
            bloom.num_hash_functions(),
            bloom.false_positive_rate(self.local_psks.len()) * 100.0
        );

        Ok(bloom)
    }

    /// Phase 2: Process discovery request and create response (responder side)
    pub fn process_discovery_request(
        responder_psks: &[Vec<u8>],
        discovery_id: DiscoveryId,
        session_salt: SessionSalt,
        bloom_filter: &BloomFilter,
    ) -> Result<Vec<[u8; 32]>, EngineError> {
        let fingerprint_creator = BlindedFingerprintCreator::new(discovery_id, session_salt);
        let responder_blinded_fps = fingerprint_creator.create_blinded_fingerprint_set(responder_psks)?;

        // Test each responder fingerprint against Bloom filter
        let mut candidate_hashes = Vec::new();

        for blinded_fp in &responder_blinded_fps {
            if bloom_filter.test(blinded_fp) {
                // Possible match - create candidate hash
                let candidate_hash = Self::create_candidate_hash(blinded_fp);
                candidate_hashes.push(candidate_hash);
            }
        }

        info!(
            "Processed discovery request: responder_psks={}, candidates={}",
            responder_psks.len(),
            candidate_hashes.len()
        );

        Ok(candidate_hashes)
    }

    /// Create candidate hash from blinded fingerprint
    /// Formula: SHA-256(blinded_fp || "candidate_v1")
    fn create_candidate_hash(blinded_fp: &BlindedFingerprint) -> [u8; 32] {
        let mut input = Vec::with_capacity(32 + 12);
        input.extend_from_slice(blinded_fp);
        input.extend_from_slice(b"candidate_v1");

        let hash = digest::digest(&digest::SHA256, &input);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());
        result
    }

    /// Phase 3: Verify candidates and find intersections
    pub fn verify_candidates(&mut self, candidate_hashes: Vec<[u8; 32]>) -> Result<Vec<usize>, EngineError> {
        if self.phase != DiscoveryPhase::RequestSent {
            return Err(EngineError::InvalidState(
                format!("Cannot verify candidates from phase {:?}", self.phase)
            ));
        }

        let candidate_set: HashSet<[u8; 32]> = candidate_hashes.into_iter().collect();
        let mut verified_indices = Vec::new();

        // Check each local blinded fingerprint
        for (i, blinded_fp) in self.local_blinded_fps.iter().enumerate() {
            let expected_candidate = Self::create_candidate_hash(blinded_fp);

            if candidate_set.contains(&expected_candidate) {
                // Real intersection found
                verified_indices.push(i);
                debug!("Verified intersection at index {}", i);
            }
        }

        self.phase = DiscoveryPhase::CandidatesVerified;

        info!(
            "Verified candidates: total={}, intersections={}",
            candidate_set.len(),
            verified_indices.len()
        );

        Ok(verified_indices)
    }

    /// Phase 4: Select optimal PSK from intersections
    pub fn select_optimal_psk(&mut self, intersection_indices: &[usize]) -> Result<Vec<u8>, EngineError> {
        if self.phase != DiscoveryPhase::CandidatesVerified {
            return Err(EngineError::InvalidState(
                format!("Cannot select PSK from phase {:?}", self.phase)
            ));
        }

        if intersection_indices.is_empty() {
            self.phase = DiscoveryPhase::Failed;
            return Err(EngineError::NotFound("No PSK intersection found".to_string()));
        }

        // Select first intersection (could use more sophisticated selection)
        let selected_index = intersection_indices[0];
        let selected_psk = self.local_psks[selected_index].clone();

        self.discovered_psk = Some(selected_psk.clone());
        self.phase = DiscoveryPhase::Complete;

        info!("Selected optimal PSK at index {}", selected_index);

        Ok(selected_psk)
    }

    /// Create PSK confirmation hash
    /// Formula: SHA-256(psk_fingerprint || discovery_id || session_salt || "psk_confirmation_v1")
    pub fn create_confirmation_hash(&self, psk: &[u8]) -> Result<[u8; 32], EngineError> {
        let mut input = Vec::with_capacity(32 + 8 + 32 + 20);

        // PSK fingerprint (SHA-256 of PSK)
        let psk_fp = digest::digest(&digest::SHA256, psk);
        input.extend_from_slice(psk_fp.as_ref());

        // Discovery ID
        input.extend_from_slice(&self.discovery_id.to_be_bytes());

        // Session salt
        input.extend_from_slice(&self.session_salt);

        // Context
        input.extend_from_slice(b"psk_confirmation_v1");

        let hash = digest::digest(&digest::SHA256, &input);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());

        debug!("Created PSK confirmation hash");
        Ok(result)
    }

    /// Verify PSK confirmation hash
    pub fn verify_confirmation_hash(&self, confirmation_hash: &[u8; 32]) -> Result<Vec<u8>, EngineError> {
        for psk in &self.local_psks {
            let expected_hash = self.create_confirmation_hash(psk)?;

            // Constant-time comparison
            let mut diff = 0u8;
            for i in 0..32 {
                diff |= expected_hash[i] ^ confirmation_hash[i];
            }

            if diff == 0 {
                info!("PSK confirmation verified successfully");
                return Ok(psk.clone());
            }
        }

        Err(EngineError::AuthenticationFailed("Confirmation hash does not match any PSK".to_string()))
    }

    /// Get discovered PSK
    pub fn discovered_psk(&self) -> Option<&[u8]> {
        self.discovered_psk.as_deref()
    }

    /// Get current phase
    pub fn phase(&self) -> DiscoveryPhase {
        self.phase
    }

    /// Check if discovery complete
    pub fn is_complete(&self) -> bool {
        self.phase == DiscoveryPhase::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blinded_fingerprint_creation() {
        let psk = b"test_psk_12345678901234567890".to_vec();
        let discovery_id = 12345;
        let session_salt = [42u8; 32];

        let creator = BlindedFingerprintCreator::new(discovery_id, session_salt);
        let blinded_fp1 = creator.create_blinded_fingerprint(&psk).unwrap();
        let blinded_fp2 = creator.create_blinded_fingerprint(&psk).unwrap();

        // Same PSK with same parameters should produce same fingerprint
        assert_eq!(blinded_fp1, blinded_fp2);

        // Different salt should produce different fingerprint
        let creator2 = BlindedFingerprintCreator::new(discovery_id, [99u8; 32]);
        let blinded_fp3 = creator2.create_blinded_fingerprint(&psk).unwrap();
        assert_ne!(blinded_fp1, blinded_fp3);
    }

    #[test]
    fn test_bloom_filter_operations() {
        let mut bloom = BloomFilter::new(1024, 3);

        let fp1 = [1u8; 32];
        let fp2 = [2u8; 32];
        let fp3 = [3u8; 32];

        // Add fp1 and fp2
        bloom.add(&fp1);
        bloom.add(&fp2);

        // Should test positive for added items
        assert!(bloom.test(&fp1));
        assert!(bloom.test(&fp2));

        // fp3 was not added, so should (likely) test negative
        // Note: false positives are possible but unlikely with these parameters
    }

    #[test]
    fn test_bloom_filter_optimal_parameters() {
        let (size_bits, num_hashes) = BloomFilter::optimal_parameters(100, 0.01);

        // Should be reasonable values
        assert!(size_bits >= 1024);
        assert!(size_bits <= 65536);
        assert!(num_hashes >= 1);
        assert!(num_hashes <= 8);
    }

    #[test]
    fn test_psk_discovery_protocol() {
        // Client has PSKs 1, 2, 3
        let client_psks = vec![
            b"psk1_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
            b"psk2_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
            b"psk3_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
        ];

        // Server has PSKs 2, 3, 4 (intersection: 2, 3)
        let server_psks = vec![
            b"psk2_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
            b"psk3_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
            b"psk4_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
        ];

        // Client initiates discovery
        let mut client_discovery = PskDiscoveryProtocol::new(client_psks).unwrap();
        let bloom_filter = client_discovery.create_discovery_request().unwrap();

        // Server processes request
        let candidate_hashes = PskDiscoveryProtocol::process_discovery_request(
            &server_psks,
            client_discovery.discovery_id(),
            *client_discovery.session_salt(),
            &bloom_filter,
        ).unwrap();

        // Should have found some candidates (at least PSK2 and PSK3)
        assert!(!candidate_hashes.is_empty());

        // Client verifies candidates
        let intersections = client_discovery.verify_candidates(candidate_hashes).unwrap();

        // Should have found intersections
        assert!(!intersections.is_empty());

        // Client selects PSK
        let selected_psk = client_discovery.select_optimal_psk(&intersections).unwrap();

        // Selected PSK should be one of the intersecting ones (psk2 or psk3)
        assert!(selected_psk == b"psk2_32_bytes_long!!!!!!!!!!!!!!" ||
                selected_psk == b"psk3_32_bytes_long!!!!!!!!!!!!!!");
    }

    #[test]
    fn test_psk_confirmation() {
        let psks = vec![
            b"psk1_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
            b"psk2_32_bytes_long!!!!!!!!!!!!!!".to_vec(),
        ];

        let discovery = PskDiscoveryProtocol::new(psks.clone()).unwrap();

        // Create confirmation for PSK1
        let confirmation = discovery.create_confirmation_hash(&psks[0]).unwrap();

        // Verify confirmation
        let verified_psk = discovery.verify_confirmation_hash(&confirmation).unwrap();
        assert_eq!(verified_psk, psks[0]);

        // Wrong confirmation should fail
        let wrong_confirmation = [99u8; 32];
        assert!(discovery.verify_confirmation_hash(&wrong_confirmation).is_err());
    }
}
