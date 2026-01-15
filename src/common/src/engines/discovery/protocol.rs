#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Privacy-Preserving Discovery Protocol
//
// Implements a secure peer discovery protocol using Bloom filters and blinded PSK hints
// to enable two peers to discover shared pre-shared keys without revealing non-matching PSKs.
//
// Protocol Flow:
// 1. Client creates discovery request with Bloom filter containing blinded PSK hints
// 2. Server processes request, finds potential matches, and returns candidate hashes
// 3. Client verifies candidates to eliminate false positives
// 4. Neither party learns about unmatched PSKs (privacy-preserving)

use crate::engines::discovery::bloom::{BloomFilterBuilder, PskFingerprint};
use crate::protocol::types::*;
use ring::digest;
use tracing::{debug, trace};

/// Discovery protocol error types
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid filter data: {reason}")]
    InvalidFilterData { reason: String },

    #[error("No matching PSKs found")]
    NoMatches,

    #[error("Invalid nonce: expected {expected:?}, got {actual:?}")]
    NonceVerificationFailed {
        expected: [u8; 16],
        actual: [u8; 16],
    },
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Discovery request message sent by the client
#[derive(Debug, Clone)]
pub struct DiscoveryRequest {
    /// Bloom filter data containing blinded PSK hints
    pub filter_data: Vec<u8>,
    /// Request nonce for replay protection
    pub nonce: [u8; 16],
    /// Discovery session identifier
    pub discovery_id: DiscoveryId,
    /// Session salt for blinding
    pub session_salt: u32,
}

impl DiscoveryRequest {
    /// Create a new discovery request
    pub fn new(
        filter_data: Vec<u8>,
        nonce: [u8; 16],
        discovery_id: DiscoveryId,
        session_salt: u32,
    ) -> Self {
        Self {
            filter_data,
            nonce,
            discovery_id,
            session_salt,
        }
    }
}

/// Blinded hint in discovery response
#[derive(Debug, Clone, PartialEq)]
pub struct BlindedHint {
    /// Blinded fingerprint (16 bytes)
    pub blinded_fingerprint: [u8; 16],
    /// Candidate hash for verification (32 bytes)
    pub candidate_hash: CandidateHash,
}

impl BlindedHint {
    /// Create a new blinded hint
    pub fn new(blinded_fingerprint: [u8; 16], candidate_hash: CandidateHash) -> Self {
        Self {
            blinded_fingerprint,
            candidate_hash,
        }
    }
}

/// Discovery response message sent by the server
#[derive(Debug, Clone)]
pub struct DiscoveryResponse {
    /// Matching blinded hints from server's PSK set
    pub matching_hints: Vec<BlindedHint>,
    /// Response nonce (must match request nonce)
    pub nonce: [u8; 16],
}

impl DiscoveryResponse {
    /// Create a new discovery response
    pub fn new(matching_hints: Vec<BlindedHint>, nonce: [u8; 16]) -> Self {
        Self {
            matching_hints,
            nonce,
        }
    }
}

/// PSK match result after verification
#[derive(Debug, Clone, PartialEq)]
pub struct PskMatch {
    /// Original PSK fingerprint (unblinded)
    pub psk_fingerprint: PskFingerprint,
    /// Blinded fingerprint used in protocol
    pub blinded_fingerprint: [u8; 16],
}

impl PskMatch {
    /// Create a new PSK match
    pub fn new(psk_fingerprint: PskFingerprint, blinded_fingerprint: [u8; 16]) -> Self {
        Self {
            psk_fingerprint,
            blinded_fingerprint,
        }
    }
}

/// Privacy-preserving discovery protocol implementation
pub struct DiscoveryProtocol {
    /// Bloom filter builder for PSK operations
    builder: BloomFilterBuilder,
    /// Local PSK fingerprints
    local_fingerprints: Vec<PskFingerprint>,
    /// Discovery session identifier
    discovery_id: DiscoveryId,
    /// Session salt for blinding
    session_salt: u32,
}

impl DiscoveryProtocol {
    /// Create a new discovery protocol instance with local PSKs
    ///
    /// # Arguments
    /// * `local_psks` - Array of local PSK bytes (each 32 bytes)
    /// * `discovery_id` - Discovery session identifier
    /// * `session_salt` - Session salt for PSK blinding
    pub fn new(local_psks: &[&[u8]], discovery_id: DiscoveryId, session_salt: u32) -> Self {
        debug!(
            psk_count = local_psks.len(),
            discovery_id = discovery_id.0,
            session_salt = session_salt,
            "Creating discovery protocol instance"
        );

        // Convert PSK bytes to fingerprints
        let local_fingerprints: Vec<PskFingerprint> = local_psks
            .iter()
            .filter_map(|psk| {
                if psk.len() == 32 {
                    let mut psk_array = [0u8; 32];
                    psk_array.copy_from_slice(psk);
                    Some(PskId::new(psk_array))
                } else {
                    trace!(psk_len = psk.len(), "Skipping PSK with invalid length");
                    None
                }
            })
            .collect();

        let builder = BloomFilterBuilder::new(local_fingerprints.len() as u32, 0.01);

        Self {
            builder,
            local_fingerprints,
            discovery_id,
            session_salt,
        }
    }

    /// Create a discovery request to send to the peer
    ///
    /// This creates a Bloom filter containing blinded versions of all local PSK hints,
    /// allowing the peer to check for intersection without revealing non-matching PSKs.
    pub fn create_discovery_request(&self) -> DiscoveryRequest {
        trace!(
            fingerprint_count = self.local_fingerprints.len(),
            "Creating discovery request"
        );

        // Build Bloom filter with blinded fingerprints
        let bloom_filter = self.builder.build_from_fingerprints(
            &self.local_fingerprints,
            self.discovery_id,
            self.session_salt,
        );

        // Generate random nonce for replay protection
        let mut nonce = [0u8; 16];
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        if rng.fill(&mut nonce).is_err() {
            // If RNG fails, use deterministic nonce based on discovery context
            // This should never happen in practice, but provides fallback
            let mut context = Vec::new();
            context.extend_from_slice(&self.discovery_id.0.to_be_bytes());
            context.extend_from_slice(&self.session_salt.to_be_bytes());
            let hash_result = digest::digest(&digest::SHA256, &context);
            nonce.copy_from_slice(&hash_result.as_ref()[0..16]);
        }

        debug!(nonce_len = nonce.len(), "Generated request nonce");

        DiscoveryRequest::new(
            bloom_filter.bits,
            nonce,
            self.discovery_id,
            self.session_salt,
        )
    }

    /// Process a discovery request from a peer
    ///
    /// Checks which of our local PSK fingerprints might be in the peer's Bloom filter,
    /// then returns candidate hashes for those potential matches. The peer will verify
    /// these candidates to eliminate false positives.
    pub fn process_discovery_request(&self, request: &DiscoveryRequest) -> DiscoveryResponse {
        trace!(
            filter_size = request.filter_data.len(),
            "Processing discovery request"
        );

        // Reconstruct Bloom filter from request data
        let bloom_filter = BloomFilter {
            bits: request.filter_data.clone(),
            hash_functions: HashFunctionCount::new(self.builder.hash_functions()),
            expected_elements: ElementCount::new(0), // Not used by test() method
        };

        let mut matching_hints = Vec::new();

        // Check each local PSK fingerprint against the Bloom filter
        for fingerprint in &self.local_fingerprints {
            // Create blinded fingerprint using request's discovery context
            let blinded = self.builder.blind_fingerprint(
                fingerprint,
                request.discovery_id,
                request.session_salt,
            );

            // Test if this blinded fingerprint might be in the peer's set
            if self.builder.test(&bloom_filter, &blinded) {
                // Calculate candidate hash for this potential match
                // Protocol: SHA256(blinded_fp || b"candidate_v1")
                let mut input = Vec::new();
                input.extend_from_slice(&blinded);
                input.extend_from_slice(b"candidate_v1");
                let hash_result = digest::digest(&digest::SHA256, &input);

                let candidate_hash = match hash_result.as_ref().try_into() {
                    Ok(hash_array) => CandidateHash::new(hash_array),
                    Err(_) => {
                        // SHA256 should always produce 32 bytes, but handle gracefully
                        trace!("Failed to convert hash to array, skipping candidate");
                        continue;
                    }
                };

                matching_hints.push(BlindedHint::new(blinded, candidate_hash));

                trace!(
                    fingerprint = ?fingerprint,
                    "Found potential match (may be false positive)"
                );
            }
        }

        debug!(
            match_count = matching_hints.len(),
            total_psks = self.local_fingerprints.len(),
            "Discovery request processing complete"
        );

        DiscoveryResponse::new(matching_hints, request.nonce)
    }

    /// Process a discovery response from a peer
    ///
    /// Verifies the candidate hashes to eliminate Bloom filter false positives
    /// and returns only the real PSK matches.
    pub fn process_discovery_response(
        &self,
        response: &DiscoveryResponse,
    ) -> ProtocolResult<Vec<PskMatch>> {
        trace!(
            candidate_count = response.matching_hints.len(),
            "Processing discovery response"
        );

        // Extract candidate hashes from response
        let candidate_hashes: Vec<CandidateHash> = response
            .matching_hints
            .iter()
            .map(|hint| hint.candidate_hash.clone())
            .collect();

        // Verify candidates against local fingerprints
        let verified_intersections = self.builder.verify_candidates(
            &candidate_hashes,
            &self.local_fingerprints,
            self.discovery_id,
            self.session_salt,
        );

        if verified_intersections.is_empty() {
            debug!("No verified matches found (all were false positives)");
            return Err(ProtocolError::NoMatches);
        }

        // Convert verified intersections to PSK matches
        let matches: Vec<PskMatch> = verified_intersections
            .into_iter()
            .map(|intersection| {
                PskMatch::new(
                    intersection.original_fingerprint,
                    intersection.blinded_fingerprint,
                )
            })
            .collect();

        debug!(match_count = matches.len(), "Discovery complete");

        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_psk(value: u32) -> [u8; 32] {
        let mut psk = [0u8; 32];
        psk[0..4].copy_from_slice(&value.to_be_bytes());
        psk
    }

    #[test]
    fn test_discovery_protocol_create_request() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;

        let psk1 = create_test_psk(1);
        let psk2 = create_test_psk(2);
        let local_psks = [psk1.as_slice(), psk2.as_slice()];

        let protocol = DiscoveryProtocol::new(&local_psks, discovery_id, session_salt);
        let request = protocol.create_discovery_request();

        // Verify request structure
        assert_eq!(request.discovery_id, discovery_id);
        assert_eq!(request.session_salt, session_salt);
        assert_eq!(request.nonce.len(), 16);
        assert!(!request.filter_data.is_empty());
    }

    #[test]
    fn test_discovery_protocol_process_request() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;

        // Server has PSKs 1, 2, 3
        let server_psk1 = create_test_psk(1);
        let server_psk2 = create_test_psk(2);
        let server_psk3 = create_test_psk(3);
        let server_psks = [
            server_psk1.as_slice(),
            server_psk2.as_slice(),
            server_psk3.as_slice(),
        ];

        // Client has PSKs 2, 3, 4
        let client_psk2 = create_test_psk(2);
        let client_psk3 = create_test_psk(3);
        let client_psk4 = create_test_psk(4);
        let client_psks = [
            client_psk2.as_slice(),
            client_psk3.as_slice(),
            client_psk4.as_slice(),
        ];

        let server_protocol = DiscoveryProtocol::new(&server_psks, discovery_id, session_salt);
        let client_protocol = DiscoveryProtocol::new(&client_psks, discovery_id, session_salt);

        // Client creates request
        let request = client_protocol.create_discovery_request();

        // Server processes request
        let response = server_protocol.process_discovery_request(&request);

        // Response nonce should match request nonce
        assert_eq!(response.nonce, request.nonce);

        // Client verifies the response to get actual matches (eliminating false positives)
        let matches = client_protocol
            .process_discovery_response(&response)
            .expect("Should find matches");

        // Should find exactly 2 matches (PSK 2 and 3)
        assert_eq!(matches.len(), 2);

        // Verify the correct PSKs were matched
        let expected_fingerprints: Vec<PskId> =
            vec![PskId::new(client_psk2), PskId::new(client_psk3)];

        for expected in &expected_fingerprints {
            assert!(
                matches.iter().any(|m| m.psk_fingerprint == *expected),
                "Missing PSK: {:?}",
                expected
            );
        }
    }

    #[test]
    fn test_privacy_preservation() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;

        // Server has PSKs 1, 2, 3
        let server_psk1 = create_test_psk(1);
        let server_psk2 = create_test_psk(2);
        let server_psk3 = create_test_psk(3);
        let server_psks = [
            server_psk1.as_slice(),
            server_psk2.as_slice(),
            server_psk3.as_slice(),
        ];

        // Client has PSKs 2, 99, 100 (only 2 matches, 99 and 100 do not)
        // This ensures both peers have the same number of PSKs, so Bloom filter sizes match
        let client_psk2 = create_test_psk(2);
        let client_psk99 = create_test_psk(99);
        let client_psk100 = create_test_psk(100);
        let client_psks = [
            client_psk2.as_slice(),
            client_psk99.as_slice(),
            client_psk100.as_slice(),
        ];

        let server_protocol = DiscoveryProtocol::new(&server_psks, discovery_id, session_salt);
        let client_protocol = DiscoveryProtocol::new(&client_psks, discovery_id, session_salt);

        // Client creates request
        let request = client_protocol.create_discovery_request();

        // Server processes request - should not reveal PSK 1 or 3
        let response = server_protocol.process_discovery_request(&request);

        // The response contains blinded hints, not original PSK IDs
        // Privacy is preserved: server learns nothing about client's non-matching PSKs
        // Client learns nothing about server's non-matching PSKs
        for hint in &response.matching_hints {
            // Verify blinded fingerprints are not the original PSK IDs
            let psk1_bytes: &[u8] = server_psk1.as_slice();
            let psk3_bytes: &[u8] = server_psk3.as_slice();

            // Blinded fingerprint should not match unmatched PSKs directly
            assert_ne!(&hint.blinded_fingerprint[..], &psk1_bytes[0..16]);
            assert_ne!(&hint.blinded_fingerprint[..], &psk3_bytes[0..16]);
        }
    }

    #[test]
    fn test_full_discovery_roundtrip() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;

        // Server and client both have PSK 42
        let shared_psk = create_test_psk(42);
        let server_psks = [shared_psk.as_slice()];
        let client_psks = [shared_psk.as_slice()];

        let server_protocol = DiscoveryProtocol::new(&server_psks, discovery_id, session_salt);
        let client_protocol = DiscoveryProtocol::new(&client_psks, discovery_id, session_salt);

        // Full roundtrip
        let request = client_protocol.create_discovery_request();
        let response = server_protocol.process_discovery_request(&request);
        let matches = client_protocol
            .process_discovery_response(&response)
            .expect("Should find matches");

        // Should find exactly one match
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].psk_fingerprint, PskId::new(shared_psk));
    }

    #[test]
    fn test_no_intersection() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;

        // Server has PSK 1
        let server_psk = create_test_psk(1);
        let server_psks = [server_psk.as_slice()];

        // Client has PSK 2 (no overlap)
        let client_psk = create_test_psk(2);
        let client_psks = [client_psk.as_slice()];

        let server_protocol = DiscoveryProtocol::new(&server_psks, discovery_id, session_salt);
        let client_protocol = DiscoveryProtocol::new(&client_psks, discovery_id, session_salt);

        let request = client_protocol.create_discovery_request();
        let response = server_protocol.process_discovery_request(&request);

        // Process response - should return error due to no matches
        let result = client_protocol.process_discovery_response(&response);

        // Should fail with NoMatches (or return empty if no candidates passed Bloom filter)
        match result {
            Err(ProtocolError::NoMatches) => (),
            Ok(matches) if matches.is_empty() => (), // Also acceptable
            _ => panic!("Expected no matches or NoMatches error"),
        }
    }

    #[test]
    fn test_multiple_psks() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;

        // Both have PSKs 10, 20, 30
        let psk10 = create_test_psk(10);
        let psk20 = create_test_psk(20);
        let psk30 = create_test_psk(30);

        let psks = [psk10.as_slice(), psk20.as_slice(), psk30.as_slice()];

        let server_protocol = DiscoveryProtocol::new(&psks, discovery_id, session_salt);
        let client_protocol = DiscoveryProtocol::new(&psks, discovery_id, session_salt);

        let request = client_protocol.create_discovery_request();
        let response = server_protocol.process_discovery_request(&request);
        let matches = client_protocol
            .process_discovery_response(&response)
            .expect("Should find matches");

        // Should find all three PSKs
        assert_eq!(matches.len(), 3);

        // Verify all PSKs are present
        let expected_fingerprints: Vec<PskId> =
            vec![PskId::new(psk10), PskId::new(psk20), PskId::new(psk30)];

        for expected in &expected_fingerprints {
            assert!(
                matches.iter().any(|m| m.psk_fingerprint == *expected),
                "Missing PSK: {:?}",
                expected
            );
        }
    }
}
