#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Bloom Filter implementation for privacy-preserving PSK discovery

use crate::protocol::types::*;

// Type alias for PSK fingerprints (using PskId as fingerprint)
pub type PskFingerprint = PskId;

/// Result of candidate verification - represents a verified PSK intersection
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateIntersection {
    /// Original PSK fingerprint (unblinded)
    pub original_fingerprint: PskFingerprint,
    /// Blinded fingerprint used in Bloom filter
    pub blinded_fingerprint: [u8; 16],
    /// Candidate hash received from peer
    pub candidate_hash: CandidateHash,
}

/// Bloom filter builder for PSK discovery
pub struct BloomFilterBuilder {
    size_bits: usize,
    hash_functions: u8,
    expected_elements: u32,
}

impl BloomFilterBuilder {
    /// Create a new Bloom filter builder with optimal parameters
    pub fn new(expected_elements: u32, false_positive_rate: f64) -> Self {
        // Calculate optimal size and hash function count
        let size_bits = Self::optimal_size(expected_elements, false_positive_rate);
        let hash_functions = Self::optimal_hash_count(expected_elements, size_bits);

        Self {
            size_bits,
            hash_functions,
            expected_elements,
        }
    }

    /// Get the filter size in bits (for testing)
    pub fn size_bits(&self) -> usize {
        self.size_bits
    }

    /// Get the number of hash functions (for testing)
    pub fn hash_functions(&self) -> u8 {
        self.hash_functions
    }

    /// Build a Bloom filter from PSK fingerprints with blinding
    pub fn build_from_fingerprints(
        &self,
        fingerprints: &[PskFingerprint],
        discovery_id: DiscoveryId,
        session_salt: u32,
    ) -> BloomFilter {
        let mut bloom = BloomFilter {
            bits: vec![0u8; self.size_bits.div_ceil(8)],
            hash_functions: HashFunctionCount::new(self.hash_functions),
            expected_elements: ElementCount::new(self.expected_elements),
        };

        // Create blinded fingerprints and add to Bloom filter
        for fingerprint in fingerprints {
            let blinded = self.blind_fingerprint(fingerprint, discovery_id, session_salt);
            self.insert(&mut bloom, &blinded);
        }

        bloom
    }

    /// Blind a PSK fingerprint using discovery context
    ///
    /// Protocol specification: HMAC_SHA256_128(key=fingerprint, data=discovery_context || b"psi_blinding_v1")
    /// This provides privacy-preserving blinding with unlinkability across discovery sessions.
    pub(crate) fn blind_fingerprint(
        &self,
        fingerprint: &PskFingerprint,
        discovery_id: DiscoveryId,
        session_salt: u32,
    ) -> [u8; 16] {
        use crate::security::crypto::hmac::HmacCalculator;

        // Create discovery context as per protocol spec
        // discovery_context = discovery_id (8 bytes) || session_salt (4 bytes) || b"psi_blinding_v1"
        let mut context = Vec::new();
        context.extend_from_slice(&discovery_id.to_be_bytes()); // 8 bytes
        context.extend_from_slice(&session_salt.to_be_bytes()); // 4 bytes
        context.extend_from_slice(b"psi_blinding_v1"); // context string

        // Use HMAC-SHA256 with 128-bit (16-byte) output
        // Key = PSK fingerprint, Data = discovery context
        let hmac_calc = HmacCalculator::new();
        let hmac_result = match hmac_calc.calculate_packet_hmac(
            &context,
            fingerprint.as_bytes(),
            HmacPolicy::Medium, // Medium = 16 bytes (128 bits) per protocol
        ) {
            Ok(result) => result,
            Err(_) => {
                // HMAC calculation failed - use deterministic fallback based on input
                // This should never happen in practice, but we handle it gracefully
                // Use zero bytes as fallback (will not produce valid matches)
                match HmacTag::new(vec![0u8; 16], HmacPolicy::Medium) {
                    Ok(tag) => tag,
                    Err(_) => {
                        // Fallback creation also failed - use minimal blinded value
                        // This path is extremely unlikely but ensures no panic
                        return [0u8; 16];
                    }
                }
            }
        };

        // Extract 16-byte blinded fingerprint
        let mut blinded = [0u8; 16];
        blinded.copy_from_slice(&hmac_result.as_bytes()[0..16]);
        blinded
    }

    /// Insert a blinded fingerprint into the Bloom filter
    fn insert(&self, bloom: &mut BloomFilter, blinded: &[u8; 16]) {
        for i in 0..self.hash_functions {
            let bit_index = self.hash(blinded, i) % self.size_bits;
            let byte_index = bit_index / 8;
            let bit_offset = bit_index % 8;
            bloom.bits[byte_index] |= 1 << bit_offset;
        }
    }

    /// Test if a blinded fingerprint might be in the Bloom filter
    pub fn test(&self, bloom: &BloomFilter, blinded: &[u8; 16]) -> bool {
        for i in 0..self.hash_functions {
            let bit_index = self.hash(blinded, i) % self.size_bits;
            let byte_index = bit_index / 8;
            let bit_offset = bit_index % 8;

            if bloom.bits[byte_index] & (1 << bit_offset) == 0 {
                return false; // Definitely not in set
            }
        }
        true // Might be in set (could be false positive)
    }

    /// Hash function for Bloom filter
    fn hash(&self, data: &[u8; 16], function_index: u8) -> usize {
        // Use BLAKE3 for high-quality hashing (better distribution than simple multiplicative)
        use ring::digest;

        // Combine data with function index to get independent hash functions
        let mut input = Vec::with_capacity(17);
        input.extend_from_slice(data);
        input.push(function_index);

        // Hash and extract 8 bytes as u64
        let hash_result = digest::digest(&digest::SHA256, &input);
        let hash_bytes = hash_result.as_ref();

        // Take first 8 bytes and convert to u64
        let hash_u64 = u64::from_be_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
            hash_bytes[4],
            hash_bytes[5],
            hash_bytes[6],
            hash_bytes[7],
        ]);

        (hash_u64 as usize) % self.size_bits
    }

    /// Calculate optimal Bloom filter size
    fn optimal_size(expected_elements: u32, false_positive_rate: f64) -> usize {
        let n = expected_elements as f64;
        let p = false_positive_rate;
        let size = -(n * p.ln()) / (2.0_f64.ln().powi(2));
        size.ceil() as usize
    }

    /// Calculate optimal number of hash functions
    fn optimal_hash_count(expected_elements: u32, size_bits: usize) -> u8 {
        let n = expected_elements as f64;
        let m = size_bits as f64;
        let k = (m / n) * 2.0_f64.ln();
        k.ceil().min(255.0) as u8
    }

    /// Verify PSK candidates against local fingerprints
    ///
    /// Protocol: For each local fingerprint, create blinded fingerprint and candidate hash,
    /// then check if it matches any received candidate hashes. This eliminates Bloom filter
    /// false positives and returns only real intersections.
    pub fn verify_candidates(
        &self,
        candidate_hashes: &[CandidateHash],
        local_fingerprints: &[PskFingerprint],
        discovery_id: DiscoveryId,
        session_salt: u32,
    ) -> Vec<CandidateIntersection> {
        use ring::digest;

        let mut verified = Vec::new();

        // Check each local fingerprint against candidate hashes
        for fingerprint in local_fingerprints {
            // Create blinded fingerprint
            let blinded = self.blind_fingerprint(fingerprint, discovery_id, session_salt);

            // Calculate expected candidate hash: SHA256(blinded_fp || b"candidate_v1")
            let mut input = Vec::new();
            input.extend_from_slice(&blinded);
            input.extend_from_slice(b"candidate_v1");
            let hash_result = digest::digest(&digest::SHA256, &input);
            let expected_hash: [u8; 32] = match hash_result.as_ref().try_into() {
                Ok(hash) => hash,
                Err(_) => {
                    // SHA256 should always produce 32 bytes, but handle gracefully
                    // Skip this candidate if conversion fails
                    continue;
                }
            };
            let expected_candidate = CandidateHash::new(expected_hash);

            // Check if this candidate is in the received list
            if candidate_hashes
                .iter()
                .any(|c| c.as_bytes() == expected_candidate.as_bytes())
            {
                // This is a real intersection
                verified.push(CandidateIntersection {
                    original_fingerprint: fingerprint.clone(),
                    blinded_fingerprint: blinded,
                    candidate_hash: expected_candidate,
                });
            }
        }

        verified
    }

    /// Select optimal PSK from verified intersections
    ///
    /// Protocol: When multiple PSKs match, select based on priority.
    /// For simplicity, we select the first one (deterministic).
    /// In a full implementation, this would consider PSK priority, recency, security level, etc.
    pub fn select_optimal_psk(intersections: &[CandidateIntersection]) -> Option<PskFingerprint> {
        if intersections.is_empty() {
            return None;
        }

        // For now, select first PSK (deterministic)
        // In a full implementation: sort by priority/recency and select best
        Some(intersections[0].original_fingerprint.clone())
    }

    /// Calculate confirmation hash for selected PSK
    ///
    /// Protocol: SHA256(psk_fingerprint || confirmation_context || b"psk_confirmation_v1")
    /// confirmation_context = discovery_id || session_salt
    pub fn calculate_confirmation_hash(
        &self,
        psk_fingerprint: &PskFingerprint,
        discovery_id: DiscoveryId,
        session_salt: u32,
    ) -> [u8; 32] {
        use ring::digest;

        // Build input: fingerprint || discovery_id || session_salt || b"psk_confirmation_v1"
        let mut input = Vec::new();
        input.extend_from_slice(psk_fingerprint.as_bytes());
        input.extend_from_slice(&discovery_id.to_be_bytes());
        input.extend_from_slice(&session_salt.to_be_bytes());
        input.extend_from_slice(b"psk_confirmation_v1");

        // Calculate SHA256 hash
        let hash_result = digest::digest(&digest::SHA256, &input);
        hash_result.as_ref().try_into().unwrap_or_default()
    }

    /// Verify confirmation hash against local fingerprints
    ///
    /// Protocol: Check if confirmation hash matches any of our local PSK fingerprints.
    /// Returns the matching fingerprint if found, None otherwise.
    pub fn verify_confirmation(
        &self,
        confirmation_hash: &[u8; 32],
        local_fingerprints: &[PskFingerprint],
        discovery_id: DiscoveryId,
        session_salt: u32,
    ) -> Option<PskFingerprint> {
        use subtle::ConstantTimeEq;

        // Check each fingerprint
        for fingerprint in local_fingerprints {
            let expected_hash =
                self.calculate_confirmation_hash(fingerprint, discovery_id, session_salt);

            // Constant-time comparison to prevent timing attacks
            if confirmation_hash.ct_eq(&expected_hash).into() {
                return Some(fingerprint.clone());
            }
        }

        None
    }
}

impl Default for BloomFilterBuilder {
    fn default() -> Self {
        // Default: 256 expected elements with 1% false positive rate
        Self::new(256, 0.01)
    }
}

/// PSK hint filter wrapper providing a simpler API for PSK hint operations
pub struct PskHintFilter {
    builder: BloomFilterBuilder,
    filter: BloomFilter,
    discovery_id: DiscoveryId,
    session_salt: u32,
}

impl PskHintFilter {
    /// Create a new PSK hint filter with expected number of PSKs
    pub fn new(expected_psks: usize) -> Self {
        let builder = BloomFilterBuilder::new(expected_psks as u32, 0.01);
        let size_bytes = builder.size_bits.div_ceil(8);
        let filter = BloomFilter {
            bits: vec![0u8; size_bytes],
            hash_functions: HashFunctionCount::new(builder.hash_functions),
            expected_elements: ElementCount::new(builder.expected_elements),
        };

        Self {
            builder,
            filter,
            discovery_id: DiscoveryId::new(0),
            session_salt: 0,
        }
    }

    /// Create with specific discovery context
    pub fn new_with_context(
        expected_psks: usize,
        discovery_id: DiscoveryId,
        session_salt: u32,
    ) -> Self {
        let builder = BloomFilterBuilder::new(expected_psks as u32, 0.01);
        let size_bytes = builder.size_bits.div_ceil(8);
        let filter = BloomFilter {
            bits: vec![0u8; size_bytes],
            hash_functions: HashFunctionCount::new(builder.hash_functions),
            expected_elements: ElementCount::new(builder.expected_elements),
        };

        Self {
            builder,
            filter,
            discovery_id,
            session_salt,
        }
    }

    /// Add a PSK hint to the filter
    pub fn add_psk_hint(&mut self, psk: &[u8]) {
        let blinded = if psk.len() == 32 {
            // If it's a full PSK, create fingerprint and blind it
            let psk_id = PskId::new(psk.try_into().unwrap_or([0u8; 32]));
            self.builder
                .blind_fingerprint(&psk_id, self.discovery_id, self.session_salt)
        } else {
            // Otherwise, pad/truncate to 16 bytes for blinded fingerprint
            let mut blinded = [0u8; 16];
            let len = psk.len().min(16);
            blinded[..len].copy_from_slice(&psk[..len]);
            blinded
        };

        self.builder.insert(&mut self.filter, &blinded);
    }

    /// Check if a PSK hint might be in the filter
    pub fn might_have_psk(&self, psk: &[u8]) -> bool {
        let blinded = if psk.len() == 32 {
            let psk_id = PskId::new(psk.try_into().unwrap_or([0u8; 32]));
            self.builder
                .blind_fingerprint(&psk_id, self.discovery_id, self.session_salt)
        } else {
            let mut blinded = [0u8; 16];
            let len = psk.len().min(16);
            blinded[..len].copy_from_slice(&psk[..len]);
            blinded
        };

        self.builder.test(&self.filter, &blinded)
    }

    /// Clear all entries from the filter
    pub fn clear(&mut self) {
        for byte in &mut self.filter.bits {
            *byte = 0;
        }
    }

    /// Get estimated false positive rate based on current capacity
    pub fn estimated_false_positive_rate(&self) -> f64 {
        // Calculate based on number of bits set
        let bits_set = self
            .filter
            .bits
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum::<usize>();

        let total_bits = self.builder.size_bits;
        if total_bits == 0 {
            return 0.0;
        }

        let proportion_set = bits_set as f64 / total_bits as f64;

        // False positive probability: (1 - e^(-kn/m))^k
        // where k = hash functions, n = elements, m = bits
        // We approximate by using the proportion of bits set
        proportion_set.powi(self.builder.hash_functions as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_builder() {
        let builder = BloomFilterBuilder::new(100, 0.01);
        assert!(builder.size_bits > 0);
        assert!(builder.hash_functions > 0);
    }

    #[test]
    fn test_bloom_filter_insert_and_test() {
        let builder = BloomFilterBuilder::default();
        // Calculate the correct size for the filter
        let size_bytes = builder.size_bits.div_ceil(8);
        let mut bloom = BloomFilter {
            bits: vec![0u8; size_bytes],
            hash_functions: HashFunctionCount::new(builder.hash_functions),
            expected_elements: ElementCount::new(builder.expected_elements),
        };

        let test_data = [1u8; 16];
        builder.insert(&mut bloom, &test_data);

        assert!(builder.test(&bloom, &test_data));

        let other_data = [2u8; 16];
        // Might be false positive, but usually should be false
        let _result = builder.test(&bloom, &other_data);
    }

    #[test]
    fn test_bloom_filter_no_false_negatives() {
        // Bloom filters NEVER produce false negatives - inserted items are ALWAYS found
        let builder = BloomFilterBuilder::new(100, 0.01);
        let size_bytes = builder.size_bits.div_ceil(8);
        let mut bloom = BloomFilter {
            bits: vec![0u8; size_bytes],
            hash_functions: HashFunctionCount::new(builder.hash_functions),
            expected_elements: ElementCount::new(builder.expected_elements),
        };

        // Insert 50 distinct items
        let mut inserted_items = Vec::new();
        for i in 0..50u8 {
            let mut item = [0u8; 16];
            item[0] = i;
            item[1] = i.wrapping_mul(7); // Add some variation
            inserted_items.push(item);
            builder.insert(&mut bloom, &item);
        }

        // Verify EVERY inserted item is found (no false negatives)
        for (idx, item) in inserted_items.iter().enumerate() {
            assert!(
                builder.test(&bloom, item),
                "Item {} should always be found (no false negatives allowed)",
                idx
            );
        }
    }

    #[test]
    fn test_bloom_filter_clear() {
        let builder = BloomFilterBuilder::new(100, 0.01);
        let size_bytes = builder.size_bits.div_ceil(8);
        let mut bloom = BloomFilter {
            bits: vec![0u8; size_bytes],
            hash_functions: HashFunctionCount::new(builder.hash_functions),
            expected_elements: ElementCount::new(builder.expected_elements),
        };

        // Insert some items
        let item1 = [1u8; 16];
        let item2 = [2u8; 16];
        builder.insert(&mut bloom, &item1);
        builder.insert(&mut bloom, &item2);

        // Verify items are present
        assert!(builder.test(&bloom, &item1));
        assert!(builder.test(&bloom, &item2));

        // Clear the filter
        for byte in &mut bloom.bits {
            *byte = 0;
        }

        // Verify items are no longer found
        assert!(!builder.test(&bloom, &item1));
        assert!(!builder.test(&bloom, &item2));

        // Verify all bits are cleared
        assert!(bloom.bits.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn test_psk_hint_insert() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;
        let mut filter = PskHintFilter::new_with_context(100, discovery_id, session_salt);

        // Insert several PSK hints
        let psk1 = PskId::from_u32(1);
        let psk2 = PskId::from_u32(2);
        let psk3 = PskId::from_u32(3);

        filter.add_psk_hint(psk1.as_bytes());
        filter.add_psk_hint(psk2.as_bytes());
        filter.add_psk_hint(psk3.as_bytes());

        // Verify all inserted PSKs are found
        assert!(filter.might_have_psk(psk1.as_bytes()));
        assert!(filter.might_have_psk(psk2.as_bytes()));
        assert!(filter.might_have_psk(psk3.as_bytes()));
    }

    #[test]
    fn test_psk_hint_lookup() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;
        let mut filter = PskHintFilter::new_with_context(100, discovery_id, session_salt);

        // Insert known PSKs
        let known_psk = PskId::from_u32(42);
        let unknown_psk = PskId::from_u32(99);

        filter.add_psk_hint(known_psk.as_bytes());

        // Lookup should find known PSK
        assert!(
            filter.might_have_psk(known_psk.as_bytes()),
            "Known PSK should be found"
        );

        // Unknown PSK should usually not be found (may have false positives)
        let unknown_result = filter.might_have_psk(unknown_psk.as_bytes());

        // We can't assert false here due to potential false positives,
        // but we can verify the lookup completes without error
        let _ = unknown_result;
    }

    #[test]
    fn test_psk_hint_filter_clear() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;
        let mut filter = PskHintFilter::new_with_context(50, discovery_id, session_salt);

        // Insert several PSKs
        for i in 0..10 {
            let psk = PskId::from_u32(i);
            filter.add_psk_hint(psk.as_bytes());
        }

        // Verify at least one is found
        let test_psk = PskId::from_u32(5);
        assert!(filter.might_have_psk(test_psk.as_bytes()));

        // Clear the filter
        filter.clear();

        // After clear, previously inserted items should not be found
        for i in 0..10 {
            let psk = PskId::from_u32(i);
            assert!(
                !filter.might_have_psk(psk.as_bytes()),
                "PSK {} should not be found after clear",
                i
            );
        }
    }

    #[test]
    fn test_psk_hint_filter_false_positive_rate() {
        let discovery_id = DiscoveryId::new(12345);
        let session_salt = 67890u32;
        let mut filter = PskHintFilter::new_with_context(100, discovery_id, session_salt);

        // Insert 100 PSKs
        for i in 0..100 {
            let psk = PskId::from_u32(i);
            filter.add_psk_hint(psk.as_bytes());
        }

        // Test with non-member PSKs
        let mut false_positives = 0;
        for i in 200..1200 {
            let psk = PskId::from_u32(i);
            if filter.might_have_psk(psk.as_bytes()) {
                false_positives += 1;
            }
        }

        let fp_rate = false_positives as f64 / 1000.0;

        // Should be reasonably low (< 5%)
        assert!(
            fp_rate < 0.05,
            "False positive rate should be < 5%, got {}",
            fp_rate
        );

        // Estimated FP rate should be reasonable
        let estimated_fp = filter.estimated_false_positive_rate();
        assert!(
            (0.0..1.0).contains(&estimated_fp),
            "Estimated FP rate should be between 0 and 1, got {}",
            estimated_fp
        );
    }
}
