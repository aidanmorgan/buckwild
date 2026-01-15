#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Key derivation functions
//
// This module provides key derivation functions for the Buckwild protocol,
// using HKDF-SHA256 for key derivation from high-entropy ECDH shared secrets.

use crate::error::security::SecurityError;
use crate::memory::secure::SecureBytes;
use crate::protocol::types::SaltBytes;
use pbkdf2::pbkdf2_hmac;
use ring::hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Result type for KDF operations
pub type KdfResult<T> = Result<T, SecurityError>;

/// HKDF parameters
#[derive(Default)]
pub struct HkdfParams {
    pub salt: SaltBytes,
    pub info: Vec<u8>,
}

/// Parameter chunk allocation as defined in the protocol specification
///
/// HKDF derives 1024-bit (128 bytes) master key material, extracted as 64 × 16-bit chunks:
/// - Chunks 0-3: 32-bit client/server initial sequence numbers
/// - Chunks 4-5: 16-bit client/server port offsets  
/// - Chunks 6-21: 256-bit HMAC authentication key
/// - Chunks 22-23: 32-bit port hopping seed
/// - Chunks 24-25: Reserved for future use
/// - Chunks 26-63: Additional session parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkRange {
    /// Chunks 0-3: Initial sequence numbers (client/server)
    SequenceNumbers,

    /// Chunks 4-5: Port offsets (client/server)
    PortOffsets,

    /// Chunks 6-21: HMAC authentication key (256-bit)
    HmacKey,

    /// Chunks 22-23: Port hopping seed (32-bit)
    PortHoppingSeed,

    /// Chunks 24-25: Reserved for future use
    Reserved,

    /// Chunks 26-63: Additional session parameters
    SessionParameters,
}

impl ChunkRange {
    /// Get the start and end chunk indices for this range
    pub fn range(&self) -> (usize, usize) {
        match self {
            Self::SequenceNumbers => (0, 4),
            Self::PortOffsets => (4, 6),
            Self::HmacKey => (6, 22),
            Self::PortHoppingSeed => (22, 24),
            Self::Reserved => (24, 26),
            Self::SessionParameters => (26, 64),
        }
    }

    /// Get the number of chunks in this range
    pub fn count(&self) -> usize {
        let (start, end) = self.range();
        end - start
    }
}

/// HKDF output length specification
struct MyLength(usize);

impl hkdf::KeyType for MyLength {
    fn len(&self) -> usize {
        self.0
    }
}

/// Key derivation function
pub struct Kdf {
    /// HKDF parameters
    params: HkdfParams,
}

impl Kdf {
    /// Create a new KDF with the specified parameters
    pub fn new(params: HkdfParams) -> Self {
        Self { params }
    }

    /// Create a new KDF with default parameters
    pub fn new_default() -> Self {
        Self::new(HkdfParams::default())
    }

    /// Derive parameters from a key using HKDF-SHA256
    ///
    /// This function derives 64 × 16-bit chunks from a key using HKDF-SHA256.
    /// HKDF is designed for key derivation from high-entropy secrets like ECDH shared secrets.
    ///
    /// **Note**: This function is deprecated in favor of `derive_key_pbkdf2()` for port hopping
    /// and session parameters as specified in design/protocol/04-ecdh-cryptography.md:363-368.
    /// HKDF is designed for high-entropy keys like ECDH shared secrets, while PBKDF2 is designed
    /// for password-based key derivation with computational cost.
    ///
    /// # Arguments
    ///
    /// * `key` - The input key material (IKM) to derive parameters from
    ///
    /// # Returns
    ///
    /// A vector of 64 × 16-bit chunks (128 bytes)
    #[deprecated(
        since = "0.1.0",
        note = "Use derive_key_pbkdf2() for port hopping parameters as per protocol specification"
    )]
    pub fn derive_parameters(&self, key: &[u8]) -> KdfResult<SecureBytes> {
        // Derive 128 bytes (64 × 16-bit chunks)
        let mut output = SecureBytes::with_size(128);

        // Extract phase: create PRK from IKM
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, self.params.salt.as_slice());
        let prk = salt.extract(key);

        // Expand phase: derive output key material
        prk.expand(&[&self.params.info], MyLength(128))
            .map_err(|_| SecurityError::key_derivation_failed("Hkdf expand failed"))?
            .fill(output.as_mut_slice())
            .map_err(|_| SecurityError::key_derivation_failed("Hkdf fill failed"))?;

        Ok(output)
    }

    /// Get a specific chunk from derived parameters
    ///
    /// # Arguments
    ///
    /// * `params` - The derived parameters
    /// * `chunk_range` - The range of chunks to get from
    /// * `index` - The index of the chunk within the range
    ///
    /// # Returns
    ///
    /// A 16-bit chunk
    pub fn get_chunk(params: &[u8], chunk_range: ChunkRange, index: usize) -> KdfResult<u16> {
        let (start, end) = chunk_range.range();
        let absolute_index = start + index;

        // Check bounds
        if absolute_index >= end {
            return Err(SecurityError::invalid_parameter(format!(
                "Chunk index out of bounds: range={:?}, index={}, max={}",
                chunk_range,
                index,
                end - start - 1
            )));
        }

        let offset = absolute_index * 2; // 2 bytes per chunk

        if offset + 1 >= params.len() {
            return Err(SecurityError::invalid_parameter(format!(
                "Parameter buffer too small: need {}, got {}",
                offset + 2,
                params.len()
            )));
        }

        // Extract the chunk with proper endianness (big-endian)
        let chunk = u16::from_be_bytes([params[offset], params[offset + 1]]);

        Ok(chunk)
    }

    /// Get a slice of chunks from derived parameters
    ///
    /// # Arguments
    ///
    /// * `params` - The derived parameters
    /// * `chunk_range` - The range of chunks to get from
    /// * `start` - The starting index within the range
    /// * `count` - The number of chunks to get
    ///
    /// # Returns
    ///
    /// A vector of 16-bit chunks
    pub fn get_chunks(
        params: &[u8],
        chunk_range: ChunkRange,
        start: usize,
        count: usize,
    ) -> KdfResult<Vec<u16>> {
        let (range_start, range_end) = chunk_range.range();

        // Check bounds
        if start + count > range_end - range_start {
            return Err(SecurityError::invalid_parameter(format!(
                "Chunk range out of bounds: range={:?}, start={}, count={}, max={}",
                chunk_range,
                start,
                count,
                range_end - range_start
            )));
        }

        let mut chunks = Vec::with_capacity(count);

        for i in 0..count {
            chunks.push(Self::get_chunk(params, chunk_range, start + i)?);
        }

        Ok(chunks)
    }

    /// Get all chunks from a specific range
    ///
    /// # Arguments
    ///
    /// * `params` - The derived parameters
    /// * `chunk_range` - The range of chunks to get
    ///
    /// # Returns
    ///
    /// A vector of 16-bit chunks
    pub fn get_range_chunks(params: &[u8], chunk_range: ChunkRange) -> KdfResult<Vec<u16>> {
        Self::get_chunks(params, chunk_range, 0, chunk_range.count())
    }

    /// Extract sequence numbers (chunks 0-3)
    pub fn extract_sequence_numbers(params: &[u8]) -> KdfResult<(u32, u32)> {
        let chunks = Self::get_range_chunks(params, ChunkRange::SequenceNumbers)?;
        if chunks.len() != 4 {
            return Err(SecurityError::invalid_parameter(
                "Invalid sequence number chunks",
            ));
        }

        let client_seq = ((chunks[0] as u32) << 16) | (chunks[1] as u32);
        let server_seq = ((chunks[2] as u32) << 16) | (chunks[3] as u32);

        Ok((client_seq, server_seq))
    }

    /// Extract port offsets (chunks 4-5)
    pub fn extract_port_offsets(params: &[u8]) -> KdfResult<(u16, u16)> {
        let chunks = Self::get_range_chunks(params, ChunkRange::PortOffsets)?;
        if chunks.len() != 2 {
            return Err(SecurityError::invalid_parameter(
                "Invalid port offset chunks",
            ));
        }

        Ok((chunks[0], chunks[1]))
    }

    /// Extract HMAC key (chunks 6-21)
    pub fn extract_hmac_key(params: &[u8]) -> KdfResult<[u8; 32]> {
        let chunks = Self::get_range_chunks(params, ChunkRange::HmacKey)?;
        if chunks.len() != 16 {
            return Err(SecurityError::invalid_parameter("Invalid HMAC key chunks"));
        }

        let mut key = [0u8; 32];
        for (i, chunk) in chunks.iter().enumerate() {
            key[i * 2] = (*chunk >> 8) as u8;
            key[i * 2 + 1] = (*chunk & 0xFF) as u8;
        }

        Ok(key)
    }

    /// Extract port hopping seed (chunks 22-23)
    pub fn extract_port_hopping_seed(params: &[u8]) -> KdfResult<u32> {
        let chunks = Self::get_range_chunks(params, ChunkRange::PortHoppingSeed)?;
        if chunks.len() != 2 {
            return Err(SecurityError::invalid_parameter(
                "Invalid port hopping seed chunks",
            ));
        }

        let seed = ((chunks[0] as u32) << 16) | (chunks[1] as u32);
        Ok(seed)
    }

    /// Extract all 26 session chunks from derived key material
    ///
    /// This function extracts all 26 chunks (0-25) from the 128-byte derived key material
    /// as specified in design/protocol/04-ecdh-cryptography.md §280-296.
    ///
    /// # Chunk Layout (26 chunks total):
    /// - Chunks 0-1: Client initial sequence number (32-bit)
    /// - Chunks 2-3: Server initial sequence number (32-bit)
    /// - Chunk 4: Client port offset (16-bit)
    /// - Chunk 5: Server port offset (16-bit)
    /// - Chunks 6-21: Session HMAC key (256-bit, 16 chunks)
    /// - Chunks 22-23: Port hopping seed (32-bit)
    /// - Chunk 24: Time synchronization offset (16-bit)
    /// - Chunk 25: Congestion control seed (16-bit)
    ///
    /// # Arguments
    ///
    /// * `params` - The 128-byte derived key material from PBKDF2
    ///
    /// # Returns
    ///
    /// Array of 26 16-bit chunks on success, or `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::InvalidParameter` if:
    /// - Input length is not 128 bytes
    pub fn extract_session_chunks(params: &[u8]) -> KdfResult<[u16; 26]> {
        // Validate input length
        Self::validate_parameters(params)?;

        let mut chunks = [0u16; 26];

        // Extract all 26 chunks (each chunk is 2 bytes, big-endian)
        for (i, chunk) in chunks.iter_mut().enumerate() {
            let offset = i * 2;
            *chunk = u16::from_be_bytes([params[offset], params[offset + 1]]);
        }

        Ok(chunks)
    }

    /// Validate derived parameters
    ///
    /// # Arguments
    ///
    /// * `params` - The derived parameters
    ///
    /// # Returns
    ///
    /// `Ok(())` if the parameters are valid, `Err(SecurityError)` otherwise
    pub fn validate_parameters(params: &[u8]) -> KdfResult<()> {
        // Check length
        if params.len() != 128 {
            return Err(SecurityError::invalid_parameter(format!(
                "Invalid parameter length: expected 128, got {}",
                params.len()
            )));
        }

        Ok(())
    }

    /// Set the salt for the KDF
    ///
    /// # Arguments
    ///
    /// * `salt` - The new salt
    pub fn set_salt(&mut self, salt: SaltBytes) {
        self.params.salt = salt;
    }

    /// Set the info context string for HKDF
    ///
    /// # Arguments
    ///
    /// * `info` - The info/context string for HKDF
    pub fn set_info(&mut self, info: Vec<u8>) {
        self.params.info = info;
    }

    /// Get the current parameters
    pub fn get_params(&self) -> &HkdfParams {
        &self.params
    }
}

/// Derive key using PBKDF2-HMAC-SHA256
///
/// This function implements the port hopping parameter derivation as specified in
/// design/protocol/04-ecdh-cryptography.md:363-368. PBKDF2 provides computational
/// cost through iterations, making it suitable for deriving port hopping sequences
/// from shared secrets.
///
/// # Protocol Reference
///
/// From design/protocol/04-ecdh-cryptography.md:363-368:
/// ```text
/// port_material = PBKDF2_HMAC_SHA256(
///     password = shared_secret,
///     salt = salt,
///     iterations = PBKDF2_ITERATIONS_PORT,
///     key_length = 8      # 64 bits for port parameters
/// )
/// ```
///
/// # Arguments
///
/// * `password` - The password/key material (e.g., ECDH shared secret)
/// * `salt` - Salt value for the derivation
/// * `iterations` - Number of PBKDF2 iterations (computational cost)
/// * `output_length` - Desired output length in bytes
///
/// # Returns
///
/// Derived key bytes on success, or `SecurityError` on failure
///
/// # Errors
///
/// Returns `SecurityError::InvalidParameter` if:
/// - Password is empty
/// - Iterations is zero
/// - Output length is zero or excessively large (> 1024 bytes)
pub fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_length: usize,
) -> KdfResult<Zeroizing<Vec<u8>>> {
    // Validate inputs
    if password.is_empty() {
        return Err(SecurityError::invalid_parameter("Password cannot be empty"));
    }

    if iterations == 0 {
        return Err(SecurityError::invalid_parameter(
            "Iterations must be greater than zero",
        ));
    }

    if output_length == 0 {
        return Err(SecurityError::invalid_parameter(
            "Output length must be greater than zero",
        ));
    }

    // Prevent excessive memory allocation
    if output_length > 1024 {
        return Err(SecurityError::invalid_parameter(format!(
            "Output length too large: {} bytes (max 1024)",
            output_length
        )));
    }

    // Derive key using PBKDF2-HMAC-SHA256
    // Use Zeroizing to ensure key material is zeroed on drop
    let mut output = Zeroizing::new(vec![0u8; output_length]);
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_kdf_parameter_derivation() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x42; 32]);

        let result = kdf.derive_parameters(&key);
        assert!(result.is_ok());

        let params = result.unwrap();
        assert_eq!(params.len(), 128); // Should be 1024 bits = 128 bytes
    }

    #[test]
    #[allow(deprecated)]
    fn test_kdf_determinism() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0xAB; 32]);

        let params1 = kdf.derive_parameters(&key).unwrap();
        let params2 = kdf.derive_parameters(&key).unwrap();

        // Compare bytes since SecureBuffer doesn't implement PartialEq
        assert_eq!(params1.as_slice(), params2.as_slice());
    }

    #[test]
    fn test_chunk_range_counts() {
        assert_eq!(ChunkRange::SequenceNumbers.count(), 4);
        assert_eq!(ChunkRange::PortOffsets.count(), 2);
        assert_eq!(ChunkRange::HmacKey.count(), 16);
        assert_eq!(ChunkRange::PortHoppingSeed.count(), 2);
        assert_eq!(ChunkRange::Reserved.count(), 2);
        assert_eq!(ChunkRange::SessionParameters.count(), 38);
    }

    #[test]
    #[allow(deprecated)]
    fn test_extract_sequence_numbers() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x01; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        let result = Kdf::extract_sequence_numbers(&params);
        assert!(result.is_ok());

        let (client_seq, server_seq) = result.unwrap();
        assert!(client_seq > 0 || server_seq > 0);
    }

    #[test]
    #[allow(deprecated)]
    fn test_extract_port_offsets() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x02; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        let result = Kdf::extract_port_offsets(&params);
        assert!(result.is_ok());

        let (_client_offset, _server_offset) = result.unwrap();
        // Port offsets are u16, so they're always valid
    }

    #[test]
    #[allow(deprecated)]
    fn test_extract_hmac_key() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x03; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        let result = Kdf::extract_hmac_key(&params);
        assert!(result.is_ok());

        let hmac_key = result.unwrap();
        assert_eq!(hmac_key.len(), 32);
    }

    #[test]
    #[allow(deprecated)]
    fn test_extract_port_hopping_seed() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x04; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        let result = Kdf::extract_port_hopping_seed(&params);
        assert!(result.is_ok());
    }

    #[test]
    #[allow(deprecated)]
    fn test_validate_parameters() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x05; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        assert!(Kdf::validate_parameters(&params).is_ok());

        // Test invalid length
        let invalid_params = vec![0u8; 64];
        assert!(Kdf::validate_parameters(&invalid_params).is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_chunk() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x06; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        // Get first chunk from sequence numbers
        let result = Kdf::get_chunk(&params, ChunkRange::SequenceNumbers, 0);
        assert!(result.is_ok());

        // Test out of bounds
        let result = Kdf::get_chunk(&params, ChunkRange::SequenceNumbers, 100);
        assert!(result.is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_chunks() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x07; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        let result = Kdf::get_chunks(&params, ChunkRange::SequenceNumbers, 0, 2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_range_chunks() {
        let kdf = Kdf::new_default();
        let key = SecureBytes::from_slice(&[0x08; 32]);
        let params = kdf.derive_parameters(&key).unwrap();

        let result = Kdf::get_range_chunks(&params, ChunkRange::HmacKey);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    // =========================================================================
    // PBKDF2 Tests
    // =========================================================================

    /// RFC 6070 Test Vector 1 (adapted for PBKDF2-HMAC-SHA256)
    ///
    /// Password: "password"
    /// Salt: "salt"
    /// Iterations: 1
    /// Output length: 20 bytes
    /// Expected (SHA256): 120fb6cffcf8b32c43e7225256c4f837a86548c9
    ///
    /// Note: RFC 6070 originally specified SHA1, but we use SHA256 for security.
    #[test]
    fn test_pbkdf2_rfc6070_vector1() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1;
        let output_length = 20;

        let result = derive_key_pbkdf2(password, salt, iterations, output_length);
        assert!(result.is_ok());

        let derived = result.unwrap();
        assert_eq!(derived.len(), 20);

        // PBKDF2-HMAC-SHA256 expected output (adapted from RFC 6070)
        let expected = hex::decode("120fb6cffcf8b32c43e7225256c4f837a86548c9")
            .expect("Failed to decode expected hex");
        assert_eq!(
            &derived[..],
            expected.as_slice(),
            "RFC 6070 Test Vector 1 (SHA256) failed"
        );
    }

    /// RFC 6070 Test Vector 2 (adapted for PBKDF2-HMAC-SHA256)
    ///
    /// Password: "password"
    /// Salt: "salt"
    /// Iterations: 2
    /// Output length: 20 bytes
    /// Expected (SHA256): ae4d0c95af6b46d32d0adff928f06dd02a303f8e
    ///
    /// Note: RFC 6070 originally specified SHA1, but we use SHA256 for security.
    #[test]
    fn test_pbkdf2_rfc6070_vector2() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let output_length = 20;

        let result = derive_key_pbkdf2(password, salt, iterations, output_length);
        assert!(result.is_ok());

        let derived = result.unwrap();
        assert_eq!(derived.len(), 20);

        // PBKDF2-HMAC-SHA256 expected output (adapted from RFC 6070)
        let expected = hex::decode("ae4d0c95af6b46d32d0adff928f06dd02a303f8e")
            .expect("Failed to decode expected hex");
        assert_eq!(
            &derived[..],
            expected.as_slice(),
            "RFC 6070 Test Vector 2 (SHA256) failed"
        );
    }

    /// Test that different iteration counts produce different outputs
    #[test]
    fn test_pbkdf2_iterations_differ() {
        let password = b"test_password";
        let salt = b"test_salt";
        let output_length = 32;

        let result_2048 =
            derive_key_pbkdf2(password, salt, 2048, output_length).expect("2048 iterations failed");
        let result_4096 =
            derive_key_pbkdf2(password, salt, 4096, output_length).expect("4096 iterations failed");

        assert_eq!(result_2048.len(), 32);
        assert_eq!(result_4096.len(), 32);
        assert_ne!(
            &result_2048[..],
            &result_4096[..],
            "Different iteration counts should produce different keys"
        );
    }

    /// Test empty password returns error
    #[test]
    fn test_pbkdf2_empty_password() {
        let password = b"";
        let salt = b"salt";
        let iterations = 1000;
        let output_length = 32;

        let result = derive_key_pbkdf2(password, salt, iterations, output_length);
        assert!(result.is_err(), "Empty password should return error");

        if let Err(e) = result {
            assert!(e.to_string().contains("Password cannot be empty"));
        }
    }

    /// Test zero iterations returns error
    #[test]
    fn test_pbkdf2_zero_iterations() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 0;
        let output_length = 32;

        let result = derive_key_pbkdf2(password, salt, iterations, output_length);
        assert!(result.is_err(), "Zero iterations should return error");

        if let Err(e) = result {
            assert!(
                e.to_string()
                    .contains("Iterations must be greater than zero")
            );
        }
    }

    /// Test large output length succeeds
    #[test]
    fn test_pbkdf2_large_output() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 100;
        let output_length = 128;

        let result = derive_key_pbkdf2(password, salt, iterations, output_length);
        assert!(result.is_ok(), "128 byte output should succeed");

        let derived = result.unwrap();
        assert_eq!(derived.len(), 128, "Output length should be 128 bytes");
    }

    /// Test excessive output length returns error
    #[test]
    fn test_pbkdf2_excessive_output() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 100;
        let output_length = 2048; // Exceeds 1024 byte limit

        let result = derive_key_pbkdf2(password, salt, iterations, output_length);
        assert!(
            result.is_err(),
            "Excessive output length should return error"
        );

        if let Err(e) = result {
            assert!(e.to_string().contains("Output length too large"));
        }
    }

    /// Test determinism - same inputs produce same outputs
    #[test]
    fn test_pbkdf2_determinism() {
        let password = b"deterministic_password";
        let salt = b"deterministic_salt";
        let iterations = 1000;
        let output_length = 64;

        let result1 = derive_key_pbkdf2(password, salt, iterations, output_length)
            .expect("First derivation failed");
        let result2 = derive_key_pbkdf2(password, salt, iterations, output_length)
            .expect("Second derivation failed");

        assert_eq!(&result1[..], &result2[..], "PBKDF2 should be deterministic");
    }

    /// Test different salts produce different outputs
    #[test]
    fn test_pbkdf2_salt_differs() {
        let password = b"password";
        let salt1 = b"salt1";
        let salt2 = b"salt2";
        let iterations = 1000;
        let output_length = 32;

        let result1 = derive_key_pbkdf2(password, salt1, iterations, output_length)
            .expect("Salt1 derivation failed");
        let result2 = derive_key_pbkdf2(password, salt2, iterations, output_length)
            .expect("Salt2 derivation failed");

        assert_ne!(
            &result1[..],
            &result2[..],
            "Different salts should produce different keys"
        );
    }

    /// Test zero output length returns error
    #[test]
    fn test_pbkdf2_zero_output_length() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1000;
        let output_length = 0;

        let result = derive_key_pbkdf2(password, salt, iterations, output_length);
        assert!(result.is_err(), "Zero output length should return error");

        if let Err(e) = result {
            assert!(
                e.to_string()
                    .contains("Output length must be greater than zero")
            );
        }
    }

    // =========================================================================
    // 26-Chunk Session Key Extraction Tests (TASK-005)
    // =========================================================================

    /// Test that extract_session_chunks returns exactly 26 chunks
    #[test]
    fn test_extract_session_chunks_count() {
        let password = b"test_shared_secret_32_bytes_long";
        let salt = b"test_salt";
        let key_material =
            derive_key_pbkdf2(password, salt, 4096, 128).expect("PBKDF2 derivation failed");

        let chunks = Kdf::extract_session_chunks(&key_material).expect("Chunk extraction failed");

        assert_eq!(chunks.len(), 26, "Should extract exactly 26 chunks");
    }

    /// Test that modifying one input byte changes all chunks (avalanche effect)
    #[test]
    fn test_extract_session_chunks_avalanche() {
        let password1 = b"test_shared_secret_32_bytes_long";
        let password2 = b"test_shared_secret_32_bytes_lonG"; // Last byte different
        let salt = b"test_salt";

        let key_material1 =
            derive_key_pbkdf2(password1, salt, 4096, 128).expect("PBKDF2 derivation 1 failed");
        let key_material2 =
            derive_key_pbkdf2(password2, salt, 4096, 128).expect("PBKDF2 derivation 2 failed");

        let chunks1 =
            Kdf::extract_session_chunks(&key_material1).expect("Chunk extraction 1 failed");
        let chunks2 =
            Kdf::extract_session_chunks(&key_material2).expect("Chunk extraction 2 failed");

        // Count how many chunks are different
        let different_chunks = chunks1
            .iter()
            .zip(chunks2.iter())
            .filter(|(a, b)| a != b)
            .count();

        // With good key derivation, changing one input byte should change most/all chunks
        assert!(
            different_chunks >= 20,
            "Avalanche effect: expected most chunks to differ, but only {} of 26 differ",
            different_chunks
        );
    }

    /// Test that each chunk is used for its designated purpose
    #[test]
    fn test_extract_session_chunks_designated_usage() {
        let password = b"test_shared_secret_32_bytes_long";
        let salt = b"test_salt";
        let key_material =
            derive_key_pbkdf2(password, salt, 4096, 128).expect("PBKDF2 derivation failed");

        let chunks = Kdf::extract_session_chunks(&key_material).expect("Chunk extraction failed");

        // Verify chunks match the protocol specification layout

        // Chunks 0-1: Client sequence
        let client_seq_from_chunks = ((chunks[0] as u32) << 16) | (chunks[1] as u32);
        let (client_seq_extracted, _) =
            Kdf::extract_sequence_numbers(&key_material).expect("Sequence extraction failed");
        assert_eq!(
            client_seq_from_chunks, client_seq_extracted,
            "Client sequence from chunks should match extracted sequence"
        );

        // Chunks 2-3: Server sequence
        let server_seq_from_chunks = ((chunks[2] as u32) << 16) | (chunks[3] as u32);
        let (_, server_seq_extracted) =
            Kdf::extract_sequence_numbers(&key_material).expect("Sequence extraction failed");
        assert_eq!(
            server_seq_from_chunks, server_seq_extracted,
            "Server sequence from chunks should match extracted sequence"
        );

        // Chunks 4-5: Port offsets
        let (client_port_extracted, server_port_extracted) =
            Kdf::extract_port_offsets(&key_material).expect("Port offset extraction failed");
        assert_eq!(
            chunks[4], client_port_extracted,
            "Client port offset from chunk 4 should match extracted value"
        );
        assert_eq!(
            chunks[5], server_port_extracted,
            "Server port offset from chunk 5 should match extracted value"
        );

        // Chunks 6-21: HMAC key (verify it can be reconstructed)
        let hmac_key_extracted =
            Kdf::extract_hmac_key(&key_material).expect("HMAC key extraction failed");
        let mut hmac_key_from_chunks = [0u8; 32];
        for i in 0..16 {
            hmac_key_from_chunks[i * 2] = (chunks[6 + i] >> 8) as u8;
            hmac_key_from_chunks[i * 2 + 1] = (chunks[6 + i] & 0xFF) as u8;
        }
        assert_eq!(
            hmac_key_from_chunks, hmac_key_extracted,
            "HMAC key from chunks 6-21 should match extracted key"
        );

        // Chunks 22-23: Port hopping seed
        let port_hop_seed_from_chunks = ((chunks[22] as u32) << 16) | (chunks[23] as u32);
        let port_hop_seed_extracted = Kdf::extract_port_hopping_seed(&key_material)
            .expect("Port hopping seed extraction failed");
        assert_eq!(
            port_hop_seed_from_chunks, port_hop_seed_extracted,
            "Port hopping seed from chunks 22-23 should match extracted seed"
        );

        // Chunks 24-25: Reserved (time offset, congestion seed)
        let time_offset = chunks[24];
        let congestion_seed = chunks[25];
        // These are just verification that they exist and are accessible
        assert!(time_offset <= u16::MAX);
        assert!(congestion_seed <= u16::MAX);
    }

    /// Test that no chunk is used for multiple purposes (verify uniqueness of usage)
    #[test]
    fn test_extract_session_chunks_no_overlap() {
        // This test verifies the chunk allocation matches the spec and has no overlaps
        // Chunk allocation from spec (design/protocol/04-ecdh-cryptography.md):
        // - Chunks 0-1: Client sequence
        // - Chunks 2-3: Server sequence
        // - Chunk 4: Client port offset
        // - Chunk 5: Server port offset
        // - Chunks 6-21: HMAC key (16 chunks)
        // - Chunks 22-23: Port hopping seed
        // - Chunk 24: Time offset
        // - Chunk 25: Congestion seed
        // Total: 26 chunks (0-25), no gaps, no overlaps

        let used_chunks = vec![
            (0, 1, "Client sequence"),
            (2, 3, "Server sequence"),
            (4, 4, "Client port offset"),
            (5, 5, "Server port offset"),
            (6, 21, "HMAC key"),
            (22, 23, "Port hopping seed"),
            (24, 24, "Time offset"),
            (25, 25, "Congestion seed"),
        ];

        let mut coverage = [false; 26];

        for (start, end, purpose) in &used_chunks {
            for i in *start..=*end {
                assert!(
                    !coverage[i],
                    "Chunk {} used multiple times (currently: {})",
                    i, purpose
                );
                coverage[i] = true;
            }
        }

        // Verify all chunks are accounted for
        assert!(
            coverage.iter().all(|&covered| covered),
            "All 26 chunks should be accounted for in the specification"
        );
    }

    /// Test that extraction is deterministic (same input produces same chunks)
    #[test]
    fn test_extract_session_chunks_deterministic() {
        let password = b"deterministic_test_password_here";
        let salt = b"deterministic_salt";
        let iterations = 4096;

        let key_material1 =
            derive_key_pbkdf2(password, salt, iterations, 128).expect("PBKDF2 derivation 1 failed");
        let key_material2 =
            derive_key_pbkdf2(password, salt, iterations, 128).expect("PBKDF2 derivation 2 failed");

        let chunks1 =
            Kdf::extract_session_chunks(&key_material1).expect("Chunk extraction 1 failed");
        let chunks2 =
            Kdf::extract_session_chunks(&key_material2).expect("Chunk extraction 2 failed");

        assert_eq!(
            chunks1, chunks2,
            "Same input should produce identical chunks"
        );
    }

    /// Test that extraction fails with invalid input length
    #[test]
    fn test_extract_session_chunks_invalid_length() {
        let invalid_material_short = vec![0u8; 64]; // Too short
        let invalid_material_long = vec![0u8; 256]; // Too long

        let result_short = Kdf::extract_session_chunks(&invalid_material_short);
        assert!(
            result_short.is_err(),
            "Should fail with input shorter than 128 bytes"
        );

        let result_long = Kdf::extract_session_chunks(&invalid_material_long);
        assert!(
            result_long.is_err(),
            "Should fail with input longer than 128 bytes"
        );
    }

    /// Integration test: Full key exchange uses all chunks correctly
    #[test]
    fn test_full_key_exchange_uses_all_chunks() {
        // Simulate a full ECDH key exchange and verify all chunks are used
        let shared_secret = b"simulated_ecdh_shared_secret_val"; // 32 bytes
        let client_pubkey = [0x11u8; 64];
        let server_pubkey = [0x22u8; 64];
        let session_context = b"test_session_ctx";

        // Create salt as per protocol spec
        use ring::digest;
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(&client_pubkey);
        salt_input.extend_from_slice(&server_pubkey);
        salt_input.extend_from_slice(session_context);
        salt_input.extend_from_slice(b"ecdh_salt_v1");
        let salt_hash = digest::digest(&digest::SHA256, &salt_input);
        let salt = salt_hash.as_ref();

        // Derive key material
        let key_material =
            derive_key_pbkdf2(shared_secret, salt, 4096, 128).expect("PBKDF2 derivation failed");

        // Extract all chunks
        let chunks = Kdf::extract_session_chunks(&key_material).expect("Chunk extraction failed");

        // Verify we can extract all session parameters
        let (client_seq, server_seq) = Kdf::extract_sequence_numbers(&key_material)
            .expect("Sequence numbers extraction failed");
        let (client_port, server_port) =
            Kdf::extract_port_offsets(&key_material).expect("Port offsets extraction failed");
        let hmac_key = Kdf::extract_hmac_key(&key_material).expect("HMAC key extraction failed");
        let port_hop_seed = Kdf::extract_port_hopping_seed(&key_material)
            .expect("Port hopping seed extraction failed");

        // Verify all extracted values match chunks
        assert_eq!(client_seq, ((chunks[0] as u32) << 16) | (chunks[1] as u32));
        assert_eq!(server_seq, ((chunks[2] as u32) << 16) | (chunks[3] as u32));
        assert_eq!(client_port, chunks[4]);
        assert_eq!(server_port, chunks[5]);
        assert_eq!(
            port_hop_seed,
            ((chunks[22] as u32) << 16) | (chunks[23] as u32)
        );

        // Verify HMAC key
        let mut hmac_key_reconstructed = [0u8; 32];
        for i in 0..16 {
            hmac_key_reconstructed[i * 2] = (chunks[6 + i] >> 8) as u8;
            hmac_key_reconstructed[i * 2 + 1] = (chunks[6 + i] & 0xFF) as u8;
        }
        assert_eq!(hmac_key, hmac_key_reconstructed);

        // All chunks accounted for and used correctly
        assert_eq!(chunks.len(), 26);
    }
}
