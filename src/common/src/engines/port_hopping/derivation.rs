#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Port hopping parameter derivation from session keys
//!
//! This module implements TASK-048: derive_session_port_parameters() for deriving
//! port hopping parameters from session keys using PBKDF2.
//!
//! Protocol References:
//! - design/protocol/10-port-hopping.md §119-160: ECDH-Based Port Parameter Derivation
//! - design/protocol/02-core-definitions.md: Port and timing constants
//!
//! Audit Remediation:
//! - PORT-001: Implementation of derive_session_port_parameters()
//! - 3P-MED-003: Session port parameter derivation

use ring::{digest, pbkdf2};

use crate::protocol::types::{Port, SessionId, SessionKey};

/// PBKDF2 iterations for port derivation (design/protocol/10-port-hopping.md:133)
pub const PBKDF2_ITERATIONS_PORT: u32 = 2048;

/// Minimum port for port hopping (1024 - first non-privileged port)
pub const MIN_PORT: u16 = 1024;

/// Maximum port for port hopping (65535 - last valid port)
pub const MAX_PORT: u16 = 65535;

/// Port range for hopping calculations
pub const PORT_RANGE: u16 = MAX_PORT - MIN_PORT + 1;

/// Hop interval in milliseconds (500ms per design/protocol/10-port-hopping.md)
pub const HOP_INTERVAL_MS: u64 = 500;

/// Port parameters derived from session key
///
/// These parameters control the port hopping behavior for a specific session.
/// All values are derived deterministically from the session key and session ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortParameters {
    /// Base port for this session (1024-65535)
    pub base_port: Port,

    /// Hop interval in milliseconds (always 500ms per spec)
    pub hop_interval_ms: u64,

    /// Port range size (always 64512 ports: 1024-65535)
    pub port_range: u16,

    /// Primary port seed (32-bit) for HMAC calculations
    pub port_seed: u32,

    /// Hop sequence seed (32-bit) for sequence generation
    pub hop_sequence_seed: u32,

    /// Time variance in milliseconds (0-100ms)
    pub time_variance_ms: u8,

    /// Hop pattern seed (16-bit) for pattern generation
    pub hop_pattern_seed: u16,
}

impl PortParameters {
    /// Create new port parameters
    pub fn new(
        base_port: Port,
        port_seed: u32,
        hop_sequence_seed: u32,
        time_variance_ms: u8,
        hop_pattern_seed: u16,
    ) -> Self {
        Self {
            base_port,
            hop_interval_ms: HOP_INTERVAL_MS,
            port_range: PORT_RANGE,
            port_seed,
            hop_sequence_seed,
            time_variance_ms,
            hop_pattern_seed,
        }
    }
}

/// Derive session port parameters from session key
///
/// Uses PBKDF2-HMAC-SHA256 with 2048 iterations to derive port hopping parameters
/// from the session key. The derivation includes the session ID to ensure unique
/// parameters for each session.
///
/// # Arguments
///
/// * `session_key` - The session key (32 bytes)
/// * `session_id` - The session ID (8 bytes)
///
/// # Returns
///
/// Port parameters including base port, hop interval, and cryptographic seeds
///
/// # Protocol Compliance
///
/// Per design/protocol/10-port-hopping.md §122-154:
/// - Uses PBKDF2-HMAC-SHA256 with 2048 iterations
/// - Derives 12 bytes (96 bits) of port material
/// - Extracts 6 chunks of 16 bits each
/// - Base port mapped to range 1024-65535
/// - Hop interval fixed at 500ms
pub fn derive_session_port_parameters(
    session_key: &SessionKey,
    session_id: &SessionId,
) -> PortParameters {
    // Create session-specific salt combining session ID
    // Per protocol spec line 127: SHA256(session_id || "port_derivation_v3")
    let mut salt_input = Vec::with_capacity(8 + 18);
    salt_input.extend_from_slice(&session_id.to_be_bytes());
    salt_input.extend_from_slice(b"port_derivation_v3");

    // Hash the salt input
    let salt = digest::digest(&digest::SHA256, &salt_input);

    // Use PBKDF2 to derive port material from session key
    // Per spec (design/protocol/10-port-hopping.md:133), use 2048 iterations
    let mut port_material = [0u8; 12]; // 96 bits = 6 chunks of 16 bits
    let iterations = std::num::NonZeroU32::new(PBKDF2_ITERATIONS_PORT)
        .unwrap_or_else(|| std::num::NonZeroU32::new(2048).unwrap());

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt.as_ref(),
        session_key.as_bytes(),
        &mut port_material,
    );

    // Extract as 16-bit chunks as per protocol specification (lines 137-141)
    let chunk0 = u16::from_be_bytes([port_material[0], port_material[1]]);
    let chunk1 = u16::from_be_bytes([port_material[2], port_material[3]]);
    let chunk2 = u16::from_be_bytes([port_material[4], port_material[5]]);
    let chunk3 = u16::from_be_bytes([port_material[6], port_material[7]]);
    let chunk4 = u16::from_be_bytes([port_material[8], port_material[9]]);
    let chunk5 = u16::from_be_bytes([port_material[10], port_material[11]]);

    // Derive port parameters per spec lines 143-147
    let port_seed = ((chunk0 as u32) << 16) | (chunk1 as u32);
    let hop_sequence_seed = ((chunk2 as u32) << 16) | (chunk3 as u32);
    let time_variance_ms = (chunk4 % 100) as u8; // 0-99ms time variance
    let hop_pattern_seed = chunk5;

    // Calculate base port from first seed value
    // Map to port range 1024-65535
    let port_offset = (port_seed as u64 % PORT_RANGE as u64) as u16;
    let base_port = Port::from_u16_unchecked(MIN_PORT + port_offset);

    PortParameters::new(
        base_port,
        port_seed,
        hop_sequence_seed,
        time_variance_ms,
        hop_pattern_seed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_port_parameters_deterministic() {
        // Same inputs should always produce same outputs
        let session_key = SessionKey::new([0x42; 32]);
        let session_id = SessionId::new(0x1234567890ABCDEF);

        let params1 = derive_session_port_parameters(&session_key, &session_id);
        let params2 = derive_session_port_parameters(&session_key, &session_id);

        assert_eq!(
            params1, params2,
            "Same inputs should produce identical parameters"
        );
        assert_eq!(
            params1.base_port, params2.base_port,
            "Base port should be deterministic"
        );
        assert_eq!(
            params1.port_seed, params2.port_seed,
            "Port seed should be deterministic"
        );
        assert_eq!(
            params1.hop_sequence_seed, params2.hop_sequence_seed,
            "Hop sequence seed should be deterministic"
        );
        assert_eq!(
            params1.time_variance_ms, params2.time_variance_ms,
            "Time variance should be deterministic"
        );
        assert_eq!(
            params1.hop_pattern_seed, params2.hop_pattern_seed,
            "Hop pattern seed should be deterministic"
        );
    }

    #[test]
    fn test_derive_session_port_parameters_different_sessions() {
        // Different session IDs should produce different parameters
        let session_key = SessionKey::new([0x42; 32]);
        let session_id1 = SessionId::new(100);
        let session_id2 = SessionId::new(200);

        let params1 = derive_session_port_parameters(&session_key, &session_id1);
        let params2 = derive_session_port_parameters(&session_key, &session_id2);

        // At least one parameter should differ
        assert!(
            params1.base_port != params2.base_port
                || params1.port_seed != params2.port_seed
                || params1.hop_sequence_seed != params2.hop_sequence_seed
                || params1.hop_pattern_seed != params2.hop_pattern_seed,
            "Different session IDs should produce different parameters"
        );
    }

    #[test]
    fn test_derive_session_port_parameters_valid_port_range() {
        // Base port should always be in valid range 1024-65535
        let session_key = SessionKey::new([0x11; 32]);
        let session_id = SessionId::new(12345);

        let params = derive_session_port_parameters(&session_key, &session_id);

        assert!(
            params.base_port.as_u16() >= MIN_PORT,
            "Base port {} should be >= MIN_PORT {}",
            params.base_port.as_u16(),
            MIN_PORT
        );
        assert!(
            params.base_port.as_u16() <= MAX_PORT,
            "Base port {} should be <= MAX_PORT {}",
            params.base_port.as_u16(),
            MAX_PORT
        );
    }

    #[test]
    fn test_derive_session_port_parameters_hop_interval() {
        // Hop interval should always be 500ms per spec
        let session_key = SessionKey::new([0x22; 32]);
        let session_id = SessionId::new(67890);

        let params = derive_session_port_parameters(&session_key, &session_id);

        assert_eq!(
            params.hop_interval_ms, HOP_INTERVAL_MS,
            "Hop interval should be {} ms",
            HOP_INTERVAL_MS
        );
        assert_eq!(
            params.hop_interval_ms, 500,
            "Hop interval should be exactly 500ms"
        );
    }

    #[test]
    fn test_derive_session_port_parameters_time_variance() {
        // Time variance should be 0-99ms (chunk4 % 100)
        let session_key = SessionKey::new([0x33; 32]);
        let session_id = SessionId::new(11111);

        let params = derive_session_port_parameters(&session_key, &session_id);

        assert!(
            params.time_variance_ms < 100,
            "Time variance {} should be < 100ms",
            params.time_variance_ms
        );
    }

    #[test]
    fn test_derive_session_port_parameters_port_range() {
        // Port range should always be PORT_RANGE
        let session_key = SessionKey::new([0x44; 32]);
        let session_id = SessionId::new(22222);

        let params = derive_session_port_parameters(&session_key, &session_id);

        assert_eq!(
            params.port_range, PORT_RANGE,
            "Port range should be {} ports",
            PORT_RANGE
        );
        assert_eq!(
            params.port_range, 64512,
            "Port range should be exactly 64512 ports (65535-1024+1)"
        );
    }

    #[test]
    fn test_derive_session_port_parameters_different_keys() {
        // Different session keys should produce different parameters
        let session_key1 = SessionKey::new([0x55; 32]);
        let session_key2 = SessionKey::new([0x66; 32]);
        let session_id = SessionId::new(33333);

        let params1 = derive_session_port_parameters(&session_key1, &session_id);
        let params2 = derive_session_port_parameters(&session_key2, &session_id);

        // At least one parameter should differ
        assert!(
            params1.base_port != params2.base_port
                || params1.port_seed != params2.port_seed
                || params1.hop_sequence_seed != params2.hop_sequence_seed
                || params1.hop_pattern_seed != params2.hop_pattern_seed,
            "Different session keys should produce different parameters"
        );
    }

    #[test]
    fn test_port_parameters_constants() {
        // Verify constants match protocol specification
        assert_eq!(MIN_PORT, 1024, "MIN_PORT should be 1024");
        assert_eq!(MAX_PORT, 65535, "MAX_PORT should be 65535");
        assert_eq!(
            PORT_RANGE,
            MAX_PORT - MIN_PORT + 1,
            "PORT_RANGE should be MAX - MIN + 1"
        );
        assert_eq!(HOP_INTERVAL_MS, 500, "HOP_INTERVAL_MS should be 500ms");
        assert_eq!(
            PBKDF2_ITERATIONS_PORT, 2048,
            "PBKDF2_ITERATIONS_PORT should be 2048"
        );
    }

    #[test]
    fn test_port_parameters_new() {
        // Test PortParameters constructor
        let base_port = Port::from_u16_unchecked(5000);
        let params = PortParameters::new(base_port, 12345, 67890, 50, 111);

        assert_eq!(params.base_port, base_port);
        assert_eq!(params.port_seed, 12345);
        assert_eq!(params.hop_sequence_seed, 67890);
        assert_eq!(params.time_variance_ms, 50);
        assert_eq!(params.hop_pattern_seed, 111);
        assert_eq!(params.hop_interval_ms, HOP_INTERVAL_MS);
        assert_eq!(params.port_range, PORT_RANGE);
    }

    #[test]
    fn test_pbkdf2_uses_2048_iterations() {
        // Verify that PBKDF2 uses exactly 2048 iterations as per spec
        let session_key = SessionKey::new([0x77; 32]);
        let session_id = SessionId::new(44444);

        // Create salt same way as derive_session_port_parameters
        let mut salt_input = Vec::with_capacity(8 + 18);
        salt_input.extend_from_slice(&session_id.to_be_bytes());
        salt_input.extend_from_slice(b"port_derivation_v3");
        let salt = digest::digest(&digest::SHA256, &salt_input);

        // Test with 2048 iterations (should match our function)
        let mut port_material_2048 = [0u8; 12];
        let iterations_2048 = std::num::NonZeroU32::new(2048).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations_2048,
            salt.as_ref(),
            session_key.as_bytes(),
            &mut port_material_2048,
        );

        // Test with 4096 iterations (should be different)
        let mut port_material_4096 = [0u8; 12];
        let iterations_4096 = std::num::NonZeroU32::new(4096).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations_4096,
            salt.as_ref(),
            session_key.as_bytes(),
            &mut port_material_4096,
        );

        // Verify different iteration counts produce different outputs
        assert_ne!(
            port_material_2048, port_material_4096,
            "2048 and 4096 iterations should produce different outputs"
        );

        // Verify our function produces the 2048-iteration output
        let params = derive_session_port_parameters(&session_key, &session_id);
        let chunk0 = u16::from_be_bytes([port_material_2048[0], port_material_2048[1]]);
        let chunk1 = u16::from_be_bytes([port_material_2048[2], port_material_2048[3]]);
        let expected_port_seed = ((chunk0 as u32) << 16) | (chunk1 as u32);

        assert_eq!(
            params.port_seed, expected_port_seed,
            "Function should use 2048 iterations"
        );
    }

    #[test]
    fn test_multiple_different_sessions() {
        // Test that multiple different session IDs all produce valid parameters
        let session_key = SessionKey::new([0x88; 32]);

        for session_num in 0..10 {
            let session_id = SessionId::new(session_num * 1000);
            let params = derive_session_port_parameters(&session_key, &session_id);

            assert!(params.base_port.as_u16() >= MIN_PORT);
            assert!(params.base_port.as_u16() <= MAX_PORT);
            assert_eq!(params.hop_interval_ms, 500);
            assert!(params.time_variance_ms < 100);
        }
    }
}
