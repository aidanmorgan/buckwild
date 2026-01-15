//! Tenant-aware key derivation functions
//!
//! Incorporates tenant context into all key derivation to ensure
//! cryptographic isolation between tenants.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use super::psk_store::{DailyKey, DayEpoch};
use super::tenant_id::TenantId;
use crate::error::security::SecurityError;
use ring::hkdf;
use ring::pbkdf2;
use std::num::NonZeroU32;

/// PBKDF2 iterations for session key derivation
const PBKDF2_ITERATIONS_SESSION: u32 = 4096;

/// Session key material derived from ECDH shared secret with tenant context
pub struct SessionKeyMaterial {
    /// HMAC key (256 bits)
    pub hmac_key: [u8; 32],

    /// Client initial sequence number
    pub client_seq: u32,

    /// Server initial sequence number
    pub server_seq: u32,

    /// Client port offset
    pub client_port_offset: u16,

    /// Server port offset
    pub server_port_offset: u16,

    /// Port hopping seed
    pub port_hopping_seed: u32,
}

impl SessionKeyMaterial {
    /// Extract session parameters from PBKDF2 output
    ///
    /// Layout of 128-byte derived material:
    /// - Bytes 0-3: Client sequence number (big-endian)
    /// - Bytes 4-7: Server sequence number (big-endian)
    /// - Bytes 8-9: Client port offset (big-endian)
    /// - Bytes 10-11: Server port offset (big-endian)
    /// - Bytes 12-43: HMAC key (256 bits)
    /// - Bytes 44-47: Port hopping seed (big-endian)
    /// - Bytes 48-127: Reserved
    pub fn from_pbkdf2_output(output: &[u8; 128]) -> Self {
        let mut hmac_key = [0u8; 32];
        hmac_key.copy_from_slice(&output[12..44]);

        Self {
            client_seq: u32::from_be_bytes([output[0], output[1], output[2], output[3]]),
            server_seq: u32::from_be_bytes([output[4], output[5], output[6], output[7]]),
            client_port_offset: u16::from_be_bytes([output[8], output[9]]),
            server_port_offset: u16::from_be_bytes([output[10], output[11]]),
            hmac_key,
            port_hopping_seed: u32::from_be_bytes([output[44], output[45], output[46], output[47]]),
        }
    }
}

/// Tenant-aware key derivation function for session establishment
///
/// Incorporates tenant context into all key derivation to ensure
/// cryptographic isolation between tenants.
///
/// # Arguments
///
/// * `tenant_id` - Tenant identifier for cryptographic binding
/// * `ecdh_shared_secret` - Shared secret from ECDH key exchange
/// * `client_public_key` - Client's ephemeral public key
/// * `server_public_key` - Server's ephemeral public key
/// * `key_exchange_id` - Unique identifier for this key exchange
///
/// # Returns
///
/// Session key material including HMAC key, sequence numbers, and port parameters
pub fn derive_session_keys_with_tenant_context(
    tenant_id: TenantId,
    ecdh_shared_secret: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
    key_exchange_id: u16,
) -> Result<SessionKeyMaterial, SecurityError> {
    // Construct tenant-aware salt
    // Format: tenant_id (8 bytes) || client_pubkey || server_pubkey || key_exchange_id (2 bytes)
    let mut salt = Vec::with_capacity(8 + client_public_key.len() + server_public_key.len() + 2);
    salt.extend_from_slice(&tenant_id.as_u64().to_be_bytes());
    salt.extend_from_slice(client_public_key);
    salt.extend_from_slice(server_public_key);
    salt.extend_from_slice(&key_exchange_id.to_be_bytes());

    // PBKDF2 derivation with tenant context
    let mut key_material = [0u8; 128];
    let iterations = NonZeroU32::new(PBKDF2_ITERATIONS_SESSION)
        .ok_or_else(|| SecurityError::key_derivation_failed("Invalid iteration count"))?;

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        ecdh_shared_secret,
        &mut key_material,
    );

    // Extract session parameters from derived material
    Ok(SessionKeyMaterial::from_pbkdf2_output(&key_material))
}

/// HKDF parameters for key type
struct HkdfKeyType(usize);

impl hkdf::KeyType for HkdfKeyType {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive daily key with tenant isolation
///
/// Uses HKDF-SHA256 with tenant context in the info string to ensure
/// that the same PSK produces different daily keys for different tenants.
///
/// # Arguments
///
/// * `tenant_id` - Tenant identifier for cryptographic binding
/// * `psk` - Pre-shared key material
/// * `day_epoch` - Day epoch for daily rotation
///
/// # Returns
///
/// Daily key for this tenant, PSK, and day
pub fn derive_daily_key_with_tenant_context(
    tenant_id: TenantId,
    psk: &[u8],
    day_epoch: DayEpoch,
) -> Result<DailyKey, SecurityError> {
    // Construct tenant-aware info string
    let info = format!(
        "tenant:{:016x}:daily_key:day:{}",
        tenant_id.as_u64(),
        day_epoch.as_u64()
    );

    // HKDF derivation with tenant context
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(psk);

    let mut daily_key = [0u8; 32]; // 256 bits

    let info_bytes = info.as_bytes();
    let info_slice = [info_bytes];
    let okm = prk
        .expand(&info_slice, HkdfKeyType(32))
        .map_err(|_| SecurityError::key_derivation_failed("Hkdf expand failed"))?;

    okm.fill(&mut daily_key)
        .map_err(|_| SecurityError::key_derivation_failed("Hkdf fill failed"))?;

    Ok(DailyKey::from_bytes(daily_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_derivation() {
        let tenant_id = TenantId::from_u64(123);
        let ecdh_secret = vec![0x42; 32];
        let client_pk = vec![0x01; 32];
        let server_pk = vec![0x02; 32];
        let key_exchange_id = 1;

        let result = derive_session_keys_with_tenant_context(
            tenant_id,
            &ecdh_secret,
            &client_pk,
            &server_pk,
            key_exchange_id,
        );

        assert!(result.is_ok());

        let material = result.unwrap();
        assert_eq!(material.hmac_key.len(), 32);
    }

    #[test]
    fn test_session_key_determinism() {
        let tenant_id = TenantId::from_u64(456);
        let ecdh_secret = vec![0xAB; 32];
        let client_pk = vec![0x03; 32];
        let server_pk = vec![0x04; 32];
        let key_exchange_id = 2;

        let material1 = derive_session_keys_with_tenant_context(
            tenant_id,
            &ecdh_secret,
            &client_pk,
            &server_pk,
            key_exchange_id,
        )
        .unwrap();

        let material2 = derive_session_keys_with_tenant_context(
            tenant_id,
            &ecdh_secret,
            &client_pk,
            &server_pk,
            key_exchange_id,
        )
        .unwrap();

        // Same inputs should produce same outputs
        assert_eq!(material1.hmac_key, material2.hmac_key);
        assert_eq!(material1.client_seq, material2.client_seq);
        assert_eq!(material1.server_seq, material2.server_seq);
        assert_eq!(material1.port_hopping_seed, material2.port_hopping_seed);
    }

    #[test]
    fn test_session_key_tenant_isolation() {
        let tenant1 = TenantId::from_u64(111);
        let tenant2 = TenantId::from_u64(222);
        let ecdh_secret = vec![0xCD; 32];
        let client_pk = vec![0x05; 32];
        let server_pk = vec![0x06; 32];
        let key_exchange_id = 3;

        let material1 = derive_session_keys_with_tenant_context(
            tenant1,
            &ecdh_secret,
            &client_pk,
            &server_pk,
            key_exchange_id,
        )
        .unwrap();

        let material2 = derive_session_keys_with_tenant_context(
            tenant2,
            &ecdh_secret,
            &client_pk,
            &server_pk,
            key_exchange_id,
        )
        .unwrap();

        // Different tenants should produce different keys
        assert_ne!(material1.hmac_key, material2.hmac_key);
        assert_ne!(material1.client_seq, material2.client_seq);
        assert_ne!(material1.server_seq, material2.server_seq);
    }

    #[test]
    fn test_daily_key_derivation() {
        let tenant_id = TenantId::from_u64(789);
        let psk = vec![0xEF; 32];
        let day_epoch = DayEpoch::from_utc_ms(86_400_000); // Day 1

        let result = derive_daily_key_with_tenant_context(tenant_id, &psk, day_epoch);

        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_daily_key_determinism() {
        let tenant_id = TenantId::from_u64(321);
        let psk = vec![0x12; 32];
        let day_epoch = DayEpoch::from_utc_ms(172_800_000); // Day 2

        let key1 = derive_daily_key_with_tenant_context(tenant_id, &psk, day_epoch).unwrap();
        let key2 = derive_daily_key_with_tenant_context(tenant_id, &psk, day_epoch).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_daily_key_tenant_isolation() {
        let tenant1 = TenantId::from_u64(555);
        let tenant2 = TenantId::from_u64(666);
        let psk = vec![0x34; 32];
        let day_epoch = DayEpoch::from_utc_ms(259_200_000); // Day 3

        let key1 = derive_daily_key_with_tenant_context(tenant1, &psk, day_epoch).unwrap();
        let key2 = derive_daily_key_with_tenant_context(tenant2, &psk, day_epoch).unwrap();

        // Different tenants should produce different daily keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_daily_key_day_isolation() {
        let tenant_id = TenantId::from_u64(777);
        let psk = vec![0x56; 32];
        let day1 = DayEpoch::from_utc_ms(86_400_000);
        let day2 = DayEpoch::from_utc_ms(172_800_000);

        let key1 = derive_daily_key_with_tenant_context(tenant_id, &psk, day1).unwrap();
        let key2 = derive_daily_key_with_tenant_context(tenant_id, &psk, day2).unwrap();

        // Different days should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_session_material_extraction() {
        let mut output = [0u8; 128];

        // Set known values
        output[0..4].copy_from_slice(&0x12345678u32.to_be_bytes());
        output[4..8].copy_from_slice(&0x9ABCDEF0u32.to_be_bytes());
        output[8..10].copy_from_slice(&0x1234u16.to_be_bytes());
        output[10..12].copy_from_slice(&0x5678u16.to_be_bytes());

        let hmac_test = [0xAAu8; 32];
        output[12..44].copy_from_slice(&hmac_test);

        output[44..48].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());

        let material = SessionKeyMaterial::from_pbkdf2_output(&output);

        assert_eq!(material.client_seq, 0x12345678);
        assert_eq!(material.server_seq, 0x9ABCDEF0);
        assert_eq!(material.client_port_offset, 0x1234);
        assert_eq!(material.server_port_offset, 0x5678);
        assert_eq!(material.hmac_key, hmac_test);
        assert_eq!(material.port_hopping_seed, 0xDEADBEEF);
    }
}
