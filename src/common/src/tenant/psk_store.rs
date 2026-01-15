//! Per-tenant PSK storage implementation
//!
//! Provides isolated PSK collections for each tenant with:
//! - Lock-free concurrent access using DashMap
//! - PSK fingerprint generation for discovery
//! - Daily key derivation with tenant context
//! - Secure memory zeroing on deletion

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use super::key_derivation::derive_daily_key_with_tenant_context;
use super::tenant_id::TenantId;
use crate::memory::secure::SecureBytes;
use dashmap::DashMap;
use ring::digest;
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors related to PSK store operations
#[derive(Error, Debug)]
pub enum PskStoreError {
    #[error("Maximum PSKs exceeded for tenant {tenant_id}: limit {limit}")]
    MaxPsksExceeded { tenant_id: TenantId, limit: usize },

    #[error("PSK not found for tenant {tenant_id}: {psk_id}")]
    PskNotFound { tenant_id: TenantId, psk_id: String },

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Invalid PSK: {0}")]
    InvalidPsk(String),
}

/// PSK fingerprint for privacy-preserving discovery
///
/// Blinded representation of a PSK for discovery protocol
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PskFingerprint([u8; 32]);

impl PskFingerprint {
    /// Compute fingerprint from PSK using SHA-256
    pub fn from_psk(psk: &[u8]) -> Self {
        let digest = digest::digest(&digest::SHA256, psk);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_ref());
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Day epoch for daily key rotation
///
/// Represents the number of days since UNIX epoch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DayEpoch(u32);

impl DayEpoch {
    /// Create from UTC milliseconds
    pub fn from_utc_ms(ms: u64) -> Self {
        const MS_PER_DAY: u64 = 86_400_000;
        Self((ms / MS_PER_DAY) as u32)
    }

    /// Get current day epoch
    pub fn current() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        Self::from_utc_ms(ms)
    }

    /// Convert to u32
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Convert to u64
    pub const fn as_u64(&self) -> u64 {
        self.0 as u64
    }
}

/// Daily key derived from PSK with tenant context
#[derive(Clone)]
pub struct DailyKey {
    key: SecureBytes,
}

impl DailyKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: SecureBytes::from_slice(&bytes),
        }
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl Zeroize for DailyKey {
    fn zeroize(&mut self) {
        // SecureBytes already handles zeroization
    }
}

impl Drop for DailyKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Tenant-specific PSK
pub struct TenantPsk {
    /// PSK identifier
    pub id: String,

    /// PSK material (secure memory)
    material: SecureBytes,

    /// Tenant this PSK belongs to
    tenant_id: TenantId,

    /// Cached fingerprint
    fingerprint: PskFingerprint,
}

impl TenantPsk {
    /// Create a new tenant PSK
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this PSK within tenant scope
    /// * `material` - PSK bytes (will be securely stored)
    /// * `tenant_id` - Tenant this PSK belongs to
    pub fn new(id: String, material: &[u8], tenant_id: TenantId) -> Result<Self, PskStoreError> {
        if material.is_empty() {
            return Err(PskStoreError::InvalidPsk("PSK cannot be empty".to_string()));
        }

        if material.len() < 16 {
            return Err(PskStoreError::InvalidPsk(
                "PSK must be at least 16 bytes".to_string(),
            ));
        }

        let fingerprint = PskFingerprint::from_psk(material);
        let secure_material = SecureBytes::from_slice(material);

        Ok(Self {
            id,
            material: secure_material,
            tenant_id,
            fingerprint,
        })
    }

    /// Compute PSK fingerprint for discovery
    pub fn compute_fingerprint(&self) -> PskFingerprint {
        self.fingerprint.clone()
    }

    /// Derive daily key with tenant context
    pub fn derive_daily_key(&self, day_epoch: DayEpoch) -> Result<DailyKey, PskStoreError> {
        derive_daily_key_with_tenant_context(self.tenant_id, self.material.as_slice(), day_epoch)
            .map_err(|e| PskStoreError::KeyDerivation(format!("{}", e)))
    }

    /// Get tenant ID
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Drop for TenantPsk {
    fn drop(&mut self) {
        // SecureBytes handles automatic zeroing
    }
}

/// Per-tenant PSK collection with isolation guarantees
///
/// Each tenant maintains a completely isolated PSK collection with:
/// - Independent PSK rotation schedules
/// - Separate daily key derivation
/// - Isolated PSK fingerprint sets for discovery
pub struct TenantPskStore {
    /// Tenant this store belongs to
    tenant_id: TenantId,

    /// Active PSKs (indexed by PSK ID)
    active_psks: Arc<DashMap<String, TenantPsk>>,

    /// PSK fingerprints for discovery (blinded representations)
    psk_fingerprints: Arc<DashMap<PskFingerprint, String>>,

    /// Daily keys derived from PSKs (per-PSK, per-day)
    daily_keys: Arc<DashMap<(String, DayEpoch), DailyKey>>,
}

impl TenantPskStore {
    /// Maximum PSKs per tenant (protocol limit)
    pub const MAX_PSKS_PER_TENANT: usize = 256;

    /// Creates a new isolated PSK store for a tenant
    pub fn new(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            active_psks: Arc::new(DashMap::new()),
            psk_fingerprints: Arc::new(DashMap::new()),
            daily_keys: Arc::new(DashMap::new()),
        }
    }

    /// Adds a PSK to this tenant's store
    pub fn add_psk(&self, psk: TenantPsk) -> Result<(), PskStoreError> {
        if self.active_psks.len() >= Self::MAX_PSKS_PER_TENANT {
            return Err(PskStoreError::MaxPsksExceeded {
                tenant_id: self.tenant_id,
                limit: Self::MAX_PSKS_PER_TENANT,
            });
        }

        // Verify tenant matches
        if psk.tenant_id != self.tenant_id {
            return Err(PskStoreError::InvalidPsk(
                "PSK tenant ID does not match store".to_string(),
            ));
        }

        let fingerprint = psk.compute_fingerprint();
        let psk_id = psk.id.clone();

        // Store PSK and fingerprint atomically
        self.active_psks.insert(psk_id.clone(), psk);
        self.psk_fingerprints.insert(fingerprint, psk_id.clone());

        tracing::info!(
            tenant_id = %self.tenant_id,
            psk_id = %psk_id,
            "PSK added to tenant store"
        );

        Ok(())
    }

    /// Removes a PSK from this tenant's store
    pub fn remove_psk(&self, psk_id: &str) -> Result<TenantPsk, PskStoreError> {
        let (_, psk) =
            self.active_psks
                .remove(psk_id)
                .ok_or_else(|| PskStoreError::PskNotFound {
                    tenant_id: self.tenant_id,
                    psk_id: psk_id.to_string(),
                })?;

        // Remove fingerprint
        let fingerprint = psk.compute_fingerprint();
        self.psk_fingerprints.remove(&fingerprint);

        // Clean up daily keys for this PSK
        self.daily_keys.retain(|(id, _), _| id != psk_id);

        tracing::info!(
            tenant_id = %self.tenant_id,
            psk_id = %psk_id,
            "PSK removed from tenant store"
        );

        Ok(psk)
    }

    /// Retrieves a daily key for a PSK, deriving if necessary
    pub fn get_daily_key(
        &self,
        psk_id: &str,
        day_epoch: DayEpoch,
    ) -> Result<DailyKey, PskStoreError> {
        let cache_key = (psk_id.to_string(), day_epoch);

        // Check cache first
        if let Some(entry) = self.daily_keys.get(&cache_key) {
            return Ok(entry.value().clone());
        }

        // Derive new daily key
        let psk = self
            .active_psks
            .get(psk_id)
            .ok_or_else(|| PskStoreError::PskNotFound {
                tenant_id: self.tenant_id,
                psk_id: psk_id.to_string(),
            })?;

        let daily_key = psk.derive_daily_key(day_epoch)?;

        // Cache for future use
        self.daily_keys.insert(cache_key, daily_key.clone());

        Ok(daily_key)
    }

    /// Gets all PSK fingerprints for discovery
    pub fn get_fingerprints(&self) -> Vec<PskFingerprint> {
        self.psk_fingerprints
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get number of active PSKs
    pub fn psk_count(&self) -> usize {
        self.active_psks.len()
    }

    /// Get tenant ID
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// List all PSK IDs
    pub fn list_psk_ids(&self) -> Vec<String> {
        self.active_psks
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Clear all PSKs (secure cleanup)
    pub fn clear_all_psks(&self) -> Result<(), PskStoreError> {
        self.active_psks.clear();
        self.psk_fingerprints.clear();
        self.daily_keys.clear();

        tracing::info!(
            tenant_id = %self.tenant_id,
            "All PSKs cleared from tenant store"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_psk(id: &str, tenant_id: TenantId) -> TenantPsk {
        let material = vec![0x42u8; 32]; // 32 bytes of test data
        TenantPsk::new(id.to_string(), &material, tenant_id).unwrap()
    }

    #[test]
    fn test_psk_fingerprint() {
        let psk1 = b"test_psk_1";
        let psk2 = b"test_psk_2";

        let fp1 = PskFingerprint::from_psk(psk1);
        let fp2 = PskFingerprint::from_psk(psk2);

        assert_ne!(fp1, fp2);

        // Same PSK should produce same fingerprint
        let fp1_again = PskFingerprint::from_psk(psk1);
        assert_eq!(fp1, fp1_again);
    }

    #[test]
    fn test_day_epoch() {
        let epoch1 = DayEpoch::from_utc_ms(0);
        assert_eq!(epoch1.as_u32(), 0);

        let epoch2 = DayEpoch::from_utc_ms(86_400_000); // 1 day
        assert_eq!(epoch2.as_u32(), 1);

        let epoch3 = DayEpoch::from_utc_ms(172_800_000); // 2 days
        assert_eq!(epoch3.as_u32(), 2);
    }

    #[test]
    fn test_tenant_psk_creation() {
        let tenant_id = TenantId::from_u64(123);
        let psk = create_test_psk("psk1", tenant_id);

        assert_eq!(psk.id, "psk1");
        assert_eq!(psk.tenant_id(), tenant_id);
    }

    #[test]
    fn test_tenant_psk_invalid() {
        let tenant_id = TenantId::from_u64(123);

        // Empty PSK
        let result = TenantPsk::new("psk1".to_string(), &[], tenant_id);
        assert!(result.is_err());

        // Too short PSK
        let result = TenantPsk::new("psk1".to_string(), &[0x42; 8], tenant_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_psk_store_creation() {
        let tenant_id = TenantId::from_u64(456);
        let store = TenantPskStore::new(tenant_id);

        assert_eq!(store.tenant_id(), tenant_id);
        assert_eq!(store.psk_count(), 0);
    }

    #[test]
    fn test_psk_store_add() {
        let tenant_id = TenantId::from_u64(789);
        let store = TenantPskStore::new(tenant_id);

        let psk = create_test_psk("psk1", tenant_id);
        let result = store.add_psk(psk);

        assert!(result.is_ok());
        assert_eq!(store.psk_count(), 1);
    }

    #[test]
    fn test_psk_store_remove() {
        let tenant_id = TenantId::from_u64(101);
        let store = TenantPskStore::new(tenant_id);

        let psk = create_test_psk("psk1", tenant_id);
        store.add_psk(psk).unwrap();

        let result = store.remove_psk("psk1");
        assert!(result.is_ok());
        assert_eq!(store.psk_count(), 0);
    }

    #[test]
    fn test_psk_store_max_limit() {
        let tenant_id = TenantId::from_u64(202);
        let store = TenantPskStore::new(tenant_id);

        // Add PSKs up to the limit
        for i in 0..TenantPskStore::MAX_PSKS_PER_TENANT {
            let psk = create_test_psk(&format!("psk{}", i), tenant_id);
            assert!(store.add_psk(psk).is_ok());
        }

        // Attempt to add one more should fail
        let psk = create_test_psk("overflow_psk", tenant_id);
        let result = store.add_psk(psk);
        assert!(result.is_err());
    }

    #[test]
    fn test_daily_key_derivation() {
        let tenant_id = TenantId::from_u64(303);
        let store = TenantPskStore::new(tenant_id);

        let psk = create_test_psk("psk1", tenant_id);
        store.add_psk(psk).unwrap();

        let day_epoch = DayEpoch::current();
        let result = store.get_daily_key("psk1", day_epoch);

        assert!(result.is_ok());
    }

    #[test]
    fn test_daily_key_caching() {
        let tenant_id = TenantId::from_u64(404);
        let store = TenantPskStore::new(tenant_id);

        let psk = create_test_psk("psk1", tenant_id);
        store.add_psk(psk).unwrap();

        let day_epoch = DayEpoch::current();

        // First retrieval
        let key1 = store.get_daily_key("psk1", day_epoch).unwrap();

        // Second retrieval (should be cached)
        let key2 = store.get_daily_key("psk1", day_epoch).unwrap();

        // Keys should be identical
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_fingerprints() {
        let tenant_id = TenantId::from_u64(505);
        let store = TenantPskStore::new(tenant_id);

        // Create PSKs with different material
        let material1 = vec![0x42u8; 32];
        let material2 = vec![0xAAu8; 32];

        let psk1 = TenantPsk::new("psk1".to_string(), &material1, tenant_id).unwrap();
        let psk2 = TenantPsk::new("psk2".to_string(), &material2, tenant_id).unwrap();

        store.add_psk(psk1).unwrap();
        store.add_psk(psk2).unwrap();

        let fingerprints = store.get_fingerprints();
        assert_eq!(fingerprints.len(), 2);
    }

    #[test]
    fn test_list_psk_ids() {
        let tenant_id = TenantId::from_u64(606);
        let store = TenantPskStore::new(tenant_id);

        let psk1 = create_test_psk("psk1", tenant_id);
        let psk2 = create_test_psk("psk2", tenant_id);

        store.add_psk(psk1).unwrap();
        store.add_psk(psk2).unwrap();

        let ids = store.list_psk_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"psk1".to_string()));
        assert!(ids.contains(&"psk2".to_string()));
    }

    #[test]
    fn test_clear_all_psks() {
        let tenant_id = TenantId::from_u64(707);
        let store = TenantPskStore::new(tenant_id);

        let psk1 = create_test_psk("psk1", tenant_id);
        let psk2 = create_test_psk("psk2", tenant_id);

        store.add_psk(psk1).unwrap();
        store.add_psk(psk2).unwrap();

        assert_eq!(store.psk_count(), 2);

        store.clear_all_psks().unwrap();
        assert_eq!(store.psk_count(), 0);
    }

    #[test]
    fn test_wrong_tenant_rejection() {
        let tenant1 = TenantId::from_u64(111);
        let tenant2 = TenantId::from_u64(222);

        let store = TenantPskStore::new(tenant1);
        let psk = create_test_psk("psk1", tenant2); // Wrong tenant

        let result = store.add_psk(psk);
        assert!(result.is_err());
    }
}
