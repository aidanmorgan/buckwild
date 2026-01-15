#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// ECDH key exchange implementation
//
// This module provides ECDH key exchange functionality with key caching
// for the Buckwild frequency hopping network.
//
// Uses P-256 (NIST P-256 / secp256r1) elliptic curve for ECDH key agreement
// as specified in design/protocol/04-ecdh-cryptography.md

use crate::error::security::SecurityError;
use crate::protocol::types::UsageCount;
use crate::protocol::types::*;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration as StdDuration, Instant};
use zeroize::Zeroizing;

/// Result type for ECDH operations
pub type EcdhResult<T> = Result<T, SecurityError>;

/// ECDH key pair with expiration and reference counting
struct CachedKeyPair {
    /// Private key (stored as bytes, zeroized on drop)
    private_key_bytes: Zeroizing<[u8; 32]>,

    /// Public key
    public_key: EcdhPublicKey,

    /// Creation time
    created_at: Instant,

    /// Reference count for safe concurrent access
    ref_count: UsageCount,
}

/// ECDH shared secret with expiration and reference counting
struct CachedSharedSecret {
    /// Shared secret
    secret: SharedSecret,

    /// Creation time
    created_at: Instant,

    /// Reference count for safe concurrent access
    ref_count: UsageCount,
}

/// ECDH key cache
struct KeyCache {
    /// Key pairs indexed by a string identifier
    key_pairs: HashMap<String, CachedKeyPair>,

    /// Shared secrets indexed by a composite key of local and remote identifiers
    shared_secrets: HashMap<(String, EcdhPublicKey), CachedSharedSecret>,

    /// Key expiration time
    expiration: StdDuration,
}

impl KeyCache {
    /// Create a new key cache with the specified expiration time
    fn new(expiration: StdDuration) -> Self {
        Self {
            key_pairs: HashMap::new(),
            shared_secrets: HashMap::new(),
            expiration,
        }
    }

    /// Clean expired keys
    fn clean_expired(&mut self) {
        let now = Instant::now();

        // Clean expired key pairs
        self.key_pairs
            .retain(|_, pair| now.duration_since(pair.created_at) < self.expiration);

        // Clean expired shared secrets
        self.shared_secrets
            .retain(|_, secret| now.duration_since(secret.created_at) < self.expiration);
    }
}

/// ECDH key exchange manager
pub struct EcdhManager {
    /// Key cache
    cache: Arc<RwLock<KeyCache>>,
}

impl EcdhManager {
    /// Create a new ECDH manager with the specified key expiration time
    pub fn new(expiration_minutes: u64) -> Self {
        let expiration = std::time::Duration::from_secs(expiration_minutes * 60);

        Self {
            cache: Arc::new(RwLock::new(KeyCache::new(expiration))),
        }
    }

    /// Generate a new key pair or return a cached one
    pub fn get_key_pair(&self, id: &str) -> EcdhResult<EcdhPublicKey> {
        // Try to get from cache first
        {
            let cache = self.cache.read().map_err(|_| {
                SecurityError::internal_error("Failed to acquire read lock on key cache")
            })?;

            if let Some(pair) = cache.key_pairs.get(id) {
                let now = Instant::now();
                if now.duration_since(pair.created_at) < cache.expiration {
                    pair.ref_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(pair.public_key);
                }
            }
        }

        // Generate a new secret key using p256
        // Uses OsRng for cryptographically secure random generation
        let secret_key = P256SecretKey::random(&mut OsRng);

        // Derive public key from private key
        let public_key_p256 = secret_key.public_key();

        // Convert to uncompressed bytes (0x04 || x || y = 65 bytes)
        let encoded_point = public_key_p256.to_encoded_point(false);
        let public_key_bytes = encoded_point.as_bytes();

        // Remove the 0x04 prefix to get just the x and y coordinates (64 bytes)
        if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
            return Err(SecurityError::ecdh_key_exchange_failed(
                "Invalid public key encoding".to_string(),
            ));
        }

        let mut key_array = [0u8; 64];
        key_array.copy_from_slice(&public_key_bytes[1..]); // Skip 0x04 prefix
        let ecdh_public_key = EcdhPublicKey::new(key_array);

        // Extract private key bytes (32 bytes)
        let private_key_bytes = secret_key.to_bytes();
        let mut private_array = [0u8; 32];
        private_array.copy_from_slice(&private_key_bytes[..]);

        // Cache the key pair with zeroizing private key
        {
            let mut cache = self.cache.write().map_err(|_| {
                SecurityError::internal_error("Failed to acquire write lock on key cache")
            })?;

            // Clean expired keys
            cache.clean_expired();

            // Store the new key pair
            cache.key_pairs.insert(
                id.to_string(),
                CachedKeyPair {
                    private_key_bytes: Zeroizing::new(private_array),
                    public_key: ecdh_public_key,
                    created_at: Instant::now(),
                    ref_count: UsageCount::new(1),
                },
            );
        }

        Ok(ecdh_public_key)
    }

    /// Compute shared secret from a remote public key
    /// Uses the stored private key from get_key_pair() to perform ECDH with remote public key
    pub fn compute_shared_secret(
        &self,
        local_id: &str,
        remote_public_key: &EcdhPublicKey,
    ) -> EcdhResult<SharedSecret> {
        // Try to get from cache first
        {
            let cache = self.cache.read().map_err(|_| {
                SecurityError::internal_error("Failed to acquire read lock on key cache")
            })?;

            let cache_key = (local_id.to_string(), *remote_public_key);
            if let Some(secret) = cache.shared_secrets.get(&cache_key) {
                let now = Instant::now();
                if now.duration_since(secret.created_at) < cache.expiration {
                    secret
                        .ref_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(secret.secret.clone());
                }
            }
        }

        // Retrieve the stored private key for this ID
        let private_key_bytes: [u8; 32] = {
            let cache = self.cache.read().map_err(|_| {
                SecurityError::internal_error("Failed to acquire read lock on key cache")
            })?;

            let pair = cache.key_pairs.get(local_id).ok_or_else(|| {
                SecurityError::ecdh_key_exchange_failed(format!(
                    "No private key found for ID: {}",
                    local_id
                ))
            })?;

            // Copy the bytes from Zeroizing
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(pair.private_key_bytes.as_ref());
            bytes
        };

        // Reconstruct the secret key from stored bytes
        let secret_key = P256SecretKey::from_bytes((&private_key_bytes).into()).map_err(|e| {
            SecurityError::ecdh_key_exchange_failed(format!(
                "Failed to reconstruct private key: {:?}",
                e
            ))
        })?;

        // Reconstruct the remote public key from 64 bytes (add 0x04 prefix)
        let mut full_public_key = vec![0x04];
        full_public_key.extend_from_slice(remote_public_key.as_bytes());

        let encoded_point = EncodedPoint::from_bytes(&full_public_key).map_err(|e| {
            SecurityError::ecdh_key_exchange_failed(format!(
                "Invalid remote public key encoding: {:?}",
                e
            ))
        })?;

        let peer_public_key_opt = P256PublicKey::from_encoded_point(&encoded_point);
        let peer_public_key = peer_public_key_opt.into_option().ok_or_else(|| {
            SecurityError::ecdh_key_exchange_failed(
                "Failed to decode remote public key".to_string(),
            )
        })?;

        // Perform ECDH key agreement using our stored secret key
        let p256_shared_secret =
            p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_public_key.as_affine());

        // Convert to our SharedSecret type
        let secret_bytes = p256_shared_secret.raw_secret_bytes();
        if secret_bytes.len() != 32 {
            return Err(SecurityError::ecdh_key_exchange_failed(
                "Invalid shared secret length".to_string(),
            ));
        }

        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&secret_bytes[..]);
        let shared_secret = SharedSecret::new(secret_array);

        // Cache the shared secret
        {
            let mut cache = self.cache.write().map_err(|_| {
                SecurityError::internal_error("Failed to acquire write lock on key cache")
            })?;

            // Clean expired secrets
            cache.clean_expired();

            let cache_key = (local_id.to_string(), *remote_public_key);
            cache.shared_secrets.insert(
                cache_key,
                CachedSharedSecret {
                    secret: shared_secret.clone(),
                    created_at: Instant::now(),
                    ref_count: UsageCount::new(1),
                },
            );
        }

        Ok(shared_secret)
    }

    /// Rotate all keys in the cache
    pub fn rotate_keys(&self) -> EcdhResult<()> {
        let mut cache = self.cache.write().map_err(|_| {
            SecurityError::internal_error("Failed to acquire write lock on key cache")
        })?;

        // Clear all cached keys
        cache.key_pairs.clear();
        cache.shared_secrets.clear();

        Ok(())
    }

    /// Serialize a public key for network transmission (returns 64 bytes: x || y)
    pub fn serialize_public_key(public_key: &EcdhPublicKey) -> Vec<u8> {
        public_key.as_bytes().to_vec()
    }

    /// Deserialize a public key from network transmission (expects 64 bytes: x || y)
    pub fn deserialize_public_key(data: &[u8]) -> EcdhResult<EcdhPublicKey> {
        if data.len() != 64 {
            return Err(SecurityError::ecdh_key_exchange_failed(
                "Invalid public key length".to_string(),
            ));
        }

        // Add 0x04 prefix for uncompressed point validation
        let mut full_key = vec![0x04];
        full_key.extend_from_slice(data);

        // Validate it's a valid P-256 public key
        let encoded_point = EncodedPoint::from_bytes(&full_key).map_err(|e| {
            SecurityError::ecdh_key_exchange_failed(format!("Invalid public key encoding: {:?}", e))
        })?;

        let public_key_opt = P256PublicKey::from_encoded_point(&encoded_point);
        if !bool::from(public_key_opt.is_some()) {
            return Err(SecurityError::ecdh_key_exchange_failed(
                "Invalid P-256 public key".to_string(),
            ));
        }

        // If validation passed, create EcdhPublicKey
        let mut key_array = [0u8; 64];
        key_array.copy_from_slice(data);
        Ok(EcdhPublicKey::new(key_array))
    }
}

/// Thread-safe ECDH manager
pub struct ThreadSafeEcdhManager {
    /// Inner ECDH manager
    inner: Arc<Mutex<EcdhManager>>,
}

impl ThreadSafeEcdhManager {
    /// Create a new thread-safe ECDH manager
    pub fn new(expiration_minutes: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(EcdhManager::new(expiration_minutes))),
        }
    }

    /// Generate a new key pair or return a cached one
    pub fn get_key_pair(&self, id: &str) -> EcdhResult<EcdhPublicKey> {
        let manager = self
            .inner
            .lock()
            .map_err(|_| SecurityError::internal_error("Failed to acquire lock on ECDH manager"))?;

        manager.get_key_pair(id)
    }

    /// Compute shared secret from a remote public key
    pub fn compute_shared_secret(
        &self,
        local_id: &str,
        remote_public_key: &EcdhPublicKey,
    ) -> EcdhResult<SharedSecret> {
        let manager = self
            .inner
            .lock()
            .map_err(|_| SecurityError::internal_error("Failed to acquire lock on ECDH manager"))?;

        manager.compute_shared_secret(local_id, remote_public_key)
    }

    /// Rotate all keys in the cache
    pub fn rotate_keys(&self) -> EcdhResult<()> {
        let manager = self
            .inner
            .lock()
            .map_err(|_| SecurityError::internal_error("Failed to acquire lock on ECDH manager"))?;

        manager.rotate_keys()
    }
}

/// Create a default ECDH manager with 10-minute key caching
pub fn create_default_ecdh_manager() -> ThreadSafeEcdhManager {
    ThreadSafeEcdhManager::new(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_key_generation() {
        let manager = EcdhManager::new(10);
        let result = manager.get_key_pair("test_id");

        assert!(result.is_ok());
        let public_key = result.unwrap();
        assert_eq!(public_key.as_bytes().len(), 64); // P-256 public key is 64 bytes
    }

    #[test]
    fn test_ecdh_key_agreement() {
        let manager1 = EcdhManager::new(10);
        let manager2 = EcdhManager::new(10);

        // Generate key pairs for both parties
        let pub1 = manager1.get_key_pair("alice").unwrap();
        let pub2 = manager2.get_key_pair("bob").unwrap();

        // Perform key agreement
        let secret1 = manager1.compute_shared_secret("alice", &pub2).unwrap();
        let secret2 = manager2.compute_shared_secret("bob", &pub1).unwrap();

        // Both should derive the same shared secret
        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_ecdh_public_key_serialization() {
        let manager = EcdhManager::new(10);
        let public_key = manager.get_key_pair("test").unwrap();

        let serialized = EcdhManager::serialize_public_key(&public_key);
        let deserialized = EcdhManager::deserialize_public_key(&serialized).unwrap();

        assert_eq!(public_key.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_ecdh_key_caching() {
        let manager = EcdhManager::new(10);

        // Generate same key twice
        let pub1 = manager.get_key_pair("cached_id").unwrap();
        let pub2 = manager.get_key_pair("cached_id").unwrap();

        // Should return the same cached key
        assert_eq!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn test_ecdh_key_rotation() {
        let manager = EcdhManager::new(10);

        let pub1 = manager.get_key_pair("rotate_test").unwrap();
        manager.rotate_keys().unwrap();
        let pub2 = manager.get_key_pair("rotate_test").unwrap();

        // After rotation, should generate a new key
        assert_ne!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn test_thread_safe_ecdh_manager() {
        let manager = ThreadSafeEcdhManager::new(10);

        let pub1 = manager.get_key_pair("thread_safe_test").unwrap();
        let pub2 = manager.get_key_pair("thread_safe_test").unwrap();

        // Should use cached key
        assert_eq!(pub1.as_bytes(), pub2.as_bytes());
    }
}
