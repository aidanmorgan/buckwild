#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Key management with secure lifecycle
//
// This module provides secure key management with automatic cleanup,
// key rotation, and lifecycle management for the Buckwild protocol.

use crate::error::SecurityError;
use crate::memory::secure::SecureBytes;
use crate::protocol::types::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

/// Result type for key management operations
pub type KeyResult<T> = Result<T, SecurityError>;

/// Key lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Key is active and can be used
    Active,

    /// Key is scheduled for rotation
    Rotating,

    /// Key is expired and should not be used
    Expired,

    /// Key has been revoked
    Revoked,
}

/// Key metadata
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// Key identifier
    pub id: String,

    /// Creation time
    pub created_at: SystemTime,

    /// Last used time
    pub last_used: SystemTime,

    /// Expiration time
    pub expires_at: SystemTime,

    /// Current state
    pub state: KeyState,

    /// Usage count
    pub usage_count: UsageCount,

    /// Maximum usage count
    pub max_usage: Option<UsageCount>,
}

impl KeyMetadata {
    /// Create new key metadata
    pub fn new(id: String, lifetime: Duration) -> Self {
        let now = SystemTime::now();

        Self {
            id,
            created_at: now,
            last_used: now,
            expires_at: now + std::time::Duration::from_nanos(lifetime.as_nanos() as u64),
            state: KeyState::Active,
            usage_count: UsageCount::new(0),
            max_usage: None,
        }
    }

    /// Check if the key is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at || self.state == KeyState::Expired
    }

    /// Check if the key is revoked
    pub fn is_revoked(&self) -> bool {
        self.state == KeyState::Revoked
    }

    /// Check if the key is usable
    pub fn is_usable(&self) -> bool {
        self.state == KeyState::Active && !self.is_expired() && !self.is_revoked()
    }

    /// Update usage statistics
    pub fn update_usage(&mut self) {
        self.last_used = SystemTime::now();
        self.usage_count =
            UsageCount::new(self.usage_count.load(std::sync::atomic::Ordering::Relaxed) + 1);
    }

    /// Check if usage limit is exceeded
    pub fn is_usage_exceeded(&self) -> bool {
        use std::sync::atomic::Ordering;
        if let Some(max) = &self.max_usage {
            self.usage_count.load(Ordering::Relaxed) >= max.load(Ordering::Relaxed)
        } else {
            false
        }
    }
}

/// Secure key storage
pub struct SecureKey {
    /// Key material
    material: SecureBytes,

    /// Key metadata
    metadata: KeyMetadata,
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(id: String, material: SecureBytes, lifetime: Duration) -> Self {
        Self {
            material,
            metadata: KeyMetadata::new(id, lifetime),
        }
    }

    /// Get key material (updates usage statistics)
    pub fn get_material(&mut self) -> KeyResult<&[u8]> {
        if !self.metadata.is_usable() {
            return Err(SecurityError::invalid_key("Key is not usable"));
        }

        if self.metadata.is_usage_exceeded() {
            return Err(SecurityError::invalid_key("Key usage limit exceeded"));
        }

        self.metadata.update_usage();
        Ok(self.material.as_slice())
    }

    /// Get key metadata
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }

    /// Revoke the key
    pub fn revoke(&mut self) {
        self.metadata.state = KeyState::Revoked;
    }

    /// Mark key for rotation
    pub fn mark_for_rotation(&mut self) {
        self.metadata.state = KeyState::Rotating;
    }
}

/// Key manager for secure key lifecycle management
pub struct KeyManager {
    /// Stored keys
    keys: RwLock<HashMap<String, SecureKey>>,

    /// Session keys
    session_keys: RwLock<HashMap<SessionId, SecureKey>>,

    /// Random number generator
    rng: Mutex<SystemRandom>,

    /// Default key lifetime
    default_lifetime: Duration,

    /// Cleanup interval
    cleanup_interval: Duration,

    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new(default_lifetime: Duration, cleanup_interval: Duration) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            session_keys: RwLock::new(HashMap::new()),
            rng: Mutex::new(SystemRandom::new()),
            default_lifetime,
            cleanup_interval,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Create a key manager with default settings
    pub fn new_default() -> Self {
        Self::new(
            Duration::from_secs(3600), // 1 hour default lifetime
            Duration::from_secs(300),  // 5 minute cleanup interval
        )
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new_default()
    }
}

impl KeyManager {
    /// Generate a new key
    pub fn generate_key(&self, id: String, size: usize) -> KeyResult<()> {
        let mut key_material = SecureBytes::with_size(size);

        // Generate random key material
        {
            let rng = self
                .rng
                .lock()
                .map_err(|_| SecurityError::internal_error("Failed to acquire RNG lock"))?;

            rng.fill(key_material.as_mut_slice()).map_err(|e| {
                SecurityError::key_generation_failed(format!(
                    "Failed to generate random key: {:?}",
                    e
                ))
            })?;
        }

        let secure_key = SecureKey::new(id.clone(), key_material.clone(), self.default_lifetime);

        // Store the key
        {
            let mut keys = self
                .keys
                .write()
                .map_err(|_| SecurityError::internal_error("Failed to acquire keys write lock"))?;

            keys.insert(id, secure_key);
        }

        Ok(())
    }

    /// Store a key
    pub fn store_key(&self, id: String, material: SecureBytes) -> KeyResult<()> {
        let secure_key = SecureKey::new(id.clone(), material, self.default_lifetime);

        {
            let mut keys = self
                .keys
                .write()
                .map_err(|_| SecurityError::internal_error("Failed to acquire keys write lock"))?;

            keys.insert(id, secure_key);
        }

        Ok(())
    }

    /// Get a key
    /// Returns key material wrapped in Zeroizing to ensure it is zeroed on drop
    pub fn get_key(&self, id: &str) -> KeyResult<Zeroizing<Vec<u8>>> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire keys write lock"))?;

        if let Some(key) = keys.get_mut(id) {
            let material = key.get_material()?;
            Ok(Zeroizing::new(material.to_vec()))
        } else {
            Err(SecurityError::invalid_key("Key not found"))
        }
    }

    /// Store a session key
    pub fn store_session_key(&self, session_id: SessionId, material: SecureBytes) -> KeyResult<()> {
        let key_id = format!("session_{}", session_id);
        let secure_key = SecureKey::new(key_id, material, self.default_lifetime);

        {
            let mut session_keys = self.session_keys.write().map_err(|_| {
                SecurityError::internal_error("Failed to acquire session keys write lock")
            })?;

            session_keys.insert(session_id, secure_key);
        }

        Ok(())
    }

    /// Get a session key
    /// Returns key material wrapped in Zeroizing to ensure it is zeroed on drop
    pub fn get_session_key(&self, session_id: &SessionId) -> KeyResult<Zeroizing<Vec<u8>>> {
        let mut session_keys = self.session_keys.write().map_err(|_| {
            SecurityError::internal_error("Failed to acquire session keys write lock")
        })?;

        if let Some(key) = session_keys.get_mut(session_id) {
            let material = key.get_material()?;
            Ok(Zeroizing::new(material.to_vec()))
        } else {
            Err(SecurityError::invalid_key("Session key not found"))
        }
    }

    /// Revoke a key
    pub fn revoke_key(&self, id: &str) -> KeyResult<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire keys write lock"))?;

        if let Some(key) = keys.get_mut(id) {
            key.revoke();
            Ok(())
        } else {
            Err(SecurityError::invalid_key("Key not found"))
        }
    }

    /// Revoke a session key
    pub fn revoke_session_key(&self, session_id: &SessionId) -> KeyResult<()> {
        let mut session_keys = self.session_keys.write().map_err(|_| {
            SecurityError::internal_error("Failed to acquire session keys write lock")
        })?;

        if let Some(key) = session_keys.get_mut(session_id) {
            key.revoke();
            Ok(())
        } else {
            Err(SecurityError::invalid_key("Session key not found"))
        }
    }

    /// Rotate a key
    pub fn rotate_key(&self, id: &str, new_material: SecureBytes) -> KeyResult<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| SecurityError::internal_error("Failed to acquire keys write lock"))?;

        // Mark old key for rotation
        if let Some(old_key) = keys.get_mut(id) {
            old_key.mark_for_rotation();
        }

        // Store new key
        let new_key = SecureKey::new(id.to_string(), new_material, self.default_lifetime);
        keys.insert(id.to_string(), new_key);

        Ok(())
    }

    /// Clean up expired keys
    pub fn cleanup_expired_keys(&self) -> KeyResult<usize> {
        let now = Instant::now();

        // Check if cleanup is needed
        {
            let last_cleanup = self.last_cleanup.read().map_err(|_| {
                SecurityError::internal_error("Failed to acquire cleanup time read lock")
            })?;

            if now.duration_since(*last_cleanup)
                < std::time::Duration::from_nanos(self.cleanup_interval.as_nanos() as u64)
            {
                return Ok(0);
            }
        }

        let mut cleaned_count = 0;

        // Clean up regular keys
        {
            let mut keys = self
                .keys
                .write()
                .map_err(|_| SecurityError::internal_error("Failed to acquire keys write lock"))?;

            keys.retain(|_, key| {
                if key.metadata().is_expired() || key.metadata().is_revoked() {
                    cleaned_count += 1;
                    false
                } else {
                    true
                }
            });
        }

        // Clean up session keys
        {
            let mut session_keys = self.session_keys.write().map_err(|_| {
                SecurityError::internal_error("Failed to acquire session keys write lock")
            })?;

            session_keys.retain(|_, key| {
                if key.metadata().is_expired() || key.metadata().is_revoked() {
                    cleaned_count += 1;
                    false
                } else {
                    true
                }
            });
        }

        // Update last cleanup time
        {
            let mut last_cleanup = self.last_cleanup.write().map_err(|_| {
                SecurityError::internal_error("Failed to acquire cleanup time write lock")
            })?;

            *last_cleanup = now;
        }

        Ok(cleaned_count)
    }

    /// Get key statistics
    pub fn get_key_stats(&self) -> KeyResult<(usize, usize, usize, usize)> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire keys read lock"))?;

        let session_keys = self.session_keys.read().map_err(|_| {
            SecurityError::internal_error("Failed to acquire session keys read lock")
        })?;

        let total_keys = keys.len();
        let total_session_keys = session_keys.len();

        let expired_keys = keys.values().filter(|k| k.metadata().is_expired()).count();
        let revoked_keys = keys.values().filter(|k| k.metadata().is_revoked()).count();

        Ok((total_keys, total_session_keys, expired_keys, revoked_keys))
    }

    /// List all key IDs
    pub fn list_keys(&self) -> KeyResult<Vec<String>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire keys read lock"))?;

        Ok(keys.keys().cloned().collect())
    }

    /// Get key metadata
    pub fn get_key_metadata(&self, id: &str) -> KeyResult<KeyMetadata> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SecurityError::internal_error("Failed to acquire keys read lock"))?;

        if let Some(key) = keys.get(id) {
            Ok(key.metadata().clone())
        } else {
            Err(SecurityError::invalid_key("Key not found"))
        }
    }
}

/// Thread-safe key manager
pub struct ThreadSafeKeyManager {
    /// Inner key manager
    inner: Arc<KeyManager>,
}

impl ThreadSafeKeyManager {
    /// Create a new thread-safe key manager
    pub fn new(default_lifetime: Duration, cleanup_interval: Duration) -> Self {
        Self {
            inner: Arc::new(KeyManager::new(default_lifetime, cleanup_interval)),
        }
    }

    /// Create a thread-safe key manager with default settings
    pub fn new_default() -> Self {
        Self {
            inner: Arc::new(KeyManager::new_default()),
        }
    }
}

impl Default for ThreadSafeKeyManager {
    fn default() -> Self {
        Self::new_default()
    }
}

impl ThreadSafeKeyManager {
    /// Generate a new key
    pub fn generate_key(&self, id: String, size: usize) -> KeyResult<()> {
        self.inner.generate_key(id, size)
    }

    /// Store a key
    pub fn store_key(&self, id: String, material: SecureBytes) -> KeyResult<()> {
        self.inner.store_key(id, material)
    }

    /// Get a key
    /// Returns key material wrapped in Zeroizing to ensure it is zeroed on drop
    pub fn get_key(&self, id: &str) -> KeyResult<Zeroizing<Vec<u8>>> {
        self.inner.get_key(id)
    }

    /// Store a session key
    pub fn store_session_key(&self, session_id: SessionId, material: SecureBytes) -> KeyResult<()> {
        self.inner.store_session_key(session_id, material)
    }

    /// Get a session key
    /// Returns key material wrapped in Zeroizing to ensure it is zeroed on drop
    pub fn get_session_key(&self, session_id: &SessionId) -> KeyResult<Zeroizing<Vec<u8>>> {
        self.inner.get_session_key(session_id)
    }

    /// Revoke a key
    pub fn revoke_key(&self, id: &str) -> KeyResult<()> {
        self.inner.revoke_key(id)
    }

    /// Revoke a session key
    pub fn revoke_session_key(&self, session_id: &SessionId) -> KeyResult<()> {
        self.inner.revoke_session_key(session_id)
    }

    /// Rotate a key
    pub fn rotate_key(&self, id: &str, new_material: SecureBytes) -> KeyResult<()> {
        self.inner.rotate_key(id, new_material)
    }

    /// Clean up expired keys
    pub fn cleanup_expired_keys(&self) -> KeyResult<usize> {
        self.inner.cleanup_expired_keys()
    }

    /// Get key statistics
    pub fn get_key_stats(&self) -> KeyResult<(usize, usize, usize, usize)> {
        self.inner.get_key_stats()
    }

    /// List all key IDs
    pub fn list_keys(&self) -> KeyResult<Vec<String>> {
        self.inner.list_keys()
    }

    /// Get key metadata
    pub fn get_key_metadata(&self, id: &str) -> KeyResult<KeyMetadata> {
        self.inner.get_key_metadata(id)
    }
}
