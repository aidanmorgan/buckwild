// Timestamp cache for replay protection
//
// This module implements the timestamp+nonce cache for detecting replay attacks
// as specified in design/protocol/14-replay-protection.md. The cache stores recently
// seen timestamp+nonce combinations within a 30-second window.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::error::SecurityError;
use crate::protocol::types::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Result type for timestamp cache operations
pub type TimestampCacheResult<T> = Result<T, SecurityError>;

/// Entry in the timestamp cache
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Time when entry was added (for cleanup)
    received_time: Timestamp,

    /// Session ID
    session_id: SessionId,

    /// Sequence number
    sequence: SequenceNumber,
}

/// Cache key combining timestamp and nonce
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Timestamp portion
    timestamp: u64,

    /// Nonce hash (first 64 bits)
    nonce_hash: u64,
}

impl CacheKey {
    /// Create a new cache key from timestamp and nonce
    fn new(timestamp: Timestamp, nonce: &[u8]) -> Self {
        // Hash the nonce to 64 bits for efficient storage
        // Use a simple hash combining bytes - production would use a proper hash function
        let nonce_hash = nonce.iter().fold(0u64, |acc, &b| {
            acc.wrapping_mul(31).wrapping_add(u64::from(b))
        });

        Self {
            timestamp: timestamp.as_u64(),
            nonce_hash,
        }
    }
}

/// Timestamp cache for replay protection
///
/// Stores seen timestamp+nonce combinations within a 30-second retention window.
/// Provides efficient lookup (sub-microsecond) and periodic cleanup of expired entries.
///
/// # Thread Safety
///
/// This structure uses internal locking and can be safely shared across threads
/// via `Arc<TimestampCache>`.
pub struct TimestampCache {
    /// Cache storage mapping keys to entries
    cache: RwLock<HashMap<CacheKey, CacheEntry>>,

    /// Last cleanup time
    last_cleanup: RwLock<Timestamp>,

    /// Window size in nanoseconds (30 seconds)
    window_ns: u64,
}

impl TimestampCache {
    /// 30-second retention window in nanoseconds (per spec 14-replay-protection.md)
    const WINDOW_NS: u64 = 30_000_000_000;

    /// Cleanup interval (every 15 seconds = half the window)
    const CLEANUP_INTERVAL_NS: u64 = 15_000_000_000;

    /// Create a new timestamp cache with default 30-second window
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(1000)),
            last_cleanup: RwLock::new(Timestamp::now()),
            window_ns: Self::WINDOW_NS,
        }
    }

    /// Create a timestamp cache with custom window size (for testing)
    pub fn with_window(window_ns: u64) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(1000)),
            last_cleanup: RwLock::new(Timestamp::now()),
            window_ns,
        }
    }

    /// Check if timestamp+nonce combination has been seen, and add it if not
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Packet timestamp
    /// * `nonce` - Cryptographic nonce from packet
    ///
    /// # Returns
    ///
    /// * `Ok(())` - First time seeing this combination
    /// * `Err(SecurityError::ReplayAttack)` - Duplicate detected (replay attack)
    ///
    /// # Performance
    ///
    /// This operation completes in sub-microsecond time for typical cache sizes.
    pub fn check_and_add(&self, timestamp: Timestamp, nonce: &[u8]) -> TimestampCacheResult<()> {
        let key = CacheKey::new(timestamp, nonce);
        let current_time = Timestamp::now();

        // Check if entry exists (read lock - allows concurrent reads)
        {
            let cache = self.cache.read().map_err(|_| {
                SecurityError::anti_replay_failed("timestamp cache lock poisoned".to_string())
            })?;

            if let Some(entry) = cache.get(&key) {
                // Entry exists - this is a replay attack
                return Err(SecurityError::replay_attack(
                    entry.session_id.clone(),
                    entry.sequence,
                ));
            }
        }

        // Add new entry (write lock)
        {
            let mut cache = self.cache.write().map_err(|_| {
                SecurityError::anti_replay_failed("timestamp cache lock poisoned".to_string())
            })?;

            // Double-check after acquiring write lock (another thread may have added it)
            if cache.contains_key(&key) {
                // Another thread added it between our read and write lock
                // Treat as duplicate
                return Err(SecurityError::anti_replay_failed(
                    "duplicate timestamp+nonce detected".to_string(),
                ));
            }

            // Create entry (session_id and sequence are placeholders - not used for lookup)
            let entry = CacheEntry {
                received_time: current_time,
                session_id: SessionId::new(0),
                sequence: SequenceNumber::new(0),
            };

            cache.insert(key, entry);
        }

        // Trigger cleanup if needed
        self.cleanup_if_needed(current_time)?;

        Ok(())
    }

    /// Check if timestamp+nonce combination has been seen, with session context
    ///
    /// This variant accepts session_id and sequence for better error reporting.
    pub fn check_and_add_with_context(
        &self,
        timestamp: Timestamp,
        nonce: &[u8],
        session_id: SessionId,
        sequence: SequenceNumber,
    ) -> TimestampCacheResult<()> {
        let key = CacheKey::new(timestamp, nonce);
        let current_time = Timestamp::now();

        // Check if entry exists (read lock)
        {
            let cache = self.cache.read().map_err(|_| {
                SecurityError::anti_replay_failed("timestamp cache lock poisoned".to_string())
            })?;

            if let Some(entry) = cache.get(&key) {
                return Err(SecurityError::replay_attack(
                    entry.session_id.clone(),
                    entry.sequence,
                ));
            }
        }

        // Add new entry (write lock)
        {
            let mut cache = self.cache.write().map_err(|_| {
                SecurityError::anti_replay_failed("timestamp cache lock poisoned".to_string())
            })?;

            if cache.contains_key(&key) {
                return Err(SecurityError::replay_attack(session_id, sequence));
            }

            let entry = CacheEntry {
                received_time: current_time,
                session_id,
                sequence,
            };

            cache.insert(key, entry);
        }

        self.cleanup_if_needed(current_time)?;

        Ok(())
    }

    /// Force cleanup of expired entries
    ///
    /// This is called automatically during `check_and_add` but can be called
    /// manually for testing or maintenance.
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current timestamp for age calculation
    pub fn cleanup_expired(&self, current_time: Timestamp) -> TimestampCacheResult<usize> {
        let cutoff_time = if current_time.as_u64() > self.window_ns {
            Timestamp::from_raw(current_time.as_u64() - self.window_ns)
        } else {
            Timestamp::from_raw(0)
        };

        let mut cache = self.cache.write().map_err(|_| {
            SecurityError::anti_replay_failed("timestamp cache lock poisoned".to_string())
        })?;

        let initial_size = cache.len();

        // Remove entries older than cutoff
        cache.retain(|_, entry| entry.received_time.as_u64() >= cutoff_time.as_u64());

        let removed = initial_size - cache.len();

        // Update last cleanup time
        let mut last_cleanup = self.last_cleanup.write().map_err(|_| {
            SecurityError::anti_replay_failed("cleanup time lock poisoned".to_string())
        })?;
        *last_cleanup = current_time;

        Ok(removed)
    }

    /// Check if cleanup is needed and perform it
    fn cleanup_if_needed(&self, current_time: Timestamp) -> TimestampCacheResult<()> {
        let last_cleanup = self.last_cleanup.read().map_err(|_| {
            SecurityError::anti_replay_failed("cleanup time lock poisoned".to_string())
        })?;

        let time_since_cleanup = current_time.as_u64().saturating_sub(last_cleanup.as_u64());

        if time_since_cleanup >= Self::CLEANUP_INTERVAL_NS {
            drop(last_cleanup); // Release read lock before cleanup
            self.cleanup_expired(current_time)?;
        }

        Ok(())
    }

    /// Get current cache size (number of entries)
    ///
    /// This is primarily for testing and monitoring.
    pub fn len(&self) -> usize {
        self.cache.read().map(|cache| cache.len()).unwrap_or(0)
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries from the cache
    ///
    /// This is primarily for testing.
    pub fn clear(&self) -> TimestampCacheResult<()> {
        let mut cache = self.cache.write().map_err(|_| {
            SecurityError::anti_replay_failed("timestamp cache lock poisoned".to_string())
        })?;
        cache.clear();
        Ok(())
    }
}

impl Default for TimestampCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for TimestampCache
pub type ThreadSafeTimestampCache = Arc<TimestampCache>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_time_accept() {
        let cache = TimestampCache::new();
        let timestamp = Timestamp::now();
        let nonce = b"test_nonce_12345";

        let result = cache.check_and_add(timestamp, nonce);
        assert!(result.is_ok(), "First time should be accepted");
    }

    #[test]
    fn test_replay_reject() {
        let cache = TimestampCache::new();
        let timestamp = Timestamp::now();
        let nonce = b"test_nonce_12345";

        // First check should succeed
        cache.check_and_add(timestamp, nonce).ok();

        // Second check should fail (replay)
        let result = cache.check_and_add(timestamp, nonce);
        assert!(result.is_err(), "Replay should be rejected");
    }

    #[test]
    fn test_different_nonce_accept() {
        let cache = TimestampCache::new();
        let timestamp = Timestamp::now();
        let nonce1 = b"test_nonce_12345";
        let nonce2 = b"test_nonce_67890";

        cache.check_and_add(timestamp, nonce1).ok();

        // Same timestamp, different nonce should be accepted
        let result = cache.check_and_add(timestamp, nonce2);
        assert!(result.is_ok(), "Different nonce should be accepted");
    }

    #[test]
    fn test_expiry_cleanup() {
        // Use 1-second window for faster testing
        let cache = TimestampCache::with_window(1_000_000_000);
        let timestamp = Timestamp::now();
        let nonce = b"test_nonce_12345";

        cache.check_and_add(timestamp, nonce).ok();
        assert_eq!(cache.len(), 1, "Should have 1 entry");

        // Simulate time passing (2 seconds)
        let future_time = Timestamp::from_raw(timestamp.as_u64() + 2_000_000_000);
        let removed = cache.cleanup_expired(future_time).ok();

        assert_eq!(removed, Some(1), "Should remove 1 expired entry");
        assert_eq!(cache.len(), 0, "Cache should be empty after cleanup");
    }

    #[test]
    fn test_high_packet_rate() {
        let cache = TimestampCache::new();
        let base_timestamp = Timestamp::now();

        // Simulate high packet rate with 1000 different nonces
        for i in 0u64..1000 {
            let nonce = format!("nonce_{:08}", i);
            let timestamp = Timestamp::from_raw(base_timestamp.as_u64() + i * 1000);

            let result = cache.check_and_add(timestamp, nonce.as_bytes());
            assert!(result.is_ok(), "Packet {} should be accepted", i);
        }

        assert_eq!(cache.len(), 1000, "Should have 1000 entries");
    }

    #[test]
    fn test_capacity_handling() {
        let cache = TimestampCache::new();
        let base_timestamp = Timestamp::now();

        // Add many entries
        for i in 0u64..5000 {
            let nonce = format!("nonce_{:08}", i);
            let timestamp = Timestamp::from_raw(base_timestamp.as_u64() + i * 1000);
            cache.check_and_add(timestamp, nonce.as_bytes()).ok();
        }

        // Cache should handle large number of entries
        assert!(cache.len() >= 4000, "Should handle high capacity");
    }

    #[test]
    fn test_with_context() {
        let cache = TimestampCache::new();
        let timestamp = Timestamp::now();
        let nonce = b"test_nonce";
        let session = SessionId::new(42);
        let sequence = SequenceNumber::new(100);

        let result = cache.check_and_add_with_context(timestamp, nonce, session.clone(), sequence);
        assert!(result.is_ok(), "First time should succeed");

        let result = cache.check_and_add_with_context(timestamp, nonce, session, sequence);
        assert!(result.is_err(), "Duplicate should fail");
    }

    #[test]
    fn test_clear() {
        let cache = TimestampCache::new();
        let timestamp = Timestamp::now();

        for i in 0u64..10 {
            let nonce = format!("nonce_{}", i);
            cache.check_and_add(timestamp, nonce.as_bytes()).ok();
        }

        assert_eq!(cache.len(), 10);
        cache.clear().ok();
        assert_eq!(cache.len(), 0);
    }
}
