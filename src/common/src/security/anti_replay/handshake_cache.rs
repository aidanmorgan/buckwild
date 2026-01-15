// Handshake replay cache for SYN flood protection
//
// This module implements a cache for detecting replayed key_exchange_ids during
// handshake processing to prevent SYN flood attacks with duplicated exchange IDs.
// The cache stores recently seen exchange IDs within a 60-second window.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::error::SecurityError;
use crate::protocol::types::Timestamp;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Result type for handshake cache operations
pub type HandshakeCacheResult<T> = Result<T, SecurityError>;

/// Entry in the handshake cache
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Time when entry was added (for cleanup)
    received_time: Timestamp,
}

/// Handshake replay cache for SYN flood protection
///
/// Stores seen key_exchange_ids within a 60-second retention window to prevent
/// replay attacks during the handshake phase. This is separate from the timestamp
/// cache and provides longer retention for handshake-specific protection.
///
/// # Thread Safety
///
/// This structure uses internal locking and can be safely shared across threads
/// via `Arc<HandshakeReplayCache>`.
pub struct HandshakeReplayCache {
    /// Cache storage mapping exchange IDs to entries
    cache: RwLock<HashMap<u16, CacheEntry>>,

    /// Last cleanup time
    last_cleanup: RwLock<Timestamp>,

    /// Window size in nanoseconds (60 seconds)
    window_ns: u64,
}

impl HandshakeReplayCache {
    /// 60-second retention window in nanoseconds (for handshake replay protection)
    const WINDOW_NS: u64 = 60_000_000_000;

    /// Cleanup interval (every 30 seconds = half the window)
    const CLEANUP_INTERVAL_NS: u64 = 30_000_000_000;

    /// Create a new handshake replay cache with default 60-second window
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(1000)),
            last_cleanup: RwLock::new(Timestamp::now()),
            window_ns: Self::WINDOW_NS,
        }
    }

    /// Create a handshake cache with custom window size (for testing)
    pub fn with_window(window_ns: u64) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(1000)),
            last_cleanup: RwLock::new(Timestamp::now()),
            window_ns,
        }
    }

    /// Check if key_exchange_id has been seen, and add it if not
    ///
    /// # Arguments
    ///
    /// * `key_exchange_id` - The exchange ID from the SYN packet
    ///
    /// # Returns
    ///
    /// * `Ok(())` - First time seeing this exchange ID
    /// * `Err(SecurityError::ReplayAttack)` - Duplicate detected (SYN replay)
    ///
    /// # Performance
    ///
    /// This operation completes in sub-microsecond time for typical cache sizes.
    pub fn check_and_add(&self, key_exchange_id: u16) -> HandshakeCacheResult<()> {
        let current_time = Timestamp::now();

        // Check if entry exists (read lock - allows concurrent reads)
        {
            let cache = self.cache.read().map_err(|_| {
                SecurityError::anti_replay_failed("handshake cache lock poisoned".to_string())
            })?;

            if cache.contains_key(&key_exchange_id) {
                // Entry exists - this is a SYN replay attack
                return Err(SecurityError::anti_replay_failed(format!(
                    "handshake replay detected: key_exchange_id={}",
                    key_exchange_id
                )));
            }
        }

        // Add new entry (write lock)
        {
            let mut cache = self.cache.write().map_err(|_| {
                SecurityError::anti_replay_failed("handshake cache lock poisoned".to_string())
            })?;

            // Double-check after acquiring write lock (another thread may have added it)
            if cache.contains_key(&key_exchange_id) {
                // Another thread added it between our read and write lock
                return Err(SecurityError::anti_replay_failed(format!(
                    "handshake replay detected: key_exchange_id={}",
                    key_exchange_id
                )));
            }

            // Create entry
            let entry = CacheEntry {
                received_time: current_time,
            };

            cache.insert(key_exchange_id, entry);
        }

        // Trigger cleanup if needed
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
    pub fn cleanup_expired(&self, current_time: Timestamp) -> HandshakeCacheResult<usize> {
        let cutoff_time = if current_time.as_u64() > self.window_ns {
            Timestamp::from_raw(current_time.as_u64() - self.window_ns)
        } else {
            Timestamp::from_raw(0)
        };

        let mut cache = self.cache.write().map_err(|_| {
            SecurityError::anti_replay_failed("handshake cache lock poisoned".to_string())
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
    fn cleanup_if_needed(&self, current_time: Timestamp) -> HandshakeCacheResult<()> {
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
    pub fn clear(&self) -> HandshakeCacheResult<()> {
        let mut cache = self.cache.write().map_err(|_| {
            SecurityError::anti_replay_failed("handshake cache lock poisoned".to_string())
        })?;
        cache.clear();
        Ok(())
    }
}

impl Default for HandshakeReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for HandshakeReplayCache
pub type ThreadSafeHandshakeCache = Arc<HandshakeReplayCache>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_syn_accept() {
        let cache = HandshakeReplayCache::new();
        let key_exchange_id = 12345u16;

        let result = cache.check_and_add(key_exchange_id);
        assert!(result.is_ok(), "First SYN should be accepted");
    }

    #[test]
    fn test_replay_syn_reject() {
        let cache = HandshakeReplayCache::new();
        let key_exchange_id = 12345u16;

        // First check should succeed
        cache.check_and_add(key_exchange_id).ok();

        // Second check should fail (replay)
        let result = cache.check_and_add(key_exchange_id);
        assert!(result.is_err(), "Replay SYN should be rejected");
    }

    #[test]
    fn test_different_id_accept() {
        let cache = HandshakeReplayCache::new();
        let key_exchange_id1 = 12345u16;
        let key_exchange_id2 = 54321u16;

        cache.check_and_add(key_exchange_id1).ok();

        // Different exchange ID should be accepted
        let result = cache.check_and_add(key_exchange_id2);
        assert!(result.is_ok(), "Different exchange ID should be accepted");
    }

    #[test]
    fn test_expiry() {
        // Use 1-second window for faster testing
        let cache = HandshakeReplayCache::with_window(1_000_000_000);
        let timestamp = Timestamp::now();
        let key_exchange_id = 12345u16;

        cache.check_and_add(key_exchange_id).ok();
        assert_eq!(cache.len(), 1, "Should have 1 entry");

        // Simulate time passing (2 seconds)
        let future_time = Timestamp::from_raw(timestamp.as_u64() + 2_000_000_000);
        let removed = cache.cleanup_expired(future_time).ok();

        assert_eq!(removed, Some(1), "Should remove 1 expired entry");
        assert_eq!(cache.len(), 0, "Cache should be empty after cleanup");
    }

    #[test]
    fn test_flood_protection() {
        let cache = HandshakeReplayCache::new();
        let key_exchange_id = 12345u16;

        // First SYN accepted
        assert!(cache.check_and_add(key_exchange_id).is_ok());

        // High rate of duplicates should all be rejected
        for _ in 0..1000 {
            let result = cache.check_and_add(key_exchange_id);
            assert!(result.is_err(), "Duplicate SYN should be rejected");
        }

        // Should still only have 1 entry
        assert_eq!(cache.len(), 1, "Should have only 1 entry despite flood");
    }

    #[test]
    fn test_capacity_handling() {
        let cache = HandshakeReplayCache::new();

        // Add many different exchange IDs
        for i in 0u16..5000 {
            let result = cache.check_and_add(i);
            assert!(result.is_ok(), "Exchange ID {} should be accepted", i);
        }

        // Cache should handle large number of entries
        assert!(cache.len() >= 4000, "Should handle high capacity");
    }

    #[test]
    fn test_clear() {
        let cache = HandshakeReplayCache::new();

        for i in 0u16..10 {
            cache.check_and_add(i).ok();
        }

        assert_eq!(cache.len(), 10);
        cache.clear().ok();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(HandshakeReplayCache::new());
        let mut handles = vec![];

        // Spawn multiple threads trying to add the same exchange ID
        for _ in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || cache_clone.check_and_add(65000u16));
            handles.push(handle);
        }

        // Collect results
        let mut success_count = 0;
        let mut failure_count = 0;

        for handle in handles {
            match handle.join() {
                Ok(Ok(_)) => success_count += 1,
                Ok(Err(_)) => failure_count += 1,
                Err(_) => panic!("Thread panicked"),
            }
        }

        // Exactly one should succeed, rest should fail
        assert_eq!(success_count, 1, "Exactly one thread should succeed");
        assert_eq!(failure_count, 9, "Nine threads should fail");
        assert_eq!(cache.len(), 1, "Should have exactly 1 entry");
    }
}
