#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// PSK Cache for Session Duration
//
// This module implements caching of validated PSKs to avoid redundant discovery
// operations within the same session. PSKs are stored with zeroization on drop
// to prevent key material from remaining in memory.

use dashmap::DashMap;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::protocol::types::{PskId, SessionId};

/// Default PSK cache expiration time (session duration)
const DEFAULT_PSK_CACHE_EXPIRATION: Duration = Duration::from_secs(3600); // 1 hour

/// Cache for validated PSKs
pub struct PskCache {
    /// Cached PSKs indexed by PskId
    cache: DashMap<PskId, CachedPsk>,
}

/// Cached PSK entry with expiration and session tracking
#[derive(Clone)]
pub struct CachedPsk {
    /// The PSK bytes (256-bit) with zeroization on drop
    pub(crate) psk: Zeroizing<[u8; 32]>,
    /// When this PSK was validated
    pub(crate) validated_at: Instant,
    /// Session ID this PSK is associated with
    pub(crate) session_id: SessionId,
    /// Expiration time
    pub(crate) expires_at: Instant,
}

impl PskCache {
    /// Create a new PSK cache
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    /// Insert a PSK into the cache with default expiration
    pub fn insert(&self, psk_id: PskId, psk: [u8; 32], session_id: SessionId) {
        self.insert_with_expiration(psk_id, psk, session_id, DEFAULT_PSK_CACHE_EXPIRATION);
    }

    /// Insert a PSK into the cache with custom expiration duration
    pub fn insert_with_expiration(
        &self,
        psk_id: PskId,
        psk: [u8; 32],
        session_id: SessionId,
        expiration: Duration,
    ) {
        let now = Instant::now();
        let cached_psk = CachedPsk {
            psk: Zeroizing::new(psk),
            validated_at: now,
            session_id,
            expires_at: now + expiration,
        };
        self.cache.insert(psk_id, cached_psk);
    }

    /// Get a cached PSK if it exists and has not expired
    pub fn get(&self, psk_id: &PskId) -> Option<CachedPsk> {
        if let Some(entry) = self.cache.get(psk_id) {
            let cached = entry.value();
            if Instant::now() < cached.expires_at {
                Some(cached.clone())
            } else {
                // Remove expired entry
                drop(entry);
                self.cache.remove(psk_id);
                None
            }
        } else {
            None
        }
    }

    /// Remove a PSK from the cache
    pub fn remove(&self, psk_id: &PskId) -> Option<CachedPsk> {
        self.cache.remove(psk_id).map(|(_, cached)| cached)
    }

    /// Clean up all expired PSKs
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.cache.retain(|_, cached| now < cached.expires_at);
    }

    /// Get the number of cached PSKs (including expired ones)
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clear all cached PSKs
    pub fn clear(&self) {
        self.cache.clear();
    }
}

impl Default for PskCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CachedPsk {
    /// Get a reference to the PSK bytes
    pub fn psk(&self) -> &[u8; 32] {
        &self.psk
    }

    /// Get the validation timestamp
    pub fn validated_at(&self) -> Instant {
        self.validated_at
    }

    /// Get the session ID
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the expiration timestamp
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Check if this PSK has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::SessionIdLength;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = PskCache::new();
        let psk_id = PskId::from_u32(1);
        let psk = [0x42u8; 32];
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

        cache.insert(psk_id.clone(), psk, session_id);

        let cached = cache.get(&psk_id);
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.psk(), &psk);
    }

    #[test]
    fn test_cache_remove() {
        let cache = PskCache::new();
        let psk_id = PskId::from_u32(1);
        let psk = [0x42u8; 32];
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

        cache.insert(psk_id.clone(), psk, session_id);
        assert!(cache.get(&psk_id).is_some());

        let removed = cache.remove(&psk_id);
        assert!(removed.is_some());
        assert!(cache.get(&psk_id).is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = PskCache::new();
        let psk_id = PskId::from_u32(1);
        let psk = [0x42u8; 32];
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

        // Insert with very short expiration
        cache.insert_with_expiration(psk_id.clone(), psk, session_id, Duration::from_millis(10));

        // Should be available immediately
        assert!(cache.get(&psk_id).is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Should be expired now
        assert!(cache.get(&psk_id).is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = PskCache::new();
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

        // Insert PSKs with different expirations
        cache.insert_with_expiration(
            PskId::from_u32(1),
            [0x01u8; 32],
            session_id.clone(),
            Duration::from_millis(10),
        );
        cache.insert_with_expiration(
            PskId::from_u32(2),
            [0x02u8; 32],
            session_id.clone(),
            Duration::from_secs(3600),
        );

        assert_eq!(cache.len(), 2);

        // Wait for first PSK to expire
        std::thread::sleep(Duration::from_millis(20));

        // Cleanup expired entries
        cache.cleanup_expired();

        // Should only have one entry left
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&PskId::from_u32(2)).is_some());
    }

    #[test]
    fn test_cached_psk_is_expired() {
        let psk = [0x42u8; 32];
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);
        let now = Instant::now();

        // Create expired PSK
        let expired = CachedPsk {
            psk: Zeroizing::new(psk),
            validated_at: now,
            session_id: session_id.clone(),
            expires_at: now - Duration::from_secs(1),
        };

        assert!(expired.is_expired());

        // Create non-expired PSK
        let valid = CachedPsk {
            psk: Zeroizing::new(psk),
            validated_at: now,
            session_id,
            expires_at: now + Duration::from_secs(3600),
        };

        assert!(!valid.is_expired());
    }

    #[test]
    fn test_cache_clear() {
        let cache = PskCache::new();
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

        cache.insert(PskId::from_u32(1), [0x01u8; 32], session_id.clone());
        cache.insert(PskId::from_u32(2), [0x02u8; 32], session_id);

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_multiple_psks() {
        let cache = PskCache::new();
        let session_id = SessionId::new_with_length(1, SessionIdLength::Bits32);

        // Insert multiple PSKs
        for i in 0..10 {
            let psk_id = PskId::from_u32(i);
            let mut psk = [0u8; 32];
            psk[0] = i as u8;
            cache.insert(psk_id, psk, session_id.clone());
        }

        assert_eq!(cache.len(), 10);

        // Verify all PSKs are retrievable
        for i in 0..10 {
            let psk_id = PskId::from_u32(i);
            let cached = cache.get(&psk_id);
            assert!(cached.is_some());
            let cached = cached.unwrap();
            assert_eq!(cached.psk()[0], i as u8);
        }
    }
}
