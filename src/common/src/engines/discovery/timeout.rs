// Timeout and cleanup for stale discovery attempts
//
// Tracks discovery attempts and cleans up expired/abandoned operations
// to prevent resource exhaustion.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::protocol::types::*;

/// Discovery attempt state
#[derive(Debug, Clone)]
struct DiscoveryAttempt {
    /// Discovery session ID (stored for debug purposes, key is in DashMap)
    #[allow(dead_code)]
    discovery_id: DiscoveryId,
    /// When the attempt started
    started_at: Instant,
    /// Attempt phase
    phase: DiscoveryPhase,
    /// Number of retries
    retry_count: u8,
}

/// Discovery attempt phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryPhase {
    /// Waiting for response to initial request
    AwaitingResponse,
    /// Waiting for confirmation
    AwaitingConfirmation,
    /// Completed successfully
    Completed,
    /// Failed or abandoned
    Failed,
}

/// Configuration for discovery timeouts
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Discovery request timeout (10 seconds per design/protocol/05-psk-discovery.md line 422)
    pub discovery_timeout: Duration,
    /// Maximum retry count (3 per line 423)
    pub max_retries: u8,
    /// Cleanup interval for expired attempts
    pub cleanup_interval: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            discovery_timeout: Duration::from_millis(DISCOVERY_TIMEOUT_MS),
            max_retries: DISCOVERY_RETRY_COUNT,
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

/// Manager for tracking and cleaning up discovery attempts
pub struct DiscoveryTimeoutManager {
    /// Active discovery attempts by discovery ID
    attempts: Arc<DashMap<DiscoveryId, DiscoveryAttempt>>,
    /// Configuration
    config: TimeoutConfig,
    /// Last cleanup time
    last_cleanup: Arc<parking_lot::Mutex<Instant>>,
}

impl DiscoveryTimeoutManager {
    /// Create a new timeout manager with default configuration
    pub fn new() -> Self {
        Self::with_config(TimeoutConfig::default())
    }

    /// Create a new timeout manager with custom configuration
    pub fn with_config(config: TimeoutConfig) -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            config,
            last_cleanup: Arc::new(parking_lot::Mutex::new(Instant::now())),
        }
    }

    /// Register a new discovery attempt
    pub fn register_attempt(&self, discovery_id: DiscoveryId) {
        let attempt = DiscoveryAttempt {
            discovery_id,
            started_at: Instant::now(),
            phase: DiscoveryPhase::AwaitingResponse,
            retry_count: 0,
        };

        self.attempts.insert(discovery_id, attempt);
        debug!(
            discovery_id = discovery_id.0,
            "Registered discovery attempt"
        );
    }

    /// Update the phase of a discovery attempt
    pub fn update_phase(&self, discovery_id: &DiscoveryId, phase: DiscoveryPhase) {
        if let Some(mut entry) = self.attempts.get_mut(discovery_id) {
            entry.phase = phase;
            debug!(
                discovery_id = discovery_id.0,
                phase = ?phase,
                "Updated discovery phase"
            );
        }
    }

    /// Increment retry count for a discovery attempt
    pub fn increment_retry(&self, discovery_id: &DiscoveryId) -> bool {
        if let Some(mut entry) = self.attempts.get_mut(discovery_id) {
            entry.retry_count += 1;
            let can_retry = entry.retry_count < self.config.max_retries;
            debug!(
                discovery_id = discovery_id.0,
                retry_count = entry.retry_count,
                max_retries = self.config.max_retries,
                can_retry,
                "Incremented discovery retry count"
            );
            can_retry
        } else {
            false
        }
    }

    /// Check if a discovery attempt has timed out
    pub fn is_timed_out(&self, discovery_id: &DiscoveryId) -> bool {
        if let Some(entry) = self.attempts.get(discovery_id) {
            let elapsed = entry.started_at.elapsed();
            let timed_out = elapsed >= self.config.discovery_timeout;

            if timed_out {
                warn!(
                    discovery_id = discovery_id.0,
                    elapsed_ms = elapsed.as_millis(),
                    timeout_ms = self.config.discovery_timeout.as_millis(),
                    phase = ?entry.phase,
                    "Discovery attempt timed out"
                );
            }

            timed_out
        } else {
            false
        }
    }

    /// Mark a discovery attempt as completed
    pub fn mark_completed(&self, discovery_id: &DiscoveryId) {
        self.update_phase(discovery_id, DiscoveryPhase::Completed);
    }

    /// Mark a discovery attempt as failed
    pub fn mark_failed(&self, discovery_id: &DiscoveryId) {
        self.update_phase(discovery_id, DiscoveryPhase::Failed);
    }

    /// Remove a discovery attempt
    pub fn remove_attempt(&self, discovery_id: &DiscoveryId) {
        if self.attempts.remove(discovery_id).is_some() {
            debug!(discovery_id = discovery_id.0, "Removed discovery attempt");
        }
    }

    /// Clean up timed out and completed discovery attempts
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let timeout = self.config.discovery_timeout;
        let retention = Duration::from_secs(60); // Keep completed/failed for 1 minute

        let mut removed_count = 0;

        self.attempts.retain(|_id, attempt| {
            let elapsed = now.duration_since(attempt.started_at);

            match attempt.phase {
                DiscoveryPhase::AwaitingResponse | DiscoveryPhase::AwaitingConfirmation => {
                    // Remove if timed out
                    if elapsed >= timeout {
                        removed_count += 1;
                        false
                    } else {
                        true
                    }
                }
                DiscoveryPhase::Completed | DiscoveryPhase::Failed => {
                    // Remove if old enough
                    if elapsed >= retention {
                        removed_count += 1;
                        false
                    } else {
                        true
                    }
                }
            }
        });

        if removed_count > 0 {
            debug!(
                removed_count,
                active_count = self.attempts.len(),
                "Cleaned up expired discovery attempts"
            );
        }
    }

    /// Internal cleanup that runs periodically
    pub fn maybe_cleanup(&self) {
        let last_cleanup = self.last_cleanup.lock();
        if last_cleanup.elapsed() >= self.config.cleanup_interval {
            drop(last_cleanup); // Drop lock before cleanup
            self.cleanup_expired();
            *self.last_cleanup.lock() = Instant::now();
        }
    }

    /// Get current attempt count (for monitoring)
    pub fn active_count(&self) -> usize {
        self.attempts.len()
    }

    /// Get attempt phase for a discovery ID
    pub fn get_phase(&self, discovery_id: &DiscoveryId) -> Option<DiscoveryPhase> {
        self.attempts.get(discovery_id).map(|a| a.phase)
    }

    /// Get retry count for a discovery ID
    pub fn get_retry_count(&self, discovery_id: &DiscoveryId) -> Option<u8> {
        self.attempts.get(discovery_id).map(|a| a.retry_count)
    }
}

impl Default for DiscoveryTimeoutManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_retrieve_attempt() {
        let manager = DiscoveryTimeoutManager::new();
        let discovery_id = DiscoveryId::new(12345);

        manager.register_attempt(discovery_id);

        assert_eq!(manager.active_count(), 1);
        assert_eq!(
            manager.get_phase(&discovery_id),
            Some(DiscoveryPhase::AwaitingResponse)
        );
    }

    #[test]
    fn test_update_phase() {
        let manager = DiscoveryTimeoutManager::new();
        let discovery_id = DiscoveryId::new(12345);

        manager.register_attempt(discovery_id);
        manager.update_phase(&discovery_id, DiscoveryPhase::AwaitingConfirmation);

        assert_eq!(
            manager.get_phase(&discovery_id),
            Some(DiscoveryPhase::AwaitingConfirmation)
        );
    }

    #[test]
    fn test_increment_retry() {
        let manager = DiscoveryTimeoutManager::new();
        let discovery_id = DiscoveryId::new(12345);

        manager.register_attempt(discovery_id);

        assert_eq!(manager.get_retry_count(&discovery_id), Some(0));

        // Should allow retries up to max
        assert!(manager.increment_retry(&discovery_id));
        assert_eq!(manager.get_retry_count(&discovery_id), Some(1));

        assert!(manager.increment_retry(&discovery_id));
        assert_eq!(manager.get_retry_count(&discovery_id), Some(2));

        // Third retry should fail (max is 3)
        assert!(!manager.increment_retry(&discovery_id));
        assert_eq!(manager.get_retry_count(&discovery_id), Some(3));
    }

    #[test]
    fn test_timeout_detection() {
        let config = TimeoutConfig {
            discovery_timeout: Duration::from_millis(100),
            max_retries: 3,
            cleanup_interval: Duration::from_secs(30),
        };
        let manager = DiscoveryTimeoutManager::with_config(config);
        let discovery_id = DiscoveryId::new(12345);

        manager.register_attempt(discovery_id);

        // Should not be timed out immediately
        assert!(!manager.is_timed_out(&discovery_id));

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));

        // Should now be timed out
        assert!(manager.is_timed_out(&discovery_id));
    }

    #[test]
    fn test_cleanup_expired() {
        let config = TimeoutConfig {
            discovery_timeout: Duration::from_millis(50),
            max_retries: 3,
            cleanup_interval: Duration::from_secs(30),
        };
        let manager = DiscoveryTimeoutManager::with_config(config);

        let discovery_id1 = DiscoveryId::new(11111);
        let discovery_id2 = DiscoveryId::new(22222);

        manager.register_attempt(discovery_id1);
        manager.register_attempt(discovery_id2);

        assert_eq!(manager.active_count(), 2);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(100));

        // Cleanup should remove both
        manager.cleanup_expired();

        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_completed_attempts_retained_briefly() {
        let config = TimeoutConfig {
            discovery_timeout: Duration::from_secs(10),
            max_retries: 3,
            cleanup_interval: Duration::from_secs(30),
        };
        let manager = DiscoveryTimeoutManager::with_config(config);
        let discovery_id = DiscoveryId::new(12345);

        manager.register_attempt(discovery_id);
        manager.mark_completed(&discovery_id);

        // Should still be present after completion
        assert_eq!(manager.active_count(), 1);
        assert_eq!(
            manager.get_phase(&discovery_id),
            Some(DiscoveryPhase::Completed)
        );

        // Immediate cleanup should not remove it (retention period)
        manager.cleanup_expired();
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_remove_attempt() {
        let manager = DiscoveryTimeoutManager::new();
        let discovery_id = DiscoveryId::new(12345);

        manager.register_attempt(discovery_id);
        assert_eq!(manager.active_count(), 1);

        manager.remove_attempt(&discovery_id);
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_mark_completed_and_failed() {
        let manager = DiscoveryTimeoutManager::new();
        let discovery_id1 = DiscoveryId::new(11111);
        let discovery_id2 = DiscoveryId::new(22222);

        manager.register_attempt(discovery_id1);
        manager.register_attempt(discovery_id2);

        manager.mark_completed(&discovery_id1);
        manager.mark_failed(&discovery_id2);

        assert_eq!(
            manager.get_phase(&discovery_id1),
            Some(DiscoveryPhase::Completed)
        );
        assert_eq!(
            manager.get_phase(&discovery_id2),
            Some(DiscoveryPhase::Failed)
        );
    }
}
