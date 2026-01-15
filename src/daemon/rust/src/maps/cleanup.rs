//! eBPF map cleanup on session expiry
//!
//! Provides cleanup mechanisms for removing stale entries from eBPF maps
//! when sessions expire. Integrates with session lifecycle events and
//! periodic cleanup tasks.

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{Instant, interval};
use tracing::{debug, info, instrument, warn};

use buckwild_common::protocol::types::SessionId;

#[cfg(target_os = "linux")]
use buckwild_ebpf::maps::MapManager;

/// Cleanup configuration
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Interval between periodic cleanup runs (default: 30 seconds)
    pub cleanup_interval: Duration,
    /// Maximum session age before cleanup (default: 300 seconds / 5 minutes)
    pub session_max_age: Duration,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            cleanup_interval: Duration::from_secs(30),
            session_max_age: Duration::from_secs(300),
        }
    }
}

/// Statistics for cleanup operations
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    pub total_cleanups: u64,
    pub sessions_cleaned: u64,
    pub last_cleanup_at: Option<Instant>,
    pub last_cleanup_duration: Option<Duration>,
}

/// Map cleanup manager
pub struct MapCleanup {
    #[cfg(target_os = "linux")]
    map_manager: Arc<RwLock<MapManager>>,
    config: CleanupConfig,
    stats: Arc<RwLock<CleanupStats>>,
    running: Arc<tokio::sync::RwLock<bool>>,
}

impl MapCleanup {
    /// Create a new map cleanup instance
    #[cfg(target_os = "linux")]
    pub fn new(map_manager: Arc<RwLock<MapManager>>, config: CleanupConfig) -> Self {
        info!(
            "Creating map cleanup with interval: {:?}, max age: {:?}",
            config.cleanup_interval, config.session_max_age
        );

        Self {
            map_manager,
            config,
            stats: Arc::new(RwLock::new(CleanupStats::default())),
            running: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    /// Create a new map cleanup instance (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn new(_config: CleanupConfig) -> Self {
        Self {
            config: _config,
            stats: Arc::new(RwLock::new(CleanupStats::default())),
            running: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    /// Cleanup a specific session from all eBPF maps
    #[cfg(target_os = "linux")]
    #[instrument(skip(self))]
    pub async fn cleanup_session(&self, session_id: SessionId) -> Result<()> {
        debug!("Cleaning up session: {}", session_id);

        let map_mgr = self.map_manager.read().await;

        // Delete from session map
        let session_id_display = session_id.clone();
        map_mgr
            .session_manager()
            .write()
            .await
            .delete_session_typed(session_id)
            .await?;

        // Port map entries are implicitly cleaned when session is removed
        // Security map entries are managed separately by security policy

        info!("Cleaned up session {} from eBPF maps", session_id_display);
        Ok(())
    }

    /// Cleanup a specific session (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[instrument(skip(self))]
    pub async fn cleanup_session(&self, session_id: SessionId) -> Result<()> {
        debug!("Cleanup session {} (non-Linux no-op)", session_id);
        Ok(())
    }

    /// Perform periodic cleanup of stale entries
    #[cfg(target_os = "linux")]
    #[instrument(skip(self))]
    pub async fn periodic_cleanup(&self) -> Result<usize> {
        let start = Instant::now();
        debug!("Starting periodic cleanup");

        let map_mgr = self.map_manager.read().await;

        // Cleanup expired sessions from session map
        let max_age_ns = self.config.session_max_age.as_nanos() as u64;
        let expired_count = map_mgr
            .session_manager()
            .write()
            .await
            .cleanup_expired_sessions(max_age_ns)
            .await?;

        let duration = start.elapsed();

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_cleanups += 1;
        stats.sessions_cleaned += expired_count;
        stats.last_cleanup_at = Some(Instant::now());
        stats.last_cleanup_duration = Some(duration);

        if expired_count > 0 {
            info!(
                "Periodic cleanup removed {} expired sessions in {:?}",
                expired_count, duration
            );
        } else {
            debug!(
                "Periodic cleanup found no expired sessions ({:?})",
                duration
            );
        }

        Ok(expired_count as usize)
    }

    /// Perform periodic cleanup (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[instrument(skip(self))]
    pub async fn periodic_cleanup(&self) -> Result<usize> {
        debug!("Periodic cleanup (non-Linux no-op)");
        Ok(0)
    }

    /// Start periodic cleanup task
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            warn!("Cleanup task already running");
            return Ok(());
        }

        info!(
            "Starting periodic cleanup task (interval: {:?})",
            self.config.cleanup_interval
        );
        *running = true;

        let cleanup_interval = self.config.cleanup_interval;
        let running_flag = Arc::clone(&self.running);

        #[cfg(target_os = "linux")]
        let map_manager = Arc::clone(&self.map_manager);

        #[cfg(target_os = "linux")]
        let config = self.config.clone();
        #[cfg(target_os = "linux")]
        let stats = Arc::clone(&self.stats);

        // Note: MapManager contains non-Send libbpf types, so cleanup runs on the calling
        // task's context using spawn_local or is deferred to manual cleanup calls.
        // For now, we log the intent and defer actual cleanup to explicit cleanup() calls.
        //
        // TODO: Implement proper cleanup using tokio::task::spawn_local with LocalSet,
        // or restructure MapManager to use channels for thread-safe communication.
        let _cleanup_interval = cleanup_interval;
        let _running_flag = running_flag;
        #[cfg(target_os = "linux")]
        let _map_manager = map_manager;
        #[cfg(target_os = "linux")]
        let _config = config;
        #[cfg(target_os = "linux")]
        let _stats = stats;

        info!(
            "Periodic cleanup task registered (cleanup_interval={:?}). \
             Note: Automatic background cleanup is currently deferred; \
             use explicit cleanup() calls for session expiry.",
            _cleanup_interval
        );

        Ok(())
    }

    /// Stop periodic cleanup task
    #[instrument(skip(self))]
    pub async fn stop(&self) {
        info!("Stopping periodic cleanup task");
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Get cleanup statistics
    pub async fn get_stats(&self) -> CleanupStats {
        self.stats.read().await.clone()
    }

    /// Check if cleanup task is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cleanup_config_default() {
        let config = CleanupConfig::default();
        assert_eq!(config.cleanup_interval, Duration::from_secs(30));
        assert_eq!(config.session_max_age, Duration::from_secs(300));
    }

    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn test_cleanup_non_linux() {
        let config = CleanupConfig::default();
        let cleanup = MapCleanup::new(config);

        // Should succeed on non-Linux
        assert!(!cleanup.is_running().await);

        // Cleanup operations should be no-ops
        assert!(cleanup.cleanup_session(SessionId::new(1)).await.is_ok());
        assert_eq!(cleanup.periodic_cleanup().await.unwrap(), 0);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_cleanup_creation() {
        let map_manager = MapManager::new().expect("Failed to create map manager");
        let config = CleanupConfig::default();
        let cleanup = MapCleanup::new(Arc::new(RwLock::new(map_manager)), config);

        assert!(!cleanup.is_running().await);

        let stats = cleanup.get_stats().await;
        assert_eq!(stats.total_cleanups, 0);
        assert_eq!(stats.sessions_cleaned, 0);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_cleanup_start_stop() {
        let map_manager = MapManager::new().expect("Failed to create map manager");
        let config = CleanupConfig {
            cleanup_interval: Duration::from_millis(100),
            session_max_age: Duration::from_secs(1),
        };
        let cleanup = MapCleanup::new(Arc::new(RwLock::new(map_manager)), config);

        // Start cleanup - note: due to non-Send MapManager types, background
        // cleanup is deferred to manual cleanup() calls. The start() method
        // just marks the cleanup as "running" and logs the intent.
        cleanup.start().await.expect("Failed to start cleanup");
        assert!(cleanup.is_running().await);

        // Stop cleanup
        cleanup.stop().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!cleanup.is_running().await);

        // Stats remain at initial values since background cleanup is deferred
        let stats = cleanup.get_stats().await;
        assert_eq!(stats.total_cleanups, 0);
    }
}
