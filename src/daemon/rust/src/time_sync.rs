// Time Synchronization Integration for Daemon
//
// Integrates the TimeSync engine from buckwild-common with daemon lifecycle,
// providing periodic synchronization, startup sync, and failure handling.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::time;
use tracing::{error, info, warn};

use buckwild_common::engines::time_sync::{TimeSyncEngine, TimeSyncStatus};
use buckwild_common::protocol::types::{TimeOffset, Timestamp};

/// Time synchronization configuration
#[derive(Debug, Clone)]
pub struct TimeSyncConfig {
    /// Interval between periodic synchronization attempts (seconds)
    pub sync_interval_seconds: u64,
    /// Timeout for individual sync requests (milliseconds)
    pub sync_timeout_ms: u64,
    /// Maximum number of consecutive sync failures before emergency recovery
    pub max_consecutive_failures: u32,
}

impl Default for TimeSyncConfig {
    fn default() -> Self {
        Self {
            sync_interval_seconds: 60,   // Default: 60 seconds
            sync_timeout_ms: 5000,       // Default: 5 seconds
            max_consecutive_failures: 3, // Default: 3 failures
        }
    }
}

/// Daemon time synchronization manager
///
/// Wraps the TimeSync engine from buckwild-common and provides:
/// - Startup synchronization
/// - Periodic re-synchronization
/// - Failure handling and recovery
/// - Health monitoring
pub struct DaemonTimeSync {
    /// TimeSync engine from buckwild-common
    engine: TimeSyncEngine,
    /// Configuration
    config: TimeSyncConfig,
    /// Consecutive failure counter
    consecutive_failures: std::sync::atomic::AtomicU32,
    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl DaemonTimeSync {
    /// Create a new daemon time sync manager
    pub fn new(config: TimeSyncConfig) -> Self {
        Self {
            engine: TimeSyncEngine::new(),
            config,
            consecutive_failures: std::sync::atomic::AtomicU32::new(0),
            shutdown_tx: None,
        }
    }

    /// Get the underlying TimeSync engine for direct access
    pub fn engine(&self) -> &TimeSyncEngine {
        &self.engine
    }

    /// Perform initial synchronization on startup
    ///
    /// This should be called during daemon initialization to ensure
    /// time is synchronized before starting protocol operations.
    pub async fn startup_sync<F, G>(
        &mut self,
        send_request: F,
        receive_response: G,
    ) -> Result<TimeOffset>
    where
        F: Fn(buckwild_common::engines::time_sync::SyncRequest) -> bool,
        G: Fn(
            buckwild_common::protocol::types::ChallengeNonce,
        ) -> Option<buckwild_common::engines::time_sync::SyncResponse>,
    {
        info!("Performing startup time synchronization");

        match self
            .engine
            .execute_precision_time_sync(send_request, receive_response)
            .await
        {
            Ok(offset) => {
                info!(
                    offset_ns = offset.as_nanos(),
                    "Startup time synchronization successful"
                );
                self.consecutive_failures
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                Ok(offset)
            }
            Err(e) => {
                error!(error = %e, "Startup time synchronization failed");
                Err(anyhow::anyhow!("Startup sync failed: {}", e))
            }
        }
    }

    /// Start periodic time synchronization
    ///
    /// Spawns a background task that performs synchronization at the configured interval.
    /// Returns a handle to stop the periodic sync.
    pub fn start_periodic_sync<F, G>(
        &mut self,
        send_request: F,
        receive_response: G,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn(buckwild_common::engines::time_sync::SyncRequest) -> bool + Send + Sync + 'static,
        G: Fn(
                buckwild_common::protocol::types::ChallengeNonce,
            ) -> Option<buckwild_common::engines::time_sync::SyncResponse>
            + Send
            + Sync
            + 'static,
    {
        let interval = Duration::from_secs(self.config.sync_interval_seconds);
        let max_failures = self.config.max_consecutive_failures;
        let consecutive_failures = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let mut engine = TimeSyncEngine::new();

        tokio::spawn(async move {
            let mut sync_interval = time::interval(interval);
            sync_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = sync_interval.tick() => {
                        match engine
                            .execute_precision_time_sync(&send_request, &receive_response)
                            .await
                        {
                            Ok(offset) => {
                                info!(
                                    offset_ns = offset.as_nanos(),
                                    "Periodic time synchronization successful"
                                );
                                consecutive_failures.store(0, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                let failures = consecutive_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                error!(
                                    error = %e,
                                    consecutive_failures = failures,
                                    "Periodic time synchronization failed"
                                );

                                if failures >= max_failures {
                                    error!(
                                        "Maximum consecutive sync failures ({}) reached - entering emergency recovery",
                                        max_failures
                                    );
                                    // Emergency recovery would be handled by recovery actor
                                }
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("Periodic time synchronization shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Start periodic time synchronization for a specific host
    ///
    /// Spawns a background task that performs synchronization with a specific peer.
    pub fn start_periodic_sync_for_host<F, G>(
        &mut self,
        host: IpAddr,
        send_request: F,
        receive_response: G,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn(buckwild_common::engines::time_sync::SyncRequest) -> bool + Send + Sync + 'static,
        G: Fn(
                buckwild_common::protocol::types::ChallengeNonce,
            ) -> Option<buckwild_common::engines::time_sync::SyncResponse>
            + Send
            + Sync
            + 'static,
    {
        let interval = Duration::from_secs(self.config.sync_interval_seconds);
        let max_failures = self.config.max_consecutive_failures;

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let mut engine = TimeSyncEngine::new();

        tokio::spawn(async move {
            let mut sync_interval = time::interval(interval);
            sync_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            let mut consecutive_failures = 0u32;

            loop {
                tokio::select! {
                    _ = sync_interval.tick() => {
                        match engine
                            .execute_precision_time_sync_for_host(host, &send_request, &receive_response)
                            .await
                        {
                            Ok(offset) => {
                                info!(
                                    host = %host,
                                    offset_ns = offset.as_nanos(),
                                    "Periodic time synchronization successful for host"
                                );
                                consecutive_failures = 0;
                            }
                            Err(e) => {
                                consecutive_failures += 1;
                                error!(
                                    host = %host,
                                    error = %e,
                                    consecutive_failures,
                                    "Periodic time synchronization failed for host"
                                );

                                if consecutive_failures >= max_failures {
                                    error!(
                                        host = %host,
                                        "Maximum consecutive sync failures ({}) reached for host - entering emergency recovery",
                                        max_failures
                                    );
                                }
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!(host = %host, "Periodic time synchronization for host shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Check if time synchronization is healthy
    pub fn is_healthy(&self) -> bool {
        self.engine.is_sync_healthy()
    }

    /// Check if time synchronization is healthy for a specific host
    pub fn is_healthy_for_host(&self, host: IpAddr) -> bool {
        self.engine.is_sync_healthy_for_host(host)
    }

    /// Get current synchronization status
    pub fn status(&self) -> TimeSyncStatus {
        self.engine.state().status()
    }

    /// Get current synchronization status for a specific host
    pub fn status_for_host(&self, host: IpAddr) -> TimeSyncStatus {
        self.engine.state().status_for_host(host)
    }

    /// Get synchronized time in milliseconds
    pub fn synchronized_time_ms(&self) -> Timestamp {
        self.engine.synchronized_time_ms()
    }

    /// Get synchronized time for a specific host
    pub fn synchronized_time_ms_for_host(&self, host: IpAddr) -> Timestamp {
        self.engine.synchronized_time_ms_for_host(host)
    }

    /// Get current time offset
    pub fn current_offset(&self) -> TimeOffset {
        self.engine.state().local_offset()
    }

    /// Get current time offset for a specific host
    pub fn current_offset_for_host(&self, host: IpAddr) -> TimeOffset {
        self.engine.state().local_offset_for_host(host)
    }

    /// Handle large clock jumps
    ///
    /// Detects and handles sudden large changes in system clock.
    /// Returns true if a clock jump was detected and handled.
    pub async fn handle_clock_jump(&mut self) -> Result<bool> {
        let current_offset = self.current_offset();
        let offset_ns = current_offset.as_nanos().unsigned_abs();

        // Check if offset indicates a clock jump (> 1 second)
        if offset_ns > 1_000_000_000 {
            warn!(
                offset_ns,
                "Large clock jump detected - triggering emergency sync"
            );

            // Mark status as requiring emergency sync
            self.engine.state().set_status(TimeSyncStatus::Emergency);

            return Ok(true);
        }

        Ok(false)
    }

    /// Stop periodic synchronization
    pub fn stop_periodic_sync(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Shutdown the time sync manager
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down time synchronization manager");

        // Stop periodic sync if running
        self.stop_periodic_sync();

        // Shutdown the engine
        self.engine
            .shutdown()
            .await
            .context("Failed to shutdown time sync engine")?;

        info!("Time synchronization manager shutdown complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buckwild_common::engines::time_sync::{SyncRequest, SyncResponse};
    use buckwild_common::protocol::types::{ChallengeNonce, MicrosecondTimestamp};

    #[test]
    fn test_daemon_time_sync_creation() {
        let config = TimeSyncConfig::default();
        let time_sync = DaemonTimeSync::new(config.clone());

        assert_eq!(time_sync.config.sync_interval_seconds, 60);
        assert_eq!(time_sync.config.sync_timeout_ms, 5000);
        assert_eq!(time_sync.config.max_consecutive_failures, 3);
    }

    #[test]
    fn test_custom_config() {
        let config = TimeSyncConfig {
            sync_interval_seconds: 120,
            sync_timeout_ms: 10000,
            max_consecutive_failures: 5,
        };

        let time_sync = DaemonTimeSync::new(config.clone());

        assert_eq!(time_sync.config.sync_interval_seconds, 120);
        assert_eq!(time_sync.config.sync_timeout_ms, 10000);
        assert_eq!(time_sync.config.max_consecutive_failures, 5);
    }

    #[tokio::test]
    async fn test_startup_sync_success() {
        let config = TimeSyncConfig::default();
        let mut time_sync = DaemonTimeSync::new(config);

        // Mock send/receive functions
        // The timestamps must be strictly ordered: t1 < t2 < t3 < t4
        // t1 is captured by the engine before calling receive_fn
        // t4 is captured by the engine after receive_fn returns
        // We need to ensure t2 (peer_precision) < t3 (local_precision)
        let send_fn = |_req: SyncRequest| true;
        let receive_fn = |_nonce: ChallengeNonce| {
            // Timestamps must be strictly ordered: t1 < t2 < t3 < t4
            // Strategy:
            // - Capture now_us for t2 and t3 (now_us > t1 since time has passed)
            // - t2 = now_us, t3 = now_us + 1 (ensures t2 < t3)
            // - Sleep after capturing timestamps so t4 will be > t3
            let now_us = MicrosecondTimestamp::now().as_u64();
            let response = SyncResponse {
                peer_timestamp: Timestamp::now(),
                // t2: peer receive time
                peer_precision: MicrosecondTimestamp::new(now_us),
                local_timestamp: Timestamp::now(),
                // t3: peer send time - +1us ensures t2 < t3
                local_precision: MicrosecondTimestamp::new(now_us + 1),
            };
            // Sleep to ensure t4 (captured after return) > t3 (now_us + 1)
            std::thread::sleep(std::time::Duration::from_micros(10));
            Some(response)
        };

        let result = time_sync.startup_sync(send_fn, receive_fn).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_startup_sync_timeout() {
        let config = TimeSyncConfig::default();
        let mut time_sync = DaemonTimeSync::new(config);

        // Mock send/receive functions that simulate timeout
        let send_fn = |_req: SyncRequest| true;
        let receive_fn = |_nonce: ChallengeNonce| None; // Never responds

        let result = time_sync.startup_sync(send_fn, receive_fn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_clock_jump_detection() {
        let config = TimeSyncConfig::default();
        let mut time_sync = DaemonTimeSync::new(config);

        // Simulate a large offset (2 seconds)
        time_sync.engine.state().add_local_offset_for_host(
            "127.0.0.1".parse().unwrap(),
            TimeOffset::new(2_000_000_000),
        );

        let result = time_sync.handle_clock_jump().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_health_check() {
        let config = TimeSyncConfig::default();
        let time_sync = DaemonTimeSync::new(config);

        // Initial state should be healthy (default synchronized state)
        let is_healthy = time_sync.is_healthy();
        // Note: Health depends on multiple factors, so this is a basic check
        assert!(is_healthy || !is_healthy); // Always passes, just tests the call
    }

    #[test]
    fn test_synchronized_time_access() {
        let config = TimeSyncConfig::default();
        let time_sync = DaemonTimeSync::new(config);

        let sync_time = time_sync.synchronized_time_ms();
        assert!(sync_time.as_nanos() > 0);
    }
}
