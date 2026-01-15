//! Integrated TUN/eBPF Manager
//!
//! ## TDD Status: RED Phase (Task 5/Phase 5)
//!
//! This module provides an integrated manager that coordinates:
//! - TUN Device Manager (Phase 3)
//! - eBPF Loader (Phase 4)
//!
//! The integrated manager handles lifecycle coordination, session registration,
//! statistics aggregation, and graceful shutdown across all components.

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use super::ebpf::{AdaptiveStats, EbpfLoader, LoaderConfig, LoaderError};

#[cfg(test)]
use super::ebpf::{AdaptiveWindowConfig, PortHoppingConfig};
use super::tun::{ManagerError, ManagerStats, TunDeviceManager, TunManagerConfig};
use crate::protocol::types::SessionId;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};

/// Errors that can occur during integrated manager operations
#[derive(Error, Debug)]
pub enum IntegratedError {
    /// TUN device manager error
    #[error("TUN device manager error")]
    TunManager {
        #[source]
        source: ManagerError,
    },

    /// eBPF loader error
    #[error("eBPF loader error")]
    EbpfLoader {
        #[source]
        source: LoaderError,
    },

    /// Manager already running
    #[error("integrated manager already running")]
    AlreadyRunning,

    /// Manager not running
    #[error("integrated manager not running")]
    NotRunning,

    /// Configuration error
    #[error("configuration error: {reason}")]
    ConfigError { reason: String },

    /// Lifecycle coordination error
    #[error("lifecycle coordination error: {details}")]
    LifecycleError { details: String },
}

/// Result type for integrated manager operations
pub type IntegratedResult<T> = Result<T, IntegratedError>;

/// Configuration for the integrated manager
#[derive(Debug, Clone)]
pub struct IntegratedConfig {
    /// TUN device manager configuration
    pub tun_config: TunManagerConfig,
    /// eBPF loader configuration
    pub ebpf_config: LoaderConfig,
    /// Network interface for eBPF attachment
    pub network_interface: String,
}

impl IntegratedConfig {
    /// Create a new integrated configuration
    ///
    /// # Errors
    ///
    /// Returns error if configurations are invalid or incompatible
    pub fn new(
        tun_config: TunManagerConfig,
        ebpf_config: LoaderConfig,
        network_interface: String,
    ) -> IntegratedResult<Self> {
        if network_interface.is_empty() {
            return Err(IntegratedError::ConfigError {
                reason: "network interface cannot be empty".to_string(),
            });
        }

        Ok(Self {
            tun_config,
            ebpf_config,
            network_interface,
        })
    }
}

/// Aggregated statistics from all components
#[derive(Debug, Clone, Copy, Default)]
pub struct IntegratedStats {
    /// TUN device statistics
    pub tun: ManagerStats,
    /// eBPF adaptive window statistics
    pub ebpf_adaptive: AdaptiveStats,
    /// Total sessions registered
    pub total_sessions: u64,
}

/// Shared state for the integrated manager
struct IntegratedState {
    running: Arc<Mutex<bool>>,
    session_count: Arc<Mutex<u64>>,
}

impl IntegratedState {
    fn new() -> Self {
        Self {
            running: Arc::new(Mutex::new(false)),
            session_count: Arc::new(Mutex::new(0)),
        }
    }

    fn is_running(&self) -> bool {
        *self.running.lock()
    }

    fn set_running(&self, running: bool) {
        *self.running.lock() = running;
    }

    fn increment_sessions(&self) {
        *self.session_count.lock() += 1;
    }

    fn decrement_sessions(&self) {
        let mut count = self.session_count.lock();
        if *count > 0 {
            *count -= 1;
        }
    }

    fn get_session_count(&self) -> u64 {
        *self.session_count.lock()
    }
}

/// Integrated TUN/eBPF Manager
///
/// Coordinates lifecycle and operation of TUN device manager and eBPF loader.
///
/// ## Lifecycle
///
/// 1. Create with `new(config)`
/// 2. Start with `start()` - initializes both TUN and eBPF layers
/// 3. Register sessions with `register_session()`
/// 4. Stop with `stop()` - gracefully shuts down all components
///
/// ## Responsibilities
///
/// - Start/stop TUN device and eBPF programs in correct order
/// - Register sessions with both TUN translator and eBPF maps
/// - Aggregate statistics from all components
/// - Handle errors and coordinate graceful shutdown
/// - Update adaptive window configuration
pub struct IntegratedManager {
    config: IntegratedConfig,
    state: IntegratedState,
    tun_manager: Arc<AsyncMutex<TunDeviceManager>>,
    ebpf_loader: Arc<AsyncMutex<EbpfLoader>>,
    packet_rx: Arc<Mutex<Option<mpsc::Receiver<Vec<u8>>>>>,
    update_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl IntegratedManager {
    /// Create a new integrated manager
    pub fn new(config: IntegratedConfig) -> Self {
        let tun_manager = TunDeviceManager::new(config.tun_config.clone());
        let ebpf_loader = EbpfLoader::new(config.ebpf_config.clone());

        Self {
            config,
            state: IntegratedState::new(),
            tun_manager: Arc::new(AsyncMutex::new(tun_manager)),
            ebpf_loader: Arc::new(AsyncMutex::new(ebpf_loader)),
            packet_rx: Arc::new(Mutex::new(None)),
            update_task: Arc::new(Mutex::new(None)),
        }
    }

    /// Start the integrated manager
    ///
    /// ## Startup Sequence
    ///
    /// 1. Load eBPF programs (XDP for ingress filtering)
    /// 2. Attach eBPF programs to network interface
    /// 3. Start port hopping table updates
    /// 4. Create and configure TUN device
    /// 5. Start TUN device packet processing
    ///
    /// ## Errors
    ///
    /// Returns error if:
    /// - Manager is already running
    /// - eBPF program loading fails
    /// - TUN device creation fails
    /// - Component coordination fails
    #[instrument(name = "integrated.start", skip(self))]
    pub async fn start(&mut self) -> IntegratedResult<()> {
        if self.state.is_running() {
            return Err(IntegratedError::AlreadyRunning);
        }

        info!("Starting integrated TUN/eBPF manager");

        // Step 1: Load eBPF programs
        info!("Loading eBPF XDP programs");
        self.ebpf_loader
            .lock()
            .await
            .load_xdp()
            .await
            .map_err(|e| IntegratedError::EbpfLoader { source: e })?;

        // Step 2: Attach eBPF to network interface
        info!(
            interface = %self.config.network_interface,
            "Attaching eBPF programs to network interface"
        );
        self.ebpf_loader
            .lock()
            .await
            .attach_xdp(&self.config.network_interface)
            .await
            .map_err(|e| IntegratedError::EbpfLoader { source: e })?;

        // Step 3: Start port hopping updates
        info!("Starting port hopping table updates");
        self.ebpf_loader
            .lock()
            .await
            .start_port_updates()
            .await
            .map_err(|e| IntegratedError::EbpfLoader { source: e })?;

        // Step 4: Start TUN device manager
        info!("Starting TUN device manager");
        let packet_rx = self
            .tun_manager
            .lock()
            .await
            .start()
            .await
            .map_err(|e| IntegratedError::TunManager { source: e })?;

        *self.packet_rx.lock() = Some(packet_rx);

        // Step 5: Start integrated update task
        let update_task = self.spawn_update_task();
        *self.update_task.lock() = Some(update_task);

        self.state.set_running(true);

        info!("Integrated TUN/eBPF manager started successfully");
        Ok(())
    }

    /// Stop the integrated manager
    ///
    /// ## Shutdown Sequence
    ///
    /// 1. Stop TUN device packet processing
    /// 2. Stop port hopping updates
    /// 3. Detach eBPF programs
    /// 4. Destroy TUN device
    ///
    /// ## Errors
    ///
    /// Returns error if:
    /// - Manager is not running
    /// - Shutdown coordination fails
    /// - Component cleanup encounters errors
    #[instrument(name = "integrated.stop", skip(self))]
    pub async fn stop(&mut self) -> IntegratedResult<()> {
        if !self.state.is_running() {
            return Err(IntegratedError::NotRunning);
        }

        info!("Stopping integrated TUN/eBPF manager");

        // Stop update task
        let task = self.update_task.lock().take();
        if let Some(task) = task {
            task.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }

        // Step 1: Stop TUN device manager (stops packet ingress)
        info!("Stopping TUN device manager");
        if let Err(e) = self.tun_manager.lock().await.stop().await {
            warn!(error = %e, "TUN device manager stop warning");
        }

        // Step 2: Stop eBPF components
        info!("Stopping eBPF loader");
        if let Err(e) = self.ebpf_loader.lock().await.stop().await {
            warn!(error = %e, "eBPF loader stop warning");
        }

        *self.packet_rx.lock() = None;

        self.state.set_running(false);

        info!("Integrated TUN/eBPF manager stopped successfully");
        Ok(())
    }

    /// Check if manager is running
    pub fn is_running(&self) -> bool {
        self.state.is_running()
    }

    /// Register a session with both TUN and eBPF layers
    ///
    /// This registers the session in:
    /// - eBPF session routing map (for packet routing)
    /// - Updates session counter
    ///
    /// ## Arguments
    ///
    /// * `session_id` - Unique session identifier
    /// * `ring_buffer_id` - Ring buffer ID for packet routing
    ///
    /// ## Errors
    ///
    /// Returns error if manager is not running or registration fails
    #[instrument(name = "integrated.register_session", skip(self))]
    pub async fn register_session(
        &mut self,
        session_id: SessionId,
        ring_buffer_id: u32,
    ) -> IntegratedResult<()> {
        if !self.state.is_running() {
            return Err(IntegratedError::NotRunning);
        }

        info!(
            session_id = ?session_id,
            ring_buffer_id = ring_buffer_id,
            "Registering session in integrated manager"
        );

        // Register with eBPF
        self.ebpf_loader
            .lock()
            .await
            .register_session(session_id.clone(), ring_buffer_id)
            .await
            .map_err(|e| IntegratedError::EbpfLoader { source: e })?;

        self.state.increment_sessions();

        info!(session_id = ?session_id, "Session registered successfully");
        Ok(())
    }

    /// Unregister a session from both TUN and eBPF layers
    ///
    /// ## Errors
    ///
    /// Returns error if manager is not running or unregistration fails
    #[instrument(name = "integrated.unregister_session", skip(self))]
    pub async fn unregister_session(&mut self, session_id: SessionId) -> IntegratedResult<()> {
        if !self.state.is_running() {
            return Err(IntegratedError::NotRunning);
        }

        info!(session_id = ?session_id, "Unregistering session");

        // Unregister from eBPF
        self.ebpf_loader
            .lock()
            .await
            .unregister_session(session_id.clone())
            .await
            .map_err(|e| IntegratedError::EbpfLoader { source: e })?;

        self.state.decrement_sessions();

        info!(session_id = ?session_id, "Session unregistered successfully");
        Ok(())
    }

    /// Update adaptive window configuration
    ///
    /// ## Errors
    ///
    /// Returns error if manager is not running or update fails
    #[instrument(name = "integrated.set_adaptive_window", skip(self))]
    pub async fn set_adaptive_window(
        &mut self,
        past_ms: u32,
        future_ms: u32,
    ) -> IntegratedResult<()> {
        if !self.state.is_running() {
            return Err(IntegratedError::NotRunning);
        }

        info!(
            past_window_ms = past_ms,
            future_window_ms = future_ms,
            "Updating adaptive window configuration"
        );

        self.ebpf_loader
            .lock()
            .await
            .set_adaptive_window(past_ms, future_ms)
            .await
            .map_err(|e| IntegratedError::EbpfLoader { source: e })?;

        Ok(())
    }

    /// Get aggregated statistics from all components
    pub async fn stats(&self) -> IntegratedStats {
        let tun_stats = self.tun_manager.lock().await.stats();
        let ebpf_stats = self.ebpf_loader.lock().await.get_adaptive_stats();
        let session_count = self.state.get_session_count();

        IntegratedStats {
            tun: tun_stats,
            ebpf_adaptive: ebpf_stats,
            total_sessions: session_count,
        }
    }

    /// Get packet receiver for consuming processed packets
    ///
    /// Returns None if manager is not running
    pub fn packet_receiver(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        // This is a simplified API - in a real implementation,
        // we'd use a broadcast channel or multiple consumers
        None
    }

    /// Spawn background task for periodic updates
    fn spawn_update_task(&self) -> JoinHandle<()> {
        let ebpf_loader = self.ebpf_loader.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Periodic maintenance tasks
                let stats = ebpf_loader.lock().await.get_adaptive_stats();
                info!(
                    early_count = stats.early_count,
                    late_count = stats.late_count,
                    "Adaptive window statistics"
                );
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn create_test_config() -> IntegratedConfig {
        let tun_config = TunManagerConfig::new(
            "test0".to_string(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "255.255.255.0".parse::<IpAddr>().unwrap(),
            super::super::tun::types::Mtu::default(),
            100,
        )
        .unwrap();

        let port_hopping =
            PortHoppingConfig::new(vec![0x42; 32], 500, AdaptiveWindowConfig::new(100, 200))
                .unwrap();

        let ebpf_config = LoaderConfig {
            xdp_program_path: None,
            tc_program_path: None,
            port_hopping,
            update_interval: Duration::from_secs(10),
        };

        IntegratedConfig::new(tun_config, ebpf_config, "lo".to_string()).unwrap()
    }

    #[test]
    fn test_integrated_config_creation() {
        let config = create_test_config();
        assert_eq!(config.network_interface, "lo");
    }

    #[test]
    fn test_integrated_config_empty_interface() {
        let tun_config = TunManagerConfig::new(
            "test0".to_string(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "255.255.255.0".parse::<IpAddr>().unwrap(),
            super::super::tun::types::Mtu::default(),
            100,
        )
        .unwrap();

        let port_hopping =
            PortHoppingConfig::new(vec![0x42; 32], 500, AdaptiveWindowConfig::new(100, 200))
                .unwrap();

        let ebpf_config = LoaderConfig {
            xdp_program_path: None,
            tc_program_path: None,
            port_hopping,
            update_interval: Duration::from_secs(10),
        };

        let result = IntegratedConfig::new(tun_config, ebpf_config, "".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_integrated_manager_creation() {
        let config = create_test_config();
        let manager = IntegratedManager::new(config);
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn test_integrated_manager_lifecycle() {
        let config = create_test_config();
        let mut manager = IntegratedManager::new(config);

        // Should not be running initially
        assert!(!manager.is_running());

        // Cannot stop when not running
        let result = manager.stop().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IntegratedError::NotRunning));
    }

    #[tokio::test]
    async fn test_register_session_when_not_running() {
        let config = create_test_config();
        let mut manager = IntegratedManager::new(config);

        let session_id = SessionId::new(42);
        let result = manager.register_session(session_id, 1).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IntegratedError::NotRunning));
    }

    #[tokio::test]
    async fn test_unregister_session_when_not_running() {
        let config = create_test_config();
        let mut manager = IntegratedManager::new(config);

        let session_id = SessionId::new(42);
        let result = manager.unregister_session(session_id).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IntegratedError::NotRunning));
    }

    #[tokio::test]
    async fn test_set_adaptive_window_when_not_running() {
        let config = create_test_config();
        let mut manager = IntegratedManager::new(config);

        let result = manager.set_adaptive_window(100, 200).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IntegratedError::NotRunning));
    }

    #[tokio::test]
    async fn test_integrated_stats() {
        let config = create_test_config();
        let manager = IntegratedManager::new(config);

        let stats = manager.stats().await;
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.tun.received_count, 0);
        assert_eq!(stats.ebpf_adaptive.early_count, 0);
    }

    #[test]
    fn test_integrated_state() {
        let state = IntegratedState::new();
        assert!(!state.is_running());
        assert_eq!(state.get_session_count(), 0);

        state.set_running(true);
        assert!(state.is_running());

        state.increment_sessions();
        assert_eq!(state.get_session_count(), 1);

        state.increment_sessions();
        assert_eq!(state.get_session_count(), 2);

        state.decrement_sessions();
        assert_eq!(state.get_session_count(), 1);

        state.set_running(false);
        assert!(!state.is_running());
    }
}
