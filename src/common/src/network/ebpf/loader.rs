//! eBPF program loader and manager
//!
//! ## TDD Status: GREEN Phase (Task 6)
//!
//! Provides APIs for loading XDP/TC programs, managing eBPF maps,
//! and handling port hopping updates.
//!
//! ## Design Note
//!
//! This is a stub/mock implementation that provides the API surface
//! for eBPF program management without requiring actual eBPF programs.
//! When actual eBPF .o files are available, this can be extended to
//! use the aya crate for real loading.

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use super::error::{LoaderError, LoaderResult};
use super::manager::EbpfManager;
use super::port_hopping::calculate_port_window;
use super::types::{AdaptiveStats, AdaptiveWindowConfig, PortHoppingConfig, TimeBucket};
use crate::protocol::types::SessionId;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info, instrument};

/// eBPF Program Loader Configuration
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// Path to XDP program .o file
    pub xdp_program_path: Option<String>,
    /// Path to TC program .o file
    pub tc_program_path: Option<String>,
    /// Port hopping configuration
    pub port_hopping: PortHoppingConfig,
    /// Port table update interval (default: 10 seconds)
    pub update_interval: Duration,
}

impl LoaderConfig {
    /// Create a new loader configuration
    pub fn new(port_hopping: PortHoppingConfig) -> Self {
        Self {
            xdp_program_path: None,
            tc_program_path: None,
            port_hopping,
            update_interval: Duration::from_secs(10),
        }
    }
}

/// Program attachment type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgramType {
    Xdp,
    Tc,
}

/// Shared loader state
struct LoaderState {
    /// Whether XDP program is attached
    xdp_attached: Mutex<Option<String>>,
    /// Whether TC program is attached
    tc_attached: Mutex<Option<String>>,
    /// Interface to attached program mapping (interface → program_type)
    interface_map: Mutex<HashMap<String, ProgramType>>,
    /// Port validity map (port → valid)
    port_map: Mutex<HashMap<u16, bool>>,
    /// Session routing map (session_id → ring_buffer_id)
    session_map: Mutex<HashMap<SessionId, u32>>,
    /// Adaptive window statistics
    early_count: AtomicU32,
    late_count: AtomicU32,
    /// Adaptive window configuration
    adaptive_window: Mutex<AdaptiveWindowConfig>,
}

impl LoaderState {
    fn new(adaptive_window: AdaptiveWindowConfig) -> Self {
        Self {
            xdp_attached: Mutex::new(None),
            tc_attached: Mutex::new(None),
            interface_map: Mutex::new(HashMap::new()),
            port_map: Mutex::new(HashMap::new()),
            session_map: Mutex::new(HashMap::new()),
            early_count: AtomicU32::new(0),
            late_count: AtomicU32::new(0),
            adaptive_window: Mutex::new(adaptive_window),
        }
    }
}

/// eBPF Program Loader
///
/// Manages lifecycle of XDP and TC eBPF programs, handles port hopping
/// updates, and manages eBPF maps.
///
/// ## Lifecycle
///
/// 1. Create loader with `new(config)`
/// 2. Load programs with `load_xdp()` and `load_tc()`
/// 3. Attach to interfaces with `attach_xdp()` and `attach_tc()`
/// 4. Start periodic updates with `start_port_updates()`
/// 5. Register sessions with `register_session()`
/// 6. Stop with `stop()` - gracefully detaches and cleans up
pub struct EbpfLoader {
    config: LoaderConfig,
    state: Arc<LoaderState>,
    update_task: Mutex<Option<JoinHandle<()>>>,
    shutdown_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

impl EbpfLoader {
    /// Create a new eBPF loader
    pub fn new(config: LoaderConfig) -> Self {
        let state = Arc::new(LoaderState::new(config.port_hopping.adaptive_window));

        Self {
            config,
            state,
            update_task: Mutex::new(None),
            shutdown_tx: Mutex::new(None),
        }
    }

    /// Load XDP program from file
    ///
    /// REQ-LOADER-001: Load XDP program
    ///
    /// # Errors
    ///
    /// Returns error if program file not found or verifier rejects program
    #[instrument(name = "ebpf.load_xdp", skip(self), fields(path = ?self.config.xdp_program_path))]
    pub async fn load_xdp(&mut self) -> LoaderResult<()> {
        // Stub implementation - would use aya crate with real eBPF programs
        info!("Loading XDP program (stub)");

        // Simulate loading from file
        if let Some(path) = &self.config.xdp_program_path {
            if !std::path::Path::new(path).exists() {
                return Err(LoaderError::Io {
                    operation: "load_xdp".to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Xdp program not found: {}", path),
                    ),
                });
            }
        }

        Ok(())
    }

    /// Attach XDP program to network interface
    ///
    /// REQ-LOADER-002: Attach XDP program to interface
    ///
    /// # Errors
    ///
    /// Returns error if interface not found or already attached
    #[instrument(name = "ebpf.attach_xdp", skip(self), fields(interface = %interface))]
    pub async fn attach_xdp(&mut self, interface: &str) -> LoaderResult<()> {
        let mut attached = self.state.xdp_attached.lock();

        if let Some(ref current) = *attached {
            return Err(LoaderError::AlreadyAttached {
                interface: current.clone(),
            });
        }

        // Stub implementation - would use aya to actually attach
        info!(interface = %interface, "Attaching XDP program (stub)");

        *attached = Some(interface.to_string());

        // Track interface attachment
        let mut interface_map = self.state.interface_map.lock();
        interface_map.insert(interface.to_string(), ProgramType::Xdp);

        Ok(())
    }

    /// Detach XDP program from network interface
    ///
    /// REQ-LOADER-003: Detach XDP program
    ///
    /// # Errors
    ///
    /// Returns error if not attached to specified interface
    #[instrument(name = "ebpf.detach_xdp", skip(self), fields(interface = %interface))]
    pub async fn detach_xdp(&mut self, interface: &str) -> LoaderResult<()> {
        let mut attached = self.state.xdp_attached.lock();

        match attached.as_ref() {
            Some(current) if current == interface => {
                info!(interface = %interface, "Detaching XDP program (stub)");
                *attached = None;

                // Remove from interface tracking
                let mut interface_map = self.state.interface_map.lock();
                interface_map.remove(interface);

                Ok(())
            }
            Some(current) => Err(LoaderError::NotAttached {
                interface: current.clone(),
            }),
            None => Err(LoaderError::NotAttached {
                interface: interface.to_string(),
            }),
        }
    }

    /// Load TC egress program from file
    ///
    /// REQ-LOADER-004: Load TC egress program
    ///
    /// # Errors
    ///
    /// Returns error if program file not found or verifier rejects program
    #[instrument(name = "ebpf.load_tc", skip(self), fields(path = ?self.config.tc_program_path))]
    pub async fn load_tc(&mut self) -> LoaderResult<()> {
        // Stub implementation
        info!("Loading TC egress program (stub)");

        if let Some(path) = &self.config.tc_program_path {
            if !std::path::Path::new(path).exists() {
                return Err(LoaderError::Io {
                    operation: "load_tc".to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("TC program not found: {}", path),
                    ),
                });
            }
        }

        Ok(())
    }

    /// Attach TC egress program to interface
    ///
    /// # Errors
    ///
    /// Returns error if interface not found or already attached
    pub async fn attach_tc(&mut self, interface: &str) -> LoaderResult<()> {
        let mut attached = self.state.tc_attached.lock();

        if let Some(ref current) = *attached {
            return Err(LoaderError::AlreadyAttached {
                interface: current.clone(),
            });
        }

        info!(interface = %interface, "Attaching TC egress program (stub)");

        *attached = Some(interface.to_string());

        // Track interface attachment
        let mut interface_map = self.state.interface_map.lock();
        interface_map.insert(interface.to_string(), ProgramType::Tc);

        Ok(())
    }

    /// Detach TC egress program from network interface
    ///
    /// # Errors
    ///
    /// Returns error if not attached to specified interface
    #[instrument(name = "ebpf.detach_tc", skip(self), fields(interface = %interface))]
    pub async fn detach_tc(&mut self, interface: &str) -> LoaderResult<()> {
        let mut attached = self.state.tc_attached.lock();

        match attached.as_ref() {
            Some(current) if current == interface => {
                info!(interface = %interface, "Detaching TC program (stub)");
                *attached = None;

                // Remove from interface tracking
                let mut interface_map = self.state.interface_map.lock();
                interface_map.remove(interface);

                Ok(())
            }
            Some(current) => Err(LoaderError::NotAttached {
                interface: current.clone(),
            }),
            None => Err(LoaderError::NotAttached {
                interface: interface.to_string(),
            }),
        }
    }

    /// Get list of interfaces with attached programs
    ///
    /// Returns a vector of interface names that have either XDP or TC programs attached
    pub fn get_attached_interfaces(&self) -> Vec<String> {
        let interface_map = self.state.interface_map.lock();
        interface_map.keys().cloned().collect()
    }

    /// Update port validity map with current port hopping schedule
    ///
    /// REQ-LOADER-006: Populate port_validity_map
    ///
    /// Calculates valid ports for current time bucket plus adaptive window
    /// and updates the port validity map.
    #[instrument(name = "ebpf.update_port_table", skip(self))]
    pub async fn update_port_table(&mut self) -> LoaderResult<()> {
        // Calculate current time bucket
        let now = std::time::SystemTime::now();
        let duration_since_epoch = now.duration_since(std::time::UNIX_EPOCH).map_err(|e| {
            LoaderError::InvalidConfiguration {
                reason: format!("System time before UNIX epoch: {}", e),
            }
        })?;

        // Calculate milliseconds since midnight UTC
        let total_ms = duration_since_epoch.as_millis() as u64;
        let millis_in_day = 24 * 60 * 60 * 1000;
        let millis_since_midnight = total_ms % millis_in_day;

        let current_bucket = TimeBucket::from_millis(
            millis_since_midnight,
            self.config.port_hopping.hop_interval_ms,
        );

        // Calculate bucket counts for adaptive window
        let adaptive = *self.state.adaptive_window.lock();
        let past_buckets = adaptive.past_window_ms / self.config.port_hopping.hop_interval_ms;
        let future_buckets = adaptive.future_window_ms / self.config.port_hopping.hop_interval_ms;

        // Calculate valid ports
        let valid_ports = calculate_port_window(
            &self.config.port_hopping.daily_key,
            current_bucket,
            past_buckets,
            future_buckets,
        );

        // Update port map (clear old entries, add new ones)
        let mut port_map = self.state.port_map.lock();
        port_map.clear();
        for port in valid_ports {
            port_map.insert(port, true);
        }

        info!(
            current_bucket = %current_bucket,
            valid_ports = port_map.len(),
            "Updated port validity map"
        );

        Ok(())
    }

    /// Start periodic port table updates
    ///
    /// REQ-LOADER-007: Update port_validity_map periodically
    ///
    /// Spawns a background task that updates the port table at the
    /// configured interval.
    #[instrument(name = "ebpf.start_port_updates", skip(self))]
    pub async fn start_port_updates(&mut self) -> LoaderResult<()> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);

        let interval = self.config.update_interval;
        let daily_key = self.config.port_hopping.daily_key.clone();
        let hop_interval_ms = self.config.port_hopping.hop_interval_ms;
        let state = self.state.clone();

        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Port update task shutting down");
                        break;
                    }
                    _ = ticker.tick() => {
                        // Calculate current bucket and update port map
                        if let Ok(now) = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                        {
                            let total_ms = now.as_millis() as u64;
                            let millis_in_day = 24 * 60 * 60 * 1000;
                            let millis_since_midnight = total_ms % millis_in_day;

                            let current_bucket = TimeBucket::from_millis(millis_since_midnight, hop_interval_ms);

                            let adaptive = *state.adaptive_window.lock();
                            let past_buckets = adaptive.past_window_ms / hop_interval_ms;
                            let future_buckets = adaptive.future_window_ms / hop_interval_ms;

                            let valid_ports = calculate_port_window(
                                &daily_key,
                                current_bucket,
                                past_buckets,
                                future_buckets,
                            );

                            let mut port_map = state.port_map.lock();
                            port_map.clear();
                            for port in valid_ports {
                                port_map.insert(port, true);
                            }

                            info!(
                                current_bucket = %current_bucket,
                                valid_ports = port_map.len(),
                                "Periodic port table update"
                            );
                        } else {
                            error!("Failed to get system time for port update");
                        }
                    }
                }
            }
        });

        *self.update_task.lock() = Some(task);
        *self.shutdown_tx.lock() = Some(shutdown_tx);

        Ok(())
    }

    /// Register a session in the routing map
    ///
    /// REQ-LOADER-009: Register sessions in session_routing_map
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    /// * `ring_buffer_id` - Ring buffer ID for this session
    #[instrument(name = "ebpf.register_session", skip(self))]
    pub async fn register_session(
        &mut self,
        session_id: SessionId,
        ring_buffer_id: u32,
    ) -> LoaderResult<()> {
        let mut session_map = self.state.session_map.lock();
        session_map.insert(session_id.clone(), ring_buffer_id);

        info!(
            session_id = ?session_id,
            ring_buffer_id = ring_buffer_id,
            "Registered session"
        );

        Ok(())
    }

    /// Unregister a session from the routing map
    ///
    /// REQ-LOADER-010: Unregister sessions from routing map
    ///
    /// # Errors
    ///
    /// Returns error if session not found
    #[instrument(name = "ebpf.unregister_session", skip(self))]
    pub async fn unregister_session(&mut self, session_id: SessionId) -> LoaderResult<()> {
        let mut session_map = self.state.session_map.lock();

        if session_map.remove(&session_id).is_none() {
            return Err(LoaderError::SessionNotFound);
        }

        info!(session_id = ?session_id, "Unregistered session");

        Ok(())
    }

    /// Configure adaptive delay windows
    ///
    /// REQ-LOADER-008: Configure adaptive_window_map
    ///
    /// # Arguments
    ///
    /// * `past_ms` - Past window size in milliseconds
    /// * `future_ms` - Future window size in milliseconds
    #[instrument(name = "ebpf.set_adaptive_window", skip(self))]
    pub async fn set_adaptive_window(&mut self, past_ms: u32, future_ms: u32) -> LoaderResult<()> {
        let mut adaptive = self.state.adaptive_window.lock();
        adaptive.past_window_ms = past_ms;
        adaptive.future_window_ms = future_ms;

        info!(
            past_window_ms = past_ms,
            future_window_ms = future_ms,
            "Updated adaptive window configuration"
        );

        Ok(())
    }

    /// Get adaptive delay statistics
    ///
    /// REQ-LOADER-012: Read statistics from adaptive_window_map
    pub fn get_adaptive_stats(&self) -> AdaptiveStats {
        AdaptiveStats {
            early_count: self.state.early_count.load(Ordering::Relaxed),
            late_count: self.state.late_count.load(Ordering::Relaxed),
        }
    }

    /// Check if port is currently valid
    ///
    /// Helper method for testing
    pub fn is_port_valid(&self, port: u16) -> bool {
        self.state
            .port_map
            .lock()
            .get(&port)
            .copied()
            .unwrap_or(false)
    }

    /// Stop the loader and clean up resources
    ///
    /// Detaches programs, stops update task, clears maps
    #[instrument(name = "ebpf.stop", skip(self))]
    pub async fn stop(&mut self) -> LoaderResult<()> {
        // Stop update task
        let shutdown_tx = self.shutdown_tx.lock().take();
        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(()).await;
        }

        let task = self.update_task.lock().take();
        if let Some(task) = task {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }

        // Detach programs (stub)
        let xdp_interface = self.state.xdp_attached.lock().take();
        if let Some(interface) = xdp_interface {
            info!(interface = %interface, "Detaching XDP program on stop");
        }

        let tc_interface = self.state.tc_attached.lock().take();
        if let Some(interface) = tc_interface {
            info!(interface = %interface, "Detaching TC program on stop");
        }

        // Clear maps
        self.state.port_map.lock().clear();
        self.state.session_map.lock().clear();
        self.state.interface_map.lock().clear();

        info!("eBPF loader stopped and cleaned up");

        Ok(())
    }
}

// Implement EbpfManager trait for EbpfLoader
#[async_trait::async_trait]
impl EbpfManager for EbpfLoader {
    async fn load_xdp(&mut self) -> LoaderResult<()> {
        self.load_xdp().await
    }

    async fn load_tc(&mut self) -> LoaderResult<()> {
        self.load_tc().await
    }

    async fn attach_xdp(&mut self, interface: &str) -> LoaderResult<()> {
        self.attach_xdp(interface).await
    }

    async fn attach_tc(&mut self, interface: &str) -> LoaderResult<()> {
        self.attach_tc(interface).await
    }

    async fn detach_xdp(&mut self, interface: &str) -> LoaderResult<()> {
        self.detach_xdp(interface).await
    }

    async fn detach_tc(&mut self, interface: &str) -> LoaderResult<()> {
        self.detach_tc(interface).await
    }

    async fn update_port_table(&mut self) -> LoaderResult<()> {
        self.update_port_table().await
    }

    async fn start_port_updates(&mut self) -> LoaderResult<()> {
        self.start_port_updates().await
    }

    async fn register_session(
        &mut self,
        session_id: SessionId,
        ring_buffer_id: u32,
    ) -> LoaderResult<()> {
        self.register_session(session_id, ring_buffer_id).await
    }

    async fn unregister_session(&mut self, session_id: SessionId) -> LoaderResult<()> {
        self.unregister_session(session_id).await
    }

    async fn set_adaptive_window(&mut self, past_ms: u32, future_ms: u32) -> LoaderResult<()> {
        self.set_adaptive_window(past_ms, future_ms).await
    }

    fn get_adaptive_stats(&self) -> AdaptiveStats {
        self.get_adaptive_stats()
    }

    fn is_port_valid(&self, port: u16) -> bool {
        self.is_port_valid(port)
    }

    async fn stop(&mut self) -> LoaderResult<()> {
        self.stop().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> LoaderConfig {
        let daily_key = vec![0x42; 32];
        let port_hopping =
            PortHoppingConfig::new(daily_key, 500, AdaptiveWindowConfig::default()).unwrap();

        LoaderConfig::new(port_hopping)
    }

    #[tokio::test]
    async fn test_loader_creation() {
        let config = create_test_config();
        let loader = EbpfLoader::new(config);

        let stats = loader.get_adaptive_stats();
        assert_eq!(stats.early_count, 0);
        assert_eq!(stats.late_count, 0);
    }

    #[tokio::test]
    async fn test_xdp_attach_detach() {
        let config = create_test_config();
        let mut loader = EbpfLoader::new(config);

        loader.load_xdp().await.expect("Load should succeed");
        loader
            .attach_xdp("lo")
            .await
            .expect("Attach should succeed");

        // Second attach should fail
        let result = loader.attach_xdp("lo").await;
        assert!(result.is_err());

        loader
            .detach_xdp("lo")
            .await
            .expect("Detach should succeed");

        // Second detach should fail
        let result = loader.detach_xdp("lo").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_registration() {
        let config = create_test_config();
        let mut loader = EbpfLoader::new(config);

        let session_id = SessionId::new(42);

        loader
            .register_session(session_id.clone(), 5)
            .await
            .expect("Registration should succeed");

        loader
            .unregister_session(session_id.clone())
            .await
            .expect("Unregistration should succeed");

        // Second unregister should fail
        let result = loader.unregister_session(session_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_adaptive_window_config() {
        let config = create_test_config();
        let mut loader = EbpfLoader::new(config);

        loader
            .set_adaptive_window(250, 500)
            .await
            .expect("Set adaptive window should succeed");

        // Verify configuration was updated
        let adaptive = *loader.state.adaptive_window.lock();
        assert_eq!(adaptive.past_window_ms, 250);
        assert_eq!(adaptive.future_window_ms, 500);
    }

    #[tokio::test]
    async fn test_port_table_update() {
        let config = create_test_config();
        let mut loader = EbpfLoader::new(config);

        loader
            .update_port_table()
            .await
            .expect("Update should succeed");

        // Verify some ports were added
        let port_count = loader.state.port_map.lock().len();
        assert!(port_count > 0, "Port table should have entries");
    }

    #[tokio::test]
    async fn test_interface_tracking() {
        let config = create_test_config();
        let mut loader = EbpfLoader::new(config);

        // Initially no interfaces attached
        assert_eq!(loader.get_attached_interfaces().len(), 0);

        // Attach XDP to eth0
        loader.load_xdp().await.expect("Load should succeed");
        loader
            .attach_xdp("eth0")
            .await
            .expect("Attach should succeed");

        let interfaces = loader.get_attached_interfaces();
        assert_eq!(interfaces.len(), 1);
        assert!(interfaces.contains(&"eth0".to_string()));

        // Attach TC to eth1
        loader.load_tc().await.expect("Load should succeed");
        loader
            .attach_tc("eth1")
            .await
            .expect("Attach should succeed");

        let interfaces = loader.get_attached_interfaces();
        assert_eq!(interfaces.len(), 2);
        assert!(interfaces.contains(&"eth0".to_string()));
        assert!(interfaces.contains(&"eth1".to_string()));

        // Detach XDP from eth0
        loader
            .detach_xdp("eth0")
            .await
            .expect("Detach should succeed");

        let interfaces = loader.get_attached_interfaces();
        assert_eq!(interfaces.len(), 1);
        assert!(interfaces.contains(&"eth1".to_string()));

        // Detach TC from eth1
        loader
            .detach_tc("eth1")
            .await
            .expect("Detach should succeed");

        assert_eq!(loader.get_attached_interfaces().len(), 0);
    }

    #[tokio::test]
    async fn test_interface_tracking_stop_cleanup() {
        let config = create_test_config();
        let mut loader = EbpfLoader::new(config);

        // Attach programs to interfaces
        loader.load_xdp().await.expect("Load should succeed");
        loader
            .attach_xdp("eth0")
            .await
            .expect("Attach should succeed");

        loader.load_tc().await.expect("Load should succeed");
        loader
            .attach_tc("eth1")
            .await
            .expect("Attach should succeed");

        assert_eq!(loader.get_attached_interfaces().len(), 2);

        // Stop should clear interface map
        loader.stop().await.expect("Stop should succeed");

        assert_eq!(loader.get_attached_interfaces().len(), 0);
    }

    #[tokio::test]
    async fn test_tc_detach() {
        let config = create_test_config();
        let mut loader = EbpfLoader::new(config);

        loader.load_tc().await.expect("Load should succeed");
        loader.attach_tc("lo").await.expect("Attach should succeed");

        loader.detach_tc("lo").await.expect("Detach should succeed");

        // Second detach should fail
        let result = loader.detach_tc("lo").await;
        assert!(result.is_err());

        // Detaching wrong interface should fail
        loader
            .attach_tc("eth0")
            .await
            .expect("Attach should succeed");

        let result = loader.detach_tc("eth1").await;
        assert!(result.is_err());
    }
}
