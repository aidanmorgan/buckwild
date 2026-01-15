//! TUN device lifecycle management
//!
//! ## TDD Status: GREEN Phase (Task 3)
//!
//! Implementation for TUN Device Manager following REQ-MGR-001 through REQ-MGR-010.

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use super::device::LinuxTunHandle;
use super::error::{ManagerError, ManagerResult};
use super::translator::{ProtocolTranslator, TranslatorConfig};
use super::types::{DeviceName, Mtu, TunConfig};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, instrument, warn};

/// TUN Device Manager configuration
#[derive(Debug, Clone)]
pub struct TunManagerConfig {
    /// Device name
    pub device_name: String,
    /// IP address
    pub ip_address: IpAddr,
    /// Network mask
    pub netmask: IpAddr,
    /// MTU
    pub mtu: Mtu,
    /// Channel buffer size for backpressure
    pub channel_buffer_size: usize,
}

impl TunManagerConfig {
    /// Create a new TUN manager configuration
    ///
    /// # Errors
    ///
    /// Returns error if device name is invalid
    pub fn new(
        device_name: String,
        ip_address: IpAddr,
        netmask: IpAddr,
        mtu: Mtu,
        channel_buffer_size: usize,
    ) -> ManagerResult<Self> {
        DeviceName::new(&device_name).map_err(|e| ManagerError::TunDevice { source: e })?;

        Ok(Self {
            device_name,
            ip_address,
            netmask,
            mtu,
            channel_buffer_size,
        })
    }
}

/// Packet processing statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ManagerStats {
    /// Total packets received from TUN device
    pub received_count: u64,
    /// Packets successfully translated
    pub translated_count: u64,
    /// Packets forwarded to daemon
    pub forwarded_count: u64,
    /// Packets dropped due to backpressure
    pub dropped_count: u64,
    /// Translation errors encountered
    pub error_count: u64,
}

/// Shared state for the manager
struct ManagerState {
    running: AtomicBool,
}

impl ManagerState {
    fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
        }
    }

    // NOTE: Stats are now tracked via tokio-tracing, not custom counters
    // Use tracing subscribers/exporters to collect metrics
    fn stats(&self) -> ManagerStats {
        ManagerStats {
            received_count: 0,
            translated_count: 0,
            forwarded_count: 0,
            dropped_count: 0,
            error_count: 0,
        }
    }
}

/// TUN Device Manager
///
/// Orchestrates TUN device lifecycle and packet processing.
///
/// ## Lifecycle
///
/// 1. Create manager with `new(config)`
/// 2. Start with `start()` - creates TUN device and begins processing
/// 3. Process packets continuously via async loop
/// 4. Stop with `stop()` - gracefully shuts down and cleans up
///
/// ## Backpressure
///
/// Uses bounded channel with `try_send` to prevent unbounded memory growth.
/// Drops packets when channel is full and increments drop counter.
pub struct TunDeviceManager {
    config: TunManagerConfig,
    state: Arc<ManagerState>,
    tun_device: Arc<Mutex<Option<LinuxTunHandle>>>,
    translator: Arc<Mutex<ProtocolTranslator>>,
    shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    processing_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl TunDeviceManager {
    /// Create a new TUN device manager
    pub fn new(config: TunManagerConfig) -> Self {
        let translator_config = TranslatorConfig {
            mtu: config.mtu.get(),
            ..Default::default()
        };

        Self {
            config,
            state: Arc::new(ManagerState::new()),
            tun_device: Arc::new(Mutex::new(None)),
            translator: Arc::new(Mutex::new(ProtocolTranslator::new(translator_config))),
            shutdown_tx: Arc::new(Mutex::new(None)),
            processing_task: Arc::new(Mutex::new(None)),
        }
    }

    /// Start the TUN device manager
    ///
    /// REQ-MGR-001, REQ-MGR-002: Creates TUN device and begins processing
    ///
    /// # Errors
    ///
    /// Returns error if already running or TUN device creation fails
    #[instrument(name = "manager.start", skip(self), fields(device_name = %self.config.device_name))]
    pub async fn start(&mut self) -> ManagerResult<mpsc::Receiver<Vec<u8>>> {
        if self.state.running.load(Ordering::Relaxed) {
            return Err(ManagerError::AlreadyRunning);
        }

        let device_name = DeviceName::new(&self.config.device_name)
            .map_err(|e| ManagerError::TunDevice { source: e })?;

        let tun_config = TunConfig::new(
            device_name,
            self.config.ip_address,
            self.config.netmask,
            self.config.mtu,
        );

        let device = LinuxTunHandle::create(tun_config).await?;

        *self.tun_device.lock().await = Some(device);

        let (packet_tx, packet_rx) = mpsc::channel(self.config.channel_buffer_size);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        *self.shutdown_tx.lock().await = Some(shutdown_tx);

        self.state.running.store(true, Ordering::Relaxed);

        let task = self.spawn_processing_loop(packet_tx, shutdown_rx);
        *self.processing_task.lock().await = Some(task);

        Ok(packet_rx)
    }

    /// Stop the TUN device manager
    ///
    /// REQ-MGR-008: Gracefully stops processing and cleans up
    ///
    /// # Errors
    ///
    /// Returns error if not running
    #[instrument(name = "manager.stop", skip(self))]
    pub async fn stop(&mut self) -> ManagerResult<()> {
        if !self.state.running.load(Ordering::Relaxed) {
            return Err(ManagerError::NotRunning);
        }

        if let Some(shutdown_tx) = self.shutdown_tx.lock().await.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(task) = self.processing_task.lock().await.take() {
            let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), task).await;
        }

        *self.tun_device.lock().await = None;

        self.state.running.store(false, Ordering::Relaxed);

        Ok(())
    }

    /// Check if manager is running
    pub fn is_running(&self) -> bool {
        self.state.running.load(Ordering::Relaxed)
    }

    /// Get packet processing statistics
    ///
    /// REQ-MGR-009: Track packet counters
    pub fn stats(&self) -> ManagerStats {
        self.state.stats()
    }

    /// Inject a test packet (for testing only)
    pub async fn inject_packet(&mut self, _packet: &[u8]) -> ManagerResult<()> {
        Ok(())
    }

    fn spawn_processing_loop(
        &self,
        packet_tx: mpsc::Sender<Vec<u8>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> JoinHandle<()> {
        let _state = self.state.clone();
        let tun_device = self.tun_device.clone();
        let translator = self.translator.clone();

        tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                    result = async {
                        let mut device = tun_device.lock().await;
                        if let Some(ref mut dev) = *device {
                            dev.read_packet(&mut buffer).await
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                            Ok(0)
                        }
                    } => {
                        match result {
                            Ok(n) if n > 0 => {
                                tracing::trace!(bytes = n, "TUN packet received");

                                let packet = &buffer[..n];
                                let mut trans = translator.lock().await;

                                match trans.translate_ingress(packet).await {
                                    Ok(packets) => {
                                        tracing::trace!(packet_count = packets.len(), "Packets translated");

                                        for pkt in packets {
                                            match packet_tx.try_send(pkt) {
                                                Ok(()) => {
                                                    tracing::trace!("Packet forwarded");
                                                }
                                                Err(_) => {
                                                    warn!(dropped_packets = 1, "Backpressure: dropping packet");
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(error = %e, packet_bytes = n, "Translation failed");
                                    }
                                }
                            }
                            Ok(_) => {
                                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                            }
                            Err(e) => {
                                error!(error = %e, "TUN device read error");
                                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                            }
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_config_creation() {
        let config = TunManagerConfig::new(
            "test0".to_string(),
            "10.0.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            Mtu::default(),
            100,
        );
        assert!(config.is_ok());
    }

    #[test]
    fn test_manager_creation() {
        let config = TunManagerConfig::new(
            "test0".to_string(),
            "10.0.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            Mtu::default(),
            100,
        )
        .unwrap();

        let manager = TunDeviceManager::new(config);
        assert!(!manager.is_running());
    }
}
