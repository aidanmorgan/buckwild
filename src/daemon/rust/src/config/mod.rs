pub mod atomic_updates;
pub mod hosts;
pub mod psk;
pub mod runtime_management;
pub mod watcher;

use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use tracing::{debug, error, info, instrument};

// Import consolidated types from common crate
use buckwild_common::protocol::types::{MetricsInterval, WorkerThreadCount};

use crate::config::atomic_updates::AtomicConfig;
use crate::config::hosts::parser::HostsConfig;
use crate::config::psk::directory::PskDirectoryMonitor;
use crate::config::psk::fingerprint::FingerprintCalculator;
use crate::config::watcher::{FileWatcher, WatcherConfig};
use crate::tun::routing::manager::RoutingManager;

/// Errors that can occur during configuration management
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to load hosts configuration: {0}")]
    HostsLoadError(#[from] crate::config::hosts::parser::HostsParserError),

    #[error("Failed to watch configuration: {0}")]
    WatcherError(#[from] crate::config::watcher::WatcherError),

    #[error("Failed to update routing: {0}")]
    RoutingError(#[from] crate::tun::routing::manager::RoutingError),

    #[error("Failed to update configuration: {0}")]
    UpdateError(#[from] crate::config::atomic_updates::AtomicUpdateError),

    #[error("PSK directory error: {0}")]
    PskDirectoryError(#[from] crate::config::psk::directory::PskDirectoryError),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Configuration manager for the daemon
pub struct ConfigManager {
    /// Hosts configuration
    hosts_config: Arc<AtomicConfig<HostsConfig>>,

    /// PSK directory monitor
    psk_monitor: Arc<PskDirectoryMonitor>,

    /// Routing manager
    routing_manager: Arc<RoutingManager>,

    /// Hosts configuration watcher
    hosts_watcher: Arc<FileWatcher>,

    /// Fingerprint calculator
    fingerprint_calculator: Arc<FingerprintCalculator>,
}

impl ConfigManager {
    /// Create a new configuration manager
    #[instrument(skip(hosts_path, psk_dir), err)]
    pub async fn new(
        hosts_path: impl AsRef<Path>,
        psk_dir: impl AsRef<Path>,
        tun_device: &str,
    ) -> Result<Self, ConfigError> {
        // Create fingerprint calculator
        let fingerprint_calculator = Arc::new(FingerprintCalculator::new(
            WorkerThreadCount::from_raw(num_cpus::get().max(2) as u32),
        ));

        // Load hosts configuration
        let hosts_config = HostsConfig::load(hosts_path.as_ref()).await?;

        // Create atomic configuration
        let hosts_config = Arc::new(AtomicConfig::new(hosts_config));

        // Create routing manager
        #[cfg(target_os = "linux")]
        let routing_manager = Arc::new(RoutingManager::new(tun_device).await?);

        #[cfg(not(target_os = "linux"))]
        let routing_manager = Arc::new(RoutingManager::new(tun_device)?);

        // Create PSK directory monitor
        let mut psk_monitor = PskDirectoryMonitor::new(
            crate::config::psk::directory::PskDirectoryConfig {
                base_dir: psk_dir.as_ref().to_path_buf(),
                debounce_ms: MetricsInterval::from_raw(std::time::Duration::from_millis(100)),
                recursive: true,
            },
            fingerprint_calculator.clone(),
        )?;

        // Start PSK monitoring
        psk_monitor.start_watching()?;

        // Wrap in Arc after initialization
        let psk_monitor = Arc::new(psk_monitor);

        // Create hosts configuration watcher
        let hosts_watcher = Arc::new(FileWatcher::new(
            WatcherConfig::new(hosts_path.as_ref())
                .debounce(
                    MetricsInterval::from_raw(std::time::Duration::from_millis(100))
                        .as_raw()
                        .as_millis() as u64,
                )
                .recursive(false),
        )?);

        // Create manager
        let manager = Self {
            hosts_config,
            psk_monitor,
            routing_manager,
            hosts_watcher,
            fingerprint_calculator,
        };

        // Update routing table
        manager.update_routing().await?;

        // Start watching for configuration changes
        manager.start_watching().await?;

        Ok(manager)
    }

    /// Start watching for configuration changes
    #[instrument(skip(self), err)]
    async fn start_watching(&self) -> Result<(), ConfigError> {
        // Subscribe to hosts configuration changes
        let mut hosts_subscriber = self.hosts_watcher.subscribe();
        let hosts_config = self.hosts_config.clone();
        let routing_manager = self.routing_manager.clone();
        let hosts_path = self.hosts_watcher.watched_path().to_path_buf();

        // Spawn task to handle hosts configuration changes
        tokio::spawn(async move {
            while let Ok(events) = hosts_subscriber.recv().await {
                if !events.is_empty() {
                    debug!("Hosts configuration file changed, reloading");

                    match HostsConfig::load(&hosts_path).await {
                        Ok(new_config) => {
                            if let Err(e) = hosts_config.update(new_config) {
                                error!(error = %e, "Failed to update hosts configuration");
                                continue;
                            }

                            // Update routing table
                            #[cfg(target_os = "linux")]
                            {
                                if let Err(e) = routing_manager
                                    .update_from_config(&hosts_config.get())
                                    .await
                                {
                                    error!(error = %e, "Failed to update routing table");

                                    // Try to rollback configuration
                                    if let Err(e) = hosts_config.rollback() {
                                        error!(error = %e, "Failed to rollback hosts configuration");
                                    }
                                } else {
                                    info!("Hosts configuration updated successfully");
                                }
                            }

                            #[cfg(not(target_os = "linux"))]
                            {
                                info!("Routing updates not supported on this platform");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to load hosts configuration");
                        }
                    }
                }
            }
        });

        info!("Started watching for configuration changes");

        Ok(())
    }

    /// Update routing table based on hosts configuration
    #[cfg(target_os = "linux")]
    #[instrument(skip(self), err)]
    pub async fn update_routing(&self) -> Result<(), ConfigError> {
        let hosts_config = self.hosts_config.get();
        self.routing_manager
            .update_from_config(&hosts_config)
            .await?;

        info!("Updated routing table");

        Ok(())
    }

    /// Update routing table based on hosts configuration (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[instrument(skip(self), err)]
    pub async fn update_routing(&self) -> Result<(), ConfigError> {
        info!("Routing updates not supported on this platform");
        Ok(())
    }

    /// Get the hosts configuration
    pub fn get_hosts_config(&self) -> HostsConfig {
        self.hosts_config.get()
    }

    /// Update the hosts configuration
    #[instrument(skip(self, new_config), err)]
    pub async fn update_hosts_config(&self, new_config: HostsConfig) -> Result<(), ConfigError> {
        // Update configuration
        self.hosts_config.update(new_config)?;

        // Update routing table
        self.update_routing().await?;

        Ok(())
    }

    /// Get a PSK by fingerprint
    pub fn get_psk(
        &self,
        fingerprint: &str,
    ) -> Option<Arc<crate::crypto::secure_storage::SecureBytes>> {
        self.psk_monitor.get_psk(fingerprint)
    }

    /// Get all PSK fingerprints
    pub fn get_all_fingerprints(&self) -> Vec<String> {
        self.psk_monitor.get_all_fingerprints()
    }

    /// Get the number of loaded PSKs
    pub fn psk_count(&self) -> usize {
        self.psk_monitor.psk_count()
    }

    /// Get the fingerprint calculator
    pub fn fingerprint_calculator(&self) -> Arc<FingerprintCalculator> {
        self.fingerprint_calculator.clone()
    }
}
