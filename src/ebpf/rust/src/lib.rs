// eBPF Rust integration library
//! This library provides Rust bindings and integration for the Buckwild eBPF programs.
//! It handles loading, managing, and communicating with eBPF programs for packet processing,
//! security enforcement, and performance optimization.

// Top-level module declarations (Linux-only)
#[cfg(target_os = "linux")]
pub mod bindings;
#[cfg(target_os = "linux")]
pub mod events;
#[cfg(target_os = "linux")]
pub mod interop;
#[cfg(target_os = "linux")]
pub mod loader;
#[cfg(target_os = "linux")]
pub mod maps;
#[cfg(target_os = "linux")]
pub mod pipeline;

#[cfg(target_os = "linux")]
mod linux_impl {
    // Import consolidated types from the authoritative source
    use buckwild_common::protocol::types::*;

    // Re-export top-level modules
    pub use crate::bindings;
    pub use crate::events;
    pub use crate::interop;
    pub use crate::loader;
    pub use crate::maps;
    pub use crate::pipeline;

    use crate::loader::EbpfLoader;
    use anyhow::Result;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Main eBPF integration manager
    pub struct EbpfManager {
        xdp_loader: Arc<RwLock<loader::XdpLoader>>,
        tc_loader: Arc<RwLock<loader::TcLoader>>,
        event_processor: Arc<RwLock<events::EventProcessor>>,
        map_manager: Arc<RwLock<maps::MapManager>>,
    }

    impl EbpfManager {
        /// Create a new eBPF manager instance
        pub fn new() -> Result<Self> {
            tracing::debug!("EbpfManager: Creating new instance");

            tracing::debug!("EbpfManager: Creating XDP loader");
            let xdp_loader = loader::XdpLoader::new().map_err(|e| {
                tracing::error!("EbpfManager: Failed to create XDP loader: {}", e);
                e
            })?;

            tracing::debug!("EbpfManager: Creating TC loader");
            let tc_loader = loader::TcLoader::new().map_err(|e| {
                tracing::error!("EbpfManager: Failed to create TC loader: {}", e);
                e
            })?;

            tracing::debug!("EbpfManager: Creating event processor");
            let event_processor = events::EventProcessor::new().map_err(|e| {
                tracing::error!("EbpfManager: Failed to create event processor: {}", e);
                e
            })?;

            tracing::debug!("EbpfManager: Creating map manager");
            let map_manager = maps::MapManager::new().map_err(|e| {
                tracing::error!("EbpfManager: Failed to create map manager: {}", e);
                e
            })?;

            tracing::info!("EbpfManager: Instance created successfully");
            Ok(Self {
                xdp_loader: Arc::new(RwLock::new(xdp_loader)),
                tc_loader: Arc::new(RwLock::new(tc_loader)),
                event_processor: Arc::new(RwLock::new(event_processor)),
                map_manager: Arc::new(RwLock::new(map_manager)),
            })
        }

        /// Initialize all eBPF programs and maps
        pub async fn initialize(&self) -> Result<()> {
            tracing::info!("EbpfManager: Starting initialization");

            // Initialize map manager first
            tracing::debug!("EbpfManager: Initializing map manager");
            self.map_manager
                .write()
                .await
                .initialize()
                .await
                .map_err(|e| {
                    tracing::error!("EbpfManager: Map manager initialization failed: {}", e);
                    e
                })?;
            tracing::debug!("EbpfManager: Map manager initialized");

            // Load XDP programs
            tracing::debug!("EbpfManager: Loading XDP programs");
            self.xdp_loader
                .write()
                .await
                .load_programs()
                .await
                .map_err(|e| {
                    tracing::error!("EbpfManager: XDP program loading failed: {}", e);
                    e
                })?;
            tracing::info!("EbpfManager: XDP programs loaded");

            // Load TC programs
            tracing::debug!("EbpfManager: Loading TC programs");
            self.tc_loader
                .write()
                .await
                .load_programs()
                .await
                .map_err(|e| {
                    tracing::error!("EbpfManager: TC program loading failed: {}", e);
                    e
                })?;
            tracing::info!("EbpfManager: TC programs loaded");

            // Start event processing
            tracing::debug!("EbpfManager: Starting event processor");
            self.event_processor
                .write()
                .await
                .start()
                .await
                .map_err(|e| {
                    tracing::error!("EbpfManager: Event processor start failed: {}", e);
                    e
                })?;
            tracing::debug!("EbpfManager: Event processor started");

            tracing::info!("EbpfManager: Initialization completed successfully");
            Ok(())
        }

        /// Shutdown all eBPF programs and cleanup resources
        pub async fn shutdown(&self) -> Result<()> {
            tracing::info!("EbpfManager: Starting shutdown");

            // Stop event processing
            tracing::debug!("EbpfManager: Stopping event processor");
            if let Err(e) = self.event_processor.write().await.stop().await {
                tracing::error!("EbpfManager: Event processor stop failed: {}", e);
            } else {
                tracing::debug!("EbpfManager: Event processor stopped");
            }

            // Unload XDP programs
            tracing::debug!("EbpfManager: Unloading XDP programs");
            if let Err(e) = self.xdp_loader.write().await.unload_programs().await {
                tracing::error!("EbpfManager: XDP program unload failed: {}", e);
            } else {
                tracing::debug!("EbpfManager: XDP programs unloaded");
            }

            // Unload TC programs
            tracing::debug!("EbpfManager: Unloading TC programs");
            if let Err(e) = self.tc_loader.write().await.unload_programs().await {
                tracing::error!("EbpfManager: TC program unload failed: {}", e);
            } else {
                tracing::debug!("EbpfManager: TC programs unloaded");
            }

            // Cleanup maps
            tracing::debug!("EbpfManager: Cleaning up maps");
            if let Err(e) = self.map_manager.write().await.cleanup().await {
                tracing::error!("EbpfManager: Map cleanup failed: {}", e);
            } else {
                tracing::debug!("EbpfManager: Maps cleaned up");
            }

            tracing::info!("EbpfManager: Shutdown completed");
            Ok(())
        }

        /// Get reference to XDP loader
        pub fn xdp_loader(&self) -> Arc<RwLock<loader::XdpLoader>> {
            Arc::clone(&self.xdp_loader)
        }

        /// Get reference to TC loader
        pub fn tc_loader(&self) -> Arc<RwLock<loader::TcLoader>> {
            Arc::clone(&self.tc_loader)
        }

        /// Get reference to event processor
        pub fn event_processor(&self) -> Arc<RwLock<events::EventProcessor>> {
            Arc::clone(&self.event_processor)
        }

        /// Get reference to map manager
        pub fn map_manager(&self) -> Arc<RwLock<maps::MapManager>> {
            Arc::clone(&self.map_manager)
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct EbpfManager;

#[cfg(not(target_os = "linux"))]
impl EbpfManager {
    /// Create a new eBPF manager instance
    ///
    /// # Platform Requirements
    ///
    /// This is a compile-time stub for cross-platform development.
    /// eBPF functionality requires:
    /// - Linux kernel 5.10 or later
    /// - BPF enabled in kernel config
    /// - CAP_BPF or CAP_NET_ADMIN capabilities
    ///
    /// # Errors
    ///
    /// Always returns an error on non-Linux platforms explaining the platform requirement.
    pub fn new() -> anyhow::Result<Self> {
        anyhow::bail!(
            "eBPF functionality requires Linux kernel with BPF support. \
             This platform ({}) does not support eBPF operations. \
             This is a compile-time stub for cross-platform development only.",
            std::env::consts::OS
        )
    }

    /// Initialize all eBPF programs and maps
    ///
    /// # Platform Requirements
    ///
    /// This is a compile-time stub. eBPF initialization requires Linux.
    ///
    /// # Errors
    ///
    /// Always returns an error on non-Linux platforms.
    pub async fn initialize(&self) -> anyhow::Result<()> {
        anyhow::bail!(
            "eBPF initialization requires Linux. Current platform: {}",
            std::env::consts::OS
        )
    }

    /// Shutdown all eBPF programs and cleanup resources
    ///
    /// # Platform Requirements
    ///
    /// This is a compile-time stub. On non-Linux platforms, this is a no-op
    /// since no resources can be allocated.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_ebpf_manager_creation() {
        let manager = EbpfManager::new();
        assert!(manager.is_ok());
    }

    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn test_ebpf_manager_creation_fails_on_non_linux() {
        let manager = EbpfManager::new();
        assert!(manager.is_err());
        let err = manager.unwrap_err();
        assert!(err.to_string().contains("Linux"));
    }

    #[tokio::test]
    #[ignore]
    #[cfg(target_os = "linux")]
    async fn test_ebpf_manager_initialization() {
        let _manager = EbpfManager::new().unwrap();
    }
}
