//! XDP program loader
//! This module provides functionality for loading and managing XDP eBPF programs.
//! It handles program lifecycle, interface attachment, and error recovery.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use super::{EbpfLoader, validate_ebpf_object};
use crate::bindings::EbpfBinding;
use crate::bindings::xdp_bindings::{XdpProgramManager, find_network_interfaces, is_xdp_supported};
use crate::maps::{cpu_map::CpuMapManager, device_map::DeviceMapManager};
use anyhow::Result;
use buckwild_common::protocol::types::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// XDP program loader
pub struct XdpLoader {
    program_manager: Arc<RwLock<XdpProgramManager>>,
    device_manager: Arc<RwLock<DeviceMapManager>>,
    cpu_manager: Arc<RwLock<CpuMapManager>>,
    program_directory: Option<PathBuf>,
    target_interfaces: Vec<String>,
    attached_interfaces: std::collections::HashSet<String>,
    tun_device_ifindex: Option<u32>,
    loaded: bool,
    auto_discover_interfaces: bool,
}

impl XdpLoader {
    /// Create a new XDP loader
    pub fn new() -> Result<Self> {
        Ok(Self {
            program_manager: Arc::new(RwLock::new(XdpProgramManager::new())),
            device_manager: Arc::new(RwLock::new(DeviceMapManager::new())),
            cpu_manager: Arc::new(RwLock::new(CpuMapManager::new())),
            program_directory: None,
            target_interfaces: Vec::new(),
            attached_interfaces: std::collections::HashSet::new(),
            tun_device_ifindex: None,
            loaded: false,
            auto_discover_interfaces: true,
        })
    }

    /// Set the directory containing eBPF object files
    pub fn set_program_directory<P: AsRef<Path>>(&mut self, dir: P) {
        self.program_directory = Some(dir.as_ref().to_path_buf());
    }

    /// Set target interfaces for XDP attachment
    pub fn set_target_interfaces(&mut self, interfaces: Vec<String>) {
        self.target_interfaces = interfaces;
        self.auto_discover_interfaces = false;
    }

    /// Enable or disable automatic interface discovery
    pub fn set_auto_discover_interfaces(&mut self, enabled: bool) {
        self.auto_discover_interfaces = enabled;
    }

    /// Set TUN device interface index for XDP redirect
    pub fn set_tun_device_ifindex(&mut self, ifindex: u32) {
        self.tun_device_ifindex = Some(ifindex);
        tracing::debug!("Set TUN device ifindex to {}", ifindex);
    }

    /// Discover and validate network interfaces
    async fn discover_interfaces(&self) -> Result<Vec<String>> {
        if !self.auto_discover_interfaces && !self.target_interfaces.is_empty() {
            // Use manually specified interfaces
            let mut valid_interfaces = Vec::new();
            for interface in &self.target_interfaces {
                if is_xdp_supported(interface)? {
                    valid_interfaces.push(interface.clone());
                    tracing::info!("Interface {} supports XDP", interface);
                } else {
                    tracing::warn!("Interface {} does not support XDP", interface);
                }
            }
            return Ok(valid_interfaces);
        }

        // Auto-discover interfaces
        let available_interfaces = find_network_interfaces()?;
        let mut valid_interfaces = Vec::new();

        for interface in available_interfaces {
            if is_xdp_supported(&interface)? {
                valid_interfaces.push(interface.clone());
                tracing::info!("Discovered XDP-capable interface: {}", interface);
            }
        }

        if valid_interfaces.is_empty() {
            return Err(anyhow::anyhow!("No XDP-capable interfaces found"));
        }

        Ok(valid_interfaces)
    }

    /// Load XDP programs for discovered interfaces
    async fn load_xdp_programs(&mut self) -> Result<()> {
        let program_dir = self
            .program_directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Program directory not set"))?;

        // Validate XDP object file
        let xdp_object_path = program_dir.join("buckwild_xdp.o");
        validate_ebpf_object(&xdp_object_path)?;

        // Discover interfaces
        let interfaces = self.discover_interfaces().await?;
        if interfaces.is_empty() {
            return Err(anyhow::anyhow!("No suitable interfaces found for XDP"));
        }

        // Set up program manager
        {
            let mut manager = self.program_manager.write().await;
            manager.set_program_directory(program_dir);

            // Add interfaces to manager
            for interface in &interfaces {
                manager.add_interface(interface.clone());
                tracing::debug!("Added interface {} to XDP manager", interface);
            }
        }

        // Load programs
        {
            let manager = self.program_manager.read().await;
            manager.load_all_programs().await?;
        }

        tracing::info!("Loaded XDP programs for {} interfaces", interfaces.len());
        Ok(())
    }

    /// Attach XDP programs to interfaces
    async fn attach_xdp_programs(&mut self) -> Result<()> {
        // Scope the read lock so it's released before mutable borrow
        {
            let manager = self.program_manager.read().await;
            manager.attach_all_programs().await?;

            let attached_count = manager.attached_count().await;
            tracing::info!("Attached XDP programs to {} interfaces", attached_count);

            // Track attached interfaces
            for binding in &manager.bindings {
                let binding = binding.read().await;
                if binding.is_attached() {
                    self.attached_interfaces
                        .insert(binding.interface().to_string());
                }
            }
        }

        self.initialize_device_map().await?;
        self.initialize_cpu_map().await?;

        Ok(())
    }

    /// Initialize device map with TUN device ifindex
    async fn initialize_device_map(&mut self) -> Result<()> {
        if let Some(tun_ifindex) = self.tun_device_ifindex {
            let mut device_manager = self.device_manager.write().await;

            for interface in &self.target_interfaces {
                if let Ok(ifindex) = get_interface_index(interface) {
                    device_manager.register_device(ifindex, tun_ifindex).await?;
                    tracing::debug!("Registered device map: {} -> TUN {}", ifindex, tun_ifindex);
                }
            }

            tracing::info!("Initialized device map with TUN ifindex {}", tun_ifindex);
        } else {
            tracing::warn!("TUN device ifindex not set, skipping device map initialization");
        }
        Ok(())
    }

    /// Initialize CPU map with per-CPU queue sizes
    async fn initialize_cpu_map(&mut self) -> Result<()> {
        let mut cpu_manager = self.cpu_manager.write().await;

        const DEFAULT_QUEUE_SIZE: u32 = 256;
        cpu_manager
            .initialize_online_cpus(DEFAULT_QUEUE_SIZE)
            .await?;

        tracing::info!("Initialized CPU map with {} CPUs", cpu_manager.cpu_count());
        Ok(())
    }

    /// Detach XDP programs from interfaces
    async fn detach_xdp_programs(&mut self) -> Result<()> {
        let manager = self.program_manager.read().await;
        manager.detach_all_programs().await?;

        // Clear attached interfaces tracking
        self.attached_interfaces.clear();

        tracing::info!("Detached XDP programs from all interfaces");
        Ok(())
    }

    /// Get XDP program statistics
    pub async fn get_program_statistics(
        &self,
    ) -> Result<Vec<(String, crate::bindings::ProgramStats)>> {
        let manager = self.program_manager.read().await;
        manager.get_all_stats().await
    }

    /// Get the number of attached interfaces
    pub async fn attached_interface_count(&self) -> usize {
        let manager = self.program_manager.read().await;
        manager.attached_count().await
    }

    /// Check if a specific interface has XDP attached
    pub async fn is_interface_attached(&self, interface: &str) -> bool {
        self.attached_interfaces.contains(interface)
    }

    /// Get list of attached interfaces
    pub fn get_attached_interfaces(&self) -> Vec<String> {
        self.attached_interfaces.iter().cloned().collect()
    }

    /// Reload XDP programs with atomic swap (load new before detaching old)
    pub async fn reload_programs(&mut self) -> Result<()> {
        tracing::info!("Reloading XDP programs with atomic swap");

        if !self.loaded {
            // No existing programs, just load normally
            self.load_xdp_programs().await?;
            self.attach_xdp_programs().await?;
            self.loaded = true;
            tracing::info!("XDP programs loaded successfully (no existing programs)");
            return Ok(());
        }

        // Atomic swap: Load new program BEFORE detaching old
        // This ensures continuous packet processing during reload

        // Store reference to old program manager for cleanup
        let old_manager = Arc::clone(&self.program_manager);

        // Create new program manager for new programs
        self.program_manager = Arc::new(RwLock::new(XdpProgramManager::new()));

        // Load new programs
        match self.load_xdp_programs().await {
            Ok(()) => {
                // Attach new programs (this replaces old programs atomically at kernel level)
                match self.attach_xdp_programs().await {
                    Ok(()) => {
                        // New programs successfully attached, now clean up old programs
                        let old_mgr = old_manager.read().await;
                        let _ = old_mgr.detach_all_programs().await; // Detach old programs
                        drop(old_mgr); // Release old programs

                        self.loaded = true;
                        tracing::info!("XDP programs reloaded successfully via atomic swap");
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!("Failed to attach new XDP programs during reload: {}", e);
                        // Rollback: Restore old program manager since new attach failed
                        self.program_manager = old_manager;
                        Err(anyhow::anyhow!(
                            "Atomic swap failed during attach, old programs retained: {}",
                            e
                        ))
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to load new XDP programs during reload: {}", e);
                // Rollback: Restore old program manager since new load failed
                self.program_manager = old_manager;
                Err(anyhow::anyhow!(
                    "Atomic swap failed during load, old programs retained: {}",
                    e
                ))
            }
        }
    }

    /// Handle XDP program errors and attempt recovery
    async fn handle_program_error(&mut self, error: &anyhow::Error) -> Result<()> {
        tracing::error!("XDP program error: {}", error);

        // Attempt to recover by reloading programs
        match self.reload_programs().await {
            Ok(()) => {
                tracing::info!("XDP program recovery successful");
                Ok(())
            }
            Err(recovery_error) => {
                tracing::error!("XDP program recovery failed: {}", recovery_error);
                Err(anyhow::anyhow!(
                    "XDP program recovery failed: {}",
                    recovery_error
                ))
            }
        }
    }

    /// Validate XDP program health
    pub async fn validate_program_health(&self) -> Result<bool> {
        if !self.loaded {
            return Ok(false);
        }

        let attached_count = self.attached_interface_count().await;
        if attached_count == 0 {
            return Ok(false);
        }

        // Check program statistics for anomalies
        match self.get_program_statistics().await {
            Ok(stats) => {
                for (interface, program_stats) in stats {
                    if program_stats
                        .run_cnt
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 0
                    {
                        tracing::warn!(
                            "XDP program on {} has not processed any packets",
                            interface
                        );
                    }

                    // Check for excessive recursion misses
                    if program_stats
                        .recursion_misses
                        .load(std::sync::atomic::Ordering::Relaxed)
                        > program_stats
                            .run_cnt
                            .load(std::sync::atomic::Ordering::Relaxed)
                            / 10
                    {
                        tracing::warn!(
                            "High recursion misses on {}: {}",
                            interface,
                            program_stats
                                .recursion_misses
                                .load(std::sync::atomic::Ordering::Relaxed)
                        );
                    }
                }
                Ok(true)
            }
            Err(e) => {
                tracing::error!("Failed to get XDP program statistics: {}", e);
                Ok(false)
            }
        }
    }

    /// Get program manager reference
    pub fn program_manager(&self) -> Arc<RwLock<XdpProgramManager>> {
        Arc::clone(&self.program_manager)
    }

    /// Get device map manager reference
    pub fn device_manager(&self) -> Arc<RwLock<DeviceMapManager>> {
        Arc::clone(&self.device_manager)
    }

    /// Get CPU map manager reference
    pub fn cpu_manager(&self) -> Arc<RwLock<CpuMapManager>> {
        Arc::clone(&self.cpu_manager)
    }
}

/// Helper function to get network interface index by name
fn get_interface_index(interface_name: &str) -> Result<u32> {
    use nix::net::if_::if_nametoindex;
    let ifindex = if_nametoindex(interface_name)
        .map_err(|e| anyhow::anyhow!("Failed to get ifindex for {}: {}", interface_name, e))?;
    Ok(ifindex)
}

impl EbpfLoader for XdpLoader {
    async fn load_programs(&mut self) -> Result<()> {
        if self.loaded {
            tracing::warn!("XDP programs already loaded");
            return Ok(());
        }

        match self.load_xdp_programs().await {
            Ok(()) => {
                match self.attach_xdp_programs().await {
                    Ok(()) => {
                        self.loaded = true;
                        tracing::info!("XDP programs loaded and attached successfully");
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!("Failed to attach XDP programs: {}", e);
                        // Try to clean up loaded programs
                        let _ = self.detach_xdp_programs().await;
                        Err(e)
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to load XDP programs: {}", e);
                self.handle_program_error(&e).await
            }
        }
    }

    async fn unload_programs(&mut self) -> Result<()> {
        if !self.loaded {
            tracing::warn!("XDP programs not loaded");
            return Ok(());
        }

        match self.detach_xdp_programs().await {
            Ok(()) => {
                self.loaded = false;
                tracing::info!("XDP programs unloaded successfully");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to unload XDP programs: {}", e);
                // Force unload state even if detach failed
                self.loaded = false;
                Err(e)
            }
        }
    }

    fn is_loaded(&self) -> bool {
        self.loaded
    }

    fn program_count(&self) -> EbpfProgramCount {
        // This would need to be tracked based on loaded interfaces
        if self.loaded {
            EbpfProgramCount::new(self.target_interfaces.len().max(1) as u32) // At least 1 if loaded
        } else {
            EbpfProgramCount::new(0)
        }
    }
}

/// XDP loader configuration
#[derive(Debug, Clone)]
pub struct XdpLoaderConfig {
    pub program_directory: PathBuf,
    pub target_interfaces: Vec<String>,
    pub auto_discover_interfaces: bool,
    pub retry_attempts: AttemptCount,
    pub retry_delay_ms: u64, // Retry delay in milliseconds
}

impl Default for XdpLoaderConfig {
    fn default() -> Self {
        Self {
            program_directory: PathBuf::from("/usr/lib/buckwild/ebpf"),
            target_interfaces: Vec::new(),
            auto_discover_interfaces: true,
            retry_attempts: AttemptCount::from_raw(3),
            retry_delay_ms: 1000, // 1 second
        }
    }
}

/// XDP program status for CLI and monitoring
#[derive(Debug, Clone)]
pub struct ProgramStatus {
    /// Whether programs are loaded and attached
    pub loaded: bool,
    /// Interfaces targeted for XDP attachment
    pub target_interfaces: Vec<String>,
}

impl XdpLoader {
    /// Create XDP loader with configuration
    pub fn with_config(config: XdpLoaderConfig) -> Result<Self> {
        let mut loader = Self::new()?;
        loader.set_program_directory(&config.program_directory);
        loader.set_target_interfaces(config.target_interfaces);
        loader.set_auto_discover_interfaces(config.auto_discover_interfaces);
        Ok(loader)
    }

    /// Load programs with retry logic
    pub async fn load_programs_with_retry(&mut self, config: &XdpLoaderConfig) -> Result<()> {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < config.retry_attempts.as_raw() {
            match self.load_programs().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    attempts += 1;
                    last_error = Some(e);

                    if attempts < config.retry_attempts.as_raw() {
                        tracing::warn!(
                            "XDP load attempt {} failed, retrying in {}ms",
                            attempts,
                            config.retry_delay_ms
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(config.retry_delay_ms))
                            .await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All retry attempts failed")))
    }

    /// Get current program status
    /// Wraps existing is_loaded() and target_interfaces for CLI convenience
    pub fn get_status(&self) -> ProgramStatus {
        ProgramStatus {
            loaded: self.loaded,
            target_interfaces: self.target_interfaces.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_xdp_loader_creation() {
        let loader = XdpLoader::new();
        assert!(loader.is_ok());

        let loader = loader.unwrap();
        assert!(!loader.is_loaded());
        assert_eq!(
            loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(loader.program_directory.is_none());
        assert!(loader.auto_discover_interfaces);
    }

    #[test]
    fn test_xdp_loader_config() {
        let config = XdpLoaderConfig::default();
        assert!(config.auto_discover_interfaces);
        assert_eq!(config.retry_attempts.as_raw(), 3);
        assert_eq!(config.retry_delay_ms, 1000);
    }

    #[tokio::test]
    async fn test_set_target_interfaces() {
        let mut loader = XdpLoader::new().unwrap();
        let interfaces = vec!["eth0".to_string(), "eth1".to_string()];

        loader.set_target_interfaces(interfaces.clone());
        assert_eq!(loader.target_interfaces, interfaces);
        assert!(!loader.auto_discover_interfaces);
    }

    #[tokio::test]
    async fn test_set_program_directory() {
        let mut loader = XdpLoader::new().unwrap();
        let temp_dir = TempDir::new().unwrap();

        loader.set_program_directory(temp_dir.path());
        assert_eq!(
            loader.program_directory,
            Some(temp_dir.path().to_path_buf())
        );
    }

    #[tokio::test]
    async fn test_load_programs_without_directory() {
        let mut loader = XdpLoader::new().unwrap();
        let result = loader.load_programs().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_program_health_not_loaded() {
        let loader = XdpLoader::new().unwrap();
        let health = loader.validate_program_health().await.unwrap();
        assert!(!health);
    }

    #[test]
    fn test_xdp_loader_with_config() {
        let config = XdpLoaderConfig {
            program_directory: PathBuf::from("/test"),
            target_interfaces: vec!["eth0".to_string()],
            auto_discover_interfaces: false,
            retry_attempts: AttemptCount::new(5),
            retry_delay_ms: 500,
        };

        let loader = XdpLoader::with_config(config);
        assert!(loader.is_ok());

        let loader = loader.unwrap();
        assert_eq!(loader.target_interfaces, vec!["eth0".to_string()]);
        assert!(!loader.auto_discover_interfaces);
    }

    #[test]
    fn test_program_status_new_loader() {
        let loader = XdpLoader::new().unwrap();
        let status = loader.get_status();
        assert!(!status.loaded);
        assert!(status.target_interfaces.is_empty());
    }

    #[test]
    fn test_program_status_with_target_interfaces() {
        let mut loader = XdpLoader::new().unwrap();
        loader.set_target_interfaces(vec!["eth0".to_string(), "eth1".to_string()]);
        let status = loader.get_status();
        assert!(!status.loaded);
        assert_eq!(status.target_interfaces, vec!["eth0", "eth1"]);
    }

    #[tokio::test]
    async fn test_interface_tracking_initial_state() {
        let loader = XdpLoader::new().unwrap();

        // Initially no interfaces attached
        assert_eq!(loader.attached_interface_count().await, 0);
        assert!(!loader.is_interface_attached("eth0").await);
        assert!(loader.get_attached_interfaces().is_empty());
    }

    #[tokio::test]
    async fn test_interface_tracking_after_manual_insertion() {
        let mut loader = XdpLoader::new().unwrap();

        // Simulate attachment by manually inserting into attached_interfaces
        loader.attached_interfaces.insert("eth0".to_string());
        loader.attached_interfaces.insert("eth1".to_string());

        // Verify tracking
        assert_eq!(loader.attached_interface_count().await, 0); // program_manager still reports 0
        assert!(loader.is_interface_attached("eth0").await);
        assert!(loader.is_interface_attached("eth1").await);
        assert!(!loader.is_interface_attached("eth2").await);

        let attached = loader.get_attached_interfaces();
        assert_eq!(attached.len(), 2);
        assert!(attached.contains(&"eth0".to_string()));
        assert!(attached.contains(&"eth1".to_string()));
    }

    #[tokio::test]
    async fn test_interface_tracking_detachment() {
        let mut loader = XdpLoader::new().unwrap();

        // Simulate attachment
        loader.attached_interfaces.insert("eth0".to_string());
        loader.attached_interfaces.insert("eth1".to_string());

        assert_eq!(loader.get_attached_interfaces().len(), 2);

        // Simulate detachment (what detach_xdp_programs does)
        loader.attached_interfaces.clear();

        // Verify all interfaces cleared
        assert_eq!(loader.attached_interface_count().await, 0);
        assert!(!loader.is_interface_attached("eth0").await);
        assert!(!loader.is_interface_attached("eth1").await);
        assert!(loader.get_attached_interfaces().is_empty());
    }

    #[tokio::test]
    async fn test_interface_tracking_query_attached_interfaces() {
        let mut loader = XdpLoader::new().unwrap();

        // Add multiple interfaces
        loader.attached_interfaces.insert("wlan0".to_string());
        loader.attached_interfaces.insert("eth0".to_string());
        loader.attached_interfaces.insert("eth1".to_string());

        let attached = loader.get_attached_interfaces();
        assert_eq!(attached.len(), 3);
        assert!(attached.contains(&"wlan0".to_string()));
        assert!(attached.contains(&"eth0".to_string()));
        assert!(attached.contains(&"eth1".to_string()));
    }
}
