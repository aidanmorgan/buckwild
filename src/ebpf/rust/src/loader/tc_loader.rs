//! TC program loader
//! This module provides functionality for loading and managing TC eBPF programs.
//! It handles program lifecycle, qdisc management, and traffic control attachment.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use super::{EbpfLoader, validate_ebpf_object};
use crate::bindings::EbpfBinding;
use crate::bindings::tc_bindings::{
    TcProgramManager, create_clsact_qdisc, is_tc_supported, remove_clsact_qdisc,
};
use anyhow::Result;
use buckwild_common::protocol::types::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// TC program loader
pub struct TcLoader {
    program_manager: Arc<RwLock<TcProgramManager>>,
    program_directory: Option<PathBuf>,
    target_interfaces: Vec<String>,
    attached_egress_interfaces: std::collections::HashSet<String>,
    attached_ingress_interfaces: std::collections::HashSet<String>,
    loaded: bool,
    auto_discover_interfaces: bool,
    enable_egress: bool,
    enable_ingress: bool,
}

impl TcLoader {
    /// Create a new TC loader
    pub fn new() -> Result<Self> {
        Ok(Self {
            program_manager: Arc::new(RwLock::new(TcProgramManager::new())),
            program_directory: None,
            target_interfaces: Vec::new(),
            attached_egress_interfaces: std::collections::HashSet::new(),
            attached_ingress_interfaces: std::collections::HashSet::new(),
            loaded: false,
            auto_discover_interfaces: true,
            enable_egress: true,
            enable_ingress: false, // Typically only egress is needed for traffic shaping
        })
    }

    /// Set the directory containing eBPF object files
    pub fn set_program_directory<P: AsRef<Path>>(&mut self, dir: P) {
        self.program_directory = Some(dir.as_ref().to_path_buf());
    }

    /// Set target interfaces for TC attachment
    pub fn set_target_interfaces(&mut self, interfaces: Vec<String>) {
        self.target_interfaces = interfaces;
        self.auto_discover_interfaces = false;
    }

    /// Enable or disable automatic interface discovery
    pub fn set_auto_discover_interfaces(&mut self, enabled: bool) {
        self.auto_discover_interfaces = enabled;
    }

    /// Enable or disable egress traffic control
    pub fn set_enable_egress(&mut self, enabled: bool) {
        self.enable_egress = enabled;
    }

    /// Enable or disable ingress traffic control
    pub fn set_enable_ingress(&mut self, enabled: bool) {
        self.enable_ingress = enabled;
    }

    /// Discover and validate network interfaces for TC
    async fn discover_interfaces(&self) -> Result<Vec<String>> {
        if !self.auto_discover_interfaces && !self.target_interfaces.is_empty() {
            // Use manually specified interfaces
            let mut valid_interfaces = Vec::new();
            for interface in &self.target_interfaces {
                if is_tc_supported(interface)? {
                    valid_interfaces.push(interface.clone());
                    tracing::info!("Interface {} supports TC", interface);
                } else {
                    tracing::warn!("Interface {} does not support TC", interface);
                }
            }
            return Ok(valid_interfaces);
        }

        // Auto-discover interfaces (similar to XDP discovery but for TC)
        let available_interfaces = self.find_network_interfaces()?;
        let mut valid_interfaces = Vec::new();

        for interface in available_interfaces {
            if is_tc_supported(&interface)? {
                valid_interfaces.push(interface.clone());
                tracing::info!("Discovered TC-capable interface: {}", interface);
            }
        }

        if valid_interfaces.is_empty() {
            return Err(anyhow::anyhow!("No TC-capable interfaces found"));
        }

        Ok(valid_interfaces)
    }

    /// Find available network interfaces (similar to XDP version)
    fn find_network_interfaces(&self) -> Result<Vec<String>> {
        use std::fs;

        let sys_net_path = "/sys/class/net";
        let entries = fs::read_dir(sys_net_path)?;

        let mut interfaces = Vec::new();
        for entry in entries {
            let entry = entry?;
            let interface_name = entry.file_name().to_string_lossy().to_string();

            // Skip loopback and virtual interfaces
            if !interface_name.starts_with("lo")
                && !interface_name.starts_with("veth")
                && !interface_name.starts_with("docker")
            {
                interfaces.push(interface_name);
            }
        }

        Ok(interfaces)
    }

    /// Setup clsact qdiscs for interfaces
    async fn setup_qdiscs(&self, interfaces: &[String]) -> Result<()> {
        for interface in interfaces {
            match create_clsact_qdisc(interface) {
                Ok(()) => {
                    tracing::debug!("Created clsact qdisc for interface: {}", interface);
                }
                Err(e) => {
                    tracing::warn!("Failed to create clsact qdisc for {}: {}", interface, e);
                    // Continue with other interfaces
                }
            }
        }
        Ok(())
    }

    /// Remove clsact qdiscs from interfaces
    async fn cleanup_qdiscs(&self, interfaces: &[String]) -> Result<()> {
        for interface in interfaces {
            match remove_clsact_qdisc(interface) {
                Ok(()) => {
                    tracing::debug!("Removed clsact qdisc from interface: {}", interface);
                }
                Err(e) => {
                    tracing::warn!("Failed to remove clsact qdisc from {}: {}", interface, e);
                    // Continue with other interfaces
                }
            }
        }
        Ok(())
    }

    /// Load TC programs for discovered interfaces
    async fn load_tc_programs(&mut self) -> Result<()> {
        let program_dir = self
            .program_directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Program directory not set"))?;

        // Validate TC object file
        let tc_object_path = program_dir.join("buckwild_tc.o");
        validate_ebpf_object(&tc_object_path)?;

        // Discover interfaces
        let interfaces = self.discover_interfaces().await?;
        if interfaces.is_empty() {
            return Err(anyhow::anyhow!("No suitable interfaces found for TC"));
        }

        // Setup qdiscs first
        self.setup_qdiscs(&interfaces).await?;

        // Set up program manager
        {
            let mut manager = self.program_manager.write().await;
            manager.set_program_directory(program_dir);

            // Add interfaces to manager
            for interface in &interfaces {
                if self.enable_egress {
                    manager.add_egress_interface(interface.clone());
                    tracing::debug!("Added egress interface {} to TC manager", interface);
                }

                if self.enable_ingress {
                    manager.add_ingress_interface(interface.clone());
                    tracing::debug!("Added ingress interface {} to TC manager", interface);
                }
            }
        }

        // Load programs
        {
            let manager = self.program_manager.read().await;
            manager.load_all_programs().await?;
        }

        tracing::info!("Loaded TC programs for {} interfaces", interfaces.len());
        Ok(())
    }

    /// Attach TC programs to interfaces
    async fn attach_tc_programs(&mut self) -> Result<()> {
        let manager = self.program_manager.read().await;
        manager.attach_all_programs().await?;

        // Track attached interfaces
        for binding in &manager.egress_bindings {
            let binding = binding.read().await;
            if binding.is_attached() {
                self.attached_egress_interfaces
                    .insert(binding.interface().to_string());
            }
        }

        for binding in &manager.ingress_bindings {
            let binding = binding.read().await;
            if binding.is_attached() {
                self.attached_ingress_interfaces
                    .insert(binding.interface().to_string());
            }
        }

        let (egress_count, ingress_count) = manager.attached_count().await;
        tracing::info!(
            "Attached TC programs: {} egress, {} ingress",
            egress_count,
            ingress_count
        );
        Ok(())
    }

    /// Detach TC programs from interfaces
    async fn detach_tc_programs(&mut self) -> Result<()> {
        let manager = self.program_manager.read().await;
        manager.detach_all_programs().await?;

        // Clear attached interfaces tracking
        self.attached_egress_interfaces.clear();
        self.attached_ingress_interfaces.clear();

        tracing::info!("Detached TC programs from all interfaces");
        Ok(())
    }

    /// Get TC program statistics
    pub async fn get_program_statistics(
        &self,
    ) -> Result<Vec<(String, String, crate::bindings::ProgramStats)>> {
        let manager = self.program_manager.read().await;
        manager.get_all_stats().await
    }

    /// Get the number of attached interfaces
    pub async fn attached_interface_count(&self) -> (usize, usize) {
        let manager = self.program_manager.read().await;
        manager.attached_count().await
    }

    /// Check if a specific interface has TC attached
    pub async fn is_interface_attached(&self, interface: &str) -> bool {
        self.attached_egress_interfaces.contains(interface)
            || self.attached_ingress_interfaces.contains(interface)
    }

    /// Get list of attached interfaces (egress and ingress combined)
    pub fn get_attached_interfaces(&self) -> Vec<String> {
        let mut interfaces = self
            .attached_egress_interfaces
            .union(&self.attached_ingress_interfaces)
            .cloned()
            .collect::<Vec<_>>();
        interfaces.sort();
        interfaces
    }

    /// Get list of egress-attached interfaces
    pub fn get_egress_interfaces(&self) -> Vec<String> {
        self.attached_egress_interfaces.iter().cloned().collect()
    }

    /// Get list of ingress-attached interfaces
    pub fn get_ingress_interfaces(&self) -> Vec<String> {
        self.attached_ingress_interfaces.iter().cloned().collect()
    }

    /// Reload TC programs with atomic swap (load new before detaching old)
    pub async fn reload_programs(&mut self) -> Result<()> {
        tracing::info!("Reloading TC programs with atomic swap");

        if !self.loaded {
            // No existing programs, just load normally
            self.load_tc_programs().await?;
            self.attach_tc_programs().await?;
            self.loaded = true;
            tracing::info!("TC programs loaded successfully (no existing programs)");
            return Ok(());
        }

        // Atomic swap: Load new program BEFORE detaching old
        // This ensures continuous traffic control during reload

        // Store reference to old program manager for cleanup
        let old_manager = Arc::clone(&self.program_manager);

        // Create new program manager for new programs
        self.program_manager = Arc::new(RwLock::new(TcProgramManager::new()));

        // Load new programs
        match self.load_tc_programs().await {
            Ok(()) => {
                // Attach new programs (this replaces old programs atomically at kernel level)
                match self.attach_tc_programs().await {
                    Ok(()) => {
                        // New programs successfully attached, now clean up old programs
                        let old_mgr = old_manager.read().await;
                        let _ = old_mgr.detach_all_programs().await; // Detach old programs
                        drop(old_mgr); // Release old programs

                        self.loaded = true;
                        tracing::info!("TC programs reloaded successfully via atomic swap");
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!("Failed to attach new TC programs during reload: {}", e);
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
                tracing::error!("Failed to load new TC programs during reload: {}", e);
                // Rollback: Restore old program manager since new load failed
                self.program_manager = old_manager;
                Err(anyhow::anyhow!(
                    "Atomic swap failed during load, old programs retained: {}",
                    e
                ))
            }
        }
    }

    /// Handle TC program errors and attempt recovery
    async fn handle_program_error(&mut self, error: &anyhow::Error) -> Result<()> {
        tracing::error!("TC program error: {}", error);

        // Attempt to recover by reloading programs
        match self.reload_programs().await {
            Ok(()) => {
                tracing::info!("TC program recovery successful");
                Ok(())
            }
            Err(recovery_error) => {
                tracing::error!("TC program recovery failed: {}", recovery_error);
                Err(anyhow::anyhow!(
                    "TC program recovery failed: {}",
                    recovery_error
                ))
            }
        }
    }

    /// Validate TC program health
    pub async fn validate_program_health(&self) -> Result<bool> {
        if !self.loaded {
            return Ok(false);
        }

        let (egress_count, ingress_count) = self.attached_interface_count().await;
        if egress_count == 0 && ingress_count == 0 {
            return Ok(false);
        }

        // Check program statistics for anomalies
        match self.get_program_statistics().await {
            Ok(stats) => {
                for (interface, direction, program_stats) in stats {
                    if program_stats
                        .run_cnt
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 0
                    {
                        tracing::warn!(
                            "TC program on {} ({}) has not processed any packets",
                            interface,
                            direction
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
                            "High recursion misses on {} ({}): {}",
                            interface,
                            direction,
                            program_stats
                                .recursion_misses
                                .load(std::sync::atomic::Ordering::Relaxed)
                        );
                    }
                }
                Ok(true)
            }
            Err(e) => {
                tracing::error!("Failed to get TC program statistics: {}", e);
                Ok(false)
            }
        }
    }

    /// Get program manager reference
    pub fn program_manager(&self) -> Arc<RwLock<TcProgramManager>> {
        Arc::clone(&self.program_manager)
    }

    /// Cleanup qdiscs for current interfaces
    async fn cleanup_current_qdiscs(&self) -> Result<()> {
        let interfaces = if self.auto_discover_interfaces {
            self.discover_interfaces().await.unwrap_or_default()
        } else {
            self.target_interfaces.clone()
        };

        self.cleanup_qdiscs(&interfaces).await
    }
}

impl EbpfLoader for TcLoader {
    async fn load_programs(&mut self) -> Result<()> {
        if self.loaded {
            tracing::warn!("TC programs already loaded");
            return Ok(());
        }

        match self.load_tc_programs().await {
            Ok(()) => {
                match self.attach_tc_programs().await {
                    Ok(()) => {
                        self.loaded = true;
                        tracing::info!("TC programs loaded and attached successfully");
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!("Failed to attach TC programs: {}", e);
                        // Try to clean up loaded programs
                        let _ = self.detach_tc_programs().await;
                        Err(e)
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to load TC programs: {}", e);
                self.handle_program_error(&e).await
            }
        }
    }

    async fn unload_programs(&mut self) -> Result<()> {
        if !self.loaded {
            tracing::warn!("TC programs not loaded");
            return Ok(());
        }

        match self.detach_tc_programs().await {
            Ok(()) => {
                // Cleanup qdiscs
                let _ = self.cleanup_current_qdiscs().await;

                self.loaded = false;
                tracing::info!("TC programs unloaded successfully");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to unload TC programs: {}", e);
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
        // This would need to be tracked based on loaded interfaces and directions
        if self.loaded {
            let interface_count = self.target_interfaces.len().max(1);
            let direction_count = if self.enable_egress && self.enable_ingress {
                2
            } else if self.enable_egress || self.enable_ingress {
                1
            } else {
                0
            };
            EbpfProgramCount::new((interface_count * direction_count) as u32)
        } else {
            EbpfProgramCount::new(0)
        }
    }
}

/// TC loader configuration
#[derive(Debug, Clone)]
pub struct TcLoaderConfig {
    pub program_directory: PathBuf,
    pub target_interfaces: Vec<String>,
    pub auto_discover_interfaces: bool,
    pub enable_egress: bool,
    pub enable_ingress: bool,
    pub retry_attempts: AttemptCount,
    pub retry_delay_ms: u64, // Retry delay in milliseconds
}

impl Default for TcLoaderConfig {
    fn default() -> Self {
        Self {
            program_directory: PathBuf::from("/usr/lib/buckwild/ebpf"),
            target_interfaces: Vec::new(),
            auto_discover_interfaces: true,
            enable_egress: true,
            enable_ingress: false,
            retry_attempts: AttemptCount::from_raw(3),
            retry_delay_ms: 1000, // 1 second
        }
    }
}

impl TcLoader {
    /// Create TC loader with configuration
    pub fn with_config(config: TcLoaderConfig) -> Result<Self> {
        let mut loader = Self::new()?;
        loader.set_program_directory(&config.program_directory);
        loader.set_target_interfaces(config.target_interfaces);
        loader.set_auto_discover_interfaces(config.auto_discover_interfaces);
        loader.set_enable_egress(config.enable_egress);
        loader.set_enable_ingress(config.enable_ingress);
        Ok(loader)
    }

    /// Load programs with retry logic
    pub async fn load_programs_with_retry(&mut self, config: &TcLoaderConfig) -> Result<()> {
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
                            "TC load attempt {} failed, retrying in {}ms",
                            attempts,
                            config.retry_delay_ms
                        );
                        tokio::time::sleep(Duration::from_millis(config.retry_delay_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All retry attempts failed")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_tc_loader_creation() {
        let loader = TcLoader::new();
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
        assert!(loader.enable_egress);
        assert!(!loader.enable_ingress);
    }

    #[test]
    fn test_tc_loader_config() {
        let config = TcLoaderConfig::default();
        assert!(config.auto_discover_interfaces);
        assert!(config.enable_egress);
        assert!(!config.enable_ingress);
        assert_eq!(config.retry_attempts.as_raw(), 3);
        assert_eq!(config.retry_delay_ms, 1000);
    }

    #[tokio::test]
    async fn test_set_target_interfaces() {
        let mut loader = TcLoader::new().unwrap();
        let interfaces = vec!["eth0".to_string(), "eth1".to_string()];

        loader.set_target_interfaces(interfaces.clone());
        assert_eq!(loader.target_interfaces, interfaces);
        assert!(!loader.auto_discover_interfaces);
    }

    #[tokio::test]
    async fn test_set_program_directory() {
        let mut loader = TcLoader::new().unwrap();
        let temp_dir = TempDir::new().unwrap();

        loader.set_program_directory(temp_dir.path());
        assert_eq!(
            loader.program_directory,
            Some(temp_dir.path().to_path_buf())
        );
    }

    #[tokio::test]
    async fn test_enable_directions() {
        let mut loader = TcLoader::new().unwrap();

        loader.set_enable_egress(false);
        loader.set_enable_ingress(true);

        assert!(!loader.enable_egress);
        assert!(loader.enable_ingress);
    }

    #[tokio::test]
    async fn test_load_programs_without_directory() {
        let mut loader = TcLoader::new().unwrap();
        let result = loader.load_programs().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_program_health_not_loaded() {
        let loader = TcLoader::new().unwrap();
        let health = loader.validate_program_health().await.unwrap();
        assert!(!health);
    }

    #[test]
    fn test_tc_loader_with_config() {
        let config = TcLoaderConfig {
            program_directory: PathBuf::from("/test"),
            target_interfaces: vec!["eth0".to_string()],
            auto_discover_interfaces: false,
            enable_egress: false,
            enable_ingress: true,
            retry_attempts: AttemptCount::new(5),
            retry_delay_ms: 500,
        };

        let loader = TcLoader::with_config(config);
        assert!(loader.is_ok());

        let loader = loader.unwrap();
        assert_eq!(loader.target_interfaces, vec!["eth0".to_string()]);
        assert!(!loader.auto_discover_interfaces);
        assert!(!loader.enable_egress);
        assert!(loader.enable_ingress);
    }

    #[tokio::test]
    async fn test_program_count_calculation() {
        let mut loader = TcLoader::new().unwrap();
        loader.set_target_interfaces(vec!["eth0".to_string(), "eth1".to_string()]);

        // Not loaded
        assert_eq!(
            loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        // Simulate loaded state
        loader.loaded = true;

        // Both egress and ingress enabled
        loader.set_enable_egress(true);
        loader.set_enable_ingress(true);
        assert_eq!(
            loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            4
        ); // 2 interfaces * 2 directions

        // Only egress enabled
        loader.set_enable_egress(true);
        loader.set_enable_ingress(false);
        assert_eq!(
            loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        ); // 2 interfaces * 1 direction

        // Neither enabled
        loader.set_enable_egress(false);
        loader.set_enable_ingress(false);
        assert_eq!(
            loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        ); // 2 interfaces * 0 directions
    }

    #[tokio::test]
    async fn test_interface_tracking_initial_state() {
        let loader = TcLoader::new().unwrap();

        // Initially no interfaces attached
        assert_eq!(loader.attached_interface_count().await, (0, 0));
        assert!(!loader.is_interface_attached("eth0").await);
        assert!(loader.get_attached_interfaces().is_empty());
        assert!(loader.get_egress_interfaces().is_empty());
        assert!(loader.get_ingress_interfaces().is_empty());
    }

    #[tokio::test]
    async fn test_interface_tracking_egress_only() {
        let mut loader = TcLoader::new().unwrap();

        // Simulate egress attachment
        loader.attached_egress_interfaces.insert("eth0".to_string());
        loader.attached_egress_interfaces.insert("eth1".to_string());

        // Verify tracking
        assert!(loader.is_interface_attached("eth0").await);
        assert!(loader.is_interface_attached("eth1").await);
        assert!(!loader.is_interface_attached("eth2").await);

        let attached = loader.get_attached_interfaces();
        assert_eq!(attached.len(), 2);
        assert!(attached.contains(&"eth0".to_string()));
        assert!(attached.contains(&"eth1".to_string()));

        let egress = loader.get_egress_interfaces();
        assert_eq!(egress.len(), 2);

        let ingress = loader.get_ingress_interfaces();
        assert_eq!(ingress.len(), 0);
    }

    #[tokio::test]
    async fn test_interface_tracking_ingress_only() {
        let mut loader = TcLoader::new().unwrap();

        // Simulate ingress attachment
        loader
            .attached_ingress_interfaces
            .insert("wlan0".to_string());

        // Verify tracking
        assert!(loader.is_interface_attached("wlan0").await);
        assert!(!loader.is_interface_attached("eth0").await);

        let attached = loader.get_attached_interfaces();
        assert_eq!(attached.len(), 1);
        assert!(attached.contains(&"wlan0".to_string()));

        let egress = loader.get_egress_interfaces();
        assert_eq!(egress.len(), 0);

        let ingress = loader.get_ingress_interfaces();
        assert_eq!(ingress.len(), 1);
    }

    #[tokio::test]
    async fn test_interface_tracking_both_directions() {
        let mut loader = TcLoader::new().unwrap();

        // Simulate attachment in both directions
        loader.attached_egress_interfaces.insert("eth0".to_string());
        loader
            .attached_ingress_interfaces
            .insert("eth0".to_string());
        loader.attached_egress_interfaces.insert("eth1".to_string());

        // Verify tracking
        assert!(loader.is_interface_attached("eth0").await);
        assert!(loader.is_interface_attached("eth1").await);

        let attached = loader.get_attached_interfaces();
        assert_eq!(attached.len(), 2); // eth0 and eth1 (deduplicated)
        assert!(attached.contains(&"eth0".to_string()));
        assert!(attached.contains(&"eth1".to_string()));

        let egress = loader.get_egress_interfaces();
        assert_eq!(egress.len(), 2);

        let ingress = loader.get_ingress_interfaces();
        assert_eq!(ingress.len(), 1);
    }

    #[tokio::test]
    async fn test_interface_tracking_detachment() {
        let mut loader = TcLoader::new().unwrap();

        // Simulate attachment
        loader.attached_egress_interfaces.insert("eth0".to_string());
        loader
            .attached_ingress_interfaces
            .insert("eth1".to_string());

        assert_eq!(loader.get_attached_interfaces().len(), 2);

        // Simulate detachment (what detach_tc_programs does)
        loader.attached_egress_interfaces.clear();
        loader.attached_ingress_interfaces.clear();

        // Verify all interfaces cleared
        assert_eq!(loader.attached_interface_count().await, (0, 0));
        assert!(!loader.is_interface_attached("eth0").await);
        assert!(!loader.is_interface_attached("eth1").await);
        assert!(loader.get_attached_interfaces().is_empty());
    }
}
