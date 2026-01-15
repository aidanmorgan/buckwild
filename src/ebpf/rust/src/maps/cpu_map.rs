//! CPU map management for XDP load balancing
//! This module provides management for the xdp_cpumap eBPF map.
//! It handles configuring per-CPU queue sizes for packet distribution.

#![cfg(target_os = "linux")]

use anyhow::{Result, anyhow, bail};
use libbpf_rs::Map;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum CPUs supported by xdp_cpumap (must match max_entries in maps.h)
pub const MAX_CPUS: u32 = 256;

/// CPU map entry (CPU index to queue size mapping)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuMapEntry {
    pub cpu_id: u32,
    pub queue_size: u32,
}

/// CPU map manager for XDP load balancing
pub struct CpuMapManager {
    map: Option<Arc<RwLock<Map>>>,
    cpu_queues: HashMap<u32, u32>,
}

impl CpuMapManager {
    /// Create a new CPU map manager
    pub fn new() -> Self {
        Self {
            map: None,
            cpu_queues: HashMap::new(),
        }
    }

    /// Set the eBPF map reference
    pub async fn set_map(&mut self, map: Arc<RwLock<Map>>) -> Result<()> {
        self.map = Some(map);
        tracing::info!("CPU map reference set");
        Ok(())
    }

    /// Check if eBPF map is configured
    pub fn has_map(&self) -> bool {
        self.map.is_some()
    }

    /// Register a CPU with queue size
    pub async fn register_cpu(&mut self, cpu_id: u32, queue_size: u32) -> Result<()> {
        // Update local cache
        self.cpu_queues.insert(cpu_id, queue_size);

        // Sync to eBPF map if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            let key_bytes = cpu_id.to_ne_bytes();
            let value_bytes = queue_size.to_ne_bytes();
            map_guard
                .update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)
                .map_err(|e| anyhow!("Failed to update cpumap: {}", e))?;
        }

        tracing::debug!("Registered CPU {} with queue size {}", cpu_id, queue_size);
        Ok(())
    }

    /// Unregister a CPU
    pub async fn unregister_cpu(&mut self, cpu_id: u32) -> Result<()> {
        // Update local cache
        self.cpu_queues.remove(&cpu_id);

        // Sync to eBPF map if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            let key_bytes = cpu_id.to_ne_bytes();
            let _ = map_guard.delete(&key_bytes);
        }

        tracing::debug!("Unregistered CPU {}", cpu_id);
        Ok(())
    }

    /// Get queue size for a CPU
    pub fn get_queue_size(&self, cpu_id: u32) -> Option<u32> {
        self.cpu_queues.get(&cpu_id).copied()
    }

    /// Initialize all online CPUs with default queue size
    ///
    /// Validates that the number of CPUs does not exceed MAX_CPUS (256),
    /// which matches the xdp_cpumap max_entries in eBPF maps.h.
    /// The XDP load balancer uses session_id % num_online_cpus for CPU affinity.
    pub async fn initialize_online_cpus(&mut self, queue_size: u32) -> Result<()> {
        let num_cpus = num_cpus::get() as u32;

        if num_cpus > MAX_CPUS {
            bail!(
                "System has {} CPUs but xdp_cpumap only supports {} (would cause hash collisions)",
                num_cpus,
                MAX_CPUS
            );
        }

        for cpu_id in 0..num_cpus {
            self.register_cpu(cpu_id, queue_size).await?;
        }
        tracing::info!(
            "Initialized {} CPUs with queue size {}",
            num_cpus,
            queue_size
        );
        Ok(())
    }

    /// Get the number of online CPUs (for XDP load balancer hash modulo)
    pub fn online_cpu_count() -> u32 {
        num_cpus::get() as u32
    }

    /// Get all registered CPU queue configurations
    pub fn get_all_cpus(&self) -> &HashMap<u32, u32> {
        &self.cpu_queues
    }

    /// Clear all CPU mappings
    pub async fn clear(&mut self) -> Result<()> {
        // Clear eBPF map entries if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            for &key in self.cpu_queues.keys() {
                let key_bytes = key.to_ne_bytes();
                let _ = map_guard.delete(&key_bytes);
            }
        }

        self.cpu_queues.clear();
        tracing::debug!("Cleared all CPU mappings");
        Ok(())
    }

    /// Get number of registered CPUs
    pub fn cpu_count(&self) -> usize {
        self.cpu_queues.len()
    }
}

impl Default for CpuMapManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Basic Operations
    // ==========================================================================

    #[test]
    fn test_cpu_map_manager_creation() {
        let manager = CpuMapManager::new();
        assert_eq!(manager.cpu_count(), 0);
        assert!(!manager.has_map());
    }

    #[tokio::test]
    async fn test_register_cpu() {
        let mut manager = CpuMapManager::new();
        // Without eBPF map, still updates local cache
        assert!(manager.register_cpu(0, 512).await.is_ok());
        assert_eq!(manager.cpu_count(), 1);
        assert_eq!(manager.get_queue_size(0), Some(512));
    }

    #[tokio::test]
    async fn test_unregister_cpu() {
        let mut manager = CpuMapManager::new();
        manager.register_cpu(0, 512).await.unwrap();
        assert!(manager.unregister_cpu(0).await.is_ok());
        assert_eq!(manager.cpu_count(), 0);
        assert_eq!(manager.get_queue_size(0), None);
    }

    #[tokio::test]
    async fn test_initialize_online_cpus() {
        let mut manager = CpuMapManager::new();
        assert!(manager.initialize_online_cpus(256).await.is_ok());
        assert!(manager.cpu_count() > 0);

        for cpu_id in 0..manager.cpu_count() as u32 {
            assert_eq!(manager.get_queue_size(cpu_id), Some(256));
        }
    }

    #[tokio::test]
    async fn test_clear_cpus() {
        let mut manager = CpuMapManager::new();
        manager.register_cpu(0, 512).await.unwrap();
        manager.register_cpu(1, 512).await.unwrap();
        manager.clear().await.unwrap();
        assert_eq!(manager.cpu_count(), 0);
    }

    #[test]
    fn test_online_cpu_count() {
        let count = CpuMapManager::online_cpu_count();
        assert!(count > 0);
        assert!(count <= MAX_CPUS);
    }

    // ==========================================================================
    // Corner Cases - Duplicate/Override
    // ==========================================================================

    #[tokio::test]
    async fn test_register_same_cpu_twice_overwrites() {
        let mut manager = CpuMapManager::new();
        manager.register_cpu(0, 256).await.unwrap();
        manager.register_cpu(0, 512).await.unwrap();

        // Second registration overwrites first
        assert_eq!(manager.cpu_count(), 1);
        assert_eq!(manager.get_queue_size(0), Some(512));
    }

    #[tokio::test]
    async fn test_unregister_nonexistent_cpu_succeeds() {
        let mut manager = CpuMapManager::new();
        // Unregistering a CPU that doesn't exist should succeed silently
        assert!(manager.unregister_cpu(999).await.is_ok());
        assert_eq!(manager.cpu_count(), 0);
    }

    #[tokio::test]
    async fn test_unregister_twice_succeeds() {
        let mut manager = CpuMapManager::new();
        manager.register_cpu(0, 512).await.unwrap();
        manager.unregister_cpu(0).await.unwrap();
        // Second unregister should also succeed
        assert!(manager.unregister_cpu(0).await.is_ok());
    }

    // ==========================================================================
    // Corner Cases - Boundary Values
    // ==========================================================================

    #[tokio::test]
    async fn test_register_cpu_zero_queue_size() {
        let mut manager = CpuMapManager::new();
        // Zero queue size is technically valid (disables the CPU for processing)
        assert!(manager.register_cpu(0, 0).await.is_ok());
        assert_eq!(manager.get_queue_size(0), Some(0));
    }

    #[tokio::test]
    async fn test_register_cpu_max_queue_size() {
        let mut manager = CpuMapManager::new();
        // Test maximum u32 queue size
        assert!(manager.register_cpu(0, u32::MAX).await.is_ok());
        assert_eq!(manager.get_queue_size(0), Some(u32::MAX));
    }

    #[tokio::test]
    async fn test_register_max_cpu_id() {
        let mut manager = CpuMapManager::new();
        // MAX_CPUS - 1 is the highest valid CPU index
        assert!(manager.register_cpu(MAX_CPUS - 1, 256).await.is_ok());
        assert_eq!(manager.get_queue_size(MAX_CPUS - 1), Some(256));
    }

    #[tokio::test]
    async fn test_register_cpu_beyond_max() {
        let mut manager = CpuMapManager::new();
        // Local cache accepts any CPU ID (eBPF map would reject >255)
        // This tests that the Rust manager handles edge cases gracefully
        assert!(manager.register_cpu(MAX_CPUS, 256).await.is_ok());
        assert_eq!(manager.get_queue_size(MAX_CPUS), Some(256));
    }

    // ==========================================================================
    // Corner Cases - Scale Testing
    // ==========================================================================

    #[tokio::test]
    async fn test_register_all_256_cpus() {
        let mut manager = CpuMapManager::new();

        for cpu_id in 0..MAX_CPUS {
            manager.register_cpu(cpu_id, 128).await.unwrap();
        }

        assert_eq!(manager.cpu_count(), MAX_CPUS as usize);

        // Verify all entries
        for cpu_id in 0..MAX_CPUS {
            assert_eq!(manager.get_queue_size(cpu_id), Some(128));
        }
    }

    #[tokio::test]
    async fn test_clear_empty_manager() {
        let mut manager = CpuMapManager::new();
        // Clearing an empty manager should succeed
        assert!(manager.clear().await.is_ok());
        assert_eq!(manager.cpu_count(), 0);
    }

    #[tokio::test]
    async fn test_clear_after_partial_unregister() {
        let mut manager = CpuMapManager::new();
        manager.register_cpu(0, 256).await.unwrap();
        manager.register_cpu(1, 256).await.unwrap();
        manager.register_cpu(2, 256).await.unwrap();

        // Unregister one, then clear
        manager.unregister_cpu(1).await.unwrap();
        assert_eq!(manager.cpu_count(), 2);

        manager.clear().await.unwrap();
        assert_eq!(manager.cpu_count(), 0);
    }

    // ==========================================================================
    // Corner Cases - get_all_cpus
    // ==========================================================================

    #[tokio::test]
    async fn test_get_all_cpus_empty() {
        let manager = CpuMapManager::new();
        let cpus = manager.get_all_cpus();
        assert!(cpus.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_cpus_multiple() {
        let mut manager = CpuMapManager::new();
        manager.register_cpu(0, 128).await.unwrap();
        manager.register_cpu(4, 256).await.unwrap();
        manager.register_cpu(7, 512).await.unwrap();

        let cpus = manager.get_all_cpus();
        assert_eq!(cpus.len(), 3);
        assert_eq!(cpus.get(&0), Some(&128));
        assert_eq!(cpus.get(&4), Some(&256));
        assert_eq!(cpus.get(&7), Some(&512));
    }

    // ==========================================================================
    // Corner Cases - Lookup non-existent
    // ==========================================================================

    #[test]
    fn test_get_queue_size_nonexistent() {
        let manager = CpuMapManager::new();
        assert_eq!(manager.get_queue_size(42), None);
    }

    #[tokio::test]
    async fn test_get_queue_size_after_unregister() {
        let mut manager = CpuMapManager::new();
        manager.register_cpu(0, 512).await.unwrap();
        manager.unregister_cpu(0).await.unwrap();
        assert_eq!(manager.get_queue_size(0), None);
    }

    // ==========================================================================
    // Corner Cases - initialize_online_cpus variations
    // ==========================================================================

    #[tokio::test]
    async fn test_initialize_online_cpus_different_queue_sizes() {
        let mut manager = CpuMapManager::new();

        // First initialization
        manager.initialize_online_cpus(128).await.unwrap();
        let first_count = manager.cpu_count();

        // Second initialization overwrites with different queue size
        manager.initialize_online_cpus(256).await.unwrap();

        // Same CPU count, but queue sizes changed
        assert_eq!(manager.cpu_count(), first_count);
        for cpu_id in 0..manager.cpu_count() as u32 {
            assert_eq!(manager.get_queue_size(cpu_id), Some(256));
        }
    }

    #[tokio::test]
    async fn test_initialize_online_cpus_zero_queue() {
        let mut manager = CpuMapManager::new();
        // Zero queue size initialization
        assert!(manager.initialize_online_cpus(0).await.is_ok());
        assert!(manager.cpu_count() > 0);

        for cpu_id in 0..manager.cpu_count() as u32 {
            assert_eq!(manager.get_queue_size(cpu_id), Some(0));
        }
    }
}
