//! Device map management for XDP redirect
//! This module provides management for the xdp_devmap eBPF map.
//! It handles registering TUN device interface indexes for XDP_REDIRECT.

#![cfg(target_os = "linux")]

use anyhow::{Result, anyhow};
use libbpf_rs::Map;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Device map entry (ifindex to target ifindex mapping)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeviceMapEntry {
    pub source_ifindex: u32,
    pub target_ifindex: u32,
}

/// Device map manager for XDP redirect operations
pub struct DeviceMapManager {
    map: Option<Arc<RwLock<Map>>>,
    devices: HashMap<u32, u32>,
}

impl DeviceMapManager {
    /// Create a new device map manager
    pub fn new() -> Self {
        Self {
            map: None,
            devices: HashMap::new(),
        }
    }

    /// Set the eBPF map reference
    pub async fn set_map(&mut self, map: Arc<RwLock<Map>>) -> Result<()> {
        self.map = Some(map);
        tracing::info!("Device map reference set");
        Ok(())
    }

    /// Check if eBPF map is configured
    pub fn has_map(&self) -> bool {
        self.map.is_some()
    }

    /// Register a device mapping (source ifindex -> target ifindex)
    pub async fn register_device(
        &mut self,
        source_ifindex: u32,
        target_ifindex: u32,
    ) -> Result<()> {
        // Update local cache
        self.devices.insert(source_ifindex, target_ifindex);

        // Sync to eBPF map if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            let key_bytes = source_ifindex.to_ne_bytes();
            let value_bytes = target_ifindex.to_ne_bytes();
            map_guard
                .update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)
                .map_err(|e| anyhow!("Failed to update devmap: {}", e))?;
        }

        tracing::debug!(
            "Registered device mapping: {} -> {}",
            source_ifindex,
            target_ifindex
        );
        Ok(())
    }

    /// Unregister a device mapping
    pub async fn unregister_device(&mut self, source_ifindex: u32) -> Result<()> {
        // Update local cache
        self.devices.remove(&source_ifindex);

        // Sync to eBPF map if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            let key_bytes = source_ifindex.to_ne_bytes();
            // Ignore error if key doesn't exist
            let _ = map_guard.delete(&key_bytes);
        }

        tracing::debug!("Unregistered device mapping for ifindex {}", source_ifindex);
        Ok(())
    }

    /// Get target ifindex for a source ifindex
    pub fn get_target_ifindex(&self, source_ifindex: u32) -> Option<u32> {
        self.devices.get(&source_ifindex).copied()
    }

    /// Get all registered device mappings
    pub fn get_all_mappings(&self) -> &HashMap<u32, u32> {
        &self.devices
    }

    /// Clear all device mappings
    pub async fn clear(&mut self) -> Result<()> {
        // Clear eBPF map entries if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            for &key in self.devices.keys() {
                let key_bytes = key.to_ne_bytes();
                let _ = map_guard.delete(&key_bytes);
            }
        }

        self.devices.clear();
        tracing::debug!("Cleared all device mappings");
        Ok(())
    }

    /// Get number of registered devices
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
}

impl Default for DeviceMapManager {
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
    fn test_device_map_manager_creation() {
        let manager = DeviceMapManager::new();
        assert_eq!(manager.device_count(), 0);
        assert!(!manager.has_map());
    }

    #[tokio::test]
    async fn test_register_device() {
        let mut manager = DeviceMapManager::new();
        // Without eBPF map, still updates local cache
        assert!(manager.register_device(1, 2).await.is_ok());
        assert_eq!(manager.device_count(), 1);
        assert_eq!(manager.get_target_ifindex(1), Some(2));
    }

    #[tokio::test]
    async fn test_unregister_device() {
        let mut manager = DeviceMapManager::new();
        manager.register_device(1, 2).await.unwrap();
        assert!(manager.unregister_device(1).await.is_ok());
        assert_eq!(manager.device_count(), 0);
        assert_eq!(manager.get_target_ifindex(1), None);
    }

    #[tokio::test]
    async fn test_clear_devices() {
        let mut manager = DeviceMapManager::new();
        manager.register_device(1, 2).await.unwrap();
        manager.register_device(3, 4).await.unwrap();
        manager.clear().await.unwrap();
        assert_eq!(manager.device_count(), 0);
    }

    // ==========================================================================
    // Corner Cases - Duplicate/Override
    // ==========================================================================

    #[tokio::test]
    async fn test_register_same_device_twice_overwrites() {
        let mut manager = DeviceMapManager::new();
        manager.register_device(1, 100).await.unwrap();
        manager.register_device(1, 200).await.unwrap();

        // Second registration overwrites first
        assert_eq!(manager.device_count(), 1);
        assert_eq!(manager.get_target_ifindex(1), Some(200));
    }

    #[tokio::test]
    async fn test_unregister_nonexistent_device_succeeds() {
        let mut manager = DeviceMapManager::new();
        // Unregistering a device that doesn't exist should succeed silently
        assert!(manager.unregister_device(999).await.is_ok());
        assert_eq!(manager.device_count(), 0);
    }

    #[tokio::test]
    async fn test_unregister_twice_succeeds() {
        let mut manager = DeviceMapManager::new();
        manager.register_device(1, 2).await.unwrap();
        manager.unregister_device(1).await.unwrap();
        // Second unregister should also succeed
        assert!(manager.unregister_device(1).await.is_ok());
    }

    // ==========================================================================
    // Corner Cases - Boundary Values
    // ==========================================================================

    #[tokio::test]
    async fn test_register_zero_ifindex() {
        let mut manager = DeviceMapManager::new();
        // ifindex 0 is technically invalid but should be handled
        assert!(manager.register_device(0, 1).await.is_ok());
        assert_eq!(manager.get_target_ifindex(0), Some(1));
    }

    #[tokio::test]
    async fn test_register_max_ifindex() {
        let mut manager = DeviceMapManager::new();
        // Test u32::MAX as ifindex
        assert!(manager.register_device(u32::MAX, u32::MAX).await.is_ok());
        assert_eq!(manager.get_target_ifindex(u32::MAX), Some(u32::MAX));
    }

    #[tokio::test]
    async fn test_self_redirect_same_ifindex() {
        let mut manager = DeviceMapManager::new();
        // Source == Target (self-redirect, unusual but valid)
        assert!(manager.register_device(5, 5).await.is_ok());
        assert_eq!(manager.get_target_ifindex(5), Some(5));
    }

    // ==========================================================================
    // Corner Cases - Scale Testing
    // ==========================================================================

    #[tokio::test]
    async fn test_register_many_devices() {
        let mut manager = DeviceMapManager::new();
        const NUM_DEVICES: u32 = 64; // devmap max_entries

        for i in 0..NUM_DEVICES {
            manager.register_device(i, i + 1000).await.unwrap();
        }

        assert_eq!(manager.device_count(), NUM_DEVICES as usize);

        // Verify all entries
        for i in 0..NUM_DEVICES {
            assert_eq!(manager.get_target_ifindex(i), Some(i + 1000));
        }
    }

    #[tokio::test]
    async fn test_clear_empty_manager() {
        let mut manager = DeviceMapManager::new();
        // Clearing an empty manager should succeed
        assert!(manager.clear().await.is_ok());
        assert_eq!(manager.device_count(), 0);
    }

    // ==========================================================================
    // Corner Cases - get_all_mappings
    // ==========================================================================

    #[tokio::test]
    async fn test_get_all_mappings_empty() {
        let manager = DeviceMapManager::new();
        let mappings = manager.get_all_mappings();
        assert!(mappings.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_mappings_multiple() {
        let mut manager = DeviceMapManager::new();
        manager.register_device(1, 10).await.unwrap();
        manager.register_device(2, 20).await.unwrap();
        manager.register_device(3, 30).await.unwrap();

        let mappings = manager.get_all_mappings();
        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings.get(&1), Some(&10));
        assert_eq!(mappings.get(&2), Some(&20));
        assert_eq!(mappings.get(&3), Some(&30));
    }

    // ==========================================================================
    // Corner Cases - Lookup non-existent
    // ==========================================================================

    #[test]
    fn test_get_target_nonexistent() {
        let manager = DeviceMapManager::new();
        assert_eq!(manager.get_target_ifindex(42), None);
    }

    #[tokio::test]
    async fn test_get_target_after_unregister() {
        let mut manager = DeviceMapManager::new();
        manager.register_device(1, 2).await.unwrap();
        manager.unregister_device(1).await.unwrap();
        assert_eq!(manager.get_target_ifindex(1), None);
    }
}
