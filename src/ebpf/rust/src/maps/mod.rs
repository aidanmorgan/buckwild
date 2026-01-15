//! eBPF map management module
//! This module provides Rust abstractions for managing eBPF maps.
//! It handles session maps, port maps, security maps, and provides
//! atomic operations and proper synchronization.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use buckwild_common::protocol::types::*;

pub mod cpu_map;
pub mod device_map;
pub mod police_map;
pub mod port_map;
pub mod security_map;
pub mod session_map;

use anyhow::Result;
use libbpf_rs::{Map, Object};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Map manager for handling all eBPF maps
pub struct MapManager {
    object: Option<Object>,
    map_names: Vec<String>,
    session_manager: Arc<RwLock<session_map::SessionMapManager>>,
    port_manager: Arc<RwLock<port_map::PortMapManager>>,
    security_manager: Arc<RwLock<security_map::SecurityMapManager>>,
    device_manager: Arc<RwLock<device_map::DeviceMapManager>>,
    cpu_manager: Arc<RwLock<cpu_map::CpuMapManager>>,
    police_manager: Arc<RwLock<police_map::PoliceConfigManager>>,
    initialized: bool,
}

impl MapManager {
    /// Create a new map manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            object: None,
            map_names: Vec::new(),
            session_manager: Arc::new(RwLock::new(session_map::SessionMapManager::new())),
            port_manager: Arc::new(RwLock::new(port_map::PortMapManager::new())),
            security_manager: Arc::new(RwLock::new(security_map::SecurityMapManager::new())),
            device_manager: Arc::new(RwLock::new(device_map::DeviceMapManager::new())),
            cpu_manager: Arc::new(RwLock::new(cpu_map::CpuMapManager::new())),
            police_manager: Arc::new(RwLock::new(police_map::PoliceConfigManager::new())),
            initialized: false,
        })
    }

    /// Initialize all maps from loaded eBPF objects
    pub async fn initialize(&mut self) -> Result<()> {
        // Initialize individual map managers
        self.session_manager.write().await.initialize().await?;
        self.port_manager.write().await.initialize().await?;
        self.security_manager.write().await.initialize().await?;

        self.initialized = true;
        tracing::info!("eBPF map manager initialized");
        Ok(())
    }

    /// Load maps from an eBPF object
    pub async fn load_maps_from_object(&mut self, object: Object) -> Result<()> {
        // Collect map names
        for map in object.maps_iter() {
            let map_name = map.name().to_string();
            self.map_names.push(map_name.clone());
            tracing::debug!("Loaded eBPF map: {}", map_name);
        }

        // Store the object
        self.object = Some(object);

        // Update individual managers with loaded maps
        self.update_managers_with_maps().await?;
        Ok(())
    }

    /// Update individual map managers with loaded maps
    /// Note: libbpf-rs 0.21+ changed Map lifetime semantics; maps are accessed via Object
    async fn update_managers_with_maps(&self) -> Result<()> {
        // Map operations go through the Object; submanagers use syscall-based access
        Ok(())
    }

    /// Get a reference to a specific map by name
    /// Note: With libbpf-rs 0.21+, Map references are tied to Object lifetime.
    /// Returns None if object not loaded or map not found.
    pub fn get_map(&self, name: &str) -> Option<&Map> {
        let object = self.object.as_ref()?;
        object.map(name)
    }

    /// Get session map manager
    pub fn session_manager(&self) -> Arc<RwLock<session_map::SessionMapManager>> {
        Arc::clone(&self.session_manager)
    }

    /// Get port map manager
    pub fn port_manager(&self) -> Arc<RwLock<port_map::PortMapManager>> {
        Arc::clone(&self.port_manager)
    }

    /// Get security map manager
    pub fn security_manager(&self) -> Arc<RwLock<security_map::SecurityMapManager>> {
        Arc::clone(&self.security_manager)
    }

    /// Get device map manager
    pub fn device_manager(&self) -> Arc<RwLock<device_map::DeviceMapManager>> {
        Arc::clone(&self.device_manager)
    }

    /// Get CPU map manager
    pub fn cpu_manager(&self) -> Arc<RwLock<cpu_map::CpuMapManager>> {
        Arc::clone(&self.cpu_manager)
    }

    /// Get police config manager
    pub fn police_manager(&self) -> Arc<RwLock<police_map::PoliceConfigManager>> {
        Arc::clone(&self.police_manager)
    }

    /// Check if the manager is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get statistics for all maps
    pub async fn get_map_statistics(&self) -> Result<MapStatistics> {
        let session_stats = self.session_manager.read().await.get_statistics().await?;
        let port_stats = self.port_manager.read().await.get_statistics().await?;
        let security_stats = self.security_manager.read().await.get_statistics().await?;

        Ok(MapStatistics {
            session_stats,
            port_stats,
            security_stats,
            total_maps: EbpfMapSize::new(self.map_names.len() as u32),
        })
    }

    /// Cleanup all maps and resources
    pub async fn cleanup(&mut self) -> Result<()> {
        // Cleanup individual managers
        self.session_manager.write().await.cleanup().await?;
        self.port_manager.write().await.cleanup().await?;
        self.security_manager.write().await.cleanup().await?;

        // Clear map references
        self.map_names.clear();
        self.object = None;
        self.initialized = false;

        tracing::info!("eBPF map manager cleaned up");
        Ok(())
    }
}

/// Combined statistics for all map types
#[derive(Debug, Clone)]
pub struct MapStatistics {
    pub session_stats: session_map::SessionMapStats,
    pub port_stats: port_map::PortMapStats,
    pub security_stats: security_map::SecurityMapStats,
    pub total_maps: EbpfMapSize,
}

/// Common map operations trait
pub trait MapOperations<K, V> {
    /// Lookup a value by key
    fn lookup(&self, key: &K) -> Result<Option<V>>;

    /// Update or insert a key-value pair
    fn update(&self, key: &K, value: &V) -> Result<()>;

    /// Delete a key-value pair
    fn delete(&self, key: &K) -> Result<()>;

    /// Get the next key after the given key (for iteration)
    fn get_next_key(&self, key: Option<&K>) -> Result<Option<K>>;
}

/// Wrapper for libbpf-rs Map that implements MapOperations
pub struct LibbpfMapWrapper {
    map: Arc<RwLock<Map>>,
}

impl LibbpfMapWrapper {
    pub fn new(map: Arc<RwLock<Map>>) -> Self {
        Self { map }
    }
}

impl<K, V> MapOperations<K, V> for LibbpfMapWrapper
where
    K: Sized,
    V: Sized,
{
    fn lookup(&self, key: &K) -> Result<Option<V>> {
        let map = tokio::runtime::Handle::current().block_on(self.map.read());
        let key_bytes = unsafe {
            std::slice::from_raw_parts(key as *const K as *const u8, std::mem::size_of::<K>())
        };

        match map.lookup(key_bytes, libbpf_rs::MapFlags::ANY) {
            Ok(Some(value_bytes)) => Ok(Some(bytes_to_value(&value_bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Map lookup failed: {}", e)),
        }
    }

    fn update(&self, key: &K, value: &V) -> Result<()> {
        let map = tokio::runtime::Handle::current().block_on(self.map.write());
        let key_bytes = unsafe {
            std::slice::from_raw_parts(key as *const K as *const u8, std::mem::size_of::<K>())
        };
        let value_bytes = unsafe {
            std::slice::from_raw_parts(value as *const V as *const u8, std::mem::size_of::<V>())
        };

        map.update(key_bytes, value_bytes, libbpf_rs::MapFlags::ANY)
            .map_err(|e| anyhow::anyhow!("Map update failed: {}", e))
    }

    fn delete(&self, key: &K) -> Result<()> {
        let map = tokio::runtime::Handle::current().block_on(self.map.write());
        let key_bytes = unsafe {
            std::slice::from_raw_parts(key as *const K as *const u8, std::mem::size_of::<K>())
        };

        map.delete(key_bytes)
            .map_err(|e| anyhow::anyhow!("Map delete failed: {}", e))
    }

    fn get_next_key(&self, key: Option<&K>) -> Result<Option<K>> {
        let map = tokio::runtime::Handle::current().block_on(self.map.read());

        let key_bytes = key.map(|k| unsafe {
            std::slice::from_raw_parts(k as *const K as *const u8, std::mem::size_of::<K>())
                .to_vec()
        });

        match map.keys().next() {
            Some(next_key_bytes) => {
                if next_key_bytes.len() == std::mem::size_of::<K>() {
                    Ok(Some(bytes_to_value(&next_key_bytes)?))
                } else {
                    Err(anyhow::anyhow!("Invalid key size"))
                }
            }
            None => Ok(None),
        }
    }
}

/// Helper function to convert raw bytes to typed value
pub fn bytes_to_value<T>(bytes: &[u8]) -> Result<T> {
    if bytes.len() != std::mem::size_of::<T>() {
        return Err(anyhow::anyhow!(
            "Invalid byte length: expected {}, got {}",
            std::mem::size_of::<T>(),
            bytes.len()
        ));
    }

    unsafe {
        let ptr = bytes.as_ptr() as *const T;
        Ok(std::ptr::read(ptr))
    }
}

/// Helper function to convert typed value to raw bytes
pub fn value_to_bytes<T>(value: &T) -> Vec<u8> {
    unsafe {
        let ptr = value as *const T as *const u8;
        let slice = std::slice::from_raw_parts(ptr, std::mem::size_of::<T>());
        slice.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_map_manager_creation() {
        let manager = MapManager::new();
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert!(!manager.is_initialized());
        assert_eq!(manager.map_names.len(), 0);
    }

    #[test]
    fn test_bytes_conversion() {
        let value: u64 = 12345;
        let bytes = value_to_bytes(&value);
        let converted: u64 = bytes_to_value(&bytes).unwrap();
        assert_eq!(value, converted);
    }

    #[test]
    fn test_bytes_conversion_invalid_length() {
        let bytes = vec![1, 2, 3]; // Wrong length for u64
        let result: Result<u64> = bytes_to_value(&bytes);
        assert!(result.is_err());
    }
}
