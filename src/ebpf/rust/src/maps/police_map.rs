//! Police configuration map management for TC traffic policing
//! This module provides management for the police_config_map eBPF map.
//! It handles configuring Committed Information Rate (CIR) and Committed Burst Size (CBS)
//! for per-session traffic policing.

#![cfg(target_os = "linux")]

use anyhow::{Result, anyhow};
use buckwild_common::protocol::types::SessionId;
use libbpf_rs::Map;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Police configuration entry (matches eBPF struct police_config)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PoliceConfig {
    pub cir_bytes_per_sec: u64,
    pub cbs_bytes: u64,
    pub tokens: u64,
    pub last_update_ns: u64,
}

impl Default for PoliceConfig {
    fn default() -> Self {
        Self {
            cir_bytes_per_sec: 0,
            cbs_bytes: 0,
            tokens: 0,
            last_update_ns: 0,
        }
    }
}

impl PoliceConfig {
    /// Create a new police configuration
    pub fn new(cir_bytes_per_sec: u64, cbs_bytes: u64) -> Self {
        Self {
            cir_bytes_per_sec,
            cbs_bytes,
            tokens: cbs_bytes,
            last_update_ns: 0,
        }
    }

    /// Create with megabits per second rate
    pub fn from_mbps(mbps: u32, burst_kb: u32) -> Self {
        let cir_bytes_per_sec = (mbps as u64 * 1_000_000) / 8;
        let cbs_bytes = (burst_kb as u64) * 1024;
        Self::new(cir_bytes_per_sec, cbs_bytes)
    }

    /// Convert to bytes for eBPF map storage
    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&self.cir_bytes_per_sec.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.cbs_bytes.to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.tokens.to_ne_bytes());
        bytes[24..32].copy_from_slice(&self.last_update_ns.to_ne_bytes());
        bytes
    }
}

/// Police configuration manager for TC traffic policing
pub struct PoliceConfigManager {
    map: Option<Arc<RwLock<Map>>>,
    configs: HashMap<u64, PoliceConfig>,
}

impl PoliceConfigManager {
    /// Create a new police config manager
    pub fn new() -> Self {
        Self {
            map: None,
            configs: HashMap::new(),
        }
    }

    /// Set the eBPF map reference
    pub async fn set_map(&mut self, map: Arc<RwLock<Map>>) -> Result<()> {
        self.map = Some(map);
        tracing::info!("Police config map reference set");
        Ok(())
    }

    /// Check if eBPF map is configured
    pub fn has_map(&self) -> bool {
        self.map.is_some()
    }

    /// Configure policing for a session
    pub async fn configure_session(
        &mut self,
        session_id: SessionId,
        cir_bytes_per_sec: u64,
        cbs_bytes: u64,
    ) -> Result<()> {
        let config = PoliceConfig::new(cir_bytes_per_sec, cbs_bytes);

        // Update local cache
        self.configs.insert(session_id.as_u64(), config);

        // Sync to eBPF map if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            let key_bytes = session_id.as_u64().to_ne_bytes();
            let value_bytes = config.to_bytes();
            map_guard
                .update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)
                .map_err(|e| anyhow!("Failed to update police_config_map: {}", e))?;
        }

        tracing::debug!(
            "Configured policing for session {}: CIR {} bytes/sec, CBS {} bytes",
            session_id.as_u64(),
            cir_bytes_per_sec,
            cbs_bytes
        );
        Ok(())
    }

    /// Configure policing using megabits per second
    pub async fn configure_session_mbps(
        &mut self,
        session_id: SessionId,
        mbps: u32,
        burst_kb: u32,
    ) -> Result<()> {
        let config = PoliceConfig::from_mbps(mbps, burst_kb);

        // Update local cache
        self.configs.insert(session_id.as_u64(), config);

        // Sync to eBPF map if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            let key_bytes = session_id.as_u64().to_ne_bytes();
            let value_bytes = config.to_bytes();
            map_guard
                .update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)
                .map_err(|e| anyhow!("Failed to update police_config_map: {}", e))?;
        }

        tracing::debug!(
            "Configured policing for session {}: {} Mbps, {} KB burst",
            session_id.as_u64(),
            mbps,
            burst_kb
        );
        Ok(())
    }

    /// Remove policing configuration for a session
    pub async fn remove_session(&mut self, session_id: SessionId) -> Result<()> {
        // Update local cache
        self.configs.remove(&session_id.as_u64());

        // Sync to eBPF map if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            let key_bytes = session_id.as_u64().to_ne_bytes();
            let _ = map_guard.delete(&key_bytes);
        }

        tracing::debug!(
            "Removed policing config for session {}",
            session_id.as_u64()
        );
        Ok(())
    }

    /// Get policing configuration for a session
    pub fn get_config(&self, session_id: SessionId) -> Option<&PoliceConfig> {
        self.configs.get(&session_id.as_u64())
    }

    /// Update token count for a session (from eBPF sync)
    pub fn update_tokens(&mut self, session_id: SessionId, tokens: u64, last_update_ns: u64) {
        if let Some(config) = self.configs.get_mut(&session_id.as_u64()) {
            config.tokens = tokens;
            config.last_update_ns = last_update_ns;
        }
    }

    /// Get all configured sessions
    pub fn get_all_configs(&self) -> &HashMap<u64, PoliceConfig> {
        &self.configs
    }

    /// Clear all policing configurations
    pub async fn clear(&mut self) -> Result<()> {
        // Clear eBPF map entries if available
        if let Some(ref map) = self.map {
            let map_guard = map.write().await;
            for &key in self.configs.keys() {
                let key_bytes = key.to_ne_bytes();
                let _ = map_guard.delete(&key_bytes);
            }
        }

        self.configs.clear();
        tracing::debug!("Cleared all policing configurations");
        Ok(())
    }

    /// Get number of configured sessions
    pub fn config_count(&self) -> usize {
        self.configs.len()
    }
}

impl Default for PoliceConfigManager {
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
    fn test_police_config_manager_creation() {
        let manager = PoliceConfigManager::new();
        assert_eq!(manager.config_count(), 0);
        assert!(!manager.has_map());
    }

    #[tokio::test]
    async fn test_configure_session() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        // Without eBPF map, still updates local cache
        assert!(
            manager
                .configure_session(session_id.clone(), 1_000_000, 10_000)
                .await
                .is_ok()
        );
        assert_eq!(manager.config_count(), 1);

        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.cir_bytes_per_sec, 1_000_000);
        assert_eq!(config.cbs_bytes, 10_000);
        assert_eq!(config.tokens, 10_000);
    }

    #[tokio::test]
    async fn test_configure_session_mbps() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        assert!(
            manager
                .configure_session_mbps(session_id.clone(), 10, 100)
                .await
                .is_ok()
        );

        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.cir_bytes_per_sec, 1_250_000);
        assert_eq!(config.cbs_bytes, 102_400);
    }

    #[tokio::test]
    async fn test_remove_session() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        manager
            .configure_session(session_id.clone(), 1_000_000, 10_000)
            .await
            .unwrap();
        assert!(manager.remove_session(session_id.clone()).await.is_ok());
        assert_eq!(manager.config_count(), 0);
        assert!(manager.get_config(session_id).is_none());
    }

    #[test]
    fn test_update_tokens() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        // Need to use block_on for the async configure
        let rt = tokio::runtime::Runtime::new().unwrap();
        let session_id_clone = session_id.clone();
        rt.block_on(async {
            manager
                .configure_session(session_id_clone, 1_000_000, 10_000)
                .await
                .unwrap();
        });

        manager.update_tokens(session_id.clone(), 5000, 123456789);

        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.tokens, 5000);
        assert_eq!(config.last_update_ns, 123456789);
    }

    #[tokio::test]
    async fn test_clear_configs() {
        let mut manager = PoliceConfigManager::new();
        manager
            .configure_session(SessionId::new(1), 1_000_000, 10_000)
            .await
            .unwrap();
        manager
            .configure_session(SessionId::new(2), 2_000_000, 20_000)
            .await
            .unwrap();
        manager.clear().await.unwrap();
        assert_eq!(manager.config_count(), 0);
    }

    #[test]
    fn test_police_config_from_mbps() {
        let config = PoliceConfig::from_mbps(100, 256);
        assert_eq!(config.cir_bytes_per_sec, 12_500_000);
        assert_eq!(config.cbs_bytes, 262_144);
        assert_eq!(config.tokens, 262_144);
    }

    #[test]
    fn test_police_config_to_bytes() {
        let config = PoliceConfig::new(1_000_000, 10_000);
        let bytes = config.to_bytes();
        assert_eq!(bytes.len(), 32);
        // Verify CIR
        assert_eq!(
            u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            1_000_000
        );
        // Verify CBS
        assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 10_000);
        // Verify tokens (same as CBS initially)
        assert_eq!(
            u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            10_000
        );
    }

    // ==========================================================================
    // Corner Cases - Duplicate/Override
    // ==========================================================================

    #[tokio::test]
    async fn test_configure_same_session_twice_overwrites() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        manager
            .configure_session(session_id.clone(), 1_000_000, 10_000)
            .await
            .unwrap();
        manager
            .configure_session(session_id.clone(), 2_000_000, 20_000)
            .await
            .unwrap();

        // Second configuration overwrites first
        assert_eq!(manager.config_count(), 1);
        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.cir_bytes_per_sec, 2_000_000);
        assert_eq!(config.cbs_bytes, 20_000);
    }

    #[tokio::test]
    async fn test_remove_nonexistent_session_succeeds() {
        let mut manager = PoliceConfigManager::new();
        // Removing a session that doesn't exist should succeed silently
        assert!(manager.remove_session(SessionId::new(999)).await.is_ok());
        assert_eq!(manager.config_count(), 0);
    }

    #[tokio::test]
    async fn test_remove_twice_succeeds() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        manager
            .configure_session(session_id.clone(), 1_000_000, 10_000)
            .await
            .unwrap();
        manager.remove_session(session_id.clone()).await.unwrap();
        // Second remove should also succeed
        assert!(manager.remove_session(session_id).await.is_ok());
    }

    // ==========================================================================
    // Corner Cases - Boundary Values
    // ==========================================================================

    #[tokio::test]
    async fn test_configure_zero_rate() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(1);

        // Zero rate means no traffic allowed (drop all)
        assert!(
            manager
                .configure_session(session_id.clone(), 0, 0)
                .await
                .is_ok()
        );
        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.cir_bytes_per_sec, 0);
        assert_eq!(config.cbs_bytes, 0);
        assert_eq!(config.tokens, 0);
    }

    #[tokio::test]
    async fn test_configure_max_rate() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(1);

        // Test maximum u64 values (100+ Gbps scenarios)
        assert!(
            manager
                .configure_session(session_id.clone(), u64::MAX, u64::MAX)
                .await
                .is_ok()
        );
        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.cir_bytes_per_sec, u64::MAX);
        assert_eq!(config.cbs_bytes, u64::MAX);
    }

    #[tokio::test]
    async fn test_configure_session_id_zero() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(0);

        // Session ID 0 should work
        assert!(
            manager
                .configure_session(session_id.clone(), 1_000_000, 10_000)
                .await
                .is_ok()
        );
        assert!(manager.get_config(session_id).is_some());
    }

    #[tokio::test]
    async fn test_configure_session_id_max() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(u64::MAX);

        // Maximum session ID should work
        assert!(
            manager
                .configure_session(session_id.clone(), 1_000_000, 10_000)
                .await
                .is_ok()
        );
        assert!(manager.get_config(session_id).is_some());
    }

    #[test]
    fn test_police_config_from_mbps_zero() {
        let config = PoliceConfig::from_mbps(0, 0);
        assert_eq!(config.cir_bytes_per_sec, 0);
        assert_eq!(config.cbs_bytes, 0);
        assert_eq!(config.tokens, 0);
    }

    #[test]
    fn test_police_config_from_mbps_high_bandwidth() {
        // 100 Gbps = 100,000 Mbps
        // This would exceed u32::MAX in mbps, test with max u32
        let config = PoliceConfig::from_mbps(u32::MAX, u32::MAX);
        // 4294967295 Mbps = 4294967295 * 1_000_000 / 8 bytes/sec
        // This tests overflow safety in the conversion
        assert!(config.cir_bytes_per_sec > 0);
        assert!(config.cbs_bytes > 0);
    }

    #[test]
    fn test_police_config_from_mbps_1gbps() {
        // 1 Gbps = 1000 Mbps
        let config = PoliceConfig::from_mbps(1000, 1024);
        assert_eq!(config.cir_bytes_per_sec, 125_000_000); // 1 Gbps in bytes
        assert_eq!(config.cbs_bytes, 1_048_576); // 1 MB burst
    }

    #[test]
    fn test_police_config_from_mbps_10gbps() {
        // 10 Gbps = 10000 Mbps
        let config = PoliceConfig::from_mbps(10000, 4096);
        assert_eq!(config.cir_bytes_per_sec, 1_250_000_000); // 10 Gbps in bytes
        assert_eq!(config.cbs_bytes, 4_194_304); // 4 MB burst
    }

    // ==========================================================================
    // Corner Cases - Scale Testing
    // ==========================================================================

    #[tokio::test]
    async fn test_configure_many_sessions() {
        let mut manager = PoliceConfigManager::new();
        const NUM_SESSIONS: u64 = 1000;

        for i in 0..NUM_SESSIONS {
            let session_id = SessionId::new(i);
            manager
                .configure_session(session_id, i * 1000, i * 100)
                .await
                .unwrap();
        }

        assert_eq!(manager.config_count(), NUM_SESSIONS as usize);

        // Verify all entries
        for i in 0..NUM_SESSIONS {
            let session_id = SessionId::new(i);
            let config = manager.get_config(session_id).unwrap();
            assert_eq!(config.cir_bytes_per_sec, i * 1000);
            assert_eq!(config.cbs_bytes, i * 100);
        }
    }

    #[tokio::test]
    async fn test_clear_empty_manager() {
        let mut manager = PoliceConfigManager::new();
        // Clearing an empty manager should succeed
        assert!(manager.clear().await.is_ok());
        assert_eq!(manager.config_count(), 0);
    }

    #[tokio::test]
    async fn test_clear_after_partial_remove() {
        let mut manager = PoliceConfigManager::new();
        manager
            .configure_session(SessionId::new(1), 1_000_000, 10_000)
            .await
            .unwrap();
        manager
            .configure_session(SessionId::new(2), 2_000_000, 20_000)
            .await
            .unwrap();
        manager
            .configure_session(SessionId::new(3), 3_000_000, 30_000)
            .await
            .unwrap();

        // Remove one, then clear
        manager.remove_session(SessionId::new(2)).await.unwrap();
        assert_eq!(manager.config_count(), 2);

        manager.clear().await.unwrap();
        assert_eq!(manager.config_count(), 0);
    }

    // ==========================================================================
    // Corner Cases - get_all_configs
    // ==========================================================================

    #[tokio::test]
    async fn test_get_all_configs_empty() {
        let manager = PoliceConfigManager::new();
        let configs = manager.get_all_configs();
        assert!(configs.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_configs_multiple() {
        let mut manager = PoliceConfigManager::new();
        manager
            .configure_session(SessionId::new(100), 1_000_000, 10_000)
            .await
            .unwrap();
        manager
            .configure_session(SessionId::new(200), 2_000_000, 20_000)
            .await
            .unwrap();
        manager
            .configure_session(SessionId::new(300), 3_000_000, 30_000)
            .await
            .unwrap();

        let configs = manager.get_all_configs();
        assert_eq!(configs.len(), 3);
        assert!(configs.contains_key(&100));
        assert!(configs.contains_key(&200));
        assert!(configs.contains_key(&300));
    }

    // ==========================================================================
    // Corner Cases - Lookup non-existent
    // ==========================================================================

    #[test]
    fn test_get_config_nonexistent() {
        let manager = PoliceConfigManager::new();
        assert!(manager.get_config(SessionId::new(42)).is_none());
    }

    #[tokio::test]
    async fn test_get_config_after_remove() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);
        manager
            .configure_session(session_id.clone(), 1_000_000, 10_000)
            .await
            .unwrap();
        manager.remove_session(session_id.clone()).await.unwrap();
        assert!(manager.get_config(session_id).is_none());
    }

    // ==========================================================================
    // Corner Cases - update_tokens
    // ==========================================================================

    #[test]
    fn test_update_tokens_nonexistent_session() {
        let mut manager = PoliceConfigManager::new();
        // Updating tokens for non-existent session should do nothing (no panic)
        manager.update_tokens(SessionId::new(999), 5000, 123456789);
        assert_eq!(manager.config_count(), 0);
    }

    #[test]
    fn test_update_tokens_zero() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let session_id_clone = session_id.clone();
        rt.block_on(async {
            manager
                .configure_session(session_id_clone, 1_000_000, 10_000)
                .await
                .unwrap();
        });

        // Set tokens to zero (bucket empty)
        manager.update_tokens(session_id.clone(), 0, 123456789);

        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.tokens, 0);
    }

    #[test]
    fn test_update_tokens_max() {
        let mut manager = PoliceConfigManager::new();
        let session_id = SessionId::new(12345);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let session_id_clone = session_id.clone();
        rt.block_on(async {
            manager
                .configure_session(session_id_clone, 1_000_000, 10_000)
                .await
                .unwrap();
        });

        // Set tokens to max u64
        manager.update_tokens(session_id.clone(), u64::MAX, u64::MAX);

        let config = manager.get_config(session_id).unwrap();
        assert_eq!(config.tokens, u64::MAX);
        assert_eq!(config.last_update_ns, u64::MAX);
    }

    // ==========================================================================
    // Corner Cases - PoliceConfig struct
    // ==========================================================================

    #[test]
    fn test_police_config_default() {
        let config = PoliceConfig::default();
        assert_eq!(config.cir_bytes_per_sec, 0);
        assert_eq!(config.cbs_bytes, 0);
        assert_eq!(config.tokens, 0);
        assert_eq!(config.last_update_ns, 0);
    }

    #[test]
    fn test_police_config_to_bytes_with_updated_tokens() {
        let mut config = PoliceConfig::new(1_000_000, 10_000);
        config.tokens = 5000;
        config.last_update_ns = 123456789;

        let bytes = config.to_bytes();
        assert_eq!(
            u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            1_000_000
        );
        assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 10_000);
        assert_eq!(u64::from_ne_bytes(bytes[16..24].try_into().unwrap()), 5000);
        assert_eq!(
            u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            123456789
        );
    }

    #[test]
    fn test_police_config_clone() {
        let config1 = PoliceConfig::new(1_000_000, 10_000);
        let config2 = config1;

        assert_eq!(config1.cir_bytes_per_sec, config2.cir_bytes_per_sec);
        assert_eq!(config1.cbs_bytes, config2.cbs_bytes);
        assert_eq!(config1.tokens, config2.tokens);
    }
}
