//! Session map management
//! This module provides management for the session eBPF map.
//! It handles session information, lifecycle, and provides atomic operations.

#![cfg(target_os = "linux")]

use super::{MapOperations, bytes_to_value, value_to_bytes};
use anyhow::Result;
use buckwild_common::protocol::types::{Port, SequenceNumber, SessionId, ValidationError};
use libbpf_rs::Map;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Session information structure (matches eBPF struct)
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: u64,
    pub last_sequence: u32,
    pub expected_port: u32,
    pub last_packet_time: u64,
    pub packet_count: u32,
    pub session_state: u8,
    pub hmac_policy: u8,
    pub session_id_length: u8,
    pub timestamp_length: u8,
    pub src_ip: u32,
    pub src_port: u16,
    pub creation_time: u64,
    pub security_violations: u32,
    pub attack_detected: u8,
    pub reserved: [u8; 3],
}

impl Default for SessionInfo {
    fn default() -> Self {
        Self {
            session_id: 0,
            last_sequence: 0,
            expected_port: 0,
            last_packet_time: 0,
            packet_count: 0,
            session_state: 0,
            hmac_policy: 0,
            session_id_length: 0,
            timestamp_length: 0,
            src_ip: 0,
            src_port: 0,
            creation_time: 0,
            security_violations: 0,
            attack_detected: 0,
            reserved: [0; 3],
        }
    }
}

impl SessionInfo {
    /// Get typed session ID from eBPF u64
    pub fn get_session_id(&self) -> SessionId {
        SessionId::new(self.session_id)
    }

    /// Set session ID from typed SessionId
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = session_id.as_u64();
        self
    }

    /// Get typed sequence number from eBPF u32
    pub fn get_last_sequence(&self) -> SequenceNumber {
        SequenceNumber::new(self.last_sequence)
    }

    /// Set last sequence from typed SequenceNumber
    pub fn with_last_sequence(mut self, sequence: SequenceNumber) -> Self {
        self.last_sequence = sequence.as_u32();
        self
    }

    /// Get typed source port from eBPF u16
    pub fn get_src_port(&self) -> Result<Port, ValidationError> {
        Port::new(self.src_port)
    }

    /// Get typed expected port from eBPF u32 (assuming it should be u16)
    pub fn get_expected_port(&self) -> Result<Port, ValidationError> {
        Port::new(self.expected_port as u16)
    }
}

/// Session states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionState {
    Inactive = 0,
    Establishing = 1,
    Active = 2,
    Terminating = 3,
}

impl From<u8> for SessionState {
    fn from(value: u8) -> Self {
        match value {
            0 => SessionState::Inactive,
            1 => SessionState::Establishing,
            2 => SessionState::Active,
            3 => SessionState::Terminating,
            _ => SessionState::Inactive,
        }
    }
}

impl From<SessionState> for u8 {
    fn from(state: SessionState) -> Self {
        state as u8
    }
}

/// HMAC policies
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HmacPolicy {
    Light = 0,
    Medium = 1,
    Strong = 2,
}

impl From<u8> for HmacPolicy {
    fn from(value: u8) -> Self {
        match value {
            0 => HmacPolicy::Light,
            1 => HmacPolicy::Medium,
            2 => HmacPolicy::Strong,
            _ => HmacPolicy::Light,
        }
    }
}

impl From<HmacPolicy> for u8 {
    fn from(policy: HmacPolicy) -> Self {
        policy as u8
    }
}

/// Session map manager
pub struct SessionMapManager {
    map: Option<Arc<RwLock<Map>>>,
    session_cache: HashMap<u64, SessionInfo>,
    cache_enabled: bool,
}

impl SessionMapManager {
    /// Create a new session map manager
    pub fn new() -> Self {
        Self {
            map: None,
            session_cache: HashMap::new(),
            cache_enabled: true,
        }
    }

    /// Initialize the session map manager
    pub async fn initialize(&mut self) -> Result<()> {
        // Clear any existing cache
        self.session_cache.clear();
        tracing::info!("Session map manager initialized");
        Ok(())
    }

    /// Set the eBPF map reference
    pub async fn set_map(&mut self, map: Arc<RwLock<Map>>) -> Result<()> {
        self.map = Some(map);
        tracing::info!("Session map reference set");
        Ok(())
    }

    /// Enable or disable caching
    pub fn set_cache_enabled(&mut self, enabled: bool) {
        self.cache_enabled = enabled;
        if !enabled {
            self.session_cache.clear();
        }
    }

    /// Create a new session
    pub async fn create_session(
        &mut self,
        session_id: u64,
        src_ip: u32,
        src_port: u16,
        hmac_policy: HmacPolicy,
    ) -> Result<()> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;

        let session_info = SessionInfo {
            session_id,
            last_sequence: 0,
            expected_port: 0,
            last_packet_time: current_time,
            packet_count: 0,
            session_state: SessionState::Establishing.into(),
            hmac_policy: hmac_policy.into(),
            session_id_length: 2, // Default to 64-bit session ID
            timestamp_length: 2,  // Default to 32-bit timestamp
            src_ip,
            src_port,
            creation_time: current_time,
            security_violations: 0,
            attack_detected: 0,
            reserved: [0; 3],
        };

        self.update_session(session_id, &session_info).await?;
        tracing::debug!("Created session: {}", session_id);
        Ok(())
    }

    /// Update session information
    pub async fn update_session(&mut self, session_id: u64, info: &SessionInfo) -> Result<()> {
        // Update eBPF map
        if let Some(map) = &self.map {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&session_id);
            let value_bytes = value_to_bytes(info);
            map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
        }

        // Update cache if enabled
        if self.cache_enabled {
            self.session_cache.insert(session_id, *info);
        }

        Ok(())
    }

    /// Get session information
    pub async fn get_session(&mut self, session_id: u64) -> Result<Option<SessionInfo>> {
        // Check cache first if enabled
        if self.cache_enabled {
            if let Some(info) = self.session_cache.get(&session_id) {
                return Ok(Some(*info));
            }
        }

        // Query eBPF map
        if let Some(map) = &self.map {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&session_id);

            if let Some(value_bytes) = map.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                let info: SessionInfo = bytes_to_value(&value_bytes)?;

                // Update cache if enabled
                if self.cache_enabled {
                    self.session_cache.insert(session_id, info);
                }

                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Delete a session
    pub async fn delete_session(&mut self, session_id: u64) -> Result<()> {
        // Remove from eBPF map
        if let Some(map) = &self.map {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&session_id);
            map.delete(&key_bytes)?;
        }

        // Remove from cache
        self.session_cache.remove(&session_id);

        tracing::debug!("Deleted session: {}", session_id);
        Ok(())
    }

    /// Update session activity
    pub async fn update_session_activity(
        &mut self,
        session_id: u64,
        sequence_number: u32,
        expected_port: u32,
    ) -> Result<()> {
        if let Some(mut info) = self.get_session(session_id).await? {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64;

            info.last_sequence = sequence_number;
            info.expected_port = expected_port;
            info.last_packet_time = current_time;
            info.packet_count += 1;

            self.update_session(session_id, &info).await?;
        }

        Ok(())
    }

    /// Mark session as having security violations
    pub async fn mark_security_violation(&mut self, session_id: u64) -> Result<()> {
        if let Some(mut info) = self.get_session(session_id).await? {
            info.security_violations += 1;
            info.attack_detected = 1;

            // Escalate HMAC policy on security violations
            if info.security_violations > 3 {
                info.hmac_policy = HmacPolicy::Strong.into();
            } else if info.security_violations > 1 {
                info.hmac_policy = HmacPolicy::Medium.into();
            }

            self.update_session(session_id, &info).await?;
            tracing::warn!("Security violation for session: {}", session_id);
        }

        Ok(())
    }

    /// Get all active sessions
    pub async fn get_active_sessions(&mut self) -> Result<Vec<(u64, SessionInfo)>> {
        let mut sessions = Vec::new();

        if let Some(map) = &self.map {
            let map = map.read().await;

            for key_bytes in (*map).keys() {
                if let Some(value_bytes) = (*map).lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                    let session_id: u64 = bytes_to_value(&key_bytes)?;
                    let info: SessionInfo = bytes_to_value(&value_bytes)?;

                    if SessionState::from(info.session_state) == SessionState::Active {
                        sessions.push((session_id, info));
                    }
                }
            }
        }

        Ok(sessions)
    }

    /// Get session statistics
    pub async fn get_statistics(&self) -> Result<SessionMapStats> {
        let mut stats = SessionMapStats::default();

        if let Some(map) = &self.map {
            let map = map.read().await;

            for key_bytes in (*map).keys() {
                if let Some(value_bytes) = (*map).lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                    let info: SessionInfo = bytes_to_value(&value_bytes)?;

                    stats.total_sessions += 1;
                    stats.total_packets += info.packet_count as u64;
                    stats.total_security_violations += info.security_violations as u64;

                    match SessionState::from(info.session_state) {
                        SessionState::Active => stats.active_sessions += 1,
                        SessionState::Establishing => stats.establishing_sessions += 1,
                        SessionState::Terminating => stats.terminating_sessions += 1,
                        _ => {}
                    }

                    if info.attack_detected != 0 {
                        stats.sessions_with_attacks += 1;
                    }
                }
            }
        }

        stats.cached_sessions = self.session_cache.len() as u64;
        Ok(stats)
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&mut self, max_age_ns: u64) -> Result<u64> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;

        let mut expired_sessions = Vec::new();

        if let Some(map) = &self.map {
            let map = map.read().await;

            for key_bytes in (*map).keys() {
                if let Some(value_bytes) = (*map).lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                    let session_id: u64 = bytes_to_value(&key_bytes)?;
                    let info: SessionInfo = bytes_to_value(&value_bytes)?;

                    if current_time - info.last_packet_time > max_age_ns {
                        expired_sessions.push(session_id);
                    }
                }
            }
        }

        // Delete expired sessions
        let expired_count = expired_sessions.len() as u64;
        for session_id in expired_sessions {
            self.delete_session(session_id).await?;
        }

        if expired_count > 0 {
            tracing::info!("Cleaned up {} expired sessions", expired_count);
        }

        Ok(expired_count)
    }

    /// Cleanup all resources
    pub async fn cleanup(&mut self) -> Result<()> {
        self.session_cache.clear();
        self.map = None;
        tracing::info!("Session map manager cleaned up");
        Ok(())
    }

    // Typed convenience methods for SessionId

    /// Create session with typed SessionId
    pub async fn create_session_typed(
        &mut self,
        session_id: SessionId,
        src_ip: u32,
        src_port: Port,
        hmac_policy: HmacPolicy,
    ) -> Result<()> {
        self.create_session(session_id.as_u64(), src_ip, src_port.as_u16(), hmac_policy)
            .await
    }

    /// Update session with typed SessionId
    pub async fn update_session_typed(
        &mut self,
        session_id: SessionId,
        info: &SessionInfo,
    ) -> Result<()> {
        self.update_session(session_id.as_u64(), info).await
    }

    /// Get session with typed SessionId
    pub async fn get_session_typed(
        &mut self,
        session_id: SessionId,
    ) -> Result<Option<SessionInfo>> {
        self.get_session(session_id.as_u64()).await
    }

    /// Delete session with typed SessionId
    pub async fn delete_session_typed(&mut self, session_id: SessionId) -> Result<()> {
        self.delete_session(session_id.as_u64()).await
    }
}

impl Default for SessionMapManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Session map statistics
#[derive(Debug, Clone, Default)]
pub struct SessionMapStats {
    pub total_sessions: u64,
    pub active_sessions: u64,
    pub establishing_sessions: u64,
    pub terminating_sessions: u64,
    pub cached_sessions: u64,
    pub total_packets: u64,
    pub total_security_violations: u64,
    pub sessions_with_attacks: u64,
}

impl MapOperations<u64, SessionInfo> for SessionMapManager {
    fn lookup(&self, key: &u64) -> Result<Option<SessionInfo>> {
        // This is a synchronous version - in practice, you'd use the async version
        if self.cache_enabled {
            Ok(self.session_cache.get(key).copied())
        } else {
            // Would need to implement sync eBPF map access
            Ok(None)
        }
    }

    fn update(&self, _key: &u64, _value: &SessionInfo) -> Result<()> {
        // This would be implemented for synchronous access
        Ok(())
    }

    fn delete(&self, _key: &u64) -> Result<()> {
        // This would be implemented for synchronous access
        Ok(())
    }

    fn get_next_key(&self, _key: Option<&u64>) -> Result<Option<u64>> {
        // This would be implemented for synchronous access
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_info_default() {
        let info = SessionInfo::default();
        assert_eq!(info.session_id, 0);
        assert_eq!(info.session_state, 0);
        assert_eq!(info.hmac_policy, 0);
    }

    #[test]
    fn test_session_state_conversion() {
        assert_eq!(SessionState::from(0), SessionState::Inactive);
        assert_eq!(SessionState::from(1), SessionState::Establishing);
        assert_eq!(SessionState::from(2), SessionState::Active);
        assert_eq!(SessionState::from(3), SessionState::Terminating);
        assert_eq!(SessionState::from(255), SessionState::Inactive); // Invalid value
    }

    #[test]
    fn test_hmac_policy_conversion() {
        assert_eq!(HmacPolicy::from(0), HmacPolicy::Light);
        assert_eq!(HmacPolicy::from(1), HmacPolicy::Medium);
        assert_eq!(HmacPolicy::from(2), HmacPolicy::Strong);
        assert_eq!(HmacPolicy::from(255), HmacPolicy::Light); // Invalid value
    }

    #[tokio::test]
    async fn test_session_manager_creation() {
        let manager = SessionMapManager::new();
        assert!(manager.session_cache.is_empty());
        assert!(manager.cache_enabled);
        assert!(manager.map.is_none());
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let mut manager = SessionMapManager::new();

        // Test cache enable/disable
        manager.set_cache_enabled(false);
        assert!(!manager.cache_enabled);

        manager.set_cache_enabled(true);
        assert!(manager.cache_enabled);
    }
}
