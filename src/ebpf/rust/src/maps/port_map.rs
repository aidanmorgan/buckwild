//! Port map management
//! This module provides management for port-related eBPF maps.
//! It handles port statistics, port hopping coordination, and port validation.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use super::{MapOperations, bytes_to_value, value_to_bytes};
use anyhow::Result;
use buckwild_common::protocol::types::*;
use libbpf_rs::Map;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Port statistics structure (matches eBPF struct)
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStats {
    pub packet_count: PacketCount,
    pub byte_count: ByteCount,
    pub last_used_time: Timestamp,
    pub session_count: SessionCount,
    pub security_events: EventCount,
    pub rate_limit_violations: EventCount,
    pub attack_attempts: EventCount,
    pub current_hop_window: u16,
    pub security_level: u8,
    pub reserved: u8,
}

impl Default for PortStats {
    fn default() -> Self {
        Self {
            packet_count: PacketCount::zero(),
            byte_count: ByteCount::from_raw(0),
            last_used_time: Timestamp::from_nanos(0),
            session_count: SessionCount::new(0),
            security_events: EventCount::from_raw(0),
            rate_limit_violations: EventCount::from_raw(0),
            attack_attempts: EventCount::from_raw(0),
            current_hop_window: 0,
            security_level: 0,
            reserved: 0,
        }
    }
}

/// Port hopping state for coordination
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortHoppingState {
    pub current_port: Port,
    pub next_port: Port,
    pub transition_time: Timestamp,
    pub packets_on_current: PacketCount,
    pub packets_on_next: PacketCount,
    pub transition_active: u8,
    pub coordination_required: u8,
    pub reserved: u16,
}

impl Default for PortHoppingState {
    fn default() -> Self {
        Self {
            current_port: Port::from_raw(0),
            next_port: Port::from_raw(0),
            transition_time: Timestamp::from_nanos(0),
            packets_on_current: PacketCount::zero(),
            packets_on_next: PacketCount::zero(),
            transition_active: 0,
            coordination_required: 0,
            reserved: 0,
        }
    }
}

/// Port security levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortSecurityLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl From<u8> for PortSecurityLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => PortSecurityLevel::Low,
            1 => PortSecurityLevel::Medium,
            2 => PortSecurityLevel::High,
            3 => PortSecurityLevel::Critical,
            _ => PortSecurityLevel::Low,
        }
    }
}

impl From<PortSecurityLevel> for u8 {
    fn from(level: PortSecurityLevel) -> Self {
        level as u8
    }
}

/// Port map manager
pub struct PortMapManager {
    port_stats_map: Option<Arc<RwLock<Map>>>,
    port_hopping_map: Option<Arc<RwLock<Map>>>,
    stats_cache: HashMap<u32, PortStats>,
    hopping_cache: HashMap<u64, PortHoppingState>,
    cache_enabled: bool,
}

impl PortMapManager {
    /// Create a new port map manager
    pub fn new() -> Self {
        Self {
            port_stats_map: None,
            port_hopping_map: None,
            stats_cache: HashMap::new(),
            hopping_cache: HashMap::new(),
            cache_enabled: true,
        }
    }

    /// Initialize the port map manager
    pub async fn initialize(&mut self) -> Result<()> {
        self.stats_cache.clear();
        self.hopping_cache.clear();
        tracing::info!("Port map manager initialized");
        Ok(())
    }

    /// Set the port statistics eBPF map reference
    pub async fn set_map(&mut self, map: Arc<RwLock<Map>>) -> Result<()> {
        self.port_stats_map = Some(map);
        tracing::info!("Port statistics map reference set");
        Ok(())
    }

    /// Set the port hopping eBPF map reference
    pub async fn set_hopping_map(&mut self, map: Arc<RwLock<Map>>) -> Result<()> {
        self.port_hopping_map = Some(map);
        tracing::info!("Port hopping map reference set");
        Ok(())
    }

    /// Enable or disable caching
    pub fn set_cache_enabled(&mut self, enabled: bool) {
        self.cache_enabled = enabled;
        if !enabled {
            self.stats_cache.clear();
            self.hopping_cache.clear();
        }
    }

    /// Update port statistics
    pub async fn update_port_stats(
        &mut self,
        port: Port,
        packet_size: PacketSize,
        security_event: bool,
    ) -> Result<()> {
        let port_key = port.as_raw() as u32;
        let current_time = Timestamp::from_nanos(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64,
        );

        // Get existing stats or create new ones
        let mut stats = self.get_port_stats(port).await?.unwrap_or_default();

        // Update statistics
        stats
            .packet_count
            .increment(std::sync::atomic::Ordering::Relaxed);
        stats.byte_count.fetch_add(
            packet_size.as_usize() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        stats.last_used_time = current_time;

        if security_event {
            stats
                .security_events
                .increment(std::sync::atomic::Ordering::Relaxed);
        }

        // Update eBPF map
        if let Some(map) = &self.port_stats_map {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&port_key);
            let value_bytes = value_to_bytes(&stats);
            map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
        }

        // Update cache if enabled
        if self.cache_enabled {
            self.stats_cache.insert(port_key, stats);
        }

        Ok(())
    }

    /// Get port statistics
    pub async fn get_port_stats(&mut self, port: Port) -> Result<Option<PortStats>> {
        let port_key = port.as_raw() as u32;

        // Check cache first if enabled
        if self.cache_enabled {
            if let Some(stats) = self.stats_cache.get(&port_key) {
                return Ok(Some(stats.clone()));
            }
        }

        // Query eBPF map
        if let Some(map) = &self.port_stats_map {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&port_key);

            if let Some(value_bytes) = map.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                let stats: PortStats = bytes_to_value(&value_bytes)?;

                // Update cache if enabled
                if self.cache_enabled {
                    self.stats_cache.insert(port_key, stats.clone());
                }

                return Ok(Some(stats));
            }
        }

        Ok(None)
    }

    /// Update port security level
    pub async fn update_port_security_level(
        &mut self,
        port: Port,
        level: PortSecurityLevel,
    ) -> Result<()> {
        if let Some(mut stats) = self.get_port_stats(port).await? {
            stats.security_level = level.into();

            let port_key = port.as_raw() as u32;

            // Update eBPF map
            if let Some(map) = &self.port_stats_map {
                let map = map.read().await;
                let key_bytes = value_to_bytes(&port_key);
                let value_bytes = value_to_bytes(&stats);
                map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
            }

            // Update cache if enabled
            if self.cache_enabled {
                self.stats_cache.insert(port_key, stats);
            }
        }

        Ok(())
    }

    /// Record security event for a port
    pub async fn record_security_event(
        &mut self,
        port: Port,
        event_type: SecurityEventType,
    ) -> Result<()> {
        if let Some(mut stats) = self.get_port_stats(port).await? {
            stats
                .security_events
                .increment(std::sync::atomic::Ordering::Relaxed);

            match event_type {
                SecurityEventType::RateLimit => {
                    stats
                        .rate_limit_violations
                        .increment(std::sync::atomic::Ordering::Relaxed);
                }
                SecurityEventType::Attack => {
                    stats
                        .attack_attempts
                        .increment(std::sync::atomic::Ordering::Relaxed);
                }
            }

            // Escalate security level based on events
            let current_level = PortSecurityLevel::from(stats.security_level);
            let new_level = match (current_level, event_type) {
                (PortSecurityLevel::Low, SecurityEventType::Attack) => PortSecurityLevel::Medium,
                (PortSecurityLevel::Medium, SecurityEventType::Attack) => PortSecurityLevel::High,
                (PortSecurityLevel::High, SecurityEventType::Attack) => PortSecurityLevel::Critical,
                _ => current_level,
            };

            stats.security_level = new_level.into();

            let port_key = port.as_raw() as u32;

            // Update eBPF map
            if let Some(map) = &self.port_stats_map {
                let map = map.read().await;
                let key_bytes = value_to_bytes(&port_key);
                let value_bytes = value_to_bytes(&stats);
                map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
            }

            // Update cache if enabled
            if self.cache_enabled {
                self.stats_cache.insert(port_key, stats);
            }

            tracing::warn!(
                "Security event {:?} recorded for port {}",
                event_type,
                port.as_raw()
            );
        }

        Ok(())
    }

    /// Update port hopping state
    pub async fn update_port_hopping_state(
        &mut self,
        session_id: &SessionId,
        state: &PortHoppingState,
    ) -> Result<()> {
        let session_id_raw = session_id.as_raw();
        // Update eBPF map
        if let Some(map) = &self.port_hopping_map {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&session_id_raw);
            let value_bytes = value_to_bytes(state);
            map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
        }

        // Update cache if enabled
        if self.cache_enabled {
            self.hopping_cache.insert(session_id_raw, state.clone());
        }

        Ok(())
    }

    /// Get port hopping state
    pub async fn get_port_hopping_state(
        &mut self,
        session_id: &SessionId,
    ) -> Result<Option<PortHoppingState>> {
        let session_id_raw = session_id.as_raw();

        // Check cache first if enabled
        if self.cache_enabled {
            if let Some(state) = self.hopping_cache.get(&session_id_raw) {
                return Ok(Some(state.clone()));
            }
        }

        // Query eBPF map
        if let Some(map) = &self.port_hopping_map {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&session_id_raw);

            if let Some(value_bytes) = map.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                let state: PortHoppingState = bytes_to_value(&value_bytes)?;

                // Update cache if enabled
                if self.cache_enabled {
                    self.hopping_cache.insert(session_id_raw, state.clone());
                }

                return Ok(Some(state));
            }
        }

        Ok(None)
    }

    /// Initiate port transition
    pub async fn initiate_port_transition(
        &mut self,
        session_id: &SessionId,
        current_port: Port,
        next_port: Port,
    ) -> Result<()> {
        let current_time = Timestamp::from_nanos(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64,
        );

        let state = PortHoppingState {
            current_port,
            next_port,
            transition_time: current_time,
            packets_on_current: PacketCount::zero(),
            packets_on_next: PacketCount::zero(),
            transition_active: 1,
            coordination_required: 1,
            reserved: 0,
        };

        self.update_port_hopping_state(session_id, &state).await?;
        tracing::debug!(
            "Initiated port transition for session {} from {} to {}",
            session_id.as_raw(),
            current_port.as_raw(),
            next_port.as_raw()
        );
        Ok(())
    }

    /// Complete port transition
    pub async fn complete_port_transition(&mut self, session_id: &SessionId) -> Result<()> {
        if let Some(mut state) = self.get_port_hopping_state(session_id).await? {
            state.current_port = state.next_port;
            state.next_port = Port::from_raw(0);
            state.transition_active = 0;
            state.coordination_required = 0;
            state.packets_on_current = state.packets_on_next;
            state.packets_on_next = PacketCount::zero();

            self.update_port_hopping_state(session_id, &state).await?;
            tracing::debug!(
                "Completed port transition for session {} to port {}",
                session_id.as_raw(),
                state.current_port.as_raw()
            );
        }

        Ok(())
    }

    /// Get top ports by traffic
    pub async fn get_top_ports_by_traffic(
        &mut self,
        limit: usize,
    ) -> Result<Vec<(Port, PortStats)>> {
        let mut port_stats = Vec::new();

        if let Some(map) = &self.port_stats_map {
            let map = map.read().await;

            for key_bytes in (*map).keys() {
                if let Some(value_bytes) = (*map).lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                    let port: u32 = bytes_to_value(&key_bytes)?;
                    let stats: PortStats = bytes_to_value(&value_bytes)?;
                    port_stats.push((Port::from_raw(port as u16), stats));
                }
            }
        }

        // Sort by packet count and take top N
        port_stats.sort_by(|a, b| b.1.packet_count.as_raw().cmp(&a.1.packet_count.as_raw()));
        port_stats.truncate(limit);

        Ok(port_stats)
    }

    /// Get ports with security events
    pub async fn get_ports_with_security_events(&mut self) -> Result<Vec<(Port, PortStats)>> {
        let mut security_ports = Vec::new();

        if let Some(map) = &self.port_stats_map {
            let map = map.read().await;

            for key_bytes in (*map).keys() {
                if let Some(value_bytes) = (*map).lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                    let port: u32 = bytes_to_value(&key_bytes)?;
                    let stats: PortStats = bytes_to_value(&value_bytes)?;

                    if stats
                        .security_events
                        .load(std::sync::atomic::Ordering::Relaxed)
                        > 0
                    {
                        security_ports.push((Port::from_raw(port as u16), stats));
                    }
                }
            }
        }

        // Sort by security events count
        security_ports.sort_by(|a, b| {
            b.1.security_events
                .load(std::sync::atomic::Ordering::Relaxed)
                .cmp(
                    &a.1.security_events
                        .load(std::sync::atomic::Ordering::Relaxed),
                )
        });

        Ok(security_ports)
    }

    /// Get port map statistics
    pub async fn get_statistics(&self) -> Result<PortMapStats> {
        let mut stats = PortMapStats::default();

        if let Some(map) = &self.port_stats_map {
            let map = map.read().await;

            for key_bytes in (*map).keys() {
                if let Some(value_bytes) = (*map).lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                    let port_stats: PortStats = bytes_to_value(&value_bytes)?;

                    stats
                        .total_ports
                        .increment(std::sync::atomic::Ordering::Relaxed);
                    stats.total_packets.fetch_add(
                        port_stats.packet_count.as_raw(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    stats.total_bytes.fetch_add(
                        port_stats
                            .byte_count
                            .load(std::sync::atomic::Ordering::Relaxed),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    stats.total_security_events.fetch_add(
                        port_stats
                            .security_events
                            .load(std::sync::atomic::Ordering::Relaxed),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    stats.total_rate_limit_violations.fetch_add(
                        port_stats
                            .rate_limit_violations
                            .load(std::sync::atomic::Ordering::Relaxed),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    stats.total_attack_attempts.fetch_add(
                        port_stats
                            .attack_attempts
                            .load(std::sync::atomic::Ordering::Relaxed),
                        std::sync::atomic::Ordering::Relaxed,
                    );

                    if port_stats
                        .security_events
                        .load(std::sync::atomic::Ordering::Relaxed)
                        > 0
                    {
                        stats
                            .ports_with_security_events
                            .increment(std::sync::atomic::Ordering::Relaxed);
                    }

                    if port_stats.packet_count.as_raw() > 0 {
                        stats
                            .active_ports
                            .increment(std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }

        stats.cached_port_stats = EventCount::from_raw(self.stats_cache.len() as u64);
        stats.cached_hopping_states = EventCount::from_raw(self.hopping_cache.len() as u64);

        Ok(stats)
    }

    /// Cleanup expired port hopping states
    pub async fn cleanup_expired_hopping_states(
        &mut self,
        max_age: std::time::Duration,
    ) -> Result<EventCount> {
        let current_time = Timestamp::from_nanos(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64,
        );

        let mut expired_states = Vec::new();

        if let Some(map) = &self.port_hopping_map {
            let map = map.read().await;

            for key_bytes in (*map).keys() {
                if let Some(value_bytes) = (*map).lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                    let session_id: u64 = bytes_to_value(&key_bytes)?;
                    let state: PortHoppingState = bytes_to_value(&value_bytes)?;

                    if (current_time.as_nanos() - state.transition_time.as_nanos()) as u64
                        > max_age.as_nanos() as u64
                    {
                        expired_states.push(session_id);
                    }
                }
            }
        }

        // Delete expired states
        let expired_count = EventCount::from_raw(expired_states.len() as u64);
        for session_id in expired_states {
            if let Some(map) = &self.port_hopping_map {
                let map = map.read().await;
                let key_bytes = value_to_bytes(&session_id);
                map.delete(&key_bytes)?;
            }
            self.hopping_cache.remove(&session_id);
        }

        if expired_count.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            tracing::info!(
                "Cleaned up {} expired port hopping states",
                expired_count.load(std::sync::atomic::Ordering::Relaxed)
            );
        }

        Ok(expired_count)
    }

    /// Cleanup all resources
    pub async fn cleanup(&mut self) -> Result<()> {
        self.stats_cache.clear();
        self.hopping_cache.clear();
        self.port_stats_map = None;
        self.port_hopping_map = None;
        tracing::info!("Port map manager cleaned up");
        Ok(())
    }
}

impl Default for PortMapManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Security event types for ports
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityEventType {
    RateLimit,
    Attack,
}

/// Port map statistics
#[derive(Debug, Clone, Default)]
pub struct PortMapStats {
    pub total_ports: EventCount,
    pub active_ports: EventCount,
    pub ports_with_security_events: EventCount,
    pub cached_port_stats: EventCount,
    pub cached_hopping_states: EventCount,
    pub total_packets: PacketCount,
    pub total_bytes: ByteCount,
    pub total_security_events: EventCount,
    pub total_rate_limit_violations: EventCount,
    pub total_attack_attempts: EventCount,
}

impl MapOperations<u32, PortStats> for PortMapManager {
    fn lookup(&self, key: &u32) -> Result<Option<PortStats>> {
        if self.cache_enabled {
            Ok(self.stats_cache.get(key).cloned())
        } else {
            Ok(None)
        }
    }

    fn update(&self, _key: &u32, _value: &PortStats) -> Result<()> {
        Ok(())
    }

    fn delete(&self, _key: &u32) -> Result<()> {
        Ok(())
    }

    fn get_next_key(&self, _key: Option<&u32>) -> Result<Option<u32>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_stats_default() {
        let stats = PortStats::default();
        assert_eq!(stats.packet_count, PacketCount::new(0));
        assert_eq!(stats.security_events, EventCount::new(0));
        assert_eq!(stats.security_level, 0);
    }

    #[test]
    fn test_port_hopping_state_default() {
        let state = PortHoppingState::default();
        assert_eq!(state.current_port, Port::from_raw(0));
        assert_eq!(state.next_port, Port::from_raw(0));
        assert_eq!(state.transition_active, 0);
    }

    #[test]
    fn test_port_security_level_conversion() {
        assert_eq!(PortSecurityLevel::from(0), PortSecurityLevel::Low);
        assert_eq!(PortSecurityLevel::from(1), PortSecurityLevel::Medium);
        assert_eq!(PortSecurityLevel::from(2), PortSecurityLevel::High);
        assert_eq!(PortSecurityLevel::from(3), PortSecurityLevel::Critical);
        assert_eq!(PortSecurityLevel::from(255), PortSecurityLevel::Low);
    }

    #[tokio::test]
    async fn test_port_manager_creation() {
        let manager = PortMapManager::new();
        assert!(manager.stats_cache.is_empty());
        assert!(manager.hopping_cache.is_empty());
        assert!(manager.cache_enabled);
        assert!(manager.port_stats_map.is_none());
        assert!(manager.port_hopping_map.is_none());
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let mut manager = PortMapManager::new();

        manager.set_cache_enabled(false);
        assert!(!manager.cache_enabled);
        assert!(manager.stats_cache.is_empty());
        assert!(manager.hopping_cache.is_empty());

        manager.set_cache_enabled(true);
        assert!(manager.cache_enabled);
    }
}
