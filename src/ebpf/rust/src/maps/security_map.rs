//! Security map management
//! This module provides management for security-related eBPF maps.
//! It handles rate limiting, attack detection, fragment security, and security statistics.

#![cfg(target_os = "linux")]

use super::{MapOperations, bytes_to_value, value_to_bytes};
use anyhow::Result;
use libbpf_rs::Map;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Rate limiting information structure (matches eBPF struct)
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub last_reset_time: u64,
    pub packet_count: u32,
    pub byte_count: u32,
    pub violation_count: u32,
    pub blocked: u8,
    pub escalation_level: u8,
    pub block_duration: u16,
    pub last_violation_time: u64,
    pub total_violations: u32,
}

impl Default for RateLimitInfo {
    fn default() -> Self {
        Self {
            last_reset_time: 0,
            packet_count: 0,
            byte_count: 0,
            violation_count: 0,
            blocked: 0,
            escalation_level: 0,
            block_duration: 0,
            last_violation_time: 0,
            total_violations: 0,
        }
    }
}

/// Attack detection information structure (matches eBPF struct)
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AttackDetectionInfo {
    pub src_ip: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub connection_attempts: u32,
    pub failed_authentications: u32,
    pub enumeration_score: u32,
    pub replay_attempts: u32,
    pub timing_violations: u32,
    pub attack_type: u8,
    pub confidence_level: u8,
    pub response_level: u8,
    pub permanent_block: u8,
}

impl Default for AttackDetectionInfo {
    fn default() -> Self {
        Self {
            src_ip: 0,
            first_seen: 0,
            last_seen: 0,
            connection_attempts: 0,
            failed_authentications: 0,
            enumeration_score: 0,
            replay_attempts: 0,
            timing_violations: 0,
            attack_type: 0,
            confidence_level: 0,
            response_level: 0,
            permanent_block: 0,
        }
    }
}

/// Fragment security information structure (matches eBPF struct)
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FragmentSecurityInfo {
    pub session_id: u64,
    pub src_ip: u32,
    pub fragment_id: u16,
    pub total_fragments: u16,
    pub received_fragments: u32,
    pub total_bytes: u32,
    pub first_fragment_time: u64,
    pub last_fragment_time: u64,
    pub fragment_rate: u32,
    pub overlap_detected: u8,
    pub bomb_detected: u8,
    pub session_bound: u8,
    pub reserved: u8,
}

impl Default for FragmentSecurityInfo {
    fn default() -> Self {
        Self {
            session_id: 0,
            src_ip: 0,
            fragment_id: 0,
            total_fragments: 0,
            received_fragments: 0,
            total_bytes: 0,
            first_fragment_time: 0,
            last_fragment_time: 0,
            fragment_rate: 0,
            overlap_detected: 0,
            bomb_detected: 0,
            session_bound: 0,
            reserved: 0,
        }
    }
}

/// Security statistics structure (matches eBPF struct)
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SecurityStats {
    pub total_packets: u64,
    pub dropped_packets: u64,
    pub security_events: u64,
    pub rate_limit_violations: u64,
    pub fragment_attacks: u64,
    pub replay_attacks: u64,
    pub enumeration_attempts: u64,
    pub timing_attacks: u64,
    pub blocked_sources: u64,
    pub last_update_time: u64,
}

impl Default for SecurityStats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            dropped_packets: 0,
            security_events: 0,
            rate_limit_violations: 0,
            fragment_attacks: 0,
            replay_attacks: 0,
            enumeration_attempts: 0,
            timing_attacks: 0,
            blocked_sources: 0,
            last_update_time: 0,
        }
    }
}

/// Attack types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttackType {
    None = 0,
    RateLimit = 1,
    FragmentBomb = 2,
    FragmentOverlap = 3,
    Replay = 4,
    Enumeration = 5,
    Timing = 6,
    SessionHijack = 7,
    InvalidPacket = 8,
    PortScan = 9,
    UnknownSession = 10,
}

impl From<u8> for AttackType {
    fn from(value: u8) -> Self {
        match value {
            0 => AttackType::None,
            1 => AttackType::RateLimit,
            2 => AttackType::FragmentBomb,
            3 => AttackType::FragmentOverlap,
            4 => AttackType::Replay,
            5 => AttackType::Enumeration,
            6 => AttackType::Timing,
            7 => AttackType::SessionHijack,
            8 => AttackType::InvalidPacket,
            9 => AttackType::PortScan,
            10 => AttackType::UnknownSession,
            _ => AttackType::None,
        }
    }
}

impl From<AttackType> for u8 {
    fn from(attack_type: AttackType) -> Self {
        attack_type as u8
    }
}

/// Response levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseLevel {
    Monitor = 0,
    RateLimit = 1,
    TempBlock = 2,
    PermBlock = 3,
}

impl From<u8> for ResponseLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => ResponseLevel::Monitor,
            1 => ResponseLevel::RateLimit,
            2 => ResponseLevel::TempBlock,
            3 => ResponseLevel::PermBlock,
            _ => ResponseLevel::Monitor,
        }
    }
}

impl From<ResponseLevel> for u8 {
    fn from(level: ResponseLevel) -> Self {
        level as u8
    }
}

/// Security map manager
pub struct SecurityMapManager {
    maps: HashMap<String, Arc<RwLock<Map>>>,
    rate_limit_cache: HashMap<u32, RateLimitInfo>,
    attack_detection_cache: HashMap<u32, AttackDetectionInfo>,
    fragment_security_cache: HashMap<u64, FragmentSecurityInfo>,
    cache_enabled: bool,
}

impl SecurityMapManager {
    /// Create a new security map manager
    pub fn new() -> Self {
        Self {
            maps: HashMap::new(),
            rate_limit_cache: HashMap::new(),
            attack_detection_cache: HashMap::new(),
            fragment_security_cache: HashMap::new(),
            cache_enabled: true,
        }
    }

    /// Initialize the security map manager
    pub async fn initialize(&mut self) -> Result<()> {
        self.rate_limit_cache.clear();
        self.attack_detection_cache.clear();
        self.fragment_security_cache.clear();
        tracing::info!("Security map manager initialized");
        Ok(())
    }

    /// Add an eBPF map reference
    pub async fn add_map(&mut self, name: String, map: Arc<RwLock<Map>>) -> Result<()> {
        self.maps.insert(name.clone(), map);
        tracing::info!("Added security map: {}", name);
        Ok(())
    }

    /// Enable or disable caching
    pub fn set_cache_enabled(&mut self, enabled: bool) {
        self.cache_enabled = enabled;
        if !enabled {
            self.rate_limit_cache.clear();
            self.attack_detection_cache.clear();
            self.fragment_security_cache.clear();
        }
    }

    /// Update rate limit information
    pub async fn update_rate_limit_info(
        &mut self,
        src_ip: u32,
        info: &RateLimitInfo,
    ) -> Result<()> {
        // Update eBPF map
        if let Some(map) = self.maps.get("rate_limit_map") {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&src_ip);
            let value_bytes = value_to_bytes(info);
            map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
        }

        // Update cache if enabled
        if self.cache_enabled {
            self.rate_limit_cache.insert(src_ip, *info);
        }

        Ok(())
    }

    /// Get rate limit information
    pub async fn get_rate_limit_info(&mut self, src_ip: u32) -> Result<Option<RateLimitInfo>> {
        // Check cache first if enabled
        if self.cache_enabled {
            if let Some(info) = self.rate_limit_cache.get(&src_ip) {
                return Ok(Some(*info));
            }
        }

        // Query eBPF map
        if let Some(map) = self.maps.get("rate_limit_map") {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&src_ip);

            if let Some(value_bytes) = map.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                let info: RateLimitInfo = bytes_to_value(&value_bytes)?;

                // Update cache if enabled
                if self.cache_enabled {
                    self.rate_limit_cache.insert(src_ip, info);
                }

                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Apply rate limiting
    pub async fn apply_rate_limiting(
        &mut self,
        src_ip: u32,
        packet_size: u32,
        current_time: u64,
    ) -> Result<bool> {
        let mut info = self
            .get_rate_limit_info(src_ip)
            .await?
            .unwrap_or_else(|| RateLimitInfo {
                last_reset_time: current_time,
                packet_count: 0,
                byte_count: 0,
                violation_count: 0,
                blocked: 0,
                escalation_level: 0,
                block_duration: 0,
                last_violation_time: 0,
                total_violations: 0,
            });

        // Reset counters every second
        if current_time - info.last_reset_time > 1_000_000_000 {
            info.last_reset_time = current_time;
            info.packet_count = 0;
            info.byte_count = 0;
        }

        // Update counters
        info.packet_count += 1;
        info.byte_count += packet_size;

        // Check rate limits (1000 pps or 1MB/s)
        let rate_limited = info.packet_count > 1000 || info.byte_count > 1_048_576;

        if rate_limited {
            info.violation_count += 1;
            info.total_violations += 1;
            info.last_violation_time = current_time;

            // Progressive blocking
            if info.violation_count > 3 {
                info.blocked = 1;
                info.escalation_level += 1;
                info.block_duration = 1 << info.escalation_level; // Exponential backoff
                if info.block_duration > 3600 {
                    info.block_duration = 3600; // Max 1 hour
                }
            }
        }

        self.update_rate_limit_info(src_ip, &info).await?;
        Ok(rate_limited)
    }

    /// Update attack detection information
    pub async fn update_attack_detection_info(
        &mut self,
        src_ip: u32,
        info: &AttackDetectionInfo,
    ) -> Result<()> {
        // Update eBPF map
        if let Some(map) = self.maps.get("attack_detection_map") {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&src_ip);
            let value_bytes = value_to_bytes(info);
            map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
        }

        // Update cache if enabled
        if self.cache_enabled {
            self.attack_detection_cache.insert(src_ip, *info);
        }

        Ok(())
    }

    /// Get attack detection information
    pub async fn get_attack_detection_info(
        &mut self,
        src_ip: u32,
    ) -> Result<Option<AttackDetectionInfo>> {
        // Check cache first if enabled
        if self.cache_enabled {
            if let Some(info) = self.attack_detection_cache.get(&src_ip) {
                return Ok(Some(*info));
            }
        }

        // Query eBPF map
        if let Some(map) = self.maps.get("attack_detection_map") {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&src_ip);

            if let Some(value_bytes) = map.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                let info: AttackDetectionInfo = bytes_to_value(&value_bytes)?;

                // Update cache if enabled
                if self.cache_enabled {
                    self.attack_detection_cache.insert(src_ip, info);
                }

                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Record attack attempt
    pub async fn record_attack_attempt(
        &mut self,
        src_ip: u32,
        attack_type: AttackType,
        current_time: u64,
    ) -> Result<ResponseLevel> {
        let mut info = self
            .get_attack_detection_info(src_ip)
            .await?
            .unwrap_or_else(|| AttackDetectionInfo {
                src_ip,
                first_seen: current_time,
                last_seen: current_time,
                connection_attempts: 0,
                failed_authentications: 0,
                enumeration_score: 0,
                replay_attempts: 0,
                timing_violations: 0,
                attack_type: attack_type.into(),
                confidence_level: 25,
                response_level: ResponseLevel::Monitor.into(),
                permanent_block: 0,
            });

        // Update attack information
        info.last_seen = current_time;
        info.attack_type = attack_type.into();

        match attack_type {
            AttackType::Enumeration => {
                info.connection_attempts += 1;
                info.enumeration_score += 10;
            }
            AttackType::Replay => {
                info.replay_attempts += 1;
            }
            AttackType::Timing => {
                info.timing_violations += 1;
            }
            AttackType::FragmentBomb | AttackType::FragmentOverlap => {
                info.confidence_level += 20;
            }
            _ => {}
        }

        // Escalate response based on attack frequency and type
        let time_window = current_time - info.first_seen;
        if time_window < 60_000_000_000 {
            // Within 1 minute
            info.confidence_level += 10;
            if info.confidence_level > 100 {
                info.confidence_level = 100;
            }

            // Escalate response level
            if info.confidence_level >= 90 {
                info.response_level = ResponseLevel::PermBlock.into();
                info.permanent_block = 1;
            } else if info.confidence_level >= 75 {
                info.response_level = ResponseLevel::TempBlock.into();
            } else if info.confidence_level >= 50 {
                info.response_level = ResponseLevel::RateLimit.into();
            }
        }

        let response_level = ResponseLevel::from(info.response_level);
        self.update_attack_detection_info(src_ip, &info).await?;

        tracing::warn!(
            "Attack {:?} detected from IP {}: confidence={}, response={:?}",
            attack_type,
            std::net::Ipv4Addr::from(src_ip),
            info.confidence_level,
            response_level
        );

        Ok(response_level)
    }

    /// Check if source is blocked
    pub async fn is_source_blocked(&mut self, src_ip: u32, current_time: u64) -> Result<bool> {
        if let Some(info) = self.get_attack_detection_info(src_ip).await? {
            // Check permanent block
            if info.permanent_block != 0 {
                return Ok(true);
            }

            // Check temporary block
            if ResponseLevel::from(info.response_level) >= ResponseLevel::TempBlock {
                let block_duration = 60 * (1 << info.response_level) as u64 * 1_000_000_000; // Exponential backoff in nanoseconds
                let time_since_last = current_time - info.last_seen;
                return Ok(time_since_last < block_duration);
            }
        }

        Ok(false)
    }

    /// Update fragment security information
    pub async fn update_fragment_security_info(
        &mut self,
        fragment_key: u64,
        info: &FragmentSecurityInfo,
    ) -> Result<()> {
        // Update eBPF map
        if let Some(map) = self.maps.get("fragment_security_map") {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&fragment_key);
            let value_bytes = value_to_bytes(info);
            map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
        }

        // Update cache if enabled
        if self.cache_enabled {
            self.fragment_security_cache.insert(fragment_key, *info);
        }

        Ok(())
    }

    /// Get fragment security information
    pub async fn get_fragment_security_info(
        &mut self,
        fragment_key: u64,
    ) -> Result<Option<FragmentSecurityInfo>> {
        // Check cache first if enabled
        if self.cache_enabled {
            if let Some(info) = self.fragment_security_cache.get(&fragment_key) {
                return Ok(Some(*info));
            }
        }

        // Query eBPF map
        if let Some(map) = self.maps.get("fragment_security_map") {
            let map = map.read().await;
            let key_bytes = value_to_bytes(&fragment_key);

            if let Some(value_bytes) = map.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                let info: FragmentSecurityInfo = bytes_to_value(&value_bytes)?;

                // Update cache if enabled
                if self.cache_enabled {
                    self.fragment_security_cache.insert(fragment_key, info);
                }

                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Validate fragment security
    pub async fn validate_fragment_security(
        &mut self,
        src_ip: u32,
        fragment_id: u16,
        session_id: u64,
        total_fragments: u16,
        current_time: u64,
    ) -> Result<bool> {
        let fragment_key = ((src_ip as u64) << 32) | (fragment_id as u64);

        let mut info = self
            .get_fragment_security_info(fragment_key)
            .await?
            .unwrap_or_else(|| FragmentSecurityInfo {
                session_id,
                src_ip,
                fragment_id,
                total_fragments,
                received_fragments: 1,
                total_bytes: 0,
                first_fragment_time: current_time,
                last_fragment_time: current_time,
                fragment_rate: 0,
                overlap_detected: 0,
                bomb_detected: 0,
                session_bound: 1,
                reserved: 0,
            });

        // Update fragment tracking
        info.received_fragments += 1;
        info.last_fragment_time = current_time;

        // Calculate fragment rate
        let time_diff = current_time - info.first_fragment_time;
        if time_diff > 0 {
            info.fragment_rate =
                ((info.received_fragments as u64 * 1_000_000_000) / time_diff) as u32;
        }

        // Check for fragment bomb (too many fragments)
        if info.total_fragments > 50 || info.received_fragments > 100 || info.fragment_rate > 40 {
            info.bomb_detected = 1;
            self.update_fragment_security_info(fragment_key, &info)
                .await?;

            // Record attack
            self.record_attack_attempt(src_ip, AttackType::FragmentBomb, current_time)
                .await?;
            return Ok(false);
        }

        // Check for timeout (5 seconds)
        if time_diff > 5_000_000_000 {
            // Clean up expired fragment
            if let Some(map) = self.maps.get("fragment_security_map") {
                let map = map.read().await;
                let key_bytes = value_to_bytes(&fragment_key);
                map.delete(&key_bytes)?;
            }
            self.fragment_security_cache.remove(&fragment_key);
            return Ok(false);
        }

        self.update_fragment_security_info(fragment_key, &info)
            .await?;
        Ok(true)
    }

    /// Get security statistics
    pub async fn get_security_statistics(&self) -> Result<SecurityStats> {
        if let Some(map) = self.maps.get("security_stats_map") {
            let map = map.read().await;
            let key: u32 = 0;
            let key_bytes = value_to_bytes(&key);

            if let Some(value_bytes) = map.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
                let stats: SecurityStats = bytes_to_value(&value_bytes)?;
                return Ok(stats);
            }
        }

        Ok(SecurityStats::default())
    }

    /// Get comprehensive security map statistics
    pub async fn get_statistics(&self) -> Result<SecurityMapStats> {
        let security_stats = self.get_security_statistics().await?;

        Ok(SecurityMapStats {
            cached_rate_limits: self.rate_limit_cache.len() as u64,
            cached_attack_detections: self.attack_detection_cache.len() as u64,
            cached_fragment_securities: self.fragment_security_cache.len() as u64,
            total_maps: self.maps.len() as u64,
            security_stats,
        })
    }

    /// Cleanup expired entries
    pub async fn cleanup_expired_entries(&mut self, max_age_ns: u64) -> Result<u64> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;

        let mut cleaned_count = 0;

        // Cleanup fragment security entries
        let mut expired_fragments = Vec::new();
        for (&fragment_key, info) in &self.fragment_security_cache {
            if current_time - info.last_fragment_time > max_age_ns {
                expired_fragments.push(fragment_key);
            }
        }

        for fragment_key in expired_fragments {
            if let Some(map) = self.maps.get("fragment_security_map") {
                let map = map.read().await;
                let key_bytes = value_to_bytes(&fragment_key);
                map.delete(&key_bytes)?;
            }
            self.fragment_security_cache.remove(&fragment_key);
            cleaned_count += 1;
        }

        if cleaned_count > 0 {
            tracing::info!("Cleaned up {} expired security entries", cleaned_count);
        }

        Ok(cleaned_count)
    }

    /// Cleanup all resources
    pub async fn cleanup(&mut self) -> Result<()> {
        self.rate_limit_cache.clear();
        self.attack_detection_cache.clear();
        self.fragment_security_cache.clear();
        self.maps.clear();
        tracing::info!("Security map manager cleaned up");
        Ok(())
    }
}

impl Default for SecurityMapManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Security map statistics
#[derive(Debug, Clone, Default)]
pub struct SecurityMapStats {
    pub cached_rate_limits: u64,
    pub cached_attack_detections: u64,
    pub cached_fragment_securities: u64,
    pub total_maps: u64,
    pub security_stats: SecurityStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_info_default() {
        let info = RateLimitInfo::default();
        assert_eq!(info.packet_count, 0);
        assert_eq!(info.blocked, 0);
        assert_eq!(info.escalation_level, 0);
    }

    #[test]
    fn test_attack_detection_info_default() {
        let info = AttackDetectionInfo::default();
        assert_eq!(info.src_ip, 0);
        assert_eq!(info.attack_type, 0);
        assert_eq!(info.confidence_level, 0);
        assert_eq!(info.permanent_block, 0);
    }

    #[test]
    fn test_attack_type_conversion() {
        assert_eq!(AttackType::from(0), AttackType::None);
        assert_eq!(AttackType::from(1), AttackType::RateLimit);
        assert_eq!(AttackType::from(5), AttackType::Enumeration);
        assert_eq!(AttackType::from(255), AttackType::None);
    }

    #[test]
    fn test_response_level_conversion() {
        assert_eq!(ResponseLevel::from(0), ResponseLevel::Monitor);
        assert_eq!(ResponseLevel::from(1), ResponseLevel::RateLimit);
        assert_eq!(ResponseLevel::from(2), ResponseLevel::TempBlock);
        assert_eq!(ResponseLevel::from(3), ResponseLevel::PermBlock);
        assert_eq!(ResponseLevel::from(255), ResponseLevel::Monitor);
    }

    #[tokio::test]
    async fn test_security_manager_creation() {
        let manager = SecurityMapManager::new();
        assert!(manager.maps.is_empty());
        assert!(manager.rate_limit_cache.is_empty());
        assert!(manager.attack_detection_cache.is_empty());
        assert!(manager.fragment_security_cache.is_empty());
        assert!(manager.cache_enabled);
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let mut manager = SecurityMapManager::new();

        manager.set_cache_enabled(false);
        assert!(!manager.cache_enabled);
        assert!(manager.rate_limit_cache.is_empty());

        manager.set_cache_enabled(true);
        assert!(manager.cache_enabled);
    }
}
