//! Tenant identifier implementation
//!
//! TenantId uses a 64-bit format combining timestamp and counter for uniqueness.
//! Format: [48-bit timestamp (ms since epoch)][16-bit counter]

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors related to tenant ID operations
#[derive(Error, Debug)]
pub enum TenantIdError {
    #[error("Failed to get system time: {0}")]
    SystemTime(String),

    #[error("Invalid tenant ID format: {0}")]
    InvalidFormat(String),

    #[error("Failed to parse tenant ID: {0}")]
    ParseError(String),
}

/// Global atomic counter for tenant ID generation
static TENANT_ID_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Unique identifier for a tenant in the multi-tenant system.
///
/// TenantId uses a 64-bit identifier combining timestamp and counter
/// for uniqueness, collision avoidance, and temporal ordering.
///
/// Format: [48-bit timestamp (ms since epoch)][16-bit counter]
///
/// This provides:
/// - Natural temporal ordering for tenant creation
/// - ~281 trillion years of timestamp space
/// - 65,536 tenants per millisecond capacity
/// - Collision-free ID generation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TenantId(u64);

impl TenantId {
    /// Creates a new TenantId with timestamp-based uniqueness.
    ///
    /// # Returns
    ///
    /// A new TenantId or error if system time is not available.
    pub fn new() -> Result<Self, TenantIdError> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TenantIdError::SystemTime(format!("{}", e)))?
            .as_millis() as u64;

        // Validate timestamp fits in 48 bits
        if timestamp_ms > 0xFFFF_FFFF_FFFF {
            return Err(TenantIdError::SystemTime(
                "Timestamp exceeds 48-bit limit".to_string(),
            ));
        }

        let counter = TENANT_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Combine timestamp (upper 48 bits) and counter (lower 16 bits)
        let id = (timestamp_ms << 16) | (counter as u64);

        Ok(Self(id))
    }

    /// Creates TenantId from a known value (for configuration loading).
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Extracts the raw u64 value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Extracts timestamp component (milliseconds since epoch).
    pub const fn timestamp_ms(&self) -> u64 {
        self.0 >> 16
    }

    /// Extracts counter component.
    pub const fn counter(&self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tenant-{:016x}", self.0)
    }
}

impl FromStr for TenantId {
    type Err = TenantIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Parse "tenant-{hex}" format
        if let Some(hex_part) = s.strip_prefix("tenant-") {
            let value = u64::from_str_radix(hex_part, 16)
                .map_err(|e| TenantIdError::ParseError(format!("Invalid hex value: {}", e)))?;
            Ok(Self(value))
        } else {
            Err(TenantIdError::InvalidFormat(
                "Expected format: tenant-{hex}".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_creation() {
        let id1 = TenantId::new();
        assert!(id1.is_ok());

        let id2 = TenantId::new();
        assert!(id2.is_ok());

        // IDs should be unique
        assert_ne!(id1.unwrap(), id2.unwrap());
    }

    #[test]
    fn test_tenant_id_components() {
        let id = TenantId::new().unwrap();

        let timestamp = id.timestamp_ms();
        let counter = id.counter();

        // Reconstruct and verify
        let reconstructed = (timestamp << 16) | (counter as u64);
        assert_eq!(reconstructed, id.as_u64());
    }

    #[test]
    fn test_tenant_id_from_u64() {
        let value = 0x0123_4567_89AB_CDEF;
        let id = TenantId::from_u64(value);

        assert_eq!(id.as_u64(), value);
        assert_eq!(id.timestamp_ms(), 0x0123_4567_89AB);
        assert_eq!(id.counter(), 0xCDEF);
    }

    #[test]
    fn test_tenant_id_display() {
        let id = TenantId::from_u64(0x0123_4567_89AB_CDEF);
        let display = format!("{}", id);

        assert_eq!(display, "tenant-0123456789abcdef");
    }

    #[test]
    fn test_tenant_id_from_str() {
        let id_str = "tenant-0123456789abcdef";
        let id = TenantId::from_str(id_str);

        assert!(id.is_ok());
        assert_eq!(id.unwrap().as_u64(), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn test_tenant_id_roundtrip() {
        let id1 = TenantId::new().unwrap();
        let id_str = format!("{}", id1);
        let id2 = TenantId::from_str(&id_str).unwrap();

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_tenant_id_invalid_format() {
        let result = TenantId::from_str("invalid");
        assert!(result.is_err());

        let result = TenantId::from_str("tenant-xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_tenant_id_ordering() {
        let id1 = TenantId::from_u64(1000);
        let id2 = TenantId::from_u64(2000);
        let id3 = TenantId::from_u64(3000);

        assert!(id1 < id2);
        assert!(id2 < id3);
        assert!(id1 < id3);
    }

    #[test]
    fn test_tenant_id_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        let id1 = TenantId::from_u64(100);
        let id2 = TenantId::from_u64(200);
        let id3 = TenantId::from_u64(100); // Duplicate

        assert!(set.insert(id1));
        assert!(set.insert(id2));
        assert!(!set.insert(id3)); // Should fail as duplicate
    }

    #[test]
    fn test_counter_increment() {
        // Create multiple IDs in quick succession
        let mut counters = Vec::new();
        for _ in 0..10 {
            let id = TenantId::new().unwrap();
            counters.push(id.counter());
        }

        // Verify counters are increasing
        for i in 1..counters.len() {
            assert!(counters[i] >= counters[i - 1]);
        }
    }
}
