//! Shared port allocation strategy for multi-tenant deployment
//!
//! Implements session-based routing (Option B from design) where:
//! - All tenants share the full port range (1024-65535)
//! - Port calculation incorporates tenant context for distribution
//! - Session ID routing bypasses port-based filtering
//!
//! This strategy provides:
//! - Maximum port space utilization
//! - Unlimited tenant scaling
//! - Flexible resource allocation

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::{MIN_PORT, Port, SessionId};
use crate::tenant::TenantId;
use std::sync::Arc;
use thiserror::Error;

/// Errors related to port allocation
#[derive(Error, Debug)]
pub enum PortAllocationError {
    #[error("Invalid port range: start={start}, end={end}")]
    InvalidPortRange { start: u16, end: u16 },

    #[error("Port calculation overflow")]
    CalculationOverflow,
}

/// Port range definition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Creates a new port range
    pub fn new(start: u16, end: u16) -> Result<Self, PortAllocationError> {
        if start >= end {
            return Err(PortAllocationError::InvalidPortRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Returns the start port
    pub const fn start(&self) -> u16 {
        self.start
    }

    /// Returns the end port
    pub const fn end(&self) -> u16 {
        self.end
    }

    /// Returns the size of the range
    pub const fn size(&self) -> u32 {
        (self.end - self.start + 1) as u32
    }
}

/// Shared port allocation strategy with tenant routing via session ID.
///
/// Advantages:
/// - Maximum port space utilization
/// - Unlimited tenant scaling
/// - Flexible resource allocation
///
/// Port calculation incorporates tenant ID for distribution while
/// session ID routing provides actual packet dispatch.
#[derive(Debug, Clone)]
pub struct SharedPortStrategy {
    /// Full port range available for all tenants
    available_ports: PortRange,
}

impl SharedPortStrategy {
    /// Creates strategy using entire non-privileged port range
    pub fn full_range() -> Result<Self, PortAllocationError> {
        Ok(Self {
            available_ports: PortRange::new(MIN_PORT.as_u16(), 65535)?,
        })
    }

    /// Creates strategy with custom port range
    pub fn with_range(range: PortRange) -> Self {
        Self {
            available_ports: range,
        }
    }

    /// Calculates port for a tenant session at a given time window.
    ///
    /// Port calculation incorporates:
    /// - Tenant ID for distribution across port space
    /// - Session ID for session-specific variation
    /// - Time window for frequency hopping
    /// - Port hop seed for additional entropy
    ///
    /// This ensures:
    /// - Different tenants use different port ranges (probabilistically)
    /// - Same session uses different ports over time
    /// - Port sequences unpredictable without session parameters
    pub fn calculate_port(
        &self,
        tenant_id: TenantId,
        session_id: &SessionId,
        time_window: u64,
        port_hop_seed: u32,
    ) -> Port {
        // Hash tenant ID for distribution
        let tenant_hash = self.hash_64bit(&tenant_id.as_u64().to_be_bytes());

        // Hash session ID for session-specific variation
        let session_hash = self.hash_64bit(&session_id.get().to_be_bytes());

        // Hash time window for temporal variation
        let window_hash = self.hash_64bit(&time_window.to_be_bytes());

        // Combine all hashes with port hop seed
        let combined = tenant_hash ^ session_hash ^ window_hash ^ (port_hop_seed as u64);

        // Map to port range
        let port_offset = (combined % self.available_ports.size() as u64) as u16;
        let port_value = self.available_ports.start() + port_offset;

        Port::from_u16_unchecked(port_value)
    }

    /// Returns the available port range
    pub const fn port_range(&self) -> &PortRange {
        &self.available_ports
    }

    /// Simple hash function for 64-bit values
    ///
    /// Uses FNV-1a hash algorithm for simplicity and speed.
    fn hash_64bit(&self, bytes: &[u8]) -> u64 {
        const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut hash = FNV_OFFSET_BASIS;
        for &byte in bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }
}

impl Default for SharedPortStrategy {
    fn default() -> Self {
        Self::full_range().unwrap_or({
            Self {
                available_ports: PortRange {
                    start: 1024,
                    end: 65535,
                },
            }
        })
    }
}

/// Port allocation manager coordinating tenant-aware port selection
pub struct PortAllocationManager {
    /// Shared port strategy
    strategy: Arc<SharedPortStrategy>,
}

impl PortAllocationManager {
    /// Creates a new port allocation manager with full range strategy
    pub fn new() -> Result<Self, PortAllocationError> {
        Ok(Self {
            strategy: Arc::new(SharedPortStrategy::full_range()?),
        })
    }

    /// Creates manager with custom strategy
    pub fn with_strategy(strategy: SharedPortStrategy) -> Self {
        Self {
            strategy: Arc::new(strategy),
        }
    }

    /// Calculates port for tenant session
    pub fn calculate_port(
        &self,
        tenant_id: TenantId,
        session_id: &SessionId,
        time_window: u64,
        port_hop_seed: u32,
    ) -> Port {
        self.strategy
            .calculate_port(tenant_id, session_id, time_window, port_hop_seed)
    }

    /// Returns the port range
    pub fn port_range(&self) -> &PortRange {
        self.strategy.port_range()
    }
}

impl Default for PortAllocationManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            strategy: Arc::new(SharedPortStrategy::default()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_range_creation() {
        let range = PortRange::new(1024, 65535);
        assert!(range.is_ok());

        let range = range.unwrap();
        assert_eq!(range.start(), 1024);
        assert_eq!(range.end(), 65535);
        assert_eq!(range.size(), 64512);
    }

    #[test]
    fn test_port_range_invalid() {
        let range = PortRange::new(65535, 1024);
        assert!(range.is_err());

        let range = PortRange::new(1024, 1024);
        assert!(range.is_err());
    }

    #[test]
    fn test_shared_port_strategy_creation() {
        let strategy = SharedPortStrategy::full_range();
        assert!(strategy.is_ok());

        let strategy = strategy.unwrap();
        assert_eq!(strategy.port_range().start(), 1024);
        assert_eq!(strategy.port_range().end(), 65535);
    }

    #[test]
    fn test_port_calculation_deterministic() {
        let strategy = SharedPortStrategy::full_range().unwrap();
        let tenant_id = TenantId::from_u64(1);
        let session_id = SessionId::new(42);

        let port1 = strategy.calculate_port(tenant_id, &session_id, 1000, 123);
        let port2 = strategy.calculate_port(tenant_id, &session_id, 1000, 123);

        assert_eq!(port1, port2);
    }

    #[test]
    fn test_port_calculation_varies_by_tenant() {
        let strategy = SharedPortStrategy::full_range().unwrap();
        let tenant1 = TenantId::from_u64(1);
        let tenant2 = TenantId::from_u64(2);
        let session_id = SessionId::new(42);

        let port1 = strategy.calculate_port(tenant1, &session_id, 1000, 123);
        let port2 = strategy.calculate_port(tenant2, &session_id, 1000, 123);

        // Different tenants should (probabilistically) get different ports
        assert_ne!(port1, port2);
    }

    #[test]
    fn test_port_calculation_varies_by_session() {
        let strategy = SharedPortStrategy::full_range().unwrap();
        let tenant_id = TenantId::from_u64(1);
        let session1 = SessionId::new(42);
        let session2 = SessionId::new(43);

        let port1 = strategy.calculate_port(tenant_id, &session1, 1000, 123);
        let port2 = strategy.calculate_port(tenant_id, &session2, 1000, 123);

        // Different sessions should get different ports
        assert_ne!(port1, port2);
    }

    #[test]
    fn test_port_calculation_varies_by_time() {
        let strategy = SharedPortStrategy::full_range().unwrap();
        let tenant_id = TenantId::from_u64(1);
        let session_id = SessionId::new(42);

        let port1 = strategy.calculate_port(tenant_id, &session_id, 1000, 123);
        let port2 = strategy.calculate_port(tenant_id, &session_id, 2000, 123);

        // Different time windows should get different ports
        assert_ne!(port1, port2);
    }

    #[test]
    fn test_port_calculation_in_range() {
        let strategy = SharedPortStrategy::full_range().unwrap();
        let tenant_id = TenantId::from_u64(1);
        let session_id = SessionId::new(42);

        for time_window in 0..100 {
            let port = strategy.calculate_port(tenant_id, &session_id, time_window, 123);
            assert!(port.as_u16() >= 1024);
        }
    }

    #[test]
    fn test_port_allocation_manager() {
        let manager = PortAllocationManager::new().unwrap();
        let tenant_id = TenantId::from_u64(1);
        let session_id = SessionId::new(42);

        let port = manager.calculate_port(tenant_id, &session_id, 1000, 123);
        assert!(port.as_u16() >= 1024);
    }

    #[test]
    fn test_port_distribution_across_tenants() {
        let strategy = SharedPortStrategy::full_range().unwrap();
        let session_id = SessionId::new(42);
        let mut ports = std::collections::HashSet::new();

        // Generate ports for multiple tenants
        for tenant_num in 0..100 {
            let tenant_id = TenantId::from_u64(tenant_num);
            let port = strategy.calculate_port(tenant_id, &session_id, 1000, 123);
            ports.insert(port.as_u16());
        }

        // Should have good distribution (at least 90% unique)
        assert!(ports.len() >= 90);
    }

    #[test]
    fn test_hash_function_distribution() {
        let strategy = SharedPortStrategy::full_range().unwrap();

        // Test that hash function produces diverse outputs
        let mut hashes = std::collections::HashSet::new();
        for i in 0..100 {
            let input = (i as u64).to_be_bytes();
            let hash = strategy.hash_64bit(&input);
            hashes.insert(hash);
        }

        // Should have high uniqueness (FNV-1a produces good distribution)
        assert!(
            hashes.len() >= 95,
            "Expected at least 95 unique hashes, got {}",
            hashes.len()
        );
    }
}
