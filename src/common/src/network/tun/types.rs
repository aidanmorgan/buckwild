//! TUN device domain types
//!
//! This module defines domain types using the newtype pattern as specified
//! in design/rules.md. Each type encapsulates invariants and validation logic.

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use super::error::{TunError, TunResult};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// TUN device name with validated invariants
///
/// Device names must be:
/// - Non-empty
/// - 15 characters or less (Linux IFNAMSIZ - 1)
/// - Valid ASCII characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceName(String);

impl DeviceName {
    /// Create a new DeviceName with validation
    ///
    /// # Errors
    ///
    /// Returns `TunError::InvalidDeviceName` if:
    /// - Name is empty
    /// - Name exceeds 15 characters
    /// - Name contains invalid characters
    pub fn new(name: impl Into<String>) -> TunResult<Self> {
        let name = name.into();

        if name.is_empty() {
            return Err(TunError::InvalidDeviceName {
                reason: "name cannot be empty".into(),
            });
        }

        if name.len() > 15 {
            return Err(TunError::InvalidDeviceName {
                reason: format!("name must be 15 chars or less, got {}", name.len()),
            });
        }

        if !name.is_ascii() {
            return Err(TunError::InvalidDeviceName {
                reason: "name must contain only ASCII characters".into(),
            });
        }

        Ok(Self(name))
    }

    /// Get the device name as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for DeviceName {
    type Err = TunError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Maximum Transmission Unit (MTU) for TUN device
///
/// MTU must be:
/// - At least 68 bytes (IPv4 minimum per RFC 791)
/// - At most 65535 bytes (maximum IP packet size)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Mtu(u16);

impl Mtu {
    /// Minimum MTU value (IPv4 minimum per RFC 791)
    pub const MIN: u16 = 576;

    /// Maximum MTU value
    pub const MAX: u16 = 65535;

    /// Default MTU value (standard Ethernet MTU)
    pub const DEFAULT: u16 = 1500;

    /// Create a new MTU with validation
    ///
    /// # Errors
    ///
    /// Returns `TunError::InvalidMtu` if value is less than `MIN` (576) or greater than `MAX` (65535)
    pub fn new(value: u16) -> TunResult<Self> {
        if value < Self::MIN {
            return Err(TunError::InvalidMtu {
                value,
                reason: format!("MTU must be >= {} (IPv4 minimum per RFC 791)", Self::MIN),
            });
        }
        // Note: MAX check omitted as Self::MAX == u16::MAX (all values are valid at upper bound)
        Ok(Self(value))
    }

    /// Create MTU with default value
    pub fn new_default() -> Self {
        Self(Self::DEFAULT)
    }

    /// Get the MTU value
    pub fn get(&self) -> u16 {
        self.0
    }

    /// Get MTU value.as_usize() for buffer allocation
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl Default for Mtu {
    fn default() -> Self {
        Self::new_default()
    }
}

impl fmt::Display for Mtu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Mtu {
    type Err = TunError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value: u16 = s.parse().map_err(|_| TunError::InvalidMtu {
            value: 0,
            reason: format!("failed to parse MTU from '{}'", s),
        })?;
        Self::new(value)
    }
}

/// TUN device configuration
///
/// Contains all parameters needed to create and configure a TUN device
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name
    pub name: DeviceName,
    /// IP address assigned to the TUN device
    pub ip_address: IpAddr,
    /// Network mask
    pub netmask: IpAddr,
    /// Maximum transmission unit
    pub mtu: Mtu,
}

impl TunConfig {
    /// Create a new TUN device configuration
    pub fn new(name: DeviceName, ip_address: IpAddr, netmask: IpAddr, mtu: Mtu) -> Self {
        Self {
            name,
            ip_address,
            netmask,
            mtu,
        }
    }

    /// Calculate netmask prefix length from netmask IP
    pub fn netmask_to_prefix(netmask: &IpAddr) -> u8 {
        match netmask {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let mask = u32::from_be_bytes(octets);
                mask.count_ones() as u8
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let mut count = 0;
                for &octet in &octets {
                    count += octet.count_ones();
                }
                count as u8
            }
        }
    }

    /// Get the netmask prefix length for this configuration
    pub fn prefix(&self) -> u8 {
        Self::netmask_to_prefix(&self.netmask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_name_valid() {
        let name = DeviceName::new("buckwild0").unwrap();
        assert_eq!(name.as_str(), "buckwild0");
    }

    #[test]
    fn test_device_name_empty() {
        let result = DeviceName::new("");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TunError::InvalidDeviceName { .. }
        ));
    }

    #[test]
    fn test_device_name_too_long() {
        let long_name = "a".repeat(16);
        let result = DeviceName::new(long_name);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TunError::InvalidDeviceName { .. }
        ));
    }

    #[test]
    fn test_device_name_max_length() {
        let name = DeviceName::new("a".repeat(15)).unwrap();
        assert_eq!(name.as_str().len(), 15);
    }

    #[test]
    fn test_mtu_valid() {
        let mtu = Mtu::new(1400).unwrap();
        assert_eq!(mtu.get(), 1400);
    }

    #[test]
    fn test_mtu_minimum() {
        let mtu = Mtu::new(576).unwrap();
        assert_eq!(mtu.get(), 576);
    }

    #[test]
    fn test_mtu_below_minimum() {
        let result = Mtu::new(575);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TunError::InvalidMtu { .. }));
    }

    #[test]
    fn test_mtu_maximum() {
        let mtu = Mtu::new(65535).unwrap();
        assert_eq!(mtu.get(), 65535);
    }

    #[test]
    fn test_mtu_default() {
        let mtu = Mtu::default();
        assert_eq!(mtu.get(), 1500);
    }

    #[test]
    fn test_netmask_to_prefix_v4() {
        let netmask: IpAddr = "255.255.255.0".parse().unwrap();
        assert_eq!(TunConfig::netmask_to_prefix(&netmask), 24);

        let netmask: IpAddr = "255.255.0.0".parse().unwrap();
        assert_eq!(TunConfig::netmask_to_prefix(&netmask), 16);
    }

    #[test]
    fn test_device_name_from_str() {
        let name: DeviceName = "buckwild0".parse().unwrap();
        assert_eq!(name.as_str(), "buckwild0");
    }

    #[test]
    fn test_mtu_from_str() {
        let mtu: Mtu = "1500".parse().unwrap();
        assert_eq!(mtu.get(), 1500);
    }
}
