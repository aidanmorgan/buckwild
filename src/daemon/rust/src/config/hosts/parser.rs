use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;
use tracing::instrument;

// Import consolidated types from common crate
use crate::types::{PskFingerprint, TunDeviceName};
use buckwild_common::protocol::types::*;

/// Errors that can occur during hosts configuration parsing
#[derive(Error, Debug)]
pub enum HostsParserError {
    #[error("Failed to read hosts file: {0}")]
    FileReadError(#[from] std::io::Error),

    #[error("Failed to parse TOML: {0}")]
    TomlParseError(#[from] toml::de::Error),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Duplicate host entry: {0}")]
    DuplicateHost(String),
}

/// Host configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostsConfig {
    /// Global settings
    #[serde(default)]
    pub settings: Settings,

    /// Host entries
    #[serde(default)]
    pub hosts: Vec<Host>,
}

/// Global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Default PSK fingerprint
    #[serde(default)]
    pub default_psk_fingerprint: Option<String>,

    /// TUN device name
    #[serde(default = "default_tun_device")]
    pub tun_device: TunDeviceName,

    /// Update interval in milliseconds
    #[serde(default = "default_update_interval")]
    pub update_interval_ms: MetricsInterval,

    /// Whether to enable IPv6
    #[serde(default = "default_ipv6_enabled")]
    pub ipv6_enabled: bool,

    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: MaxConnections,

    /// Connection timeout in seconds
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_sec: Timeout,
}

/// Host entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    /// IP address
    pub ip: IpAddress,

    /// PSK fingerprint
    pub psk_fingerprint: PskFingerprint,

    /// Optional description
    #[serde(default)]
    pub description: Option<String>,

    /// Optional port range
    #[serde(default)]
    pub port_range: Option<Port>,

    /// Optional HMAC policy
    #[serde(default)]
    pub hmac_policy: Option<HmacPolicy>,

    /// Optional priority
    #[serde(default = "default_priority")]
    pub priority: Counter,
}

// Default values
fn default_tun_device() -> TunDeviceName {
    TunDeviceName::new("tun0")
}

fn default_update_interval() -> MetricsInterval {
    MetricsInterval::from_raw(std::time::Duration::from_millis(500))
}

fn default_ipv6_enabled() -> bool {
    true
}

fn default_max_connections() -> MaxConnections {
    MaxConnections::from_raw(1000)
}

fn default_connection_timeout() -> Timeout {
    Timeout::from_millis(30000)
}

fn default_priority() -> Counter {
    Counter::new(100)
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_psk_fingerprint: None,
            tun_device: default_tun_device(),
            update_interval_ms: default_update_interval(),
            ipv6_enabled: default_ipv6_enabled(),
            max_connections: default_max_connections(),
            connection_timeout_sec: default_connection_timeout(),
        }
    }
}

impl HostsConfig {
    /// Load hosts configuration from a file
    #[instrument(skip(path), err)]
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, HostsParserError> {
        // Read file
        let content = fs::read_to_string(path).await?;

        // Parse TOML
        let config: HostsConfig = toml::from_str(&content)?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate the configuration
    #[instrument(skip(self), err)]
    pub fn validate(&self) -> Result<(), HostsParserError> {
        // Check for duplicate IPs
        let mut ips = std::collections::HashSet::new();

        for host in &self.hosts {
            // IP validation - IpAddress type is already validated during deserialization
            let ip_str = host.ip.to_std().to_string();

            // Check for duplicates
            if !ips.insert(ip_str.clone()) {
                return Err(HostsParserError::DuplicateHost(ip_str));
            }

            // Validate fingerprint
            if !Self::is_valid_fingerprint(&host.psk_fingerprint) {
                return Err(HostsParserError::InvalidFingerprint(
                    host.psk_fingerprint.clone(),
                ));
            }

            // Port and HmacPolicy are already validated during deserialization via their newtypes
            // No additional validation needed
        }

        // Validate default fingerprint if present
        if let Some(fingerprint) = &self.settings.default_psk_fingerprint {
            if !Self::is_valid_fingerprint(fingerprint) {
                return Err(HostsParserError::InvalidFingerprint(fingerprint.clone()));
            }
        }

        Ok(())
    }

    /// Check if an IP address is valid

    fn is_valid_ip(ip: &str) -> bool {
        // Try parsing as IPv4 or IPv6
        IpAddr::from_str(ip).is_ok()
    }

    /// Check if a fingerprint is valid
    fn is_valid_fingerprint(fingerprint: &str) -> bool {
        // Fingerprint should be a hex string of appropriate length
        fingerprint.len() == 64 && fingerprint.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Check if a port range is valid

    fn is_valid_port_range(port_range: &str) -> bool {
        // Format should be "start-end" or a single port
        if port_range.contains('-') {
            let parts: Vec<&str> = port_range.split('-').collect();
            if parts.len() != 2 {
                return false;
            }

            let start = parts[0].parse::<u16>();
            let end = parts[1].parse::<u16>();

            if let (Ok(start), Ok(end)) = (start, end) {
                return start <= end && start >= 1024;
            }

            false
        } else {
            // Single port
            if let Ok(port) = port_range.parse::<u16>() {
                port >= 1024
            } else {
                false
            }
        }
    }

    /// Check if an HMAC policy is valid

    fn is_valid_hmac_policy(policy: &str) -> bool {
        matches!(
            policy.to_uppercase().as_str(),
            "LIGHT" | "MEDIUM" | "STRONG"
        )
    }

    /// Get a host by IP address
    pub fn get_host_by_ip(&self, ip: &IpAddress) -> Option<&Host> {
        self.hosts.iter().find(|h| &h.ip == ip)
    }

    /// Get all hosts
    pub fn get_all_hosts(&self) -> &[Host] {
        &self.hosts
    }

    /// Get the number of hosts
    pub fn host_count(&self) -> MaxConnections {
        MaxConnections::from_raw(self.hosts.len() as u32)
    }
}
