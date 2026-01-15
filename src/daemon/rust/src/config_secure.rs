//! Secure configuration management for the Buckwild daemon
//!
//! This module provides secure configuration handling with proper type safety
//! and data sanitization using consolidated types.

use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;

// Import consolidated types from common crate
use buckwild_common::protocol::types::*;

use crate::crypto::SecureBytes;

/// Secure configuration container
#[derive(Debug, Clone)]
pub struct SecureConfig {
    /// Daemon configuration
    pub daemon_name: DaemonName,
    
    /// Network configuration
    pub listen_port: Port,
    pub bind_address: IpAddress,
    
    /// TUN device configuration
    pub tun_device_name: TunDeviceName,
    
    /// Connection limits
    pub max_connections: MaxConnections,
    
    /// Thread pool configuration
    pub worker_thread_count: WorkerThreadCount,
    pub crypto_thread_count: CryptoThreadCount,
    
    /// Logging configuration
    pub log_level: LogLevel,
    pub log_file_size: LogFileSize,
    pub log_file_count: LogFileCount,
    pub log_directory: LogDirectory,
    
    /// Monitoring configuration
    pub metrics_interval: MetricsInterval,
    pub snmp_port: SnmpPort,
    
    /// Security configuration
    pub hmac_policy: HmacPolicy,
    pub security_mode: SecurityMode,
    
    /// PSK configuration
    pub psk_directory: PskDirectory,
    pub max_psk_count: MaxPskCount,
    
    /// Timeout configuration
    pub discovery_timeout: DiscoveryTimeout,
    pub heartbeat_interval: HeartbeatInterval,
    pub recovery_timeout: RecoveryTimeout,
    
    /// Configuration paths
    pub config_path: ConfigPath,
    pub state_directory: StateDirectory,
    
    /// Secure PSK storage
    pub psks: HashMap<PskFingerprint, Arc<SecureBytes>>,
}

impl SecureConfig {
    /// Create a new secure configuration with default values
    pub fn new() -> Self {
        Self {
            daemon_name: DaemonName::from_raw("buckwild".to_string()),
            listen_port: Port::from_raw(8080),
            // SAFETY: "0.0.0.0" is a valid IPv4 address literal that will always parse successfully
            bind_address: IpAddress::from_raw("0.0.0.0".parse().expect("Valid IP address literal")),
            tun_device_name: TunDeviceName::from_raw("buckwild0".to_string()),
            max_connections: MaxConnections::from_raw(1000),
            worker_thread_count: WorkerThreadCount::from_raw(4),
            crypto_thread_count: CryptoThreadCount::from_raw(2),
            log_level: LogLevel::Info,
            log_file_size: LogFileSize::from_raw(10 * 1024 * 1024), // 10MB
            log_file_count: LogFileCount::from_raw(5),
            log_directory: LogDirectory::from_raw("/var/log/buckwild".into()),
            metrics_interval: MetricsInterval::from_raw(Duration::from_secs(30)),
            snmp_port: SnmpPort::from_raw(161),
            hmac_policy: HmacPolicy::Medium,
            security_mode: SecurityMode::Balanced,
            psk_directory: PskDirectory::from_raw("/etc/buckwild/psks".into()),
            max_psk_count: MaxPskCount::from_raw(256),
            discovery_timeout: DiscoveryTimeout::from_raw(Duration::from_secs(10)),
            heartbeat_interval: HeartbeatInterval::from_raw(Duration::from_secs(30)),
            recovery_timeout: RecoveryTimeout::from_raw(Duration::from_secs(15)),
            config_path: ConfigPath::from_raw("/etc/buckwild/config.toml".into()),
            state_directory: StateDirectory::from_raw("/var/lib/buckwild".into()),
            psks: HashMap::new(),
        }
    }
    
    /// Add a PSK to the secure configuration
    pub fn add_psk(&mut self, fingerprint: PskFingerprint, psk: Arc<SecureBytes>) {
        self.psks.insert(fingerprint, psk);
    }
    
    /// Remove a PSK from the secure configuration
    pub fn remove_psk(&mut self, fingerprint: &PskFingerprint) -> Option<Arc<SecureBytes>> {
        self.psks.remove(fingerprint)
    }
    
    /// Get all PSK fingerprints
    pub fn get_psk_fingerprints(&self) -> Vec<PskFingerprint> {
        self.psks.keys().copied().collect()
    }
    
    /// Get PSK by fingerprint
    pub fn get_psk(&self, fingerprint: &PskFingerprint) -> Option<Arc<SecureBytes>> {
        self.psks.get(fingerprint).cloned()
    }
    
    /// Validate configuration parameters
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        // Validate port range
        if self.listen_port.as_raw() < 1024 || self.listen_port.as_raw() > 65535 {
            return Err(ConfigurationError::InvalidPort);
        }
        
        // Validate thread counts
        if self.worker_thread_count.as_raw() == 0 || self.worker_thread_count.as_raw() > 64 {
            return Err(ConfigurationError::InvalidThreadCount);
        }
        
        if self.crypto_thread_count.as_raw() == 0 || self.crypto_thread_count.as_raw() > 16 {
            return Err(ConfigurationError::InvalidThreadCount);
        }
        
        // Validate connection limits
        if self.max_connections.as_raw() == 0 || self.max_connections.as_raw() > 100000 {
            return Err(ConfigurationError::InvalidConnectionLimit);
        }
        
        // Validate PSK count
        if self.psks.len() > self.max_psk_count.as_raw() {
            return Err(ConfigurationError::TooManyPsks);
        }
        
        Ok(())
    }
}

impl Default for SecureConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration validation errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationError {
    #[error("Invalid port number")]
    InvalidPort,

    #[error("Invalid thread count")]
    InvalidThreadCount,

    #[error("Invalid connection limit")]
    InvalidConnectionLimit,

    #[error("Too many PSKs configured")]
    TooManyPsks,

    #[error("Invalid file path")]
    InvalidPath,

    #[error("Invalid timeout value")]
    InvalidTimeout,

    #[error("Invalid security mode")]
    InvalidSecurityMode,
}