// Network types imported from protocol types module
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Errors that can occur during configuration validation
#[derive(Error, Debug, Clone)]
pub enum ConfigError {
    #[error("Invalid value for {field}: {message}")]
    InvalidValue { field: String, message: String },

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Global daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonConfig {
    /// General settings
    #[serde(default)]
    pub general: GeneralSettings,

    /// Network settings
    #[serde(default)]
    pub network: NetworkSettings,

    /// Security settings
    #[serde(default)]
    pub security: SecuritySettings,

    /// Logging settings
    #[serde(default)]
    pub logging: LoggingSettings,

    /// Advanced settings
    #[serde(default)]
    pub advanced: AdvancedSettings,
}

/// General daemon settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralSettings {
    /// Daemon name
    #[serde(default = "default_daemon_name")]
    pub daemon_name: String,

    /// Whether to run as a system service
    #[serde(default)]
    pub run_as_service: bool,

    /// Path to PSK directory
    #[serde(default = "default_psk_dir")]
    pub psk_directory: PathBuf,

    /// Path to hosts configuration
    #[serde(default = "default_hosts_config")]
    pub hosts_config: PathBuf,

    /// Path to state directory
    #[serde(default = "default_state_dir")]
    pub state_directory: PathBuf,
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// TUN device name
    #[serde(default = "default_tun_device")]
    pub tun_device: String,

    /// Whether to enable IPv6
    #[serde(default = "default_true")]
    pub ipv6_enabled: bool,

    /// Base port range
    #[serde(default = "default_port_range")]
    pub port_range: String,

    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: MaxConnections,

    /// Connection timeout in seconds
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_sec: Duration,

    /// Port hopping interval in milliseconds
    #[serde(default = "default_port_hop_interval")]
    pub port_hop_interval_ms: HopInterval,

    /// Maximum transmission unit (MTU)
    #[serde(default = "default_mtu")]
    pub mtu: MtuSize,

    /// Maximum fragment size for packet fragmentation
    #[serde(default = "default_max_fragment_size")]
    pub max_fragment_size: FragmentSize,

    /// Whether to enable TCP compatibility mode
    #[serde(default)]
    pub tcp_compatibility: bool,
}

/// Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Default HMAC policy
    #[serde(default = "default_hmac_policy")]
    pub default_hmac_policy: String,

    /// Whether to lock memory for sensitive data
    #[serde(default = "default_true")]
    pub lock_memory: bool,

    /// Key rotation interval in minutes
    #[serde(default = "default_key_rotation")]
    pub key_rotation_minutes: KeyRotationInterval,

    /// Maximum PSK size in bytes
    #[serde(default = "default_max_psk_size")]
    pub max_psk_size: MaxPskSize,

    /// Whether to enable replay protection
    #[serde(default = "default_true")]
    pub replay_protection: bool,

    /// Replay protection window in seconds
    #[serde(default = "default_replay_window")]
    pub replay_window_sec: ReplayWindowSize,
}

/// Logging settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Whether to log to file
    #[serde(default)]
    pub log_to_file: bool,

    /// Log file path
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,

    /// Whether to log to syslog
    #[serde(default)]
    pub log_to_syslog: bool,

    /// Maximum log file size in MB
    #[serde(default = "default_log_size")]
    pub max_log_size_mb: LogFileSize,

    /// Maximum number of log files
    #[serde(default = "default_log_files")]
    pub max_log_files: LogFileCount,

    /// Whether to log security events
    #[serde(default = "default_true")]
    pub log_security_events: bool,
}

/// Advanced settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedSettings {
    /// Number of worker threads
    #[serde(default = "default_worker_threads")]
    pub worker_threads: WorkerThreadCount,

    /// Crypto thread pool size
    #[serde(default = "default_crypto_threads")]
    pub crypto_threads: CryptoThreadCount,

    /// Whether to use SIMD acceleration
    #[serde(default = "default_true")]
    pub use_simd: bool,

    /// Ring buffer size in KB
    #[serde(default = "default_ring_buffer")]
    pub ring_buffer_kb: RingBufferSize,

    /// Whether to enable performance metrics
    #[serde(default)]
    pub enable_metrics: bool,

    /// Metrics collection interval in seconds
    #[serde(default = "default_metrics_interval")]
    pub metrics_interval_sec: MetricsInterval,

    /// Whether to enable SNMP agent
    #[serde(default)]
    pub enable_snmp: bool,

    /// SNMP agent port
    #[serde(default = "default_snmp_port")]
    pub snmp_port: Port,

    /// Memory limit configuration
    #[serde(default)]
    pub memory: MemoryConfig,
}

/// Memory limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Maximum bytes for packet buffers (default: 64MB)
    #[serde(default = "default_max_packet_buffer_bytes")]
    pub max_packet_buffer_bytes: MaxPacketBufferBytes,

    /// Maximum bytes for session state (default: 128MB)
    #[serde(default = "default_max_session_state_bytes")]
    pub max_session_state_bytes: MaxSessionStateBytes,

    /// Maximum bytes for fragment reassembly (default: 32MB)
    #[serde(default = "default_max_fragment_bytes")]
    pub max_fragment_bytes: MaxFragmentBytes,
}

// Default values
fn default_daemon_name() -> String {
    "buckwild".to_string()
}

fn default_psk_dir() -> PathBuf {
    PathBuf::from("/etc/buckwild/psk")
}

fn default_hosts_config() -> PathBuf {
    PathBuf::from("/etc/buckwild/hosts.toml")
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/buckwild")
}

fn default_tun_device() -> String {
    "tun0".to_string()
}

fn default_true() -> bool {
    true
}

fn default_port_range() -> String {
    "1024-65535".to_string()
}

fn default_max_connections() -> MaxConnections {
    MaxConnections::from_raw(1000)
}

fn default_connection_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_port_hop_interval() -> HopInterval {
    HopInterval::from_raw(500)
}

fn default_mtu() -> MtuSize {
    MtuSize::from_raw(1500)
}

fn default_max_fragment_size() -> FragmentSize {
    FragmentSize::from_raw(1400)
}

fn default_hmac_policy() -> String {
    "MEDIUM".to_string()
}

fn default_key_rotation() -> KeyRotationInterval {
    KeyRotationInterval::from_raw(60)
}

fn default_max_psk_size() -> MaxPskSize {
    MaxPskSize::from_raw(1024 * 1024) // 1 MB
}

fn default_replay_window() -> ReplayWindowSize {
    ReplayWindowSize::from_raw(30)
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/buckwild/daemon.log")
}

fn default_log_size() -> LogFileSize {
    LogFileSize::from_raw(10)
}

fn default_log_files() -> LogFileCount {
    LogFileCount::from_raw(5)
}

fn default_worker_threads() -> WorkerThreadCount {
    WorkerThreadCount::from_raw(num_cpus::get().try_into().unwrap_or(4))
}

fn default_crypto_threads() -> CryptoThreadCount {
    CryptoThreadCount::from_raw(num_cpus::get().try_into().unwrap_or(2))
}

fn default_ring_buffer() -> RingBufferSize {
    RingBufferSize::from_raw(16384) // 16 MB
}

fn default_metrics_interval() -> MetricsInterval {
    MetricsInterval::from_raw(Duration::from_secs(60))
}

fn default_snmp_port() -> Port {
    Port::from_raw(4700)
}

fn default_max_packet_buffer_bytes() -> MaxPacketBufferBytes {
    MaxPacketBufferBytes::from_raw(64 * 1024 * 1024) // 64 MB
}

fn default_max_session_state_bytes() -> MaxSessionStateBytes {
    MaxSessionStateBytes::from_raw(128 * 1024 * 1024) // 128 MB
}

fn default_max_fragment_bytes() -> MaxFragmentBytes {
    MaxFragmentBytes::from_raw(32 * 1024 * 1024) // 32 MB
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            daemon_name: default_daemon_name(),
            run_as_service: false,
            psk_directory: default_psk_dir(),
            hosts_config: default_hosts_config(),
            state_directory: default_state_dir(),
        }
    }
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            tun_device: default_tun_device(),
            ipv6_enabled: default_true(),
            port_range: default_port_range(),
            max_connections: default_max_connections(),
            connection_timeout_sec: default_connection_timeout(),
            port_hop_interval_ms: default_port_hop_interval(),
            mtu: default_mtu(),
            max_fragment_size: default_max_fragment_size(),
            tcp_compatibility: false,
        }
    }
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            default_hmac_policy: default_hmac_policy(),
            lock_memory: default_true(),
            key_rotation_minutes: default_key_rotation(),
            max_psk_size: default_max_psk_size(),
            replay_protection: default_true(),
            replay_window_sec: default_replay_window(),
        }
    }
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_to_file: false,
            log_file: default_log_file(),
            log_to_syslog: false,
            max_log_size_mb: default_log_size(),
            max_log_files: default_log_files(),
            log_security_events: default_true(),
        }
    }
}

impl Default for AdvancedSettings {
    fn default() -> Self {
        Self {
            worker_threads: default_worker_threads(),
            crypto_threads: default_crypto_threads(),
            use_simd: default_true(),
            ring_buffer_kb: default_ring_buffer(),
            enable_metrics: false,
            metrics_interval_sec: default_metrics_interval(),
            enable_snmp: false,
            snmp_port: default_snmp_port(),
            memory: MemoryConfig::default(),
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_packet_buffer_bytes: default_max_packet_buffer_bytes(),
            max_session_state_bytes: default_max_session_state_bytes(),
            max_fragment_bytes: default_max_fragment_bytes(),
        }
    }
}

impl DaemonConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate general settings
        if self.general.daemon_name.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "general.daemon_name".to_string(),
                message: "Daemon name cannot be empty".to_string(),
            });
        }

        // Validate network settings
        if self.network.tun_device.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "network.tun_device".to_string(),
                message: "TUN device name cannot be empty".to_string(),
            });
        }

        if !is_valid_port_range(&self.network.port_range) {
            return Err(ConfigError::InvalidValue {
                field: "network.port_range".to_string(),
                message: "Invalid port range format".to_string(),
            });
        }

        if self.network.max_connections == MaxConnections::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "network.max_connections".to_string(),
                message: "Max connections must be greater than 0".to_string(),
            });
        }

        if self.network.port_hop_interval_ms < HopInterval::from_raw(100) {
            return Err(ConfigError::InvalidValue {
                field: "network.port_hop_interval_ms".to_string(),
                message: "Port hop interval must be at least 100ms".to_string(),
            });
        }

        if self.network.mtu < MtuSize::from_raw(576) || self.network.mtu > MtuSize::from_raw(9000) {
            return Err(ConfigError::InvalidValue {
                field: "network.mtu".to_string(),
                message: "MTU must be between 576 and 9000".to_string(),
            });
        }

        if self.network.max_fragment_size < FragmentSize::from_raw(500)
            || self.network.max_fragment_size.as_usize() > self.network.mtu.as_usize()
        {
            return Err(ConfigError::InvalidValue {
                field: "network.max_fragment_size".to_string(),
                message: format!(
                    "Max fragment size must be between 500 and MTU ({})",
                    self.network.mtu
                ),
            });
        }

        // Validate security settings
        if !is_valid_hmac_policy(&self.security.default_hmac_policy) {
            return Err(ConfigError::InvalidValue {
                field: "security.default_hmac_policy".to_string(),
                message: "Invalid HMAC policy".to_string(),
            });
        }

        if self.security.key_rotation_minutes == KeyRotationInterval::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "security.key_rotation_minutes".to_string(),
                message: "Key rotation interval must be greater than 0".to_string(),
            });
        }

        // Validate logging settings
        if !is_valid_log_level(&self.logging.log_level) {
            return Err(ConfigError::InvalidValue {
                field: "logging.log_level".to_string(),
                message: "Invalid log level".to_string(),
            });
        }

        // Validate advanced settings
        if self.advanced.worker_threads == WorkerThreadCount::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "advanced.worker_threads".to_string(),
                message: "Worker threads must be greater than 0".to_string(),
            });
        }

        if self.advanced.crypto_threads == CryptoThreadCount::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "advanced.crypto_threads".to_string(),
                message: "Crypto threads must be greater than 0".to_string(),
            });
        }

        if self.advanced.ring_buffer_kb == RingBufferSize::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "advanced.ring_buffer_kb".to_string(),
                message: "Ring buffer size must be greater than 0".to_string(),
            });
        }

        // Validate memory settings
        if self.advanced.memory.max_packet_buffer_bytes == MaxPacketBufferBytes::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "advanced.memory.max_packet_buffer_bytes".to_string(),
                message: "Max packet buffer bytes must be greater than 0".to_string(),
            });
        }

        if self.advanced.memory.max_session_state_bytes == MaxSessionStateBytes::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "advanced.memory.max_session_state_bytes".to_string(),
                message: "Max session state bytes must be greater than 0".to_string(),
            });
        }

        if self.advanced.memory.max_fragment_bytes == MaxFragmentBytes::from_raw(0) {
            return Err(ConfigError::InvalidValue {
                field: "advanced.memory.max_fragment_bytes".to_string(),
                message: "Max fragment bytes must be greater than 0".to_string(),
            });
        }

        Ok(())
    }
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

/// Check if a log level is valid
fn is_valid_log_level(level: &str) -> bool {
    matches!(
        level.to_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    )
}

impl DaemonConfig {
    /// Convert HMAC policy string to HmacPolicy enum
    pub fn hmac_policy(&self) -> HmacPolicy {
        match self.security.default_hmac_policy.to_uppercase().as_str() {
            "LIGHT" => HmacPolicy::Light,
            "MEDIUM" => HmacPolicy::Medium,
            "STRONG" => HmacPolicy::Strong,
            _ => HmacPolicy::Medium, // Default fallback
        }
    }
}
